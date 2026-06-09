package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

type assessCmd struct {
	cache     string
	minSev    string
	category  string
	gpo       string
	jsonOut   bool
	checkACLs bool
	acl       connArgs // connection used only when --check-acls is set
}

func init() { register(&assessCmd{}) }

func (c *assessCmd) Name() string { return "assess" }
func (c *assessCmd) Synopsis() string {
	return "Flag exploitable GPO misconfigurations (privileges, groups, registry, creds)"
}
func (c *assessCmd) NeedsConnection() bool { return false }

func (c *assessCmd) DefineFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.cache, "cache", "", "Cache file (default: newest cache_gpoparser_*.json)")
	fs.StringVar(&c.cache, "c", "", "Cache file (short)")
	fs.StringVar(&c.minSev, "min-severity", "low", "Minimum severity to report: info|low|high|critical")
	fs.StringVar(&c.minSev, "a", "low", "Minimum severity (short)")
	fs.StringVar(&c.category, "category", "", "Only report findings of this category (e.g. user-rights)")
	fs.StringVar(&c.gpo, "gpo", "", "Limit assessment to GPOs matching this GUID or name substring")
	fs.StringVar(&c.gpo, "g", "", "Limit to GPO (short)")
	fs.BoolVar(&c.jsonOut, "json", false, "Emit findings as JSON")
	fs.BoolVar(&c.checkACLs, "check-acls", false, "Query AD live to flag GPO objects the assessed user can modify (needs connection options)")
	// Connection flags are bound to c.acl (used only with --check-acls); the
	// dispatcher does not add them because assess is offline by default.
	addConnectionArgs(fs, &c.acl)
}

func (c *assessCmd) Usage() string {
	return `
    Usage: ` + os.Args[0] + ` assess [-c cache.json] [-a severity] [-g GPO] [--category id] [--json]

    Runs the analyser pipeline over a cache produced by 'remote' or 'local' and
    reports exploitable misconfigurations, sorted most-severe first. Each finding
    carries the GPO's resolved blast radius (affected computers).

    By default this mode reads only the cache (fully offline). With --check-acls
    it additionally connects to AD to flag GPO objects the assessed user can
    modify (a GPO-takeover ⇒ code execution on every linked computer); that path
    accepts the standard connection options below.

    Options:
      -c, --cache        Cache file (default: newest cache_gpoparser_*.json in cwd)
      -a, --min-severity Minimum severity to report: info|low|high|critical (default low)
      -g, --gpo          Limit assessment to GPOs matching a GUID or name substring
          --category     Only report findings of this category
          --json         Emit findings as JSON
          --check-acls   Live-check GPO object writability for the connecting user
` + helpConnectionOptions
}

func (c *assessCmd) Run(_ *connArgs) error {
	min, err := parseSeverity(c.minSev)
	if err != nil {
		return err
	}
	path, err := resolveCachePath(c.cache)
	if err != nil {
		return err
	}
	cache, err := loadCache(path)
	if err != nil {
		return err
	}

	gpos := cache.findGPOs(c.gpo)
	if len(gpos) == 0 {
		return fmt.Errorf("no GPOs match %q", c.gpo)
	}

	findings := runAssessment(gpos, &assessCtx{}, min)

	if c.checkACLs {
		extra, err := c.runACLChecks(gpos, min)
		if err != nil {
			return err
		}
		findings = append(findings, extra...)
		sortFindings(findings)
	}

	if c.category != "" {
		findings = filterByCategory(findings, c.category)
	}

	if c.jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(findings)
	}
	printFindings(os.Stdout, findings, min)
	return nil
}

// runACLChecks connects to AD as the assessed user and returns gpo-object-writable
// findings for GPOs the user can modify. It replicates the minimal connection
// prologue the dispatcher performs for connection-mode subcommands, because
// assess is offline by default.
func (c *assessCmd) runACLChecks(gpos []*GPO, min Severity) ([]Finding, error) {
	if err := ensurePassword(&c.acl); err != nil {
		return nil, fmt.Errorf("reading password: %w", err)
	}
	if c.acl.useKerberos && c.acl.ccachePath == "" {
		if cc := os.Getenv("KRB5CCNAME"); cc != "" {
			c.acl.ccachePath = strings.TrimPrefix(cc, "FILE:")
		}
	}
	if c.acl.baseDN == "" {
		c.acl.discoverBaseDN = true
	}
	if c.acl.host == "" {
		if c.acl.domain == "" {
			return nil, fmt.Errorf("--check-acls requires --host (or --domain for SRV discovery)")
		}
		h, err := discoverDC(c.acl.domain)
		if err != nil {
			return nil, fmt.Errorf("--check-acls: --host required (SRV discovery failed: %w)", err)
		}
		c.acl.host = h
		logger.Infof("[*] Discovered DC via SRV: %s\n", c.acl.host)
	}
	if c.acl.user == "" {
		return nil, fmt.Errorf("--check-acls requires -u/--user (the principal to assess)")
	}

	conn, baseDN, err := makeConnection(&c.acl)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	checker, err := newACLChecker(conn, baseDN, c.acl.user)
	if err != nil {
		return nil, fmt.Errorf("resolving effective rights for %q: %w", c.acl.user, err)
	}

	// SYSVOL/path ACL checks need SMB; a failure here is non-fatal (the
	// GPO-object check over LDAP still runs).
	if smbConn, err := newSMBConnection(&c.acl); err != nil {
		logger.Errorf("[!] SYSVOL access failed; file/path writability skipped: %v\n", err)
	} else {
		checker.smb = &smbSource{conn: smbConn}
		defer checker.smb.Close()
	}

	var out []Finding
	emit := func(f Finding, min Severity) {
		if f.Severity >= min {
			out = append(out, f)
		}
	}
	for _, g := range gpos {
		// 1. The GPO object in AD.
		if wa := checker.gpoWritable(g); wa != nil {
			emit(Finding{
				GPO: g.GUID, GPOName: g.Name, Scope: "AD object",
				Category: "gpo-object-writable", Severity: SevCritical,
				Reason:            "the assessed user can modify this GPO object in AD — edit its settings to run code on every linked computer",
				Detail:            wa.Trustee.String() + " has " + strings.Join(wa.Rights, "|") + " on the GPC",
				Principals:        []Principal{wa.Trustee},
				Writable:          wa,
				AffectedComputers: g.AffectedComputers,
			}, min)
		}
		// 2. The GPO's SYSVOL policy folder.
		if wa := checker.sysvolFolderWritable(g); wa != nil {
			emit(Finding{
				GPO: g.GUID, GPOName: g.Name, Scope: "SYSVOL",
				Category: "sysvol-writable", Severity: SevCritical,
				Reason:            "the GPO's SYSVOL policy folder is writable — any policy file can be replaced to run code on every linked computer",
				Detail:            wa.Trustee.String() + " has " + strings.Join(wa.Rights, "|") + " on " + wa.Path,
				Principals:        []Principal{wa.Trustee},
				Writable:          wa,
				AffectedComputers: g.AffectedComputers,
			}, min)
		}
		// 3. Referenced executable/deployed paths (per scope).
		for _, sc := range []struct {
			name string
			cs   *ConfigSettings
		}{{"Computer", &g.Computer}, {"User", &g.User}} {
			for _, ref := range referencedPaths(sc.cs) {
				wa := checker.pathWritable(ref.path)
				if wa == nil {
					continue
				}
				sev := SevHigh
				if sc.name == "Computer" {
					sev = SevCritical // SYSTEM execution context
				}
				where := "the referenced path"
				if !wa.Existed {
					where = "the parent directory of the (missing) referenced path"
				}
				emit(Finding{
					GPO: g.GUID, GPOName: g.Name, Scope: sc.name,
					Category: "path-writable", Severity: sev,
					Reason:            ref.label + ": " + where + " is attacker-writable (code execution)",
					Detail:            wa.Trustee.String() + " has " + strings.Join(wa.Rights, "|") + " on " + wa.Path,
					Principals:        []Principal{wa.Trustee},
					Writable:          wa,
					AffectedComputers: g.AffectedComputers,
				}, min)
			}
		}
	}
	return out, nil
}

func filterByCategory(in []Finding, category string) []Finding {
	var out []Finding
	for _, f := range in {
		if strings.EqualFold(f.Category, category) {
			out = append(out, f)
		}
	}
	return out
}

func printFindings(w *os.File, findings []Finding, min Severity) {
	if len(findings) == 0 {
		fmt.Fprintf(w, "No findings at or above severity %q.\n", min)
		return
	}

	counts := map[Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	fmt.Fprintf(w, "%d finding(s): %d critical, %d high, %d low, %d info\n",
		len(findings), counts[SevCritical], counts[SevHigh], counts[SevLow], counts[SevInfo])

	for _, f := range findings {
		fmt.Fprintf(w, "\n%s %s  (GPO %q [%s])\n", f.Severity.label(), f.Category, f.GPOName, f.Scope)
		fmt.Fprintf(w, "    %s\n", f.Reason)
		if f.Detail != "" {
			fmt.Fprintf(w, "    %s\n", f.Detail)
		}
		if f.Reference != "" {
			fmt.Fprintf(w, "    ref: %s\n", f.Reference)
		}
		if f.Writable != nil {
			fmt.Fprintf(w, "    writable: %s grants %s on %s (%s)\n",
				f.Writable.Trustee.String(), strings.Join(f.Writable.Rights, "|"),
				f.Writable.Path, f.Writable.Surface)
		}
		if n := len(f.AffectedComputers); n > 0 {
			fmt.Fprintf(w, "    affects %d computer(s); run '%s query -g %s' to list them\n", n, os.Args[0], f.GPO)
		}
	}
}
