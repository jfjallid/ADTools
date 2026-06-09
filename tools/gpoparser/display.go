package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type displayCmd struct {
	cache   string
	gpo     string
	jsonOut bool
}

func init() { register(&displayCmd{}) }

func (c *displayCmd) Name() string { return "display" }
func (c *displayCmd) Synopsis() string {
	return "Show what GPOs change (groups, privileges, registry, scripts...)"
}
func (c *displayCmd) NeedsConnection() bool { return false }

func (c *displayCmd) DefineFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.cache, "cache", "", "Cache file (default: newest cache_gpoparser_*.json)")
	fs.StringVar(&c.cache, "c", "", "Cache file (short)")
	fs.StringVar(&c.gpo, "gpo", "", "Filter by GPO GUID or display-name substring")
	fs.StringVar(&c.gpo, "g", "", "Filter by GPO (short)")
	fs.BoolVar(&c.jsonOut, "json", false, "Emit JSON instead of human-readable output")
}

func (c *displayCmd) Usage() string {
	return `
    Usage: ` + os.Args[0] + ` display [-c cache.json] [-g GPO] [--json]

    Renders the parsed configuration each GPO applies — local group membership,
    privilege rights, registry changes, scripts, scheduled tasks and services —
    split into Computer and User configuration.

    Options:
      -c, --cache   Cache file (default: newest cache_gpoparser_*.json in cwd)
      -g, --gpo     Filter by GPO GUID or display-name substring
          --json    Emit JSON instead of human-readable output
`
}

func (c *displayCmd) Run(_ *connArgs) error {
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
	if c.jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(gpos)
	}
	w := os.Stdout
	for _, g := range gpos {
		displayGPO(w, g)
	}
	return nil
}

func displayGPO(w io.Writer, g *GPO) {
	fmt.Fprintf(w, "\n=== %s  %s ===\n", g.GUID, g.Name)
	if g.empty() {
		fmt.Fprintln(w, "  (no parsed settings — empty GPO, or SYSVOL was not read)")
	} else {
		renderConfig(w, "Computer configuration", &g.Computer)
		renderConfig(w, "User configuration", &g.User)
	}
	if n := len(g.AffectedComputers); n > 0 {
		fmt.Fprintf(w, "  Applies to %d computer(s); run '%s query -g %s' to list them.\n", n, os.Args[0], g.GUID)
	}
}

func renderConfig(w io.Writer, label string, cs *ConfigSettings) {
	if cs.empty() {
		return
	}
	fmt.Fprintf(w, "  %s:\n", label)

	if len(cs.GroupMemberships) > 0 {
		fmt.Fprintln(w, "    Groups:")
		for _, gm := range cs.GroupMemberships {
			if len(gm.Members) > 0 {
				fmt.Fprintf(w, "      The following principals are added to %s [%s, %s]:\n",
					gm.Group.String(), nonEmpty(gm.Action, "set"), gm.Source)
				for _, m := range gm.Members {
					fmt.Fprintf(w, "        - %s\n", m.String())
				}
			}
			for _, mo := range gm.MemberOf {
				fmt.Fprintf(w, "      %s is made a member of %s\n", gm.Group.String(), mo.String())
			}
		}
	}

	if len(cs.Privileges) > 0 {
		fmt.Fprintln(w, "    Privilege rights:")
		for _, p := range cs.Privileges {
			flag := ""
			if p.Dangerous {
				flag = "  [!] " + p.Description
			}
			fmt.Fprintf(w, "      %s%s\n", p.Privilege, flag)
			for _, m := range p.Members {
				fmt.Fprintf(w, "        - %s\n", m.String())
			}
		}
	}

	if len(cs.RegistryValues) > 0 {
		fmt.Fprintln(w, "    Registry:")
		for _, r := range cs.RegistryValues {
			loc := r.Key
			if r.Hive != "" {
				loc = r.Hive + `\` + r.Key
			}
			line := loc
			if r.Name != "" {
				line += `\` + r.Name
			}
			act := ""
			if r.Action != "" {
				act = "[" + r.Action + "] "
			}
			fmt.Fprintf(w, "      %s%s = (%s) %s  {%s}\n", act, line, nonEmpty(r.Type, "?"), truncate(r.Value, 120), r.Source)
		}
	}

	if len(cs.SystemAccess) > 0 {
		fmt.Fprintln(w, "    System access (password/lockout policy):")
		for _, kv := range cs.SystemAccess {
			fmt.Fprintf(w, "      %s = %s\n", kv.Key, kv.Value)
		}
	}

	if len(cs.LocalUsers) > 0 {
		fmt.Fprintln(w, "    Local users:")
		for _, u := range cs.LocalUsers {
			cpw := ""
			if u.CPassword != "" {
				cpw = "  [!] stored GPP password (cpassword) present — recoverable; run 'assess'"
			}
			fmt.Fprintf(w, "      %s (%s)%s\n", nonEmpty(u.UserName, u.Name), nonEmpty(u.Action, "set"), cpw)
		}
	}

	if len(cs.Services) > 0 {
		fmt.Fprintln(w, "    Services:")
		for _, s := range cs.Services {
			parts := []string{}
			if s.StartType != "" {
				parts = append(parts, "start="+s.StartType)
			}
			if s.Action != "" {
				parts = append(parts, "action="+s.Action)
			}
			if s.Account != "" {
				parts = append(parts, "account="+s.Account)
			}
			fmt.Fprintf(w, "      %s (%s)\n", s.Name, strings.Join(parts, ", "))
		}
	}

	if len(cs.Scripts) > 0 {
		fmt.Fprintln(w, "    Scripts:")
		for _, s := range cs.Scripts {
			kind := s.Type
			if s.PowerShell {
				kind += " (PowerShell)"
			}
			fmt.Fprintf(w, "      [%s #%d] %s %s\n", kind, s.Order, s.CmdLine, s.Parameters)
		}
	}

	if len(cs.ScheduledTasks) > 0 {
		fmt.Fprintln(w, "    Scheduled tasks:")
		for _, t := range cs.ScheduledTasks {
			runAs := ""
			if t.RunAs != "" {
				runAs = "  runAs=" + t.RunAs
			}
			fmt.Fprintf(w, "      %s (%s, %s): %s %s%s%s\n", t.Name, t.Type, nonEmpty(t.Action, "?"), t.Command, t.Arguments, runAs, cpasswordNote(t.CPassword))
		}
	}

	if len(cs.SoftwareInstalls) > 0 {
		fmt.Fprintln(w, "    Software installs (MSI):")
		for _, si := range cs.SoftwareInstalls {
			fmt.Fprintf(w, "      %s: %s\n", si.Name, si.Path)
		}
	}

	if len(cs.Drives) > 0 {
		fmt.Fprintln(w, "    Mapped drives:")
		for _, d := range cs.Drives {
			fmt.Fprintf(w, "      %s -> %s%s%s\n", nonEmpty(d.Letter, "?"), d.Path, userNote(d.UserName), cpasswordNote(d.CPassword))
		}
	}

	if len(cs.Files) > 0 {
		fmt.Fprintln(w, "    File copies:")
		for _, f := range cs.Files {
			fmt.Fprintf(w, "      %s -> %s\n", f.FromPath, f.TargetPath)
		}
	}

	if len(cs.Shortcuts) > 0 {
		fmt.Fprintln(w, "    Shortcuts:")
		for _, s := range cs.Shortcuts {
			fmt.Fprintf(w, "      %s -> %s %s\n", s.Name, s.TargetPath, s.Arguments)
		}
	}

	if len(cs.DataSources) > 0 {
		fmt.Fprintln(w, "    Data sources:")
		for _, d := range cs.DataSources {
			fmt.Fprintf(w, "      %s (%s)%s%s\n", nonEmpty(d.Name, d.DSN), d.Driver, userNote(d.UserName), cpasswordNote(d.CPassword))
		}
	}

	if len(cs.Printers) > 0 {
		fmt.Fprintln(w, "    Printers:")
		for _, p := range cs.Printers {
			fmt.Fprintf(w, "      %s %s%s%s\n", p.Name, p.Path, userNote(p.UserName), cpasswordNote(p.CPassword))
		}
	}

	if len(cs.EnvVars) > 0 {
		fmt.Fprintln(w, "    Environment variables:")
		for _, e := range cs.EnvVars {
			fmt.Fprintf(w, "      %s = %s\n", e.Name, truncate(e.Value, 120))
		}
	}
}

// cpasswordNote flags (without decrypting) that a GPP password is present.
func cpasswordNote(cpw string) string {
	if cpw == "" {
		return ""
	}
	return "  [!] stored GPP password (cpassword) present — recoverable; run 'assess'"
}

func userNote(user string) string {
	if user == "" {
		return ""
	}
	return "  as " + user
}

func nonEmpty(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// resolveCachePath returns the explicit cache path, or the newest
// cache_gpoparser_*.json in the working directory.
func resolveCachePath(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	matches, _ := filepath.Glob("cache_gpoparser_*.json")
	if len(matches) == 0 {
		return "", fmt.Errorf("no --cache given and no cache_gpoparser_*.json found in current directory")
	}
	sort.Strings(matches)
	return matches[len(matches)-1], nil // newest by lexical timestamp
}
