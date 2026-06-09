package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

type localCmd struct {
	sysvol  string
	ldapDir string
	format  string
	output  string
}

func init() { register(&localCmd{}) }

func (c *localCmd) Name() string { return "local" }
func (c *localCmd) Synopsis() string {
	return "Parse GPOs offline from a local SYSVOL copy + LDAP dump"
}
func (c *localCmd) NeedsConnection() bool { return false }

func (c *localCmd) DefineFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.sysvol, "sysvol", "", "Path to a local SYSVOL Policies copy (required)")
	fs.StringVar(&c.ldapDir, "ldap", "", "Path to an LDAP dump (ldeep dir or ADExplorer objects.ndjson)")
	fs.StringVar(&c.format, "format", "", "LDAP dump format: ldeep | adexplorer (auto-detected if omitted)")
	fs.StringVar(&c.format, "f", "", "LDAP dump format (short)")
	fs.StringVar(&c.output, "output", "", "Output cache file (default: cache_gpoparser_<timestamp>.json)")
	fs.StringVar(&c.output, "o", "", "Output cache file (short)")
}

func (c *localCmd) Usage() string {
	return `
    Usage: ` + os.Args[0] + ` local --sysvol <dir> [--ldap <dir> -f ldeep|adexplorer] [-o cache.json]

    Offline analysis. Parses the GPO files in a local SYSVOL Policies copy and,
    when an LDAP dump is supplied, resolves GPO names, OU/domain links and the
    affected computers. Without --ldap, GPOs are discovered from the SYSVOL
    folder names only (no link/computer mapping).

    Collect inputs with e.g.:
      mkdir sysvol && cd sysvol && \
        echo -e 'prompt\nrecurse\nmget *' | smbclient //DC/SYSVOL -U user%pass
      ldeep ldap -u user -p pass -d corp -s ldap://DC all ./ldap/dump

    Options:
          --sysvol   Local SYSVOL Policies directory (required)
          --ldap     LDAP dump directory (ldeep) or objects.ndjson (ADExplorer)
      -f, --format   ldeep | adexplorer (auto-detected if omitted)
      -o, --output   Output cache file (default cache_gpoparser_<timestamp>.json)
`
}

func (c *localCmd) Run(_ *connArgs) error {
	if c.sysvol == "" {
		return fmt.Errorf("--sysvol is required")
	}

	cache := &Cache{}
	if c.ldapDir != "" {
		gpos, ous, comps, baseDN, domSID, fqdn, err := loadDump(c.ldapDir, c.format)
		if err != nil {
			return fmt.Errorf("loading LDAP dump: %w", err)
		}
		cache.GPOs, cache.OUs, cache.Computers = gpos, ous, comps
		cache.BaseDN, cache.DomainSID, cache.DomainFQDN = baseDN, domSID, fqdn
		logger.Infof("[*] Loaded %d GPOs, %d containers, %d computers from dump\n", len(gpos), len(ous), len(comps))
	} else {
		logger.Noticeln("[*] No --ldap dump supplied; discovering GPOs from SYSVOL folder names only")
	}

	src, err := newLocalSource(c.sysvol)
	if err != nil {
		return err
	}
	defer src.Close()

	if len(cache.GPOs) == 0 {
		cache.GPOs = gposFromSysvol(src)
		if len(cache.GPOs) == 0 {
			return fmt.Errorf("no GPO {GUID} folders found under %s", c.sysvol)
		}
	}

	parseAllGPOs(src, cache.GPOs)
	cache.buildMappings()
	enrichPrincipals(cache, newSIDResolver(nil, "", "")) // offline: well-known names only

	out := c.output
	if out == "" {
		out = defaultCachePath()
	}
	if err := saveCache(out, cache); err != nil {
		return err
	}
	logger.Noticef("[+] Wrote %d GPOs to %s\n", len(cache.GPOs), out)
	fmt.Printf("Run 'gpoparser display -c %s' to view parsed settings.\n", out)
	return nil
}

// gposFromSysvol discovers GPOs by their {GUID} folder names under the SYSVOL
// Policies directory (used when no LDAP dump is available).
func gposFromSysvol(src *localSource) []*GPO {
	entries, err := os.ReadDir(src.policiesDir)
	if err != nil {
		return nil
	}
	var gpos []*GPO
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, "{") || !strings.HasSuffix(name, "}") {
			continue
		}
		guid := normalizeGUID(name)
		gpos = append(gpos, &GPO{GUID: guid, Name: guid})
	}
	return gpos
}
