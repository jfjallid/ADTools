package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

type queryCmd struct {
	cache    string
	gpo      string
	computer string
	settings bool
}

func init() { register(&queryCmd{}) }

func (c *queryCmd) Name() string          { return "query" }
func (c *queryCmd) Synopsis() string      { return "Map GPOs to affected computers (and vice versa)" }
func (c *queryCmd) NeedsConnection() bool { return false }

func (c *queryCmd) DefineFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.cache, "cache", "", "Cache file (default: newest cache_gpoparser_*.json)")
	fs.StringVar(&c.cache, "c", "", "Cache file (short)")
	fs.StringVar(&c.gpo, "gpo", "", "GPO GUID or display-name substring")
	fs.StringVar(&c.gpo, "g", "", "GPO (short)")
	fs.StringVar(&c.computer, "computer", "", "Computer name, DNS name or DN substring")
	fs.StringVar(&c.computer, "C", "", "Computer (short)")
	fs.BoolVar(&c.settings, "settings", false, "Also print the settings each applied GPO contributes")
}

func (c *queryCmd) Usage() string {
	return `
    Usage: ` + os.Args[0] + ` query [-c cache.json] (-g GPO | -C computer) [--settings]

    With -g: lists the computers a GPO applies to.
    With -C: lists the GPOs that apply to a computer (most→least specific),
             optionally with the settings each one contributes (--settings).

    Options:
      -c, --cache     Cache file (default: newest cache_gpoparser_*.json in cwd)
      -g, --gpo       GPO GUID or display-name substring
      -C, --computer  Computer name, DNS name or DN substring
          --settings  Print the settings each applied GPO contributes (-C only)
`
}

func (c *queryCmd) Run(_ *connArgs) error {
	if c.gpo == "" && c.computer == "" {
		return fmt.Errorf("specify -g (GPO) or -C (computer)")
	}
	path, err := resolveCachePath(c.cache)
	if err != nil {
		return err
	}
	cache, err := loadCache(path)
	if err != nil {
		return err
	}

	if c.computer != "" {
		return c.queryComputer(cache)
	}
	return c.queryGPO(cache)
}

func (c *queryCmd) queryGPO(cache *Cache) error {
	gpos := cache.findGPOs(c.gpo)
	if len(gpos) == 0 {
		return fmt.Errorf("no GPOs match %q", c.gpo)
	}
	dnsByDN := map[string]*Computer{}
	for _, comp := range cache.Computers {
		dnsByDN[comp.DN] = comp
	}
	for _, g := range gpos {
		fmt.Printf("\n%s: %s\n", g.GUID, g.Name)
		if len(g.AffectedComputers) == 0 {
			fmt.Println("  (no computers resolved — GPO may be unlinked, site-linked, or have no targets)")
			continue
		}
		fmt.Printf("  This GPO applies to the following %d computer(s):\n", len(g.AffectedComputers))
		for _, dn := range g.AffectedComputers {
			label := dn
			if comp := dnsByDN[dn]; comp != nil && comp.DNSHostName != "" {
				label = comp.DNSHostName + "  (" + dn + ")"
			}
			fmt.Printf("    - %s\n", label)
		}
	}
	return nil
}

func (c *queryCmd) queryComputer(cache *Cache) error {
	matches := matchComputers(cache, c.computer)
	if len(matches) == 0 {
		return fmt.Errorf("no computers match %q", c.computer)
	}
	for _, comp := range matches {
		name := comp.DNSHostName
		if name == "" {
			name = comp.Name
		}
		fmt.Printf("\n%s\n  %s\n", name, comp.DN)
		if len(comp.GPOs) == 0 {
			fmt.Println("  (no GPOs apply)")
			continue
		}
		fmt.Println("  GPOs applied (in application order, least→most specific; later wins):")
		for _, guid := range comp.GPOs {
			g := cache.gpoByGUID(guid)
			name := guid
			if g != nil {
				name = g.Name
			}
			fmt.Printf("    - %s: %s\n", guid, name)
			if c.settings && g != nil {
				printGPOSettingsIndented(g)
			}
		}
	}
	return nil
}

func printGPOSettingsIndented(g *GPO) {
	for _, gm := range g.Computer.GroupMemberships {
		if len(gm.Members) == 0 {
			continue
		}
		fmt.Printf("        adds to %s: ", gm.Group.String())
		var names []string
		for _, m := range gm.Members {
			names = append(names, m.String())
		}
		fmt.Println(strings.Join(names, ", "))
	}
	for _, p := range g.Computer.Privileges {
		if p.Dangerous {
			fmt.Printf("        [!] grants %s\n", p.Privilege)
		}
	}
}

func matchComputers(cache *Cache, filter string) []*Computer {
	lf := lowerTrim(strings.TrimSuffix(filter, "$"))
	isDN := strings.Contains(filter, "=")
	var out []*Computer
	for _, comp := range cache.Computers {
		switch {
		case isDN && lowerContains(comp.DN, lowerTrim(filter)):
			out = append(out, comp)
		case !isDN && (lowerContains(comp.Name, lf) || lowerContains(comp.DNSHostName, lf)):
			out = append(out, comp)
		}
	}
	return out
}
