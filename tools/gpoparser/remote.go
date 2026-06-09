package main

import (
	"flag"
	"fmt"
	"os"
)

type remoteCmd struct {
	output string
}

func init() { register(&remoteCmd{}) }

func (c *remoteCmd) Name() string          { return "remote" }
func (c *remoteCmd) Synopsis() string      { return "Enumerate and parse GPOs live over LDAP + SYSVOL" }
func (c *remoteCmd) NeedsConnection() bool { return true }

func (c *remoteCmd) DefineFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.output, "output", "", "Output cache file (default: cache_gpoparser_<timestamp>.json)")
	fs.StringVar(&c.output, "o", "", "Output cache file (short)")
}

func (c *remoteCmd) Usage() string {
	return `
    Usage: ` + os.Args[0] + ` remote [connection options] [-o cache.json]

    Connects to a DC over LDAP to enumerate GPOs, OU/site links and computers,
    then reads each GPO's files from the SYSVOL share over SMB and parses them.
    The analysed result is written to a JSON cache for display/query/enrich.

    Options:
      -o, --output    Output cache file (default cache_gpoparser_<timestamp>.json)
` + helpConnectionOptions
}

func (c *remoteCmd) Run(a *connArgs) error {
	if err := ensurePassword(a); err != nil {
		return fmt.Errorf("reading password: %w", err)
	}

	conn, baseDN, err := makeConnection(a)
	if err != nil {
		return err
	}
	defer conn.Close()

	ad := newADClient(conn, baseDN)
	domSID, shortName := ad.domainInfo()
	if shortName == "" {
		shortName = a.domain
	}

	gpos, err := ad.queryGPOs()
	if err != nil {
		return err
	}
	ous, err := ad.queryLinkContainers()
	if err != nil {
		return err
	}
	comps, err := ad.queryComputers()
	if err != nil {
		return err
	}
	// Software-installation packages live in AD (not SYSVOL), so attach them
	// before reading files. A failure here is non-fatal.
	ad.queryPackages(gpos)

	cache := &Cache{
		Domain:     shortName,
		DomainFQDN: baseDNToFQDN(baseDN),
		BaseDN:     baseDN,
		DomainSID:  domSID,
		GPOs:       gpos,
		OUs:        ous,
		Computers:  comps,
	}

	// Read and parse SYSVOL files. A SYSVOL failure is non-fatal — the LDAP
	// metadata and link mapping are still useful on their own.
	if smbConn, err := newSMBConnection(a); err != nil {
		logger.Errorf("[!] SYSVOL access failed, GPO settings will be empty: %v\n", err)
	} else {
		src := &smbSource{conn: smbConn}
		parseAllGPOs(src, gpos)
		src.Close()
	}

	cache.buildMappings()
	enrichPrincipals(cache, newSIDResolver(conn, baseDN, domSID))

	out := c.output
	if out == "" {
		out = defaultCachePath()
	}
	if err := saveCache(out, cache); err != nil {
		return err
	}
	logger.Noticef("[+] Wrote %d GPOs, %d link containers, %d computers to %s\n",
		len(cache.GPOs), len(cache.OUs), len(cache.Computers), out)
	fmt.Printf("Run 'gpoparser display -c %s' to view parsed settings.\n", out)
	return nil
}
