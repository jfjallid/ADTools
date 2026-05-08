package main

import (
	"flag"
	"fmt"

	ldap "github.com/jfjallid/ldap/v3"
)

var helpSPNOptions = `
    Usage: ldaptool spn [options]

    Set SPN options:
          --dn       DN of the object to set SPNs on (required)
          --add      SPN to add (repeatable, e.g. HTTP/app.corp.local)
          --remove   SPN to remove (repeatable)
          --replace  Replace all SPNs with these values (repeatable)
` + helpConnectionOptions

type spnFlag struct {
	values []string
}

func (f *spnFlag) String() string { return "" }

func (f *spnFlag) Set(val string) error {
	f.values = append(f.values, val)
	return nil
}

type spnCmd struct {
	dn         string
	spnAdd     spnFlag
	spnRemove  spnFlag
	spnReplace spnFlag
}

func init() { register(&spnCmd{}) }

func (c *spnCmd) Name() string     { return "spn" }
func (c *spnCmd) Synopsis() string { return "Manage servicePrincipalName on an object" }
func (c *spnCmd) Usage() string    { return helpSPNOptions }

func (c *spnCmd) DefineFlags(f *flag.FlagSet) {
	f.StringVar(&c.dn, "dn", "", "DN of the object to set SPNs on (required)")
	f.Var(&c.spnAdd, "add", "SPN to add (repeatable)")
	f.Var(&c.spnRemove, "remove", "SPN to remove (repeatable)")
	f.Var(&c.spnReplace, "replace", "Replace all SPNs with these (repeatable)")
}

func (c *spnCmd) Run(a *connArgs) error {
	if err := ensurePassword(a); err != nil {
		return fmt.Errorf("reading password: %w", err)
	}
	conn, _, err := makeConnection(a)
	if err != nil {
		return err
	}
	defer conn.Close()
	return runSPN(conn, c)
}

func runSPN(conn *ldap.Conn, c *spnCmd) error {
	if c.dn == "" {
		return fmt.Errorf("--dn is required for spn")
	}
	if len(c.spnAdd.values) == 0 && len(c.spnRemove.values) == 0 && len(c.spnReplace.values) == 0 {
		return fmt.Errorf("at least one --add, --remove, or --replace flag is required")
	}

	modReq := ldap.NewModifyRequest(c.dn, nil)
	if len(c.spnReplace.values) > 0 {
		modReq.Replace("servicePrincipalName", c.spnReplace.values)
	}
	if len(c.spnAdd.values) > 0 {
		modReq.Add("servicePrincipalName", c.spnAdd.values)
	}
	if len(c.spnRemove.values) > 0 {
		modReq.Delete("servicePrincipalName", c.spnRemove.values)
	}

	if err := conn.Modify(modReq); err != nil {
		return fmt.Errorf("SPN modification failed: %w", err)
	}

	fmt.Printf("SPN updated on: %s\n", c.dn)
	for _, s := range c.spnReplace.values {
		fmt.Printf("  replaced → %s\n", s)
	}
	for _, s := range c.spnAdd.values {
		fmt.Printf("  added → %s\n", s)
	}
	for _, s := range c.spnRemove.values {
		fmt.Printf("  removed → %s\n", s)
	}
	return nil
}
