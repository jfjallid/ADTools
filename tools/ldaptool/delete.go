package main

import (
	"flag"
	"fmt"

	ldap "github.com/jfjallid/ldap/v3"
)

var helpDeleteOptions = `
    Usage: ldaptool delete-object [options]

    Delete an LDAP object by DN. The object is removed from the directory
    via an LDAP DelRequest; subtree deletion is not performed, so the DN
    must be a leaf (no children) unless the directory permits otherwise.

          --dn       DN of the object to delete (required)
` + helpConnectionOptions

type deleteCmd struct {
	dn string
}

func init() { register(&deleteCmd{}) }

func (c *deleteCmd) Name() string     { return "delete-object" }
func (c *deleteCmd) Synopsis() string { return "Delete an LDAP object by DN" }
func (c *deleteCmd) Usage() string    { return helpDeleteOptions }

func (c *deleteCmd) DefineFlags(f *flag.FlagSet) {
	f.StringVar(&c.dn, "dn", "", "DN of the object to delete (required)")
}

func (c *deleteCmd) Run(a *connArgs) error {
	if err := ensurePassword(a); err != nil {
		return fmt.Errorf("reading password: %w", err)
	}
	conn, _, err := makeConnection(a)
	if err != nil {
		return err
	}
	defer conn.Close()
	return runDelete(conn, c)
}

func runDelete(conn *ldap.Conn, c *deleteCmd) error {
	if c.dn == "" {
		return fmt.Errorf("--dn is required for delete-object")
	}
	if err := conn.Del(ldap.NewDelRequest(c.dn, nil)); err != nil {
		return fmt.Errorf("delete failed: %w", err)
	}
	fmt.Printf("Deleted: %s\n", c.dn)
	return nil
}
