package main

import (
	"flag"
	"fmt"
	"strings"

	ldap "github.com/jfjallid/ldap/v3"
)

var helpGroupOptions = `
    Usage: ldaptool group [options]

    Group membership management.

    Options:
          --action   Action: add or remove (required)
          --group    Group, by DN or sAMAccountName (required)
          --member   Member to add/remove, by DN or sAMAccountName.
                     Repeatable.
` + helpConnectionOptions

type groupCmd struct {
	action  string
	group   string
	members repeatStrFlag
}

func init() { register(&groupCmd{}) }

func (c *groupCmd) Name() string     { return "group" }
func (c *groupCmd) Synopsis() string { return "Add or remove group members" }
func (c *groupCmd) Usage() string    { return helpGroupOptions }

func (c *groupCmd) DefineFlags(f *flag.FlagSet) {
	f.StringVar(&c.action, "action", "", "Action: add or remove (required)")
	f.StringVar(&c.group, "group", "", "Group DN or sAMAccountName (required)")
	f.Var(&c.members, "member", "Member DN or sAMAccountName (repeatable)")
}

func (c *groupCmd) Run(a *connArgs) error {
	if c.action != "add" && c.action != "remove" {
		return fmt.Errorf("--action must be add or remove")
	}
	if c.group == "" || len(c.members) == 0 {
		return fmt.Errorf("--group and at least one --member are required")
	}
	if err := ensurePassword(a); err != nil {
		return fmt.Errorf("reading password: %w", err)
	}
	conn, baseDN, err := makeConnection(a)
	if err != nil {
		return err
	}
	defer conn.Close()

	groupDN, err := resolveDN(conn, baseDN, c.group)
	if err != nil {
		return fmt.Errorf("resolve group: %w", err)
	}
	memberDNs := make([]string, 0, len(c.members))
	for _, m := range c.members {
		dn, err := resolveDN(conn, baseDN, m)
		if err != nil {
			return fmt.Errorf("resolve member %q: %w", m, err)
		}
		memberDNs = append(memberDNs, dn)
	}

	mod := ldap.NewModifyRequest(groupDN, nil)
	if c.action == "add" {
		mod.Add("member", memberDNs)
	} else {
		mod.Delete("member", memberDNs)
	}
	if err := conn.Modify(mod); err != nil {
		return fmt.Errorf("LDAP modify failed: %w", err)
	}

	verb := "Added"
	if c.action == "remove" {
		verb = "Removed"
	}
	fmt.Printf("%s on %s:\n", verb, groupDN)
	for _, dn := range memberDNs {
		fmt.Printf("  %s\n", dn)
	}
	return nil
}

// resolveDN treats v as a DN if it contains "=", otherwise looks it up by
// sAMAccountName. Both bare names and trailing-$ machine names are tried.
func resolveDN(conn *ldap.Conn, baseDN, v string) (string, error) {
	if strings.Contains(v, "=") {
		return v, nil
	}
	candidates := []string{v}
	if !strings.HasSuffix(v, "$") {
		candidates = append(candidates, v+"$")
	}
	var parts []string
	for _, c := range candidates {
		parts = append(parts, fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(c)))
	}
	filter := "(|" + strings.Join(parts, "") + ")"
	res, err := conn.Search(ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter,
		[]string{"distinguishedName"}, nil,
	))
	if err != nil {
		return "", err
	}
	switch {
	case len(res.Entries) == 0:
		return "", fmt.Errorf("not found")
	case len(res.Entries) > 1:
		return "", fmt.Errorf("multiple matches")
	}
	return res.Entries[0].DN, nil
}
