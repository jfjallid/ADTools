package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	ldap "github.com/jfjallid/ldap/v3"
)

var helpSetPasswordOptions = `
    Usage: ldaptool set-password [options]

    Set-password options:
          --target         sAMAccountName or DN of the account (required)
          --reset          Administrative reset: overwrite the password
                           (requires the Reset-Password right). Only the new
                           password is needed.
          --new-password   New password (prompted if omitted)
          --old-password   Current password, for a change (prompted if omitted
                           unless --reset is set)

    The default mode is a self-service change (requires only the Change-Password
    right): you must prove the current password. Any of --old-password /
    --new-password not given on the command line is prompted for. Pass --reset
    to overwrite the password instead, which needs only the new password.

    Active Directory requires a confidential connection for password changes,
    so use --tls, --starttls, or --sasl seal.
` + helpConnectionOptions

type setPasswordCmd struct {
	target  string
	newPass string
	oldPass string
	reset   bool
}

func init() { register(&setPasswordCmd{}) }

func (c *setPasswordCmd) Name() string     { return "set-password" }
func (c *setPasswordCmd) Synopsis() string { return "Set or change an account's password (unicodePwd)" }
func (c *setPasswordCmd) Usage() string    { return helpSetPasswordOptions }

func (c *setPasswordCmd) DefineFlags(f *flag.FlagSet) {
	f.StringVar(&c.target, "target", "", "sAMAccountName or DN of the account (required)")
	f.BoolVar(&c.reset, "reset", false, "Administrative reset (overwrite) instead of a change; only the new password is needed")
	f.StringVar(&c.newPass, "new-password", "", "New password (prompted if omitted)")
	f.StringVar(&c.oldPass, "old-password", "", "Current password, for a change (prompted if omitted unless --reset)")
}

func (c *setPasswordCmd) Run(a *connArgs) error {
	if c.target == "" {
		return fmt.Errorf("--target is required for set-password")
	}
	if !a.useTLS && !a.startTLS && saslSecurityFromArgs(a) != ldap.SASLSecuritySeal {
		return fmt.Errorf("password changes require a confidential connection — add --tls, --starttls, or --sasl seal")
	}
	// Resolve the bind password first so its prompt comes before the
	// target-account prompts below; otherwise the operator sees the target's
	// current/new password prompts ahead of the bind "Enter password:" prompt.
	if err := ensurePassword(a); err != nil {
		return fmt.Errorf("reading password: %w", err)
	}
	// A change (the default, no --reset) must prove the current password;
	// prompt for any value not supplied on the command line.
	if !c.reset && c.oldPass == "" {
		pw, err := promptSecret("Enter current password: ")
		if err != nil {
			return fmt.Errorf("reading current password: %w", err)
		}
		c.oldPass = pw
	}
	if c.newPass == "" {
		pw, err := promptSecret("Enter new password: ")
		if err != nil {
			return fmt.Errorf("reading new password: %w", err)
		}
		c.newPass = pw
	}
	conn, baseDN, err := makeConnection(a)
	if err != nil {
		return err
	}
	defer conn.Close()
	return runSetPassword(conn, baseDN, c, os.Stdout)
}

// runSetPassword writes unicodePwd on the resolved target. A change (default)
// issues a single Delete(old)+Add(new) modify, proving the current password; a
// --reset issues a Replace (administrative overwrite). Shared by the CLI
// subcommand and the interactive shell command.
func runSetPassword(conn *ldap.Conn, baseDN string, c *setPasswordCmd, w io.Writer) error {
	if c.target == "" {
		return fmt.Errorf("target is required")
	}
	if c.newPass == "" {
		return fmt.Errorf("new password must not be empty")
	}
	if !c.reset && c.oldPass == "" {
		return fmt.Errorf("current password is required for a change (use --reset to overwrite instead)")
	}

	dn, err := resolveDN(conn, baseDN, c.target)
	if err != nil {
		return fmt.Errorf("resolve target %q: %w", c.target, err)
	}

	modReq := ldap.NewModifyRequest(dn, nil)
	newVal := string(encodeUTF16LE("\"" + c.newPass + "\""))
	mode := "changed"
	if c.reset {
		modReq.Replace("unicodePwd", []string{newVal})
		mode = "reset"
	} else {
		oldVal := string(encodeUTF16LE("\"" + c.oldPass + "\""))
		modReq.Delete("unicodePwd", []string{oldVal})
		modReq.Add("unicodePwd", []string{newVal})
	}

	if err := conn.Modify(modReq); err != nil {
		return fmt.Errorf("password change failed: %w", err)
	}

	fmt.Fprintf(w, "Password %s for: %s\n", mode, dn)
	return nil
}
