package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jfjallid/go-smb/msdtyp"
	ldap "github.com/jfjallid/ldap/v3"
)

// The `owner` subcommand views and changes the Owner SID of an object's
// nTSecurityDescriptor (cf. impacket's owneredit.py).
//
// Why this matters: the owner of an AD object holds an implicit, irrevocable
// WRITE_DAC right over it regardless of the DACL, so an attacker with WriteOwner
// over a target can take ownership and then re-write the DACL to grant
// themselves an abusable right (DCSync, ResetPassword, etc.). Reading and
// restoring the owner is the corresponding defensive/remediation operation.
//
// Security-descriptor read/parse plumbing is shared with the `dacl` subcommand
// (lookupTargetSD, parseSD, resolveTrusteeSID, the SD-flags control). Writes are
// scoped to the owner via sdFlagOwnerOnly so the DACL/group/SACL are untouched.

var helpOwnerOptions = `
    Usage: ldaptool owner [options]

    View and change the Owner SID of an object's nTSecurityDescriptor.

    Options:
          --action       read | set | backup | restore (required)
          --target       Object to operate on: sAMAccountName, DN, or SID
                         (required)
          --owner        New owner: sAMAccountName, DN, or SID
                         (required for set)
          --file         File path for backup/restore (the owner SID)
          --resolve-sids Resolve SIDs to names in read output

    Examples:
      owner --action read    --target dc01 --resolve-sids
      owner --action backup  --target victim --file victim.owner
      owner --action set     --target victim --owner attacker
      owner --action restore --target victim --file victim.owner
` + helpConnectionOptions

type ownerCmd struct {
	action      string
	target      string
	owner       string
	file        string
	resolveSIDs bool
}

func init() { register(&ownerCmd{}) }

func (c *ownerCmd) Name() string { return "owner" }
func (c *ownerCmd) Synopsis() string {
	return "View and change the owner SID of an object's security descriptor"
}
func (c *ownerCmd) Usage() string { return helpOwnerOptions }

func (c *ownerCmd) DefineFlags(f *flag.FlagSet) {
	f.StringVar(&c.action, "action", "", "Action: read, set, backup, restore (required)")
	f.StringVar(&c.target, "target", "", "Target object: sAMAccountName, DN, or SID (required)")
	f.StringVar(&c.owner, "owner", "", "New owner: sAMAccountName, DN, or SID (required for set)")
	f.StringVar(&c.file, "file", "", "File path for backup/restore (the owner SID)")
	f.BoolVar(&c.resolveSIDs, "resolve-sids", false, "Resolve SIDs to names in read output")
}

func (c *ownerCmd) validate() error {
	if c.target == "" {
		return fmt.Errorf("--target is required")
	}
	switch c.action {
	case "read":
	case "set":
		if c.owner == "" {
			return fmt.Errorf("--owner is required for action %q", c.action)
		}
	case "backup", "restore":
		if c.file == "" {
			return fmt.Errorf("--file is required for action %q", c.action)
		}
	case "":
		return fmt.Errorf("--action is required")
	default:
		return fmt.Errorf("unknown --action %q (valid: read, set, backup, restore)", c.action)
	}
	return nil
}

func (c *ownerCmd) Run(a *connArgs) error {
	if err := c.validate(); err != nil {
		return err
	}
	if err := ensurePassword(a); err != nil {
		return fmt.Errorf("reading password: %w", err)
	}
	conn, baseDN, err := makeConnection(a)
	if err != nil {
		return err
	}
	defer conn.Close()
	return runOwner(conn, baseDN, c, os.Stdout)
}

func runOwner(conn *ldap.Conn, baseDN string, c *ownerCmd, w io.Writer) error {
	dn, blob, _, err := lookupTargetSD(conn, baseDN, c.target)
	if err != nil {
		return err
	}

	switch c.action {
	case "read":
		return ownerRead(conn, baseDN, c, dn, blob, w)
	case "backup":
		return ownerBackup(c, dn, blob, w)
	case "set":
		return ownerApply(conn, baseDN, dn, blob, c.owner, w)
	case "restore":
		data, rerr := os.ReadFile(c.file)
		if rerr != nil {
			return fmt.Errorf("reading backup: %w", rerr)
		}
		sid := strings.TrimSpace(string(data))
		if sid == "" {
			return fmt.Errorf("backup file %s is empty", c.file)
		}
		return ownerApply(conn, baseDN, dn, blob, sid, w)
	}
	return fmt.Errorf("unreachable")
}

func ownerRead(conn *ldap.Conn, baseDN string, c *ownerCmd, dn string, blob []byte, w io.Writer) error {
	sd, err := parseSD(blob)
	if err != nil {
		return err
	}
	resolver := newSIDResolver(conn, baseDN, c.resolveSIDs)
	fmt.Fprintf(w, "Owner of %s\n", dn)
	if sd.OwnerSid == nil {
		fmt.Fprintln(w, "  (no owner present)")
		return nil
	}
	fmt.Fprintf(w, "  Owner: %s\n", resolver.format(sd.OwnerSid.ToString()))
	return nil
}

// ownerBackup writes the current owner SID to a file so it can be restored
// later. Only the owner SID is saved; use `dacl --action backup` to snapshot the
// full security descriptor.
func ownerBackup(c *ownerCmd, dn string, blob []byte, w io.Writer) error {
	sd, err := parseSD(blob)
	if err != nil {
		return err
	}
	if sd.OwnerSid == nil {
		return fmt.Errorf("%s on %s has no owner to back up", sdAttr, dn)
	}
	sid := sd.OwnerSid.ToString()
	if err := os.WriteFile(c.file, []byte(sid+"\n"), 0600); err != nil {
		return fmt.Errorf("writing backup: %w", err)
	}
	fmt.Fprintf(w, "Backed up owner of %s (%s) to %s\n", dn, sid, c.file)
	return nil
}

// ownerApply resolves ownerSpec (a SID or sAMAccountName/DN) to a SID, replaces
// the descriptor's owner, and writes it back scoped to the owner only.
func ownerApply(conn *ldap.Conn, baseDN, dn string, blob []byte, ownerSpec string, w io.Writer) error {
	sidStr, err := resolveTrusteeSID(conn, baseDN, ownerSpec)
	if err != nil {
		return err
	}
	newSID, err := msdtyp.ConvertStrToSID(sidStr)
	if err != nil {
		return fmt.Errorf("invalid owner SID %q: %w", sidStr, err)
	}
	sd, err := parseSD(blob)
	if err != nil {
		return err
	}
	old := "(none)"
	if sd.OwnerSid != nil {
		old = sd.OwnerSid.ToString()
	}
	sd.OwnerSid = newSID
	if err := writeOwnerSD(conn, dn, sd); err != nil {
		return err
	}
	fmt.Fprintf(w, "Owner of %s changed: %s -> %s\n", dn, old, sidStr)
	return nil
}

// writeOwnerSD marshals the descriptor and replaces nTSecurityDescriptor,
// scoping the write to the owner (the SD-flags control) so the DACL/group/SACL
// are left unchanged.
func writeOwnerSD(conn *ldap.Conn, dn string, sd *msdtyp.SecurityDescriptor) error {
	blob, err := sd.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal security descriptor: %w", err)
	}
	ctl := ldap.NewControlMicrosoftSDFlags()
	ctl.Criticality = true
	ctl.ControlValue = sdFlagOwnerOnly
	mod := ldap.NewModifyRequest(dn, []ldap.Control{ctl})
	mod.Replace(sdAttr, []string{string(blob)})
	if err := conn.Modify(mod); err != nil {
		return fmt.Errorf("LDAP modify failed: %w", err)
	}
	return nil
}
