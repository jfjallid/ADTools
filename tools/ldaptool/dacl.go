package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/jfjallid/go-smb/msdtyp"
	ldap "github.com/jfjallid/ldap/v3"
)

// The `dacl` subcommand views and edits the discretionary ACL (DACL) of the
// nTSecurityDescriptor on arbitrary AD objects: read with friendly-name
// translation and optional SID resolution, add an ACE granting a trustee a
// permission, remove a specific ACE, and backup/restore the raw descriptor.
//
// Object ACEs (extended rights such as DCSync / ResetPassword and per-property
// writes) are supported via go-smb/msdtyp; friendly-name tables and the rights
// presets live in dacl_rights.go.

const (
	sdAttr = "nTSecurityDescriptor"

	// LDAP_SERVER_SD_FLAGS values (SECURITY_INFORMATION). Reads request
	// OWNER|GROUP|DACL so SACL access (SeSecurityPrivilege) is not needed;
	// writes scope to DACL only so owner/group/SACL are left untouched.
	sdFlagOwnerGroupDacl int32 = 0x1 | 0x2 | 0x4
	sdFlagDaclOnly       int32 = 0x4
	// Owner writes scope to OWNER only so the DACL/group/SACL are left
	// untouched (used by the `owner` subcommand in owner.go).
	sdFlagOwnerOnly int32 = 0x1
)

var helpDACLOptions = `
    Usage: ldaptool dacl [options]

    View and modify the DACL on an object's nTSecurityDescriptor.

    Options:
          --action     read | add | remove | backup | restore (required)
          --target     Object to operate on: sAMAccountName, DN, or SID
                       (required)
          --trustee    Principal the ACE applies to: sAMAccountName, DN, or
                       SID (required for add/remove)
          --rights     Named right preset (repeatable). One of:
                       FullControl, DCSync, ResetPassword, WriteMembers,
                       AllExtendedRights, WriteDacl, WriteOwner
          --mask       Raw ACCESS_MASK, hex (0x..) or decimal, e.g. 0x000F01FF
          --right-guid Extended-right/property GUID for an object ACE
                       (repeatable)
          --ace-type   allowed | denied (default allowed)
          --inheritance            Set CONTAINER_INHERIT_ACE on added ACEs
                                   (the ACE applies to the target and propagates
                                   to descendant objects). This is the flag AD
                                   uses for inheritance; every AD object is a
                                   container in the ACL model.
          --inherit-only           Set INHERIT_ONLY_ACE on added ACEs: the ACE
                                   does NOT apply to the target itself, only to
                                   inheriting children. Requires --inheritance
                                   to have any effect.
          --ace-flags              Raw ACE flags byte (hex 0x.. or decimal) as an
                                   alternative to --inheritance/--inherit-only,
                                   e.g. 0x0A for CONTAINER_INHERIT|INHERIT_ONLY.
                                   Mutually exclusive with those two flags.
          --inherited-object-guid  Schema GUID for INHERITED_OBJECT_TYPE: scope
                                   inheritance to one descendant object class
                                   (e.g. computer = bf967a86-0de6-11d0-a285-
                                   00aa003049e2). Combine with --inheritance
                                   --inherit-only.
          --resolve-sids           Resolve SIDs to names in read output, and
                                   resolve unknown object GUIDs live from the
                                   forest (Extended-Rights / schema)
          --file       File path for backup/restore (base64 of the raw SD)

    For action=remove, an ACE matches on trustee, type, mask, and object GUIDs
    (--right-guid / --inherited-object-guid). ACE flags are ignored by default,
    so a grant is removed regardless of its inheritance settings; pass any of
    --inheritance/--inherit-only/--ace-flags to additionally require an exact
    ACE-flags match (e.g. to remove the inherit-only copy but not another).

    Examples:
      dacl --action read --target krbtgt --resolve-sids
      dacl --action add  --target dc01 --trustee evil --rights DCSync
      dacl --action add  --target bob  --trustee evil --rights ResetPassword
      dacl --action remove --target bob --trustee evil --rights ResetPassword
      dacl --action backup --target bob --file bob.sd
` + helpConnectionOptions

type daclCmd struct {
	action       string
	target       string
	trustee      string
	rights       repeatStrFlag
	maskStr      string
	rightGUIDs   repeatStrFlag
	aceType      string
	inheritance  bool
	inheritOnly  bool
	aceFlagsHex  string
	inheritedOID string
	resolveSIDs  bool
	file         string
}

func init() { register(&daclCmd{}) }

func (c *daclCmd) Name() string     { return "dacl" }
func (c *daclCmd) Synopsis() string { return "View and modify DACLs on object security descriptors" }
func (c *daclCmd) Usage() string    { return helpDACLOptions }

func (c *daclCmd) DefineFlags(f *flag.FlagSet) {
	f.StringVar(&c.action, "action", "", "Action: read, add, remove, backup, restore (required)")
	f.StringVar(&c.target, "target", "", "Target object: sAMAccountName, DN, or SID (required)")
	f.StringVar(&c.trustee, "trustee", "", "Principal for the ACE: sAMAccountName, DN, or SID")
	f.Var(&c.rights, "rights", "Named right preset (repeatable): "+presetNames())
	f.StringVar(&c.maskStr, "mask", "", "Raw ACCESS_MASK (hex 0x.. or decimal)")
	f.Var(&c.rightGUIDs, "right-guid", "Extended-right/property GUID for an object ACE (repeatable)")
	f.StringVar(&c.aceType, "ace-type", "allowed", "ACE type: allowed or denied")
	f.BoolVar(&c.inheritance, "inheritance", false, "Set CONTAINER_INHERIT_ACE on added ACEs")
	f.BoolVar(&c.inheritOnly, "inherit-only", false, "Set INHERIT_ONLY_ACE: ACE applies only to inheriting children, not the target")
	f.StringVar(&c.aceFlagsHex, "ace-flags", "", "Raw ACE flags byte (hex 0x.. or decimal); alternative to --inheritance/--inherit-only, e.g. 0x0A")
	f.StringVar(&c.inheritedOID, "inherited-object-guid", "", "Schema GUID to scope inheritance to one descendant class (combine with --inheritance --inherit-only)")
	f.BoolVar(&c.resolveSIDs, "resolve-sids", false, "Resolve SIDs to names, and unknown object GUIDs live from the forest, in read output")
	f.StringVar(&c.file, "file", "", "File path for backup/restore")
}

func (c *daclCmd) Run(a *connArgs) error {
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
	return runDACL(conn, baseDN, c, os.Stdout)
}

func (c *daclCmd) validate() error {
	if c.target == "" {
		return fmt.Errorf("--target is required")
	}
	switch c.action {
	case "read":
	case "add", "remove":
		if c.trustee == "" {
			return fmt.Errorf("--trustee is required for action %q", c.action)
		}
		if len(c.rights) == 0 && c.maskStr == "" && len(c.rightGUIDs) == 0 {
			return fmt.Errorf("specify at least one of --rights, --mask, --right-guid for action %q", c.action)
		}
		// INHERIT_ONLY without CONTAINER_INHERIT yields an ACE that applies to
		// nothing (neither the target nor any child), so reject it as almost
		// certainly a mistake. Only meaningful for add; remove matches on
		// type/mask/GUID and ignores ACE flags (acesEquivalent).
		if c.action == "add" && c.inheritOnly && !c.inheritance {
			return fmt.Errorf("--inherit-only requires --inheritance; an inherit-only ACE with no inheritance flag applies to nothing")
		}
	case "backup", "restore":
		if c.file == "" {
			return fmt.Errorf("--file is required for action %q", c.action)
		}
	case "":
		return fmt.Errorf("--action is required")
	default:
		return fmt.Errorf("unknown --action %q (valid: read, add, remove, backup, restore)", c.action)
	}
	switch strings.ToLower(c.aceType) {
	case "", "allowed", "denied": // empty defaults to allowed (see aceTypeByte)
	default:
		return fmt.Errorf("--ace-type must be 'allowed' or 'denied', got %q", c.aceType)
	}
	// --ace-flags is a raw alternative to the inheritance booleans; allowing both
	// would be ambiguous (which wins?), so require exactly one source of flags.
	if c.aceFlagsHex != "" && (c.inheritance || c.inheritOnly) {
		return fmt.Errorf("--ace-flags is mutually exclusive with --inheritance/--inherit-only; specify flags one way")
	}
	if _, err := c.parsedAceFlags(); err != nil {
		return err
	}
	return nil
}

func (c *daclCmd) aceTypeByte() byte {
	if strings.EqualFold(c.aceType, "denied") {
		return msdtyp.AccessDeniedAceType
	}
	return msdtyp.AccessAllowedAceType
}

func (c *daclCmd) parsedMask() (uint32, error) {
	if c.maskStr == "" {
		return 0, nil
	}
	s := strings.TrimSpace(c.maskStr)
	base := 10
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		s = s[2:]
		base = 16
	}
	v, err := strconv.ParseUint(s, base, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid --mask %q: %w", c.maskStr, err)
	}
	return uint32(v), nil
}

func runDACL(conn *ldap.Conn, baseDN string, c *daclCmd, w io.Writer) error {
	dn, blob, classes, err := lookupTargetSD(conn, baseDN, c.target)
	if err != nil {
		return err
	}

	switch c.action {
	case "read":
		return daclRead(conn, baseDN, c, dn, blob, classes, w)
	case "backup":
		return daclBackup(c, dn, blob, w)
	case "restore":
		return daclRestore(conn, c, dn, w)
	case "add":
		return daclAdd(conn, baseDN, c, dn, blob, w)
	case "remove":
		return daclRemove(conn, baseDN, c, dn, blob, w)
	}
	return fmt.Errorf("unreachable")
}

// lookupTargetSD resolves a target (sAMAccountName, DN, or SID) to its DN and
// reads its nTSecurityDescriptor (OWNER|GROUP|DACL via the SD-flags control)
// along with its objectClass values (used to gate the domain-only DCSync check).
func lookupTargetSD(conn *ldap.Conn, baseDN, target string) (string, []byte, []string, error) {
	var searchBase, filter string
	scope := ldap.ScopeWholeSubtree

	switch {
	case strings.HasPrefix(strings.ToUpper(target), "S-1-"):
		sidBytes, err := encodeSID(target)
		if err != nil {
			return "", nil, nil, fmt.Errorf("invalid target SID %q: %w", target, err)
		}
		searchBase, filter = baseDN, "(objectSid="+ldapBinaryFilter(sidBytes)+")"
	case strings.Contains(target, "="):
		// Looks like a DN: read it directly.
		searchBase, scope, filter = target, ldap.ScopeBaseObject, "(objectClass=*)"
	default:
		candidates := []string{target}
		if !strings.HasSuffix(target, "$") {
			candidates = append(candidates, target+"$")
		}
		var parts []string
		for _, cand := range candidates {
			parts = append(parts, fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(cand)))
		}
		searchBase, filter = baseDN, "(|"+strings.Join(parts, "")+")"
	}

	ctl := ldap.NewControlMicrosoftSDFlags()
	ctl.Criticality = true
	ctl.ControlValue = sdFlagOwnerGroupDacl

	res, err := conn.Search(ldap.NewSearchRequest(
		searchBase, scope, ldap.NeverDerefAliases,
		0, 0, false, filter,
		[]string{"distinguishedName", "objectClass", sdAttr},
		[]ldap.Control{ctl},
	))
	if err != nil {
		return "", nil, nil, fmt.Errorf("LDAP search failed: %w", err)
	}
	if len(res.Entries) == 0 {
		return "", nil, nil, fmt.Errorf("target %q not found", target)
	}
	if len(res.Entries) > 1 {
		return "", nil, nil, fmt.Errorf("target %q matched %d entries; be more specific", target, len(res.Entries))
	}
	entry := res.Entries[0]
	var blob []byte
	for _, attr := range entry.Attributes {
		if strings.EqualFold(attr.Name, sdAttr) && len(attr.ByteValues) > 0 {
			blob = attr.ByteValues[0]
		}
	}
	if len(blob) == 0 {
		return "", nil, nil, fmt.Errorf("no %s returned for %q (insufficient rights?)", sdAttr, target)
	}
	return entry.DN, blob, entry.GetAttributeValues("objectClass"), nil
}

// ldapBinaryFilter renders raw bytes as an LDAP filter assertion value
// (\xx-escaped per RFC 4515), suitable for matching binary attributes.
func ldapBinaryFilter(b []byte) string {
	var sb strings.Builder
	for _, v := range b {
		fmt.Fprintf(&sb, "\\%02x", v)
	}
	return sb.String()
}

func parseSD(blob []byte) (*msdtyp.SecurityDescriptor, error) {
	sd := &msdtyp.SecurityDescriptor{}
	if err := sd.UnmarshalBinary(blob); err != nil {
		return nil, fmt.Errorf("parse %s: %w", sdAttr, err)
	}
	return sd, nil
}

func daclRead(conn *ldap.Conn, baseDN string, c *daclCmd, dn string, blob []byte, objectClasses []string, w io.Writer) error {
	sd, err := parseSD(blob)
	if err != nil {
		return err
	}
	resolver := newSIDResolver(conn, baseDN, c.resolveSIDs)
	// Well-known GUIDs are always named from the static table; --resolve-sids
	// additionally lets an unknown object-ACE GUID be resolved live against the
	// target's own forest (Extended-Rights / schema), under the same opt-in as
	// SID name resolution so `dacl read` issues no extra queries by default.
	gresolver := newGUIDResolver(conn, c.resolveSIDs)

	fmt.Fprintf(w, "DACL on %s\n", dn)
	if sd.OwnerSid != nil {
		fmt.Fprintf(w, "  Owner: %s\n", resolver.format(sd.OwnerSid.ToString()))
	}
	if sd.GroupSid != nil {
		fmt.Fprintf(w, "  Group: %s\n", resolver.format(sd.GroupSid.ToString()))
	}
	if sd.Dacl == nil || len(sd.Dacl.ACLS) == 0 {
		fmt.Fprintln(w, "  (DACL is empty or not present)")
		return nil
	}
	fmt.Fprintf(w, "  ACEs (%d):\n", len(sd.Dacl.ACLS))
	for i, ace := range sd.Dacl.ACLS {
		printACE(w, i, ace, resolver, gresolver)
	}
	// DCSync rights (DS-Replication-Get-Changes / -All) are control-access
	// rights that only have meaning on the domain NC head, so only audit for
	// them there; on ordinary objects the check would be misleading (every
	// Full-Control principal would appear "DCSync-capable").
	if isDomainObject(objectClasses) {
		if findings := dcsyncFindings(sd, resolver); len(findings) > 0 {
			fmt.Fprintln(w, "\n  [!] DCSync-capable principals (DS-Replication-Get-Changes + -All, or Full Control):")
			for _, f := range findings {
				fmt.Fprintf(w, "      - %s\n", f)
			}
		}
	}
	return nil
}

// isDomainObject reports whether the object is the domain naming-context head
// (objectClass domainDNS), the only place DCSync replication rights apply.
func isDomainObject(objectClasses []string) bool {
	for _, oc := range objectClasses {
		if strings.EqualFold(oc, "domainDNS") {
			return true
		}
	}
	return false
}

func printACE(w io.Writer, i int, ace msdtyp.ACE, resolver *sidResolver, gr *guidResolver) {
	typeName := aceTypeName(ace.Header.Type)
	fmt.Fprintf(w, "    [%d] %s\n", i, typeName)
	fmt.Fprintf(w, "        Trustee: %s\n", resolver.format(ace.Sid.ToString()))
	fmt.Fprintf(w, "        Access:  %s\n", formatAccessMask(ace.Mask))
	if flags := aceFlagsLabel(ace.Header.Flags); flags != "" {
		fmt.Fprintf(w, "        Flags:   0x%02X (%s)\n", ace.Header.Flags, flags)
	}
	if msdtyp.IsObjectAceType(ace.Header.Type) {
		if ace.ObjectFlags&msdtyp.AceObjectTypePresent != 0 {
			fmt.Fprintf(w, "        Object:  %s\n", gr.format(msdtyp.GuidToString(ace.ObjectType)))
		}
		if ace.ObjectFlags&msdtyp.AceInheritedObjectTypePresent != 0 {
			fmt.Fprintf(w, "        Inherited-Object: %s\n", gr.format(msdtyp.GuidToString(ace.InheritedObjectType)))
		}
	}
}

// formatGUID is the static (offline) "<guid> (<name>)" renderer used where no
// resolver is threaded in (the `dacl add` skip message); for the read dump see
// guidResolver.format, which also resolves unknown GUIDs live.
func formatGUID(guid string) string {
	if name := friendlyGUIDName(guid); name != "" {
		return fmt.Sprintf("%s (%s)", guid, name)
	}
	return guid
}

// dcsyncFindings returns, for each principal whose allow ACEs grant DCSync,
// a formatted "<sid/name>" line.
func dcsyncFindings(sd *msdtyp.SecurityDescriptor, resolver *sidResolver) []string {
	if sd.Dacl == nil {
		return nil
	}
	type acc struct {
		getChanges, getChangesAll, full bool
	}
	bySID := map[string]*acc{}
	order := []string{}
	for _, ace := range sd.Dacl.ACLS {
		if ace.Header.Type != msdtyp.AccessAllowedAceType && ace.Header.Type != msdtyp.AccessAllowedObjectAceType {
			continue
		}
		sid := ace.Sid.ToString()
		a := bySID[sid]
		if a == nil {
			a = &acc{}
			bySID[sid] = a
			order = append(order, sid)
		}
		if ace.Mask&maskFullControl == maskFullControl || ace.Mask&0x10000000 != 0 {
			a.full = true
		}
		if ace.Header.Type == msdtyp.AccessAllowedObjectAceType && ace.ObjectFlags&msdtyp.AceObjectTypePresent != 0 {
			switch strings.ToLower(msdtyp.GuidToString(ace.ObjectType)) {
			case guidGetChanges:
				a.getChanges = true
			case guidGetChangesAll:
				a.getChangesAll = true
			}
		}
		// An ACE granting all extended rights (ControlAccess, no ObjectType)
		// covers the replication rights too.
		if ace.Header.Type == msdtyp.AccessAllowedObjectAceType &&
			ace.ObjectFlags&msdtyp.AceObjectTypePresent == 0 &&
			ace.Mask&adsRightDSControlAccess != 0 {
			a.getChanges, a.getChangesAll = true, true
		}
		if ace.Header.Type == msdtyp.AccessAllowedAceType && ace.Mask&adsRightDSControlAccess != 0 {
			a.getChanges, a.getChangesAll = true, true
		}
	}
	var out []string
	for _, sid := range order {
		a := bySID[sid]
		if a.full || (a.getChanges && a.getChangesAll) {
			out = append(out, resolver.format(sid))
		}
	}
	return out
}

func daclAdd(conn *ldap.Conn, baseDN string, c *daclCmd, dn string, blob []byte, w io.Writer) error {
	sd, err := parseSD(blob)
	if err != nil {
		return err
	}
	trusteeSID, err := resolveTrusteeSID(conn, baseDN, c.trustee)
	if err != nil {
		return err
	}
	mask, err := c.parsedMask()
	if err != nil {
		return err
	}
	flags, err := c.parsedAceFlags()
	if err != nil {
		return err
	}
	newACEs, err := buildACEsForGrant(trusteeSID, c.aceTypeByte(), flags, c.rights, mask, c.rightGUIDs, c.inheritedOID)
	if err != nil {
		return err
	}
	if sd.Dacl == nil {
		sd.Dacl = &msdtyp.PACL{AclRevision: 4}
	}
	var added int
	for _, ace := range newACEs {
		if daclHasEquivalentACE(sd.Dacl, ace) {
			fmt.Fprintf(w, "  (skipped: %s already present for %s)\n", aceSummary(ace), trusteeSID)
			continue
		}
		sd.Dacl.ACLS = append(sd.Dacl.ACLS, ace)
		added++
	}
	if added == 0 {
		fmt.Fprintf(w, "No change: all requested ACEs already present on %s\n", dn)
		return nil
	}
	recomputeDaclSizes(sd.Dacl)
	if err := writeSD(conn, dn, sd); err != nil {
		return err
	}
	fmt.Fprintf(w, "Added %d ACE(s) for %s (%s) on %s\n", added, c.trustee, trusteeSID, dn)
	return nil
}

func daclRemove(conn *ldap.Conn, baseDN string, c *daclCmd, dn string, blob []byte, w io.Writer) error {
	sd, err := parseSD(blob)
	if err != nil {
		return err
	}
	if sd.Dacl == nil || len(sd.Dacl.ACLS) == 0 {
		return fmt.Errorf("DACL on %s is empty; nothing to remove", dn)
	}
	trusteeSID, err := resolveTrusteeSID(conn, baseDN, c.trustee)
	if err != nil {
		return err
	}
	mask, err := c.parsedMask()
	if err != nil {
		return err
	}
	flags, err := c.parsedAceFlags()
	if err != nil {
		return err
	}
	// Narrow removal to the ACE(s) the request describes rather than every ACE
	// for the trustee. The grant identity (type/mask/object GUIDs) is matched via
	// acesEquivalent; ACE flags are matched only when the user specified them, so
	// the default is permissive (a grant is removed regardless of inheritance)
	// but an explicit --inheritance/--inherit-only/--ace-flags narrows further.
	byGrant := len(c.rights) > 0 || mask != 0 || len(c.rightGUIDs) > 0
	matchFlags := c.flagsSpecified()
	var match []msdtyp.ACE
	if byGrant {
		match, err = buildACEsForGrant(trusteeSID, c.aceTypeByte(), flags, c.rights, mask, c.rightGUIDs, c.inheritedOID)
		if err != nil {
			return err
		}
	}

	kept := sd.Dacl.ACLS[:0:0]
	var removed int
	for _, ace := range sd.Dacl.ACLS {
		if ace.Sid.ToString() == trusteeSID && aceMatchesRemoval(ace, match, byGrant, matchFlags, flags) {
			removed++
			continue
		}
		kept = append(kept, ace)
	}
	if removed == 0 {
		return fmt.Errorf("no matching ACE for %s (%s) on %s", c.trustee, trusteeSID, dn)
	}
	sd.Dacl.ACLS = kept
	recomputeDaclSizes(sd.Dacl)
	if err := writeSD(conn, dn, sd); err != nil {
		return err
	}
	fmt.Fprintf(w, "Removed %d ACE(s) for %s (%s) on %s\n", removed, c.trustee, trusteeSID, dn)
	return nil
}

func daclBackup(c *daclCmd, dn string, blob []byte, w io.Writer) error {
	enc := base64.StdEncoding.EncodeToString(blob)
	if err := os.WriteFile(c.file, []byte(enc+"\n"), 0600); err != nil {
		return fmt.Errorf("writing backup: %w", err)
	}
	fmt.Fprintf(w, "Backed up %s of %s to %s (%d bytes)\n", sdAttr, dn, c.file, len(blob))
	fmt.Fprintf(w, "  hex: %s\n", hex.EncodeToString(blob))
	return nil
}

func daclRestore(conn *ldap.Conn, c *daclCmd, dn string, w io.Writer) error {
	data, err := os.ReadFile(c.file)
	if err != nil {
		return fmt.Errorf("reading backup: %w", err)
	}
	blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return fmt.Errorf("decoding backup (expected base64): %w", err)
	}
	if _, err := parseSD(blob); err != nil {
		return fmt.Errorf("backup is not a valid security descriptor: %w", err)
	}
	if err := writeSDBytes(conn, dn, blob); err != nil {
		return err
	}
	fmt.Fprintf(w, "Restored DACL on %s from %s\n", dn, c.file)
	return nil
}

// parsedAceFlags returns the ACE Header.Flags byte to apply to added ACEs,
// taken from either the raw --ace-flags value (hex 0x.. or decimal) or the
// --inheritance / --inherit-only booleans. The two sources are mutually
// exclusive (enforced in validate).
func (c *daclCmd) parsedAceFlags() (byte, error) {
	if c.aceFlagsHex != "" {
		s := strings.TrimSpace(c.aceFlagsHex)
		base := 10
		if strings.HasPrefix(strings.ToLower(s), "0x") {
			s = s[2:]
			base = 16
		}
		v, err := strconv.ParseUint(s, base, 8)
		if err != nil {
			return 0, fmt.Errorf("invalid --ace-flags %q (must be a single byte): %w", c.aceFlagsHex, err)
		}
		return byte(v), nil
	}
	var f byte
	if c.inheritance {
		f |= msdtyp.ContainerInheritAce
	}
	if c.inheritOnly {
		f |= msdtyp.InheritOnlyAce
	}
	return f, nil
}

// flagsSpecified reports whether the user explicitly requested any ACE flags,
// by either the inheritance booleans or a raw --ace-flags value. Used by remove
// to decide whether to also match on ACE flags (otherwise they are ignored).
func (c *daclCmd) flagsSpecified() bool {
	return c.aceFlagsHex != "" || c.inheritance || c.inheritOnly
}

// writeSD marshals the descriptor and replaces nTSecurityDescriptor, scoping
// the write to the DACL (the SD-flags control) so owner/group/SACL are left
// unchanged.
func writeSD(conn *ldap.Conn, dn string, sd *msdtyp.SecurityDescriptor) error {
	blob, err := sd.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal security descriptor: %w", err)
	}
	return writeSDBytes(conn, dn, blob)
}

func writeSDBytes(conn *ldap.Conn, dn string, blob []byte) error {
	ctl := ldap.NewControlMicrosoftSDFlags()
	ctl.Criticality = true
	ctl.ControlValue = sdFlagDaclOnly
	mod := ldap.NewModifyRequest(dn, []ldap.Control{ctl})
	mod.Replace(sdAttr, []string{string(blob)})
	if err := conn.Modify(mod); err != nil {
		return fmt.Errorf("LDAP modify failed: %w", err)
	}
	return nil
}

// recomputeDaclSizes fixes the ACE Header.Size and the ACL AclSize fields after
// the ACE list has been edited, so the marshalled DACL is well-formed.
func recomputeDaclSizes(dacl *msdtyp.PACL) {
	if dacl.AclRevision == 0 {
		dacl.AclRevision = 4 // ACL_REVISION_DS (supports object ACEs)
	}
	total := 8 // ACL header
	for i := range dacl.ACLS {
		dacl.ACLS[i].Header.Size = aceBinarySize(&dacl.ACLS[i])
		total += int(dacl.ACLS[i].Header.Size)
	}
	dacl.AclSize = uint16(total)
}

// acesEquivalent reports whether two ACEs grant the same thing to the same SID:
// same type, mask, trustee, and object GUIDs. ACE flags are intentionally
// ignored so removal's default match is not defeated by inheritance differences
// (add-dedup layers an explicit flags comparison on top; see daclHasEquivalentACE).
func acesEquivalent(a, b msdtyp.ACE) bool {
	return a.Header.Type == b.Header.Type &&
		a.Mask == b.Mask &&
		a.Sid.ToString() == b.Sid.ToString() &&
		a.ObjectFlags == b.ObjectFlags &&
		a.ObjectType == b.ObjectType &&
		a.InheritedObjectType == b.InheritedObjectType
}

// aceMatchesRemoval decides whether an existing ACE (already known to belong to
// the target trustee) should be removed for a `remove` request. byGrant is true
// when the request named a grant via rights/mask/right-guid, in which case the
// ACE must be acesEquivalent to one of the requested grants. matchFlags is true
// when the user specified ACE flags (via --inheritance/--inherit-only or a raw
// --ace-flags), in which case the ACE's flags byte must equal flags exactly.
// With neither specified the match is permissive: every ACE for the trustee.
func aceMatchesRemoval(ace msdtyp.ACE, match []msdtyp.ACE, byGrant, matchFlags bool, flags byte) bool {
	if !byGrant && !matchFlags {
		return true
	}
	drop := true
	if byGrant {
		drop = false
		for _, m := range match {
			if acesEquivalent(ace, m) {
				drop = true
				break
			}
		}
	}
	if drop && matchFlags && ace.Header.Flags != flags {
		drop = false
	}
	return drop
}

// daclHasEquivalentACE reports whether the DACL already contains the same grant
// with the same inheritance scope. Unlike removal's default match, dedup is
// flag-aware: the same grant with different ACE flags (e.g. an inherit-only ACE
// that applies to children versus a non-inherited ACE that applies to the
// target) is a distinct entry that may legitimately coexist, so adding one must
// not be suppressed by the presence of the other.
func daclHasEquivalentACE(dacl *msdtyp.PACL, ace msdtyp.ACE) bool {
	for _, e := range dacl.ACLS {
		if acesEquivalent(e, ace) && e.Header.Flags == ace.Header.Flags {
			return true
		}
	}
	return false
}

func aceSummary(ace msdtyp.ACE) string {
	s := fmt.Sprintf("%s %s", aceTypeName(ace.Header.Type), formatAccessMask(ace.Mask))
	if msdtyp.IsObjectAceType(ace.Header.Type) && ace.ObjectFlags&msdtyp.AceObjectTypePresent != 0 {
		s += " " + formatGUID(msdtyp.GuidToString(ace.ObjectType))
	}
	return s
}

// sidResolver translates SIDs to friendly names on demand (well-known table
// first, then LDAP), caching results. When disabled it returns the raw SID.
type sidResolver struct {
	conn    *ldap.Conn
	baseDN  string
	enabled bool
	cache   map[string]string
}

func newSIDResolver(conn *ldap.Conn, baseDN string, enabled bool) *sidResolver {
	return &sidResolver{conn: conn, baseDN: baseDN, enabled: enabled, cache: map[string]string{}}
}

// format returns "SID (Name)" when a name is known, otherwise the bare SID.
func (r *sidResolver) format(sid string) string {
	if name := r.name(sid); name != "" {
		return fmt.Sprintf("%s (%s)", sid, name)
	}
	return sid
}

func (r *sidResolver) name(sid string) string {
	if n := wellKnownSIDName(sid); n != "" {
		return n
	}
	if !r.enabled {
		return ""
	}
	if n, ok := r.cache[sid]; ok {
		return n
	}
	n := r.lookup(sid)
	r.cache[sid] = n
	return n
}

func (r *sidResolver) lookup(sid string) string {
	sidBytes, err := encodeSID(sid)
	if err != nil {
		return ""
	}
	res, err := r.conn.Search(ldap.NewSearchRequest(
		r.baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(objectSid="+ldapBinaryFilter(sidBytes)+")",
		[]string{"sAMAccountName", "name"},
		nil,
	))
	if err != nil || len(res.Entries) == 0 {
		return ""
	}
	e := res.Entries[0]
	if v := e.GetAttributeValue("sAMAccountName"); v != "" {
		return v
	}
	return e.GetAttributeValue("name")
}
