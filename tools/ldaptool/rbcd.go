package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	ldap "github.com/jfjallid/ldap/v3"
)

// Resource-Based Constrained Delegation lives on the target object's
// msDS-AllowedToActOnBehalfOfOtherIdentity attribute as a self-relative
// SECURITY_DESCRIPTOR. For RBCD purposes only the DACL matters: each
// ACCESS_ALLOWED_ACE in the DACL names a SID that is permitted to delegate
// to the target. Owner is conventionally Built-in Administrators; group
// and SACL are left empty.

const (
	rbcdAttr = "msDS-AllowedToActOnBehalfOfOtherIdentity"

	// SECURITY_DESCRIPTOR_CONTROL flags we use.
	seDaclPresent  uint16 = 0x0004
	seSelfRelative uint16 = 0x8000

	aclRevisionDS      byte   = 4 // supports object ACEs
	aceTypeAllowed     byte   = 0x00
	aceMaskFullControl uint32 = 0x000F01FF // STANDARD_RIGHTS_REQUIRED | type-specific Full Control bits
)

var helpRBCDOptions = `
    Usage: ldaptool rbcd [options]

    Manage Resource-Based Constrained Delegation (RBCD) by editing the
    target's msDS-AllowedToActOnBehalfOfOtherIdentity attribute.

    Options:
          --action     Action: add, list, remove, clear (required)
          --target     sAMAccountName of the resource to delegate TO (required)
          --trustee    SID or sAMAccountName allowed to delegate
                       (required for add/remove; repeatable)
          --dry-mode   Do not write; print the SD bytes that --add
                       would have set (raw hex + PowerShell snippet).
                       Only valid with --action add.
` + helpConnectionOptions

type rbcdCmd struct {
	action   string
	target   string
	trustees repeatStrFlag
	dryMode  bool
}

func init() { register(&rbcdCmd{}) }

func (c *rbcdCmd) Name() string     { return "rbcd" }
func (c *rbcdCmd) Synopsis() string { return "Manage msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)" }
func (c *rbcdCmd) Usage() string    { return helpRBCDOptions }

func (c *rbcdCmd) DefineFlags(f *flag.FlagSet) {
	f.StringVar(&c.action, "action", "", "Action: add, list, remove, clear (required)")
	f.StringVar(&c.target, "target", "", "sAMAccountName of the target object (required)")
	f.Var(&c.trustees, "trustee", "SID or sAMAccountName to add/remove (repeatable)")
	f.BoolVar(&c.dryMode, "dry-mode", false, "Do not write; print the SD bytes that would be set (only valid with --action add)")
}

func (c *rbcdCmd) Run(a *connArgs) error {
	if c.action == "" || c.target == "" {
		return fmt.Errorf("--action and --target are required")
	}
	switch c.action {
	case "add", "remove":
		if len(c.trustees) == 0 {
			return fmt.Errorf("--trustee is required for action %q", c.action)
		}
	case "list", "clear":
		// no extra args
	default:
		return fmt.Errorf("unknown --action %q (valid: add, list, remove, clear)", c.action)
	}
	if c.dryMode && c.action != "add" {
		return fmt.Errorf("--dry-mode is only valid with --action add")
	}
	if err := ensurePassword(a); err != nil {
		return fmt.Errorf("reading password: %w", err)
	}
	conn, baseDN, err := makeConnection(a)
	if err != nil {
		return err
	}
	defer conn.Close()
	return runRBCD(conn, baseDN, c, os.Stdout)
}

func runRBCD(conn *ldap.Conn, baseDN string, c *rbcdCmd, w io.Writer) error {
	dn, blob, err := lookupRBCDTarget(conn, baseDN, c.target)
	if err != nil {
		return err
	}

	switch c.action {
	case "list":
		return rbcdList(dn, blob, w)
	case "clear":
		return rbcdClear(conn, dn, blob, w)
	case "add":
		if c.dryMode {
			return rbcdAddDryRun(conn, baseDN, dn, c.target, c.trustees, blob, w)
		}
		return rbcdAdd(conn, baseDN, dn, blob, c.trustees, w)
	case "remove":
		return rbcdRemove(conn, baseDN, dn, blob, c.trustees, w)
	}
	return fmt.Errorf("unreachable")
}

// lookupRBCDTarget resolves a sAMAccountName to its DN and current RBCD blob.
func lookupRBCDTarget(conn *ldap.Conn, baseDN, sam string) (string, []byte, error) {
	// sAMAccountName lookups should match both users and computer accounts;
	// computers come back with a trailing "$" but the user typically passes
	// the bare hostname. Try both.
	candidates := []string{sam}
	if !strings.HasSuffix(sam, "$") {
		candidates = append(candidates, sam+"$")
	}

	var filterParts []string
	for _, cand := range candidates {
		filterParts = append(filterParts, fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(cand)))
	}
	filter := "(|" + strings.Join(filterParts, "") + ")"

	res, err := conn.Search(ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter,
		[]string{"distinguishedName", "sAMAccountName", rbcdAttr},
		nil,
	))
	if err != nil {
		return "", nil, fmt.Errorf("LDAP search failed: %w", err)
	}
	if len(res.Entries) == 0 {
		return "", nil, fmt.Errorf("target %q not found", sam)
	}
	if len(res.Entries) > 1 {
		return "", nil, fmt.Errorf("multiple targets matched %q", sam)
	}
	entry := res.Entries[0]
	var blob []byte
	for _, attr := range entry.Attributes {
		if strings.EqualFold(attr.Name, rbcdAttr) && len(attr.ByteValues) > 0 {
			blob = attr.ByteValues[0]
		}
	}
	return entry.DN, blob, nil
}

func rbcdList(dn string, blob []byte, w io.Writer) error {
	fmt.Fprintf(w, "RBCD principals on %s:\n", dn)
	if len(blob) == 0 {
		fmt.Fprintln(w, "  (none)")
		return nil
	}
	aces, err := decodeRBCDAces(blob)
	if err != nil {
		return fmt.Errorf("parse %s: %w", rbcdAttr, err)
	}
	if len(aces) == 0 {
		fmt.Fprintln(w, "  (DACL is empty)")
		return nil
	}
	for i, a := range aces {
		maskStr := fmt.Sprintf("0x%08X", a.Mask)
		if label := aceMaskLabel(a.Mask); label != "" {
			maskStr += " (" + label + ")"
		}
		flagsStr := fmt.Sprintf("0x%02X", a.Flags)
		if label := aceFlagsLabel(a.Flags); label != "" {
			flagsStr += " (" + label + ")"
		}
		sid := a.SID
		if sid == "" {
			sid = "(undecoded)"
		}
		fmt.Fprintf(w, "  [%d] %s  mask=%s  flags=%s\n", i, aceTypeName(a.Type), maskStr, flagsStr)
		fmt.Fprintf(w, "      SID: %s\n", sid)
	}
	return nil
}

func rbcdClear(conn *ldap.Conn, dn string, blob []byte, w io.Writer) error {
	if len(blob) == 0 {
		fmt.Fprintf(w, "No RBCD entry to clear on %s\n", dn)
		return nil
	}
	mod := ldap.NewModifyRequest(dn, nil)
	mod.Delete(rbcdAttr, []string{})
	if err := conn.Modify(mod); err != nil {
		return fmt.Errorf("LDAP modify failed: %w", err)
	}
	fmt.Fprintf(w, "Cleared %s on %s\n", rbcdAttr, dn)
	return nil
}

func rbcdAdd(conn *ldap.Conn, baseDN, dn string, existingBlob []byte, trustees []string, w io.Writer) error {
	sids := make([]string, 0, len(trustees))
	for _, t := range trustees {
		sid, err := resolveTrusteeSID(conn, baseDN, t)
		if err != nil {
			return err
		}
		sids = append(sids, sid)
	}

	var newBlob []byte
	if len(existingBlob) == 0 {
		// No existing attribute: build a fresh SD with our trustees.
		b, err := encodeRBCD(sids)
		if err != nil {
			return fmt.Errorf("encode SD: %w", err)
		}
		newBlob = b
	} else {
		// Append to the existing SD, preserving owner/group/SACL and
		// any ACEs already in place.
		b, added, err := appendAllowedACEs(existingBlob, sids)
		if err != nil {
			return fmt.Errorf("update SD: %w", err)
		}
		if len(added) == 0 {
			fmt.Fprintf(w, "RBCD on %s already includes all requested trustees; no change\n", dn)
			return nil
		}
		newBlob = b
	}

	if err := writeRBCD(conn, dn, existingBlob, newBlob); err != nil {
		return err
	}
	final, err := decodeRBCD(newBlob)
	if err != nil {
		return fmt.Errorf("decode result: %w", err)
	}
	fmt.Fprintf(w, "RBCD on %s now allows:\n", dn)
	for _, s := range final {
		fmt.Fprintf(w, "  %s\n", s)
	}
	return nil
}

// rbcdAddDryRun mirrors the front half of rbcdAdd — resolve trustees,
// compute the new self-relative SD — but instead of writing the result
// back to LDAP, prints the bytes in two forms (raw lowercase hex and a
// ready-to-paste PowerShell Set-ADComputer snippet). When all requested
// trustees are already present in the DACL, the current SD is printed
// unchanged so the operator sees what the attribute already holds.
func rbcdAddDryRun(conn *ldap.Conn, baseDN, dn, targetName string, trustees []string, existingBlob []byte, w io.Writer) error {
	sids := make([]string, 0, len(trustees))
	for _, t := range trustees {
		sid, err := resolveTrusteeSID(conn, baseDN, t)
		if err != nil {
			return err
		}
		sids = append(sids, sid)
	}

	var newBlob []byte
	var added []string
	if len(existingBlob) == 0 {
		b, err := encodeRBCD(sids)
		if err != nil {
			return fmt.Errorf("encode SD: %w", err)
		}
		newBlob = b
		added = sids
	} else {
		b, addedSIDs, err := appendAllowedACEs(existingBlob, sids)
		if err != nil {
			return fmt.Errorf("update SD: %w", err)
		}
		newBlob = b
		added = addedSIDs
	}

	formatRBCDDryRun(w, dn, targetName, trustees, sids, newBlob, added)
	return nil
}

// formatRBCDDryRun is the pure print path used by --dry-mode. Keeping
// the LDAP-touching code out of this function makes it directly
// unit-testable from a known blob.
func formatRBCDDryRun(w io.Writer, dn, targetName string, trustees, sids []string, blob []byte, added []string) {
	fmt.Fprintf(w, "[dry-mode] RBCD target: %s\n", dn)
	fmt.Fprintln(w, "Trustees to grant:")
	for i, t := range trustees {
		fmt.Fprintf(w, "  %s  ->  %s\n", t, sids[i])
	}
	if len(added) == 0 {
		fmt.Fprintln(w, "(all requested trustees already present; showing current SD unchanged)")
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "New msDS-AllowedToActOnBehalfOfOtherIdentity (hex):")
	fmt.Fprintln(w, hex.EncodeToString(blob))

	identity := strings.TrimSuffix(targetName, "$")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "PowerShell (copy/paste):")
	fmt.Fprintln(w, "$bytes = [byte[]]@("+formatPSByteList(blob)+")")
	fmt.Fprintf(w, "Set-ADComputer -Identity '%s' -Replace @{'msDS-AllowedToActOnBehalfOfOtherIdentity'=$bytes}\n", identity)
}

// formatPSByteList renders bytes as `0x01,0x02,...` with a line break
// (PowerShell backtick continuation) every 16 bytes for readability.
func formatPSByteList(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	var sb strings.Builder
	for i, v := range b {
		if i > 0 {
			sb.WriteByte(',')
			if i%16 == 0 {
				sb.WriteString(" `\n    ")
			}
		}
		fmt.Fprintf(&sb, "0x%02x", v)
	}
	return sb.String()
}

func rbcdRemove(conn *ldap.Conn, baseDN, dn string, existingBlob []byte, trustees []string, w io.Writer) error {
	if len(existingBlob) == 0 {
		return fmt.Errorf("no RBCD entry on %s; nothing to remove", dn)
	}
	sids := make([]string, 0, len(trustees))
	for _, t := range trustees {
		sid, err := resolveTrusteeSID(conn, baseDN, t)
		if err != nil {
			return err
		}
		sids = append(sids, sid)
	}

	newBlob, removed, daclEmpty, err := removeAllowedACEs(existingBlob, sids)
	if err != nil {
		return fmt.Errorf("update SD: %w", err)
	}

	removedSet := make(map[string]bool, len(removed))
	for _, s := range removed {
		removedSet[s] = true
	}
	for i, s := range sids {
		if !removedSet[s] {
			fmt.Fprintf(w, "warning: %s (%s) not in DACL\n", trustees[i], s)
		}
	}
	if len(removed) == 0 {
		return fmt.Errorf("no matching trustees to remove")
	}

	if daclEmpty {
		return rbcdClear(conn, dn, existingBlob, w)
	}

	if err := writeRBCD(conn, dn, existingBlob, newBlob); err != nil {
		return err
	}
	final, err := decodeRBCD(newBlob)
	if err != nil {
		return fmt.Errorf("decode result: %w", err)
	}
	fmt.Fprintf(w, "RBCD on %s now allows:\n", dn)
	for _, s := range final {
		fmt.Fprintf(w, "  %s\n", s)
	}
	return nil
}

// writeRBCD replaces or adds the RBCD attribute on dn. Replace is correct
// regardless of whether the attribute existed before, but we use Add when
// the prior blob was empty so the modlog is clearer.
func writeRBCD(conn *ldap.Conn, dn string, oldBlob, newBlob []byte) error {
	mod := ldap.NewModifyRequest(dn, nil)
	if len(oldBlob) == 0 {
		mod.Add(rbcdAttr, []string{string(newBlob)})
	} else {
		mod.Replace(rbcdAttr, []string{string(newBlob)})
	}
	if err := conn.Modify(mod); err != nil {
		return fmt.Errorf("LDAP modify failed: %w", err)
	}
	return nil
}

// resolveTrusteeSID accepts either a string SID (S-1-...) or a sAMAccountName
// and returns the canonical S-1-... form.
func resolveTrusteeSID(conn *ldap.Conn, baseDN, t string) (string, error) {
	if strings.HasPrefix(strings.ToUpper(t), "S-1-") {
		return t, nil
	}
	candidates := []string{t}
	if !strings.HasSuffix(t, "$") {
		candidates = append(candidates, t+"$")
	}
	var parts []string
	for _, c := range candidates {
		parts = append(parts, fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(c)))
	}
	filter := "(|" + strings.Join(parts, "") + ")"
	res, err := conn.Search(ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter,
		[]string{"objectSid", "sAMAccountName"},
		nil,
	))
	if err != nil {
		return "", fmt.Errorf("resolve %q: %w", t, err)
	}
	if len(res.Entries) == 0 {
		return "", fmt.Errorf("trustee %q not found", t)
	}
	if len(res.Entries) > 1 {
		return "", fmt.Errorf("trustee %q matched %d entries", t, len(res.Entries))
	}
	for _, attr := range res.Entries[0].Attributes {
		if strings.EqualFold(attr.Name, "objectSid") && len(attr.ByteValues) > 0 {
			s, ok := decodeSID(attr.ByteValues[0])
			if !ok {
				return "", fmt.Errorf("trustee %q: malformed objectSid", t)
			}
			return s, nil
		}
	}
	return "", fmt.Errorf("trustee %q has no objectSid", t)
}

// encodeSID converts an "S-1-..." string back to the binary little-endian form
// used in security descriptors.
func encodeSID(s string) ([]byte, error) {
	parts := strings.Split(s, "-")
	if len(parts) < 3 || !strings.EqualFold(parts[0], "S") {
		return nil, fmt.Errorf("not a SID: %q", s)
	}
	rev, err := strconv.ParseUint(parts[1], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("revision: %w", err)
	}
	authority, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("authority: %w", err)
	}
	subs := parts[3:]
	if len(subs) > 15 {
		return nil, fmt.Errorf("too many sub-authorities: %d", len(subs))
	}
	buf := make([]byte, 8+4*len(subs))
	buf[0] = byte(rev)
	buf[1] = byte(len(subs))
	for i := 0; i < 6; i++ {
		buf[2+i] = byte(authority >> (8 * (5 - i)))
	}
	for i, s := range subs {
		v, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("sub-authority %d: %w", i, err)
		}
		binary.LittleEndian.PutUint32(buf[8+4*i:], uint32(v))
	}
	return buf, nil
}

// encodeRBCD builds a fresh self-relative SECURITY_DESCRIPTOR with one
// ACCESS_ALLOWED_ACE per supplied trustee SID. Used when the attribute
// does not yet exist. Owner is the well-known Builtin\Administrators
// (S-1-5-32-544) so the SD is well-formed; group and SACL are absent.
func encodeRBCD(sids []string) ([]byte, error) {
	if len(sids) == 0 {
		return nil, fmt.Errorf("at least one trustee required")
	}
	ownerSID, err := encodeSID("S-1-5-32-544")
	if err != nil {
		return nil, err
	}
	aces := make([][]byte, 0, len(sids))
	for _, s := range sids {
		ace, err := buildAllowedACE(s)
		if err != nil {
			return nil, fmt.Errorf("trustee %s: %w", s, err)
		}
		aces = append(aces, ace)
	}
	dacl := daclAppendACEs(nil, aces)
	return serializeSelfRelativeSD(seDaclPresent|seSelfRelative, ownerSID, nil, nil, dacl), nil
}

// buildAllowedACE constructs an ACCESS_ALLOWED_ACE granting Full Control
// to sid (mask 0x000F01FF, matching impacket).
func buildAllowedACE(sid string) ([]byte, error) {
	sidBytes, err := encodeSID(sid)
	if err != nil {
		return nil, err
	}
	aceSize := 4 + 4 + len(sidBytes) // header(4) + mask(4) + sid
	ace := make([]byte, aceSize)
	ace[0] = aceTypeAllowed
	ace[1] = 0
	binary.LittleEndian.PutUint16(ace[2:4], uint16(aceSize))
	binary.LittleEndian.PutUint32(ace[4:8], aceMaskFullControl)
	copy(ace[8:], sidBytes)
	return ace, nil
}

// parseSelfRelativeSD splits a self-relative SECURITY_DESCRIPTOR into its
// constituent slices. An empty slice means the corresponding component
// is absent.
func parseSelfRelativeSD(blob []byte) (control uint16, owner, group, sacl, dacl []byte, err error) {
	if len(blob) < 20 {
		err = fmt.Errorf("SD too short: %d bytes", len(blob))
		return
	}
	if blob[0] != 1 {
		err = fmt.Errorf("unsupported SD revision %d", blob[0])
		return
	}
	control = binary.LittleEndian.Uint16(blob[2:4])
	if control&seSelfRelative == 0 {
		err = fmt.Errorf("SD is not self-relative (control 0x%x)", control)
		return
	}
	ownerOff := binary.LittleEndian.Uint32(blob[4:8])
	groupOff := binary.LittleEndian.Uint32(blob[8:12])
	saclOff := binary.LittleEndian.Uint32(blob[12:16])
	daclOff := binary.LittleEndian.Uint32(blob[16:20])
	if ownerOff != 0 {
		if owner, err = sliceSID(blob, ownerOff); err != nil {
			return
		}
	}
	if groupOff != 0 {
		if group, err = sliceSID(blob, groupOff); err != nil {
			return
		}
	}
	if saclOff != 0 {
		if sacl, err = sliceACL(blob, saclOff); err != nil {
			return
		}
	}
	if daclOff != 0 {
		if dacl, err = sliceACL(blob, daclOff); err != nil {
			return
		}
	}
	return
}

func sliceSID(blob []byte, off uint32) ([]byte, error) {
	if int(off)+8 > len(blob) {
		return nil, fmt.Errorf("SID at offset %d truncated", off)
	}
	sidLen := 8 + 4*int(blob[off+1])
	if int(off)+sidLen > len(blob) {
		return nil, fmt.Errorf("SID at offset %d, length %d out of range", off, sidLen)
	}
	return blob[off : int(off)+sidLen], nil
}

func sliceACL(blob []byte, off uint32) ([]byte, error) {
	if int(off)+8 > len(blob) {
		return nil, fmt.Errorf("ACL at offset %d truncated", off)
	}
	size := binary.LittleEndian.Uint16(blob[off+2 : off+4])
	if int(size) < 8 || int(off)+int(size) > len(blob) {
		return nil, fmt.Errorf("ACL at offset %d, size %d out of range", off, size)
	}
	return blob[off : int(off)+int(size)], nil
}

// aceInfo describes a single parsed ACE.
type aceInfo struct {
	Type  byte
	Flags byte
	Mask  uint32
	SID   string // canonical S-1-... form, "" if undecodable (e.g. object ACE)
}

// walkDACL returns parsed information for every ACE in dacl. For ACE
// types whose body is not Mask|SID (object ACEs), the SID field is
// left empty.
func walkDACL(dacl []byte) ([]aceInfo, error) {
	if len(dacl) < 8 {
		return nil, nil
	}
	aceCount := binary.LittleEndian.Uint16(dacl[4:6])
	out := make([]aceInfo, 0, aceCount)
	off := 8
	for i := uint16(0); i < aceCount; i++ {
		if off+8 > len(dacl) {
			return nil, fmt.Errorf("ACE %d header truncated", i)
		}
		aceSize := binary.LittleEndian.Uint16(dacl[off+2 : off+4])
		if int(aceSize) < 8 || off+int(aceSize) > len(dacl) {
			return nil, fmt.Errorf("ACE %d size %d invalid", i, aceSize)
		}
		info := aceInfo{
			Type:  dacl[off],
			Flags: dacl[off+1],
			Mask:  binary.LittleEndian.Uint32(dacl[off+4 : off+8]),
		}
		// Non-object allow/deny/audit/alarm ACEs are: type|flags|size|mask|sid.
		// Object ACEs (0x05-0x08, 0x0B-0x10) have ObjectType/InheritedObjectType
		// GUIDs before the SID and are not decoded here.
		if isSimpleACE(info.Type) && int(aceSize) > 8 {
			if s, ok := decodeSID(dacl[off+8 : off+int(aceSize)]); ok {
				info.SID = s
			}
		}
		out = append(out, info)
		off += int(aceSize)
	}
	return out, nil
}

func isSimpleACE(t byte) bool {
	switch t {
	case 0x00, 0x01, 0x02, 0x03, 0x09, 0x0A, 0x0D, 0x0E, 0x11, 0x12, 0x13:
		return true
	}
	return false
}

// daclAllowedSIDs returns the set of SIDs already granted access via
// ACCESS_ALLOWED_ACE entries in dacl.
func daclAllowedSIDs(dacl []byte) (map[string]bool, error) {
	aces, err := walkDACL(dacl)
	if err != nil {
		return nil, err
	}
	sids := make(map[string]bool, len(aces))
	for _, a := range aces {
		if a.Type == aceTypeAllowed && a.SID != "" {
			sids[a.SID] = true
		}
	}
	return sids, nil
}

// ACE-type and mask labels for human-readable list output.
var aceTypeNames = map[byte]string{
	0x00: "ACCESS_ALLOWED",
	0x01: "ACCESS_DENIED",
	0x02: "SYSTEM_AUDIT",
	0x03: "SYSTEM_ALARM",
	0x05: "ACCESS_ALLOWED_OBJECT",
	0x06: "ACCESS_DENIED_OBJECT",
	0x07: "SYSTEM_AUDIT_OBJECT",
	0x08: "SYSTEM_ALARM_OBJECT",
	0x09: "ACCESS_ALLOWED_CALLBACK",
	0x0A: "ACCESS_DENIED_CALLBACK",
	0x0B: "ACCESS_ALLOWED_CALLBACK_OBJECT",
	0x0C: "ACCESS_DENIED_CALLBACK_OBJECT",
	0x0D: "SYSTEM_AUDIT_CALLBACK",
	0x0E: "SYSTEM_ALARM_CALLBACK",
	0x0F: "SYSTEM_AUDIT_CALLBACK_OBJECT",
	0x10: "SYSTEM_ALARM_CALLBACK_OBJECT",
	0x11: "SYSTEM_MANDATORY_LABEL",
	0x12: "SYSTEM_RESOURCE_ATTRIBUTE",
	0x13: "SYSTEM_SCOPED_POLICY_ID",
}

func aceTypeName(t byte) string {
	if n, ok := aceTypeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("TYPE_0x%02X", t)
}

func aceMaskLabel(m uint32) string {
	switch m {
	case 0x000F01FF:
		return "Full Control"
	case 0x10000000:
		return "Generic All"
	case 0x20000000:
		return "Generic Execute"
	case 0x40000000:
		return "Generic Write"
	case 0x80000000:
		return "Generic Read"
	}
	return ""
}

func aceFlagsLabel(f byte) string {
	if f == 0 {
		return ""
	}
	var parts []string
	if f&0x01 != 0 {
		parts = append(parts, "OBJECT_INHERIT")
	}
	if f&0x02 != 0 {
		parts = append(parts, "CONTAINER_INHERIT")
	}
	if f&0x04 != 0 {
		parts = append(parts, "NO_PROPAGATE_INHERIT")
	}
	if f&0x08 != 0 {
		parts = append(parts, "INHERIT_ONLY")
	}
	if f&0x10 != 0 {
		parts = append(parts, "INHERITED")
	}
	if f&0x40 != 0 {
		parts = append(parts, "SUCCESSFUL_ACCESS")
	}
	if f&0x80 != 0 {
		parts = append(parts, "FAILED_ACCESS")
	}
	return strings.Join(parts, "|")
}

// daclAppendACEs returns a DACL whose body equals the input DACL with
// the supplied ACE bytes appended; size and ACE-count fields are updated
// accordingly. If dacl is empty, a fresh ACL header (revision 4) is used.
func daclAppendACEs(dacl []byte, aces [][]byte) []byte {
	var out []byte
	var existingCount uint16
	if len(dacl) >= 8 {
		out = make([]byte, len(dacl), len(dacl)+totalLen(aces))
		copy(out, dacl)
		existingCount = binary.LittleEndian.Uint16(dacl[4:6])
	} else {
		out = make([]byte, 8, 8+totalLen(aces))
		out[0] = aclRevisionDS
	}
	for _, ace := range aces {
		out = append(out, ace...)
	}
	binary.LittleEndian.PutUint16(out[2:4], uint16(len(out)))
	binary.LittleEndian.PutUint16(out[4:6], existingCount+uint16(len(aces)))
	return out
}

func totalLen(chunks [][]byte) int {
	n := 0
	for _, c := range chunks {
		n += len(c)
	}
	return n
}

// serializeSelfRelativeSD packs the supplied parts into a self-relative
// SECURITY_DESCRIPTOR. SE_SELF_RELATIVE is force-set; SE_DACL_PRESENT is
// set iff dacl is non-empty. Other control flags in `control` are
// preserved as-is.
func serializeSelfRelativeSD(control uint16, owner, group, sacl, dacl []byte) []byte {
	const headerLen = 20
	control |= seSelfRelative
	if len(dacl) > 0 {
		control |= seDaclPresent
	}
	var ownerOff, groupOff, saclOff, daclOff uint32
	var body []byte
	pos := uint32(headerLen)
	if len(owner) > 0 {
		ownerOff = pos
		body = append(body, owner...)
		pos += uint32(len(owner))
	}
	if len(group) > 0 {
		groupOff = pos
		body = append(body, group...)
		pos += uint32(len(group))
	}
	if len(sacl) > 0 {
		saclOff = pos
		body = append(body, sacl...)
		pos += uint32(len(sacl))
	}
	if len(dacl) > 0 {
		daclOff = pos
		body = append(body, dacl...)
	}
	sd := make([]byte, headerLen+len(body))
	sd[0] = 1
	sd[1] = 0
	binary.LittleEndian.PutUint16(sd[2:4], control)
	binary.LittleEndian.PutUint32(sd[4:8], ownerOff)
	binary.LittleEndian.PutUint32(sd[8:12], groupOff)
	binary.LittleEndian.PutUint32(sd[12:16], saclOff)
	binary.LittleEndian.PutUint32(sd[16:20], daclOff)
	copy(sd[headerLen:], body)
	return sd
}

// appendAllowedACEs parses an existing self-relative SD and inserts a
// new ACCESS_ALLOWED_ACE for each SID in newSIDs that is not already
// present in the DACL. Owner, group, SACL, control flags, and existing
// ACEs (including non-allowed ones) are preserved. The returned slice
// of SIDs is the subset actually appended, in input order.
func appendAllowedACEs(existing []byte, newSIDs []string) ([]byte, []string, error) {
	control, owner, group, sacl, dacl, err := parseSelfRelativeSD(existing)
	if err != nil {
		return nil, nil, err
	}
	present, err := daclAllowedSIDs(dacl)
	if err != nil {
		return nil, nil, err
	}
	var aces [][]byte
	var added []string
	for _, sid := range newSIDs {
		if present[sid] {
			continue
		}
		ace, err := buildAllowedACE(sid)
		if err != nil {
			return nil, nil, fmt.Errorf("trustee %s: %w", sid, err)
		}
		aces = append(aces, ace)
		present[sid] = true
		added = append(added, sid)
	}
	if len(aces) == 0 {
		return existing, nil, nil
	}
	newDACL := daclAppendACEs(dacl, aces)
	return serializeSelfRelativeSD(control, owner, group, sacl, newDACL), added, nil
}

// decodeRBCD returns the SIDs in the security descriptor's DACL as
// "S-1-..." strings. Only ACCESS_ALLOWED_ACE entries are returned; other
// ACE types are silently skipped (RBCD only needs allowed ACEs).
func decodeRBCD(blob []byte) ([]string, error) {
	control, _, _, _, dacl, err := parseSelfRelativeSD(blob)
	if err != nil {
		return nil, err
	}
	if control&seDaclPresent == 0 {
		return nil, nil
	}
	aces, err := walkDACL(dacl)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(aces))
	for _, a := range aces {
		if a.Type == aceTypeAllowed && a.SID != "" {
			out = append(out, a.SID)
		}
	}
	return out, nil
}

// decodeRBCDAces returns parsed-ACE info for the DACL of the SD, suitable
// for human-readable listing.
func decodeRBCDAces(blob []byte) ([]aceInfo, error) {
	_, _, _, _, dacl, err := parseSelfRelativeSD(blob)
	if err != nil {
		return nil, err
	}
	return walkDACL(dacl)
}

// removeAllowedACEs parses an existing self-relative SD and drops every
// ACCESS_ALLOWED_ACE whose SID matches one in sidsToRemove. Other ACEs
// (denied/audit/etc.) and the SD owner, group, SACL, and control flags
// are preserved.
//
// Returns: the new SD bytes, the SIDs actually removed (deduped, in
// input order), and a flag indicating whether the resulting DACL has
// zero ACEs left.
func removeAllowedACEs(existing []byte, sidsToRemove []string) ([]byte, []string, bool, error) {
	control, owner, group, sacl, dacl, err := parseSelfRelativeSD(existing)
	if err != nil {
		return nil, nil, false, err
	}
	if len(dacl) < 8 {
		return existing, nil, true, nil
	}

	target := make(map[string]bool, len(sidsToRemove))
	for _, s := range sidsToRemove {
		target[s] = true
	}

	rebuilt := make([]byte, 8, len(dacl))
	copy(rebuilt, dacl[:8])
	aceCount := binary.LittleEndian.Uint16(dacl[4:6])
	off := 8
	var newCount uint16
	removedSet := make(map[string]bool)
	for i := uint16(0); i < aceCount; i++ {
		if off+8 > len(dacl) {
			return nil, nil, false, fmt.Errorf("ACE %d header truncated", i)
		}
		aceSize := binary.LittleEndian.Uint16(dacl[off+2 : off+4])
		if int(aceSize) < 8 || off+int(aceSize) > len(dacl) {
			return nil, nil, false, fmt.Errorf("ACE %d size %d invalid", i, aceSize)
		}
		drop := false
		if dacl[off] == aceTypeAllowed && int(aceSize) > 8 {
			if s, ok := decodeSID(dacl[off+8 : off+int(aceSize)]); ok && target[s] {
				drop = true
				removedSet[s] = true
			}
		}
		if !drop {
			rebuilt = append(rebuilt, dacl[off:off+int(aceSize)]...)
			newCount++
		}
		off += int(aceSize)
	}
	binary.LittleEndian.PutUint16(rebuilt[2:4], uint16(len(rebuilt)))
	binary.LittleEndian.PutUint16(rebuilt[4:6], newCount)

	var removed []string
	for _, s := range sidsToRemove {
		if removedSet[s] {
			removed = append(removed, s)
			delete(removedSet, s) // dedupe duplicates in input
		}
	}

	daclEmpty := newCount == 0
	return serializeSelfRelativeSD(control, owner, group, sacl, rebuilt), removed, daclEmpty, nil
}

// mapKeysSorted returns the keys of a string-set in lexicographic order so
// list output is stable.
func mapKeysSorted(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
