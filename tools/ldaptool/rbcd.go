package main

import (
	"encoding/binary"
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

	aclRevisionDS    byte = 4 // supports object ACEs
	aceTypeAllowed   byte = 0x00
	aceMaskGenericAll uint32 = 0x10000000
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
` + helpConnectionOptions

type rbcdCmd struct {
	action   string
	target   string
	trustees repeatStrFlag
}

func init() { register(&rbcdCmd{}) }

func (c *rbcdCmd) Name() string     { return "rbcd" }
func (c *rbcdCmd) Synopsis() string { return "Manage msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)" }
func (c *rbcdCmd) Usage() string    { return helpRBCDOptions }

func (c *rbcdCmd) DefineFlags(f *flag.FlagSet) {
	f.StringVar(&c.action, "action", "", "Action: add, list, remove, clear (required)")
	f.StringVar(&c.target, "target", "", "sAMAccountName of the target object (required)")
	f.Var(&c.trustees, "trustee", "SID or sAMAccountName to add/remove (repeatable)")
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
	sids, err := decodeRBCD(blob)
	if err != nil {
		return fmt.Errorf("parse %s: %w", rbcdAttr, err)
	}
	if len(sids) == 0 {
		fmt.Fprintln(w, "  (DACL is empty)")
		return nil
	}
	for _, sid := range sids {
		fmt.Fprintf(w, "  %s\n", sid)
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
	current, _ := decodeRBCD(existingBlob)
	have := make(map[string]struct{}, len(current))
	for _, s := range current {
		have[s] = struct{}{}
	}
	for _, t := range trustees {
		sid, err := resolveTrusteeSID(conn, baseDN, t)
		if err != nil {
			return err
		}
		have[sid] = struct{}{}
	}
	updated := mapKeysSorted(have)

	newBlob, err := encodeRBCD(updated)
	if err != nil {
		return fmt.Errorf("encode SD: %w", err)
	}
	if err := writeRBCD(conn, dn, existingBlob, newBlob); err != nil {
		return err
	}
	fmt.Fprintf(w, "RBCD on %s now allows:\n", dn)
	for _, s := range updated {
		fmt.Fprintf(w, "  %s\n", s)
	}
	return nil
}

func rbcdRemove(conn *ldap.Conn, baseDN, dn string, existingBlob []byte, trustees []string, w io.Writer) error {
	current, err := decodeRBCD(existingBlob)
	if err != nil {
		return fmt.Errorf("decode existing SD: %w", err)
	}
	have := make(map[string]struct{}, len(current))
	for _, s := range current {
		have[s] = struct{}{}
	}
	removed := 0
	for _, t := range trustees {
		sid, err := resolveTrusteeSID(conn, baseDN, t)
		if err != nil {
			return err
		}
		if _, ok := have[sid]; ok {
			delete(have, sid)
			removed++
		} else {
			fmt.Fprintf(w, "warning: %s (%s) not in DACL\n", t, sid)
		}
	}
	if removed == 0 {
		return fmt.Errorf("no matching trustees to remove")
	}
	if len(have) == 0 {
		return rbcdClear(conn, dn, existingBlob, w)
	}
	updated := mapKeysSorted(have)
	newBlob, err := encodeRBCD(updated)
	if err != nil {
		return fmt.Errorf("encode SD: %w", err)
	}
	if err := writeRBCD(conn, dn, existingBlob, newBlob); err != nil {
		return err
	}
	fmt.Fprintf(w, "RBCD on %s now allows:\n", dn)
	for _, s := range updated {
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

// encodeRBCD builds a self-relative SECURITY_DESCRIPTOR with one
// ACCESS_ALLOWED_ACE per supplied trustee SID. Owner is the well-known
// Builtin\Administrators (S-1-5-32-544) so the SD is well-formed; group
// and SACL are absent.
func encodeRBCD(sids []string) ([]byte, error) {
	if len(sids) == 0 {
		return nil, fmt.Errorf("at least one trustee required")
	}

	ownerSID, err := encodeSID("S-1-5-32-544")
	if err != nil {
		return nil, err
	}

	// Build the DACL: header + one ACE per SID.
	var aces []byte
	for _, s := range sids {
		sidBytes, err := encodeSID(s)
		if err != nil {
			return nil, fmt.Errorf("trustee %s: %w", s, err)
		}
		aceSize := 4 + 4 + len(sidBytes) // type+flags+size header (4) + mask (4) + sid
		ace := make([]byte, aceSize)
		ace[0] = aceTypeAllowed
		ace[1] = 0
		binary.LittleEndian.PutUint16(ace[2:4], uint16(aceSize))
		binary.LittleEndian.PutUint32(ace[4:8], aceMaskGenericAll)
		copy(ace[8:], sidBytes)
		aces = append(aces, ace...)
	}
	aclSize := 8 + len(aces)
	dacl := make([]byte, aclSize)
	dacl[0] = aclRevisionDS
	dacl[1] = 0
	binary.LittleEndian.PutUint16(dacl[2:4], uint16(aclSize))
	binary.LittleEndian.PutUint16(dacl[4:6], uint16(len(sids)))
	binary.LittleEndian.PutUint16(dacl[6:8], 0)
	copy(dacl[8:], aces)

	// SD header is 20 bytes; offsets are relative to the start of the SD.
	const sdHeader = 20
	ownerOffset := uint32(sdHeader)
	daclOffset := ownerOffset + uint32(len(ownerSID))

	sd := make([]byte, sdHeader+len(ownerSID)+len(dacl))
	sd[0] = 1                                                     // Revision
	sd[1] = 0                                                     // Sbz1
	binary.LittleEndian.PutUint16(sd[2:4], seDaclPresent|seSelfRelative)
	binary.LittleEndian.PutUint32(sd[4:8], ownerOffset)
	binary.LittleEndian.PutUint32(sd[8:12], 0)
	binary.LittleEndian.PutUint32(sd[12:16], 0)
	binary.LittleEndian.PutUint32(sd[16:20], daclOffset)
	copy(sd[ownerOffset:], ownerSID)
	copy(sd[daclOffset:], dacl)
	return sd, nil
}

// decodeRBCD returns the SIDs in the security descriptor's DACL as
// "S-1-..." strings. Only ACCESS_ALLOWED_ACE entries are returned; other
// ACE types are silently skipped (RBCD only needs allowed ACEs).
func decodeRBCD(blob []byte) ([]string, error) {
	if len(blob) < 20 {
		return nil, fmt.Errorf("SD too short: %d bytes", len(blob))
	}
	rev := blob[0]
	if rev != 1 {
		return nil, fmt.Errorf("unsupported SD revision %d", rev)
	}
	control := binary.LittleEndian.Uint16(blob[2:4])
	if control&seSelfRelative == 0 {
		return nil, fmt.Errorf("SD is not self-relative (control 0x%x)", control)
	}
	if control&seDaclPresent == 0 {
		return nil, nil
	}
	daclOffset := binary.LittleEndian.Uint32(blob[16:20])
	if daclOffset == 0 || int(daclOffset)+8 > len(blob) {
		return nil, fmt.Errorf("DACL offset %d out of range", daclOffset)
	}
	dacl := blob[daclOffset:]
	if len(dacl) < 8 {
		return nil, fmt.Errorf("DACL header truncated")
	}
	aclSize := binary.LittleEndian.Uint16(dacl[2:4])
	aceCount := binary.LittleEndian.Uint16(dacl[4:6])
	if int(aclSize) > len(dacl) {
		return nil, fmt.Errorf("DACL size %d exceeds blob", aclSize)
	}
	dacl = dacl[:aclSize]
	off := 8
	var out []string
	for i := uint16(0); i < aceCount; i++ {
		if off+4 > len(dacl) {
			return nil, fmt.Errorf("ACE %d header truncated", i)
		}
		aceType := dacl[off]
		aceSize := binary.LittleEndian.Uint16(dacl[off+2 : off+4])
		if int(aceSize) < 8 || off+int(aceSize) > len(dacl) {
			return nil, fmt.Errorf("ACE %d size %d invalid", i, aceSize)
		}
		if aceType == aceTypeAllowed {
			// ACCESS_ALLOWED_ACE: type(1) flags(1) size(2) mask(4) sid(rest)
			sidBytes := dacl[off+8 : off+int(aceSize)]
			if s, ok := decodeSID(sidBytes); ok {
				out = append(out, s)
			}
		}
		off += int(aceSize)
	}
	return out, nil
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
