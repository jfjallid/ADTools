package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/jfjallid/go-smb/msdtyp"
	ldap "github.com/jfjallid/ldap/v3"
)

// The `access` subcommand answers "what effective access does this security
// principal have on this object?" — the equivalent of the Windows Advanced
// Security Settings "Effective Access" tab. It builds the principal's token
// (its own SID plus the transitive set of group SIDs the DC reports via the
// tokenGroups constructed attribute, plus the assumed session SIDs), then runs
// the canonical NT access-check against the target's flattened DACL and maps
// the result to friendly rights.
//
// Inheritance is already flattened into the stored nTSecurityDescriptor, so no
// inheritance engine is needed; we read the effective DACL as-is. Limitations
// (privileges, logon-type SIDs, claims/conditional ACEs) mirror the ones the
// Windows tab itself documents — see helpAccessOptions.

// Standard / object-specific ACCESS_MASK bits referenced by the access check.
const (
	rightCreateChild  uint32 = 0x00000001
	rightDeleteChild  uint32 = 0x00000002
	rightListChildren uint32 = 0x00000004
	rightDSSelf       uint32 = 0x00000008
	rightReadProp     uint32 = 0x00000010
	rightWriteProp    uint32 = 0x00000020
	rightDeleteTree   uint32 = 0x00000040
	rightListObject   uint32 = 0x00000080
	rightControl      uint32 = 0x00000100 // ADS_RIGHT_DS_CONTROL_ACCESS
	rightDelete       uint32 = 0x00010000
	rightReadControl  uint32 = 0x00020000
	rightGenericAll   uint32 = 0x10000000
	rightGenericExec  uint32 = 0x20000000
	rightGenericWrite uint32 = 0x40000000
	rightGenericRead  uint32 = 0x80000000

	sidOwnerRights = "S-1-3-4"  // OWNER_RIGHTS — overrides owner's implicit RC|WD
	sidPrincipself = "S-1-5-10" // SELF — the object acting on itself
)

type accessCmd struct {
	target        string
	principal     string
	rights        repeatStrFlag
	noSessionSIDs bool
	showToken     bool
}

func init() { register(&accessCmd{}) }

func (c *accessCmd) Name() string     { return "access" }
func (c *accessCmd) Synopsis() string { return "Compute a principal's effective access to an object" }
func (c *accessCmd) Usage() string    { return helpAccessOptions }

var helpAccessOptions = `
    Usage: ldaptool access [options]

    Compute the effective access a security principal has on a target object,
    accounting for direct ACEs, group membership (transitive/nested via the DC's
    tokenGroups), object ownership, and the assumed session SIDs (Everyone,
    Authenticated Users, This Organization).

    Options:
          --target      Object to evaluate: sAMAccountName, DN, or SID (required)
          --principal   Security principal to evaluate: sAMAccountName, DN, or
                        SID (required)
          --right       Ask only about a specific right (repeatable). Without it,
                        a full report is printed. Accepted forms:
                          - a preset:        ` + presetNames() + `
                          - a mask-bit name: WriteProperty, ReadProperty,
                            WriteDacl, WriteOwner, Delete, GenericAll, ...
                          - an extended-right or property GUID
                          - write:<attr>  / read:<attr>  (attribute lDAPDisplayName
                            or GUID), e.g. write:servicePrincipalName
                          - a bare attribute name reports BOTH read and write,
                            e.g. msDS-KeyCredentialLink
          --no-session-sids  Do not assume Everyone / Authenticated Users /
                             This Organization in the principal's token
          --show-token       Print the expanded SID set used for the check

    Notes / limitations (as in the Windows "Effective Access" tab):
      - Privileges (SeBackup/SeRestore/SeTakeOwnership) are not modelled.
      - Logon-type SIDs (Interactive/Network/...) are not modelled; only the
        common session SIDs are assumed (toggle with --no-session-sids).
      - Conditional/claims ACEs are not evaluated.
      - Property-SET ACEs are reported by set; member properties are not expanded.

    Examples:
      access --target dc01 --principal helpdesk
      access --target dc01 --principal bob --right write:servicePrincipalName
      access --target "DC=corp,DC=local" --principal bob --right dcsync
` + helpConnectionOptions

func (c *accessCmd) DefineFlags(f *flag.FlagSet) {
	f.StringVar(&c.target, "target", "", "Target object: sAMAccountName, DN, or SID (required)")
	f.StringVar(&c.principal, "principal", "", "Security principal: sAMAccountName, DN, or SID (required)")
	f.Var(&c.rights, "right", "Ask only about a specific right (repeatable); default is a full report")
	f.BoolVar(&c.noSessionSIDs, "no-session-sids", false, "Do not assume Everyone/Authenticated Users/This Organization")
	f.BoolVar(&c.showToken, "show-token", false, "Print the expanded SID set used for the check")
}

func (c *accessCmd) validate() error {
	if c.target == "" {
		return fmt.Errorf("--target is required")
	}
	if c.principal == "" {
		return fmt.Errorf("--principal is required")
	}
	return nil
}

func (c *accessCmd) Run(a *connArgs) error {
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
	return runAccess(conn, baseDN, c, os.Stdout)
}

func runAccess(conn *ldap.Conn, baseDN string, c *accessCmd, w io.Writer) error {
	// Collecting the security descriptor and expanding the principal's token are
	// the slow, network-bound steps (and resolving SID names during the report
	// adds more round-trips). On objects with large DACLs this looks like a hang,
	// so emit progress markers around data collection and report the counts that
	// drive the analysis.
	fmt.Fprintf(w, "[*] Collecting security descriptor for target %q...\n", c.target)
	dn, blob, _, err := lookupTargetSD(conn, baseDN, c.target)
	if err != nil {
		return err
	}
	sd, err := parseSD(blob)
	if err != nil {
		return err
	}
	targetSID := objectSIDForDN(conn, dn)

	fmt.Fprintf(w, "[*] Expanding group membership for principal %q...\n", c.principal)
	token, degraded, err := principalSIDSet(conn, baseDN, c.principal, targetSID, !c.noSessionSIDs)
	if err != nil {
		return err
	}

	resolver := newSIDResolver(conn, baseDN, true)
	gresolver := newGUIDResolver(conn, true)
	ac := newAccessChecker(sd, token)

	daclACEs := 0
	if sd.Dacl != nil {
		daclACEs = len(sd.Dacl.ACLS)
	}
	fmt.Fprintf(w, "[*] Data collection complete: %d ACE(s) in DACL, %d SID(s) in principal token, %d ACE(s) apply to the principal.\n",
		daclACEs, len(token), len(ac.aces))
	fmt.Fprintln(w, "[*] Analyzing effective access (resolving SID names may take a moment)...")
	fmt.Fprintln(w)

	fmt.Fprintf(w, "Effective access for %s on %s\n", c.principal, dn)
	if degraded {
		fmt.Fprintln(w, "  [!] tokenGroups unavailable; membership computed via fallback (may be incomplete)")
	}
	if c.showToken {
		printToken(w, token, resolver)
	}

	if len(c.rights) > 0 {
		checks, err := buildRightChecks(conn, c.rights)
		if err != nil {
			return err
		}
		fmt.Fprintln(w)
		for _, rc := range checks {
			status, src := ac.evaluate(rc)
			printRightResult(w, rc.label, status, src, resolver)
		}
		return nil
	}

	reportEffective(w, ac, sd, resolver, gresolver)
	return nil
}

// objectSIDForDN reads objectSid for a DN; returns "" if unavailable. Used only
// to decide whether the SELF SID applies (target == principal).
func objectSIDForDN(conn *ldap.Conn, dn string) string {
	res, err := conn.Search(ldap.NewSearchRequest(
		dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"objectSid"}, nil,
	))
	if err != nil || len(res.Entries) == 0 {
		return ""
	}
	for _, attr := range res.Entries[0].Attributes {
		if strings.EqualFold(attr.Name, "objectSid") && len(attr.ByteValues) > 0 {
			if s, ok := decodeSID(attr.ByteValues[0]); ok {
				return s
			}
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Token building
// ---------------------------------------------------------------------------

// principalSIDSet expands a principal into the set of SIDs that participate in
// an access check: its own SID, every group SID the DC reports via tokenGroups
// (transitive/nested, plus primary group and sIDHistory groups), the SELF SID
// when the principal is the target, and the assumed session SIDs. The bool
// return reports that tokenGroups was unavailable and a degraded fallback was
// used.
func principalSIDSet(conn *ldap.Conn, baseDN, principal, targetSID string, includeSession bool) (map[string]bool, bool, error) {
	dn, primarySID, err := resolvePrincipalDN(conn, baseDN, principal)
	if err != nil {
		return nil, false, err
	}

	set := map[string]bool{}
	if primarySID != "" {
		set[primarySID] = true
	}

	degraded := false
	res, err := conn.Search(ldap.NewSearchRequest(
		dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)",
		[]string{"tokenGroups", "primaryGroupID", "objectSid"}, nil,
	))
	if err == nil && len(res.Entries) > 0 {
		for _, attr := range res.Entries[0].Attributes {
			if strings.EqualFold(attr.Name, "tokenGroups") {
				for _, bv := range attr.ByteValues {
					if s, ok := decodeSID(bv); ok {
						set[s] = true
					}
				}
			}
		}
	}

	// Count how many group SIDs we got; tokenGroups always includes at least
	// the primary group, so an empty result means the server withheld it.
	if len(set) <= 1 {
		degraded = true
		for s := range chainGroupSIDs(conn, baseDN, dn) {
			set[s] = true
		}
		if primarySID != "" {
			if pg := primaryGroupSID(primarySID); pg != "" {
				set[pg] = true
			}
		}
	}

	if targetSID != "" && primarySID != "" && strings.EqualFold(targetSID, primarySID) {
		set[sidPrincipself] = true
	}
	if includeSession {
		set["S-1-1-0"] = true  // Everyone
		set["S-1-5-11"] = true // Authenticated Users
		set["S-1-5-15"] = true // This Organization
	}
	return set, degraded, nil
}

// resolvePrincipalDN resolves a sAMAccountName/DN/SID to its DN and string SID.
func resolvePrincipalDN(conn *ldap.Conn, baseDN, principal string) (dn, sid string, err error) {
	var searchBase, filter string
	scope := ldap.ScopeWholeSubtree
	switch {
	case strings.HasPrefix(strings.ToUpper(principal), "S-1-"):
		sidBytes, e := encodeSID(principal)
		if e != nil {
			return "", "", fmt.Errorf("invalid principal SID %q: %w", principal, e)
		}
		searchBase, filter = baseDN, "(objectSid="+ldapBinaryFilter(sidBytes)+")"
	case strings.Contains(principal, "="):
		searchBase, scope, filter = principal, ldap.ScopeBaseObject, "(objectClass=*)"
	default:
		candidates := []string{principal}
		if !strings.HasSuffix(principal, "$") {
			candidates = append(candidates, principal+"$")
		}
		var parts []string
		for _, cand := range candidates {
			parts = append(parts, fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(cand)))
		}
		searchBase, filter = baseDN, "(|"+strings.Join(parts, "")+")"
	}
	res, err := conn.Search(ldap.NewSearchRequest(
		searchBase, scope, ldap.NeverDerefAliases,
		0, 0, false, filter,
		[]string{"distinguishedName", "objectSid"}, nil,
	))
	if err != nil {
		return "", "", fmt.Errorf("resolve principal %q: %w", principal, err)
	}
	if len(res.Entries) == 0 {
		return "", "", fmt.Errorf("principal %q not found", principal)
	}
	if len(res.Entries) > 1 {
		return "", "", fmt.Errorf("principal %q matched %d entries; be more specific", principal, len(res.Entries))
	}
	e := res.Entries[0]
	for _, attr := range e.Attributes {
		if strings.EqualFold(attr.Name, "objectSid") && len(attr.ByteValues) > 0 {
			sid, _ = decodeSID(attr.ByteValues[0])
		}
	}
	return e.DN, sid, nil
}

// chainGroupSIDs is the tokenGroups fallback: it walks transitive group
// membership with LDAP_MATCHING_RULE_IN_CHAIN and returns the groups' SIDs.
func chainGroupSIDs(conn *ldap.Conn, baseDN, principalDN string) map[string]bool {
	out := map[string]bool{}
	filter := "(member:1.2.840.113556.1.4.1941:=" + ldap.EscapeFilter(principalDN) + ")"
	res, err := conn.Search(ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter, []string{"objectSid"}, nil,
	))
	if err != nil {
		return out
	}
	for _, e := range res.Entries {
		for _, attr := range e.Attributes {
			if strings.EqualFold(attr.Name, "objectSid") && len(attr.ByteValues) > 0 {
				if s, ok := decodeSID(attr.ByteValues[0]); ok {
					out[s] = true
				}
			}
		}
	}
	return out
}

// primaryGroupSID derives the primary-group SID (domain SID + 513 etc.) from a
// user's own SID. The fallback path can't read primaryGroupID reliably, so we
// approximate Domain Users; callers already have the user SID's domain prefix.
func primaryGroupSID(userSID string) string {
	i := strings.LastIndex(userSID, "-")
	if i < 0 {
		return ""
	}
	return userSID[:i] + "-513" // Domain Users; best-effort in the fallback path
}

func printToken(w io.Writer, token map[string]bool, r *sidResolver) {
	sids := make([]string, 0, len(token))
	for s := range token {
		sids = append(sids, s)
	}
	sort.Strings(sids)
	fmt.Fprintf(w, "  Token (%d SIDs):\n", len(sids))
	for _, s := range sids {
		fmt.Fprintf(w, "    %s\n", r.format(s))
	}
}

// ---------------------------------------------------------------------------
// Access check
// ---------------------------------------------------------------------------

type accessStatus int

const (
	statusNotGranted accessStatus = iota
	statusAllow
	statusDeny
)

// appliedACE is a DACL ACE that applies to the principal (its trustee SID is in
// the token and it is not inherit-only), reduced to what the check needs.
type appliedACE struct {
	allow bool
	mask  uint32
	guid  string // lowercase ObjectType GUID, "" if none (applies generally)
	src   string // trustee SID, for attribution
}

type accessChecker struct {
	aces           []appliedACE
	ownerInToken   bool
	ownerSID       string
	ownerRightsACE bool
}

func newAccessChecker(sd *msdtyp.SecurityDescriptor, token map[string]bool) *accessChecker {
	ac := &accessChecker{}
	if sd.OwnerSid != nil {
		ac.ownerSID = sd.OwnerSid.ToString()
		ac.ownerInToken = token[ac.ownerSID]
	}
	if sd.Dacl == nil {
		return ac
	}
	for _, ace := range sd.Dacl.ACLS {
		t := ace.Header.Type
		allow := t == msdtyp.AccessAllowedAceType || t == msdtyp.AccessAllowedObjectAceType
		deny := t == msdtyp.AccessDeniedAceType || t == msdtyp.AccessDeniedObjectAceType
		if !allow && !deny {
			continue // audit/alarm/callback ACEs are not access-granting
		}
		if ace.Header.Flags&msdtyp.InheritOnlyAce != 0 {
			continue // inherit-only ACEs do not control access to this object
		}
		sid := ace.Sid.ToString()
		if sid == sidOwnerRights {
			ac.ownerRightsACE = true
		}
		if !token[sid] {
			continue
		}
		var guid string
		if msdtyp.IsObjectAceType(t) && ace.ObjectFlags&msdtyp.AceObjectTypePresent != 0 {
			guid = strings.ToLower(msdtyp.GuidToString(ace.ObjectType))
		}
		ac.aces = append(ac.aces, appliedACE{allow: allow, mask: ace.Mask, guid: guid, src: sid})
	}
	return ac
}

// expandADGenericMask maps the GENERIC_* bits onto their AD-specific
// equivalents (MS-ADTS 5.1.3.2.1) so a GenericAll/Write/Read ACE is recognised
// as granting the concrete object rights it implies.
func expandADGenericMask(m uint32) uint32 {
	if m&rightGenericRead != 0 {
		m |= rightReadControl | rightListChildren | rightReadProp | rightListObject
	}
	if m&rightGenericWrite != 0 {
		m |= rightReadControl | rightDSSelf | rightWriteProp
	}
	if m&rightGenericExec != 0 {
		m |= rightReadControl | rightListChildren
	}
	if m&rightGenericAll != 0 {
		m |= maskFullControl | rightControl | rightDeleteTree | rightListObject
	}
	return m
}

// check answers whether the principal is granted neededBit for the given object
// type (guid; "" for a non-object-typed standard right). It walks the DACL in
// canonical order: the first applicable ACE that speaks to neededBit wins, so a
// preceding deny beats a later allow. Owner's implicit READ_CONTROL|WRITE_DAC
// is applied only when no ACE spoke to the bit and OWNER_RIGHTS is absent.
func (ac *accessChecker) check(neededBit uint32, guid string) (accessStatus, string) {
	guid = strings.ToLower(guid)
	for _, a := range ac.aces {
		if !aceApplies(a.guid, guid) {
			continue
		}
		if expandADGenericMask(a.mask)&neededBit == 0 {
			continue
		}
		if a.allow {
			return statusAllow, a.src
		}
		return statusDeny, a.src
	}
	if neededBit&(rightReadControl|rightWriteDacl) != 0 && ac.ownerInToken && !ac.ownerRightsACE {
		return statusAllow, ac.ownerSID + " (owner)"
	}
	return statusNotGranted, ""
}

// aceApplies reports whether an ACE with object-type aceGUID is in scope for a
// query about object-type queryGUID. A generic ACE (no ObjectType) applies to
// everything; an object-typed ACE applies only to a matching object-type query.
func aceApplies(aceGUID, queryGUID string) bool {
	if aceGUID == "" {
		return true
	}
	if queryGUID == "" {
		return false
	}
	return aceGUID == queryGUID
}

// ---------------------------------------------------------------------------
// --right parsing and evaluation
// ---------------------------------------------------------------------------

// queryPart is one (bit, object-type) test; a rightCheck is satisfied only when
// all of its parts are allowed (e.g. DCSync needs both replication rights).
type queryPart struct {
	bit  uint32
	guid string
}

type rightCheck struct {
	label string
	parts []queryPart
}

func (ac *accessChecker) evaluate(rc rightCheck) (accessStatus, string) {
	var firstAllowSrc string
	for _, p := range rc.parts {
		st, src := ac.check(p.bit, p.guid)
		switch st {
		case statusDeny:
			return statusDeny, src
		case statusNotGranted:
			return statusNotGranted, ""
		case statusAllow:
			if firstAllowSrc == "" {
				firstAllowSrc = src
			}
		}
	}
	return statusAllow, firstAllowSrc
}

// maskBitByName maps a friendly mask-bit name (as printed by formatAccessMask)
// to its bit, for --right WriteProperty / WriteDacl / GenericAll / ...
func maskBitByName(name string) (uint32, bool) {
	for _, e := range adAccessMaskNames {
		if strings.EqualFold(e.name, name) {
			return e.bit, true
		}
	}
	return 0, false
}

// buildRightChecks turns each --right token into one or more rightChecks.
func buildRightChecks(conn *ldap.Conn, tokens []string) ([]rightCheck, error) {
	var out []rightCheck
	for _, tok := range tokens {
		rcs, err := parseRightToken(conn, tok)
		if err != nil {
			return nil, err
		}
		out = append(out, rcs...)
	}
	return out, nil
}

func parseRightToken(conn *ldap.Conn, tok string) ([]rightCheck, error) {
	tok = strings.TrimSpace(tok)

	// Qualified property forms: write:<attr|guid> / read:<attr|guid>.
	if op, rest, ok := splitOp(tok); ok {
		guid, label, err := resolvePropTarget(conn, rest)
		if err != nil {
			return nil, err
		}
		bit := rightWriteProp
		verb := "Write"
		if op == "read" {
			bit, verb = rightReadProp, "Read"
		}
		return []rightCheck{{label: verb + " " + label, parts: []queryPart{{bit: bit, guid: guid}}}}, nil
	}

	low := strings.ToLower(tok)

	// Preset (FullControl, DCSync, ResetPassword, ...).
	if specs, ok := rightsPresets[low]; ok {
		var parts []queryPart
		for _, s := range specs {
			parts = append(parts, queryPart{bit: s.mask, guid: s.guid})
		}
		return []rightCheck{{label: tok, parts: parts}}, nil
	}

	// Mask-bit name (WriteProperty, WriteDacl, GenericAll, ...).
	if bit, ok := maskBitByName(tok); ok {
		return []rightCheck{{label: tok, parts: []queryPart{{bit: bit, guid: ""}}}}, nil
	}

	// Raw GUID: treat as an extended/control-access right.
	if looksLikeGUID(tok) {
		label := friendlyGUIDName(tok)
		if label == "" {
			label = tok
		}
		return []rightCheck{{label: label, parts: []queryPart{{bit: rightControl, guid: low}}}}, nil
	}

	// Bare attribute lDAPDisplayName: report both read and write.
	guid, label, err := resolvePropTarget(conn, tok)
	if err != nil {
		return nil, fmt.Errorf("unrecognised --right %q: %w", tok, err)
	}
	return []rightCheck{
		{label: "Write " + label, parts: []queryPart{{bit: rightWriteProp, guid: guid}}},
		{label: "Read " + label, parts: []queryPart{{bit: rightReadProp, guid: guid}}},
	}, nil
}

func splitOp(tok string) (op, rest string, ok bool) {
	for _, p := range []string{"write", "read"} {
		if len(tok) > len(p)+1 && strings.EqualFold(tok[:len(p)], p) && tok[len(p)] == ':' {
			return p, tok[len(p)+1:], true
		}
	}
	return "", "", false
}

// resolvePropTarget resolves an attribute lDAPDisplayName or GUID to its
// schemaIDGUID (lowercase) and a friendly label.
func resolvePropTarget(conn *ldap.Conn, name string) (guid, label string, err error) {
	if looksLikeGUID(name) {
		g := strings.ToLower(name)
		if l := friendlyGUIDName(g); l != "" {
			return g, l, nil
		}
		return g, name, nil
	}
	g, err := resolveAttrGUID(conn, name)
	if err != nil {
		return "", "", err
	}
	return g, name, nil
}

func looksLikeGUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, ch := range s {
		switch i {
		case 8, 13, 18, 23:
			if ch != '-' {
				return false
			}
		default:
			if !isHexDigit(byte(ch)) {
				return false
			}
		}
	}
	return true
}

func isHexDigit(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// resolveAttrGUID looks up an attribute's schemaIDGUID from the schema NC.
func resolveAttrGUID(conn *ldap.Conn, lDAPDisplayName string) (string, error) {
	if schemaDNCache == "" {
		root, err := conn.Search(ldap.NewSearchRequest(
			"", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
			0, 0, false, "(objectClass=*)", []string{"schemaNamingContext"}, nil,
		))
		if err != nil || len(root.Entries) == 0 {
			return "", fmt.Errorf("locate schema NC: %v", err)
		}
		schemaDNCache = root.Entries[0].GetAttributeValue("schemaNamingContext")
	}
	filter := fmt.Sprintf("(&(objectClass=attributeSchema)(lDAPDisplayName=%s))", ldap.EscapeFilter(lDAPDisplayName))
	res, err := conn.Search(ldap.NewSearchRequest(
		schemaDNCache, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter, []string{"schemaIDGUID"}, nil,
	))
	if err != nil {
		return "", fmt.Errorf("schema lookup: %w", err)
	}
	if len(res.Entries) == 0 {
		return "", fmt.Errorf("attribute %q not found in schema", lDAPDisplayName)
	}
	for _, attr := range res.Entries[0].Attributes {
		if strings.EqualFold(attr.Name, "schemaIDGUID") && len(attr.ByteValues) > 0 && len(attr.ByteValues[0]) == 16 {
			var g [16]byte
			copy(g[:], attr.ByteValues[0])
			return strings.ToLower(msdtyp.GuidToString(g)), nil
		}
	}
	return "", fmt.Errorf("attribute %q has no schemaIDGUID", lDAPDisplayName)
}

// ---------------------------------------------------------------------------
// Live GUID -> name resolution
// ---------------------------------------------------------------------------

// guidResolver turns an object-ACE ObjectType GUID into a friendly name. It
// first consults the static wellKnownGUIDNames table (offline, no round-trip)
// and, on a miss, falls back to the target's own forest: control-access rights
// (extended rights / validated writes / property sets) are looked up under
// CN=Extended-Rights in the configuration NC by their string rightsGuid, and
// individual attributes / classes are looked up in the schema NC by their
// binary schemaIDGUID. Results (including misses, cached as "") are memoised, so
// a DACL with many ACEs costs at most one round-trip per distinct unknown GUID.
type guidResolver struct {
	conn     *ldap.Conn
	enabled  bool
	ncLoaded bool
	configNC string
	schemaNC string
	cache    map[string]string
}

func newGUIDResolver(conn *ldap.Conn, enabled bool) *guidResolver {
	return &guidResolver{conn: conn, enabled: enabled, cache: map[string]string{}}
}

// name returns a friendly name for an object GUID, or "" if it cannot be
// resolved. Input is case-insensitive.
func (r *guidResolver) name(guid string) string {
	g := strings.ToLower(guid)
	if n := friendlyGUIDName(g); n != "" {
		return n
	}
	if !r.enabled || r.conn == nil {
		return ""
	}
	if n, ok := r.cache[g]; ok {
		return n
	}
	n := r.lookup(g)
	r.cache[g] = n
	return n
}

// label returns a friendly name when known, otherwise the bare GUID, so callers
// always have something printable.
func (r *guidResolver) label(guid string) string {
	if n := r.name(guid); n != "" {
		return n
	}
	return guid
}

// format renders "<guid> (<name>)" when a name is resolvable, otherwise the bare
// GUID — the verbose form used by the raw DACL dump in `dacl read`. Mirrors
// sidResolver.format.
func (r *guidResolver) format(guid string) string {
	if n := r.name(guid); n != "" {
		return fmt.Sprintf("%s (%s)", guid, n)
	}
	return guid
}

// ensureNCs discovers the configuration and schema naming contexts from the
// rootDSE once; on failure the NCs stay "" and live lookups are skipped.
func (r *guidResolver) ensureNCs() {
	if r.ncLoaded {
		return
	}
	r.ncLoaded = true
	res, err := r.conn.Search(ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)",
		[]string{"configurationNamingContext", "schemaNamingContext"}, nil,
	))
	if err != nil || len(res.Entries) == 0 {
		return
	}
	r.configNC = res.Entries[0].GetAttributeValue("configurationNamingContext")
	r.schemaNC = res.Entries[0].GetAttributeValue("schemaNamingContext")
}

func (r *guidResolver) lookup(guid string) string {
	r.ensureNCs()
	// Control-access right: rightsGuid is stored as a dashed string.
	if r.configNC != "" {
		res, err := r.conn.Search(ldap.NewSearchRequest(
			"CN=Extended-Rights,"+r.configNC, ldap.ScopeSingleLevel, ldap.NeverDerefAliases,
			0, 0, false,
			"(rightsGuid="+ldap.EscapeFilter(guid)+")",
			[]string{"cn", "displayName"}, nil,
		))
		if err == nil && len(res.Entries) > 0 {
			if n := labelControlAccessRight(res.Entries[0]); n != "" {
				return n
			}
		}
	}
	// Schema attribute / class: schemaIDGUID is stored as a 16-byte octet string.
	if r.schemaNC != "" {
		if gb, err := msdtyp.GuidFromString(guid); err == nil {
			res, err := r.conn.Search(ldap.NewSearchRequest(
				r.schemaNC, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
				0, 0, false,
				"(schemaIDGUID="+ldapBinaryFilter(gb[:])+")",
				[]string{"lDAPDisplayName", "objectClass"}, nil,
			))
			if err == nil && len(res.Entries) > 0 {
				if n := labelSchemaObject(res.Entries[0]); n != "" {
					return n
				}
			}
		}
	}
	return ""
}

// labelControlAccessRight names a CN=Extended-Rights entry, preferring the cn so
// it matches the wellKnownGUIDNames style (e.g. "DS-Replication-Get-Changes").
func labelControlAccessRight(e *ldap.Entry) string {
	if cn := e.GetAttributeValue("cn"); cn != "" {
		return cn
	}
	return e.GetAttributeValue("displayName")
}

// labelSchemaObject names an attributeSchema/classSchema entry with a "(class)"
// or "(attribute)" suffix, matching the static table's convention.
func labelSchemaObject(e *ldap.Entry) string {
	name := e.GetAttributeValue("lDAPDisplayName")
	if name == "" {
		return ""
	}
	for _, oc := range e.GetAttributeValues("objectClass") {
		if strings.EqualFold(oc, "classSchema") {
			return name + " (class)"
		}
	}
	return name + " (attribute)"
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

func printRightResult(w io.Writer, label string, st accessStatus, src string, r *sidResolver) {
	switch st {
	case statusAllow:
		fmt.Fprintf(w, "  %-40s ALLOW   (via %s)\n", label+":", srcLabel(src, r))
	case statusDeny:
		fmt.Fprintf(w, "  %-40s DENY    (explicit deny from %s)\n", label+":", srcLabel(src, r))
	default:
		fmt.Fprintf(w, "  %-40s not granted\n", label+":")
	}
}

// srcLabel renders a granting-source SID with its resolved name. The synthetic
// "<sid> (owner)" attribution string is passed through as-is.
func srcLabel(src string, r *sidResolver) string {
	if i := strings.Index(src, " ("); i >= 0 {
		return r.format(src[:i]) + src[i:]
	}
	return r.format(src)
}

// standardReportRights are the non-object rights listed in a full report.
var standardReportRights = []struct {
	bit  uint32
	name string
}{
	{rightGenericAll, "Full Control / GenericAll"},
	{rightWriteDacl, "Write DACL (→ takeover)"},
	{rightWriteOwner, "Write Owner (→ takeover)"},
	{rightDelete, "Delete"},
	{rightDeleteTree, "Delete Tree"},
	{rightCreateChild, "Create Child"},
	{rightDeleteChild, "Delete Child"},
	{rightWriteProp, "Write (all properties)"},
	{rightReadProp, "Read (all properties)"},
	{rightControl, "All Extended Rights"},
	{rightReadControl, "Read Control"},
}

// notableExtRights are extended rights / properties flagged as abuse primitives
// in a full report even when granted via a generic ControlAccess/WriteProp ACE.
var notableExtRights = []struct {
	guid string
	bit  uint32
	name string
}{
	{guidResetPassword, rightControl, "Reset Password"},
	{guidMember, rightWriteProp, "Write member"},
	{guidServicePrincipalName, rightWriteProp, "Write servicePrincipalName"},
	{guidKeyCredentialLink, rightWriteProp, "Write msDS-KeyCredentialLink"},
	{guidAllowedToActOnBehalf, rightWriteProp, "Write msDS-AllowedToActOnBehalfOfOtherIdentity"},
}

func reportEffective(w io.Writer, ac *accessChecker, sd *msdtyp.SecurityDescriptor, r *sidResolver, gr *guidResolver) {
	if sd.OwnerSid != nil {
		owned := ""
		if ac.ownerInToken {
			owned = "  <-- principal is (in) the owner"
		}
		fmt.Fprintf(w, "  Owner: %s%s\n", r.format(sd.OwnerSid.ToString()), owned)
	}
	fmt.Fprintln(w, "\n  Standard rights:")
	anyStd := false
	for _, sr := range standardReportRights {
		if st, src := ac.check(sr.bit, ""); st == statusAllow {
			anyStd = true
			fmt.Fprintf(w, "    [+] %-32s via %s\n", sr.name, srcLabel(src, r))
		}
	}
	if !anyStd {
		fmt.Fprintln(w, "    (none)")
	}

	fmt.Fprintln(w, "\n  Notable extended rights / property writes:")
	anyExt := false
	if dcsyncCapable(ac) {
		anyExt = true
		fmt.Fprintln(w, "    [!] DCSync (DS-Replication-Get-Changes + -All)")
	}
	for _, nr := range notableExtRights {
		if st, src := ac.check(nr.bit, nr.guid); st == statusAllow {
			anyExt = true
			fmt.Fprintf(w, "    [!] %-40s via %s\n", nr.name, srcLabel(src, r))
		}
	}
	if !anyExt {
		fmt.Fprintln(w, "    (none)")
	}

	// Per-GUID grants actually present in the DACL for this principal, beyond
	// the well-known set above.
	printObjectGrants(w, ac, r, gr)
}

func dcsyncCapable(ac *accessChecker) bool {
	a, _ := ac.check(rightControl, guidGetChanges)
	b, _ := ac.check(rightControl, guidGetChangesAll)
	return a == statusAllow && b == statusAllow
}

func printObjectGrants(w io.Writer, ac *accessChecker, r *sidResolver, gr *guidResolver) {
	seen := map[string]bool{}
	var lines []string
	for _, a := range ac.aces {
		if !a.allow || a.guid == "" || seen[a.guid] {
			continue
		}
		seen[a.guid] = true
		st, src := ac.check(expandADGenericMask(a.mask), a.guid)
		if st != statusAllow {
			continue
		}
		name := gr.label(a.guid)
		lines = append(lines, fmt.Sprintf("    [+] %-44s (%s) via %s", name, formatAccessMask(a.mask), srcLabel(src, r)))
	}
	if len(lines) == 0 {
		return
	}
	sort.Strings(lines)
	fmt.Fprintln(w, "\n  Object-specific grants:")
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
}
