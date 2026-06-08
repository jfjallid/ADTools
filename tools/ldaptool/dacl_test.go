package main

import (
	"strings"
	"testing"

	"github.com/jfjallid/go-smb/msdtyp"
)

func TestFormatAccessMask(t *testing.T) {
	cases := []struct {
		mask uint32
		want string // substring that must appear in the rendered names
	}{
		{0, "0x00000000"},
		{maskFullControl, "FullControl"},
		{adsRightDSControlAccess, "ControlAccess"},
		{adsRightDSWriteProp, "WriteProperty"},
		{rightWriteDacl, "WriteDacl"},
		{0x10000000, "GenericAll"},
		{0x00000010 | 0x00000020, "ReadProperty|WriteProperty"},
	}
	for _, c := range cases {
		got := formatAccessMask(c.mask)
		if !strings.Contains(got, c.want) {
			t.Errorf("formatAccessMask(%#x) = %q, want substring %q", c.mask, got, c.want)
		}
	}
	// Unknown leftover bits are surfaced as hex, not dropped.
	if got := formatAccessMask(0x00000010 | 0x00000800); !strings.Contains(got, "0x00000800") {
		t.Errorf("formatAccessMask did not surface unknown bits: %q", got)
	}
}

func TestWellKnownSIDName(t *testing.T) {
	cases := map[string]string{
		"S-1-1-0":      "Everyone",
		"S-1-5-18":     "Local System",
		"S-1-5-32-544": "BUILTIN\\Administrators",
		"S-1-5-21-1004336348-1177238915-682003330-512": "Domain Admins",
		"S-1-5-21-1004336348-1177238915-682003330-502": "krbtgt",
	}
	for sid, want := range cases {
		if got := wellKnownSIDName(sid); got != want {
			t.Errorf("wellKnownSIDName(%q) = %q, want %q", sid, got, want)
		}
	}
	if got := wellKnownSIDName("S-1-5-21-1-2-3-1104"); got != "" {
		t.Errorf("wellKnownSIDName(non-well-known) = %q, want empty", got)
	}
}

func TestFriendlyGUIDName(t *testing.T) {
	if got := friendlyGUIDName(strings.ToUpper(guidGetChanges)); got != "DS-Replication-Get-Changes" {
		t.Errorf("friendlyGUIDName(GetChanges) = %q", got)
	}
	if got := friendlyGUIDName("deadbeef-0000-0000-0000-000000000000"); got != "" {
		t.Errorf("friendlyGUIDName(unknown) = %q, want empty", got)
	}
	// Default attribute schemaIDGUIDs must now resolve so per-property grants
	// (e.g. write sAMAccountName/displayName) read as names, not bare GUIDs.
	attrs := map[string]string{
		"3e0abfd0-126a-11d0-a060-00aa006c33ed": "sAMAccountName (attribute)",
		"bf967953-0de6-11d0-a285-00aa003049e2": "displayName (attribute)",
		guidServicePrincipalName:               "servicePrincipalName (attribute / Validated-SPN)",
	}
	for guid, want := range attrs {
		if got := friendlyGUIDName(guid); got != want {
			t.Errorf("friendlyGUIDName(%q) = %q, want %q", guid, got, want)
		}
	}
}

func TestParsedMask(t *testing.T) {
	cases := []struct {
		in   string
		want uint32
		err  bool
	}{
		{"", 0, false},
		{"0x000F01FF", 0x000F01FF, false},
		{"0xff", 0xff, false},
		{"256", 256, false},
		{"nothex", 0, true},
	}
	for _, c := range cases {
		cmd := &daclCmd{maskStr: c.in}
		got, err := cmd.parsedMask()
		if c.err {
			if err == nil {
				t.Errorf("parsedMask(%q): expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parsedMask(%q): %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("parsedMask(%q) = %#x, want %#x", c.in, got, c.want)
		}
	}
}

const testTrustee = "S-1-5-21-1004336348-1177238915-682003330-1104"

func TestBuildACEsFullControl(t *testing.T) {
	aces, err := buildACEsForGrant(testTrustee, msdtyp.AccessAllowedAceType, 0, []string{"FullControl"}, 0, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(aces) != 1 {
		t.Fatalf("expected 1 ACE, got %d", len(aces))
	}
	a := aces[0]
	if a.Header.Type != msdtyp.AccessAllowedAceType {
		t.Errorf("FullControl should be a basic ACE, got type %#x", a.Header.Type)
	}
	if a.Mask != maskFullControl {
		t.Errorf("mask = %#x, want %#x", a.Mask, maskFullControl)
	}
	if msdtyp.IsObjectAceType(a.Header.Type) {
		t.Error("FullControl must not be an object ACE")
	}
	assertACESizeMatchesMarshal(t, a)
}

func TestBuildACEsResetPassword(t *testing.T) {
	aces, err := buildACEsForGrant(testTrustee, msdtyp.AccessAllowedAceType, 0, []string{"ResetPassword"}, 0, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(aces) != 1 {
		t.Fatalf("expected 1 ACE, got %d", len(aces))
	}
	a := aces[0]
	if a.Header.Type != msdtyp.AccessAllowedObjectAceType {
		t.Fatalf("ResetPassword should be an object ACE, got %#x", a.Header.Type)
	}
	if a.Mask != adsRightDSControlAccess {
		t.Errorf("mask = %#x, want ControlAccess %#x", a.Mask, adsRightDSControlAccess)
	}
	if a.ObjectFlags&msdtyp.AceObjectTypePresent == 0 {
		t.Error("ObjectType flag not set")
	}
	if got := msdtyp.GuidToString(a.ObjectType); got != guidResetPassword {
		t.Errorf("ObjectType = %q, want %q", got, guidResetPassword)
	}
	assertACESizeMatchesMarshal(t, a)
}

func TestBuildACEsDCSync(t *testing.T) {
	aces, err := buildACEsForGrant(testTrustee, msdtyp.AccessAllowedAceType, 0, []string{"DCSync"}, 0, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(aces) != 2 {
		t.Fatalf("DCSync should expand to 2 ACEs, got %d", len(aces))
	}
	guids := map[string]bool{}
	for _, a := range aces {
		if a.Header.Type != msdtyp.AccessAllowedObjectAceType || a.Mask != adsRightDSControlAccess {
			t.Errorf("unexpected DCSync ACE: type=%#x mask=%#x", a.Header.Type, a.Mask)
		}
		guids[msdtyp.GuidToString(a.ObjectType)] = true
		assertACESizeMatchesMarshal(t, a)
	}
	if !guids[guidGetChanges] || !guids[guidGetChangesAll] {
		t.Errorf("DCSync ACEs missing replication GUIDs: %v", guids)
	}
}

func TestBuildACEsRawMaskAndDenied(t *testing.T) {
	aces, err := buildACEsForGrant(testTrustee, msdtyp.AccessDeniedAceType, msdtyp.ContainerInheritAce, nil, 0x00020000, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(aces) != 1 {
		t.Fatalf("expected 1 ACE, got %d", len(aces))
	}
	a := aces[0]
	if a.Header.Type != msdtyp.AccessDeniedAceType {
		t.Errorf("type = %#x, want AccessDenied", a.Header.Type)
	}
	if a.Mask != 0x00020000 {
		t.Errorf("mask = %#x", a.Mask)
	}
	if a.Header.Flags&msdtyp.ContainerInheritAce == 0 {
		t.Error("ContainerInheritAce flag not propagated")
	}
}

func TestBuildACEsRightGUID(t *testing.T) {
	aces, err := buildACEsForGrant(testTrustee, msdtyp.AccessAllowedAceType, 0, nil, 0, []string{guidGetChanges}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(aces) != 1 || aces[0].Header.Type != msdtyp.AccessAllowedObjectAceType {
		t.Fatalf("right-guid should yield one object ACE: %+v", aces)
	}
	if aces[0].Mask != adsRightDSControlAccess {
		t.Errorf("right-guid ACE mask = %#x, want ControlAccess", aces[0].Mask)
	}
}

func TestBuildACEsErrors(t *testing.T) {
	if _, err := buildACEsForGrant(testTrustee, msdtyp.AccessAllowedAceType, 0, []string{"Bogus"}, 0, nil, ""); err == nil {
		t.Error("expected error for unknown preset")
	}
	if _, err := buildACEsForGrant(testTrustee, msdtyp.AccessAllowedAceType, 0, nil, 0, nil, ""); err == nil {
		t.Error("expected error when no rights specified")
	}
	if _, err := buildACEsForGrant(testTrustee, msdtyp.AccessAllowedAceType, 0, nil, 0, []string{"not-a-guid"}, ""); err == nil {
		t.Error("expected error for invalid right GUID")
	}
}

func assertACESizeMatchesMarshal(t *testing.T, a msdtyp.ACE) {
	t.Helper()
	buf, err := a.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if int(a.Header.Size) != len(buf) {
		t.Errorf("Header.Size %d != marshalled length %d", a.Header.Size, len(buf))
	}
}

func TestACEEquivalence(t *testing.T) {
	a, _ := buildACEsForGrant(testTrustee, msdtyp.AccessAllowedAceType, 0, []string{"ResetPassword"}, 0, nil, "")
	b, _ := buildACEsForGrant(testTrustee, msdtyp.AccessAllowedAceType, msdtyp.ContainerInheritAce, []string{"ResetPassword"}, 0, nil, "")
	// Flags differ but the grant is the same: must be considered equivalent.
	if !acesEquivalent(a[0], b[0]) {
		t.Error("ACEs differing only in flags should be equivalent")
	}
	c, _ := buildACEsForGrant(testTrustee, msdtyp.AccessAllowedAceType, 0, []string{"WriteMembers"}, 0, nil, "")
	if acesEquivalent(a[0], c[0]) {
		t.Error("ResetPassword and WriteMembers must not be equivalent")
	}
	dacl := &msdtyp.PACL{ACLS: []msdtyp.ACE{a[0]}}
	// Dedup is flag-aware: the same grant with a different inheritance scope is a
	// distinct ACE that may coexist, so it must not be reported as already present.
	if daclHasEquivalentACE(dacl, b[0]) {
		t.Error("daclHasEquivalentACE should treat different inheritance flags as distinct")
	}
	// An identical ACE (same grant and same flags) is already present.
	if !daclHasEquivalentACE(dacl, a[0]) {
		t.Error("daclHasEquivalentACE should match an identical ACE")
	}
	if daclHasEquivalentACE(dacl, c[0]) {
		t.Error("daclHasEquivalentACE matched a different grant")
	}
}

// TestDaclEditRoundTrip exercises the add→marshal→reparse→remove pipeline used
// by daclAdd/daclRemove, without any LDAP I/O.
func TestDaclEditRoundTrip(t *testing.T) {
	owner, _ := msdtyp.ConvertStrToSID("S-1-5-32-544")
	existing, _ := msdtyp.ConvertStrToSID("S-1-5-18")
	base := msdtyp.ACE{
		Header: msdtyp.ACEHeader{Type: msdtyp.AccessAllowedAceType},
		Mask:   maskFullControl,
		Sid:    *existing,
	}
	sd := &msdtyp.SecurityDescriptor{
		Revision: 1,
		Control:  msdtyp.SecurityDescriptorFlagSR,
		OwnerSid: owner,
		Dacl:     &msdtyp.PACL{AclRevision: 4, ACLS: []msdtyp.ACE{base}},
	}

	// Add a ResetPassword object ACE.
	add, err := buildACEsForGrant(testTrustee, msdtyp.AccessAllowedAceType, 0, []string{"ResetPassword"}, 0, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	sd.Dacl.ACLS = append(sd.Dacl.ACLS, add[0])
	recomputeDaclSizes(sd.Dacl)

	blob, err := sd.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	reparsed, err := parseSD(blob)
	if err != nil {
		t.Fatalf("parseSD: %v", err)
	}
	if len(reparsed.Dacl.ACLS) != 2 {
		t.Fatalf("expected 2 ACEs after add, got %d", len(reparsed.Dacl.ACLS))
	}
	objACE := reparsed.Dacl.ACLS[1]
	if objACE.Header.Type != msdtyp.AccessAllowedObjectAceType ||
		msdtyp.GuidToString(objACE.ObjectType) != guidResetPassword ||
		objACE.Sid.ToString() != testTrustee {
		t.Fatalf("object ACE did not survive round-trip: %+v", objACE)
	}

	// Now remove only the trustee's ResetPassword ACE; the SYSTEM full-control
	// ACE must remain.
	kept := reparsed.Dacl.ACLS[:0:0]
	for _, ace := range reparsed.Dacl.ACLS {
		if ace.Sid.ToString() == testTrustee && acesEquivalent(ace, add[0]) {
			continue
		}
		kept = append(kept, ace)
	}
	if len(kept) != 1 || kept[0].Sid.ToString() != existing.ToString() {
		t.Fatalf("remove-narrowing failed: %+v", kept)
	}
}

func TestParsedAceFlags(t *testing.T) {
	const ci = msdtyp.ContainerInheritAce
	const io = msdtyp.InheritOnlyAce
	cases := []struct {
		name string
		cmd  *daclCmd
		want byte
		err  bool
	}{
		{"none", &daclCmd{}, 0, false},
		{"inheritance", &daclCmd{inheritance: true}, ci, false},
		{"inheritance+inherit-only", &daclCmd{inheritance: true, inheritOnly: true}, ci | io, false},
		{"raw hex", &daclCmd{aceFlagsHex: "0x0A"}, 0x0A, false},
		{"raw decimal", &daclCmd{aceFlagsHex: "10"}, 0x0A, false},
		{"raw overflows byte", &daclCmd{aceFlagsHex: "0x100"}, 0, true},
		{"raw not a number", &daclCmd{aceFlagsHex: "xyz"}, 0, true},
	}
	for _, c := range cases {
		got, err := c.cmd.parsedAceFlags()
		if c.err {
			if err == nil {
				t.Errorf("%s: expected error", c.name)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: unexpected error: %v", c.name, err)
		}
		if got != c.want {
			t.Errorf("%s: parsedAceFlags = %#x, want %#x", c.name, got, c.want)
		}
	}
	// Raw flags and the inheritance booleans are mutually exclusive.
	mix := &daclCmd{action: "add", target: "bob", trustee: "evil",
		rights: repeatStrFlag{"FullControl"}, aceFlagsHex: "0x0A", inheritance: true}
	if err := mix.validate(); err == nil {
		t.Error("validate should reject --ace-flags combined with --inheritance")
	}
}

func TestAceMatchesRemoval(t *testing.T) {
	const ci = msdtyp.ContainerInheritAce
	const io = msdtyp.InheritOnlyAce
	// Two grants for the same trustee: a plain one (no flags) and an
	// inherit-only one (CI|IO).
	plain, _ := buildACEsForGrant(testTrustee, msdtyp.AccessAllowedAceType, 0, []string{"FullControl"}, 0, nil, "")
	inherit, _ := buildACEsForGrant(testTrustee, msdtyp.AccessAllowedAceType, ci|io, []string{"FullControl"}, 0, nil, "")
	other, _ := buildACEsForGrant(testTrustee, msdtyp.AccessAllowedAceType, 0, []string{"ResetPassword"}, 0, nil, "")

	// Permissive default (no grant, no flags): matches any ACE for the trustee.
	if !aceMatchesRemoval(plain[0], nil, false, false, 0) {
		t.Error("permissive removal should match every ACE for the trustee")
	}

	// By grant only: FullControl request matches both flag variants (flags
	// ignored) but not a different grant.
	match := plain
	if !aceMatchesRemoval(plain[0], match, true, false, 0) {
		t.Error("grant match should drop the plain FullControl ACE")
	}
	if !aceMatchesRemoval(inherit[0], match, true, false, 0) {
		t.Error("grant match should drop the inherit-only FullControl ACE (flags ignored)")
	}
	if aceMatchesRemoval(other[0], match, true, false, 0) {
		t.Error("grant match must not drop a different grant (ResetPassword)")
	}

	// Grant + flags: only the ACE whose flags byte equals the requested flags.
	if aceMatchesRemoval(plain[0], match, true, true, ci|io) {
		t.Error("flag-specific removal must not drop the plain ACE when CI|IO requested")
	}
	if !aceMatchesRemoval(inherit[0], match, true, true, ci|io) {
		t.Error("flag-specific removal should drop the CI|IO ACE")
	}
}

func TestIsDomainObject(t *testing.T) {
	if !isDomainObject([]string{"top", "domain", "domainDNS"}) {
		t.Error("domainDNS object should be recognised as the domain head")
	}
	if !isDomainObject([]string{"DOMAINDNS"}) { // case-insensitive
		t.Error("objectClass match should be case-insensitive")
	}
	if isDomainObject([]string{"top", "person", "organizationalPerson", "user", "computer"}) {
		t.Error("a computer object must not be treated as the domain head")
	}
	if isDomainObject(nil) {
		t.Error("empty objectClass must not be treated as the domain head")
	}
}

func TestLdapBinaryFilter(t *testing.T) {
	// S-1-5-18 → 01 01 00 00 00 00 00 05 12 00 00 00
	sidBytes, err := encodeSID("S-1-5-18")
	if err != nil {
		t.Fatal(err)
	}
	got := ldapBinaryFilter(sidBytes)
	want := "\\01\\01\\00\\00\\00\\00\\00\\05\\12\\00\\00\\00"
	if got != want {
		t.Errorf("ldapBinaryFilter = %q, want %q", got, want)
	}
}

func TestDaclValidate(t *testing.T) {
	good := []*daclCmd{
		{action: "read", target: "bob"},
		{action: "add", target: "bob", trustee: "evil", rights: repeatStrFlag{"DCSync"}},
		{action: "remove", target: "bob", trustee: "evil", maskStr: "0x20000"},
		{action: "backup", target: "bob", file: "/tmp/x"},
	}
	for _, c := range good {
		if err := c.validate(); err != nil {
			t.Errorf("validate(%+v) unexpected error: %v", c, err)
		}
	}
	bad := []*daclCmd{
		{action: "read"},                                  // no target
		{action: "add", target: "bob"},                    // no trustee
		{action: "add", target: "bob", trustee: "evil"},   // no rights/mask/guid
		{action: "backup", target: "bob"},                 // no file
		{action: "bogus", target: "bob"},                  // bad action
		{action: "read", target: "bob", aceType: "weird"}, // bad ace-type
	}
	for _, c := range bad {
		if err := c.validate(); err == nil {
			t.Errorf("validate(%+v) expected error, got nil", c)
		}
	}
}
