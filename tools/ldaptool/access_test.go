package main

import (
	"testing"

	"github.com/jfjallid/go-smb/msdtyp"
	ldap "github.com/jfjallid/ldap/v3"
)

// sidOf converts a string SID to the msdtyp.SID value used inside ACEs; it
// fatals on bad input so tests stay terse.
func sidOf(t *testing.T, s string) msdtyp.SID {
	t.Helper()
	sid, err := msdtyp.ConvertStrToSID(s)
	if err != nil {
		t.Fatalf("ConvertStrToSID(%q): %v", s, err)
	}
	return *sid
}

// ace builds a (non-object) allow/deny ACE for a trustee.
func ace(t *testing.T, aceType byte, flags byte, mask uint32, sid string) msdtyp.ACE {
	return msdtyp.ACE{
		Header: msdtyp.ACEHeader{Type: aceType, Flags: flags},
		Mask:   mask,
		Sid:    sidOf(t, sid),
	}
}

// objACE builds an object ACE carrying an ObjectType GUID.
func objACE(t *testing.T, aceType byte, mask uint32, guid, sid string) msdtyp.ACE {
	g, err := msdtyp.GuidFromString(guid)
	if err != nil {
		t.Fatalf("GuidFromString(%q): %v", guid, err)
	}
	return msdtyp.ACE{
		Header:      msdtyp.ACEHeader{Type: aceType},
		Mask:        mask,
		Sid:         sidOf(t, sid),
		ObjectFlags: msdtyp.AceObjectTypePresent,
		ObjectType:  g,
	}
}

func sdWith(owner string, aces ...msdtyp.ACE) *msdtyp.SecurityDescriptor {
	sd := &msdtyp.SecurityDescriptor{Dacl: &msdtyp.PACL{ACLS: aces}}
	if owner != "" {
		o, _ := msdtyp.ConvertStrToSID(owner)
		sd.OwnerSid = o
	}
	return sd
}

func tokenOf(sids ...string) map[string]bool {
	m := map[string]bool{}
	for _, s := range sids {
		m[s] = true
	}
	return m
}

const (
	tUser  = "S-1-5-21-1-2-3-1101"
	tGroup = "S-1-5-21-1-2-3-1102"
	tOther = "S-1-5-21-1-2-3-9999"
)

func TestAccessCheck(t *testing.T) {
	cases := []struct {
		name  string
		sd    *msdtyp.SecurityDescriptor
		token map[string]bool
		bit   uint32
		guid  string
		want  accessStatus
	}{
		{
			name:  "direct allow",
			sd:    sdWith("", ace(t, msdtyp.AccessAllowedAceType, 0, rightWriteProp, tUser)),
			token: tokenOf(tUser),
			bit:   rightWriteProp,
			want:  statusAllow,
		},
		{
			name:  "allow via group membership",
			sd:    sdWith("", ace(t, msdtyp.AccessAllowedAceType, 0, rightWriteProp, tGroup)),
			token: tokenOf(tUser, tGroup),
			bit:   rightWriteProp,
			want:  statusAllow,
		},
		{
			name:  "sid not in token",
			sd:    sdWith("", ace(t, msdtyp.AccessAllowedAceType, 0, rightWriteProp, tOther)),
			token: tokenOf(tUser),
			bit:   rightWriteProp,
			want:  statusNotGranted,
		},
		{
			name: "deny precedes allow (canonical)",
			sd: sdWith("",
				ace(t, msdtyp.AccessDeniedAceType, 0, rightWriteProp, tUser),
				ace(t, msdtyp.AccessAllowedAceType, 0, rightWriteProp, tUser),
			),
			token: tokenOf(tUser),
			bit:   rightWriteProp,
			want:  statusDeny,
		},
		{
			name:  "inherit-only ACE ignored",
			sd:    sdWith("", ace(t, msdtyp.AccessAllowedAceType, msdtyp.InheritOnlyAce, rightWriteProp, tUser)),
			token: tokenOf(tUser),
			bit:   rightWriteProp,
			want:  statusNotGranted,
		},
		{
			name:  "object ACE scoped to its GUID",
			sd:    sdWith("", objACE(t, msdtyp.AccessAllowedObjectAceType, rightControl, guidGetChanges, tUser)),
			token: tokenOf(tUser),
			bit:   rightControl,
			guid:  guidGetChanges,
			want:  statusAllow,
		},
		{
			name:  "object ACE does not grant a different GUID",
			sd:    sdWith("", objACE(t, msdtyp.AccessAllowedObjectAceType, rightControl, guidGetChanges, tUser)),
			token: tokenOf(tUser),
			bit:   rightControl,
			guid:  guidGetChangesAll,
			want:  statusNotGranted,
		},
		{
			name:  "generic ControlAccess (no ObjectType) covers any ext right",
			sd:    sdWith("", ace(t, msdtyp.AccessAllowedAceType, 0, rightControl, tUser)),
			token: tokenOf(tUser),
			bit:   rightControl,
			guid:  guidGetChangesAll,
			want:  statusAllow,
		},
		{
			name:  "GenericAll expands to write property",
			sd:    sdWith("", ace(t, msdtyp.AccessAllowedAceType, 0, rightGenericAll, tUser)),
			token: tokenOf(tUser),
			bit:   rightWriteProp,
			want:  statusAllow,
		},
		{
			name:  "GenericAll expands to WriteDacl",
			sd:    sdWith("", ace(t, msdtyp.AccessAllowedAceType, 0, rightGenericAll, tUser)),
			token: tokenOf(tUser),
			bit:   rightWriteDacl,
			want:  statusAllow,
		},
		{
			name:  "owner implicit WriteDacl",
			sd:    sdWith(tUser),
			token: tokenOf(tUser),
			bit:   rightWriteDacl,
			want:  statusAllow,
		},
		{
			name: "OWNER_RIGHTS suppresses owner implicit",
			sd: func() *msdtyp.SecurityDescriptor {
				sd := sdWith(tUser, ace(t, msdtyp.AccessAllowedAceType, 0, rightReadProp, sidOwnerRights))
				return sd
			}(),
			token: tokenOf(tUser),
			bit:   rightWriteDacl,
			want:  statusNotGranted,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ac := newAccessChecker(tc.sd, tc.token)
			got, _ := ac.check(tc.bit, tc.guid)
			if got != tc.want {
				t.Fatalf("check(0x%x, %q) = %v, want %v", tc.bit, tc.guid, got, tc.want)
			}
		})
	}
}

func TestDCSyncCapable(t *testing.T) {
	sd := sdWith("",
		objACE(t, msdtyp.AccessAllowedObjectAceType, rightControl, guidGetChanges, tUser),
		objACE(t, msdtyp.AccessAllowedObjectAceType, rightControl, guidGetChangesAll, tUser),
	)
	if !dcsyncCapable(newAccessChecker(sd, tokenOf(tUser))) {
		t.Fatal("expected DCSync-capable with both replication rights")
	}

	// Only one of the two replication rights → not capable.
	sd1 := sdWith("", objACE(t, msdtyp.AccessAllowedObjectAceType, rightControl, guidGetChanges, tUser))
	if dcsyncCapable(newAccessChecker(sd1, tokenOf(tUser))) {
		t.Fatal("one replication right should not be DCSync-capable")
	}
}

func TestEvaluateMultiPart(t *testing.T) {
	// DCSync preset has two parts; both must be allowed.
	sdBoth := sdWith("",
		objACE(t, msdtyp.AccessAllowedObjectAceType, rightControl, guidGetChanges, tUser),
		objACE(t, msdtyp.AccessAllowedObjectAceType, rightControl, guidGetChangesAll, tUser),
	)
	rc := rightCheck{label: "dcsync", parts: []queryPart{
		{bit: rightControl, guid: guidGetChanges},
		{bit: rightControl, guid: guidGetChangesAll},
	}}
	if st, _ := newAccessChecker(sdBoth, tokenOf(tUser)).evaluate(rc); st != statusAllow {
		t.Fatalf("both parts allowed → want Allow, got %v", st)
	}

	sdOne := sdWith("", objACE(t, msdtyp.AccessAllowedObjectAceType, rightControl, guidGetChanges, tUser))
	if st, _ := newAccessChecker(sdOne, tokenOf(tUser)).evaluate(rc); st != statusNotGranted {
		t.Fatalf("one part missing → want NotGranted, got %v", st)
	}
}

func TestParseRightTokenOffline(t *testing.T) {
	t.Run("preset dcsync → two parts", func(t *testing.T) {
		rcs, err := parseRightToken(nil, "dcsync")
		if err != nil {
			t.Fatal(err)
		}
		if len(rcs) != 1 || len(rcs[0].parts) != 2 {
			t.Fatalf("got %d checks / parts %v", len(rcs), rcs)
		}
	})
	t.Run("mask-bit name", func(t *testing.T) {
		rcs, err := parseRightToken(nil, "WriteDacl")
		if err != nil {
			t.Fatal(err)
		}
		if len(rcs) != 1 || rcs[0].parts[0].bit != rightWriteDacl || rcs[0].parts[0].guid != "" {
			t.Fatalf("unexpected: %+v", rcs)
		}
	})
	t.Run("raw guid → ext right", func(t *testing.T) {
		rcs, err := parseRightToken(nil, guidResetPassword)
		if err != nil {
			t.Fatal(err)
		}
		if len(rcs) != 1 || rcs[0].parts[0].bit != rightControl || rcs[0].parts[0].guid != guidResetPassword {
			t.Fatalf("unexpected: %+v", rcs)
		}
	})
	t.Run("write:<guid> → property write", func(t *testing.T) {
		rcs, err := parseRightToken(nil, "write:"+guidMember)
		if err != nil {
			t.Fatal(err)
		}
		if len(rcs) != 1 || rcs[0].parts[0].bit != rightWriteProp || rcs[0].parts[0].guid != guidMember {
			t.Fatalf("unexpected: %+v", rcs)
		}
	})
}

func TestGUIDResolverOffline(t *testing.T) {
	// With no connection, the resolver still serves the static table and
	// degrades gracefully on a miss (no panic, label falls back to the GUID).
	r := newGUIDResolver(nil, true)
	if got := r.name(guidGetChanges); got != "DS-Replication-Get-Changes" {
		t.Errorf("name(GetChanges) = %q, want static table hit", got)
	}
	const unknown = "deadbeef-0000-0000-0000-000000000000"
	if got := r.name(unknown); got != "" {
		t.Errorf("name(unknown, no conn) = %q, want empty", got)
	}
	if got := r.label(unknown); got != unknown {
		t.Errorf("label(unknown) = %q, want the bare GUID", got)
	}
}

func TestSchemaAndRightLabels(t *testing.T) {
	attr := ldap.NewEntry("CN=Display-Name", map[string][]string{
		"lDAPDisplayName": {"displayName"},
		"objectClass":     {"top", "attributeSchema"},
	})
	if got := labelSchemaObject(attr); got != "displayName (attribute)" {
		t.Errorf("labelSchemaObject(attribute) = %q", got)
	}
	cls := ldap.NewEntry("CN=Computer", map[string][]string{
		"lDAPDisplayName": {"computer"},
		"objectClass":     {"top", "classSchema"},
	})
	if got := labelSchemaObject(cls); got != "computer (class)" {
		t.Errorf("labelSchemaObject(class) = %q", got)
	}
	right := ldap.NewEntry("CN=DS-Replication-Get-Changes", map[string][]string{
		"cn":          {"DS-Replication-Get-Changes"},
		"displayName": {"Replicating Directory Changes"},
	})
	if got := labelControlAccessRight(right); got != "DS-Replication-Get-Changes" {
		t.Errorf("labelControlAccessRight = %q, want cn", got)
	}
}

func TestLooksLikeGUID(t *testing.T) {
	if !looksLikeGUID(guidResetPassword) {
		t.Fatal("valid GUID rejected")
	}
	if looksLikeGUID("servicePrincipalName") {
		t.Fatal("attribute name accepted as GUID")
	}
	if looksLikeGUID("not-a-guid") {
		t.Fatal("short string accepted as GUID")
	}
}
