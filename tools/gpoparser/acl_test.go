package main

import (
	"testing"

	"github.com/jfjallid/go-smb/msdtyp"
)

func mustSID(t *testing.T, s string) msdtyp.SID {
	t.Helper()
	sid, err := msdtyp.ConvertStrToSID(s)
	if err != nil {
		t.Fatalf("ConvertStrToSID(%q): %v", s, err)
	}
	return *sid
}

func ace(t *testing.T, aceType byte, mask uint32, sid string) msdtyp.ACE {
	return msdtyp.ACE{
		Header: msdtyp.ACEHeader{Type: aceType},
		Mask:   mask,
		Sid:    mustSID(t, sid),
	}
}

func TestFileWriteRights(t *testing.T) {
	// FILE_WRITE_DATA (0x2) — the bit the old QueryInfoSecurity friendly-name
	// path dropped. Must now be recognised.
	if r := fileWriteRights(fileWriteData); len(r) != 1 || r[0] != "WriteData" {
		t.Errorf("FILE_WRITE_DATA not detected: %+v", r)
	}
	if r := fileWriteRights(fileAppendData); len(r) != 1 || r[0] != "AppendData" {
		t.Errorf("FILE_APPEND_DATA not detected: %+v", r)
	}
	// Read-only (READ_CONTROL|SYNCHRONIZE) yields nothing.
	if r := fileWriteRights(0x00020000 | 0x00100000); len(r) != 0 {
		t.Errorf("read-only mask should yield no write rights: %+v", r)
	}
}

func TestSDWritableGrantToEffectiveSID(t *testing.T) {
	a := &aclChecker{effective: map[string]bool{"S-1-5-21-1-2-3-1107": true}}
	sd := &msdtyp.SecurityDescriptor{
		OwnerSid: ptrSID(t, "S-1-5-32-544"), // owner is admins, not us
		Dacl: &msdtyp.PACL{ACLS: []msdtyp.ACE{
			ace(t, msdtyp.AccessAllowedAceType, fileWriteData, "S-1-5-21-1-2-3-1107"),
		}},
	}
	wa := a.sdWritable(sd, surfaceSysvol, `\\dc\sysvol\x`, true, false, fileWriteRights)
	if wa == nil || wa.Trustee.SID != "S-1-5-21-1-2-3-1107" {
		t.Fatalf("expected writable by effective SID, got %+v", wa)
	}
}

func TestSDWritableDenySuppressesGrant(t *testing.T) {
	me := "S-1-5-21-1-2-3-1107"
	a := &aclChecker{effective: map[string]bool{me: true}}
	sd := &msdtyp.SecurityDescriptor{
		Dacl: &msdtyp.PACL{ACLS: []msdtyp.ACE{
			ace(t, msdtyp.AccessDeniedAceType, fileWriteData, me), // deny wins
			ace(t, msdtyp.AccessAllowedAceType, fileWriteData, me),
		}},
	}
	if wa := a.sdWritable(sd, surfaceSysvol, "p", true, false, fileWriteRights); wa != nil {
		t.Fatalf("deny ACE should suppress the grant, got %+v", wa)
	}
}

func TestSDWritableLowPrivOptIn(t *testing.T) {
	// BUILTIN\Users (S-1-5-32-545) is not in the effective set but is low-priv.
	a := &aclChecker{effective: map[string]bool{}}
	sd := &msdtyp.SecurityDescriptor{
		Dacl: &msdtyp.PACL{ACLS: []msdtyp.ACE{
			ace(t, msdtyp.AccessAllowedAceType, fileGenericWrite, "S-1-5-32-545"),
		}},
	}
	if wa := a.sdWritable(sd, surfaceSysvol, "p", true, false, fileWriteRights); wa != nil {
		t.Errorf("low-priv grant must not match when includeLowPriv=false: %+v", wa)
	}
	wa := a.sdWritable(sd, surfaceSysvol, "p", true, true, fileWriteRights)
	if wa == nil || wa.Trustee.SID != "S-1-5-32-545" {
		t.Fatalf("expected low-priv match when includeLowPriv=true, got %+v", wa)
	}
}

func TestSDWritableOwner(t *testing.T) {
	me := "S-1-5-21-1-2-3-1107"
	a := &aclChecker{effective: map[string]bool{me: true}}
	sd := &msdtyp.SecurityDescriptor{OwnerSid: ptrSID(t, me)}
	wa := a.sdWritable(sd, surfaceGPOObject, "dn", true, false, adWriteRights)
	if wa == nil || len(wa.Rights) != 1 || wa.Rights[0] != "Owner" {
		t.Fatalf("owner should be writable, got %+v", wa)
	}
}

func TestParentPath(t *testing.T) {
	cases := []struct {
		in       string
		want     string
		wantMore bool
	}{
		{`Policies\{GUID}\Machine\file.ini`, `Policies\{GUID}\Machine`, true},
		{`top`, "", true},
		{"", "", false},
	}
	for _, c := range cases {
		got, more := parentPath(c.in)
		if got != c.want || more != c.wantMore {
			t.Errorf("parentPath(%q)=(%q,%v) want (%q,%v)", c.in, got, more, c.want, c.wantMore)
		}
	}
}

func TestReferencedPaths(t *testing.T) {
	cs := &ConfigSettings{
		Scripts:          []ScriptEntry{{Type: "Startup", CmdLine: `\\dc\netlogon\s.bat`}},
		ScheduledTasks:   []ScheduledTask{{Name: "t", Command: "cmd.exe"}},
		SoftwareInstalls: []SoftwareInstall{{Name: "7z", Path: `\\fs\sw\7z.msi`}},
		Files:            []FileDeploy{{FromPath: `\\fs\f\a.exe`}},
		Shortcuts:        []Shortcut{{Name: "lnk", TargetPath: `\\fs\t\a.exe`}},
	}
	refs := referencedPaths(cs)
	if len(refs) != 5 {
		t.Fatalf("expected 5 referenced paths, got %d: %+v", len(refs), refs)
	}
}

func ptrSID(t *testing.T, s string) *msdtyp.SID {
	t.Helper()
	sid := mustSID(t, s)
	return &sid
}
