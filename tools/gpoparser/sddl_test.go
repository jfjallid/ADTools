package main

import "testing"

func TestParseSDDLACEs(t *testing.T) {
	// Full SD string: owner SY, group SY, DACL with three ACEs. The trailing
	// S: SACL audit ACE must not be mistaken for an allow ACE.
	sddl := "O:SYG:SYD:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWP;;;AU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
	aces := parseSDDLACEs(sddl)
	if len(aces) != 4 {
		t.Fatalf("expected 4 ACEs parsed, got %d: %+v", len(aces), aces)
	}
	if aces[0].Trustee != "SY" || aces[1].Trustee != "BA" || aces[2].Trustee != "AU" {
		t.Errorf("unexpected trustees: %+v", aces)
	}
	// AU ace has RP/WP (start/stop) but none of the dangerous tokens.
	if len(dangerousServiceRights(aces[2].Rights)) != 0 {
		t.Errorf("AU start/stop should not be dangerous: %+v", aces[2].Rights)
	}
	// BA ace has WD/WO but BA is administrators (privileged trustee).
	if !isPrivilegedServiceTrustee(aces[1].Trustee, sddlTrusteeSID(aces[1].Trustee)) {
		t.Errorf("BA should be a privileged trustee")
	}
}

func TestSplitRightsTokensHexMask(t *testing.T) {
	// 0x10000000 = GENERIC_ALL.
	if got := splitRightsTokens("0x10000000"); len(got) != 1 || got[0] != "GA" {
		t.Errorf("hex mask not expanded: %+v", got)
	}
}

func TestAssessServiceSDDLDangerousToLowPriv(t *testing.T) {
	// Authenticated Users (AU) granted SERVICE_CHANGE_CONFIG (DC) + WRITE_DAC (WD).
	cs := ConfigSettings{Services: []ServiceSetting{
		{Source: "gpttmpl", Name: "VulnSvc", SDDL: "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;AU)(A;;CCLCSWLOCRRC;;;IU)"},
	}}
	got := analyseServiceSDDL(nil, "Computer", &cs, nil)
	if !hasSeverity(got, "service-sddl", SevHigh) {
		t.Fatalf("expected High service-sddl finding for AU change-config, got %+v", got)
	}
}

func TestAssessServiceSDDLAdminsIgnored(t *testing.T) {
	// Only administrators / SYSTEM hold write rights => no finding.
	cs := ConfigSettings{Services: []ServiceSetting{
		{Source: "gpttmpl", Name: "OkSvc", SDDL: "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWRPWP;;;AU)"},
	}}
	if got := analyseServiceSDDL(nil, "Computer", &cs, nil); len(got) != 0 {
		t.Errorf("expected no finding when only admins/SYSTEM have write, got %+v", got)
	}
}

func TestADWriteRights(t *testing.T) {
	if r := adWriteRights(adGenericAll); len(r) != 1 || r[0] != "GenericAll" {
		t.Errorf("GenericAll not detected: %+v", r)
	}
	if r := adWriteRights(adWriteDACL | adWriteOwner); len(r) != 2 {
		t.Errorf("WriteDacl|WriteOwner not detected: %+v", r)
	}
	// READ_CONTROL alone (0x20000) is not a write right.
	if r := adWriteRights(0x00020000); len(r) != 0 {
		t.Errorf("read-only mask should yield no write rights: %+v", r)
	}
	if r := adWriteRights(adWriteProp); len(r) != 1 || r[0] != "WriteProperty" {
		t.Errorf("WriteProperty not detected: %+v", r)
	}
}
