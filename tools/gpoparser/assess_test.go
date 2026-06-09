package main

import "testing"

// findFinding returns the first finding with the given category, or nil.
func findFinding(fs []Finding, category string) *Finding {
	for i := range fs {
		if fs[i].Category == category {
			return &fs[i]
		}
	}
	return nil
}

func hasSeverity(fs []Finding, category string, sev Severity) bool {
	for _, f := range fs {
		if f.Category == category && f.Severity == sev {
			return true
		}
	}
	return false
}

func TestAssessUserRights(t *testing.T) {
	// SeDebug to a custom group => High; SeImpersonate to Authenticated Users
	// => Critical; SeBackup to Local System only => no finding (expected holder).
	cs := ConfigSettings{Privileges: []PrivilegeRight{
		{Privilege: "SeDebugPrivilege", Dangerous: true, Members: []Principal{{SID: "S-1-5-21-1-2-3-1106", Name: "CORP\\helpdesk"}}},
		{Privilege: "SeImpersonatePrivilege", Dangerous: true, Members: []Principal{{SID: "S-1-5-11", Name: "Authenticated Users"}}},
		{Privilege: "SeBackupPrivilege", Dangerous: true, Members: []Principal{{SID: "S-1-5-18", Name: "Local System"}}},
	}}
	got := analyseUserRights(nil, "Computer", &cs, nil)
	if len(got) != 2 {
		t.Fatalf("expected 2 user-rights findings, got %d: %+v", len(got), got)
	}
	if !hasSeverity(got, "user-rights", SevHigh) {
		t.Errorf("expected a High finding for SeDebug to a custom group: %+v", got)
	}
	if !hasSeverity(got, "user-rights", SevCritical) {
		t.Errorf("expected a Critical finding for SeImpersonate to Authenticated Users: %+v", got)
	}
}

func TestAssessImpersonateServiceAccountSuppressed(t *testing.T) {
	// SeImpersonate to the built-in service accounts is default config.
	cs := ConfigSettings{Privileges: []PrivilegeRight{
		{Privilege: "SeImpersonatePrivilege", Dangerous: true, Members: []Principal{
			{SID: "S-1-5-19"}, {SID: "S-1-5-20"},
		}},
	}}
	if got := analyseUserRights(nil, "Computer", &cs, nil); len(got) != 0 {
		t.Errorf("expected no finding for service-account impersonation, got %+v", got)
	}
}

func TestAssessRestrictedGroups(t *testing.T) {
	// Domain Users (513) added to BUILTIN\Administrators (544) => High.
	cs := ConfigSettings{GroupMemberships: []GroupMembership{
		{Group: Principal{SID: "S-1-5-32-544", Name: "BUILTIN\\Administrators"},
			Members: []Principal{{SID: "S-1-5-21-1-2-3-513", Name: "Domain Users"}}},
	}}
	got := analyseRestrictedGroups(nil, "Computer", &cs, nil)
	if !hasSeverity(got, "restricted-groups", SevHigh) {
		t.Fatalf("expected High restricted-groups finding, got %+v", got)
	}
}

func TestAssessRestrictedGroupsMemberOf(t *testing.T) {
	// A low-priv group made a member of a privileged group via __Memberof.
	cs := ConfigSettings{GroupMemberships: []GroupMembership{
		{Group: Principal{SID: "S-1-5-21-1-2-3-513", Name: "Domain Users"},
			MemberOf: []Principal{{SID: "S-1-5-32-544", Name: "BUILTIN\\Administrators"}}},
	}}
	got := analyseRestrictedGroups(nil, "Computer", &cs, nil)
	if !hasSeverity(got, "restricted-groups", SevHigh) {
		t.Fatalf("expected High finding for low-priv group joining admins, got %+v", got)
	}
}

func TestAssessRegistryAlwaysInstallElevated(t *testing.T) {
	cs := ConfigSettings{RegistryValues: []RegistrySetting{
		{Source: "registry.pol", Hive: "HKLM", Key: `Software\Policies\Microsoft\Windows\Installer`, Name: "AlwaysInstallElevated", Type: "REG_DWORD", Value: "1"},
	}}
	got := analyseRegistryPolicy(nil, "Computer", &cs, nil)
	f := findFinding(got, "registry-policy")
	if f == nil || f.Severity != SevCritical {
		t.Fatalf("expected Critical AlwaysInstallElevated finding, got %+v", got)
	}
}

func TestAssessRegistryGptTmplEmbeddedName(t *testing.T) {
	// GptTmpl stores the value name as the final key segment with no Name field.
	cs := ConfigSettings{RegistryValues: []RegistrySetting{
		{Source: "gpttmpl", Key: `MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel`, Type: "REG_DWORD", Value: "1"},
	}}
	got := analyseRegistryPolicy(nil, "Computer", &cs, nil)
	if !hasSeverity(got, "registry-policy", SevHigh) {
		t.Fatalf("expected High LmCompatibilityLevel finding, got %+v", got)
	}
}

func TestAssessRegistryAutologonPassword(t *testing.T) {
	cs := ConfigSettings{RegistryValues: []RegistrySetting{
		{Source: "gpp", Hive: "HKLM", Key: `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`, Name: "DefaultPassword", Type: "REG_SZ", Value: "Summer2026!"},
	}}
	got := analyseRegistryPolicy(nil, "Computer", &cs, nil)
	if !hasSeverity(got, "registry-policy", SevCritical) {
		t.Fatalf("expected Critical autologon-password finding, got %+v", got)
	}
}

func TestAssessSystemAccess(t *testing.T) {
	cs := ConfigSettings{SystemAccess: []KeyValue{
		{Key: "ClearTextPassword", Value: "1"},
		{Key: "MinimumPasswordLength", Value: "6"},
		{Key: "MinimumPasswordAge", Value: "1"}, // benign, no finding
	}}
	got := analyseSystemAccess(nil, "Computer", &cs, nil)
	if !hasSeverity(got, "system-access", SevLow) {
		t.Errorf("expected Low ClearTextPassword finding: %+v", got)
	}
	if !hasSeverity(got, "system-access", SevInfo) {
		t.Errorf("expected Info weak-password-length finding: %+v", got)
	}
	if len(got) != 2 {
		t.Errorf("expected exactly 2 findings (benign key ignored), got %d: %+v", len(got), got)
	}
}

func TestAssessExecPath(t *testing.T) {
	cs := ConfigSettings{
		Scripts:        []ScriptEntry{{Type: "Startup", CmdLine: `\\corp.local\netlogon\setup.bat`}},
		ScheduledTasks: []ScheduledTask{{Name: "t", Command: "powershell.exe", Arguments: "-User admin -Password Hunter2"}},
	}
	got := analyseExecPath(nil, "Computer", &cs, nil)
	if !hasSeverity(got, "exec-path", SevInfo) {
		t.Errorf("expected Info UNC-script finding: %+v", got)
	}
	if !hasSeverity(got, "exec-path", SevLow) {
		t.Errorf("expected Low credential-in-args finding: %+v", got)
	}
}

func TestRunAssessmentSortAndBlastRadius(t *testing.T) {
	g := &GPO{
		GUID: "{G1}", Name: "Test GPO",
		AffectedComputers: []string{"CN=PC01,DC=corp,DC=local", "CN=PC02,DC=corp,DC=local"},
		Computer: ConfigSettings{
			SystemAccess: []KeyValue{{Key: "ClearTextPassword", Value: "1"}}, // Low
			RegistryValues: []RegistrySetting{
				{Source: "registry.pol", Hive: "HKLM", Key: `Software\Policies\Microsoft\Windows\Installer`, Name: "AlwaysInstallElevated", Value: "1"}, // Critical
			},
		},
	}
	got := runAssessment([]*GPO{g}, &assessCtx{}, SevLow)
	if len(got) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(got), got)
	}
	if got[0].Severity != SevCritical {
		t.Errorf("expected most-severe finding first, got %s", got[0].Severity)
	}
	if len(got[0].AffectedComputers) != 2 || got[0].GPOName != "Test GPO" || got[0].Scope != "Computer" {
		t.Errorf("driver did not attach GPO identity/blast radius: %+v", got[0])
	}
}

func TestRunAssessmentMinSeverityFilter(t *testing.T) {
	g := &GPO{GUID: "{G1}", Name: "G", Computer: ConfigSettings{
		SystemAccess: []KeyValue{{Key: "PasswordComplexity", Value: "0"}}, // Info
	}}
	if got := runAssessment([]*GPO{g}, &assessCtx{}, SevLow); len(got) != 0 {
		t.Errorf("Info finding should be filtered out at min=Low, got %+v", got)
	}
	if got := runAssessment([]*GPO{g}, &assessCtx{}, SevInfo); len(got) != 1 {
		t.Errorf("Info finding should appear at min=Info, got %+v", got)
	}
}
