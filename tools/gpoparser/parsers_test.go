package main

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

// utf16le encodes s as UTF-16LE bytes with a leading BOM, matching how Windows
// writes GptTmpl.inf / scripts.ini.
func utf16le(s string) []byte {
	out := []byte{0xFF, 0xFE}
	for _, u := range utf16.Encode([]rune(s)) {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

func TestParseGptTmpl(t *testing.T) {
	content := "[Unicode]\r\nUnicode=yes\r\n" +
		"[Privilege Rights]\r\n" +
		"SeDebugPrivilege = *S-1-5-32-544,*S-1-5-21-1-2-3-1105\r\n" +
		"SeRemoteInteractiveLogonRight = *S-1-5-32-555\r\n" +
		"[Group Membership]\r\n" +
		"*S-1-5-32-544__Members = *S-1-5-21-1-2-3-1106,CORP\\admins\r\n" +
		"[Registry Values]\r\n" +
		"MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LimitBlankPasswordUse=4,1\r\n" +
		"[System Access]\r\n" +
		"MinimumPasswordAge = 1\r\n"

	var cs ConfigSettings
	parseGptTmpl(utf16le(content), &cs)

	if len(cs.Privileges) != 2 {
		t.Fatalf("expected 2 privileges, got %d", len(cs.Privileges))
	}
	seDebug := cs.Privileges[0]
	if seDebug.Privilege != "SeDebugPrivilege" || !seDebug.Dangerous {
		t.Errorf("SeDebugPrivilege not flagged dangerous: %+v", seDebug)
	}
	if len(seDebug.Members) != 2 || seDebug.Members[0].SID != "S-1-5-32-544" {
		t.Errorf("unexpected SeDebug members: %+v", seDebug.Members)
	}
	if seDebug.Members[0].Name != "BUILTIN\\Administrators" {
		t.Errorf("well-known name not resolved: %+v", seDebug.Members[0])
	}

	if len(cs.GroupMemberships) != 1 {
		t.Fatalf("expected 1 group membership, got %d", len(cs.GroupMemberships))
	}
	gm := cs.GroupMemberships[0]
	if gm.Group.SID != "S-1-5-32-544" || len(gm.Members) != 2 {
		t.Errorf("unexpected group membership: %+v", gm)
	}
	if gm.Members[1].Name != "CORP\\admins" {
		t.Errorf("expected name member, got %+v", gm.Members[1])
	}

	if len(cs.RegistryValues) != 1 || cs.RegistryValues[0].Type != "REG_DWORD" || cs.RegistryValues[0].Value != "1" {
		t.Errorf("unexpected registry values: %+v", cs.RegistryValues)
	}
	if len(cs.SystemAccess) != 1 || cs.SystemAccess[0].Key != "MinimumPasswordAge" {
		t.Errorf("unexpected system access: %+v", cs.SystemAccess)
	}
}

func TestParseGPPGroups(t *testing.T) {
	xml := `<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{1}">
  <Group name="Administrators (built-in)" clsid="{2}">
    <Properties action="U" groupSid="S-1-5-32-544" groupName="Administrators (built-in)">
      <Members>
        <Member name="CORP\evil" action="ADD" sid="S-1-5-21-1-2-3-1107"/>
        <Member name="CORP\gone" action="REMOVE" sid="S-1-5-21-1-2-3-1108"/>
      </Members>
    </Properties>
  </Group>
</Groups>`
	var cs ConfigSettings
	parseGPPGroups([]byte(xml), &cs)
	if len(cs.GroupMemberships) != 1 {
		t.Fatalf("expected 1 membership, got %d", len(cs.GroupMemberships))
	}
	gm := cs.GroupMemberships[0]
	if gm.Group.SID != "S-1-5-32-544" || gm.Group.Name != "Administrators" {
		t.Errorf("group not parsed/cleaned: %+v", gm.Group)
	}
	if gm.Action != "Update" {
		t.Errorf("action not expanded: %q", gm.Action)
	}
	if len(gm.Members) != 1 || gm.Members[0].SID != "S-1-5-21-1-2-3-1107" {
		t.Errorf("expected only the ADD member, got %+v", gm.Members)
	}
}

func TestParseGPPRegistryAndTasks(t *testing.T) {
	reg := `<RegistrySettings clsid="{1}">
  <Collection name="c">
    <Registry clsid="{2}"><Properties action="U" hive="HKEY_LOCAL_MACHINE" key="Software\Foo" name="Bar" type="REG_SZ" value="baz"/></Registry>
  </Collection>
</RegistrySettings>`
	var cs ConfigSettings
	parseGPPRegistry([]byte(reg), &cs)
	if len(cs.RegistryValues) != 1 || cs.RegistryValues[0].Name != "Bar" || cs.RegistryValues[0].Action != "Update" {
		t.Fatalf("registry (with Collection) not parsed: %+v", cs.RegistryValues)
	}

	tasks := `<ScheduledTasks clsid="{1}">
  <ImmediateTaskV2 name="t1"><Properties action="C" name="t1"><Task><Principals><Principal><UserId>NT AUTHORITY\System</UserId></Principal></Principals><Actions><Exec><Command>cmd.exe</Command><Arguments>/c whoami</Arguments></Exec></Actions></Task></Properties></ImmediateTaskV2>
</ScheduledTasks>`
	cs = ConfigSettings{}
	parseGPPTasks([]byte(tasks), &cs)
	if len(cs.ScheduledTasks) != 1 {
		t.Fatalf("expected 1 task, got %d", len(cs.ScheduledTasks))
	}
	tk := cs.ScheduledTasks[0]
	if tk.Command != "cmd.exe" || tk.Arguments != "/c whoami" || tk.RunAs != "NT AUTHORITY\\System" {
		t.Errorf("task v2 not parsed: %+v", tk)
	}
}

func TestParseRegistryPol(t *testing.T) {
	// Build [Software\Policies\Test;Flag;REG_DWORD;4;1]
	var body []byte
	enc16 := func(s string) []byte {
		var b []byte
		for _, u := range utf16.Encode([]rune(s)) {
			b = append(b, byte(u), byte(u>>8))
		}
		b = append(b, 0x00, 0x00) // null terminator
		return b
	}
	delim := func(ch rune) []byte { return []byte{byte(ch), 0x00} }

	body = append(body, delim('[')...)
	body = append(body, enc16(`Software\Policies\Test`)...)
	body = append(body, delim(';')...)
	body = append(body, enc16("Flag")...)
	body = append(body, delim(';')...)
	typ := make([]byte, 4)
	binary.LittleEndian.PutUint32(typ, regDWORD)
	body = append(body, typ...)
	body = append(body, delim(';')...)
	sz := make([]byte, 4)
	binary.LittleEndian.PutUint32(sz, 4)
	body = append(body, sz...)
	body = append(body, delim(';')...)
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, 1)
	body = append(body, data...)
	body = append(body, delim(']')...)

	pol := append([]byte("PReg"), 0x01, 0x00, 0x00, 0x00)
	pol = append(pol, body...)

	var cs ConfigSettings
	parseRegistryPol(pol, "HKLM", &cs)
	if len(cs.RegistryValues) != 1 {
		t.Fatalf("expected 1 registry value, got %d", len(cs.RegistryValues))
	}
	r := cs.RegistryValues[0]
	if r.Key != `Software\Policies\Test` || r.Name != "Flag" || r.Type != "REG_DWORD" || r.Value != "1" || r.Hive != "HKLM" {
		t.Errorf("registry.pol parsed incorrectly: %+v", r)
	}
}

func TestParseScripts(t *testing.T) {
	content := "[Startup]\r\n0CmdLine=evil.bat\r\n0Parameters=-x\r\n1CmdLine=second.exe\r\n"
	var cs ConfigSettings
	parseScripts(utf16le(content), false, &cs)
	if len(cs.Scripts) != 2 {
		t.Fatalf("expected 2 scripts, got %d", len(cs.Scripts))
	}
	if cs.Scripts[0].Type != "Startup" || cs.Scripts[0].CmdLine != "evil.bat" || cs.Scripts[0].Parameters != "-x" {
		t.Errorf("script 0 wrong: %+v", cs.Scripts[0])
	}
	if cs.Scripts[1].Order != 1 || cs.Scripts[1].CmdLine != "second.exe" {
		t.Errorf("script 1 wrong: %+v", cs.Scripts[1])
	}
}

func TestParseGPLink(t *testing.T) {
	raw := `[LDAP://cn={31B2F340-016D-11D2-945F-00C04FB984F9},cn=policies,cn=system,DC=corp,DC=local;0]` +
		`[LDAP://cn={AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE},cn=policies,cn=system,DC=corp,DC=local;2]` +
		`[LDAP://cn={11111111-2222-3333-4444-555555555555},cn=policies,cn=system,DC=corp,DC=local;1]`
	links := parseGPLink(raw)
	if len(links) != 3 {
		t.Fatalf("expected 3 links, got %d", len(links))
	}
	if links[0].GUID != "{31B2F340-016D-11D2-945F-00C04FB984F9}" || links[0].Enforced || links[0].Disabled {
		t.Errorf("link0 wrong: %+v", links[0])
	}
	if !links[1].Enforced {
		t.Errorf("link1 should be enforced: %+v", links[1])
	}
	if !links[2].Disabled {
		t.Errorf("link2 should be disabled: %+v", links[2])
	}
}

func TestEffectiveGPOInheritance(t *testing.T) {
	domain := &OU{DN: "DC=corp,DC=local", Kind: "domain", Links: []GPLink{
		{GUID: "{DOMAIN-GPO}"},
		{GUID: "{ENFORCED-GPO}", Enforced: true},
	}}
	parent := &OU{DN: "OU=Corp,DC=corp,DC=local", Kind: "ou", Links: []GPLink{{GUID: "{PARENT-GPO}"}}}
	blocked := &OU{DN: "OU=Secure,OU=Corp,DC=corp,DC=local", Kind: "ou", BlockInheritance: true,
		Links: []GPLink{{GUID: "{LOCAL-GPO}"}}}

	got := effectiveGPOGUIDs([]*OU{domain, parent, blocked})
	// Block-inheritance drops DOMAIN-GPO and PARENT-GPO, keeps LOCAL-GPO and the
	// enforced DOMAIN ENFORCED-GPO.
	want := map[string]bool{"{LOCAL-GPO}": true, "{ENFORCED-GPO}": true}
	if len(got) != 2 {
		t.Fatalf("expected 2 effective GPOs, got %v", got)
	}
	for _, g := range got {
		if !want[normalizeGUID(g)] && !want[g] {
			t.Errorf("unexpected GPO in effective set: %s (full=%v)", g, got)
		}
	}
}

func TestParentDN(t *testing.T) {
	cases := map[string]string{
		"CN=PC01,OU=Workstations,DC=corp,DC=local": "OU=Workstations,DC=corp,DC=local",
		"DC=corp,DC=local":                         "DC=local",
		"DC=local":                                 "",
	}
	for in, want := range cases {
		if got := parentDN(in); got != want {
			t.Errorf("parentDN(%q)=%q want %q", in, got, want)
		}
	}
}
