package main

import (
	"strings"
	"testing"
)

func TestParseGPPDrivesAndCPassword(t *testing.T) {
	blob := encryptGPP(t, "DrivePw1")
	xml := `<Drives clsid="{1}"><Drive name="S:" clsid="{2}"><Properties action="U" letter="S" path="\\fs01\share" userName="CORP\svc" cpassword="` + blob + `"/></Drive></Drives>`
	var cs ConfigSettings
	parseGPPDrives([]byte(xml), &cs)
	if len(cs.Drives) != 1 || cs.Drives[0].Path != `\\fs01\share` || cs.Drives[0].CPassword != blob {
		t.Fatalf("drive not parsed: %+v", cs.Drives)
	}
	got := analyseGPPPassword(nil, "User", &cs, nil)
	if !hasSeverity(got, "gpp-cpassword", SevCritical) || !strings.Contains(got[0].Detail, "DrivePw1") {
		t.Fatalf("expected Critical cpassword finding with recovered password: %+v", got)
	}
}

func TestParseGPPDataSources(t *testing.T) {
	xml := `<DataSources clsid="{1}"><DataSource name="db" clsid="{2}"><Properties action="C" dsn="db" driver="SQL Server" username="sa"/></DataSource></DataSources>`
	var cs ConfigSettings
	parseGPPDataSources([]byte(xml), &cs)
	if len(cs.DataSources) != 1 || cs.DataSources[0].UserName != "sa" || cs.DataSources[0].Action != "Create" {
		t.Fatalf("data source not parsed: %+v", cs.DataSources)
	}
}

func TestParseGPPFilesAndShortcutsDeployPaths(t *testing.T) {
	files := `<Files clsid="{1}"><File clsid="{2}"><Properties action="U" fromPath="\\dc01\sysvol\evil.exe" targetPath="C:\tools\app.exe"/></File></Files>`
	var cs ConfigSettings
	parseGPPFiles([]byte(files), &cs)
	if len(cs.Files) != 1 || cs.Files[0].FromPath != `\\dc01\sysvol\evil.exe` {
		t.Fatalf("file copy not parsed: %+v", cs.Files)
	}

	sc := `<Shortcuts clsid="{1}"><Shortcut name="App" clsid="{2}"><Properties action="C" targetPath="\\fs\share\app.exe" arguments="-user admin -password Hunter2" startIn="C:\"/></Shortcut></Shortcuts>`
	parseGPPShortcuts([]byte(sc), &cs)
	if len(cs.Shortcuts) != 1 || cs.Shortcuts[0].TargetPath != `\\fs\share\app.exe` {
		t.Fatalf("shortcut not parsed: %+v", cs.Shortcuts)
	}

	got := analyseDeployPaths(nil, "Computer", &cs, nil)
	if !hasSeverity(got, "gpp-file", SevInfo) {
		t.Errorf("expected Info gpp-file finding: %+v", got)
	}
	if !hasSeverity(got, "gpp-shortcut", SevInfo) {
		t.Errorf("expected Info gpp-shortcut UNC finding: %+v", got)
	}
	if !hasSeverity(got, "gpp-shortcut", SevLow) {
		t.Errorf("expected Low gpp-shortcut credential-arg finding: %+v", got)
	}
}

func TestParseGPPPrintersCPassword(t *testing.T) {
	blob := encryptGPP(t, "PrintPw")
	xml := `<Printers clsid="{1}"><SharedPrinter name="P1" clsid="{2}"><Properties action="U" path="\\ps\printer" username="CORP\print" cpassword="` + blob + `"/></SharedPrinter></Printers>`
	var cs ConfigSettings
	parseGPPPrinters([]byte(xml), &cs)
	if len(cs.Printers) != 1 || cs.Printers[0].Path != `\\ps\printer` {
		t.Fatalf("printer not parsed: %+v", cs.Printers)
	}
	got := analyseGPPPassword(nil, "Computer", &cs, nil)
	if !hasSeverity(got, "gpp-cpassword", SevCritical) {
		t.Fatalf("expected Critical cpassword finding for printer: %+v", got)
	}
}

func TestParseGPPEnvVarsCreds(t *testing.T) {
	xml := `<EnvironmentVariables clsid="{1}">` +
		`<EnvironmentVariable name="API_PASSWORD" clsid="{2}"><Properties action="U" name="API_PASSWORD" value="s3cret"/></EnvironmentVariable>` +
		`<EnvironmentVariable name="JAVA_HOME" clsid="{3}"><Properties action="U" name="JAVA_HOME" value="C:\jdk"/></EnvironmentVariable>` +
		`</EnvironmentVariables>`
	var cs ConfigSettings
	parseGPPEnvVars([]byte(xml), &cs)
	if len(cs.EnvVars) != 2 {
		t.Fatalf("expected 2 env vars, got %+v", cs.EnvVars)
	}
	got := analyseEnvVars(nil, "Computer", &cs, nil)
	if len(got) != 1 || got[0].Severity != SevLow || !strings.Contains(got[0].Detail, "API_PASSWORD") {
		t.Fatalf("expected one Low env-var-creds finding for the password var, got %+v", got)
	}
}

func TestFirstMSIPath(t *testing.T) {
	cases := map[string]string{
		`0:\\fs01\sw\app.msi`: `\\fs01\sw\app.msi`,
		`\\fs01\sw\app.msi`:   `\\fs01\sw\app.msi`,
		`2:C:\local\app.msi`:  `C:\local\app.msi`,
	}
	for in, want := range cases {
		if got := firstMSIPath([]string{in}); got != want {
			t.Errorf("firstMSIPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestAssessMSIInstallUNC(t *testing.T) {
	cs := ConfigSettings{SoftwareInstalls: []SoftwareInstall{
		{Name: "7-Zip", Path: `\\fs01\software\7zip.msi`},
	}}
	got := analyseDeployPaths(nil, "Computer", &cs, nil)
	if !hasSeverity(got, "msi-install", SevInfo) {
		t.Fatalf("expected Info msi-install finding, got %+v", got)
	}
}

func TestOwnerGPOScope(t *testing.T) {
	g := &GPO{GUID: "{G}", DN: "CN={G},CN=Policies,CN=System,DC=corp,DC=local"}
	byDN := map[string]*GPO{strings.ToLower(g.DN): g}
	if owner, scope := ownerGPO(byDN, "CN=pkg,CN=Class Store,CN=User,CN={G},CN=Policies,CN=System,DC=corp,DC=local"); owner != g || scope != "User" {
		t.Errorf("expected owner g / User scope, got %v / %s", owner, scope)
	}
	if owner, scope := ownerGPO(byDN, "CN=pkg,CN=Class Store,CN=Machine,CN={G},CN=Policies,CN=System,DC=corp,DC=local"); owner != g || scope != "Computer" {
		t.Errorf("expected owner g / Computer scope, got %v / %s", owner, scope)
	}
}
