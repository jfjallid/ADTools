package main

import (
	"strconv"
	"strings"
)

// regMatch selects how a regRule compares a setting's value.
type regMatch int

const (
	regPresent   regMatch = iota // fires whenever the value is configured at all
	regEquals                    // fires when value == operand (case-insensitive)
	regNotEquals                 // fires when value != operand
	regLessThan                  // fires when the integer value < operand
)

// regRule is one entry of the dangerous-registry watchlist, modelled on
// Group3r's RegKeys.cs. keyMatch is a lower-case substring that must appear in
// the (hive-stripped, lower-cased) key path; value is the lower-case value name.
type regRule struct {
	keyMatch string
	value    string
	mode     regMatch
	operand  string
	sev      Severity
	reason   string
	ref      string
}

func (r regRule) fires(val string) bool {
	switch r.mode {
	case regPresent:
		return true
	case regEquals:
		return strings.EqualFold(strings.TrimSpace(val), r.operand)
	case regNotEquals:
		return !strings.EqualFold(strings.TrimSpace(val), r.operand)
	case regLessThan:
		a, err1 := strconv.Atoi(strings.TrimSpace(val))
		b, err2 := strconv.Atoi(r.operand)
		return err1 == nil && err2 == nil && a < b
	}
	return false
}

// regRules is the dangerous-registry watchlist. It deliberately includes
// AlwaysInstallElevated, which Group3r's current watchlist omits.
var regRules = []regRule{
	// --- instant privilege escalation -------------------------------------
	{keyMatch: "installer", value: "alwaysinstallelevated", mode: regEquals, operand: "1",
		sev: SevCritical, reason: "AlwaysInstallElevated enabled — any user can install an MSI as SYSTEM"},

	// --- credentials in the open ------------------------------------------
	{keyMatch: "winlogon", value: "defaultpassword", mode: regPresent,
		sev: SevCritical, reason: "Plaintext autologon password stored in registry (Winlogon DefaultPassword)"},
	{keyMatch: "winlogon", value: "autoadminlogon", mode: regEquals, operand: "1",
		sev: SevLow, reason: "Automatic logon enabled (AutoAdminLogon=1)"},

	// --- credential exposure in LSASS -------------------------------------
	{keyMatch: "wdigest", value: "uselogoncredential", mode: regEquals, operand: "1",
		sev: SevHigh, reason: "WDigest configured to cache plaintext credentials in LSASS"},
	{keyMatch: "lsa", value: "runasppl", mode: regEquals, operand: "0",
		sev: SevLow, reason: "LSA protection (RunAsPPL) explicitly disabled"},

	// --- authentication downgrade -----------------------------------------
	{keyMatch: "lsa", value: "lmcompatibilitylevel", mode: regLessThan, operand: "3",
		sev: SevHigh, reason: "LM/NTLMv1 authentication permitted (LmCompatibilityLevel < 3)"},
	{keyMatch: "lsa", value: "limitblankpassworduse", mode: regEquals, operand: "0",
		sev: SevLow, reason: "Blank passwords permitted for network logon (LimitBlankPasswordUse=0)"},

	// --- UAC / token policy -----------------------------------------------
	{keyMatch: `policies\system`, value: "enablelua", mode: regEquals, operand: "0",
		sev: SevHigh, reason: "UAC disabled (EnableLUA=0)"},
	{keyMatch: `policies\system`, value: "localaccounttokenfilterpolicy", mode: regEquals, operand: "1",
		sev: SevHigh, reason: "Remote UAC token filtering disabled — local-admin creds usable for lateral movement"},
	{keyMatch: `policies\system`, value: "filteradministratortoken", mode: regEquals, operand: "0",
		sev: SevLow, reason: "Built-in Administrator not token-filtered for remote logon"},

	// --- anonymous / null session -----------------------------------------
	{keyMatch: "lsa", value: "restrictanonymous", mode: regEquals, operand: "0",
		sev: SevLow, reason: "Anonymous enumeration not restricted (RestrictAnonymous=0)"},
	{keyMatch: "lsa", value: "everyoneincludesanonymous", mode: regEquals, operand: "1",
		sev: SevLow, reason: "Anonymous users included in Everyone (EveryoneIncludesAnonymous=1)"},

	// --- SMB / LDAP signing -----------------------------------------------
	{keyMatch: `lanmanserver\parameters`, value: "requiresecuritysignature", mode: regEquals, operand: "0",
		sev: SevLow, reason: "SMB server signing not required"},
	{keyMatch: `lanmanworkstation\parameters`, value: "enableplaintextpassword", mode: regEquals, operand: "1",
		sev: SevLow, reason: "SMB client permits plaintext passwords"},
	{keyMatch: "ldap", value: "ldapclientintegrity", mode: regEquals, operand: "0",
		sev: SevLow, reason: "LDAP client signing not required (LDAPClientIntegrity=0)"},

	// --- Netlogon secure channel ------------------------------------------
	{keyMatch: `netlogon\parameters`, value: "requiresignorseal", mode: regEquals, operand: "0",
		sev: SevLow, reason: "Netlogon secure channel signing/sealing not required"},
	{keyMatch: `netlogon\parameters`, value: "requirestrongkey", mode: regEquals, operand: "0",
		sev: SevLow, reason: "Netlogon strong session key not required"},

	// --- WinRM -------------------------------------------------------------
	{keyMatch: "winrm", value: "allowunencryptedtraffic", mode: regEquals, operand: "1",
		sev: SevLow, reason: "WinRM allows unencrypted traffic"},
	{keyMatch: "winrm", value: "allowbasic", mode: regEquals, operand: "1",
		sev: SevLow, reason: "WinRM allows Basic authentication"},
}

// normReg normalises a RegistrySetting into a lower-cased, hive-stripped key
// path and value name for watchlist matching. GptTmpl [Registry Values] embeds
// the value name as the final path segment with no separate Name field; the
// other sources keep them apart.
func normReg(r RegistrySetting) (key, name, value string) {
	k := strings.ReplaceAll(r.Key, "/", `\`)
	name = r.Name
	if name == "" {
		if i := strings.LastIndex(k, `\`); i >= 0 {
			name = k[i+1:]
			k = k[:i]
		}
	}
	k = strings.ToLower(k)
	for _, p := range []string{`machine\`, `user\`, `hkey_local_machine\`, `hkey_current_user\`, `hkey_users\`, `hklm\`, `hkcu\`} {
		k = strings.TrimPrefix(k, p)
	}
	return k, strings.ToLower(name), strings.TrimSpace(r.Value)
}

// registryLocation renders a human-readable hive\key\value path for a finding.
func registryLocation(r RegistrySetting) string {
	loc := r.Key
	if r.Hive != "" {
		loc = r.Hive + `\` + r.Key
	}
	if r.Name != "" {
		loc += `\` + r.Name
	}
	return loc
}
