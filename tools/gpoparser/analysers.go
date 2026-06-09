package main

import (
	"strconv"
	"strings"
)

func init() {
	registerAnalyser("gpp-cpassword", analyseGPPPassword)
	registerAnalyser("user-rights", analyseUserRights)
	registerAnalyser("restricted-groups", analyseRestrictedGroups)
	registerAnalyser("registry-policy", analyseRegistryPolicy)
	registerAnalyser("system-access", analyseSystemAccess)
	registerAnalyser("exec-path", analyseExecPath)
	registerAnalyser("env-var-creds", analyseEnvVars)
	registerAnalyser("deploy-path", analyseDeployPaths)
	registerAnalyser("service-sddl", analyseServiceSDDL)
}

// analyseServiceSDDL flags service security descriptors (GptTmpl.inf
// [Service General Setting]) that grant config-change / DACL / owner rights to a
// non-administrative principal — a local privilege-escalation primitive. Offline:
// it parses the SDDL string already captured in the cache.
func analyseServiceSDDL(_ *GPO, _ string, cs *ConfigSettings, _ *assessCtx) []Finding {
	var out []Finding
	for _, s := range cs.Services {
		if s.SDDL == "" {
			continue
		}
		seen := map[string]bool{}
		for _, ace := range parseSDDLACEs(s.SDDL) {
			if ace.Type != "A" && ace.Type != "XA" {
				continue // allow ACEs only
			}
			danger := dangerousServiceRights(ace.Rights)
			if len(danger) == 0 {
				continue
			}
			sid := sddlTrusteeSID(ace.Trustee)
			if isPrivilegedServiceTrustee(ace.Trustee, sid) {
				continue
			}
			key := ace.Trustee + strings.Join(danger, "")
			if seen[key] {
				continue
			}
			seen[key] = true
			trustee := Principal{Name: ace.Trustee}
			if sid != "" {
				trustee = principalFromSID(sid)
			}
			out = append(out, Finding{
				Category: "service-sddl", Severity: SevHigh,
				Reason:     "service DACL grants " + strings.Join(danger, "/") + " to a non-administrative principal (local privilege escalation)",
				Detail:     "service " + s.Name + " → " + sddlTrusteeLabel(ace.Trustee, sid),
				Principals: []Principal{trustee},
			})
		}
	}
	return out
}

// analyseEnvVars flags GPP environment variables whose name or value looks like
// it carries a credential.
func analyseEnvVars(_ *GPO, _ string, cs *ConfigSettings, _ *assessCtx) []Finding {
	var out []Finding
	for _, e := range cs.EnvVars {
		if looksLikeCredentialArg(e.Name) || looksLikeCredentialArg(e.Value) {
			out = append(out, Finding{
				Category: "env-var-creds", Severity: SevLow,
				Reason: "environment variable may carry a credential",
				Detail: e.Name + "=" + truncate(e.Value, 120),
			})
		}
	}
	return out
}

// analyseDeployPaths flags GPP file copies, shortcuts and MSI installs that pull
// content from a UNC path. The path is Info on its own; a Phase 4 ACL check
// decides whether it is attacker-writable (writable ⇒ code execution).
func analyseDeployPaths(_ *GPO, _ string, cs *ConfigSettings, _ *assessCtx) []Finding {
	var out []Finding
	for _, f := range cs.Files {
		if isUNCPath(f.FromPath) {
			out = append(out, Finding{
				Category: "gpp-file", Severity: SevInfo,
				Reason: "file is copied from a UNC source — verify path ACLs (writable ⇒ attacker controls deployed file)",
				Detail: f.FromPath + " → " + f.TargetPath,
			})
		}
	}
	for _, s := range cs.Shortcuts {
		if isUNCPath(s.TargetPath) {
			out = append(out, Finding{
				Category: "gpp-shortcut", Severity: SevInfo,
				Reason: "shortcut targets a UNC path — verify path ACLs (writable ⇒ code execution)",
				Detail: s.Name + " → " + s.TargetPath,
			})
		}
		if looksLikeCredentialArg(s.Arguments) {
			out = append(out, Finding{
				Category: "gpp-shortcut", Severity: SevLow,
				Reason: "shortcut arguments may contain a credential",
				Detail: s.Name + ": " + s.TargetPath + " " + s.Arguments,
			})
		}
	}
	for _, si := range cs.SoftwareInstalls {
		if isUNCPath(si.Path) {
			out = append(out, Finding{
				Category: "msi-install", Severity: SevInfo,
				Reason: "MSI is installed from a UNC path — verify path ACLs (writable ⇒ SYSTEM code execution)",
				Detail: si.Name + ": " + si.Path,
			})
		}
	}
	return out
}

// analyseGPPPassword flags any Group Policy Preferences cpassword (MS14-025):
// the AES key is public, so the password is recoverable. Surfaces it from local
// users (Groups.xml), services, and scheduled tasks.
func analyseGPPPassword(_ *GPO, _ string, cs *ConfigSettings, _ *assessCtx) []Finding {
	var out []Finding
	add := func(account, where, cpw string) {
		detail := where
		if account != "" {
			detail += " (account " + account + ")"
		}
		if pw, err := decryptGPPPassword(cpw); err == nil {
			detail += " — recovered password: " + pw
		} else {
			detail += " — encrypted password present (decrypt failed: " + err.Error() + ")"
		}
		out = append(out, Finding{
			Category:  "gpp-cpassword",
			Severity:  SevCritical,
			Reason:    "Group Policy Preferences stores a reversibly-encrypted password (MS14-025)",
			Detail:    detail,
			Reference: "MS14-025; https://adsecurity.org/?p=63",
		})
	}
	for _, u := range cs.LocalUsers {
		if u.CPassword != "" {
			add(firstNonEmpty(u.UserName, u.Name), "local user "+u.Name, u.CPassword)
		}
	}
	for _, s := range cs.Services {
		if s.CPassword != "" {
			add(s.Account, "service "+s.Name, s.CPassword)
		}
	}
	for _, t := range cs.ScheduledTasks {
		if t.CPassword != "" {
			add(t.RunAs, "scheduled task "+t.Name, t.CPassword)
		}
	}
	for _, ds := range cs.DataSources {
		if ds.CPassword != "" {
			add(ds.UserName, "data source "+ds.Name, ds.CPassword)
		}
	}
	for _, dr := range cs.Drives {
		if dr.CPassword != "" {
			add(dr.UserName, "mapped drive "+firstNonEmpty(dr.Letter, dr.Path), dr.CPassword)
		}
	}
	for _, pr := range cs.Printers {
		if pr.CPassword != "" {
			add(pr.UserName, "printer "+pr.Name, pr.CPassword)
		}
	}
	return out
}

// analyseUserRights flags dangerous user-right assignments (GptTmpl.inf
// [Privilege Rights]) granted to principals that are not expected to hold them.
// Grant to a large low-trust population (Everyone/Authenticated Users/Domain
// Users) is Critical; any other unexpected holder is High.
func analyseUserRights(_ *GPO, _ string, cs *ConfigSettings, _ *assessCtx) []Finding {
	var out []Finding
	for _, p := range cs.Privileges {
		if !isDangerousPrivilege(p.Privilege) {
			continue
		}
		var interesting []Principal
		lowPriv := false
		for _, m := range p.Members {
			if isExpectedPrivHolder(m.SID, p.Privilege) {
				continue
			}
			interesting = append(interesting, m)
			if isLowPrivPrincipal(m.SID) {
				lowPriv = true
			}
		}
		if len(interesting) == 0 {
			continue
		}
		sev := SevHigh
		if lowPriv {
			sev = SevCritical
		}
		out = append(out, Finding{
			Category:   "user-rights",
			Severity:   sev,
			Reason:     p.Privilege + " — " + privilegeDescription(p.Privilege),
			Detail:     "granted to " + joinPrincipals(interesting),
			Principals: interesting,
		})
	}
	return out
}

// analyseRestrictedGroups flags low-privileged principals being placed into
// privileged groups, via either direct membership or a privileged group named
// in a group's __Memberof (Restricted Groups / GPP Local Groups).
func analyseRestrictedGroups(_ *GPO, _ string, cs *ConfigSettings, _ *assessCtx) []Finding {
	var out []Finding
	for _, gm := range cs.GroupMemberships {
		// Members added directly to a privileged group.
		if isPrivilegedGroup(gm.Group) {
			var interesting []Principal
			lowPriv := false
			for _, m := range gm.Members {
				if isAdminEquivalent(m.SID) {
					continue // adding an admin to an admin group is noise
				}
				interesting = append(interesting, m)
				if isLowPrivPrincipal(m.SID) {
					lowPriv = true
				}
			}
			if len(interesting) > 0 {
				if lowPriv {
					out = append(out, Finding{
						Category:   "restricted-groups",
						Severity:   SevHigh,
						Reason:     "low-privileged principal added to privileged group " + gm.Group.String(),
						Detail:     joinPrincipals(interesting),
						Principals: interesting,
					})
				} else {
					out = append(out, Finding{
						Category:   "restricted-groups-info",
						Severity:   SevInfo,
						Reason:     "principals added to privileged group " + gm.Group.String(),
						Detail:     joinPrincipals(interesting),
						Principals: interesting,
					})
				}
			}
		}
		// This group is made a member of a privileged group (__Memberof).
		for _, mo := range gm.MemberOf {
			if !isPrivilegedGroup(mo) {
				continue
			}
			sev := SevInfo
			cat := "restricted-groups-info"
			if isLowPrivPrincipal(gm.Group.SID) {
				sev = SevHigh
				cat = "restricted-groups"
			}
			out = append(out, Finding{
				Category:   cat,
				Severity:   sev,
				Reason:     gm.Group.String() + " is made a member of privileged group " + mo.String(),
				Principals: []Principal{gm.Group},
			})
		}
	}
	return out
}

// analyseRegistryPolicy matches deployed registry values (Registry.pol, GPP
// Registry.xml, GptTmpl.inf [Registry Values]) against the dangerous-registry
// watchlist.
func analyseRegistryPolicy(_ *GPO, _ string, cs *ConfigSettings, _ *assessCtx) []Finding {
	var out []Finding
	for _, r := range cs.RegistryValues {
		key, name, val := normReg(r)
		for _, rule := range regRules {
			if !strings.Contains(key, rule.keyMatch) {
				continue
			}
			if rule.value != "" && name != rule.value {
				continue
			}
			if !rule.fires(val) {
				continue
			}
			out = append(out, Finding{
				Category:  "registry-policy",
				Severity:  rule.sev,
				Reason:    rule.reason,
				Detail:    registryLocation(r) + " = " + truncate(val, 120),
				Reference: rule.ref,
			})
			break // first matching rule wins for this setting
		}
	}
	return out
}

// analyseSystemAccess flags weak account-policy settings (GptTmpl.inf
// [System Access]).
func analyseSystemAccess(_ *GPO, _ string, cs *ConfigSettings, _ *assessCtx) []Finding {
	var out []Finding
	add := func(sev Severity, reason, detail string) {
		out = append(out, Finding{Category: "system-access", Severity: sev, Reason: reason, Detail: detail})
	}
	for _, kv := range cs.SystemAccess {
		v := strings.TrimSpace(kv.Value)
		switch strings.ToLower(kv.Key) {
		case "cleartextpassword":
			if v == "1" {
				add(SevLow, "Passwords stored with reversible encryption (ClearTextPassword=1)", kv.Key+"="+v)
			}
		case "enableguestaccount":
			if v == "1" {
				add(SevLow, "Guest account enabled", kv.Key+"="+v)
			}
		case "minimumpasswordlength":
			if n, err := strconv.Atoi(v); err == nil && n < 8 {
				add(SevInfo, "Weak minimum password length (<8)", kv.Key+"="+v)
			}
		case "passwordcomplexity":
			if v == "0" {
				add(SevInfo, "Password complexity disabled", kv.Key+"="+v)
			}
		case "lockoutbadcount":
			if v == "0" {
				add(SevInfo, "No account lockout threshold (LockoutBadCount=0)", kv.Key+"="+v)
			}
		}
	}
	return out
}

// analyseExecPath flags scripts and scheduled tasks that run from a UNC path
// (Info — a Phase 4 ACL check decides whether the path is attacker-writable)
// and arguments that look like they embed credentials (Low).
func analyseExecPath(_ *GPO, _ string, cs *ConfigSettings, _ *assessCtx) []Finding {
	var out []Finding
	for _, s := range cs.Scripts {
		if isUNCPath(s.CmdLine) {
			out = append(out, Finding{
				Category: "exec-path", Severity: SevInfo,
				Reason: "logon/startup script runs from a UNC path — verify path ACLs (writable ⇒ code execution)",
				Detail: strings.TrimSpace(s.Type + " " + s.CmdLine + " " + s.Parameters),
			})
		}
		if looksLikeCredentialArg(s.Parameters) {
			out = append(out, Finding{
				Category: "exec-path", Severity: SevLow,
				Reason: "script parameters may contain a credential",
				Detail: strings.TrimSpace(s.CmdLine + " " + s.Parameters),
			})
		}
	}
	for _, t := range cs.ScheduledTasks {
		if isUNCPath(t.Command) {
			out = append(out, Finding{
				Category: "exec-path", Severity: SevInfo,
				Reason: "scheduled task runs a command from a UNC path — verify path ACLs (writable ⇒ code execution)",
				Detail: strings.TrimSpace(t.Name + ": " + t.Command + " " + t.Arguments),
			})
		}
		if looksLikeCredentialArg(t.Arguments) {
			out = append(out, Finding{
				Category: "exec-path", Severity: SevLow,
				Reason: "scheduled task arguments may contain a credential",
				Detail: strings.TrimSpace(t.Name + ": " + t.Command + " " + t.Arguments),
			})
		}
	}
	return out
}

// isUNCPath reports whether s begins with a UNC prefix (\\server\share\...).
func isUNCPath(s string) bool {
	s = strings.TrimSpace(strings.Trim(s, `"`))
	s = strings.ReplaceAll(s, "/", `\`)
	return strings.HasPrefix(s, `\\`)
}

var credentialArgTokens = []string{"password", "passwd", "/pass", "-pass", "cred", "/p:", "-p:", "/u:", "-u:"}

// looksLikeCredentialArg reports whether an argument string contains a token
// commonly used to pass credentials on a command line.
func looksLikeCredentialArg(args string) bool {
	a := strings.ToLower(args)
	for _, tok := range credentialArgTokens {
		if strings.Contains(a, tok) {
			return true
		}
	}
	return false
}
