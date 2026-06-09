package main

import (
	"strconv"
	"strings"
)

// This file parses the subset of SDDL needed to assess service security
// descriptors (GptTmpl.inf [Service General Setting]) without a live
// connection. It is deliberately positional and tolerant rather than a full
// SDDL implementation.

// dangerousServiceRightTokens are SDDL rights codes that let a non-admin
// principal escalate via a service: change its binary path / configuration, or
// rewrite its DACL / owner to grant itself that.
var dangerousServiceRightTokens = map[string]string{
	"DC": "SERVICE_CHANGE_CONFIG", // ADS bit 0x2 — set binPath ⇒ SYSTEM execution
	"WD": "WRITE_DAC",
	"WO": "WRITE_OWNER",
	"GA": "GENERIC_ALL",
	"GW": "GENERIC_WRITE",
}

// sddlAliasSID maps the common SDDL 2-letter SID aliases (trustee field) to a
// SID so the low-priv / admin classifiers can be reused.
var sddlAliasSID = map[string]string{
	"WD": "S-1-1-0",      // Everyone
	"AN": "S-1-5-7",      // Anonymous
	"AU": "S-1-5-11",     // Authenticated Users
	"IU": "S-1-5-4",      // Interactive
	"NU": "S-1-5-2",      // Network
	"SU": "S-1-5-6",      // Service
	"BU": "S-1-5-32-545", // Users
	"BG": "S-1-5-32-546", // Guests
	"SY": "S-1-5-18",     // Local System
	"BA": "S-1-5-32-544", // Administrators
	"LS": "S-1-5-19",     // Local Service
	"NS": "S-1-5-20",     // Network Service
}

// privilegedSDDLAliases are trustees expected to hold powerful service rights,
// so granting them those rights is not a finding.
var privilegedSDDLAliases = map[string]bool{
	"BA": true, "SY": true, "DA": true, "EA": true, "LA": true,
	"SA": true, "BO": true, "PA": true, "CO": true, "OW": true, "SO": true,
}

type sddlACE struct {
	Type    string   // "A" allow, "D" deny, "XA"/"XD" callback, "AU" audit, ...
	Rights  []string // 2-char rights tokens, upper-case
	Trustee string   // SID alias or literal SID, upper-case
}

// parseSDDLACEs extracts the ACEs of the DACL portion of an SDDL string. A bare
// list of ACEs (no "O:/G:/D:" prefix) is also accepted. SACL audit ACEs that
// follow an "S:" section are tolerated because the caller filters on ace.Type.
func parseSDDLACEs(sddl string) []sddlACE {
	if i := strings.Index(sddl, "D:"); i >= 0 {
		sddl = sddl[i+2:]
	}
	var aces []sddlACE
	for {
		_, after, found := strings.Cut(sddl, "(")
		if !found {
			break
		}
		body, rest, found := strings.Cut(after, ")")
		if !found {
			break
		}
		sddl = rest

		fields := strings.Split(body, ";")
		if len(fields) < 6 {
			continue
		}
		aces = append(aces, sddlACE{
			Type:    strings.ToUpper(strings.TrimSpace(fields[0])),
			Rights:  splitRightsTokens(fields[2]),
			Trustee: strings.ToUpper(strings.TrimSpace(fields[5])),
		})
	}
	return aces
}

// splitRightsTokens splits an SDDL rights field into 2-char tokens, expanding a
// hex/decimal mask form (e.g. "0x1f01ff") into the equivalent tokens.
func splitRightsTokens(field string) []string {
	f := strings.ToUpper(strings.TrimSpace(field))
	if f == "" {
		return nil
	}
	if strings.HasPrefix(f, "0X") {
		if mask, err := strconv.ParseUint(f, 0, 32); err == nil {
			return rightsFromMask(uint32(mask))
		}
		return nil
	}
	var toks []string
	for i := 0; i+2 <= len(f); i += 2 {
		toks = append(toks, f[i:i+2])
	}
	return toks
}

func rightsFromMask(mask uint32) []string {
	var t []string
	if mask&0x10000000 != 0 {
		t = append(t, "GA")
	}
	if mask&0x40000000 != 0 {
		t = append(t, "GW")
	}
	if mask&0x00040000 != 0 {
		t = append(t, "WD")
	}
	if mask&0x00080000 != 0 {
		t = append(t, "WO")
	}
	if mask&0x00000002 != 0 {
		t = append(t, "DC") // SERVICE_CHANGE_CONFIG
	}
	return t
}

// dangerousServiceRights returns the friendly names of the privesc-enabling
// rights present in an ACE's token list.
func dangerousServiceRights(tokens []string) []string {
	var out []string
	for _, t := range tokens {
		if name, ok := dangerousServiceRightTokens[t]; ok {
			out = append(out, name)
		}
	}
	return out
}

// sddlTrusteeSID resolves a trustee field to a SID, or "" if it is an alias we
// do not map.
func sddlTrusteeSID(trustee string) string {
	if strings.HasPrefix(trustee, "S-1-") {
		return trustee
	}
	return sddlAliasSID[trustee]
}

// isPrivilegedServiceTrustee reports whether the trustee is administrator-class
// and thus expected to hold service rights.
func isPrivilegedServiceTrustee(trustee, sid string) bool {
	if privilegedSDDLAliases[trustee] {
		return true
	}
	return sid != "" && isAdminEquivalent(sid)
}

func sddlTrusteeLabel(trustee, sid string) string {
	if sid != "" {
		if n := wellKnownSIDName(sid); n != "" {
			return n + " (" + sid + ")"
		}
		return sid
	}
	return trustee
}
