package main

import "strings"

// iniEntry is a single key=value line within a section. Order is preserved.
type iniEntry struct {
	key   string
	value string
}

// iniSection is a [Name] section and its ordered entries.
type iniSection struct {
	name    string
	entries []iniEntry
}

// parseINI parses INI text into ordered sections. It tolerates the quirks of
// Windows policy files: leading BOM (already stripped by decodeUTF16), ';'
// comments, blank lines, and values that themselves contain '=' (only the
// first '=' splits key from value).
func parseINI(text string) []iniSection {
	var sections []iniSection
	var cur *iniSection
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, ";") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			sections = append(sections, iniSection{name: strings.TrimSpace(trimmed[1 : len(trimmed)-1])})
			cur = &sections[len(sections)-1]
			continue
		}
		if cur == nil {
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			// A bare line with no '=' (rare); keep it as a key with empty value.
			cur.entries = append(cur.entries, iniEntry{key: trimmed})
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		cur.entries = append(cur.entries, iniEntry{key: key, value: val})
	}
	return sections
}

// section returns the first section matching name (case-insensitive), or nil.
func section(sections []iniSection, name string) *iniSection {
	for i := range sections {
		if strings.EqualFold(sections[i].name, name) {
			return &sections[i]
		}
	}
	return nil
}

// parsePrincipalList splits a comma-separated SECEDIT principal list. SIDs are
// prefixed with '*' (e.g. *S-1-5-32-544); bare tokens are account names. Name
// resolution against well-known tables / LDAP happens in a later pass.
func parsePrincipalList(value string) []Principal {
	var out []Principal
	for _, tok := range strings.Split(value, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if strings.HasPrefix(tok, "*") {
			out = append(out, principalFromSID(strings.TrimPrefix(tok, "*")))
		} else {
			out = append(out, Principal{Name: tok})
		}
	}
	return out
}
