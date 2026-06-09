package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jfjallid/go-smb/msdtyp"
)

// loadDump reads an offline LDAP dump (ldeep JSON arrays or an ADExplorer
// objects.ndjson) from dir and classifies objects into GPOs, link containers
// and computers. format may be "ldeep", "adexplorer" or "" (auto-detect).
func loadDump(dir, format string) (gpos []*GPO, ous []*OU, comps []*Computer, baseDN, domainSID, fqdn string, err error) {
	objs, err := readDumpObjects(dir, format)
	if err != nil {
		return nil, nil, nil, "", "", "", err
	}
	if len(objs) == 0 {
		return nil, nil, nil, "", "", "", fmt.Errorf("no LDAP objects found in %s", dir)
	}

	for _, o := range objs {
		classes := lowerSet(attrStrs(o, "objectClass"))
		dn := firstNonEmpty(attrStr(o, "distinguishedName"), attrStr(o, "dn"))

		switch {
		case classes["grouppolicycontainer"] || attrStr(o, "gPCFileSysPath") != "":
			guid := normalizeGUID(attrStr(o, "cn"))
			if guid == "" {
				guid = normalizeGUID(cnGUIDRe.FindString(dn))
			}
			if guid == "" {
				continue
			}
			g := &GPO{
				GUID:        guid,
				Name:        firstNonEmpty(attrStr(o, "displayName"), guid),
				DN:          dn,
				FileSysPath: attrStr(o, "gPCFileSysPath"),
				Flags:       atoiSafe(attrStr(o, "flags")),
				Version:     atoiSafe(attrStr(o, "versionNumber")),
			}
			gpos = append(gpos, g)

		case classes["domaindns"]:
			baseDN = dn
			domainSID = sidFromValue(attrStr(o, "objectSid"))
			ous = append(ous, dumpContainer(o, dn, "domain"))

		case classes["organizationalunit"] || strings.HasPrefix(strings.ToUpper(dn), "OU="):
			ous = append(ous, dumpContainer(o, dn, "ou"))

		case classes["computer"] || attrStr(o, "dNSHostName") != "" ||
			(strings.HasSuffix(attrStr(o, "sAMAccountName"), "$") && !classes["group"]):
			comps = append(comps, &Computer{
				DN:          dn,
				Name:        attrStr(o, "name"),
				DNSHostName: attrStr(o, "dNSHostName"),
				SID:         sidFromValue(attrStr(o, "objectSid")),
			})
		}
	}

	if baseDN == "" {
		baseDN = deriveBaseDN(gpos, ous, comps)
	}
	fqdn = baseDNToFQDN(baseDN)
	return gpos, ous, comps, baseDN, domainSID, fqdn, nil
}

func dumpContainer(o map[string]any, dn, kind string) *OU {
	c := &OU{
		DN:        dn,
		Name:      attrStr(o, "name"),
		Kind:      kind,
		GUID:      formatDumpGUID(attrStr(o, "objectGUID")),
		RawGPLink: attrStr(o, "gPLink"),
		Links:     parseGPLink(attrStr(o, "gPLink")),
	}
	if atoiSafe(attrStr(o, "gPOptions"))&1 == 1 {
		c.BlockInheritance = true
	}
	return c
}

// readDumpObjects loads the raw objects, picking the file format.
func readDumpObjects(dir, format string) ([]map[string]any, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("ldap dump %q: %w", dir, err)
	}

	// A single ndjson file path is also accepted.
	if !info.IsDir() {
		if strings.HasSuffix(strings.ToLower(dir), ".ndjson") || format == "adexplorer" {
			return readNDJSON(dir)
		}
		return readJSONArray(dir)
	}

	if format == "" {
		if _, e := os.Stat(filepath.Join(dir, "objects.ndjson")); e == nil {
			format = "adexplorer"
		}
	}
	if format == "adexplorer" {
		path := filepath.Join(dir, "objects.ndjson")
		if _, e := os.Stat(path); e != nil {
			// fall back to any *.ndjson
			matches, _ := filepath.Glob(filepath.Join(dir, "*.ndjson"))
			if len(matches) == 0 {
				return nil, fmt.Errorf("no objects.ndjson found in %s", dir)
			}
			path = matches[0]
		}
		return readNDJSON(path)
	}

	// ldeep: every *.json array in the directory.
	matches, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(matches) == 0 {
		return nil, fmt.Errorf("no *.json files found in %s (expected an ldeep dump)", dir)
	}
	var all []map[string]any
	for _, m := range matches {
		objs, err := readJSONArray(m)
		if err != nil {
			logger.Debugf("skipping %s: %v\n", m, err)
			continue
		}
		all = append(all, objs...)
	}
	return all, nil
}

func readJSONArray(path string) ([]map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var arr []map[string]any
	if err := json.Unmarshal(data, &arr); err == nil {
		return arr, nil
	}
	// Maybe a single object.
	var one map[string]any
	if err := json.Unmarshal(data, &one); err == nil {
		return []map[string]any{one}, nil
	}
	return nil, fmt.Errorf("not a JSON array or object")
}

func readNDJSON(path string) ([]map[string]any, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var objs []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var o map[string]any
		if err := json.Unmarshal([]byte(line), &o); err == nil {
			objs = append(objs, o)
		}
	}
	return objs, sc.Err()
}

// ---- attribute accessors (tolerant of scalar vs array values) -------------

func attrStr(o map[string]any, key string) string {
	v, ok := o[key]
	if !ok {
		// try case-insensitive
		for k := range o {
			if strings.EqualFold(k, key) {
				v = o[k]
				ok = true
				break
			}
		}
		if !ok {
			return ""
		}
	}
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	case []any:
		if len(t) > 0 {
			if s, ok := t[0].(string); ok {
				return s
			}
			return fmt.Sprint(t[0])
		}
	}
	return ""
}

func attrStrs(o map[string]any, key string) []string {
	v, ok := o[key]
	if !ok {
		for k := range o {
			if strings.EqualFold(k, key) {
				v = o[k]
				ok = true
				break
			}
		}
		if !ok {
			return nil
		}
	}
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			} else {
				out = append(out, fmt.Sprint(e))
			}
		}
		return out
	}
	return nil
}

func lowerSet(vals []string) map[string]bool {
	m := map[string]bool{}
	for _, v := range vals {
		m[strings.ToLower(strings.TrimSpace(v))] = true
	}
	return m
}

// sidFromValue accepts a string SID, or base64/binary objectSid, and returns
// the string SID form.
func sidFromValue(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToUpper(s), "S-1-") {
		return s
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) >= 8 {
		sid := &msdtyp.SID{}
		if sid.UnmarshalBinary(b) == nil {
			return sid.ToString()
		}
	}
	return s
}

// formatDumpGUID normalises an objectGUID dump value (string GUID or base64
// binary) to BloodHound's uppercase, brace-less form.
func formatDumpGUID(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if strings.Contains(s, "-") && !looksBase64(s) {
		return strings.ToUpper(strings.Trim(s, "{}"))
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 16 {
		var g [16]byte
		copy(g[:], b)
		return strings.ToUpper(strings.Trim(msdtyp.GuidToString(g), "{}"))
	}
	return strings.ToUpper(strings.Trim(s, "{}"))
}

func looksBase64(s string) bool {
	// A canonical GUID string contains hyphens at fixed spots; base64 won't.
	return !strings.Contains(s, "-") && (strings.HasSuffix(s, "=") || len(s)%4 == 0)
}

// deriveBaseDN finds the longest DC=...,DC=... suffix shared by dumped objects.
func deriveBaseDN(gpos []*GPO, ous []*OU, comps []*Computer) string {
	pick := func(dn string) string {
		var parts []string
		for _, p := range strings.Split(dn, ",") {
			if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(p)), "DC=") {
				parts = append(parts, strings.TrimSpace(p))
			}
		}
		return strings.Join(parts, ",")
	}
	for _, o := range ous {
		if o.Kind == "domain" {
			return o.DN
		}
	}
	for _, c := range comps {
		if b := pick(c.DN); b != "" {
			return b
		}
	}
	for _, g := range gpos {
		if b := pick(g.DN); b != "" {
			return b
		}
	}
	for _, o := range ous {
		if b := pick(o.DN); b != "" {
			return b
		}
	}
	return ""
}
