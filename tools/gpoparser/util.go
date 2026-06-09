package main

import (
	"strings"
	"unicode/utf16"
)

// normalizeGUID upper-cases a GPO GUID and ensures it is wrapped in braces, so
// "{guid}", "guid", and any case all compare equal.
func normalizeGUID(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(s, "}")
	if s == "" {
		return ""
	}
	return "{" + strings.ToUpper(s) + "}"
}

func lowerTrim(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func lowerContains(haystack, lowerNeedle string) bool {
	return strings.Contains(strings.ToLower(haystack), lowerNeedle)
}

// decodeUTF16 converts a byte slice that may be UTF-16 (LE or BE, with or
// without BOM) into a Go string. Files that are not UTF-16 (no BOM and no
// obvious interleaved NULs) are returned as-is, so the same helper works for
// UTF-8 and ANSI INI files.
func decodeUTF16(b []byte) string {
	if len(b) >= 2 {
		switch {
		case b[0] == 0xFF && b[1] == 0xFE: // UTF-16 LE BOM
			return decodeUTF16Pairs(b[2:], false)
		case b[0] == 0xFE && b[1] == 0xFF: // UTF-16 BE BOM
			return decodeUTF16Pairs(b[2:], true)
		case b[0] == 0xEF && len(b) >= 3 && b[1] == 0xBB && b[2] == 0xBF: // UTF-8 BOM
			return string(b[3:])
		}
	}
	// Heuristic: GptTmpl.inf / scripts.ini are usually UTF-16LE without a BOM
	// when written by Windows. Detect lots of NUL high-bytes in even positions.
	if looksLikeUTF16LE(b) {
		return decodeUTF16Pairs(b, false)
	}
	return string(b)
}

func looksLikeUTF16LE(b []byte) bool {
	if len(b) < 4 || len(b)%2 != 0 {
		return false
	}
	nul := 0
	checked := 0
	for i := 1; i < len(b) && checked < 64; i += 2 {
		checked++
		if b[i] == 0x00 {
			nul++
		}
	}
	return checked > 0 && nul*2 >= checked // majority of high bytes are NUL
}

func decodeUTF16Pairs(b []byte, bigEndian bool) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16 := make([]uint16, len(b)/2)
	for i := 0; i < len(u16); i++ {
		if bigEndian {
			u16[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
		} else {
			u16[i] = uint16(b[2*i+1])<<8 | uint16(b[2*i])
		}
	}
	return string(utf16.Decode(u16))
}

// splitUNCShare splits a UNC path "\\server\share\rest\path" into the share
// name ("share") and the path within the share ("rest\path", backslash
// separated, no leading slash). Forward slashes are tolerated.
func splitUNCShare(unc string) (share, path string) {
	s := strings.ReplaceAll(unc, "/", "\\")
	s = strings.TrimPrefix(s, "\\\\")
	parts := strings.SplitN(s, "\\", 3)
	switch len(parts) {
	case 0, 1:
		return "", ""
	case 2:
		return parts[1], ""
	default:
		return parts[1], parts[2]
	}
}
