package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// regPolSignature is the "PReg" magic at the start of a Registry.pol file.
var regPolSignature = []byte{'P', 'R', 'e', 'g'}

// parseRegistryPol parses a binary Registry.pol (MS-GPREG) administrative
// template file into registry settings. hive is the implied root hive for the
// scope ("HKLM" for Machine, "HKCU" for User). Records are
// [Key;Value;Type;Size;Data] with UTF-16LE strings and ';'/brackets as
// UTF-16LE delimiters.
func parseRegistryPol(data []byte, hive string, cs *ConfigSettings) {
	if len(data) < 8 || !startsWith(data, regPolSignature) {
		return
	}
	pos := 8 // skip signature(4) + version(4)
	n := len(data)

	readU16Str := func() (string, bool) {
		start := pos
		for pos+1 < n {
			if data[pos] == 0 && data[pos+1] == 0 {
				s := decodeUTF16Pairs(data[start:pos], false)
				pos += 2
				return s, true
			}
			pos += 2
		}
		return "", false
	}
	// expectDelim consumes a single UTF-16LE delimiter character (e.g. '[').
	expectDelim := func(ch byte) bool {
		if pos+1 < n && data[pos] == ch && data[pos+1] == 0 {
			pos += 2
			return true
		}
		return false
	}

	for pos+1 < n {
		if !expectDelim('[') {
			break
		}
		key, ok := readU16Str()
		if !ok || !expectDelim(';') {
			break
		}
		value, ok := readU16Str()
		if !ok || !expectDelim(';') {
			break
		}
		if pos+4 > n {
			break
		}
		rtype := binary.LittleEndian.Uint32(data[pos : pos+4])
		pos += 4
		if !expectDelim(';') || pos+4 > n {
			break
		}
		size := binary.LittleEndian.Uint32(data[pos : pos+4])
		pos += 4
		if !expectDelim(';') {
			break
		}
		if size > uint32(n-pos) {
			break
		}
		raw := data[pos : pos+int(size)]
		pos += int(size)
		expectDelim(']')

		cs.RegistryValues = append(cs.RegistryValues, RegistrySetting{
			Source: "registry.pol",
			Hive:   hive,
			Key:    key,
			Name:   value,
			Type:   regTypeNameNum(rtype),
			Value:  formatRegData(rtype, raw),
		})
	}
}

func startsWith(b, prefix []byte) bool {
	if len(b) < len(prefix) {
		return false
	}
	for i := range prefix {
		if b[i] != prefix[i] {
			return false
		}
	}
	return true
}

// REG_* type numbers.
const (
	regSZ       = 1
	regExpandSZ = 2
	regBinary   = 3
	regDWORD    = 4
	regDWORDBE  = 5
	regMultiSZ  = 7
	regQWORD    = 11
)

func regTypeNameNum(t uint32) string {
	switch t {
	case regSZ:
		return "REG_SZ"
	case regExpandSZ:
		return "REG_EXPAND_SZ"
	case regBinary:
		return "REG_BINARY"
	case regDWORD:
		return "REG_DWORD"
	case regDWORDBE:
		return "REG_DWORD_BIG_ENDIAN"
	case regMultiSZ:
		return "REG_MULTI_SZ"
	case regQWORD:
		return "REG_QWORD"
	default:
		return fmt.Sprintf("REG_TYPE_%d", t)
	}
}

// formatRegData renders raw value bytes per the registry type.
func formatRegData(t uint32, raw []byte) string {
	switch t {
	case regSZ, regExpandSZ:
		return strings.TrimRight(decodeUTF16Pairs(raw, false), "\x00")
	case regMultiSZ:
		parts := strings.Split(strings.TrimRight(decodeUTF16Pairs(raw, false), "\x00"), "\x00")
		var nonEmpty []string
		for _, p := range parts {
			if p != "" {
				nonEmpty = append(nonEmpty, p)
			}
		}
		return strings.Join(nonEmpty, ", ")
	case regDWORD:
		if len(raw) >= 4 {
			return fmt.Sprintf("%d", binary.LittleEndian.Uint32(raw))
		}
	case regDWORDBE:
		if len(raw) >= 4 {
			return fmt.Sprintf("%d", binary.BigEndian.Uint32(raw))
		}
	case regQWORD:
		if len(raw) >= 8 {
			return fmt.Sprintf("%d", binary.LittleEndian.Uint64(raw))
		}
	}
	return hex.EncodeToString(raw)
}
