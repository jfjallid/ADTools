package main

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

func TestEncodeSIDRoundtrip(t *testing.T) {
	cases := []string{
		"S-1-5-32-544",
		"S-1-5-18",
		"S-1-5-21-1004336348-1177238915-682003330-512",
	}
	for _, s := range cases {
		raw, err := encodeSID(s)
		if err != nil {
			t.Fatalf("encodeSID(%q): %v", s, err)
		}
		got, ok := decodeSID(raw)
		if !ok {
			t.Fatalf("decodeSID failed for %q (encoded: % x)", s, raw)
		}
		if got != s {
			t.Errorf("roundtrip mismatch: in=%q out=%q", s, got)
		}
	}
}

func TestEncodeRBCDRoundtrip(t *testing.T) {
	in := []string{
		"S-1-5-21-1004336348-1177238915-682003330-1106",
		"S-1-5-21-1004336348-1177238915-682003330-1107",
	}
	blob, err := encodeRBCD(in)
	if err != nil {
		t.Fatalf("encodeRBCD: %v", err)
	}
	out, err := decodeRBCD(blob)
	if err != nil {
		t.Fatalf("decodeRBCD: %v", err)
	}
	if !reflect.DeepEqual(out, in) {
		t.Errorf("roundtrip mismatch:\n  in: %v\n  out: %v", in, out)
	}
}

func TestDecodeRBCDEmpty(t *testing.T) {
	if _, err := decodeRBCD(nil); err == nil {
		t.Error("expected error for empty blob")
	}
	if _, err := decodeRBCD(make([]byte, 5)); err == nil {
		t.Error("expected error for short blob")
	}
}

func TestEncodeRBCDRequiresTrustee(t *testing.T) {
	if _, err := encodeRBCD(nil); err == nil {
		t.Error("expected error when no trustees supplied")
	}
}

func TestFormatRBCDDryRunHex(t *testing.T) {
	sid := "S-1-5-21-1004336348-1177238915-682003330-1107"
	blob, err := encodeRBCD([]string{sid})
	if err != nil {
		t.Fatalf("encodeRBCD: %v", err)
	}

	var buf bytes.Buffer
	dn := "CN=victim,CN=Computers,DC=corp,DC=local"
	formatRBCDDryRun(
		&buf,
		dn,
		"victim$", // sAMAccountName as the user might pass it
		[]string{"attacker"},
		[]string{sid},
		blob,
		[]string{sid},
	)
	got := buf.String()

	wantHex := hex.EncodeToString(blob)
	if !strings.Contains(got, wantHex) {
		t.Errorf("output missing raw hex string\n--- output ---\n%s\n--- want hex ---\n%s", got, wantHex)
	}
	// Self-relative SD with SE_DACL_PRESENT|SE_SELF_RELATIVE → control 0x8004,
	// little-endian after revision/sbz: 0x01 0x00 0x04 0x80.
	if !strings.Contains(got, "[byte[]]@(0x01,0x00,0x04,0x80") {
		t.Errorf("output missing PowerShell header prefix\n--- output ---\n%s", got)
	}
	if !strings.Contains(got, dn) {
		t.Errorf("output missing target DN\n--- output ---\n%s", got)
	}
	// -Identity should strip the trailing $ from the sAMAccountName.
	if !strings.Contains(got, "Set-ADComputer -Identity 'victim'") {
		t.Errorf("output missing Set-ADComputer line with stripped $\n--- output ---\n%s", got)
	}
}
