package main

import (
	"reflect"
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
