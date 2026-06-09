package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"unicode/utf16"
)

// TestGPPAESKeyMatchesPublishedValue guards against a typo in the key array by
// comparing it to the canonical MS14-025 hex string.
func TestGPPAESKeyMatchesPublishedValue(t *testing.T) {
	want, _ := hex.DecodeString("4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b")
	if len(gppAESKey) != 32 {
		t.Fatalf("AES-256 key must be 32 bytes, got %d", len(gppAESKey))
	}
	if string(gppAESKey) != string(want) {
		t.Errorf("gppAESKey does not match the published MS14-025 key")
	}
}

// encryptGPP mirrors how Windows produces a cpassword: PKCS#7-padded UTF-16LE
// plaintext, AES-256-CBC with a zero IV, base64 with the padding stripped.
func encryptGPP(t *testing.T, plaintext string) string {
	t.Helper()
	var pt []byte
	for _, u := range utf16.Encode([]rune(plaintext)) {
		pt = append(pt, byte(u), byte(u>>8))
	}
	block, err := aes.NewCipher(gppAESKey)
	if err != nil {
		t.Fatal(err)
	}
	pad := block.BlockSize() - len(pt)%block.BlockSize()
	for range pad {
		pt = append(pt, byte(pad))
	}
	ct := make([]byte, len(pt))
	cipher.NewCBCEncrypter(block, make([]byte, block.BlockSize())).CryptBlocks(ct, pt)
	return strings.TrimRight(base64.StdEncoding.EncodeToString(ct), "=")
}

func TestDecryptGPPPasswordRoundTrip(t *testing.T) {
	for _, pw := range []string{"P@ssw0rd!", "Sup3r$ecret", "a", "Local*ish admin pw 2026"} {
		blob := encryptGPP(t, pw)
		got, err := decryptGPPPassword(blob)
		if err != nil {
			t.Fatalf("decrypt(%q) error: %v", pw, err)
		}
		if got != pw {
			t.Errorf("round-trip mismatch: got %q want %q", got, pw)
		}
	}
}

func TestDecryptGPPPasswordErrors(t *testing.T) {
	if _, err := decryptGPPPassword(""); err == nil {
		t.Error("expected error for empty cpassword")
	}
	if _, err := decryptGPPPassword("!!!not base64!!!"); err == nil {
		t.Error("expected error for invalid base64")
	}
}

func TestParseGPPServiceCPassword(t *testing.T) {
	blob := encryptGPP(t, "ServiceSecret1")
	xml := `<NTServices clsid="{1}"><NTService clsid="{2}"><Properties serviceName="svc" accountName="CORP\svc" cpassword="` + blob + `" startupType="AUTOMATIC"/></NTService></NTServices>`
	var cs ConfigSettings
	parseGPPServices([]byte(xml), &cs)
	if len(cs.Services) != 1 || cs.Services[0].CPassword != blob {
		t.Fatalf("service cpassword not captured: %+v", cs.Services)
	}
	got := analyseGPPPassword(nil, "Computer", &cs, nil)
	if !hasSeverity(got, "gpp-cpassword", SevCritical) {
		t.Fatalf("expected Critical gpp-cpassword finding, got %+v", got)
	}
	if !strings.Contains(got[0].Detail, "ServiceSecret1") {
		t.Errorf("finding should contain the recovered password: %q", got[0].Detail)
	}
}

func TestParseGPPLocalUserCPassword(t *testing.T) {
	blob := encryptGPP(t, "LocalAdminPw")
	xml := `<Groups clsid="{1}"><User clsid="{2}" name="Administrator (built-in)"><Properties action="U" userName="Administrator" cpassword="` + blob + `"/></User></Groups>`
	var cs ConfigSettings
	parseGPPLocalUsers([]byte(xml), &cs)
	if len(cs.LocalUsers) != 1 || cs.LocalUsers[0].CPassword != blob {
		t.Fatalf("local user cpassword not captured: %+v", cs.LocalUsers)
	}
	got := analyseGPPPassword(nil, "Computer", &cs, nil)
	if len(got) != 1 || got[0].Severity != SevCritical || !strings.Contains(got[0].Detail, "LocalAdminPw") {
		t.Fatalf("expected Critical finding with recovered password, got %+v", got)
	}
}
