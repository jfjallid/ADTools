package main

import (
	"strings"
	"testing"
)

func TestDecodeUAC(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// 0x200 = NORMAL_ACCOUNT
		{"512", "512 (0x200): NORMAL_ACCOUNT"},
		// 0x202 = NORMAL_ACCOUNT|ACCOUNTDISABLE
		{"514", "514 (0x202): ACCOUNTDISABLE|NORMAL_ACCOUNT"},
		// workstation trust
		{"4096", "4096 (0x1000): WORKSTATION_TRUST_ACCOUNT"},
		// 66048 = NORMAL_ACCOUNT|DONT_EXPIRE_PASSWORD
		{"66048", "66048 (0x10200): NORMAL_ACCOUNT|DONT_EXPIRE_PASSWORD"},
	}
	for _, c := range cases {
		got := decodeUAC(c.in)
		if got != c.want {
			t.Errorf("decodeUAC(%q): got %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDecodeGroupType(t *testing.T) {
	cases := []struct {
		in     string
		expect []string // substrings that must be present
	}{
		{"-2147483646", []string{"GLOBAL", "SECURITY"}}, // 0x80000002
		{"-2147483644", []string{"DOMAIN_LOCAL", "SECURITY"}},
		{"8", []string{"UNIVERSAL", "DISTRIBUTION"}},
	}
	for _, c := range cases {
		got := decodeGroupType(c.in)
		for _, sub := range c.expect {
			if !strings.Contains(got, sub) {
				t.Errorf("decodeGroupType(%q) = %q; missing %q", c.in, got, sub)
			}
		}
	}
}

func TestDecodePrimaryGroupID(t *testing.T) {
	if got := decodePrimaryGroupID("513"); !strings.Contains(got, "Domain Users") {
		t.Errorf("decodePrimaryGroupID(513) = %q; want Domain Users", got)
	}
	if got := decodePrimaryGroupID("515"); !strings.Contains(got, "Domain Computers") {
		t.Errorf("decodePrimaryGroupID(515) = %q; want Domain Computers", got)
	}
	if got := decodePrimaryGroupID("9999"); got != "9999" {
		t.Errorf("decodePrimaryGroupID(9999) = %q; want passthrough %q", got, "9999")
	}
}

func TestLDIFSafe(t *testing.T) {
	cases := []struct {
		in   string
		safe bool
	}{
		{"alice", true},
		{"", true},
		{" leading-space", false},
		{":starts-with-colon", false},
		{"<starts-with-lt", false},
		{"trailing-space ", false},
		{"embedded\nnewline", false},
		{"non-ascii-\xff", false},
		{"cn=Foo,DC=example,DC=com", true},
	}
	for _, c := range cases {
		if got := ldifSafe([]byte(c.in)); got != c.safe {
			t.Errorf("ldifSafe(%q) = %v; want %v", c.in, got, c.safe)
		}
	}
}

func TestParseScope(t *testing.T) {
	cases := []struct {
		in   string
		want int
		err  bool
	}{
		{"base", 0, false},
		{"one", 1, false},
		{"onelevel", 1, false},
		{"sub", 2, false},
		{"subtree", 2, false},
		{"", 2, false},
		{"invalid", 0, true},
	}
	for _, c := range cases {
		got, err := parseScope(c.in)
		if c.err {
			if err == nil {
				t.Errorf("parseScope(%q): expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseScope(%q): unexpected error %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseScope(%q) = %d; want %d", c.in, got, c.want)
		}
	}
}

func TestSplitRangedAttr(t *testing.T) {
	cases := []struct {
		in       string
		base, rg string
		ok       bool
	}{
		{"member;range=0-1499", "member", "0-1499", true},
		{"member;range=1500-*", "member", "1500-*", true},
		{"member;Range=0-*", "member", "0-*", true},
		{"member", "", "", false},
		{"cn", "", "", false},
	}
	for _, c := range cases {
		base, rg, ok := splitRangedAttr(c.in)
		if ok != c.ok || base != c.base || rg != c.rg {
			t.Errorf("splitRangedAttr(%q) = (%q, %q, %v); want (%q, %q, %v)",
				c.in, base, rg, ok, c.base, c.rg, c.ok)
		}
	}
}
