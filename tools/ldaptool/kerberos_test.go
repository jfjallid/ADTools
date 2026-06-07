package main

import (
	"strings"
	"testing"
)

func TestKDCRealmsForDCIP(t *testing.T) {
	cases := []struct {
		name        string
		clientRealm string
		host        string
		want        []string
	}{
		{
			// The reported bug: --domain is the NetBIOS short name, so the
			// client realm ("MYDOMAIN") differs from the realm gokrb5 derives
			// from the host FQDN ("MYDOMAIN.TLD"). Both must be registered.
			name:        "short-name domain vs fqdn host",
			clientRealm: "MYDOMAIN",
			host:        "dc01.mydomain.tld",
			want:        []string{"MYDOMAIN", "MYDOMAIN.TLD"},
		},
		{
			// Client realm already matches the host suffix: collapse to one.
			name:        "fqdn domain matches host suffix",
			clientRealm: "CORP.LOCAL",
			host:        "dc.corp.local",
			want:        []string{"CORP.LOCAL"},
		},
		{
			name:        "lowercase client realm is uppercased",
			clientRealm: "corp.local",
			host:        "dc.corp.local",
			want:        []string{"CORP.LOCAL"},
		},
		{
			name:        "host carries a port",
			clientRealm: "MYDOMAIN",
			host:        "dc01.mydomain.tld:389",
			want:        []string{"MYDOMAIN", "MYDOMAIN.TLD"},
		},
		{
			name:        "host is a bare IP, no suffix realm",
			clientRealm: "CORP.LOCAL",
			host:        "10.0.0.1",
			want:        []string{"CORP.LOCAL"},
		},
		{
			name:        "host is a single label, no suffix realm",
			clientRealm: "CORP.LOCAL",
			host:        "dc01",
			want:        []string{"CORP.LOCAL"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := kdcRealmsForDCIP(c.clientRealm, c.host)
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Errorf("kdcRealmsForDCIP(%q, %q) = %v, want %v",
					c.clientRealm, c.host, got, c.want)
			}
		})
	}
}
