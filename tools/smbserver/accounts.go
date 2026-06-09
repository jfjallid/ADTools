package main

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb/server"
)

func (a AccountConfig) Validate() error {
	if a.User == "" {
		return fmt.Errorf("user is required")
	}
	hasPw := a.Password != ""
	hasHash := a.NTHash != ""
	if hasPw == hasHash {
		return fmt.Errorf("exactly one of password/nthash must be set")
	}
	if hasHash {
		h := strings.TrimSpace(a.NTHash)
		if len(h) != 32 {
			return fmt.Errorf("nthash must be 32 hex chars (got %d)", len(h))
		}
		if _, err := hex.DecodeString(h); err != nil {
			return fmt.Errorf("nthash hex decode: %w", err)
		}
	}
	return nil
}

// nthashOf returns the 16-byte NT hash for the account.
func (a AccountConfig) nthashOf() ([]byte, error) {
	if a.NTHash != "" {
		return hex.DecodeString(strings.TrimSpace(a.NTHash))
	}
	return ntlmssp.Ntowfv1(a.Password), nil
}

// buildAuthenticator groups accounts by domain into one MapAuthenticator. The
// server.MapAuthenticator only supports a single Domain, so we pick the
// domain of the first account and require all other accounts to share it (or
// have an empty domain, which is treated as the chosen domain).
func buildAuthenticator(specs []AccountConfig, fallbackDomain string) (*server.MapAuthenticator, error) {
	if len(specs) == 0 {
		return &server.MapAuthenticator{Domain: fallbackDomain, Accounts: map[string]*server.Account{}}, nil
	}
	domain := ""
	for _, a := range specs {
		if a.Domain != "" {
			domain = a.Domain
			break
		}
	}
	if domain == "" {
		domain = fallbackDomain
	}
	acctMap := make(map[string]*server.Account, len(specs))
	for _, a := range specs {
		if a.Domain != "" && !strings.EqualFold(a.Domain, domain) {
			return nil, fmt.Errorf("account %q domain=%q conflicts with %q (MapAuthenticator supports a single domain)", a.User, a.Domain, domain)
		}
		hash, err := a.nthashOf()
		if err != nil {
			return nil, fmt.Errorf("account %q: %w", a.User, err)
		}
		acctMap[strings.ToLower(a.User)] = &server.Account{NTHash: hash}
	}
	return &server.MapAuthenticator{Domain: domain, Accounts: acctMap}, nil
}

// parseAccountSpec parses a CLI --account value:
// "user=alice,domain=WORKGROUP,password=secret" OR "user=alice,nthash=<hex>".
func parseAccountSpec(s string) (AccountConfig, error) {
	var a AccountConfig
	kv, err := parseKVList(s)
	if err != nil {
		return a, err
	}
	for k, v := range kv {
		switch k {
		case "user":
			a.User = v
		case "domain":
			a.Domain = v
		case "password":
			a.Password = v
		case "nthash":
			a.NTHash = v
		default:
			return a, fmt.Errorf("unknown account key %q", k)
		}
	}
	return a, nil
}
