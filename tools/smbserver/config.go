package main

import (
	"fmt"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen      string         `yaml:"listen"`
	NetBIOS     NetBIOSConfig  `yaml:"netbios"`
	Dialects    DialectConfig  `yaml:"dialects"`
	Encryption  EncryptConfig  `yaml:"encryption"`
	Signing     SigningConfig  `yaml:"signing"`
	Sessions    SessionsConfig `yaml:"sessions"`
	Shares      []ShareConfig  `yaml:"shares"`
	Accounts    []AccountConfig `yaml:"accounts"`
	Credentials CredsConfig    `yaml:"credentials"`
	IPWhitelist []string       `yaml:"ip_whitelist"`
}

type NetBIOSConfig struct {
	Name      string `yaml:"name"`
	Domain    string `yaml:"domain"`
	DnsName   string `yaml:"dns_name"`
	DnsDomain string `yaml:"dns_domain"`
}

type DialectConfig struct {
	Min string `yaml:"min"`
	Max string `yaml:"max"`
}

type EncryptConfig struct {
	Supported bool `yaml:"supported"`
	Required  bool `yaml:"required"`
}

type SigningConfig struct {
	Required bool `yaml:"required"`
}

type SessionsConfig struct {
	AllowGuest     bool `yaml:"allow_guest"`
	AllowAnonymous bool `yaml:"allow_anonymous"`
}

type ShareConfig struct {
	Name                string   `yaml:"name"`
	Backend             string   `yaml:"backend"` // "disk" | "memory"
	Path                string   `yaml:"path"`
	ReadOnly            bool     `yaml:"readonly"`
	Encrypt             bool     `yaml:"encrypt"`
	WritableUsers       []string `yaml:"writable_users"`
	AllowAnonymousWrite bool     `yaml:"allow_anonymous_write"`
	AllowGuestWrite     bool     `yaml:"allow_guest_write"`
}

type AccountConfig struct {
	User     string `yaml:"user"`
	Domain   string `yaml:"domain"`
	Password string `yaml:"password"`
	NTHash   string `yaml:"nthash"`
}

type CredsConfig struct {
	Dump    bool   `yaml:"dump"`
	LogFile string `yaml:"log_file"`
}

func defaultConfig() Config {
	return Config{
		Listen: ":445",
		NetBIOS: NetBIOSConfig{
			Name:   "GO-SMB",
			Domain: "WORKGROUP",
		},
		Dialects: DialectConfig{
			Min: "2.0.2",
			Max: "3.1.1",
		},
		Encryption: EncryptConfig{
			Supported: true,
		},
	}
}

func loadYAML(path string, cfg *Config) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	return nil
}

func (c *Config) Validate() error {
	if c.Listen == "" {
		return fmt.Errorf("listen address is empty")
	}
	if _, err := dialectFromString(c.Dialects.Min); err != nil {
		return fmt.Errorf("min-dialect: %w", err)
	}
	if _, err := dialectFromString(c.Dialects.Max); err != nil {
		return fmt.Errorf("max-dialect: %w", err)
	}
	for i, s := range c.Shares {
		if err := s.Validate(); err != nil {
			return fmt.Errorf("share[%d] (%q): %w", i, s.Name, err)
		}
	}
	names := map[string]bool{}
	for _, s := range c.Shares {
		k := strings.ToLower(s.Name)
		if names[k] {
			return fmt.Errorf("duplicate share name %q", s.Name)
		}
		names[k] = true
	}
	for i, a := range c.Accounts {
		if err := a.Validate(); err != nil {
			return fmt.Errorf("account[%d] (%q): %w", i, a.User, err)
		}
	}
	for _, r := range c.IPWhitelist {
		if _, err := parseIPRule(r); err != nil {
			return fmt.Errorf("ip_whitelist %q: %w", r, err)
		}
	}
	if !c.Sessions.AllowGuest && !c.Sessions.AllowAnonymous && len(c.Accounts) == 0 {
		if !c.Credentials.Dump {
			return fmt.Errorf("cannot run a server without any access configured unless running with credentials capture")
		}
		log.Warning("Running server without any accounts, guest or anonymous access enabled!")
	}
	return nil
}

func parseIPRule(s string) (*net.IPNet, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty rule")
	}
	if strings.Contains(s, "/") {
		_, n, err := net.ParseCIDR(s)
		return n, err
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("not a valid IP or CIDR")
	}
	bits := 32
	if ip.To4() == nil {
		bits = 128
	}
	mask := net.CIDRMask(bits, bits)
	return &net.IPNet{IP: ip.Mask(mask), Mask: mask}, nil
}
