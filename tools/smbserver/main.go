package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	rundebug "runtime/debug"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/jfjallid/golog"

	srvsvcsrv "github.com/jfjallid/go-smb/dcerpc/mssrvs/server"
	dcserver "github.com/jfjallid/go-smb/dcerpc/server"
	"github.com/jfjallid/go-smb/smb/server"
)

var (
	log            = golog.Get("main")
	release string = "0.1.0"
)

var helpMsg = `
    Usage: ` + os.Args[0] + ` [options]

    options:
          --config <path>         YAML config file (CLI flags override any field)
      -b, --bind <addr>           Listen address (default :445)

      SMB protocol:
          --min-dialect <ver>     2.0.2 | 2.1 | 3.0 | 3.0.2 | 3.1.1 (default 2.0.2)
          --max-dialect <ver>     ... (default 3.1.1)
          --no-encryption         Disable SMB 3.x encryption capability (default: advertised)
          --require-encryption    Force every session into encrypted mode (only applies to smb 3.1.1)
          --require-signing       Advertise signing required
          --netbios-name <name>   Advertised NetBIOS server name (default GO-SMB)
          --netbios-domain <name> Advertised NetBIOS domain (default WORKGROUP)
          --dns-name <fqdn>       Advertised DNS computer name
          --dns-domain <name>     Advertised DNS domain name
          --ntlm-challenge <hex>  Hardcode the server's ntlm challenge

      Sessions:
          --allow-guest           Permit guest sessions on auth failure
          --allow-anonymous       Permit null sessions

      Shares (repeatable):
          --share <spec>          name=Public,backend=disk,path=/srv/pub,readonly=true,encrypt=false
                                  or name=Drop,backend=memory

      Accounts (repeatable):
          --account <spec>        user=alice,domain=WORKGROUP,password=secret
                                  or user=alice,nthash=<32-hex>

      Credential dumping:
          --dump-creds            Log every captured NTLM AUTH (Net-NTLMv2 hashcat)
          --cred-log <path>       Append hashcat lines to file (mode 0600)

      IP whitelist (repeatable):
          --allow-ip <cidr>       Whitelist CIDR or IP. If any --allow-ip is set,
                                  others are silently dropped via OnConnect.

      Diagnostics:
          --debug                 Debug logging. Bare --debug turns on every registered
                                  package; --debug=smb,server turns on only the listed
                                  package-name suffixes (the '=' form is required for the filter).
          --verbose               Verbose logging (info). Same filter syntax as --debug.
                                  --debug and --verbose may be combined with different filters;
                                  a package targeted by both gets the higher level.
          --list-log-packages     List the registered log package names that can be targeted
                                  with --debug=<suffix> or --verbose=<suffix>, then exit
      -v, --version               Show version
`

type repeatable struct{ values []string }

func (r *repeatable) String() string     { return strings.Join(r.values, ";") }
func (r *repeatable) Set(v string) error { r.values = append(r.values, v); return nil }

// logFlag is a comma-separated package-suffix filter that also remembers
// whether the user passed the flag at all. IsBoolFlag is set so the bare
// "--debug" and "--verbose" form parses (the flag pkg then calls Set("true"))
// — we treat "true" as "no filter, all packages on". A filter list requires
// the "=" form, e.g. --debug=smb,server, because IsBoolFlag stops the parser
// from consuming the next positional token.
type logFlag struct {
	set    bool
	values []string
}

func (d *logFlag) String() string { return strings.Join(d.values, ",") }

func (d *logFlag) IsBoolFlag() bool { return true }

func (d *logFlag) Set(s string) error {
	d.set = true
	d.values = nil
	if s == "" || s == "true" {
		return nil
	}
	for _, tok := range strings.Split(s, ",") {
		if tok = strings.TrimSpace(tok); tok != "" {
			d.values = append(d.values, tok)
		}
	}
	return nil
}

type cliFlags struct {
	configPath, bind                                string
	minDialect, maxDialect                          string
	noEncryption, requireEncryption, requireSigning bool
	netbiosName, netbiosDomain, dnsName, dnsDomain  string
	allowGuest, allowAnonymous                      bool
	shares, accounts, allowIPs                      repeatable
	dumpCreds                                       bool
	credLog, ntlmChallenge                          string
	debug, verbose                                  logFlag
	version, listLog                                bool
	set                                             map[string]bool // map of which flags have been explicitly set
}

func parseCLI() *cliFlags {
	cli := &cliFlags{}

	flag.Usage = func() { fmt.Println(helpMsg); os.Exit(0) }

	flag.StringVar(&cli.configPath, "config", "", "")
	flag.StringVar(&cli.bind, "b", ":445", "")
	flag.StringVar(&cli.bind, "bind", ":445", "")
	flag.StringVar(&cli.minDialect, "min-dialect", "2.0.2", "")
	flag.StringVar(&cli.maxDialect, "max-dialect", "3.1.1", "")
	flag.BoolVar(&cli.noEncryption, "no-encryption", false, "")
	flag.BoolVar(&cli.requireEncryption, "require-encryption", false, "")
	flag.BoolVar(&cli.requireSigning, "require-signing", false, "")
	flag.StringVar(&cli.netbiosName, "netbios-name", "GO-SMB", "")
	flag.StringVar(&cli.netbiosDomain, "netbios-domain", "WORKGROUP", "")
	flag.StringVar(&cli.dnsName, "dns-name", "", "")
	flag.StringVar(&cli.dnsDomain, "dns-domain", "", "")
	flag.BoolVar(&cli.allowGuest, "allow-guest", false, "")
	flag.BoolVar(&cli.allowAnonymous, "allow-anonymous", false, "")
	flag.Var(&cli.shares, "share", "")
	flag.Var(&cli.accounts, "account", "")
	flag.Var(&cli.allowIPs, "allow-ip", "")
	flag.BoolVar(&cli.dumpCreds, "dump-creds", false, "")
	flag.StringVar(&cli.credLog, "cred-log", "", "")
	flag.Var(&cli.debug, "debug", "")
	flag.Var(&cli.verbose, "verbose", "")
	flag.BoolVar(&cli.listLog, "list-log-packages", false, "")
	flag.BoolVar(&cli.version, "v", false, "")
	flag.BoolVar(&cli.version, "version", false, "")
	flag.StringVar(&cli.ntlmChallenge, "ntlm-challenge", "", "")

	flag.Parse()

	cli.set = make(map[string]bool, flag.NFlag())
	flag.Visit(func(f *flag.Flag) { cli.set[f.Name] = true })
	return cli
}

func anySet(set map[string]bool, names ...string) bool {
	for _, n := range names {
		if set[n] {
			return true
		}
	}
	return false
}

// applyTo overlays the explicitly-set CLI flags onto cfg. List flags
// (--share, --account, --allow-ip) replace the config list when supplied.
func (cli *cliFlags) applyTo(cfg *Config) error {
	if anySet(cli.set, "b", "bind") {
		cfg.Listen = cli.bind
	}
	if cli.set["min-dialect"] {
		cfg.Dialects.Min = cli.minDialect
	}
	if cli.set["max-dialect"] {
		cfg.Dialects.Max = cli.maxDialect
	}
	if cli.set["no-encryption"] && cli.noEncryption {
		cfg.Encryption.Supported = false
	}
	if cli.set["require-encryption"] {
		cfg.Encryption.Required = cli.requireEncryption
		if cli.requireEncryption {
			cfg.Encryption.Supported = true
		}
	}
	if cli.set["require-signing"] {
		cfg.Signing.Required = cli.requireSigning
	}
	if cli.set["netbios-name"] {
		cfg.NetBIOS.Name = cli.netbiosName
	}
	if cli.set["netbios-domain"] {
		cfg.NetBIOS.Domain = cli.netbiosDomain
	}
	if cli.set["dns-name"] {
		cfg.NetBIOS.DnsName = cli.dnsName
	}
	if cli.set["dns-domain"] {
		cfg.NetBIOS.DnsDomain = cli.dnsDomain
	}
	if cli.set["allow-guest"] {
		cfg.Sessions.AllowGuest = cli.allowGuest
	}
	if cli.set["allow-anonymous"] {
		cfg.Sessions.AllowAnonymous = cli.allowAnonymous
	}
	if cli.set["dump-creds"] {
		cfg.Credentials.Dump = cli.dumpCreds
	}
	if cli.set["cred-log"] {
		cfg.Credentials.LogFile = cli.credLog
	}

	if len(cli.shares.values) > 0 {
		cfg.Shares = cfg.Shares[:0]
		for _, s := range cli.shares.values {
			sc, err := parseShareSpec(s)
			if err != nil {
				return fmt.Errorf("--share %q: %w", s, err)
			}
			log.Debugf("Share config: %+v\n", sc)
			cfg.Shares = append(cfg.Shares, sc)
		}
	}
	if len(cli.accounts.values) > 0 {
		cfg.Accounts = cfg.Accounts[:0]
		for _, s := range cli.accounts.values {
			ac, err := parseAccountSpec(s)
			if err != nil {
				return fmt.Errorf("--account %q: %w", s, err)
			}
			cfg.Accounts = append(cfg.Accounts, ac)
		}
	}
	if len(cli.allowIPs.values) > 0 {
		cfg.IPWhitelist = append(cfg.IPWhitelist[:0], cli.allowIPs.values...)
	}
	return nil
}

// applyLogLevel bumps registered package loggers to level. An empty filter
// matches every name returned by golog.Names(); a non-empty filter keeps only
// names whose path suffix matches one of the tokens (see matchesAny).
func applyLogLevel(level int, filter []string) {
	flags := golog.LstdFlags | golog.Lshortfile
	for _, name := range golog.Names() {
		if len(filter) == 0 || matchesAny(name, filter) {
			golog.Set(name, "", level, flags, nil, nil)
		}
	}
}

// matchesAny reports whether name equals any token or ends with "/"+token,
// so "smb" hits ".../go-smb/smb" but not ".../go-smb" (ends in "/go-smb",
// not "/smb") and not ".../smb/server" (ends in "/server").
func matchesAny(name string, tokens []string) bool {
	for _, t := range tokens {
		if name == t || strings.HasSuffix(name, "/"+t) {
			return true
		}
	}
	return false
}

// listLogPackages prints every registered log package name. The package
// loggers register themselves at import time, so golog.Names() here lists
// every logger this binary can target; the suffix of any of these names is
// what --debug=/--verbose= matches.
func listLogPackages() {
	names := golog.Names()
	sort.Strings(names)
	fmt.Println("Registered log packages (target a name's suffix with --debug=<suffix> or --verbose=<suffix>):")
	for _, name := range names {
		fmt.Println(name)
	}
}

// configureLogging applies the --debug / --verbose filters. The two are not
// mutually exclusive: each may carry its own comma-separated package filter
// (e.g. --debug=smb,server --verbose=main). Verbose is applied first and debug
// second so any package targeted by both ends up at the higher level
// (LevelDebug > LevelInfo). A bare --debug or --verbose (empty filter) targets
// every registered package, so passing both bare is ambiguous and rejected.
func configureLogging(debug, verbose logFlag) bool {
	if debug.set && verbose.set && len(debug.values) == 0 && len(verbose.values) == 0 {
		fmt.Println("Cannot enable both --debug and --verbose for all packages at once. Specify just one of them, or be more granular e.g. --debug=smb,server --verbose=main")
		return false
	}
	if verbose.set {
		applyLogLevel(golog.LevelInfo, verbose.values)
	}
	if debug.set {
		applyLogLevel(golog.LevelDebug, debug.values)
	}
	return true
}

func openCredLog(path string) (io.WriteCloser, error) {
	if path == "" {
		return nil, nil
	}
	return os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
}

func buildServerConfig(cfg *Config) (*server.ServerConfig, io.Closer, error) {
	minD, err := dialectFromString(cfg.Dialects.Min)
	if err != nil {
		return nil, nil, err
	}
	maxD, err := dialectFromString(cfg.Dialects.Max)
	if err != nil {
		return nil, nil, err
	}
	if minD > maxD {
		return nil, nil, fmt.Errorf("min-dialect (%s, 0x%04x) > max-dialect (%s, 0x%04x)",
			cfg.Dialects.Min, minD, cfg.Dialects.Max, maxD)
	}

	shares, err := buildShares(cfg.Shares)
	if err != nil {
		return nil, nil, err
	}

	auther, err := buildAuthenticator(cfg.Accounts, cfg.NetBIOS.Domain)
	if err != nil {
		return nil, nil, err
	}

	rules := make([]*net.IPNet, 0, len(cfg.IPWhitelist))
	for _, s := range cfg.IPWhitelist {
		n, err := parseIPRule(s)
		if err != nil {
			return nil, nil, fmt.Errorf("ip_whitelist %q: %w", s, err)
		}
		rules = append(rules, n)
	}

	credFile, err := openCredLog(cfg.Credentials.LogFile)
	if err != nil {
		return nil, nil, fmt.Errorf("cred-log: %w", err)
	}

	sc := &server.ServerConfig{
		ServerGUID:          [16]byte{},
		NetBIOSName:         cfg.NetBIOS.Name,
		NetBIOSDomain:       cfg.NetBIOS.Domain,
		DnsComputerName:     cfg.NetBIOS.DnsName,
		DnsDomainName:       cfg.NetBIOS.DnsDomain,
		MinDialect:          minD,
		MaxDialect:          maxD,
		EncryptionSupported: cfg.Encryption.Supported,
		RequireEncryption:   cfg.Encryption.Required,
		SigningRequired:     cfg.Signing.Required,
		Shares:              shares,
		Authenticator:       &loggingAuth{inner: auther},
		AllowGuest:          cfg.Sessions.AllowGuest,
		AllowAnonymous:      cfg.Sessions.AllowAnonymous,
		OnConnect:           ipWhitelistHook(rules),
	}

	if cfg.Credentials.Dump {
		var fw io.Writer
		if credFile != nil {
			fw = credFile
		}
		sc.OnCredentialCaptured = credDumpHook(fw)
	}

	srvsvc := &srvsvcsrv.Service{
		ServerName: sc.NetBIOSName,
		Shares:     srvsvcsrv.FromConfig(sc),
	}
	sc.PipeOpener = &server.MapPipeOpener{
		Pipes: map[string]func(*server.Session) (server.PipeBackend, error){
			"srvsvc": func(_ *server.Session) (server.PipeBackend, error) {
				return dcserver.NewPipeHandler("srvsvc", srvsvc), nil
			},
		},
	}

	return sc, credFile, nil
}

func main() {
	var err error
	cli := parseCLI()

	if cli.listLog {
		listLogPackages()
		return
	}

	if !configureLogging(cli.debug, cli.verbose) {
		return
	}

	if cli.version {
		fmt.Printf("Version: %s\n", release)
		bi, ok := rundebug.ReadBuildInfo()
		if ok {
			for _, m := range bi.Deps {
				fmt.Printf("Package: %s, Version: %s\n", m.Path, m.Version)
			}
		}
		return
	}

	cfg := defaultConfig()
	if cli.configPath != "" {
		if err := loadYAML(cli.configPath, &cfg); err != nil {
			log.Errorf("[!] %s", err)
			os.Exit(1)
		}
	}
	var ntlmServerChallenge []byte
	if cli.ntlmChallenge != "" {
		ntlmServerChallenge, err =  hex.DecodeString(cli.ntlmChallenge)
		if err != nil {
			log.Errorf("invalid --ntlm-challenge: %s\n", err)
			return
		}

	}
	//Override any values set in config file with values from cli arguments
	if err := cli.applyTo(&cfg); err != nil {
		log.Errorf("[!] %s", err)
		os.Exit(1)
	}
	if err := cfg.Validate(); err != nil {
		log.Errorf("[!] %s", err)
		os.Exit(1)
	}

	sCfg, credFile, err := buildServerConfig(&cfg)
	if err != nil {
		log.Errorf("[!] %s", err)
		os.Exit(1)
	}
	if ntlmServerChallenge != nil {
		sCfg.OnSessionSetup = func(c *server.Conn, s *server.Session, blob []byte, stage server.SessionSetupStage) (*server.Status, error) {
    	    if stage == server.SessionSetupStageNegotiate && s.NTLMServer != nil {
    	        // Set a deterministic challenge before AcceptSecContext runs.
    	        // ntlmssp.Server.AcceptNegotiate keeps this value (skips its
    	        // random fill) because it's non-zero.
				copy(s.NTLMServer.Challenge[:], ntlmServerChallenge)
    	    }
    	    return nil, nil // fall through to default handler
    	}
	}

	defer func() {
		if credFile != nil {
			credFile.Close()
		}
	}()

	srv := &server.Server{Config: sCfg}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe(cfg.Listen) }()

	log.Noticef("[*] smbserver listening on %s (dialects %s..%s, encryption=%v required=%v, guest=%v anon=%v)",
		cfg.Listen, cfg.Dialects.Min, cfg.Dialects.Max,
		cfg.Encryption.Supported, cfg.Encryption.Required,
		cfg.Sessions.AllowGuest, cfg.Sessions.AllowAnonymous)
	for _, sh := range sCfg.Shares {
		log.Noticef("[*]   share %s", sh.Name)
	}

	select {
	case sig := <-stop:
		log.Noticef("[*] received %s, shutting down", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Errorf("[!] shutdown: %v", err)
			os.Exit(1)
		}
	case err := <-errCh:
		if err != nil && err != server.ErrServerClosed {
			log.Errorf("[!] listen: %v", err)
			os.Exit(1)
		}
	}
}
