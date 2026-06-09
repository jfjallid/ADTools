// gpoparser extracts and analyses the configuration applied through Active
// Directory Group Policy Objects: what each GPO does (local-group membership,
// privilege rights, registry changes, scripts, scheduled tasks, services) and
// where it applies (which OUs and computers, via gPLink inheritance).
//
// It mirrors the functionality of github.com/synacktiv/gpoParser but adds the
// extended authentication and connection options shared by the rest of the
// adtools suite (ldaptool / go-rpcclient): full Kerberos/NTLM/PtH/AES, LDAPS,
// StartTLS, channel binding, SASL signing/sealing, SOCKS5 and DNS override.
package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	rundebug "runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jfjallid/gokrb5/v9/client"
	krbconfig "github.com/jfjallid/gokrb5/v9/config"
	"github.com/jfjallid/gokrb5/v9/credentials"
	"github.com/jfjallid/gokrb5/v9/keytab"
	"github.com/jfjallid/golog"
	ldap "github.com/jfjallid/ldap/v3"
	"github.com/jfjallid/ldap/v3/gssapi"
	"golang.org/x/net/proxy"
	"golang.org/x/term"
)

var logger = golog.Get("main")
var release string = "0.1.0"
var keyLogFile *os.File

var helpConnectionOptions = `
    Connection options (remote mode):
          --host                 DC hostname or IP (required; hostname for Kerberos)
      -P, --port                 LDAP port (default 389, or 636 with --tls)
          --tls                  Use LDAPS (implicit TLS)
          --starttls             Use StartTLS on plain LDAP port
          --insecure             Skip TLS certificate verification
          --base-dn              Search base DN (auto-detected if omitted)
          --sasl                 SASL security: none, sign, seal
          --channel              Enable TLS channel binding
          --smb-port             SMB port for SYSVOL (default 445)
          --noenc                Disable SMB encryption when reading SYSVOL
      -t, --timeout              Dial timeout (e.g. 5s, 1m; default 5s)
          --socks-host           SOCKS5 proxy host
          --socks-port           SOCKS5 proxy port (default 1080)

    Authentication (NTLM unless --simple/--anonymous/--kerberos):
      -d, --domain               AD domain (e.g. CORP)
      -u, --user                 Username (or full DN with --simple)
      -p, --pass                 Password (bare -p prompts on terminal)
          --hash                 NT hash (pass-the-hash / Kerberos RC4)
      -n, --no-pass              Send no password (unauthenticated bind)
          --simple               LDAP simple bind (DN/password)
          --anonymous            LDAP simple anonymous bind (no creds)

    Kerberos (with -k/--kerberos):
      -k, --kerberos             Use Kerberos (GSSAPI) instead of NTLM
          --keytab-file <file>   Authenticate with a Kerberos keytab (implies -k; principal and
                                 realm are read from the keytab when --user/--domain are omitted)
          --ccache               Kerberos credential cache file (falls back to $KRB5CCNAME)
          --krb5conf             Path to krb5.conf (default: /etc/krb5.conf)
          --realm                Kerberos realm (defaults to upper-cased --domain)
          --aes-key              Hex AES128/256 key
          --override-spn         LDAP service principal name (default: ldap/<host>)
          --dc-ip <ip[:port]>    KDC address override (default port 88)
          --target-ip <ip>       IP to connect to; skips DNS of --host
          --dns-host <ip[:port]> Override system's default DNS resolver (default port 53)
          --dns-tcp              Force DNS lookups over TCP

    Diagnostics:
          --debug                Enable debug logging. Bare --debug turns on every registered
                                 package; --debug=smb,ldap turns on only the listed package-name
                                 suffixes (the '=' form is required for the filter).
          --verbose              Enable verbose logging. Same filter syntax as --debug. --debug
                                 and --verbose may be combined with different filters; a package
                                 targeted by both gets the higher level.
          --list-log-packages    List the registered log package names that can be targeted with
                                 --debug=<suffix> or --verbose=<suffix>, then exit
`

// connArgs holds the shared connection/authentication state. Connection flags
// are only registered for subcommands whose NeedsConnection() returns true;
// --debug/--verbose are registered for every subcommand.
type connArgs struct {
	host           string
	port           int
	useTLS         bool
	startTLS       bool
	insecure       bool
	baseDN         string
	discoverBaseDN bool
	saslMode       string
	channelBind    bool
	smbPort        int
	noenc          bool
	forceSMB2      bool
	timeout        time.Duration
	socksHost      string
	socksPort      int
	domain         string
	user           string
	pass           string
	hash           string
	noPass         bool
	useKerberos    bool
	useSimple      bool
	useAnonymous   bool
	keytabPath     string
	ccachePath     string
	krb5conf       string
	realm          string
	aesKey         string
	authSpn        string
	dcIP           string
	targetIP       string
	dnsHost        string
	dnsTCP         bool
	debug          logFlag
	verbose        logFlag
	listLog        bool
}

// logFlag is a comma-separated package-suffix filter that also remembers
// whether the user passed the flag at all. IsBoolFlag is set so the bare
// "--debug" and "--verbose" form parses (the flag pkg then calls Set("true"))
// — we treat "true" as "no filter, all packages on". A filter list requires
// the "=" form, e.g. --debug=smb,ldap, because IsBoolFlag stops the parser
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

// Subcommand is the interface each gpoparser mode implements.
type Subcommand interface {
	// Name is the literal string the user types (e.g. "remote").
	Name() string
	// Synopsis is a short one-line description for the top-level help.
	Synopsis() string
	// NeedsConnection reports whether the mode talks to AD/SYSVOL and thus
	// needs the connection/auth flags and a --host.
	NeedsConnection() bool
	// DefineFlags registers mode-specific flags. Connection flags are added
	// by the dispatcher and must NOT be redefined here.
	DefineFlags(fs *flag.FlagSet)
	// Usage returns pre-formatted help text shown for `<cmd> --help`.
	Usage() string
	// Run executes the mode.
	Run(args *connArgs) error
}

var subcommands = map[string]Subcommand{}

func register(c Subcommand) { subcommands[c.Name()] = c }

func isFlagSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func addCommonArgs(f *flag.FlagSet, a *connArgs) {
	f.Var(&a.debug, "debug", "Enable debug logging (optionally --debug=pkg,pkg)")
	f.Var(&a.verbose, "verbose", "Enable verbose output (optionally --verbose=pkg,pkg)")
	f.BoolVar(&a.listLog, "list-log-packages", false, "List registered log package names and exit")
}

func addConnectionArgs(f *flag.FlagSet, a *connArgs) {
	f.StringVar(&a.host, "host", "", "DC hostname or IP (required)")
	f.IntVar(&a.port, "port", 0, "LDAP port (default: 389 or 636 with --tls)")
	f.IntVar(&a.port, "P", 0, "LDAP port (short)")
	f.BoolVar(&a.useTLS, "tls", false, "Use LDAPS")
	f.BoolVar(&a.startTLS, "starttls", false, "Use StartTLS")
	f.BoolVar(&a.insecure, "insecure", false, "Skip TLS certificate verification")
	f.StringVar(&a.baseDN, "base-dn", "", "Search base DN (auto-detected if omitted)")
	f.StringVar(&a.saslMode, "sasl", "", "SASL security: none, sign, seal")
	f.BoolVar(&a.channelBind, "channel", false, "Enable TLS channel binding")
	f.IntVar(&a.smbPort, "smb-port", 445, "SMB port for SYSVOL access")
	f.BoolVar(&a.noenc, "noenc", false, "Disable SMB encryption when reading SYSVOL")
	f.BoolVar(&a.forceSMB2, "smb2", false, "Force SMB 2.1 for SYSVOL access")
	f.DurationVar(&a.timeout, "timeout", 5*time.Second, "Dial timeout")
	f.DurationVar(&a.timeout, "t", 5*time.Second, "Dial timeout (short)")
	f.StringVar(&a.socksHost, "socks-host", "", "SOCKS5 proxy host")
	f.IntVar(&a.socksPort, "socks-port", 1080, "SOCKS5 proxy port")
	f.StringVar(&a.domain, "domain", "", "AD domain")
	f.StringVar(&a.domain, "d", "", "AD domain (short)")
	f.StringVar(&a.user, "user", "", "Username")
	f.StringVar(&a.user, "u", "", "Username (short)")
	f.StringVar(&a.pass, "pass", "", "Password (bare -p prompts on terminal)")
	f.StringVar(&a.pass, "p", "", "Password (short)")
	f.StringVar(&a.hash, "hash", "", "NT hash (pass-the-hash / Kerberos RC4)")
	f.BoolVar(&a.noPass, "no-pass", false, "Send no password (unauthenticated bind)")
	f.BoolVar(&a.noPass, "n", false, "Send no password (short)")
	f.BoolVar(&a.useKerberos, "kerberos", false, "Use Kerberos authentication")
	f.BoolVar(&a.useKerberos, "k", false, "Use Kerberos (short)")
	f.BoolVar(&a.useSimple, "simple", false, "Use LDAP simple bind (DN/password)")
	f.BoolVar(&a.useAnonymous, "anonymous", false, "Use simple anonymous bind (no creds)")
	f.StringVar(&a.keytabPath, "keytab-file", "", "Authenticate with a Kerberos keytab (implies -k)")
	f.StringVar(&a.ccachePath, "ccache", "", "Kerberos credential cache file")
	f.StringVar(&a.krb5conf, "krb5conf", "/etc/krb5.conf", "Path to krb5.conf")
	f.StringVar(&a.realm, "realm", "", "Kerberos realm")
	f.StringVar(&a.aesKey, "aes-key", "", "Hex AES128/256 key (Kerberos)")
	f.StringVar(&a.authSpn, "override-spn", "", "LDAP service principal name (default: ldap/<host>)")
	f.StringVar(&a.dcIP, "dc-ip", "", "KDC address override for Kerberos (host[:port], default port 88)")
	f.StringVar(&a.targetIP, "target-ip", "", "IP to connect to; skips DNS of --host")
	f.StringVar(&a.dnsHost, "dns-host", "", "Override system DNS resolver (host[:port], default port 53)")
	f.BoolVar(&a.dnsTCP, "dns-tcp", false, "Force DNS lookups over TCP")
}

func topLevelUsage() {
	names := make([]string, 0, len(subcommands))
	for n := range subcommands {
		names = append(names, n)
	}
	sort.Strings(names)

	fmt.Fprintf(os.Stderr, "gpoparser - understand what Active Directory GPOs do and where they apply\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s <subcommand> [options]\n\nSubcommands:\n", os.Args[0])
	for _, n := range names {
		fmt.Fprintf(os.Stderr, "  %-10s %s\n", n, subcommands[n].Synopsis())
	}
	fmt.Fprintf(os.Stderr, "\nRun '%s <subcommand> --help' for mode-specific options.\n", os.Args[0])
	fmt.Fprintln(os.Stderr, helpConnectionOptions)
}

func saslSecurityFromArgs(args *connArgs) ldap.SASLSecurityMode {
	switch strings.ToLower(args.saslMode) {
	case "none":
		return ldap.SASLSecurityNone
	case "sign":
		return ldap.SASLSecuritySign
	case "seal":
		return ldap.SASLSecuritySeal
	default:
		if args.useTLS || args.startTLS {
			return ldap.SASLSecurityNone
		}
		return ldap.SASLSecuritySeal
	}
}

// discoverDC resolves _ldap._tcp.dc._msdcs.<domain> and returns the target
// hostname of the highest-priority record.
func discoverDC(domain string) (string, error) {
	_, addrs, err := net.LookupSRV("ldap", "tcp", "dc._msdcs."+domain)
	if err != nil {
		return "", err
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("no SRV records returned")
	}
	target := strings.TrimSuffix(addrs[0].Target, ".")
	if target == "" {
		return "", fmt.Errorf("first SRV record has empty target")
	}
	return target, nil
}

func resolvePort(args *connArgs) int {
	if args.port != 0 {
		return args.port
	}
	if args.useTLS {
		return 636
	}
	return 389
}

// dialLDAP establishes a raw TCP (or TLS) connection to the DC, honouring
// --timeout and --socks-host / --socks-port.
func dialLDAP(args *connArgs, tlsConf *tls.Config) (net.Conn, error) {
	port := resolvePort(args)
	dialHost := args.host
	if args.targetIP != "" {
		dialHost = args.targetIP
		if h, _, err := net.SplitHostPort(dialHost); err == nil {
			dialHost = h
		}
	}
	addr := net.JoinHostPort(dialHost, fmt.Sprintf("%d", port))

	timeout := args.timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	var rawDial func(string, string) (net.Conn, error)
	if args.socksHost != "" {
		if args.socksPort < 1 {
			return nil, fmt.Errorf("invalid --socks-port %d", args.socksPort)
		}
		socksAddr := net.JoinHostPort(args.socksHost, fmt.Sprintf("%d", args.socksPort))
		base := &net.Dialer{Timeout: timeout}
		sd, err := proxy.SOCKS5("tcp", socksAddr, nil, base)
		if err != nil {
			return nil, fmt.Errorf("SOCKS5 init failed: %w", err)
		}
		rawDial = sd.Dial
	} else {
		d := &net.Dialer{Timeout: timeout}
		rawDial = d.Dial
	}

	conn, err := rawDial("tcp", addr)
	if err != nil {
		return nil, err
	}
	if args.useTLS {
		if tlsConf != nil && keyLogFile != nil {
			tlsConf.KeyLogWriter = keyLogFile
		}
		tlsConn := tls.Client(conn, tlsConf)
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}
		return tlsConn, nil
	}
	return conn, nil
}

func connect(args *connArgs) (*ldap.Conn, error) {
	tlsConf := &tls.Config{
		InsecureSkipVerify: args.insecure,
		ServerName:         args.host,
	}
	raw, err := dialLDAP(args, tlsConf)
	if err != nil {
		return nil, fmt.Errorf("connect failed: %w", err)
	}
	conn := ldap.NewConn(raw, args.useTLS)
	conn.Start()
	if args.startTLS {
		if keyLogFile != nil {
			tlsConf.KeyLogWriter = keyLogFile
		}
		if err = conn.StartTLS(tlsConf); err != nil {
			conn.Close()
			return nil, fmt.Errorf("StartTLS failed: %w", err)
		}
	}
	return conn, nil
}

func bind(conn *ldap.Conn, args *connArgs) error {
	return explainBindError(args, doBind(conn, args))
}

func doBind(conn *ldap.Conn, args *connArgs) error {
	saslSecurity := saslSecurityFromArgs(args)

	if args.useAnonymous {
		return conn.UnauthenticatedBind("")
	}

	if args.useSimple {
		if !args.useTLS && !args.startTLS && saslSecurity != ldap.SASLSecurityNone {
			return fmt.Errorf("--simple requires --tls or --starttls (or --sasl=none to override)")
		}
		return conn.Bind(args.user, args.pass)
	}

	if args.useKerberos {
		spn := args.authSpn
		if spn == "" {
			spn = "ldap/" + args.host
		}
		logger.Debugf("Using an SPN of %s\n", spn)

		krbClient, err := newKerberosClient(args)
		if err != nil {
			return err
		}
		defer krbClient.Close()
		krbClient.SASLSecurity = int(saslSecurity)

		if args.channelBind && (args.useTLS || args.startTLS) {
			tlsState, ok := conn.TLSConnectionState()
			if ok && len(tlsState.PeerCertificates) > 0 {
				if err := krbClient.SetChannelBinding(tlsState.PeerCertificates[0]); err != nil {
					return fmt.Errorf("channel binding failed: %w", err)
				}
			}
		}
		return conn.GSSAPIBindRequest(krbClient, &ldap.GSSAPIBindRequest{
			ServicePrincipalName: spn,
			SASLSecurity:         saslSecurity,
		})
	}

	req := &ldap.NTLMBindRequest{
		Domain:         args.domain,
		Username:       args.user,
		Password:       args.pass,
		Hash:           args.hash,
		SASLSecurity:   saslSecurity,
		ChannelBinding: args.channelBind,
	}
	if args.noPass {
		req.Password = ""
		req.Hash = ""
		req.AllowEmptyPassword = true
	}
	_, err := conn.NTLMChallengeBind(req)
	return err
}

// explainBindError converts a recognised AD bind failure into a one-line
// message while preserving the underlying *ldap.Error via %w.
func explainBindError(args *connArgs, err error) error {
	if err == nil {
		return nil
	}
	overTLS := args.useTLS || args.startTLS
	switch fail := ldap.ClassifyBindError(err, overTLS); fail.Kind {
	case ldap.BindFailureChannelBinding:
		if !args.channelBind && overTLS {
			return fmt.Errorf("server requires LDAP channel binding — retry with --channel: %w", err)
		}
		return fmt.Errorf("server rejected the channel binding token (SEC_E_BAD_BINDINGS): %w", err)
	case ldap.BindFailureSigning:
		return fmt.Errorf("server requires LDAP signing — retry with --sasl=sign (or use --tls/--starttls): %w", err)
	case ldap.BindFailureConfidentialityRequired:
		return fmt.Errorf("server requires a confidential connection — retry with --tls or --starttls: %w", err)
	case ldap.BindFailureCredentials:
		if fail.Description != "" {
			return fmt.Errorf("bind failed: %s: %w", fail.Description, err)
		}
	}
	return err
}

// kdcRealmsForDCIP returns the realms to register the --dc-ip KDC under: the
// client realm plus gokrb5's suffix-strip guess for the target host's realm.
func kdcRealmsForDCIP(clientRealm, host string) []string {
	var realms []string
	seen := map[string]bool{}
	add := func(r string) {
		r = strings.ToUpper(strings.TrimSpace(r))
		if r == "" || seen[r] {
			return
		}
		seen[r] = true
		realms = append(realms, r)
	}
	add(clientRealm)
	h := host
	if hp, _, err := net.SplitHostPort(h); err == nil {
		h = hp
	}
	if net.ParseIP(h) == nil {
		if i := strings.Index(h, "."); i > 0 && i < len(h)-1 {
			add(h[i+1:])
		}
	}
	return realms
}

// newKerberosClient picks the right gokrb5 client factory based on which of
// --ccache, --aes-key, --hash, or --pass was supplied.
func newKerberosClient(args *connArgs) (*gssapi.Client, error) {
	settings := []func(*client.Settings){client.DisablePAFXFAST(true)}

	cfg, err := krbconfig.Load(args.krb5conf)
	if err != nil {
		return nil, fmt.Errorf("loading krb5.conf: %w", err)
	}

	// A keytab is a self-describing credential: when --keytab-file is supplied without
	// --user (and without a realm from --realm/--domain), derive the login
	// identity from the keytab's first entry. Explicit flags still win. The
	// loaded keytab is reused by the auth block below so it is read once.
	var ktForAuth *keytab.Keytab
	if args.keytabPath != "" {
		ktForAuth, err = keytab.Load(args.keytabPath)
		if err != nil {
			return nil, fmt.Errorf("loading keytab: %w", err)
		}
		pn, ktRealm, perr := ktForAuth.Principal()
		if perr != nil {
			return nil, fmt.Errorf("keytab %s: %w", args.keytabPath, perr)
		}
		if args.user == "" {
			args.user = strings.Join(pn.NameString, "/")
		}
		if args.realm == "" && args.domain == "" {
			args.realm = ktRealm
		}
	}

	realm, err := resolveKerberosRealm(args, cfg)
	if err != nil {
		return nil, err
	}

	if args.dcIP != "" {
		addr := args.dcIP
		if !strings.Contains(addr, ":") {
			addr = net.JoinHostPort(addr, "88")
		}
		for _, r := range kdcRealmsForDCIP(realm, args.host) {
			cfg.Realms = append(cfg.Realms, krbconfig.Realm{Realm: r, KDC: []string{addr}})
		}
	}

	if args.ccachePath != "" {
		cl, err := newCcacheClient(args, cfg, settings)
		if err == nil {
			return gssapi.NewClient(cl)
		}
		if !hasFallbackCred(args) {
			return nil, err
		}
		logger.Errorf("ccache rejected (%v); falling back to direct credentials\n", err)
	}

	if args.keytabPath != "" {
		kc, err := client.NewWithKeytab(args.user, realm, ktForAuth, cfg, settings...)
		if err != nil {
			return nil, fmt.Errorf("loading keytab client: %w", err)
		}
		logger.Noticef("Creating new kerberos client using keytab as %s@%s", args.user, realm)
		return gssapi.NewClient(kc)
	}

	if args.aesKey != "" {
		keyBytes, err := hex.DecodeString(args.aesKey)
		if err != nil {
			return nil, fmt.Errorf("decoding --aes-key: %w", err)
		}
		if len(keyBytes) != 16 && len(keyBytes) != 32 {
			return nil, fmt.Errorf("--aes-key must be 16 or 32 bytes (AES128/256), got %d", len(keyBytes))
		}
		kc, _ := client.NewWithKey(args.user, realm, keyBytes, cfg, settings...)
		if kc == nil {
			return nil, fmt.Errorf("gokrb5 rejected --aes-key")
		}
		return gssapi.NewClient(kc)
	}

	if args.hash != "" {
		hashBytes, err := hex.DecodeString(args.hash)
		if err != nil {
			return nil, fmt.Errorf("decoding --hash: %w", err)
		}
		if len(hashBytes) != 16 {
			return nil, fmt.Errorf("--hash must be a 16-byte NT hash, got %d bytes", len(hashBytes))
		}
		kc, _ := client.NewWithHash(args.user, realm, hashBytes, cfg, settings...)
		if kc == nil {
			return nil, fmt.Errorf("gokrb5 rejected --hash")
		}
		return gssapi.NewClient(kc)
	}

	return gssapi.NewClientWithPasswordExt(args.user, realm, args.pass, cfg, settings...)
}

func newCcacheClient(args *connArgs, cfg *krbconfig.Config, settings []func(*client.Settings)) (*client.Client, error) {
	ccache, err := credentials.LoadCCache(args.ccachePath)
	if err != nil {
		return nil, fmt.Errorf("loading ccache: %w", err)
	}
	spnHost := args.host
	fallbacks := [][]string{
		{"host", spnHost},
		{"ldap", spnHost},
		{"cifs", spnHost},
	}
	if args.authSpn != "" {
		if parts := strings.SplitN(args.authSpn, "/", 2); len(parts) == 2 {
			fallbacks = append([][]string{parts}, fallbacks...)
		}
	}
	kc, _, err := client.NewFromCCacheWithFallbacks(ccache, fallbacks, cfg, settings...)
	if err != nil {
		return nil, fmt.Errorf("loading ccache client: %w", err)
	}
	return kc, nil
}

func hasFallbackCred(a *connArgs) bool {
	return a.aesKey != "" || a.hash != "" || a.pass != "" || a.keytabPath != ""
}

func resolveKerberosRealm(args *connArgs, cfg *krbconfig.Config) (string, error) {
	if args.realm != "" {
		return args.realm, nil
	}
	if args.domain != "" {
		return strings.ToUpper(args.domain), nil
	}
	if cfg.LibDefaults.DefaultRealm != "" {
		return cfg.LibDefaults.DefaultRealm, nil
	}
	return "", fmt.Errorf("kerberos realm is unset: pass --realm, --domain, or set default_realm in %s", args.krb5conf)
}

// applyDNSResolver redirects net.DefaultResolver to the user-specified DNS
// server, before any LDAP/SRV/KDC lookups.
func applyDNSResolver(args *connArgs) error {
	if args.dnsHost == "" {
		return nil
	}
	addr := args.dnsHost
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = "53"
		addr = net.JoinHostPort(host, port)
	}
	if net.ParseIP(host) == nil {
		return fmt.Errorf("--dns-host: %q is not a valid IP address", host)
	}
	if p, err := strconv.ParseUint(port, 10, 16); err != nil || p == 0 {
		return fmt.Errorf("--dns-host: invalid port %q", port)
	}
	protocol := "udp"
	if args.dnsTCP {
		protocol = "tcp"
	}
	timeout := args.timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, protocol, addr)
		},
	}
	return nil
}

func detectBaseDN(conn *ldap.Conn, attr string) (string, error) {
	result, err := conn.Search(ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{attr},
		nil,
	))
	if err != nil {
		return "", fmt.Errorf("RootDSE query failed: %w", err)
	}
	if len(result.Entries) == 0 {
		return "", fmt.Errorf("no RootDSE entry returned")
	}
	dn := result.Entries[0].GetAttributeValue(attr)
	if strings.TrimSpace(dn) == "" {
		return "", fmt.Errorf("%s is empty", attr)
	}
	return dn, nil
}

func makeConnection(args *connArgs) (conn *ldap.Conn, baseDN string, err error) {
	if args.channelBind && !args.useTLS && !args.startTLS {
		err = fmt.Errorf("--channel requires --tls or --starttls")
		return
	}
	conn, err = connect(args)
	if err != nil {
		return
	}
	err = bind(conn, args)
	if err != nil {
		logger.Errorf("Failed to bind with error: %v\n", err)
		conn.Close()
		conn = nil
		return
	}
	if args.baseDN != "" {
		baseDN = args.baseDN
		return
	} else if !args.discoverBaseDN {
		return
	}
	baseDN, err = detectBaseDN(conn, "defaultNamingContext")
	if err != nil {
		conn.Close()
		conn = nil
		err = fmt.Errorf("could not detect base DN (specify --base-dn manually): %w", err)
	}
	return
}

func promptSecret(label string) (string, error) {
	fmt.Printf("%s", label)
	passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(passBytes), nil
}

// ensurePassword fills args.pass from a terminal prompt when the active auth
// mode requires a cleartext password.
func ensurePassword(a *connArgs) error {
	if a.useAnonymous || a.noPass || a.hash != "" || a.aesKey != "" || a.keytabPath != "" {
		return nil
	}
	if a.useKerberos && a.ccachePath != "" {
		return nil
	}
	if a.pass != "" {
		return nil
	}
	p, err := promptSecret("Enter password: ")
	if err != nil {
		return err
	}
	a.pass = p
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

// configureLogging translates --debug / --verbose into golog levels for this
// tool and the go-smb / ldap / krb5 subpackages it drives. The two flags are
// not mutually exclusive: each may carry its own comma-separated package filter
// (e.g. --debug=smb,ldap --verbose=main). Verbose is applied first and debug
// second so any package targeted by both ends up at the higher level
// (LevelDebug > LevelInfo). A bare --debug or --verbose (empty filter) targets
// every registered package, so passing both bare is ambiguous and rejected.
func configureLogging(a *connArgs) bool {
	if a.debug.set && a.verbose.set && len(a.debug.values) == 0 && len(a.verbose.values) == 0 {
		fmt.Println("Cannot enable both --debug and --verbose for all packages at once. Specify just one of them, or be more granular e.g. --debug=smb,ldap --verbose=main")
		return false
	}
	if a.verbose.set {
		applyLogLevel(golog.LevelInfo, a.verbose.values)
	}
	if a.debug.set {
		applyLogLevel(golog.LevelDebug, a.debug.values)
	}
	return true
}

func main() {
	var err error
	if len(os.Args) < 2 {
		topLevelUsage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "-v", "--version":
		fmt.Printf("gpoparser version %s\n", release)
		if bi, ok := rundebug.ReadBuildInfo(); ok {
			for _, m := range bi.Deps {
				fmt.Printf("Package: %s, Version: %s\n", m.Path, m.Version)
			}
		}
		return
	case "-h", "--help", "help":
		topLevelUsage()
		return
	}

	name := os.Args[1]
	sc, ok := subcommands[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "Unknown subcommand: %s\n\n", name)
		topLevelUsage()
		os.Exit(2)
	}

	args := &connArgs{}
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.Usage = func() {
		if u := sc.Usage(); u != "" {
			fmt.Fprintln(os.Stderr, u)
			return
		}
		fmt.Fprintf(os.Stderr, "Usage: %s %s [options]\n\n", os.Args[0], name)
		fs.PrintDefaults()
	}
	sc.DefineFlags(fs)
	addCommonArgs(fs, args)
	if sc.NeedsConnection() {
		addConnectionArgs(fs, args)
	}

	if err := fs.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}

	if args.listLog {
		listLogPackages()
		return
	}

	if !configureLogging(args) {
		os.Exit(2)
	}

	if !sc.NeedsConnection() {
		if err := sc.Run(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if !isFlagSet(fs, "base-dn") {
		args.discoverBaseDN = true
	}

	// A keytab is a Kerberos credential, so --keytab-file selects Kerberos without a
	// separate -k. An explicit keytab must not be shadowed by a stale KRB5CCNAME.
	if args.keytabPath != "" {
		args.useKerberos = true
	}

	if args.useKerberos && args.ccachePath == "" && args.keytabPath == "" {
		if cc := os.Getenv("KRB5CCNAME"); cc != "" {
			args.ccachePath = strings.TrimPrefix(cc, "FILE:")
			logger.Debugf("Using ccache from KRB5CCNAME: %s\n", args.ccachePath)
		}
	}

	if err := applyDNSResolver(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}

	keyLogFilePath := os.Getenv("SSLKEYLOGFILE")
	if keyLogFilePath != "" {
		os.Remove(keyLogFilePath)
		keyLogFile, err = os.OpenFile(keyLogFilePath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0640)
		if err != nil {
			logger.Errorf("failed to open SSLKEYLOGFILE (%s): %v\n", keyLogFilePath, err)
			return
		}
		defer keyLogFile.Close()
	}

	if args.host == "" {
		if args.domain != "" {
			h, err := discoverDC(args.domain)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: --host is required (DC discovery via SRV failed: %v)\n", err)
				fs.Usage()
				os.Exit(2)
			}
			args.host = h
			fmt.Fprintf(os.Stderr, "[*] Discovered DC via SRV: %s\n", args.host)
		} else {
			fmt.Fprintln(os.Stderr, "Error: --host is required")
			fs.Usage()
			os.Exit(2)
		}
	}

	if err := sc.Run(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
