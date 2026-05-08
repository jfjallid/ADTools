package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jfjallid/gokrb5/v8/client"
	krbconfig "github.com/jfjallid/gokrb5/v8/config"
	"github.com/jfjallid/gokrb5/v8/credentials"
	"github.com/jfjallid/golog"
	ldap "github.com/jfjallid/ldap/v3"
	"github.com/jfjallid/ldap/v3/gssapi"
	"golang.org/x/net/proxy"
	"golang.org/x/term"
)

var logger = golog.Get("")
var release string = "0.1.0"
var keyLogFile *os.File

var helpConnectionOptions = `
    Connection options:
          --host                 DC hostname or IP (required)
      -P, --port                 LDAP port (default 389, or 636 with --tls)
          --tls                  Use LDAPS (implicit TLS)
          --starttls             Use StartTLS on plain LDAP port
          --insecure             Skip TLS certificate verification
          --base-dn              Search base DN (auto-detected if omitted)
          --naming-context       Naming context: default, configuration, schema, root
          --sasl                 SASL security: none, sign, seal
          --channel              Enable TLS channel binding
      -t, --timeout              Dial timeout (e.g. 5s, 1m; default 5s)
          --socks-host           SOCKS5 proxy host
          --socks-port           SOCKS5 proxy port (default 1080)

    Authentication (NTLM unless --simple/--anonymous/--kerberos):
      -d, --domain               AD domain (e.g. CORP)
      -u, --user                 Username (or full DN with --simple)
      -p, --pass                 Password (or set AD_PASSWORD env var)
          --hash                 NT hash (pass-the-hash / Kerberos RC4)
      -n, --no-pass              Send no password (unauthenticated NTLM bind)
          --simple               LDAP simple bind (DN/password)
          --anonymous            LDAP simple anonymous bind (no creds)

    Kerberos (with -k/--kerberos):
      -k, --kerberos             Use Kerberos (GSSAPI) instead of NTLM
          --ccache               Path to Kerberos credential cache file (falls back to $KRB5CCNAME)
          --krb5conf             Path to krb5.conf (default: /etc/krb5.conf)
          --realm                Kerberos realm (defaults to upper-cased --domain)
          --aes-key              Hex AES128/256 key
          --override-spn         Service principal name (default: ldap/<host>)
          --dc-ip <ip[:port]>    KDC address override (default port 88)
          --dns-host <ip[:port]> Override system's default DNS resolver (default port 53)
          --dns-tcp              Force DNS lookups over TCP
`

type connArgs struct {
	host           string
	port           int
	useTLS         bool
	startTLS       bool
	insecure       bool
	baseDN         string
	discoverBaseDN bool
	namingContext  string
	saslMode       string
	channelBind    bool
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
	ccachePath     string
	krb5conf       string
	realm          string
	aesKey         string
	authSpn        string
	dcIP           string
	dnsHost        string
	dnsTCP         bool
	debug          bool
	verbose        bool
}

// Subcommand is the interface each ldaptool action implements.
type Subcommand interface {
	// Name is the literal string the user types (e.g. "search").
	Name() string
	// Synopsis is a short one-line description for the top-level help.
	Synopsis() string
	// DefineFlags registers action-specific flags. Connection flags are
	// added by the dispatcher and must NOT be redefined here.
	DefineFlags(fs *flag.FlagSet)
	// Usage returns pre-formatted help text shown for `<cmd> --help`.
	// An empty string falls back to flag.FlagSet.PrintDefaults.
	Usage() string
	// Run executes the action. Connection args are fully populated and
	// --server has already been validated.
	Run(args *connArgs) error
}

var subcommands = map[string]Subcommand{}

func register(c Subcommand) {
	subcommands[c.Name()] = c
}

func isFlagSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func addConnectionArgs(f *flag.FlagSet, a *connArgs) {
	f.StringVar(&a.host, "host", "", "DC hostname or IP (required)")
	f.IntVar(&a.port, "port", 0, "LDAP port (default: 389 or 636 with --tls)")
	f.IntVar(&a.port, "P", 0, "LDAP port (short)")
	f.BoolVar(&a.useTLS, "tls", false, "Use LDAPS")
	f.BoolVar(&a.startTLS, "starttls", false, "Use StartTLS")
	f.BoolVar(&a.insecure, "insecure", false, "Skip TLS certificate verification")
	f.StringVar(&a.baseDN, "base-dn", "", "Search base DN (auto-detected if omitted)")
	f.StringVar(&a.namingContext, "naming-context", "default", "Naming context: default, configuration, schema, root")
	f.StringVar(&a.saslMode, "sasl", "", "SASL security: none, sign, seal")
	f.BoolVar(&a.channelBind, "channel", false, "Enable TLS channel binding")
	f.DurationVar(&a.timeout, "timeout", 5*time.Second, "Dial timeout")
	f.DurationVar(&a.timeout, "t", 5*time.Second, "Dial timeout (short)")
	f.StringVar(&a.socksHost, "socks-host", "", "SOCKS5 proxy host")
	f.IntVar(&a.socksPort, "socks-port", 1080, "SOCKS5 proxy port")
	f.StringVar(&a.domain, "domain", "", "AD domain")
	f.StringVar(&a.domain, "d", "", "AD domain (short)")
	f.StringVar(&a.user, "user", "", "Username")
	f.StringVar(&a.user, "u", "", "Username (short)")
	f.StringVar(&a.pass, "pass", "", "Password (or set AD_PASSWORD env var)")
	f.StringVar(&a.pass, "p", "", "Password (short)")
	f.StringVar(&a.hash, "hash", "", "NT hash (pass-the-hash / Kerberos RC4)")
	f.BoolVar(&a.noPass, "no-pass", false, "Send no password (unauthenticated NTLM bind)")
	f.BoolVar(&a.noPass, "n", false, "Send no password (short)")
	f.BoolVar(&a.useKerberos, "kerberos", false, "Use Kerberos authentication")
	f.BoolVar(&a.useKerberos, "k", false, "Use Kerberos (short)")
	f.BoolVar(&a.useSimple, "simple", false, "Use LDAP simple bind (DN/password)")
	f.BoolVar(&a.useAnonymous, "anonymous", false, "Use simple anonymous bind (no creds)")
	f.StringVar(&a.ccachePath, "ccache", "", "Kerberos credential cache file")
	f.StringVar(&a.krb5conf, "krb5conf", "/etc/krb5.conf", "Path to krb5.conf")
	f.StringVar(&a.realm, "realm", "", "Kerberos realm")
	f.StringVar(&a.aesKey, "aes-key", "", "Hex AES128/256 key (Kerberos)")
	f.StringVar(&a.authSpn, "override-spn", "", "Service principal name (default: ldap/<host>)")
	f.StringVar(&a.dcIP, "dc-ip", "", "KDC address override (host[:port], default port 88)")
	f.StringVar(&a.dnsHost, "dns-host", "", "Override system DNS resolver (host[:port], default port 53)")
	f.BoolVar(&a.dnsTCP, "dns-tcp", false, "Force DNS lookups over TCP")
	f.BoolVar(&a.debug, "debug", false, "Enable debug logging")
	f.BoolVar(&a.verbose, "verbose", false, "Enable verbose output")
}

func topLevelUsage() {
	names := make([]string, 0, len(subcommands))
	for n := range subcommands {
		names = append(names, n)
	}
	sort.Strings(names)

	fmt.Fprintf(os.Stderr, "Usage: %s <subcommand> [options]\n\nSubcommands:\n", os.Args[0])
	for _, n := range names {
		fmt.Fprintf(os.Stderr, "  %-22s %s\n", n, subcommands[n].Synopsis())
	}
	fmt.Fprintf(os.Stderr, "\nRun '%s <subcommand> --help' for action-specific options.\n", os.Args[0])
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

func ncAttrFromNamingContext(nc string) string {
	switch strings.ToLower(nc) {
	case "configuration":
		return "configurationNamingContext"
	case "schema":
		return "schemaNamingContext"
	case "root":
		return "rootDomainNamingContext"
	default:
		return "defaultNamingContext"
	}
}

// discoverDC resolves _ldap._tcp.dc._msdcs.<domain> and returns the target
// hostname of the highest-priority record (lowest priority value, then
// highest weight). Falls back to net.LookupSRV semantics.
func discoverDC(domain string) (string, error) {
	_, addrs, err := net.LookupSRV("ldap", "tcp", "dc._msdcs."+domain)
	if err != nil {
		return "", err
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("no SRV records returned")
	}
	// LookupSRV already sorts by priority/weight per RFC 2782.
	target := strings.TrimSuffix(addrs[0].Target, ".")
	if target == "" {
		return "", fmt.Errorf("first SRV record has empty target")
	}
	return target, nil
}

// resolvePort picks the effective LDAP port from flags.
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
// --timeout and --socks-host / --socks-port. The caller still has to wrap it
// in ldap.NewConn and run Start() / StartTLS().
func dialLDAP(args *connArgs, tlsConf *tls.Config) (net.Conn, error) {
	port := resolvePort(args)
	addr := net.JoinHostPort(args.host, fmt.Sprintf("%d", port))

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
		// Simple bind sends the password in cleartext, so refuse over a
		// non-TLS channel unless the user really insists with --sasl=none.
		if !args.useTLS && !args.startTLS && saslSecurity != ldap.SASLSecurityNone {
			return fmt.Errorf("--simple requires --tls or --starttls (or --sasl=none to override)")
		}
		return conn.Bind(args.user, args.pass)
	}

	if args.useKerberos {
		spn := args.authSpn
		if spn == "" {
			spn = "host/" + args.host
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
// message suitable for display to the user, while preserving the underlying
// *ldap.Error via %w so callers can still inspect ResultCode / substatus.
//
// Most AD bind failures come back as "LDAP Result Code 49 \"Invalid
// Credentials\": 80090346: LdapErr: ..., data 80090346, v4563", which is
// noisy and only marginally informative. We pull out the substatus and
// translate it; for the channel-binding case we also nudge the user toward
// --channel when they haven't supplied it.
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

// newKerberosClient picks the right gokrb5 client factory based on which of
// --ccache, --aes-key, --hash, or --pass was supplied.
//
// The realm passed to gokrb5 falls back to upper-cased --domain, then to the
// default_realm in krb5.conf. --dc-ip injects an explicit KDC entry for the
// resolved realm so gokrb5's GetKDCs sees it before falling back to DNS SRV.
func newKerberosClient(args *connArgs) (*gssapi.Client, error) {
	settings := []func(*client.Settings){client.DisablePAFXFAST(true)}

	cfg, err := krbconfig.Load(args.krb5conf)
	if err != nil {
		return nil, fmt.Errorf("loading krb5.conf: %w", err)
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
		// Appending wins because GetKDCs keeps the last matching realm entry.
		cfg.Realms = append(cfg.Realms, krbconfig.Realm{
			Realm: realm,
			KDC:   []string{addr},
		})
	}

	// Try the ccache first if available; on failure, fall through to
	// aes/hash/password if any of those creds were also supplied.
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

// newCcacheClient loads the ccache and matches it against the SPNs we'd
// accept for an LDAP bind (gokrb5 rejects an ST-only cache when no target is
// supplied). AD's sPNMappings let a cached "host/<dc>" ticket satisfy ldap/
// and cifs/ requests, so we list those as fallbacks.
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

// hasFallbackCred reports whether the user supplied any non-ccache
// credential we can retry the bind with. An empty password counts as "no
// fallback" — we don't want to silently try an empty AS-REQ.
func hasFallbackCred(a *connArgs) bool {
	return a.aesKey != "" || a.hash != "" || a.pass != ""
}

// resolveKerberosRealm picks the realm in priority order: --realm,
// upper-cased --domain, then krb5.conf's default_realm. gokrb5's
// client.NewWith* constructors do not honour the "empty realm = default"
// contract that the gssapi wrapper docstring claims, so we resolve it here.
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
// server. Mirrors the dcsync flag (and applies before any LDAP/SRV lookups so
// gokrb5's KDC SRV discovery and our own DC discovery both honour it).
func applyDNSResolver(args *connArgs) error {
	if args.dnsHost == "" {
		return nil
	}
	addr := args.dnsHost
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// No port supplied: assume :53.
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
		// Intenionally empty baseDN so do not try do detect it
		return
	}

	ncAttr := ncAttrFromNamingContext(args.namingContext)
	baseDN, err = detectBaseDN(conn, ncAttr)
	if err != nil {
		conn.Close()
		conn = nil
		err = fmt.Errorf("could not detect base DN (specify --base-dn manually): %w", err)
	}
	return
}

func promptPassword() (string, error) {
	fmt.Printf("Enter password: ")
	passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(passBytes), nil
}

// ensurePassword fills args.pass from AD_PASSWORD or a terminal prompt when
// the active auth mode requires one. It is a no-op when --anonymous,
// --no-pass, --hash, or --aes-key obviates the need for a cleartext password.
//
// When a Kerberos ccache is in play we don't prompt — the ccache is the
// primary credential — but we still pick up AD_PASSWORD as a passive
// fallback so newKerberosClient can retry with a password if the ccache
// has no usable ticket.
func ensurePassword(a *connArgs) error {
	if a.useAnonymous || a.noPass || a.hash != "" || a.aesKey != "" {
		return nil
	}
	if a.useKerberos && a.ccachePath != "" {
		if a.pass == "" {
			a.pass = os.Getenv("AD_PASSWORD")
		}
		return nil
	}
	if a.pass != "" {
		return nil
	}
	a.pass = os.Getenv("AD_PASSWORD")
	if a.pass != "" {
		return nil
	}
	p, err := promptPassword()
	if err != nil {
		return err
	}
	a.pass = p
	return nil
}

// applyLogLevel translates --debug / --verbose to a golog level and, in
// debug mode, also flips the level on the noisy subpackages the shell would
// otherwise silence.
func applyLogLevel(a *connArgs) {
	lvl := golog.LevelNotice
	if a.debug {
		lvl = golog.LevelDebug
	} else if a.verbose {
		lvl = golog.LevelInfo
	}
	logger.SetLogLevel(lvl)
	logger.SetFlags(golog.LstdFlags|golog.Lshortfile)
	if !a.debug {
		return
	}
	// Mirror the shell's explicit packages so --debug actually reaches them.
	debugPackages := []struct{ pkg, name string }{
		{"github.com/jfjallid/ldap/v3", "ldap"},
		{"github.com/jfjallid/gokrb5/v8", "krb5"},
		{"github.com/jfjallid/go-smb/ntlmssp", "ntlmssp"},
	}
	for _, p := range debugPackages {
		golog.Set(p.pkg, p.name, golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
	}
}

func main() {
	var err error
	if len(os.Args) < 2 {
		topLevelUsage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "-v", "--version":
		fmt.Printf("ldaptool version %s\n", release)
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
	addConnectionArgs(fs, args)

	if err := fs.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}

	applyLogLevel(args)

	if !isFlagSet(fs, "base-dn") {
		args.discoverBaseDN = true
	}

	if args.useKerberos && args.ccachePath == "" {
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
		// Make sure to open the keylogfile for writing the TLS key log file for packet decryption
		// Remove the file if it exists and ignore errors
		os.Remove(keyLogFilePath)
		keyLogFile, err = os.OpenFile(keyLogFilePath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0640)
		if err != nil {
			logger.Errorf("failed to open SSLKEYLOGFILE (%s) for writing the TLS key log file with error: %v\n", keyLogFilePath, err)
			return
		}
		defer keyLogFile.Close()
	}

	if args.host == "" {
		// Last-ditch: if --domain is set, try a DNS SRV lookup to find a DC.
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

// ---- detect-signing subcommand --------------------------------------------

type detectSigningCmd struct{}

func init() { register(&detectSigningCmd{}) }

func (c *detectSigningCmd) Name() string              { return "detect-signing" }
func (c *detectSigningCmd) Synopsis() string          { return "Detect if LDAP signing is required" }
func (c *detectSigningCmd) DefineFlags(fs *flag.FlagSet) {}
func (c *detectSigningCmd) Usage() string {
	return `
    Usage: ` + os.Args[0] + ` detect-signing [options]

    Probes whether the target DC enforces LDAP signing. Credentials are
	currently required. A DC that enforces signing rejects the unsigned bind
	with strongerAuthRequired after validating credentials.
	Only relevant for plain ldap, not TLS connections.
` + helpConnectionOptions
}

func (c *detectSigningCmd) Run(a *connArgs) error {
	// Signing detection does an unsigned bind over plaintext LDAP and watches
	// for the stronger-auth-required error, so force plain transport.
	if a.useTLS || a.startTLS {
		return fmt.Errorf("detect-signing only works for plain ldap connections, not TLS")
	}
	if err := ensurePassword(a); err != nil {
		return fmt.Errorf("reading password: %w", err)
	}

	plainArgs := *a
	plainArgs.useTLS = false
	plainArgs.startTLS = false
	raw, err := dialLDAP(&plainArgs, nil)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	conn := ldap.NewConn(raw, false)
	conn.Start()
	defer conn.Close()

	var bindErr error
	if a.useKerberos {
		if a.authSpn == "" {
			a.authSpn = "host/" + a.host
		}
		logger.Debugf("Using an SPN of %s\n", a.authSpn)

		krbClient, err := newKerberosClient(a)
		if err != nil {
			return err
		}
		defer krbClient.Close()

		req := &ldap.GSSAPIBindRequest{
			ServicePrincipalName: a.authSpn,
		}
		bindErr = conn.GSSAPIBindRequest(krbClient, req)
	} else {
		if a.user == "" || (a.pass == "" && a.hash == "") {
			fmt.Printf("a.pass: %q\n", a.pass)
			return fmt.Errorf("valid credentials are currently required to detect ldap signing")
		}

		req := &ldap.NTLMBindRequest{
			Domain:       a.domain,
			Username:     a.user,
			SASLSecurity: ldap.SASLSecurityNone,
		}
		switch {
		case a.hash != "":
			req.Hash = a.hash
		case a.pass != "":
			req.Password = a.pass
		default:
		}

		_, bindErr = conn.NTLMChallengeBind(req)
	}

	fail := ldap.ClassifyBindError(bindErr, false)
	switch {
	case bindErr == nil:
		// Bind succeeded (real creds supplied) — signing is not enforced.
		fmt.Println("LDAP signing required: false")
	case fail.Kind == ldap.BindFailureSigning:
		fmt.Println("LDAP signing required: true")
	case fail.Kind == ldap.BindFailureCredentials:
		// Server validated creds before rejecting — signing isn't required.
		fmt.Println("LDAP signing required: false")
	default:
		return fmt.Errorf("could not detect signing requirement: %w", bindErr)
	}
	return nil
}

// ---- detect-channel-binding subcommand -----------------------------------

type detectCBCmd struct{}

func init() { register(&detectCBCmd{}) }

func (c *detectCBCmd) Name() string              { return "detect-channel-binding" }
func (c *detectCBCmd) Synopsis() string          { return "Detect if LDAP channel binding is required" }
func (c *detectCBCmd) DefineFlags(fs *flag.FlagSet) {}
func (c *detectCBCmd) Usage() string {
	return `
    Usage: ` + os.Args[0] + ` detect-channel-binding [options]

    Probes whether the target DC enforces channel binding on TLS-protected
    binds. Performs an NTLM or Kerberos bind without channel binding over
	TLS and classifies the response. Forces --tls; --starttls is also acceptable.
` + helpConnectionOptions
}

func (c *detectCBCmd) Run(a *connArgs) error {
	if !a.useTLS && !a.startTLS {
		// Channel binding only matters over TLS — implicitly enable LDAPS.
		a.useTLS = true
	}
	tlsConf := &tls.Config{InsecureSkipVerify: true, ServerName: a.host}
	raw, err := dialLDAP(a, tlsConf)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	conn := ldap.NewConn(raw, a.useTLS)
	conn.Start()
	defer conn.Close()
	if a.startTLS {
		if keyLogFile != nil {
			tlsConf.KeyLogWriter = keyLogFile
		}
		if err := conn.StartTLS(tlsConf); err != nil {
			return fmt.Errorf("StartTLS failed: %w", err)
		}
	}
	var bindErr error
	if a.useKerberos {
		if a.authSpn == "" {
			a.authSpn = "host/" + a.host
		}
		logger.Debugf("Using an SPN of %s\n", a.authSpn)

		krbClient, err := newKerberosClient(a)
		if err != nil {
			return err
		}
		defer krbClient.Close()

		req := &ldap.GSSAPIBindRequest{
			ServicePrincipalName: a.authSpn,
		}
		bindErr = conn.GSSAPIBindRequest(krbClient, req)
	} else {
		domain := a.domain
		if domain == "" {
			domain = "WORKGROUP"
		}
		user := a.user
		if user == "" {
			user = "ldaptool-probe"
		}
		req := &ldap.NTLMBindRequest{
			Domain:         domain,
			Username:       user,
			SASLSecurity:   ldap.SASLSecurityNone,
			ChannelBinding: false,
		}
		switch {
		case a.hash != "":
			req.Hash = a.hash
		case a.pass != "":
			req.Password = a.pass
		default:
			req.Password = "ldaptool-probe"
		}
		_, bindErr = conn.NTLMChallengeBind(req)
	}

	fail := ldap.ClassifyBindError(bindErr, true)
	switch {
	case bindErr == nil:
		// Probe creds were good and the bind succeeded without CB → not required.
		fmt.Println("LDAP channel binding required: false")
	case fail.Kind == ldap.BindFailureChannelBinding:
		// SEC_E_BAD_BINDINGS, or code 8 over TLS — server enforces CB policy.
		fmt.Println("LDAP channel binding required: true")
	case fail.Kind == ldap.BindFailureCredentials:
		// Bind got past the CB check and was rejected on the credential
		// itself, so CB is not being enforced for this bind type.
		fmt.Println("LDAP channel binding required: false")
	default:
		return fmt.Errorf("could not detect channel binding requirement: %w", bindErr)
	}
	return nil
}

// ---- shell subcommand -----------------------------------------------------

type shellCmd struct{
	noHistory bool
}

func init() { register(&shellCmd{}) }

func (c *shellCmd) Name() string              { return "shell" }
func (c *shellCmd) Synopsis() string          { return "Launch interactive shell" }
func (c *shellCmd) DefineFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.noHistory, "no-history", false, "Disable command history file")
}
func (c *shellCmd) Usage() string {
	return `
    Usage: ` + os.Args[0] + ` shell [options]

    Starts an interactive LDAP shell. The connection options below are used
    for the initial bind; once inside, the "connect" and "login" commands
    can open new connections.

    Shell options:
          --no-history      Disable command history file ($LDAPTOOL_HISTORY or ~/.ldaptool_history)

` + helpConnectionOptions
}

func (c *shellCmd) Run(a *connArgs) error {
	if err := ensurePassword(a); err != nil {
		return fmt.Errorf("reading password: %w", err)
	}
	conn, baseDN, err := makeConnection(a)
	if err != nil {
		return err
	}
	// cmdloop owns the connection's lifetime and closes it on exit.
	s := newShell(conn, a, baseDN, c.noHistory)
	s.cmdloop()
	return nil
}
