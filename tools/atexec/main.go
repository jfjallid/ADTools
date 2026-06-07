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
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"
	"golang.org/x/term"
	rundebug "runtime/debug"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/mstsch"
	"github.com/jfjallid/go-smb/dcerpc/smbtransport"
	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
	"github.com/jfjallid/golog"
)

var (
	log            = golog.Get("main")
	release string = "0.1.1"
)

var helpMsg = `
    Usage: ` + os.Args[0] + ` [options]

    options:
          --host <target>          Hostname or ip address of remote server. Must be hostname when using Kerberos
      -P, --port <int>             SMB Port (default 445)
      -d, --domain <name/fqdn>     Domain name to use for login
      -u, --user <string>          Username
      -p, --pass <string>          Password
      -n, --no-pass                Disable password prompt and send no credentials
          --hash <NT Hash>         Hex encoded NT Hash for user password
          --local                  Authenticate as a local user instead of domain user
      -k, --kerberos               Use Kerberos authentication. (KRB5CCNAME will be checked on Linux)
          --dc-ip <ip>             Optionally specify ip of KDC when using Kerberos authentication
          --target-ip <ip>         Optionally specify ip of target when using Kerberos authentication
          --dns-host <ip:port>     Override system's default DNS resolver
          --dns-tcp                Force DNS lookups over TCP. Default true when using --socks-host
          --aes-key <hex>          Use a hex encoded AES128/256 key for Kerberos authentication
      -t, --timeout <duration>     Dial timeout specified in 5s, 1m, 10m format (default 5s)
      -c, --command <str>          Command to execute
      -a, --args <str>             Command arguments
          --no-delete              Do not delete the scheduled task after execution
          --socks-host <target>    Establish connection via a SOCKS5 proxy server
          --socks-port <port>      SOCKS5 proxy port (default 1080)
          --noenc                  Disable smb encryption
          --smb2                   Force smb 2.1
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

func cleanup(rpc *mstsch.RPCCon, path string) {
	log.Noticef("[*] Deleting task: %s\n", path)
	err := rpc.DeleteTask(path, 0)
	if err != nil {
		log.Errorf("[!] DeleteTask failed: %s", err)
	} else {
		log.Noticeln("[+] Task deleted")
	}
}

func randomTaskName() string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, 8)
	for i := range b {
		b[i] = chars[r.Intn(len(chars))]
	}
	return "GoSMB_" + string(b)
}

func main() {
	var host, username, password, hash, domain, socksHost, targetIP, dcIP, aesKey, dnsHost, command, cmdArgs string
	var port, socksPort int
	var localUser, forceSMB2, version, noPass, kerberos, dnsTCP, noenc, noDelete, listLog bool
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
	flag.IntVar(&port, "P", 445, "")
	flag.IntVar(&port, "port", 445, "")
	flag.Var(&debug, "debug", "")
	flag.Var(&verbose, "verbose", "")
	flag.BoolVar(&listLog, "list-log-packages", false, "")
	flag.BoolVar(&localUser, "local", false, "")
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
	flag.BoolVar(&noenc, "noenc", false, "")
	flag.StringVar(&command, "c", "", "")
	flag.StringVar(&command, "command", "", "")
	flag.StringVar(&cmdArgs, "a", "", "")
	flag.StringVar(&cmdArgs, "args", "", "")
	flag.BoolVar(&noDelete, "no-delete", false, "")
	flag.BoolVar(&forceSMB2, "smb2", false, "")

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

	// Validate format
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

	if command == "" {
		log.Errorln("must specify a --command to execute")
		flag.Usage()
		return
	}

	if dialTimeout < time.Second {
		log.Errorln("valid value for the timeout is >= 1 seconds")
		return
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
			// Check if password is already specified to be empty
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
	// reuse cached TGSs across the SMB and DCERPC binds.
	var sharedKrb *spnego.KRB5Initiator
	newMech := func() gss.Mechanism {
		if kerberos {
			mech := &spnego.KRB5Initiator{
				User:        username,
				Password:    password,
				Domain:      domain,
				Hash:        hashBytes,
				AESKey:      aesKeyBytes,
				SPN:         "cifs/" + host,
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
			User:      username,
			Password:  password,
			Hash:      hashBytes,
			Domain:    domain,
			LocalUser: localUser,
		}
	}

	smbMech := newMech()
	smbOpts := smb.Options{
		Host:              targetIP,
		Port:              port,
		Domain:            domain,
		User:              username,
		Password:          password,
		Hash:              hash,
		ForceSMB2:         forceSMB2,
		DialTimeout:       dialTimeout,
		ProxyDialer:       dialSocksProxy,
		DisableEncryption: noenc,
		Initiator:         smbMech,
	}
	conn, err := smb.NewConnection(smbOpts)
	if err != nil {
		log.Errorf("SMB connect failed: %s", err)
		return
	}
	defer conn.Close()
	if conn.IsSigningRequired() {
		log.Noticeln("[-] Signing is required")
	} else {
		log.Noticeln("[+] Signing is NOT required")
	}

	if conn.IsAuthenticated() {
		log.Noticef("[+] Login successful as %s\n", conn.GetAuthUsername())
	} else {
		log.Noticeln("[-] Login failed")
		return
	}

	f, err := conn.OpenFile("IPC$", "atsvc")
	if err != nil {
		log.Errorf("failed to open atsvc pipe: %s", err)
		return
	}
	defer f.CloseFile()

	transport, err := smbtransport.NewSMBTransport(f)
	if err != nil {
		log.Errorf("failed to create SMB transport: %s", err)
		return
	}

	authLevel := dcerpc.RpcAuthnLevelPktPrivacy
	if noenc {
		authLevel = dcerpc.RpcAuthnLevelPktIntegrity
	}

	bind, err := dcerpc.BindAuth(
		transport,
		mstsch.MSRPCUuidTsch,
		mstsch.MSRPCTschMajorVersion,
		mstsch.MSRPCTschMinorVersion,
		dcerpc.MSRPCUuidNdr,
		authLevel,
		newMech(),
	)
	if err != nil {
		log.Errorf("DCERPC bind failed: %s", err)
		return
	}

	rpc := mstsch.NewRPCCon(bind)

	taskName := fmt.Sprintf("\\%s", randomTaskName())
	log.Noticef("[*] Creating task: %s\n", taskName)

	xml := mstsch.BuildExecTaskXML(command, cmdArgs)

	actualPath, err := rpc.RegisterTask(taskName, xml, mstsch.TaskCreateOrUpdate, mstsch.TaskLogonNone)
	if err != nil {
		log.Errorf("RegisterTask failed: %s", err)
		return
	}
	log.Noticef("[+] Task registered: %s\n", actualPath)

	guid, err := rpc.RunTask(actualPath, mstsch.TaskRunAsSelf, 0, "")
	if err != nil {
		log.Errorf("RunTask failed: %s", err)
		if !noDelete {
			cleanup(rpc, actualPath)
		}
		return
	}
	log.Noticef("[+] Task started (GUID: %s)\n", mstsch.GUIDToString(guid))

	// Brief pause to let the task start
	time.Sleep(1 * time.Second)

	err = rpc.StopTask(actualPath, 0)
	if err != nil {
		log.Errorf("StopTask failed: %s", err)
	}

	lastRunTime, lastReturnCode, err := rpc.GetLastRunInfo(actualPath)
	if err != nil {
		log.Errorf("[!] GetLastRunInfo failed: %s", err)
	} else {
		t := lastRunTime.ToTime()
		if !t.IsZero() {
			if desc, ok := mstsch.TaskResultToString(lastReturnCode); ok {
				log.Noticef("[*] Last run: %s, return code: %d (%s)\n", t.Format("2006-01-02 15:04:05"), lastReturnCode, desc)
			} else {
				log.Noticef("[*] Last run: %s, return code: %d (0x%08x)\n", t.Format("2006-01-02 15:04:05"), lastReturnCode, lastReturnCode)
			}
		} else {
			log.Noticeln("[*] Task has not run yet")
		}
	}

	if !noDelete {
		cleanup(rpc, actualPath)
	} else {
		log.Noticeln("[*] Skipping task deletion (--no-delete)")
	}

	log.Noticeln("[+] Done")
}
