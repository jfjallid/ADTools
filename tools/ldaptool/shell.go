package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/jfjallid/golog"
	ldap "github.com/jfjallid/ldap/v3"
	"golang.org/x/term"
)

var (
	handlers      = make(map[string]any)
	helpFunctions = make(map[int]func(*shell))
)

type shell struct {
	conn          *ldap.Conn
	connArgs      *connArgs
	baseDN        string
	prompt        string
	authenticated bool
	t             *term.Terminal
	verbose       bool
	banner        bool
	helpMapKeys   []int
	noHistory     bool
}

const (
	ShellConnect      = "connect"
	ShellLogin        = "login"
	ShellLoginKrb     = "login_krb"
	ShellLogout       = "logout"
	ShellExit         = "exit"
	ShellToggleVerbose = "toggleverbose"
	ShellToggleBanner = "togglebanner"
	ShellSetBaseDN    = "setbasedn"
)

var usageMap = map[string]string{
	ShellConnect:       ShellConnect + " <host> [port]",
	ShellLogin:         ShellLogin + " [domain/user] [password]",
	ShellLoginKrb:      ShellLoginKrb + " [domain/user] [password]",
	ShellLogout:        ShellLogout,
	ShellExit:          ShellExit,
	ShellToggleVerbose: ShellToggleVerbose,
	ShellToggleBanner:  ShellToggleBanner,
	ShellSetBaseDN:     ShellSetBaseDN + " <dn>",
}

var descriptionMap = map[string]string{
	ShellConnect:       "Opens a new LDAP connection to the target host/port (no auth)",
	ShellLogin:         "Authenticates the current connection using NTLM",
	ShellLoginKrb:      "Authenticates the current connection using Kerberos",
	ShellLogout:        "Closes the current LDAP connection",
	ShellExit:          "Exits the interactive shell",
	ShellToggleVerbose: "Toggle verbose output",
	ShellToggleBanner:  "Toggle effective search banner",
	ShellSetBaseDN:     "Set the working base DN for searches",
}

var allKeys []string

var generalUsageKeys = []string{
	ShellConnect,
	ShellLogin,
	ShellLoginKrb,
	ShellLogout,
	ShellExit,
	ShellToggleVerbose,
	ShellToggleBanner,
	ShellSetBaseDN,
}

func completer(line string) (completions []string) {
	for _, key := range allKeys {
		if strings.HasPrefix(key, line) {
			completions = append(completions, key)
		}
	}
	return
}

func (self *shell) showCustomHelpFunc(usageWidth int, heading string, usageKeys []string) {
	self.printf("[%s]\n", heading)
	for _, key := range usageKeys {
		usage, usageExists := usageMap[key]
		description, descriptionExists := descriptionMap[key]
		if !usageExists {
			usage = key
		}
		if !descriptionExists {
			description = "No description available"
		}
		self.printf("  %-*s %s\n", usageWidth, usage, description)
	}
}

// parseArgs splits a shell-like input line into tokens, honouring single- and
// double-quoted strings, backslash escapes (\" \' \\ \  \n \t \r and any
// other literal character), and mid-token quotes (foo"bar baz" → {foo, bar
// baz}). Returns an error for unterminated quoted strings or trailing
// backslashes.
func parseArgs(input string) ([]string, error) {
	var (
		args     []string
		cur      strings.Builder
		quote    rune // 0, '"', or '\''
		hadToken bool // true once any character (incl. empty quoted "") was seen
	)
	runes := []rune(input)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		if c == '\\' {
			if i+1 >= len(runes) {
				return nil, fmt.Errorf("trailing backslash")
			}
			next := runes[i+1]
			if quote == '\'' {
				// Inside single quotes backslashes are literal.
				cur.WriteRune(c)
			} else {
				switch next {
				case 'n':
					cur.WriteByte('\n')
				case 't':
					cur.WriteByte('\t')
				case 'r':
					cur.WriteByte('\r')
				default:
					cur.WriteRune(next)
				}
				i++
				hadToken = true
				continue
			}
			hadToken = true
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
				continue
			}
			cur.WriteRune(c)
			hadToken = true
			continue
		}
		switch c {
		case '"', '\'':
			quote = c
			hadToken = true
		case ' ', '\t':
			if hadToken {
				args = append(args, cur.String())
				cur.Reset()
				hadToken = false
			}
		default:
			cur.WriteRune(c)
			hadToken = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated %c-quoted string", quote)
	}
	if hadToken {
		args = append(args, cur.String())
	}
	return args, nil
}

func longestCommonPrefix(strs []string) string {
	if len(strs) == 0 {
		return ""
	}
	prefix := strs[0]
	for _, str := range strs[1:] {
		for strings.Index(str, prefix) != 0 {
			prefix = prefix[:len(prefix)-1]
			if prefix == "" {
				return ""
			}
		}
	}
	return prefix
}

func newShell(conn *ldap.Conn, ca *connArgs, baseDN string, noCmdHistory bool) *shell {
	s := &shell{
		conn:          conn,
		connArgs:      ca,
		baseDN:        baseDN,
		prompt:        "(ldap) # ",
		authenticated: true,
		helpMapKeys:   make([]int, 0, len(helpFunctions)),
		noHistory:     noCmdHistory,
	}

	handlers["help"] = showHelpFunc
	handlers["?"] = showHelpFunc
	handlers[ShellConnect] = shellConnectFunc
	handlers[ShellLogin] = shellLoginFunc
	handlers[ShellLoginKrb] = shellLoginKrbFunc
	handlers[ShellLogout] = shellLogoutFunc
	handlers[ShellToggleVerbose] = shellToggleVerboseFunc
	handlers[ShellToggleBanner] = shellToggleBannerFunc
	handlers[ShellSetBaseDN] = shellSetBaseDNFunc

	for k := range helpFunctions {
		s.helpMapKeys = append(s.helpMapKeys, k)
	}
	sort.Ints(s.helpMapKeys)

	return s
}

func showHelpFunc(self *shell, args any) {
	self.showCustomHelpFunc(45, "General commands", generalUsageKeys)
	self.println()
	for _, i := range self.helpMapKeys {
		fn := helpFunctions[i]
		fn(self)
		self.println()
	}
}

func shellConnectFunc(self *shell, argArr any) {
	args := argArr.([]string)
	if len(args) < 1 {
		self.println("Usage: " + usageMap[ShellConnect])
		return
	}

	host := args[0]
	port := 389
	if self.connArgs.useTLS {
		port = 636
	}
	if self.connArgs.port != 0 {
		port = self.connArgs.port
	}
	if len(args) > 1 {
		fmt.Sscanf(args[1], "%d", &port)
	}

	if self.conn != nil {
		self.conn.Close()
		self.conn = nil
		self.authenticated = false
	}

	ca := *self.connArgs
	ca.host = host
	ca.port = port

	conn, err := connect(&ca)
	if err != nil {
		self.printf("Connection failed: %v\n", err)
		return
	}
	self.conn = conn
	self.connArgs.host = host
	self.connArgs.port = port
	self.authenticated = false
	self.printf("Connected to %s:%d\n", host, port)
}

func shellLoginFunc(self *shell, argArr any) {
	if self.conn == nil {
		self.println("No connection open. Use 'connect' first.")
		return
	}

	args := argArr.([]string)

	domain := self.connArgs.domain
	username := self.connArgs.user
	password := ""

	if len(args) > 0 {
		parts := strings.SplitN(args[0], "/", 2)
		if len(parts) == 2 {
			domain = parts[0]
			username = parts[1]
		} else {
			username = parts[0]
		}
	}
	if len(args) > 1 {
		password = args[1]
	} else {
		self.printf("Enter password: ")
		passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		self.println()
		if err != nil {
			self.printf("Error reading password: %v\n", err)
			return
		}
		password = string(passBytes)
	}

	saslSecurity := saslSecurityFromArgs(self.connArgs)

	_, err := self.conn.NTLMChallengeBind(&ldap.NTLMBindRequest{
		Domain:         domain,
		Username:       username,
		Password:       password,
		SASLSecurity:   saslSecurity,
		ChannelBinding: self.connArgs.channelBind,
	})
	if err != nil {
		self.printf("NTLM bind failed: %v\n", err)
		return
	}
	self.authenticated = true
	self.connArgs.domain = domain
	self.connArgs.user = username
	self.printf("[+] Logged in as %s/%s\n", domain, username)

	if self.baseDN == "" {
		if dn, err := detectBaseDN(self.conn, ncAttrFromNamingContext(self.connArgs.namingContext)); err == nil {
			self.baseDN = dn
			self.printf("Base DN: %s\n", self.baseDN)
		}
	}
}

func shellLoginKrbFunc(self *shell, argArr any) {
	if self.conn == nil {
		self.println("No connection open. Use 'connect' first.")
		return
	}

	args := argArr.([]string)

	username := self.connArgs.user
	realm := self.connArgs.realm
	password := ""
	ccachePath := self.connArgs.ccachePath

	if ccachePath != "" {
		// Use cached credentials — no username/password needed
	} else {
		if len(args) > 0 {
			parts := strings.SplitN(args[0], "/", 2)
			if len(parts) == 2 {
				realm = parts[0]
				username = parts[1]
			} else {
				username = parts[0]
			}
		}
		if len(args) > 1 {
			password = args[1]
		} else {
			self.printf("Enter password: ")
			passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
			self.println()
			if err != nil {
				self.printf("Error reading password: %v\n", err)
				return
			}
			password = string(passBytes)
		}
	}

	// Temporarily update connArgs for bind
	ca := *self.connArgs
	ca.user = username
	ca.realm = realm
	ca.pass = password
	ca.useKerberos = true

	err := bind(self.conn, &ca)
	if err != nil {
		self.printf("Kerberos bind failed: %v\n", err)
		return
	}
	self.authenticated = true
	self.printf("[+] Kerberos login successful\n")

	if self.baseDN == "" {
		if dn, err := detectBaseDN(self.conn, ncAttrFromNamingContext(self.connArgs.namingContext)); err == nil {
			self.baseDN = dn
			self.printf("Base DN: %s\n", self.baseDN)
		}
	}
}

func shellLogoutFunc(self *shell, argArr any) {
	if self.conn != nil {
		self.conn.Close()
		self.conn = nil
	}
	self.authenticated = false
	self.println("Disconnected.")
}

func shellToggleVerboseFunc(self *shell, argArr any) {
	if self.verbose {
		self.verbose = false
		self.println("Verbose mode deactivated!")
		return
	}
	self.verbose = true
	self.println("Verbose mode activated!")
}

func shellToggleBannerFunc(self *shell, argArr any) {
	if self.banner {
		self.banner = false
		self.println("Effective search banner disabled!")
		return
	}
	self.banner = true
	self.println("Effective search banner enabled!")
}

func shellSetBaseDNFunc(self *shell, argArr any) {
	args := argArr.([]string)
	if len(args) < 1 {
		self.printf("Current base DN: %s\n", self.baseDN)
		self.println("Usage: " + usageMap[ShellSetBaseDN])
		return
	}
	self.baseDN = args[0]
	self.printf("Base DN set to: %s\n", self.baseDN)
}

func (self *shell) cmdloop() {
	allKeys = append(allKeys, generalUsageKeys...)
	fmt.Println("Welcome to ldaptool!\nType 'help' for a list of commands")

	self.t = term.NewTerminal(os.Stdin, self.prompt)
	width, height, err := term.GetSize(int(os.Stdin.Fd()))
	if err == nil {
		if err = self.t.SetSize(width, height); err != nil {
			self.printf("Failed to set terminal size: %s\n", err)
		}
	}

	if useRawTerminal {
		oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
		if err != nil {
			self.println(err)
			return
		}
		defer term.Restore(int(os.Stdin.Fd()), oldState)

		if !self.noHistory {
			// Persistent history.
			if path := historyFilePath(); path != "" {
				self.t.History = newFileHistory(path)
			}
		}

		self.t.AutoCompleteCallback = func(line string, pos int, key rune) (newLine string, newPos int, ok bool) {
			if key != '\t' {
				return
			}
			before := line[:pos]
			after := line[pos:]
			// If the user is typing an attribute value to -attrs, complete
			// against the common-AD-attrs list. Honors comma-separated lists.
			if attrsPrefix, attrPart, isAttrs := lastAttrsToken(before); isAttrs {
				cands := completeAttrPrefix(attrPart)
				if len(cands) == 0 {
					return
				}
				cp := longestCommonPrefix(cands)
				if len(cp) > len(attrPart) {
					return attrsPrefix + cp + after, len(attrsPrefix) + len(cp), true
				}
				self.println()
				for _, c := range cands {
					self.printf("  %s\n", c)
				}
				return line, pos, true
			}

			completions := completer(before)
			if len(completions) == 0 {
				return
			}
			commonPrefix := longestCommonPrefix(completions)
			if len(commonPrefix) > pos {
				newLine = commonPrefix + after
				newPos = len(commonPrefix)
				ok = true
				return
			}
			self.println()
			for _, completion := range completions {
				self.printf("%s - %s\n", usageMap[completion], descriptionMap[completion])
			}
			return line, pos, true
		}
	}

	// Silence library logging to prevent interference with terminal output
	golog.Set("github.com/jfjallid/ldap/v3", "ldap", golog.LevelNone, 0, golog.NoOutput, golog.NoOutput)
	golog.Set("github.com/jfjallid/gokrb5/v8", "krb5", golog.LevelNone, 0, golog.NoOutput, golog.NoOutput)
	golog.Set("github.com/jfjallid/go-smb/ntlmssp", "ntlmssp", golog.LevelNone, 0, golog.NoOutput, golog.NoOutput)
	logger.SetLogLevel(golog.LevelNone)

	if self.conn != nil {
		defer self.conn.Close()
	}

OuterLoop:
	for {
		input, err := self.t.ReadLine()
		if err != nil {
			if err == io.EOF {
				break OuterLoop
			}
			self.printf("Error reading from stdin: %s\n", err)
			return
		}
		input = strings.TrimSpace(input)
		if strings.Compare(input, "exit") == 0 {
			break OuterLoop
		}
		cmd, rest, found := strings.Cut(input, " ")
		var args []string
		if found {
			parsed, err := parseArgs(rest)
			if err != nil {
				self.printf("parse error: %s\n", err)
				continue
			}
			args = parsed
		}
		cmd = strings.ToLower(cmd)
		if val, ok := handlers[cmd]; ok {
			fn, ok := val.(func(*shell, any))
			if !ok {
				self.println("Wrong function signature for registered handler")
			} else {
				fn(self, args)
			}
		} else if cmd != "" {
			self.printf("Unknown command: (%s)\n", input)
		}
	}
	self.t.SetPrompt("")
	self.println("Bye!")
}

// newShellFlagSet creates a flag.FlagSet for interactive commands that writes
// error output to the shell instead of os.Stderr.
func (self *shell) newFlagSet(name string) (*flag.FlagSet, *bytes.Buffer) {
	var buf bytes.Buffer
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(&buf)
	return fs, &buf
}
