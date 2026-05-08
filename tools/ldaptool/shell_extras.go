package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	ldap "github.com/jfjallid/ldap/v3"
)

// ---- shell history --------------------------------------------------------

const historyMaxLines = 1000

// fileHistory wraps the term.Terminal History interface and persists every
// added line to ~/.ldaptool_history. Latest entries are at index 0.
type fileHistory struct {
	mu      sync.Mutex
	lines   []string // index 0 is most-recent
	path    string
	maxSize int
}

func newFileHistory(path string) *fileHistory {
	h := &fileHistory{path: path, maxSize: historyMaxLines}
	h.load()
	return h
}

func (h *fileHistory) load() {
	f, err := os.Open(h.path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		// File order is oldest → newest, but in-memory index 0 is most-recent.
		h.lines = append([]string{line}, h.lines...)
	}
}

func (h *fileHistory) Add(entry string) {
	if entry == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	// Drop adjacent duplicate.
	if len(h.lines) > 0 && h.lines[0] == entry {
		return
	}
	h.lines = append([]string{entry}, h.lines...)
	if len(h.lines) > h.maxSize {
		h.lines = h.lines[:h.maxSize]
	}
	// Append to file lazily; ignore IO errors, history is best-effort.
	if h.path == "" {
		return
	}
	f, err := os.OpenFile(h.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintln(f, entry)
}

func (h *fileHistory) Len() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.lines)
}

func (h *fileHistory) At(idx int) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lines[idx]
}

// historyFilePath resolves the history file path. Honors $LDAPTOOL_HISTORY
// for callers who want it elsewhere or disabled (empty value).
func historyFilePath() string {
	if v, ok := os.LookupEnv("LDAPTOOL_HISTORY"); ok {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".ldaptool_history")
}

// ---- describe / tls / reconnect commands ----------------------------------

const (
	ShellDescribe  = "describe"
	ShellTLS       = "tls"
	ShellReconnect = "reconnect"
)

func init() {
	usageMap[ShellDescribe] = ShellDescribe + " <dn>"
	descriptionMap[ShellDescribe] = "Base-scope dump of a single DN"
	handlers[ShellDescribe] = shellDescribeCmd

	usageMap[ShellTLS] = ShellTLS + " on|off"
	descriptionMap[ShellTLS] = "Toggle TLS for subsequent connections (does not change the current one)"
	handlers[ShellTLS] = shellTLSCmd

	usageMap[ShellReconnect] = ShellReconnect
	descriptionMap[ShellReconnect] = "Reopen the connection to the current host with the current settings"
	handlers[ShellReconnect] = shellReconnectCmd

	generalUsageKeys = append(generalUsageKeys, ShellDescribe, ShellTLS, ShellReconnect)
}

func shellDescribeCmd(self *shell, argArr any) {
	if self.conn == nil || !self.authenticated {
		self.println("Not connected. Use 'connect' and 'login' first.")
		return
	}
	args := argArr.([]string)
	if len(args) < 1 {
		self.println("Usage: " + usageMap[ShellDescribe])
		return
	}
	dn := args[0]
	res, err := self.conn.Search(ldap.NewSearchRequest(
		dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"*", "+"}, nil,
	))
	if err != nil {
		self.printf("describe failed: %v\n", err)
		return
	}
	loadSchemaBinaryAttrs(self.conn, res.Entries)
	w := &shellWriter{s: self}
	writeHuman(w, res.Entries)
}

func shellTLSCmd(self *shell, argArr any) {
	args := argArr.([]string)
	if len(args) < 1 {
		state := "off"
		if self.connArgs.useTLS {
			state = "on"
		}
		self.printf("TLS for new connections: %s\n", state)
		self.println("Usage: " + usageMap[ShellTLS])
		return
	}
	switch strings.ToLower(args[0]) {
	case "on":
		self.connArgs.useTLS = true
		self.connArgs.startTLS = false
		self.println("TLS will be used for the next connection. Run 'reconnect' to apply.")
	case "off":
		self.connArgs.useTLS = false
		self.connArgs.startTLS = false
		self.println("TLS disabled for the next connection. Run 'reconnect' to apply.")
	case "starttls":
		self.connArgs.useTLS = false
		self.connArgs.startTLS = true
		self.println("StartTLS will be used for the next connection. Run 'reconnect' to apply.")
	default:
		self.printf("unknown tls mode %q (want on, off, or starttls)\n", args[0])
	}
}

func shellReconnectCmd(self *shell, argArr any) {
	if self.connArgs.host == "" {
		self.println("No host configured; use 'connect <host>' first.")
		return
	}
	if self.conn != nil {
		self.conn.Close()
		self.conn = nil
		self.authenticated = false
	}
	conn, err := connect(self.connArgs)
	if err != nil {
		self.printf("Reconnect failed: %v\n", err)
		return
	}
	self.conn = conn
	self.authenticated = false
	self.printf("Reconnected to %s:%d (use 'login' to authenticate)\n", self.connArgs.host, self.connArgs.port)
}

// ---- richer tab completion ------------------------------------------------

// commonADAttrs is a static list used for tab-completing values to -attrs.
// Not exhaustive — the goal is to cut typing for the common cases.
var commonADAttrs = []string{
	"accountExpires", "adminCount", "badPwdCount", "cn", "company",
	"description", "displayName", "distinguishedName", "dNSHostName",
	"employeeID", "givenName", "groupType", "instanceType", "l",
	"lastLogon", "lastLogonTimestamp", "mail", "manager", "member",
	"memberOf", "msDS-AllowedToActOnBehalfOfOtherIdentity",
	"msDS-AllowedToDelegateTo", "msDS-KeyCredentialLink",
	"msDS-SupportedEncryptionTypes", "msLAPS-EncryptedPassword",
	"msLAPS-Password", "ms-Mcs-AdmPwd", "name", "nTSecurityDescriptor",
	"objectClass", "objectGUID", "objectSid", "operatingSystem",
	"operatingSystemVersion", "primaryGroupID", "pwdLastSet",
	"sAMAccountName", "sAMAccountType", "samAccountType",
	"servicePrincipalName", "sn", "telephoneNumber",
	"unicodePwd", "userAccountControl", "userPrincipalName",
	"whenChanged", "whenCreated",
}

// lastAttrsToken inspects the line up to the cursor and, if the user is
// currently typing the value of -attrs, returns (everything-up-to-current-attr,
// current-attr-prefix, true). The caller can splice a completion in place.
func lastAttrsToken(before string) (lead, attrPrefix string, ok bool) {
	flag := "-attrs "
	idx := strings.LastIndex(before, flag)
	if idx < 0 {
		flag = "--attrs "
		idx = strings.LastIndex(before, flag)
	}
	if idx < 0 {
		return "", "", false
	}
	// Anything after a space following "-attrs " ends the value, so abort
	// completion if we've moved past it.
	value := before[idx+len(flag):]
	if i := strings.IndexAny(value, " \t"); i >= 0 {
		return "", "", false
	}
	commaIdx := strings.LastIndexByte(value, ',')
	if commaIdx < 0 {
		return before[:idx+len(flag)], value, true
	}
	return before[:idx+len(flag)+commaIdx+1], value[commaIdx+1:], true
}

// completeAttrPrefix returns matching attribute names for tab completion of
// -attrs values. The prefix may be the part after the last comma so the user
// can keep typing comma-separated lists.
func completeAttrPrefix(prefix string) []string {
	prefixLow := strings.ToLower(prefix)
	var out []string
	for _, a := range commonADAttrs {
		if strings.HasPrefix(strings.ToLower(a), prefixLow) {
			out = append(out, a)
		}
	}
	return out
}
