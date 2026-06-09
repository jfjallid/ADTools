package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
	"github.com/jfjallid/gokrb5/v9/keytab"
	"golang.org/x/net/proxy"
)

// gpoFile describes one SYSVOL file relative to a GPO's policy folder.
type gpoFile struct {
	scope string // "Machine" | "User"
	rel   string // backslash-separated path under the scope folder
	kind  string // parser selector
}

// gpoFiles is the set of files read for every GPO. GptTmpl.inf is computer-only
// (security settings); the rest exist under both Machine and User.
var gpoFiles = []gpoFile{
	{"Machine", `Microsoft\Windows NT\SecEdit\GptTmpl.inf`, "gpttmpl"},
	{"Machine", `Registry.pol`, "registrypol"},
	{"Machine", `Preferences\Groups\Groups.xml`, "groups"},
	{"Machine", `Preferences\Registry\Registry.xml`, "registryxml"},
	{"Machine", `Preferences\ScheduledTasks\ScheduledTasks.xml`, "tasks"},
	{"Machine", `Preferences\Services\Services.xml`, "services"},
	{"Machine", `Preferences\DataSources\DataSources.xml`, "datasources"},
	{"Machine", `Preferences\Drives\Drives.xml`, "drives"},
	{"Machine", `Preferences\Files\Files.xml`, "files"},
	{"Machine", `Preferences\Shortcuts\Shortcuts.xml`, "shortcuts"},
	{"Machine", `Preferences\Printers\Printers.xml`, "printers"},
	{"Machine", `Preferences\EnvironmentVariables\EnvironmentVariables.xml`, "envvars"},
	{"Machine", `Scripts\scripts.ini`, "scripts"},
	{"Machine", `Scripts\psscripts.ini`, "psscripts"},
	{"User", `Registry.pol`, "registrypol"},
	{"User", `Preferences\Groups\Groups.xml`, "groups"},
	{"User", `Preferences\Registry\Registry.xml`, "registryxml"},
	{"User", `Preferences\ScheduledTasks\ScheduledTasks.xml`, "tasks"},
	{"User", `Preferences\DataSources\DataSources.xml`, "datasources"},
	{"User", `Preferences\Drives\Drives.xml`, "drives"},
	{"User", `Preferences\Files\Files.xml`, "files"},
	{"User", `Preferences\Shortcuts\Shortcuts.xml`, "shortcuts"},
	{"User", `Preferences\Printers\Printers.xml`, "printers"},
	{"User", `Preferences\EnvironmentVariables\EnvironmentVariables.xml`, "envvars"},
	{"User", `Scripts\scripts.ini`, "scripts"},
	{"User", `Scripts\psscripts.ini`, "psscripts"},
}

// fileSource abstracts reading GPO files from SYSVOL (over SMB) or from a local
// folder. read returns ok=false (and nil error) when the file is simply absent.
type fileSource interface {
	read(g *GPO, scope, rel string) (data []byte, ok bool, err error)
	Close()
}

// ---- SMB source ----------------------------------------------------------

type smbSource struct {
	conn *smb.Connection
}

// newSMBConnection opens an authenticated SMB session to the DC for SYSVOL
// access, reusing the same credentials/Kerberos material as the LDAP bind.
func newSMBConnection(args *connArgs) (*smb.Connection, error) {
	var hashBytes, aesKeyBytes []byte
	var err error
	if args.hash != "" {
		if hashBytes, err = hex.DecodeString(args.hash); err != nil {
			return nil, fmt.Errorf("decoding --hash: %w", err)
		}
	}
	if args.aesKey != "" {
		if aesKeyBytes, err = hex.DecodeString(args.aesKey); err != nil {
			return nil, fmt.Errorf("decoding --aes-key: %w", err)
		}
	}
	var kt *keytab.Keytab
	if args.keytabPath != "" {
		if kt, err = keytab.Load(args.keytabPath); err != nil {
			return nil, fmt.Errorf("loading keytab: %w", err)
		}
	}

	targetIP := args.targetIP
	if targetIP == "" {
		targetIP = args.host
	}
	if h, _, e := splitHostPortSafe(targetIP); e == nil {
		targetIP = h
	}

	var socksDialer proxy.Dialer
	if args.socksHost != "" {
		socksDialer, err = proxy.SOCKS5("tcp", fmt.Sprintf("%s:%d", args.socksHost, args.socksPort), nil, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("SOCKS5 init failed: %w", err)
		}
	}

	timeout := args.timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	var mech gss.Mechanism
	if args.useKerberos {
		// krb5ssp picks up a ccache via KRB5CCNAME on Linux; bridge --ccache.
		if args.ccachePath != "" {
			os.Setenv("KRB5CCNAME", args.ccachePath)
		}
		mech = &spnego.KRB5Initiator{
			User:        args.user,
			Password:    args.pass,
			Domain:      args.domain,
			Hash:        hashBytes,
			AESKey:      aesKeyBytes,
			Keytab:      kt,
			SPN:         "cifs/" + args.host,
			DCIP:        args.dcIP,
			DialTimeout: timeout,
			ProxyDialer: socksDialer,
			DnsHost:     args.dnsHost,
			DnsTCP:      args.dnsTCP,
			Host:        targetIP,
		}
	} else {
		mech = &spnego.NTLMInitiator{
			User:        args.user,
			Password:    args.pass,
			Hash:        hashBytes,
			Domain:      args.domain,
			NullSession: args.noPass && args.user == "",
		}
	}

	smbPort := args.smbPort
	if smbPort == 0 {
		smbPort = 445
	}
	opts := smb.Options{
		Host:              targetIP,
		Port:              smbPort,
		Domain:            args.domain,
		User:              args.user,
		Password:          args.pass,
		Hash:              args.hash,
		ForceSMB2:         args.forceSMB2,
		DialTimeout:       timeout,
		ProxyDialer:       socksDialer,
		DisableEncryption: args.noenc,
		Initiator:         mech,
	}
	conn, err := smb.NewConnection(opts)
	if err != nil {
		return nil, fmt.Errorf("SMB connect to %s:%d failed: %w", targetIP, smbPort, err)
	}
	if !conn.IsAuthenticated() {
		conn.Close()
		return nil, fmt.Errorf("SMB authentication failed")
	}
	logger.Infof("[+] SMB session established as %s\n", conn.GetAuthUsername())
	return conn, nil
}

func (s *smbSource) read(g *GPO, scope, rel string) ([]byte, bool, error) {
	share, within := splitUNCShare(g.FileSysPath)
	if share == "" {
		// Fall back to the default SYSVOL layout if gPCFileSysPath is empty.
		return nil, false, fmt.Errorf("GPO %s has no gPCFileSysPath", g.GUID)
	}
	full := within + `\` + scope + `\` + rel
	var buf bytes.Buffer
	err := s.conn.RetrieveFile(share, full, 0, func(b []byte) (int, error) {
		return buf.Write(b)
	})
	if err != nil {
		if isNotFoundErr(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return buf.Bytes(), true, nil
}

// queryACL opens path on share requesting only READ_CONTROL and returns its
// parsed security descriptor. ok=false (nil error) when the path is absent.
func (s *smbSource) queryACL(share, path string) (*msdtyp.SecurityDescriptor, bool, error) {
	f, err := s.conn.OpenFileReadAttributes(share, path)
	if err != nil {
		if isNotFoundErr(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	defer f.CloseFile()
	sd, err := f.QueryInfoSecurityRaw(
		smb.OwnerSecurityInformation|smb.GroupSecurityInformation|smb.DACLSecurityInformation, 0)
	if err != nil {
		if isNotFoundErr(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return sd, true, nil
}

func (s *smbSource) Close() {
	if s.conn != nil {
		s.conn.Close()
	}
}

func isNotFoundErr(err error) bool {
	if err == nil {
		return false
	}
	for _, st := range []uint32{smb.StatusObjectNameNotFound, smb.StatusObjectPathNotFound, smb.StatusNoSuchFile} {
		if mapped, ok := smb.StatusMap[st]; ok && err == mapped {
			return true
		}
	}
	// Be lenient about wording differences across go-smb versions.
	msg := strings.ToUpper(err.Error())
	return strings.Contains(msg, "NOT EXIST") || strings.Contains(msg, "NO SUCH FILE") ||
		strings.Contains(msg, "NOT FOUND")
}

func splitHostPortSafe(s string) (string, string, error) {
	if !strings.Contains(s, ":") {
		return s, "", fmt.Errorf("no port")
	}
	i := strings.LastIndex(s, ":")
	return s[:i], s[i+1:], nil
}

// ---- local filesystem source ---------------------------------------------

type localSource struct {
	policiesDir string // directory containing {GUID} subfolders
}

// newLocalSource locates the SYSVOL "Policies" directory under root. root may
// itself be the Policies dir, a SYSVOL share copy, or a parent of either.
func newLocalSource(root string) (*localSource, error) {
	dir, err := findPoliciesDir(root)
	if err != nil {
		return nil, err
	}
	logger.Infof("[*] Using SYSVOL policies directory: %s\n", dir)
	return &localSource{policiesDir: dir}, nil
}

// findPoliciesDir returns root if it already holds {GUID} folders, otherwise the
// first descendant directory named "Policies".
func findPoliciesDir(root string) (string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return "", fmt.Errorf("sysvol path %q: %w", root, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("sysvol path %q is not a directory", root)
	}
	if base := filepath.Base(root); strings.EqualFold(base, "Policies") {
		return root, nil
	}
	if hasGUIDChild(root) {
		return root, nil
	}
	var found string
	filepath.Walk(root, func(path string, fi os.FileInfo, err error) error {
		if err != nil || found != "" {
			return nil
		}
		if fi.IsDir() && strings.EqualFold(fi.Name(), "Policies") {
			found = path
		}
		return nil
	})
	if found != "" {
		return found, nil
	}
	// Last resort: use root as-is.
	return root, nil
}

func hasGUIDChild(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "{") && strings.HasSuffix(e.Name(), "}") {
			return true
		}
	}
	return false
}

func (s *localSource) read(g *GPO, scope, rel string) ([]byte, bool, error) {
	components := append([]string{g.GUID, scope}, strings.Split(rel, `\`)...)
	path, ok := resolveCaseInsensitive(s.policiesDir, components)
	if !ok {
		return nil, false, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return data, true, nil
}

func (s *localSource) Close() {}

// resolveCaseInsensitive walks components beneath root, matching each path
// element case-insensitively (SYSVOL copies often differ in case from the
// canonical names). Returns the resolved path and whether it was found.
func resolveCaseInsensitive(root string, components []string) (string, bool) {
	cur := root
	for _, want := range components {
		// Fast path: exact match.
		candidate := filepath.Join(cur, want)
		if _, err := os.Stat(candidate); err == nil {
			cur = candidate
			continue
		}
		entries, err := os.ReadDir(cur)
		if err != nil {
			return "", false
		}
		matched := ""
		for _, e := range entries {
			if strings.EqualFold(e.Name(), want) {
				matched = e.Name()
				break
			}
		}
		if matched == "" {
			return "", false
		}
		cur = filepath.Join(cur, matched)
	}
	return cur, true
}
