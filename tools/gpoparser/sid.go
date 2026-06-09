package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jfjallid/go-smb/msdtyp"
	ldap "github.com/jfjallid/ldap/v3"
)

// wellKnownSIDs maps universal (non domain-relative) SIDs to friendly names.
var wellKnownSIDs = map[string]string{
	"S-1-0-0":      "Null",
	"S-1-1-0":      "Everyone",
	"S-1-2-0":      "Local",
	"S-1-3-0":      "Creator Owner",
	"S-1-3-1":      "Creator Group",
	"S-1-5-2":      "Network",
	"S-1-5-4":      "Interactive",
	"S-1-5-6":      "Service",
	"S-1-5-7":      "Anonymous",
	"S-1-5-9":      "Enterprise Domain Controllers",
	"S-1-5-10":     "Principal Self",
	"S-1-5-11":     "Authenticated Users",
	"S-1-5-12":     "Restricted Code",
	"S-1-5-13":     "Terminal Server Users",
	"S-1-5-14":     "Remote Interactive Logon",
	"S-1-5-15":     "This Organization",
	"S-1-5-17":     "IUSR",
	"S-1-5-18":     "Local System",
	"S-1-5-19":     "Local Service",
	"S-1-5-20":     "Network Service",
	"S-1-5-32-544": "BUILTIN\\Administrators",
	"S-1-5-32-545": "BUILTIN\\Users",
	"S-1-5-32-546": "BUILTIN\\Guests",
	"S-1-5-32-547": "BUILTIN\\Power Users",
	"S-1-5-32-548": "BUILTIN\\Account Operators",
	"S-1-5-32-549": "BUILTIN\\Server Operators",
	"S-1-5-32-550": "BUILTIN\\Print Operators",
	"S-1-5-32-551": "BUILTIN\\Backup Operators",
	"S-1-5-32-552": "BUILTIN\\Replicator",
	"S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
	"S-1-5-32-556": "BUILTIN\\Network Configuration Operators",
	"S-1-5-32-559": "BUILTIN\\Performance Log Users",
	"S-1-5-32-562": "BUILTIN\\Distributed COM Users",
	"S-1-5-32-568": "BUILTIN\\IIS_IUSRS",
	"S-1-5-32-569": "BUILTIN\\Cryptographic Operators",
	"S-1-5-32-573": "BUILTIN\\Event Log Readers",
	"S-1-5-32-578": "BUILTIN\\Hyper-V Administrators",
	"S-1-5-32-579": "BUILTIN\\Access Control Assistance Operators",
	"S-1-5-32-580": "BUILTIN\\Remote Management Users",
}

// domainRelativeRIDNames maps the trailing RID of a domain SID to a name, used
// when we know a SID is domain-relative but have no LDAP connection.
var domainRelativeRIDNames = map[string]string{
	"498": "Enterprise Read-only Domain Controllers",
	"500": "Administrator",
	"501": "Guest",
	"502": "krbtgt",
	"512": "Domain Admins",
	"513": "Domain Users",
	"514": "Domain Guests",
	"515": "Domain Computers",
	"516": "Domain Controllers",
	"517": "Cert Publishers",
	"518": "Schema Admins",
	"519": "Enterprise Admins",
	"520": "Group Policy Creator Owners",
	"521": "Read-only Domain Controllers",
	"525": "Protected Users",
	"526": "Key Admins",
	"527": "Enterprise Key Admins",
}

// Local-group RIDs that BloodHound turns into native edges.
const (
	ridAdministrators      = 544 // -> AdminTo / LocalAdmins
	ridRemoteDesktopUsers  = 555 // -> CanRDP / RemoteDesktopUsers
	ridDistributedCOMUsers = 562 // -> ExecuteDCOM / DcomUsers
	ridRemoteMgmtUsers     = 580 // -> CanPSRemote / PSRemoteUsers
)

// dangerousPrivileges flags user rights that commonly enable privilege
// escalation or credential theft when granted to non-admin principals.
var dangerousPrivileges = map[string]string{
	"SeDebugPrivilege":                "Debug programs — read/write any process memory (LSASS dumping, token theft)",
	"SeBackupPrivilege":               "Back up files — read any file bypassing ACLs (SAM/SYSTEM, NTDS.dit)",
	"SeRestorePrivilege":              "Restore files — write any file bypassing ACLs",
	"SeTakeOwnershipPrivilege":        "Take ownership of any securable object",
	"SeImpersonatePrivilege":          "Impersonate a client after authentication (potato attacks)",
	"SeAssignPrimaryTokenPrivilege":   "Replace a process-level token",
	"SeLoadDriverPrivilege":           "Load and unload device drivers (kernel code execution)",
	"SeTcbPrivilege":                  "Act as part of the operating system",
	"SeCreateTokenPrivilege":          "Create a token object",
	"SeEnableDelegationPrivilege":     "Enable computer/user accounts to be trusted for delegation",
	"SeManageVolumePrivilege":         "Manage the files on a volume (raw disk read)",
	"SeRelabelPrivilege":              "Modify an object label",
	"SeSecurityPrivilege":             "Manage auditing and security log",
	"SeSyncAgentPrivilege":            "Synchronize directory service data (DCSync-adjacent)",
	"SeTrustedCredManAccessPrivilege": "Access Credential Manager as a trusted caller",
	"SeMachineAccountPrivilege":       "Add workstations to the domain (abused for resource-based constrained delegation)",
	"SeCreateSymbolicLinkPrivilege":   "Create symbolic links (local privilege escalation via symlink attacks)",
	"SeRemoteInteractiveLogonRight":   "Log on remotely via Remote Desktop",
}

func privilegeDescription(name string) string { return dangerousPrivileges[name] }
func isDangerousPrivilege(name string) bool {
	_, ok := dangerousPrivileges[name]
	return ok
}

// lowPrivSIDs are universal SIDs representing large, low-trust populations.
// Granting a powerful right to one of these is the strongest "anyone can" signal.
var lowPrivSIDs = map[string]bool{
	"S-1-1-0":      true, // Everyone
	"S-1-5-7":      true, // Anonymous
	"S-1-5-11":     true, // Authenticated Users
	"S-1-5-2":      true, // Network
	"S-1-5-4":      true, // Interactive
	"S-1-5-32-545": true, // BUILTIN\Users
	"S-1-5-32-546": true, // BUILTIN\Guests
}

// lowPrivRIDs are domain-relative RIDs representing low-trust populations.
var lowPrivRIDs = map[int]bool{
	513: true, // Domain Users
	514: true, // Domain Guests
	515: true, // Domain Computers
}

// adminEquivalentSIDs / adminEquivalentRIDs identify principals already expected
// to hold powerful rights, so granting those rights to them is not a finding.
var adminEquivalentSIDs = map[string]bool{
	"S-1-5-18":     true, // Local System
	"S-1-5-32-544": true, // BUILTIN\Administrators
}
var adminEquivalentRIDs = map[int]bool{
	500: true, // Administrator
	512: true, // Domain Admins
	518: true, // Schema Admins
	519: true, // Enterprise Admins
	520: true, // Group Policy Creator Owners
}

// ridOf returns the trailing RID of a SID, or -1 if it has none.
func ridOf(sid string) int {
	sid = strings.TrimSpace(sid)
	i := strings.LastIndex(sid, "-")
	if i < 0 {
		return -1
	}
	n, err := strconv.Atoi(sid[i+1:])
	if err != nil {
		return -1
	}
	return n
}

// isLowPrivPrincipal reports whether sid names a large low-trust population.
func isLowPrivPrincipal(sid string) bool {
	u := strings.ToUpper(strings.TrimSpace(sid))
	if lowPrivSIDs[u] {
		return true
	}
	if strings.HasPrefix(u, "S-1-5-21-") {
		return lowPrivRIDs[ridOf(u)]
	}
	return false
}

// isAdminEquivalent reports whether sid is an administrator-equivalent principal.
func isAdminEquivalent(sid string) bool {
	u := strings.ToUpper(strings.TrimSpace(sid))
	if adminEquivalentSIDs[u] {
		return true
	}
	if strings.HasPrefix(u, "S-1-5-21-") {
		return adminEquivalentRIDs[ridOf(u)]
	}
	return false
}

// isExpectedPrivHolder reports whether granting priv to sid is expected default
// configuration: administrators always, and the built-in service accounts for
// the impersonation rights they legitimately hold.
func isExpectedPrivHolder(sid, priv string) bool {
	if isAdminEquivalent(sid) {
		return true
	}
	switch priv {
	case "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege", "SeCreateGlobalPrivilege":
		switch strings.ToUpper(strings.TrimSpace(sid)) {
		case "S-1-5-6", "S-1-5-19", "S-1-5-20": // Service, Local Service, Network Service
			return true
		}
	}
	return false
}

// isPrivilegedGroup reports whether p is a high-value group worth scrutinising
// when members are added to it (admin-equivalent or remote-access groups).
func isPrivilegedGroup(p Principal) bool {
	switch ridOf(p.SID) {
	case 544, 548, 549, 550, 551, // BUILTIN admins/operators
		512, 518, 519, 520, // domain admin groups
		555, 562, 580: // Remote Desktop / DCOM / Remote Management Users
		return true
	}
	n := strings.ToLower(p.Name)
	return strings.Contains(n, "admins") || strings.Contains(n, "administrators")
}

// wellKnownSIDName returns a friendly name for a SID using only static tables.
func wellKnownSIDName(sid string) string {
	sid = strings.ToUpper(strings.TrimSpace(sid))
	if n, ok := wellKnownSIDs[sid]; ok {
		return n
	}
	// Domain-relative: S-1-5-21-<domain>-<RID>
	if strings.HasPrefix(sid, "S-1-5-21-") {
		if i := strings.LastIndex(sid, "-"); i >= 0 {
			if n, ok := domainRelativeRIDNames[sid[i+1:]]; ok {
				return n
			}
		}
	}
	return ""
}

// principalFromSID builds a Principal, filling Name from the well-known tables
// when possible (LDAP resolution happens separately via sidResolver).
func principalFromSID(sid string) Principal {
	return Principal{SID: strings.TrimSpace(sid), Name: wellKnownSIDName(sid)}
}

// encodeSID converts a string SID to its binary form for LDAP filters.
func encodeSID(sid string) ([]byte, error) {
	s, err := msdtyp.ConvertStrToSID(sid)
	if err != nil {
		return nil, err
	}
	return s.MarshalBinary()
}

// ldapBinaryFilter renders raw bytes as an RFC 4515 \xx-escaped assertion value.
func ldapBinaryFilter(b []byte) string {
	var sb strings.Builder
	for _, v := range b {
		fmt.Fprintf(&sb, "\\%02x", v)
	}
	return sb.String()
}

// sidResolver translates SIDs and account names to friendly names / SIDs on
// demand against LDAP, caching results. Well-known SIDs resolve without LDAP.
type sidResolver struct {
	conn      *ldap.Conn
	baseDN    string
	domainSID string
	cache     map[string]string // sid -> name
	nameCache map[string]string // lower(name) -> sid
}

func newSIDResolver(conn *ldap.Conn, baseDN, domainSID string) *sidResolver {
	return &sidResolver{
		conn: conn, baseDN: baseDN, domainSID: domainSID,
		cache: map[string]string{}, nameCache: map[string]string{},
	}
}

// name returns a friendly name for a SID, or "" if unknown.
func (r *sidResolver) name(sid string) string {
	sid = strings.TrimSpace(sid)
	if n := wellKnownSIDName(sid); n != "" {
		return n
	}
	if r == nil || r.conn == nil {
		return ""
	}
	if n, ok := r.cache[sid]; ok {
		return n
	}
	n := r.lookupName(sid)
	r.cache[sid] = n
	return n
}

// enrich fills in p.Name (and p.SID) from LDAP/well-known tables where missing.
func (r *sidResolver) enrich(p Principal) Principal {
	if p.SID != "" && p.Name == "" {
		p.Name = r.name(p.SID)
	}
	if p.SID == "" && p.Name != "" {
		p.SID = r.sidForName(p.Name)
	}
	return p
}

func (r *sidResolver) lookupName(sid string) string {
	sidBytes, err := encodeSID(sid)
	if err != nil {
		return ""
	}
	res, err := r.conn.Search(ldap.NewSearchRequest(
		r.baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(objectSid="+ldapBinaryFilter(sidBytes)+")",
		[]string{"sAMAccountName", "name"}, nil,
	))
	if err != nil || len(res.Entries) == 0 {
		return ""
	}
	e := res.Entries[0]
	if v := e.GetAttributeValue("sAMAccountName"); v != "" {
		return v
	}
	return e.GetAttributeValue("name")
}

// sidForName resolves a sAMAccountName (optionally DOMAIN\name) to a SID.
func (r *sidResolver) sidForName(name string) string {
	if r == nil || r.conn == nil {
		return ""
	}
	sam := name
	if i := strings.LastIndex(name, "\\"); i >= 0 {
		sam = name[i+1:]
	}
	key := strings.ToLower(sam)
	if s, ok := r.nameCache[key]; ok {
		return s
	}
	res, err := r.conn.Search(ldap.NewSearchRequest(
		r.baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(sAMAccountName="+ldap.EscapeFilter(sam)+")",
		[]string{"objectSid"}, nil,
	))
	sid := ""
	if err == nil && len(res.Entries) > 0 {
		for _, attr := range res.Entries[0].Attributes {
			if strings.EqualFold(attr.Name, "objectSid") && len(attr.ByteValues) > 0 {
				s := &msdtyp.SID{}
				if e := s.UnmarshalBinary(attr.ByteValues[0]); e == nil {
					sid = s.ToString()
				}
			}
		}
	}
	r.nameCache[key] = sid
	return sid
}
