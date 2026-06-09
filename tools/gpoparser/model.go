package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// cacheVersion is bumped whenever the on-disk schema changes incompatibly.
const cacheVersion = 1

// Cache is the full analysed dataset written by `remote`/`local` and consumed
// by `display`, `query` and `enrich`.
type Cache struct {
	Version    int         `json:"version"`
	Generated  time.Time   `json:"generated"`
	Domain     string      `json:"domain,omitempty"`      // short name, e.g. CORP
	DomainFQDN string      `json:"domain_fqdn,omitempty"` // e.g. corp.local
	BaseDN     string      `json:"base_dn,omitempty"`
	DomainSID  string      `json:"domain_sid,omitempty"`
	GPOs       []*GPO      `json:"gpos"`
	OUs        []*OU       `json:"ous"`       // link containers: domain root, OUs, sites
	Computers  []*Computer `json:"computers"` // computer objects (for the "where" mapping)
}

// Principal is a reference to a security principal, by SID and/or name.
type Principal struct {
	SID  string `json:"sid,omitempty"`
	Name string `json:"name,omitempty"`
}

func (p Principal) String() string {
	switch {
	case p.Name != "" && p.SID != "":
		return fmt.Sprintf("%s (%s)", p.Name, p.SID)
	case p.Name != "":
		return p.Name
	default:
		return p.SID
	}
}

// ConfigSettings holds the parsed settings for one configuration scope
// (Computer or User) of a GPO.
type ConfigSettings struct {
	GroupMemberships []GroupMembership `json:"group_memberships,omitempty"`
	Privileges       []PrivilegeRight  `json:"privileges,omitempty"`
	RegistryValues   []RegistrySetting `json:"registry_values,omitempty"`
	SystemAccess     []KeyValue        `json:"system_access,omitempty"`
	Services         []ServiceSetting  `json:"services,omitempty"`
	Scripts          []ScriptEntry     `json:"scripts,omitempty"`
	ScheduledTasks   []ScheduledTask   `json:"scheduled_tasks,omitempty"`
	LocalUsers       []LocalUser       `json:"local_users,omitempty"`
	DataSources      []DataSource      `json:"data_sources,omitempty"`
	Drives           []Drive           `json:"drives,omitempty"`
	Files            []FileDeploy      `json:"files,omitempty"`
	Shortcuts        []Shortcut        `json:"shortcuts,omitempty"`
	Printers         []Printer         `json:"printers,omitempty"`
	EnvVars          []EnvVar          `json:"env_vars,omitempty"`
	SoftwareInstalls []SoftwareInstall `json:"software_installs,omitempty"`
}

func (c ConfigSettings) empty() bool {
	return len(c.GroupMemberships) == 0 && len(c.Privileges) == 0 &&
		len(c.RegistryValues) == 0 && len(c.SystemAccess) == 0 &&
		len(c.Services) == 0 && len(c.Scripts) == 0 && len(c.ScheduledTasks) == 0 &&
		len(c.LocalUsers) == 0 && len(c.DataSources) == 0 && len(c.Drives) == 0 &&
		len(c.Files) == 0 && len(c.Shortcuts) == 0 && len(c.Printers) == 0 &&
		len(c.EnvVars) == 0 && len(c.SoftwareInstalls) == 0
}

// GroupMembership records principals added to (or set as) members of a local
// or domain group, sourced from GptTmpl.inf [Group Membership] or GPP Groups.xml.
type GroupMembership struct {
	Source   string      `json:"source"`              // "gpttmpl" | "gpp"
	Action   string      `json:"action,omitempty"`    // ADD/UPDATE/REPLACE/DELETE
	Group    Principal   `json:"group"`               // the target group
	Members  []Principal `json:"members,omitempty"`   // members added to Group
	MemberOf []Principal `json:"member_of,omitempty"` // groups Group is made a member of (gpttmpl __Memberof)
}

// PrivilegeRight records the principals granted a user right (GptTmpl.inf
// [Privilege Rights]).
type PrivilegeRight struct {
	Privilege   string      `json:"privilege"` // e.g. SeDebugPrivilege
	Description string      `json:"description,omitempty"`
	Members     []Principal `json:"members"`
	Dangerous   bool        `json:"dangerous,omitempty"`
}

// RegistrySetting records a registry change from Registry.pol, GPP Registry.xml
// or GptTmpl.inf [Registry Values].
type RegistrySetting struct {
	Source string `json:"source"`           // "registry.pol" | "gpp" | "gpttmpl"
	Action string `json:"action,omitempty"` // Create/Update/Replace/Delete (GPP)
	Hive   string `json:"hive,omitempty"`
	Key    string `json:"key"`
	Name   string `json:"name,omitempty"`
	Type   string `json:"type,omitempty"`
	Value  string `json:"value,omitempty"`
}

// ServiceSetting records a service configuration (GptTmpl.inf [Service General
// Setting] or GPP Services.xml).
type ServiceSetting struct {
	Source    string `json:"source"`
	Name      string `json:"name"`
	StartType string `json:"start_type,omitempty"`
	Action    string `json:"action,omitempty"`
	Account   string `json:"account,omitempty"`
	CPassword string `json:"cpassword,omitempty"` // GPP encrypted password (MS14-025)
	SDDL      string `json:"sddl,omitempty"`
}

// LocalUser records a local user account managed by GPP Groups.xml (<User>),
// which can embed a reversibly-encrypted password (cpassword / MS14-025).
type LocalUser struct {
	Name      string `json:"name"`
	UserName  string `json:"user_name,omitempty"`
	Action    string `json:"action,omitempty"`
	CPassword string `json:"cpassword,omitempty"`
}

// DataSource records a GPP ODBC data source (DataSources.xml); the connection
// account may carry a cpassword.
type DataSource struct {
	Name      string `json:"name"`
	DSN       string `json:"dsn,omitempty"`
	Driver    string `json:"driver,omitempty"`
	UserName  string `json:"user_name,omitempty"`
	Action    string `json:"action,omitempty"`
	CPassword string `json:"cpassword,omitempty"`
}

// Drive records a GPP mapped drive (Drives.xml); may carry connection creds.
type Drive struct {
	Letter    string `json:"letter,omitempty"`
	Path      string `json:"path,omitempty"`
	UserName  string `json:"user_name,omitempty"`
	Action    string `json:"action,omitempty"`
	CPassword string `json:"cpassword,omitempty"`
}

// FileDeploy records a GPP file copy (Files.xml). A writable fromPath means an
// attacker controls the file pushed to clients.
type FileDeploy struct {
	FromPath   string `json:"from_path,omitempty"`
	TargetPath string `json:"target_path,omitempty"`
	Action     string `json:"action,omitempty"`
}

// Shortcut records a GPP shortcut (Shortcuts.xml).
type Shortcut struct {
	Name       string `json:"name"`
	TargetPath string `json:"target_path,omitempty"`
	Arguments  string `json:"arguments,omitempty"`
	StartIn    string `json:"start_in,omitempty"`
	Action     string `json:"action,omitempty"`
}

// Printer records a GPP printer (Printers.xml); shared printers may carry creds.
type Printer struct {
	Name      string `json:"name"`
	Path      string `json:"path,omitempty"`
	UserName  string `json:"user_name,omitempty"`
	Action    string `json:"action,omitempty"`
	CPassword string `json:"cpassword,omitempty"`
}

// EnvVar records a GPP environment variable (EnvironmentVariables.xml).
type EnvVar struct {
	Name   string `json:"name"`
	Value  string `json:"value,omitempty"`
	Action string `json:"action,omitempty"`
}

// SoftwareInstall records an MSI software-installation package
// (packageRegistration objects under the GPO in AD).
type SoftwareInstall struct {
	Name        string `json:"name"`
	Path        string `json:"path,omitempty"` // MSI file path (often UNC)
	PackageType string `json:"package_type,omitempty"`
}

// ScriptEntry records a logon/logoff/startup/shutdown script (scripts.ini or
// psscripts.ini).
type ScriptEntry struct {
	Type       string `json:"type"` // Logon/Logoff/Startup/Shutdown
	Order      int    `json:"order"`
	CmdLine    string `json:"cmdline"`
	Parameters string `json:"parameters,omitempty"`
	PowerShell bool   `json:"powershell,omitempty"`
}

// ScheduledTask records a GPP scheduled/immediate task (ScheduledTasks.xml).
type ScheduledTask struct {
	Name      string `json:"name"`
	Type      string `json:"type,omitempty"`   // Task/ImmediateTask/TaskV2/ImmediateTaskV2
	Action    string `json:"action,omitempty"` // Create/Replace/Update/Delete
	Command   string `json:"command,omitempty"`
	Arguments string `json:"arguments,omitempty"`
	RunAs     string `json:"run_as,omitempty"`
	CPassword string `json:"cpassword,omitempty"` // GPP encrypted password (MS14-025)
}

// KeyValue is a generic name/value pair (e.g. [System Access] entries).
type KeyValue struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// GPO is one groupPolicyContainer plus its parsed SYSVOL settings and the set
// of computers it ends up applying to.
type GPO struct {
	GUID        string `json:"guid"` // {........-....-....-....-............}
	Name        string `json:"name"` // displayName
	DN          string `json:"dn,omitempty"`
	Flags       int    `json:"flags"`                   // gPCFlags / flags
	FileSysPath string `json:"file_sys_path,omitempty"` // gPCFileSysPath (UNC)
	Version     int    `json:"version,omitempty"`

	Computer ConfigSettings `json:"computer"`
	User     ConfigSettings `json:"user"`

	// AffectedComputers is the list of computer DNs this GPO applies to, filled
	// in by the processor from gPLink/OU inheritance.
	AffectedComputers []string `json:"affected_computers,omitempty"`
}

func (g *GPO) empty() bool { return g.Computer.empty() && g.User.empty() }

// GPLink is one parsed entry of an OU/domain/site gPLink attribute.
type GPLink struct {
	GPODN    string `json:"gpo_dn"` // cn={GUID},CN=Policies,...
	GUID     string `json:"guid"`
	Enforced bool   `json:"enforced"`
	Disabled bool   `json:"disabled"`
}

// OU is a GPO link container: the domain root, an organizationalUnit, or a site.
type OU struct {
	DN               string   `json:"dn"`
	Name             string   `json:"name,omitempty"`
	Kind             string   `json:"kind"` // "domain" | "ou" | "site"
	GUID             string   `json:"guid,omitempty"`
	RawGPLink        string   `json:"raw_gplink,omitempty"`
	Links            []GPLink `json:"links,omitempty"`
	BlockInheritance bool     `json:"block_inheritance,omitempty"` // gPOptions bit 0
}

// Computer is an AD computer object plus the ordered list of GPO GUIDs that
// apply to it (filled by the processor).
type Computer struct {
	DN          string   `json:"dn"`
	Name        string   `json:"name,omitempty"`
	SID         string   `json:"sid,omitempty"`
	DNSHostName string   `json:"dns_host_name,omitempty"`
	GPOs        []string `json:"gpos,omitempty"` // effective GPO GUIDs, most→least specific
}

func (c *Cache) gpoByGUID(guid string) *GPO {
	guid = normalizeGUID(guid)
	for _, g := range c.GPOs {
		if normalizeGUID(g.GUID) == guid {
			return g
		}
	}
	return nil
}

// findGPOs returns GPOs matching a filter that may be a GUID (with or without
// braces) or a (case-insensitive) substring of the display name. An empty
// filter returns all GPOs.
func (c *Cache) findGPOs(filter string) []*GPO {
	if filter == "" {
		return c.GPOs
	}
	if g := c.gpoByGUID(filter); g != nil {
		return []*GPO{g}
	}
	var out []*GPO
	lf := lowerTrim(filter)
	for _, g := range c.GPOs {
		if lowerContains(g.Name, lf) {
			out = append(out, g)
		}
	}
	return out
}

func saveCache(path string, c *Cache) error {
	c.Version = cacheVersion
	if c.Generated.IsZero() {
		c.Generated = time.Now()
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling cache: %w", err)
	}
	if err := os.WriteFile(path, data, 0640); err != nil {
		return fmt.Errorf("writing cache %s: %w", path, err)
	}
	return nil
}

func loadCache(path string) (*Cache, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading cache %s: %w", path, err)
	}
	c := &Cache{}
	if err := json.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("parsing cache %s: %w", path, err)
	}
	if c.Version != cacheVersion {
		logger.Errorf("cache %s has schema version %d (tool expects %d); results may be incomplete\n", path, c.Version, cacheVersion)
	}
	return c, nil
}

// defaultCachePath returns the conventional timestamped cache filename.
func defaultCachePath() string {
	return fmt.Sprintf("cache_gpoparser_%s.json", time.Now().Format("20060102_150405"))
}
