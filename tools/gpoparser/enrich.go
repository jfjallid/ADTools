package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// enrich emits SharpHound-native ingest JSON so BloodHound Community Edition
// turns GPO-derived local-group membership into real AdminTo / CanRDP /
// CanPSRemote / ExecuteDCOM edges (which participate in pathfinding, unlike
// generic OpenGraph data). The representation mirrors SharpHound's own
// GPOLocalGroup collection: each OU / domain carries a GPOChanges block listing
// the principals granted membership and the computers it affects; BloodHound
// expands those across AffectedComputers during analysis.
//
// NOTE: the meta.version integer and exact field shape are version-sensitive
// across BloodHound releases. Validate the output against a sample produced by
// the BloodHound CE instance's own collector (Settings → Download Collectors)
// and adjust --schema-version if ingest rejects it.

type enrichCmd struct {
	cache         string
	outPrefix     string
	schemaVersion int
}

func init() { register(&enrichCmd{}) }

func (c *enrichCmd) Name() string          { return "enrich" }
func (c *enrichCmd) Synopsis() string      { return "Emit SharpHound-native JSON for BloodHound CE upload" }
func (c *enrichCmd) NeedsConnection() bool { return false }

func (c *enrichCmd) DefineFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.cache, "cache", "", "Cache file (default: newest cache_gpoparser_*.json)")
	fs.StringVar(&c.cache, "c", "", "Cache file (short)")
	fs.StringVar(&c.outPrefix, "output", "gpoparser_bloodhound", "Output filename prefix")
	fs.StringVar(&c.outPrefix, "o", "gpoparser_bloodhound", "Output filename prefix (short)")
	fs.IntVar(&c.schemaVersion, "schema-version", 6, "SharpHound JSON meta.version to emit")
}

func (c *enrichCmd) Usage() string {
	return `
    Usage: ` + os.Args[0] + ` enrich [-c cache.json] [-o prefix] [--schema-version N]

    Produces SharpHound-format <prefix>_ous.json and <prefix>_domains.json
    carrying GPOChanges (LocalAdmins / RemoteDesktopUsers / DcomUsers /
    PSRemoteUsers + AffectedComputers) for GPO-derived local-group membership.
    Upload the file(s) in the BloodHound CE UI; BloodHound creates the matching
    AdminTo / CanRDP / ExecuteDCOM / CanPSRemote edges.

    Options:
      -c, --cache           Cache file (default: newest cache_gpoparser_*.json)
      -o, --output          Output filename prefix (default gpoparser_bloodhound)
          --schema-version  SharpHound meta.version integer (default 6)
`
}

// SharpHound ingest structs (subset sufficient for GPOChanges).

type shTypedPrincipal struct {
	ObjectIdentifier string `json:"ObjectIdentifier"`
	ObjectType       string `json:"ObjectType"`
}

type shGPOChanges struct {
	LocalAdmins        []shTypedPrincipal `json:"LocalAdmins"`
	RemoteDesktopUsers []shTypedPrincipal `json:"RemoteDesktopUsers"`
	DcomUsers          []shTypedPrincipal `json:"DcomUsers"`
	PSRemoteUsers      []shTypedPrincipal `json:"PSRemoteUsers"`
	AffectedComputers  []shTypedPrincipal `json:"AffectedComputers"`
}

func (g shGPOChanges) empty() bool {
	return len(g.LocalAdmins) == 0 && len(g.RemoteDesktopUsers) == 0 &&
		len(g.DcomUsers) == 0 && len(g.PSRemoteUsers) == 0
}

type shContainer struct {
	ObjectIdentifier string             `json:"ObjectIdentifier"`
	Properties       map[string]any     `json:"Properties"`
	Links            []shLink           `json:"Links,omitempty"`
	ChildObjects     []shTypedPrincipal `json:"ChildObjects"`
	GPOChanges       shGPOChanges       `json:"GPOChanges"`
	Aces             []any              `json:"Aces"`
	IsDeleted        bool               `json:"IsDeleted"`
	IsACLProtected   bool               `json:"IsACLProtected"`
}

type shLink struct {
	IsEnforced bool   `json:"IsEnforced"`
	GUID       string `json:"GUID"`
}

type shFile struct {
	Data []shContainer `json:"data"`
	Meta shMeta        `json:"meta"`
}

type shMeta struct {
	Methods int    `json:"methods"`
	Type    string `json:"type"`
	Count   int    `json:"count"`
	Version int    `json:"version"`
}

func (c *enrichCmd) Run(_ *connArgs) error {
	path, err := resolveCachePath(c.cache)
	if err != nil {
		return err
	}
	cache, err := loadCache(path)
	if err != nil {
		return err
	}

	compSID := map[string]string{} // computer DN -> SID
	for _, comp := range cache.Computers {
		compSID[comp.DN] = comp.SID
	}
	gpoByGUID := map[string]*GPO{}
	for _, g := range cache.GPOs {
		gpoByGUID[normalizeGUID(g.GUID)] = g
	}

	var ous, domains []shContainer
	for _, container := range cache.OUs {
		sc, ok := buildContainer(cache, container, gpoByGUID, compSID)
		if !ok {
			continue
		}
		if container.Kind == "domain" {
			domains = append(domains, sc)
		} else {
			ous = append(ous, sc)
		}
	}

	wrote := 0
	if len(ous) > 0 {
		f := c.outPrefix + "_ous.json"
		if err := writeSHFile(f, shFile{Data: ous, Meta: shMeta{Type: "ous", Count: len(ous), Version: c.schemaVersion}}); err != nil {
			return err
		}
		logger.Noticef("[+] Wrote %d OU(s) with GPOChanges to %s\n", len(ous), f)
		wrote++
	}
	if len(domains) > 0 {
		f := c.outPrefix + "_domains.json"
		if err := writeSHFile(f, shFile{Data: domains, Meta: shMeta{Type: "domains", Count: len(domains), Version: c.schemaVersion}}); err != nil {
			return err
		}
		logger.Noticef("[+] Wrote %d domain(s) with GPOChanges to %s\n", len(domains), f)
		wrote++
	}
	if wrote == 0 {
		return fmt.Errorf("no GPO-derived local-group membership found to enrich (need GptTmpl [Group Membership] or GPP Groups.xml additions to Administrators/RDP/DCOM/Remote-Management groups, plus resolved affected computers)")
	}
	fmt.Println("Upload the generated JSON file(s) via the BloodHound CE UI (Administration → File Ingest).")
	return nil
}

// buildContainer assembles the GPOChanges for one OU/domain from the GPOs
// linked directly to it. Returns ok=false when nothing relevant is present.
func buildContainer(cache *Cache, container *OU, gpoByGUID map[string]*GPO, compSID map[string]string) (shContainer, bool) {
	oid := container.GUID
	if container.Kind == "domain" {
		oid = cache.DomainSID
	}
	if oid == "" {
		return shContainer{}, false
	}

	var changes shGPOChanges
	affected := map[string]bool{}
	var links []shLink

	for _, link := range container.Links {
		if link.Disabled || link.GUID == "" {
			continue
		}
		links = append(links, shLink{IsEnforced: link.Enforced, GUID: strings.Trim(link.GUID, "{}")})
		g := gpoByGUID[normalizeGUID(link.GUID)]
		if g == nil {
			continue
		}
		addLocalGroupMembers(&changes, g, cache)
		for _, dn := range g.AffectedComputers {
			affected[dn] = true
		}
	}

	if changes.empty() || len(affected) == 0 {
		return shContainer{}, false
	}

	dns := make([]string, 0, len(affected))
	for dn := range affected {
		dns = append(dns, dn)
	}
	sort.Strings(dns)
	for _, dn := range dns {
		if sid := compSID[dn]; sid != "" {
			changes.AffectedComputers = append(changes.AffectedComputers, shTypedPrincipal{ObjectIdentifier: sid, ObjectType: "Computer"})
		}
	}
	if len(changes.AffectedComputers) == 0 {
		return shContainer{}, false
	}

	// SharpHound emits empty arrays, not null, for absent categories.
	nz := func(s []shTypedPrincipal) []shTypedPrincipal {
		if s == nil {
			return []shTypedPrincipal{}
		}
		return s
	}
	changes.LocalAdmins = nz(changes.LocalAdmins)
	changes.RemoteDesktopUsers = nz(changes.RemoteDesktopUsers)
	changes.DcomUsers = nz(changes.DcomUsers)
	changes.PSRemoteUsers = nz(changes.PSRemoteUsers)

	return shContainer{
		ObjectIdentifier: strings.ToUpper(oid),
		Properties: map[string]any{
			"name":              displayContainerName(container, cache),
			"distinguishedname": container.DN,
			"domain":            strings.ToUpper(cache.DomainFQDN),
			"domainsid":         cache.DomainSID,
		},
		Links:          links,
		ChildObjects:   []shTypedPrincipal{},
		GPOChanges:     changes,
		Aces:           []any{},
		IsDeleted:      false,
		IsACLProtected: false,
	}, true
}

// addLocalGroupMembers folds a GPO's local-group membership additions into the
// GPOChanges categories, keyed by the well-known builtin group RID.
func addLocalGroupMembers(changes *shGPOChanges, g *GPO, cache *Cache) {
	for _, gm := range g.Computer.GroupMemberships {
		rid := localGroupRID(gm.Group.SID)
		if rid == 0 {
			continue
		}
		var dst *[]shTypedPrincipal
		switch rid {
		case ridAdministrators:
			dst = &changes.LocalAdmins
		case ridRemoteDesktopUsers:
			dst = &changes.RemoteDesktopUsers
		case ridDistributedCOMUsers:
			dst = &changes.DcomUsers
		case ridRemoteMgmtUsers:
			dst = &changes.PSRemoteUsers
		default:
			continue
		}
		for _, m := range gm.Members {
			if m.SID == "" {
				continue
			}
			*dst = append(*dst, shTypedPrincipal{
				ObjectIdentifier: strings.ToUpper(m.SID),
				ObjectType:       classifyPrincipal(m.SID, cache),
			})
		}
	}
	dedupePrincipals(&changes.LocalAdmins)
	dedupePrincipals(&changes.RemoteDesktopUsers)
	dedupePrincipals(&changes.DcomUsers)
	dedupePrincipals(&changes.PSRemoteUsers)
}

// localGroupRID returns the builtin local-group RID for a BUILTIN SID
// (S-1-5-32-RID), or 0 if it is not a recognised local group.
func localGroupRID(sid string) int {
	sid = strings.ToUpper(strings.TrimSpace(sid))
	if !strings.HasPrefix(sid, "S-1-5-32-") {
		return 0
	}
	rid, err := strconv.Atoi(sid[len("S-1-5-32-"):])
	if err != nil {
		return 0
	}
	return rid
}

// classifyPrincipal best-effort assigns a BloodHound ObjectType. Unknown SIDs
// default to "Base", which lets BloodHound resolve the real type from existing
// nodes during ingest.
func classifyPrincipal(sid string, cache *Cache) string {
	sid = strings.ToUpper(strings.TrimSpace(sid))
	for _, comp := range cache.Computers {
		if strings.EqualFold(comp.SID, sid) {
			return "Computer"
		}
	}
	if strings.HasPrefix(sid, "S-1-5-32-") {
		return "Group"
	}
	// Common domain group RIDs.
	if strings.HasPrefix(sid, "S-1-5-21-") {
		if i := strings.LastIndex(sid, "-"); i >= 0 {
			switch sid[i+1:] {
			case "512", "513", "514", "515", "516", "518", "519", "520", "521", "498", "527":
				return "Group"
			case "500", "501", "502":
				return "User"
			}
		}
	}
	return "Base"
}

func dedupePrincipals(ps *[]shTypedPrincipal) {
	seen := map[string]bool{}
	out := (*ps)[:0]
	for _, p := range *ps {
		if seen[p.ObjectIdentifier] {
			continue
		}
		seen[p.ObjectIdentifier] = true
		out = append(out, p)
	}
	*ps = out
}

func displayContainerName(container *OU, cache *Cache) string {
	name := container.Name
	if container.Kind == "domain" {
		return strings.ToUpper(cache.DomainFQDN)
	}
	if name == "" {
		name = container.DN
	}
	return strings.ToUpper(name + "@" + cache.DomainFQDN)
}

func writeSHFile(path string, f shFile) error {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling %s: %w", path, err)
	}
	if err := os.WriteFile(path, data, 0640); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}
