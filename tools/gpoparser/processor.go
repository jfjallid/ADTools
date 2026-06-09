package main

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	// gplinkEntryRe matches one [LDAP://<dn>;<status>] entry of a gPLink value.
	gplinkEntryRe = regexp.MustCompile(`(?i)\[LDAP://([^;\]]+);(\d+)\]`)
	// cnGUIDRe extracts the {GUID} from a GPO DN.
	cnGUIDRe = regexp.MustCompile(`(?i)\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}`)
)

// parseGPLink parses a gPLink attribute into ordered links. The status field is
// a bitmask: bit 0 (value&1) = link disabled, bit 1 (value&2) = enforced.
func parseGPLink(raw string) []GPLink {
	var links []GPLink
	for _, m := range gplinkEntryRe.FindAllStringSubmatch(raw, -1) {
		dn := strings.TrimSpace(m[1])
		status, _ := strconv.Atoi(m[2])
		links = append(links, GPLink{
			GPODN:    dn,
			GUID:     normalizeGUID(cnGUIDRe.FindString(dn)),
			Disabled: status&1 == 1,
			Enforced: status&2 == 2,
		})
	}
	return links
}

// buildMappings computes, for every computer, the ordered set of GPO GUIDs that
// apply to it (honouring enforced links and block-inheritance), and the inverse
// list of affected computers per GPO.
//
// Resolution covers the domain head and OU hierarchy (the LSDOU model minus the
// site tier, which cannot be resolved without subnet/site membership data).
func (cache *Cache) buildMappings() {
	ouByDN := map[string]*OU{}
	for _, o := range cache.OUs {
		ouByDN[strings.ToLower(o.DN)] = o
	}

	affected := map[string]map[string]bool{} // guid -> set(computer DN)
	for _, comp := range cache.Computers {
		containers := cache.ancestorContainers(comp.DN, ouByDN)
		comp.GPOs = effectiveGPOGUIDs(containers)
		for _, guid := range comp.GPOs {
			if affected[guid] == nil {
				affected[guid] = map[string]bool{}
			}
			affected[guid][comp.DN] = true
		}
	}

	for _, g := range cache.GPOs {
		set := affected[normalizeGUID(g.GUID)]
		g.AffectedComputers = g.AffectedComputers[:0]
		for dn := range set {
			g.AffectedComputers = append(g.AffectedComputers, dn)
		}
		sort.Strings(g.AffectedComputers)
	}
}

// ancestorContainers returns the link containers (domain head + OUs) that are
// ancestors of computerDN, ordered top-down (domain first, immediate parent
// last).
func (cache *Cache) ancestorContainers(computerDN string, ouByDN map[string]*OU) []*OU {
	var dns []string
	dn := parentDN(computerDN)
	for dn != "" {
		dns = append(dns, dn)
		if strings.EqualFold(dn, cache.BaseDN) {
			break
		}
		dn = parentDN(dn)
	}
	var containers []*OU
	for i := len(dns) - 1; i >= 0; i-- { // reverse to top-down
		if o, ok := ouByDN[strings.ToLower(dns[i])]; ok {
			containers = append(containers, o)
		}
	}
	return containers
}

// effectiveGPOGUIDs applies GPO inheritance over containers ordered top-down.
// Non-enforced links from above a block-inheritance container are dropped;
// enforced links always apply.
func effectiveGPOGUIDs(containers []*OU) []string {
	var inherited []string // non-enforced, subject to block-inheritance
	var enforced []string  // always apply
	for _, c := range containers {
		if c.BlockInheritance {
			inherited = inherited[:0]
		}
		for _, link := range c.Links {
			if link.Disabled || link.GUID == "" {
				continue
			}
			if link.Enforced {
				enforced = append(enforced, link.GUID)
			} else {
				inherited = append(inherited, link.GUID)
			}
		}
	}
	return dedupeGUIDs(append(inherited, enforced...))
}

func dedupeGUIDs(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, g := range in {
		if g == "" || seen[g] {
			continue
		}
		seen[g] = true
		out = append(out, g)
	}
	return out
}

// parentDN returns the DN with its leftmost RDN removed, honouring backslash-
// escaped commas. Returns "" when there is no parent.
func parentDN(dn string) string {
	for i := 0; i < len(dn); i++ {
		if dn[i] == ',' && (i == 0 || dn[i-1] != '\\') {
			return strings.TrimSpace(dn[i+1:])
		}
	}
	return ""
}

// enrichPrincipals fills in friendly names / SIDs across all parsed settings
// using the resolver (well-known tables always; LDAP when connected).
func enrichPrincipals(cache *Cache, r *sidResolver) {
	fix := func(ps []Principal) {
		for i := range ps {
			ps[i] = r.enrich(ps[i])
		}
	}
	fixCS := func(cs *ConfigSettings) {
		for i := range cs.GroupMemberships {
			cs.GroupMemberships[i].Group = r.enrich(cs.GroupMemberships[i].Group)
			fix(cs.GroupMemberships[i].Members)
			fix(cs.GroupMemberships[i].MemberOf)
		}
		for i := range cs.Privileges {
			fix(cs.Privileges[i].Members)
		}
	}
	for _, g := range cache.GPOs {
		fixCS(&g.Computer)
		fixCS(&g.User)
	}
}
