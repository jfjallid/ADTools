package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jfjallid/go-smb/msdtyp"
	ldap "github.com/jfjallid/ldap/v3"
)

// adClient wraps an authenticated LDAP connection and the discovered naming
// contexts used to enumerate GPOs, link containers and computers.
type adClient struct {
	conn     *ldap.Conn
	baseDN   string // defaultNamingContext, e.g. DC=corp,DC=local
	configNC string // configurationNamingContext
}

func newADClient(conn *ldap.Conn, baseDN string) *adClient {
	c := &adClient{conn: conn, baseDN: baseDN}
	if nc, err := detectBaseDN(conn, "configurationNamingContext"); err == nil {
		c.configNC = nc
	} else {
		logger.Debugf("could not detect configurationNamingContext: %v\n", err)
	}
	return c
}

// entrySID extracts a string SID from a binary objectSid attribute on an entry.
func entrySID(e *ldap.Entry, attr string) string {
	for _, a := range e.Attributes {
		if strings.EqualFold(a.Name, attr) && len(a.ByteValues) > 0 {
			s := &msdtyp.SID{}
			if err := s.UnmarshalBinary(a.ByteValues[0]); err == nil {
				return s.ToString()
			}
		}
	}
	return ""
}

// entryGUID extracts a formatted objectGUID (uppercase, no braces) from a
// binary attribute, matching BloodHound's OU ObjectIdentifier convention.
func entryGUID(e *ldap.Entry, attr string) string {
	for _, a := range e.Attributes {
		if strings.EqualFold(a.Name, attr) && len(a.ByteValues) > 0 && len(a.ByteValues[0]) == 16 {
			var g [16]byte
			copy(g[:], a.ByteValues[0])
			s := msdtyp.GuidToString(g)
			s = strings.TrimSuffix(strings.TrimPrefix(s, "{"), "}")
			return strings.ToUpper(s)
		}
	}
	return ""
}

// baseDNToFQDN turns "DC=corp,DC=local" into "corp.local".
func baseDNToFQDN(baseDN string) string {
	var labels []string
	for _, part := range strings.Split(baseDN, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "DC=") {
			labels = append(labels, part[3:])
		}
	}
	return strings.Join(labels, ".")
}

// domainInfo reads the domain SID and short NetBIOS-ish name from the domain
// head object.
func (c *adClient) domainInfo() (sid, shortName string) {
	res, err := c.conn.Search(ldap.NewSearchRequest(
		c.baseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)",
		[]string{"objectSid", "name"}, nil,
	))
	if err != nil || len(res.Entries) == 0 {
		return "", ""
	}
	sid = entrySID(res.Entries[0], "objectSid")
	shortName = res.Entries[0].GetAttributeValue("name")
	return
}

// queryGPOs enumerates every groupPolicyContainer in the domain.
func (c *adClient) queryGPOs() ([]*GPO, error) {
	req := ldap.NewSearchRequest(
		c.baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=groupPolicyContainer)",
		[]string{"cn", "displayName", "gPCFileSysPath", "flags", "versionNumber", "distinguishedName"},
		nil,
	)
	res, err := c.conn.SearchWithPaging(req, 200)
	if err != nil {
		return nil, fmt.Errorf("GPO search failed: %w", err)
	}
	var gpos []*GPO
	for _, e := range res.Entries {
		g := &GPO{
			GUID:        normalizeGUID(e.GetAttributeValue("cn")),
			Name:        e.GetAttributeValue("displayName"),
			DN:          e.DN,
			FileSysPath: e.GetAttributeValue("gPCFileSysPath"),
			Flags:       atoiSafe(e.GetAttributeValue("flags")),
			Version:     atoiSafe(e.GetAttributeValue("versionNumber")),
		}
		if g.Name == "" {
			g.Name = g.GUID
		}
		gpos = append(gpos, g)
	}
	logger.Infof("[*] Found %d GPOs\n", len(gpos))
	return gpos, nil
}

// queryLinkContainers enumerates the domain head, all OUs, and all sites that
// could carry a gPLink. Containers without a gPLink are still returned (with
// no links) so block-inheritance state is captured.
func (c *adClient) queryLinkContainers() ([]*OU, error) {
	var ous []*OU

	// Domain head.
	if res, err := c.conn.Search(ldap.NewSearchRequest(
		c.baseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)",
		[]string{"gPLink", "gPOptions", "name", "distinguishedName", "objectGUID"}, nil,
	)); err == nil {
		for _, e := range res.Entries {
			ous = append(ous, ouFromEntry(e, "domain"))
		}
	} else {
		return nil, fmt.Errorf("domain head search failed: %w", err)
	}

	// Organizational units.
	if res, err := c.conn.SearchWithPaging(ldap.NewSearchRequest(
		c.baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=organizationalUnit)",
		[]string{"gPLink", "gPOptions", "name", "distinguishedName", "ou", "objectGUID"}, nil,
	), 200); err == nil {
		for _, e := range res.Entries {
			ous = append(ous, ouFromEntry(e, "ou"))
		}
	} else {
		logger.Errorf("OU search failed: %v\n", err)
	}

	// Sites (live in the configuration NC).
	if c.configNC != "" {
		siteBase := "CN=Sites," + c.configNC
		if res, err := c.conn.SearchWithPaging(ldap.NewSearchRequest(
			siteBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
			0, 0, false, "(objectClass=site)",
			[]string{"gPLink", "gPOptions", "name", "distinguishedName"}, nil,
		), 200); err == nil {
			for _, e := range res.Entries {
				ous = append(ous, ouFromEntry(e, "site"))
			}
		} else {
			logger.Debugf("site search failed: %v\n", err)
		}
	}

	logger.Infof("[*] Found %d link containers (domain/OU/site)\n", len(ous))
	return ous, nil
}

func ouFromEntry(e *ldap.Entry, kind string) *OU {
	o := &OU{
		DN:        e.DN,
		Name:      e.GetAttributeValue("name"),
		Kind:      kind,
		GUID:      entryGUID(e, "objectGUID"),
		RawGPLink: e.GetAttributeValue("gPLink"),
		Links:     parseGPLink(e.GetAttributeValue("gPLink")),
	}
	// gPOptions bit 0 set => block inheritance.
	if opt := atoiSafe(e.GetAttributeValue("gPOptions")); opt&1 == 1 {
		o.BlockInheritance = true
	}
	return o
}

// queryComputers enumerates all computer objects with their SID and DNS name.
func (c *adClient) queryComputers() ([]*Computer, error) {
	req := ldap.NewSearchRequest(
		c.baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=computer)",
		[]string{"distinguishedName", "name", "dNSHostName", "objectSid"},
		nil,
	)
	res, err := c.conn.SearchWithPaging(req, 200)
	if err != nil {
		return nil, fmt.Errorf("computer search failed: %w", err)
	}
	var comps []*Computer
	for _, e := range res.Entries {
		comps = append(comps, &Computer{
			DN:          e.DN,
			Name:        e.GetAttributeValue("name"),
			DNSHostName: e.GetAttributeValue("dNSHostName"),
			SID:         entrySID(e, "objectSid"),
		})
	}
	logger.Infof("[*] Found %d computers\n", len(comps))
	return comps, nil
}

// queryPackages enumerates msiFileList software-installation packages
// (objectClass=packageRegistration) and attaches them to their owning GPO's
// Computer or User scope (derived from the package DN's CN=Machine / CN=User).
func (c *adClient) queryPackages(gpos []*GPO) {
	req := ldap.NewSearchRequest(
		c.baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=packageRegistration)",
		[]string{"displayName", "cn", "msiFileList", "packageType", "distinguishedName"},
		nil,
	)
	res, err := c.conn.SearchWithPaging(req, 200)
	if err != nil {
		logger.Debugf("software-install package search failed: %v\n", err)
		return
	}
	byDN := make(map[string]*GPO, len(gpos))
	for _, g := range gpos {
		byDN[strings.ToLower(g.DN)] = g
	}
	count := 0
	for _, e := range res.Entries {
		g, scope := ownerGPO(byDN, e.DN)
		if g == nil {
			continue
		}
		si := SoftwareInstall{
			Name:        firstNonEmpty(e.GetAttributeValue("displayName"), e.GetAttributeValue("cn")),
			Path:        firstMSIPath(e.GetAttributeValues("msiFileList")),
			PackageType: e.GetAttributeValue("packageType"),
		}
		if scope == "User" {
			g.User.SoftwareInstalls = append(g.User.SoftwareInstalls, si)
		} else {
			g.Computer.SoftwareInstalls = append(g.Computer.SoftwareInstalls, si)
		}
		count++
	}
	if count > 0 {
		logger.Infof("[*] Found %d software-installation package(s)\n", count)
	}
}

// ownerGPO finds the GPO whose DN is a suffix of the package DN and reports
// whether the package lives in the User or Computer (Machine) half.
func ownerGPO(byDN map[string]*GPO, packageDN string) (*GPO, string) {
	lower := strings.ToLower(packageDN)
	scope := "Computer"
	if strings.Contains(lower, ",cn=user,") {
		scope = "User"
	}
	for dn, g := range byDN {
		if strings.HasSuffix(lower, dn) {
			return g, scope
		}
	}
	return nil, scope
}

// firstMSIPath returns the path from the first msiFileList value, stripping the
// leading "<index>:" prefix (values look like "0:\\server\share\app.msi").
func firstMSIPath(vals []string) string {
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if i := strings.Index(v, ":"); i >= 0 && i <= 3 {
			if _, err := strconv.Atoi(v[:i]); err == nil {
				return v[i+1:]
			}
		}
		return v
	}
	return ""
}

func atoiSafe(s string) int {
	v, _ := strconv.Atoi(strings.TrimSpace(s))
	return v
}
