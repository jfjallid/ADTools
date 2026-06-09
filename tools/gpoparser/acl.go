package main

import (
	"fmt"
	"strings"

	"github.com/jfjallid/go-smb/msdtyp"
	ldap "github.com/jfjallid/ldap/v3"
)

// AD access-mask write/control bits relevant to "can the assessed user edit
// this object" (MS-ADTS / MS-DTYP ACCESS_MASK).
const (
	adWriteProp  = 0x00000020
	adWriteDACL  = 0x00040000
	adWriteOwner = 0x00080000
	adGenericAll = 0x10000000
	adGenWrite   = 0x40000000
)

// File/directory ACCESS_MASK write bits. These differ from the AD bits above:
// 0x2/0x4 mean write-data/append-data on a file (and add-file/add-subdirectory
// on a directory), not the DS_* rights.
const (
	fileWriteData    = 0x00000002
	fileAppendData   = 0x00000004
	fileDelete       = 0x00010000
	fileWriteDAC     = 0x00040000
	fileWriteOwner   = 0x00080000
	fileGenericWrite = 0x40000000
	fileGenericAll   = 0x10000000
)

// aclChecker evaluates whether the assessed user can modify AD objects and
// SYSVOL/referenced paths, using the user's effective SID set (own SID +
// transitive group SIDs + the implicit session SIDs every authenticated user
// carries). smb is optional and powers the file/path checks.
type aclChecker struct {
	conn      *ldap.Conn
	baseDN    string
	effective map[string]bool
	smb       *smbSource
}

func newACLChecker(conn *ldap.Conn, baseDN, principal string) (*aclChecker, error) {
	eff, err := effectiveSIDSet(conn, baseDN, principal)
	if err != nil {
		return nil, err
	}
	logger.Infof("[*] Assessing writability as %s (%d effective SIDs)\n", principal, len(eff))
	return &aclChecker{conn: conn, baseDN: baseDN, effective: eff}, nil
}

// effectiveSIDSet resolves principal to its own SID plus every transitive group
// SID (tokenGroups) and the implicit session SIDs.
func effectiveSIDSet(conn *ldap.Conn, baseDN, principal string) (map[string]bool, error) {
	dn, sid := resolvePrincipalSID(conn, baseDN, principal)
	if dn == "" {
		return nil, fmt.Errorf("could not resolve principal %q in the directory", principal)
	}
	set := map[string]bool{}
	if sid != "" {
		set[sid] = true
	}
	if res, err := conn.Search(ldap.NewSearchRequest(
		dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)",
		[]string{"tokenGroups"}, nil,
	)); err == nil && len(res.Entries) > 0 {
		for _, attr := range res.Entries[0].Attributes {
			if !strings.EqualFold(attr.Name, "tokenGroups") {
				continue
			}
			for _, bv := range attr.ByteValues {
				s := &msdtyp.SID{}
				if s.UnmarshalBinary(bv) == nil {
					set[s.ToString()] = true
				}
			}
		}
	}
	set["S-1-1-0"] = true  // Everyone
	set["S-1-5-11"] = true // Authenticated Users
	set["S-1-5-15"] = true // This Organization
	return set, nil
}

// resolvePrincipalSID resolves a sAMAccountName (optionally DOMAIN\name) to its
// DN and string SID.
func resolvePrincipalSID(conn *ldap.Conn, baseDN, principal string) (dn, sid string) {
	sam := principal
	if i := strings.LastIndex(principal, "\\"); i >= 0 {
		sam = principal[i+1:]
	}
	res, err := conn.Search(ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(sAMAccountName="+ldap.EscapeFilter(sam)+")",
		[]string{"distinguishedName", "objectSid"}, nil,
	))
	if err != nil || len(res.Entries) == 0 {
		return "", ""
	}
	e := res.Entries[0]
	return e.DN, entrySID(e, "objectSid")
}

// gpoWritable reads the GPO's nTSecurityDescriptor and reports the first way the
// assessed user can modify it: ownership, or an allow-ACE granting a write right.
func (a *aclChecker) gpoWritable(g *GPO) *WriteAssessment {
	if g.DN == "" {
		return nil
	}
	blob := a.readSD(g.DN)
	if len(blob) == 0 {
		return nil
	}
	sd := &msdtyp.SecurityDescriptor{}
	if err := sd.UnmarshalBinary(blob); err != nil {
		logger.Debugf("parse SD for %s: %v\n", g.DN, err)
		return nil
	}
	// Strict: only the assessed user's own effective rights count for "can I
	// take over this GPO object".
	return a.sdWritable(sd, surfaceGPOObject, g.DN, true, false, adWriteRights)
}

// sdWritable reports the first way an eligible principal can modify the object
// described by sd. Eligible = in the assessed user's effective SID set, plus
// (when includeLowPriv) any low-trust well-known principal. Deny ACEs for an
// eligible principal suppress the matching granted bits. rightsOf decodes the
// access mask in the object's context (AD vs file). existed records whether the
// object itself was present (false ⇒ a writable parent of a missing path).
func (a *aclChecker) sdWritable(sd *msdtyp.SecurityDescriptor, surface WriteSurface, path string, existed, includeLowPriv bool, rightsOf func(uint32) []string) *WriteAssessment {
	if sd == nil {
		return nil
	}
	eligible := func(sid string) bool {
		return a.effective[sid] || (includeLowPriv && isLowPrivPrincipal(sid))
	}
	if sd.OwnerSid != nil && eligible(sd.OwnerSid.ToString()) {
		return &WriteAssessment{Surface: surface, Path: path,
			Trustee: principalFromSID(sd.OwnerSid.ToString()), Rights: []string{"Owner"}, Existed: existed}
	}
	if sd.Dacl == nil {
		return nil
	}
	var denied uint32
	for _, ace := range sd.Dacl.ACLS {
		if (ace.Header.Type == msdtyp.AccessDeniedAceType || ace.Header.Type == msdtyp.AccessDeniedObjectAceType) && eligible(ace.Sid.ToString()) {
			denied |= ace.Mask
		}
	}
	for _, ace := range sd.Dacl.ACLS {
		if ace.Header.Type != msdtyp.AccessAllowedAceType && ace.Header.Type != msdtyp.AccessAllowedObjectAceType {
			continue
		}
		sid := ace.Sid.ToString()
		if !eligible(sid) {
			continue
		}
		if rights := rightsOf(ace.Mask &^ denied); len(rights) > 0 {
			return &WriteAssessment{Surface: surface, Path: path,
				Trustee: principalFromSID(sid), Rights: rights, Existed: existed}
		}
	}
	return nil
}

// sysvolFolderWritable reports whether the assessed user (or a low-privileged
// principal) can write to the GPO's SYSVOL policy folder — equivalent to being
// able to replace any of its policy files.
func (a *aclChecker) sysvolFolderWritable(g *GPO) *WriteAssessment {
	if a.smb == nil || g.FileSysPath == "" {
		return nil
	}
	share, within := splitUNCShare(g.FileSysPath)
	if share == "" {
		return nil
	}
	sd, ok, err := a.smb.queryACL(share, within)
	if err != nil || !ok {
		return nil
	}
	return a.sdWritable(sd, surfaceSysvol, g.FileSysPath, true, true, fileWriteRights)
}

// pathWritable reports whether a referenced UNC path is attacker-writable. If
// the path itself is absent it walks up to the first existing ancestor and
// reports that (the attacker can create the missing file there).
func (a *aclChecker) pathWritable(ref string) *WriteAssessment {
	if a.smb == nil {
		return nil
	}
	ref = strings.Trim(strings.TrimSpace(ref), `"`)
	share, within := splitUNCShare(ref)
	if share == "" {
		return nil // not a UNC path
	}
	existed := true
	for {
		sd, ok, err := a.smb.queryACL(share, within)
		if err != nil {
			logger.Debugf("queryACL %s\\%s: %v\n", share, within, err)
			return nil
		}
		if ok {
			full := `\\` + share
			if within != "" {
				full += `\` + within
			}
			return a.sdWritable(sd, surfacePath, full, existed, true, fileWriteRights)
		}
		existed = false
		parent, more := parentPath(within)
		if !more {
			return nil // reached the share root, nothing exists
		}
		within = parent
	}
}

// parentPath returns the parent of a backslash-separated path within a share,
// and whether a further ancestor remained ("" is the share root, which has
// none).
func parentPath(within string) (string, bool) {
	if within == "" {
		return "", false
	}
	if i := strings.LastIndex(within, `\`); i >= 0 {
		return within[:i], true
	}
	return "", true // step from a top-level entry to the share root
}

// fileWriteRights names the file/directory-modifying rights set in a file
// ACCESS_MASK.
func fileWriteRights(mask uint32) []string {
	var r []string
	if mask&fileGenericAll != 0 {
		r = append(r, "GenericAll")
	}
	if mask&fileGenericWrite != 0 {
		r = append(r, "GenericWrite")
	}
	if mask&fileWriteOwner != 0 {
		r = append(r, "WriteOwner")
	}
	if mask&fileWriteDAC != 0 {
		r = append(r, "WriteDac")
	}
	if mask&fileDelete != 0 {
		r = append(r, "Delete")
	}
	if mask&fileWriteData != 0 {
		r = append(r, "WriteData")
	}
	if mask&fileAppendData != 0 {
		r = append(r, "AppendData")
	}
	return r
}

// pathRef is a path a GPO setting points at, for the writability walk.
type pathRef struct {
	kind  string
	label string
	path  string
}

// referencedPaths collects the executable / deployed paths a config scope points
// at (scripts, scheduled-task commands, MSI installs, file copies, shortcuts).
func referencedPaths(cs *ConfigSettings) []pathRef {
	var refs []pathRef
	for _, s := range cs.Scripts {
		refs = append(refs, pathRef{"script", s.Type + " script", s.CmdLine})
	}
	for _, t := range cs.ScheduledTasks {
		refs = append(refs, pathRef{"task", "scheduled task " + t.Name, t.Command})
	}
	for _, si := range cs.SoftwareInstalls {
		refs = append(refs, pathRef{"msi", "MSI " + si.Name, si.Path})
	}
	for _, f := range cs.Files {
		refs = append(refs, pathRef{"file", "file copy", f.FromPath})
	}
	for _, sc := range cs.Shortcuts {
		refs = append(refs, pathRef{"shortcut", "shortcut " + sc.Name, sc.TargetPath})
	}
	return refs
}

// readSD fetches an object's nTSecurityDescriptor (OWNER|GROUP|DACL via the
// SD-flags control).
func (a *aclChecker) readSD(dn string) []byte {
	ctl := ldap.NewControlMicrosoftSDFlags()
	ctl.Criticality = true
	ctl.ControlValue = 0x1 | 0x2 | 0x4 // OWNER | GROUP | DACL
	res, err := a.conn.Search(ldap.NewSearchRequest(
		dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)",
		[]string{"nTSecurityDescriptor"}, []ldap.Control{ctl},
	))
	if err != nil || len(res.Entries) == 0 {
		logger.Debugf("read SD for %s failed: %v\n", dn, err)
		return nil
	}
	for _, attr := range res.Entries[0].Attributes {
		if strings.EqualFold(attr.Name, "nTSecurityDescriptor") && len(attr.ByteValues) > 0 {
			return attr.ByteValues[0]
		}
	}
	return nil
}

// adWriteRights returns the friendly names of object-modifying rights set in an
// AD access mask.
func adWriteRights(mask uint32) []string {
	var r []string
	if mask&adGenericAll != 0 {
		r = append(r, "GenericAll")
	}
	if mask&adGenWrite != 0 {
		r = append(r, "GenericWrite")
	}
	if mask&adWriteDACL != 0 {
		r = append(r, "WriteDacl")
	}
	if mask&adWriteOwner != 0 {
		r = append(r, "WriteOwner")
	}
	if mask&adWriteProp != 0 {
		r = append(r, "WriteProperty")
	}
	return r
}
