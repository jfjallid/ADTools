package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jfjallid/go-smb/msdtyp"
)

// This file holds the pure friendly-name data and helpers used by the `dacl`
// subcommand: AD access-mask bit names, extended-right / schema GUID names,
// well-known SID names, and the named-rights presets. Everything here is
// LDAP-free so it can be unit-tested directly.

// AD-specific ACCESS_MASK bits. For directory objects the low 16 bits are
// object-type specific (ADS_RIGHTS_ENUM, MS-ADTS 5.1.3.2); the upper bits are
// the standard access rights. Ordered low→high for deterministic output.
var adAccessMaskNames = []struct {
	bit  uint32
	name string
}{
	{0x00000001, "CreateChild"},
	{0x00000002, "DeleteChild"},
	{0x00000004, "ListChildren"},
	{0x00000008, "Self"},
	{0x00000010, "ReadProperty"},
	{0x00000020, "WriteProperty"},
	{0x00000040, "DeleteTree"},
	{0x00000080, "ListObject"},
	{0x00000100, "ControlAccess"},
	{0x00010000, "Delete"},
	{0x00020000, "ReadControl"},
	{0x00040000, "WriteDacl"},
	{0x00080000, "WriteOwner"},
	{0x00100000, "Synchronize"},
	{0x01000000, "AccessSystemSecurity"},
	{0x02000000, "MaximumAllowed"},
	{0x10000000, "GenericAll"},
	{0x20000000, "GenericExecute"},
	{0x40000000, "GenericWrite"},
	{0x80000000, "GenericRead"},
}

// Access-mask and extended-right constants used by presets / object ACEs.
const (
	adsRightDSControlAccess uint32 = 0x00000100
	adsRightDSWriteProp     uint32 = 0x00000020
	rightWriteDacl          uint32 = 0x00040000
	rightWriteOwner         uint32 = 0x00080000
	maskFullControl         uint32 = 0x000F01FF // STANDARD_RIGHTS_REQUIRED | DS full control (no Synchronize)

	guidResetPassword        = "00299570-246d-11d0-a768-00aa006e0529"
	guidGetChanges           = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
	guidGetChangesAll        = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
	guidGetChangesFiltered   = "89e95b76-444d-4c62-991a-0facbeda640c"
	guidMember               = "bf9679c0-0de6-11d0-a285-00aa003049e2"
	guidServicePrincipalName = "f3a64788-5306-11d1-a9c5-0000f80367c1"
	guidKeyCredentialLink    = "5b47d60f-6090-40b2-9f37-2a4de88f3063"
	guidAllowedToActOnBehalf = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"
)

// formatAccessMask renders an ACCESS_MASK as "0xHHHHHHHH (Name|Name|...)" with
// AD-aware bit names. The 0x000F01FF aggregate is collapsed to "FullControl".
func formatAccessMask(m uint32) string {
	if m == 0 {
		return "0x00000000"
	}
	var parts []string
	remaining := m
	if m&maskFullControl == maskFullControl {
		parts = append(parts, "FullControl")
		remaining &^= maskFullControl
	}
	for _, e := range adAccessMaskNames {
		if remaining&e.bit != 0 {
			parts = append(parts, e.name)
			remaining &^= e.bit
		}
	}
	if remaining != 0 {
		parts = append(parts, fmt.Sprintf("0x%08X", remaining))
	}
	return fmt.Sprintf("0x%08X (%s)", m, strings.Join(parts, "|"))
}

// wellKnownGUIDNames maps the default, schema-defined GUIDs that can appear as
// the ObjectType of an object ACE to a human-readable name, so the dacl/access
// reports can label per-property and per-extended-right grants instead of
// printing a bare GUID. Keys are lowercase. Four kinds of GUID show up here
// (MS-ADTS 5.1.3.2.1 / 6.1.1.2.7.x):
//
//   - control-access (extended) rights — paired with ControlAccess in the mask
//   - validated writes                 — paired with Self (DS-Self)
//   - property sets                    — paired with Read/WriteProperty
//   - individual attribute schemaIDGUIDs and class schemaIDGUIDs
//
// Only the well-known, forest-independent GUIDs are listed here; site-specific
// schema extensions (e.g. LAPS ms-Mcs-AdmPwd) get a per-forest schemaIDGUID and
// are resolved live from the schema by resolveAttrGUID instead.
var wellKnownGUIDNames = map[string]string{
	// --- Control-access (extended) rights ---------------------------------
	// Password / account control.
	guidResetPassword:                      "User-Force-Change-Password",
	"ab721a53-1e2f-11d0-9819-00aa0040529b": "User-Change-Password",
	"ab721a54-1e2f-11d0-9819-00aa0040529b": "Send-As",
	"280f369c-67c7-438e-ae98-1d46f3c6f541": "Update-Password-Not-Required-Bit",
	"ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501": "Unexpire-Password",
	"05c74c5e-4deb-43b4-bd9f-86664c2a7fd5": "Enable-Per-User-Reversibly-Encrypted-Password",
	// Replication (Get-Changes + Get-Changes-All == DCSync).
	guidGetChanges:                         "DS-Replication-Get-Changes",
	guidGetChangesAll:                      "DS-Replication-Get-Changes-All",
	guidGetChangesFiltered:                 "DS-Replication-Get-Changes-In-Filtered-Set",
	"1131f6ab-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Synchronize",
	"1131f6ac-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Manage-Topology",
	"1131f6ae-9c07-11d1-f79f-00c04fc2dcd2": "Read-Only-Replication-Secret-Synchronization",
	"9923a32a-3607-11d2-b9be-0000f87a36b2": "DS-Install-Replica",
	// FSMO role transfers / RID + GUID management.
	"440820ad-65b4-11d1-a3da-0000f875ae0d": "Add-GUID",
	"1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd": "Allocate-Rids",
	"ee914b82-0a98-11d1-adbb-00c04fd8d5cd": "Abandon-Replication",
	"014bf69c-7b3b-11d1-85f6-08002be74fab": "Change-Domain-Master",
	"cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd": "Change-Infrastructure-Master",
	"bae50096-4752-11d1-9052-00c04fc2d4cf": "Change-PDC",
	"d58d5f36-0a98-11d1-adbb-00c04fd8d5cd": "Change-Rid-Master",
	"e12b56b6-0a95-11d1-adbb-00c04fd8d5cd": "Change-Schema-Master",
	// AD CS enrollment.
	"0e10c968-78fb-11d2-90d4-00c04f79dc55": "Certificate-Enrollment",
	"a05b8cc2-17bc-4802-a710-e7c15ab866a2": "Certificate-AutoEnrollment",
	// Other high-value rights.
	"edacfd8f-ffb3-11d1-b41d-00a0c968f939": "Apply-Group-Policy",
	"ba33815a-4f93-4c76-87f3-57574bff8109": "Migrate-SID-History",
	"45ec5156-db7e-47bb-b53f-dbeb2d03c40f": "Reanimate-Tombstones",
	"68b1d179-0d15-4d4f-ab71-46152e79a7bc": "Allowed-To-Authenticate",

	// --- Property sets (Read/Write-Property over a group of attributes) ----
	"59ba2f42-79a2-11d0-9020-00c04fc2d3cf": "General-Information (property set)",
	"4c164200-20c0-11d0-a768-00aa006e0529": "User-Account-Restrictions (property set)",
	"5f202010-79a5-11d0-9020-00c04fc2d4cf": "User-Logon (property set)",
	"bc0ac240-79a9-11d0-9020-00c04fc2d4cf": "Membership (property set)",
	"77b5b886-944a-11d1-aebd-0000f80367c1": "Personal-Information (property set)",
	"91e647de-d96f-4b70-9557-d63ff4f3ccd8": "Private-Information (property set)",
	"e48d0154-bcf8-11d1-8702-00c04fb96050": "Public-Information (property set)",
	"e45795b3-9455-11d1-aebd-0000f80367c1": "Web-Information (property set)",
	"e45795b2-9455-11d1-aebd-0000f80367c1": "Email-Information (property set)",
	"037088f8-0ae1-11d2-b422-00a0c968f939": "RAS-Information (property set)",
	"c7407360-20bf-11d0-a768-00aa006e0529": "Domain-Password (property set)",
	"b8119fd0-04f6-4762-ab7a-4986c76b3f9a": "Other-Domain-Parameters (property set)",
	"5805bc62-bdc9-4428-a5e2-856a0f4c185e": "Terminal-Server-License-Server (property set)",
	"ffa6f046-ca4b-4feb-b40d-04dfee722543": "MS-TS-GatewayAccess (property set)",

	// --- Individual attribute schemaIDGUIDs (per-property read/write) ------
	// The first two double as validated writes when paired with DS-Self.
	guidMember:                             "member (attribute / Self-Membership)",
	guidServicePrincipalName:               "servicePrincipalName (attribute / Validated-SPN)",
	guidKeyCredentialLink:                  "msDS-KeyCredentialLink (attribute)",
	guidAllowedToActOnBehalf:               "msDS-AllowedToActOnBehalfOfOtherIdentity (attribute)",
	"3e0abfd0-126a-11d0-a060-00aa006c33ed": "sAMAccountName (attribute)",
	"bf967953-0de6-11d0-a285-00aa003049e2": "displayName (attribute)",
	"bf967950-0de6-11d0-a285-00aa003049e2": "description (attribute)",
	"bf967a68-0de6-11d0-a285-00aa003049e2": "userAccountControl (attribute)",
	"bf967a0a-0de6-11d0-a285-00aa003049e2": "pwdLastSet (attribute)",
	"f30e3bbe-9ff0-11d1-b603-0000f80367c1": "gPLink (attribute)",
	"f30e3bc1-9ff0-11d0-b603-0000f80367c1": "gPCFileSysPath (attribute)",

	// --- Object class schemaIDGUIDs (CreateChild/DeleteChild scoping) ------
	"bf967aba-0de6-11d0-a285-00aa003049e2": "user (class)",
	"bf967a86-0de6-11d0-a285-00aa003049e2": "computer (class)",
	"bf967a9c-0de6-11d0-a285-00aa003049e2": "group (class)",
	"bf967aa5-0de6-11d0-a285-00aa003049e2": "organizationalUnit (class)",
	"7b8b558a-93a5-4af7-adca-c017e67f1057": "msDS-GroupManagedServiceAccount (class)",
	"f30e3bc2-9ff0-11d1-b603-0000f80367c1": "groupPolicyContainer (class)",
	"19195a5b-6da0-11d0-afd3-00c04fd930c9": "domainDNS (class)",
}

// friendlyGUIDName returns a human name for an object-ACE GUID, or "" if
// unknown. Input is case-insensitive.
func friendlyGUIDName(guid string) string {
	return wellKnownGUIDNames[strings.ToLower(guid)]
}

// Universal well-known SIDs (domain-independent).
var wellKnownSIDs = map[string]string{
	"S-1-0-0":      "Null SID",
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
	"S-1-5-13":     "Terminal Server Users",
	"S-1-5-15":     "This Organization",
	"S-1-5-18":     "Local System",
	"S-1-5-19":     "Local Service",
	"S-1-5-20":     "Network Service",
	"S-1-5-32-544": "BUILTIN\\Administrators",
	"S-1-5-32-545": "BUILTIN\\Users",
	"S-1-5-32-546": "BUILTIN\\Guests",
	"S-1-5-32-548": "BUILTIN\\Account Operators",
	"S-1-5-32-549": "BUILTIN\\Server Operators",
	"S-1-5-32-550": "BUILTIN\\Print Operators",
	"S-1-5-32-551": "BUILTIN\\Backup Operators",
	"S-1-5-32-552": "BUILTIN\\Replicators",
	"S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
	"S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
	"S-1-5-32-557": "BUILTIN\\Incoming Forest Trust Builders",
	"S-1-5-32-573": "BUILTIN\\Event Log Readers",
	"S-1-5-32-574": "BUILTIN\\Certificate Service DCOM Access",
}

// domainRelativeRIDs maps the RID suffix of an S-1-5-21-<domain>-<rid> SID to a
// well-known account/group name.
var domainRelativeRIDs = map[string]string{
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
	"526": "Key Admins",
	"527": "Enterprise Key Admins",
}

// wellKnownSIDName returns a friendly name for a SID without any LDAP lookup,
// covering universal SIDs and domain-relative well-known RIDs. Returns "" if
// the SID is not well-known.
func wellKnownSIDName(sid string) string {
	if n, ok := wellKnownSIDs[sid]; ok {
		return n
	}
	if strings.HasPrefix(sid, "S-1-5-21-") {
		if i := strings.LastIndex(sid, "-"); i >= 0 {
			if n, ok := domainRelativeRIDs[sid[i+1:]]; ok {
				return n
			}
		}
	}
	return ""
}

// grantSpec is one ACE to create: an access mask plus an optional object-type
// GUID (when set, an ACCESS_*_OBJECT_ACE is emitted).
type grantSpec struct {
	mask uint32
	guid string
}

// rightsPresets maps a --rights preset name (lowercase) to the ACE(s) it
// expands to. DCSync expands to two object ACEs.
var rightsPresets = map[string][]grantSpec{
	"fullcontrol":       {{mask: maskFullControl}},
	"resetpassword":     {{mask: adsRightDSControlAccess, guid: guidResetPassword}},
	"writemembers":      {{mask: adsRightDSWriteProp, guid: guidMember}},
	"dcsync":            {{mask: adsRightDSControlAccess, guid: guidGetChanges}, {mask: adsRightDSControlAccess, guid: guidGetChangesAll}},
	"allextendedrights": {{mask: adsRightDSControlAccess}},
	"writedacl":         {{mask: rightWriteDacl}},
	"writeowner":        {{mask: rightWriteOwner}},
}

func presetNames() string {
	names := make([]string, 0, len(rightsPresets))
	for k := range rightsPresets {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// aceBinarySize returns the on-the-wire size of an ACE, used to set Header.Size
// before marshalling. Mirrors the layout in msdtyp.ACE.MarshalBinary.
func aceBinarySize(a *msdtyp.ACE) uint16 {
	n := 4 + 4 + 8 + 4*len(a.Sid.SubAuthorities) // header + mask + SID
	if msdtyp.IsObjectAceType(a.Header.Type) {
		n += 4 // ObjectFlags
		if a.ObjectFlags&msdtyp.AceObjectTypePresent != 0 {
			n += 16
		}
		if a.ObjectFlags&msdtyp.AceInheritedObjectTypePresent != 0 {
			n += 16
		}
	}
	return uint16(n)
}

// buildACEsForGrant turns the requested rights (presets, raw mask, explicit
// GUIDs) into concrete msdtyp.ACE values for the given trustee SID. aceType is
// the base type (AccessAllowedAceType or AccessDeniedAceType); the object-ACE
// variant is selected automatically when a GUID is involved.
func buildACEsForGrant(trusteeSID string, aceType byte, aceFlags byte, presets []string, rawMask uint32, rightGUIDs []string, inheritedObjectGUID string) ([]msdtyp.ACE, error) {
	sid, err := msdtyp.ConvertStrToSID(trusteeSID)
	if err != nil {
		return nil, fmt.Errorf("trustee SID %q: %w", trusteeSID, err)
	}

	var specs []grantSpec
	for _, p := range presets {
		s, ok := rightsPresets[strings.ToLower(p)]
		if !ok {
			return nil, fmt.Errorf("unknown --rights preset %q (valid: %s)", p, presetNames())
		}
		specs = append(specs, s...)
	}
	if rawMask != 0 {
		specs = append(specs, grantSpec{mask: rawMask})
	}
	for _, g := range rightGUIDs {
		specs = append(specs, grantSpec{mask: adsRightDSControlAccess, guid: g})
	}
	if len(specs) == 0 {
		return nil, fmt.Errorf("no rights specified; use --rights, --mask, or --right-guid")
	}

	var inhGUID [16]byte
	haveInh := inheritedObjectGUID != ""
	if haveInh {
		inhGUID, err = msdtyp.GuidFromString(inheritedObjectGUID)
		if err != nil {
			return nil, fmt.Errorf("--inherited-object-guid: %w", err)
		}
	}

	out := make([]msdtyp.ACE, 0, len(specs))
	for _, sp := range specs {
		ace := msdtyp.ACE{
			Header: msdtyp.ACEHeader{Flags: aceFlags},
			Mask:   sp.mask,
			Sid:    *sid,
		}
		if sp.guid != "" || haveInh {
			if aceType == msdtyp.AccessDeniedAceType {
				ace.Header.Type = msdtyp.AccessDeniedObjectAceType
			} else {
				ace.Header.Type = msdtyp.AccessAllowedObjectAceType
			}
			if sp.guid != "" {
				g, err := msdtyp.GuidFromString(sp.guid)
				if err != nil {
					return nil, fmt.Errorf("right GUID %q: %w", sp.guid, err)
				}
				ace.ObjectType = g
				ace.ObjectFlags |= msdtyp.AceObjectTypePresent
			}
			if haveInh {
				ace.InheritedObjectType = inhGUID
				ace.ObjectFlags |= msdtyp.AceInheritedObjectTypePresent
			}
		} else {
			ace.Header.Type = aceType
		}
		ace.Header.Size = aceBinarySize(&ace)
		out = append(out, ace)
	}
	return out, nil
}
