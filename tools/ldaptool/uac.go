package main

import (
	"fmt"
	"strconv"
	"strings"
)

// userAccountControl flags. Names match [MS-ADTS] 2.2.16 / ADS_USER_FLAG_ENUM.
var uacFlags = []struct {
	bit  uint32
	name string
}{
	{0x00000001, "SCRIPT"},
	{0x00000002, "ACCOUNTDISABLE"},
	{0x00000008, "HOMEDIR_REQUIRED"},
	{0x00000010, "LOCKOUT"},
	{0x00000020, "PASSWD_NOTREQD"},
	{0x00000040, "PASSWD_CANT_CHANGE"},
	{0x00000080, "ENCRYPTED_TEXT_PWD_ALLOWED"},
	{0x00000100, "TEMP_DUPLICATE_ACCOUNT"},
	{0x00000200, "NORMAL_ACCOUNT"},
	{0x00000800, "INTERDOMAIN_TRUST_ACCOUNT"},
	{0x00001000, "WORKSTATION_TRUST_ACCOUNT"},
	{0x00002000, "SERVER_TRUST_ACCOUNT"},
	{0x00010000, "DONT_EXPIRE_PASSWORD"},
	{0x00020000, "MNS_LOGON_ACCOUNT"},
	{0x00040000, "SMARTCARD_REQUIRED"},
	{0x00080000, "TRUSTED_FOR_DELEGATION"},
	{0x00100000, "NOT_DELEGATED"},
	{0x00200000, "USE_DES_KEY_ONLY"},
	{0x00400000, "DONT_REQ_PREAUTH"},
	{0x00800000, "PASSWORD_EXPIRED"},
	{0x01000000, "TRUSTED_TO_AUTH_FOR_DELEGATION"},
	{0x04000000, "PARTIAL_SECRETS_ACCOUNT"},
}

// sAMAccountType well-known values from [MS-ADTS] 2.2.12.
var samAccountTypes = map[uint32]string{
	0x00000000: "SAM_DOMAIN_OBJECT",
	0x10000000: "SAM_GROUP_OBJECT",
	0x10000001: "SAM_NON_SECURITY_GROUP_OBJECT",
	0x20000000: "SAM_ALIAS_OBJECT",
	0x20000001: "SAM_NON_SECURITY_ALIAS_OBJECT",
	0x30000000: "SAM_USER_OBJECT",
	0x30000001: "SAM_MACHINE_ACCOUNT",
	0x30000002: "SAM_TRUST_ACCOUNT",
	0x40000000: "SAM_APP_BASIC_GROUP",
	0x40000001: "SAM_APP_QUERY_GROUP",
	0x7FFFFFFF: "SAM_ACCOUNT_TYPE_MAX",
}

// groupType flags, [MS-ADTS] 2.2.13.
var groupTypeFlags = []struct {
	bit  uint32
	name string
}{
	{0x00000001, "SYSTEM"},
	{0x00000002, "GLOBAL"},
	{0x00000004, "DOMAIN_LOCAL"},
	{0x00000008, "UNIVERSAL"},
	{0x00000010, "APP_BASIC"},
	{0x00000020, "APP_QUERY"},
	{0x80000000, "SECURITY"}, // when unset: distribution group
}

// trustAttributes flags, [MS-ADTS] 6.1.6.7.9.
var trustAttrFlags = []struct {
	bit  uint32
	name string
}{
	{0x00000001, "NON_TRANSITIVE"},
	{0x00000002, "UPLEVEL_ONLY"},
	{0x00000004, "QUARANTINED_DOMAIN"},
	{0x00000008, "FOREST_TRANSITIVE"},
	{0x00000010, "CROSS_ORGANIZATION"},
	{0x00000020, "WITHIN_FOREST"},
	{0x00000040, "TREAT_AS_EXTERNAL"},
	{0x00000080, "USES_RC4_ENCRYPTION"},
	{0x00000200, "CROSS_ORGANIZATION_NO_TGT_DELEGATION"},
	{0x00000400, "PIM_TRUST"},
	{0x00000800, "CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION"},
}

var trustDirection = map[uint32]string{
	0: "DISABLED",
	1: "INBOUND",
	2: "OUTBOUND",
	3: "BIDIRECTIONAL",
}

var trustType = map[uint32]string{
	1: "DOWNLEVEL",
	2: "UPLEVEL",
	3: "MIT",
	4: "DCE",
	5: "AAD",
}

// msDS-SupportedEncryptionTypes flags, [MS-KILE] 2.2.7.
var encTypeFlags = []struct {
	bit  uint32
	name string
}{
	{0x00000001, "DES_CBC_CRC"},
	{0x00000002, "DES_CBC_MD5"},
	{0x00000004, "RC4_HMAC"},
	{0x00000008, "AES128_CTS_HMAC_SHA1_96"},
	{0x00000010, "AES256_CTS_HMAC_SHA1_96"},
	{0x00000020, "AES256_CTS_HMAC_SHA1_96_SK"}, // session-key-only
	{0x00000040, "FAST_SUPPORTED"},
	{0x00000080, "COMPOUND_IDENTITY_SUPPORTED"},
	{0x00000100, "CLAIMS_SUPPORTED"},
	{0x00000200, "RESOURCE_SID_COMPRESSION_DISABLED"},
}

// pwdProperties flags, [MS-ADTS] 7.1.1.2.6.
var pwdPropertiesFlags = []struct {
	bit  uint32
	name string
}{
	{0x00000001, "COMPLEX"},
	{0x00000002, "NO_ANON_CHANGE"},
	{0x00000004, "NO_CLEAR_CHANGE"},
	{0x00000008, "LOCKOUT_ADMINS"},
	{0x00000010, "STORE_CLEARTEXT"},
	{0x00000020, "REFUSE_PASSWORD_CHANGE"},
}

// instanceType flags, [MS-ADTS] 3.1.1.3.2.4.
var instanceTypeFlags = []struct {
	bit  uint32
	name string
}{
	{0x00000001, "HEAD_OF_NAMING_CONTEXT"},
	{0x00000002, "REPLICA_NOT_INSTANTIATED"},
	{0x00000004, "OBJECT_WRITABLE"},
	{0x00000008, "NAMING_CONTEXT_ABOVE_HELD"},
	{0x00000010, "NAMING_CONTEXT_BEING_CONSTRUCTED"},
	{0x00000020, "NAMING_CONTEXT_BEING_REMOVED"},
}

// Well-known RIDs that are meaningful as primaryGroupID. [MS-DTYP] 2.4.2.4.
var wellKnownRIDs = map[uint32]string{
	513: "Domain Users",
	514: "Domain Guests",
	515: "Domain Computers",
	516: "Domain Controllers",
	517: "Cert Publishers",
	518: "Schema Admins",
	519: "Enterprise Admins",
	520: "Group Policy Creator Owners",
	521: "Read-only Domain Controllers",
}

// decodeUint32Attr parses a single attribute value as a 32-bit integer.
// AD sometimes serialises values that set the high bit (e.g. groupType with
// the SECURITY flag, 0x80000000) as negative int32 decimals, so accept both
// signed and unsigned forms.
func decodeUint32Attr(s string) (uint32, bool) {
	s = strings.TrimSpace(s)
	if v, err := strconv.ParseUint(s, 10, 32); err == nil {
		return uint32(v), true
	}
	if v, err := strconv.ParseInt(s, 10, 32); err == nil {
		return uint32(v), true
	}
	return 0, false
}

func decodeBitmask(v uint32, flags []struct {
	bit  uint32
	name string
}) string {
	var parts []string
	var matched uint32
	for _, f := range flags {
		if v&f.bit != 0 {
			parts = append(parts, f.name)
			matched |= f.bit
		}
	}
	if remaining := v &^ matched; remaining != 0 {
		parts = append(parts, fmt.Sprintf("0x%X", remaining))
	}
	if len(parts) == 0 {
		return "0 (0x0)"
	}
	return fmt.Sprintf("%d (0x%X): %s", v, v, strings.Join(parts, "|"))
}

func decodeUAC(s string) string {
	v, ok := decodeUint32Attr(s)
	if !ok {
		return s
	}
	return decodeBitmask(v, uacFlags)
}

func decodeSAMAccountType(s string) string {
	v, ok := decodeUint32Attr(s)
	if !ok {
		return s
	}
	if name, found := samAccountTypes[v]; found {
		return fmt.Sprintf("%d (0x%X): %s", v, v, name)
	}
	return fmt.Sprintf("%d (0x%X)", v, v)
}

func decodeGroupType(s string) string {
	v, ok := decodeUint32Attr(s)
	if !ok {
		return s
	}
	// groupType is declared as int32 in the schema, so treat it as signed for display.
	signed := int32(v)
	var parts []string
	var matched uint32
	for _, f := range groupTypeFlags {
		if v&f.bit != 0 {
			parts = append(parts, f.name)
			matched |= f.bit
		}
	}
	if remaining := v &^ matched; remaining != 0 {
		parts = append(parts, fmt.Sprintf("0x%X", remaining))
	}
	if !strings.Contains(strings.Join(parts, "|"), "SECURITY") {
		parts = append(parts, "DISTRIBUTION")
	}
	return fmt.Sprintf("%d (0x%X): %s", signed, v, strings.Join(parts, "|"))
}

func decodeTrustAttributes(s string) string {
	v, ok := decodeUint32Attr(s)
	if !ok {
		return s
	}
	return decodeBitmask(v, trustAttrFlags)
}

func decodeTrustDirection(s string) string {
	v, ok := decodeUint32Attr(s)
	if !ok {
		return s
	}
	if name, found := trustDirection[v]; found {
		return fmt.Sprintf("%d: %s", v, name)
	}
	return s
}

func decodeTrustType(s string) string {
	v, ok := decodeUint32Attr(s)
	if !ok {
		return s
	}
	if name, found := trustType[v]; found {
		return fmt.Sprintf("%d: %s", v, name)
	}
	return s
}

func decodeEncTypes(s string) string {
	v, ok := decodeUint32Attr(s)
	if !ok {
		return s
	}
	return decodeBitmask(v, encTypeFlags)
}

func decodePrimaryGroupID(s string) string {
	v, ok := decodeUint32Attr(s)
	if !ok {
		return s
	}
	if name, found := wellKnownRIDs[v]; found {
		return fmt.Sprintf("%d: %s", v, name)
	}
	return s
}

func decodePwdProperties(s string) string {
	v, ok := decodeUint32Attr(s)
	if !ok {
		return s
	}
	return decodeBitmask(v, pwdPropertiesFlags)
}

func decodeInstanceType(s string) string {
	v, ok := decodeUint32Attr(s)
	if !ok {
		return s
	}
	return decodeBitmask(v, instanceTypeFlags)
}

// structuralDecoders maps lowercased attribute names to a function that
// converts one raw string value to a human-readable one. Keep in sync with
// the switch in formatAttr.
var structuralDecoders = map[string]func(string) string{
	"useraccountcontrol":             decodeUAC,
	"samaccounttype":                 decodeSAMAccountType,
	"grouptype":                      decodeGroupType,
	"trustattributes":                decodeTrustAttributes,
	"trustdirection":                 decodeTrustDirection,
	"trusttype":                      decodeTrustType,
	"msds-supportedencryptiontypes":  decodeEncTypes,
	"primarygroupid":                 decodePrimaryGroupID,
	"pwdproperties":                  decodePwdProperties,
	"instancetype":                   decodeInstanceType,
}

