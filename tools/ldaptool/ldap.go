package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	ldap "github.com/jfjallid/ldap/v3"
)

// filetimeAttrs lists AD attributes whose values are Windows FILETIME
// integers (100-nanosecond intervals since 1601-01-01 UTC) stored as
// decimal strings. Lookup is case-insensitive (lowercase keys).
var filetimeAttrs = map[string]struct{}{
	"lastlogon":               {},
	"lastlogontimestamp":      {},
	"lastlogoff":              {},
	"pwdlastset":              {},
	"accountexpires":          {},
	"badpasswordtime":         {},
	"lockouttime":             {},
	"ms-ds-user-password-expiry-time-computed": {},
	"msds-user-password-expiry-time-computed":  {},
	"creationtime":            {},
	"ms-mcs-admpwdexpirationtime":              {},
}

// generalizedTimeAttrs lists AD attributes whose values are LDAP
// GeneralizedTime strings (e.g. "20260307120250.0Z"). Lookup is
// case-insensitive (lowercase keys).
var generalizedTimeAttrs = map[string]struct{}{
	"whencreated":                       {},
	"whenchanged":                       {},
	"dscorepropagationdata":             {},
	"msds-cached-membership-time-stamp": {},
	"msds-lastsuccessfulinteractivelogontime":   {},
	"msds-lastfailedinteractivelogontime":       {},
}

// knownBinaryAttrs lists attribute names whose values are always binary and
// should be base64-encoded for display. Lookup is case-insensitive (lowercase
// keys, callers must lowercase the attribute name first).
var knownBinaryAttrs = map[string]struct{}{
	"msmqsigncertificates":             {},
	"msmqdigests":                      {},
	"usercertificate":                  {},
	"cacertificate":                    {},
	"usersmimecertificate":             {},
	"mspki-accountcredentials":         {},
	"mspkiroamingtimestamp":            {},
	"mspkidpapimasterkeys":             {},
	"mspki-credentialroamingtokens":    {},
	"thumbnailphoto":                   {},
	"jpegphoto":                        {},
	"auditingpolicy":                   {},
	"dnsrecord":                        {},
	"repluptodatevector":               {},
	"repsfrom":                         {},
	"repsto":                           {},
	"msexchmailboxsecuritydescriptor":  {},
	"ntsecuritydescriptor":             {},
	"msds-generationid":                {},
	"schemaidguid":                     {},
	"attributesecurityguid":            {},
	"ms-ds-consistencyguid":            {},
	"ms-ds-creatorsid":                 {},
}

var knownStringAttrs = map[string]struct{} {
    "cn": 								{},
    "samaccountname": 					{},
    "userprincipalname": 				{},
    "distinguishedname": 				{},
    "name": 							{},
    "displayname": 						{},
    "givenname": 						{},
    "sn": 								{},
    "middlename": 						{},
    "initials": 						{},
    "title": 							{},
    "department": 						{},
    "company": 							{},
    "division": 						{},
    "office": 							{},
    "postalcode": 						{},
    "streetaddress": 					{},
    "l": 								{},
    "st": 								{},
    "co": 								{},
    "telephonenumber": 					{},
    "mobile": 							{},
    "facsimiletelephonenumber": 		{},
    "pager": 							{},
    "ipphone": 							{},
    "homephone": 						{},
    "othertelephone": 					{},
    "othermobile": 						{},
    "otherpager": 						{},
    "otheripphone": 					{},
    "otherhomephone": 					{},
    "otherfacsimiletelephonenumber":	{},
    "description": 						{},
    "info": 							{},
    "comment": 							{},
    "mail": 							{},
    "proxyaddresses": 					{},
    "legacyexchangedn": 				{},
    "targetaddress": 					{},
    "homemdb": 							{},
    "homemta": 							{},
    "msexchhomeservername": 			{},
    "member": 							{},
    "memberof": 						{},
    "managedby": 						{},
    "msds-additionaldnshostname": 		{},
    "physicaldeliveryofficename": 		{},
    "street": 							{},
    "postofficebox": 					{},
    "registeredaddress": 				{},
    "deliverylocation": 				{},
    "businesscategory": 				{},
    "seealso": 							{},
    "owner": 							{},
}

var helpSearchOptions = `
    Usage: ldaptool search [options]

    Search options:
          --filter         LDAP filter (default: "(objectClass=*)")
          --preset         Canned filter (overrides --filter). One of:
                             kerberoastable, asreproastable, admins, dcs,
                             computers, machine-accounts, trusts, gpos,
                             unconstrained
          --search-base    Override search base DN (overrides --base-dn)
          --scope          Search scope: base|one|sub (default: sub)
          --page-size      Result page size, 0 disables paging (default: 1000)
          --size-limit     Server-side size limit, 0 = unlimited (default: 0)
          --time-limit     Server-side time limit in seconds, 0 = unlimited (default: 0)
          --attrs          Comma-separated attributes to return. "*" for all user
                           attrs, "*,<operational attribute>" to also get a specific
                           operational attribute (default: *)
          --ldif           Emit LDIF instead of the human-readable format
          --json           Emit JSON instead of the human-readable format
          --control        Search control (repeatable). Recognised values:
                             show-deleted
                             server-sort=[+|-]<attr>[:matchingOid]
          --no-banner      Suppress the effective-request banner
          --no-schema-hint Skip the schema lookup that classifies unknown
                             octet-string attributes for display
          --out-file       Write output to specified file
` + helpConnectionOptions

var helpModifyOptions = `
    Usage: ldaptool modify [options]

    Modify options:
          --dn      DN of the object to modify (required)
          --set     Replace attribute: name=value (repeatable)
          --add     Add attribute value: name=value (repeatable)
          --delete  Delete attribute value: name=value (repeatable)

    Any value may be given as @<path> to load it from a file. Useful for
    binary attributes (DACLs, certificates) that don't fit on the command
    line. Example: --set nTSecurityDescriptor=@dacl.bin
` + helpConnectionOptions

// attrFlag collects multiple --set, --add, or --delete flags.
type attrFlag struct {
	entries []attrEntry
	op      string
}

type attrEntry struct {
	op    string
	name  string
	value string
}

func (f *attrFlag) String() string { return "" }

func (f *attrFlag) Set(val string) error {
	parts := strings.SplitN(val, "=", 2)
	if (len(parts) != 2 && f.op != "delete") || parts[0] == "" {
		return fmt.Errorf("expected name=value, got %q", val)
	}
	if len(parts) == 2 {
		f.entries = append(f.entries, attrEntry{op: f.op, name: parts[0], value: parts[1]})
	} else {
		f.entries = append(f.entries, attrEntry{op: f.op, name: parts[0]})
	}
	return nil
}

// repeatStrFlag collects multiple occurrences of the same string flag.
type repeatStrFlag []string

func (f *repeatStrFlag) String() string     { return strings.Join(*f, ",") }
func (f *repeatStrFlag) Set(v string) error { *f = append(*f, v); return nil }

type searchCmd struct {
	filter     string
	preset     string
	searchBase string
	scopeStr   string
	pageSize   uint
	sizeLimit  uint
	timeLimit  uint
	attrs      string
	outFile    string
	ldif       bool
	json       bool
	controls       repeatStrFlag
	noBanner       bool
	noSchemaHint   bool
}

// searchPresets maps a --preset name to a canned LDAP filter. Names match
// the things pentesters reach for repeatedly.
var searchPresets = map[string]string{
	"kerberoastable":   "(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
	"asreproastable":   "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
	"admins":           "(&(objectClass=group)(adminCount=1))",
	"dcs":              "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
	"computers":        "(objectClass=computer)",
	"machine-accounts": "(&(objectClass=computer)(sAMAccountName=*$))",
	"trusts":           "(objectClass=trustedDomain)",
	"gpos":             "(objectClass=groupPolicyContainer)",
	"unconstrained":    "(&(|(objectClass=user)(objectClass=computer))(userAccountControl:1.2.840.113556.1.4.803:=524288))",
}

func init() { register(&searchCmd{}) }

func (c *searchCmd) Name() string     { return "search" }
func (c *searchCmd) Synopsis() string { return "Search for LDAP objects" }
func (c *searchCmd) Usage() string    { return helpSearchOptions }

func (c *searchCmd) DefineFlags(f *flag.FlagSet) {
	f.StringVar(&c.filter, "filter", "(objectClass=user)", "LDAP search filter")
	f.StringVar(&c.preset, "preset", "", "Use a canned filter (overrides --filter). See --help.")
	f.StringVar(&c.searchBase, "search-base", "", "Override search base DN (overrides --base-dn for this search)")
	f.StringVar(&c.scopeStr, "scope", "sub", "Search scope: base|one|sub")
	f.UintVar(&c.pageSize, "page-size", 1000, "Paging size for search results (0 disables paging)")
	f.UintVar(&c.sizeLimit, "size-limit", 0, "Server-side size limit (0 = unlimited)")
	f.UintVar(&c.timeLimit, "time-limit", 0, "Server-side time limit in seconds (0 = unlimited)")
	f.StringVar(&c.attrs, "attrs", "*", "Comma-separated attributes (* for all, + for operational, *,+ for both)")
	f.StringVar(&c.outFile, "out-file", "", "Write output to specified file")
	f.BoolVar(&c.ldif, "ldif", false, "Emit LDIF output")
	f.BoolVar(&c.json, "json", false, "Emit JSON output")
	f.Var(&c.controls, "control", "Search control, repeatable (see --help)")
	f.BoolVar(&c.noBanner, "no-banner", false, "Suppress the effective-request banner")
	f.BoolVar(&c.noSchemaHint, "no-schema-hint", false, "Skip the schema lookup for unknown octet-string attributes")
}

// parseScope maps --scope values to ldap.Scope* constants.
func parseScope(s string) (int, error) {
	switch strings.ToLower(s) {
	case "base":
		return ldap.ScopeBaseObject, nil
	case "one", "onelevel", "single":
		return ldap.ScopeSingleLevel, nil
	case "sub", "subtree", "":
		return ldap.ScopeWholeSubtree, nil
	}
	return 0, fmt.Errorf("invalid --scope %q (want base, one, or sub)", s)
}

// parseControls turns the repeated --control strings into ldap.Control values.
func parseControls(specs []string) ([]ldap.Control, error) {
	var out []ldap.Control
	for _, spec := range specs {
		name, rest, _ := strings.Cut(strings.TrimSpace(spec), "=")
		switch strings.ToLower(name) {
		case "show-deleted":
			if rest != "" {
				return nil, fmt.Errorf("--control show-deleted takes no value")
			}
			out = append(out, ldap.NewControlMicrosoftShowDeleted())
		case "server-sort":
			if rest == "" {
				return nil, fmt.Errorf("--control server-sort requires an attribute")
			}
			reverse := false
			switch rest[0] {
			case '+':
				// Sort ascending
				rest = rest[1:]
			case '-':
				// Sort descending 
				reverse = true
				rest = rest[1:]
			default:
				// Sort ascending
			}
			attr, matchingOid, found := strings.Cut(rest, ":")
			if !found {
				logger.Infoln("No matchingOid specified for control server-sort. Falling back to 1.2.840.113556.1.4.1498 (English:United States)")
				matchingOid = "1.2.840.113556.1.4.1499"
			}
			out = append(out, ldap.NewControlServerSideSortingWithSortKeys(
				[]*ldap.SortKey{{AttributeType: attr, Reverse: reverse, MatchingRule: matchingOid}},
			))
		default:
			return nil, fmt.Errorf("unknown --control %q", spec)
		}
	}
	return out, nil
}

func (c *searchCmd) Run(a *connArgs) error {
	// Validate search-specific flags before opening a connection so typos in
	// --scope / --control / --preset fail fast.
	if c.ldif && c.json {
		return fmt.Errorf("--ldif and --json are mutually exclusive")
	}
	if c.preset != "" {
		f, ok := searchPresets[strings.ToLower(c.preset)]
		if !ok {
			names := mapKeysSorted(setFromMap(searchPresets))
			return fmt.Errorf("unknown --preset %q (known: %s)", c.preset, strings.Join(names, ", "))
		}
		c.filter = f
	}
	if _, err := parseScope(c.scopeStr); err != nil {
		return err
	}
	if _, err := parseControls(c.controls); err != nil {
		return err
	}
	if err := ensurePassword(a); err != nil {
		return fmt.Errorf("reading password: %w", err)
	}
	conn, baseDN, err := makeConnection(a)
	if err != nil {
		return err
	}
	defer conn.Close()
	return runSearch(conn, baseDN, c)
}

// setFromMap converts a string-keyed map into a string-set so mapKeysSorted
// (defined in rbcd.go) can produce a deterministic list of names.
func setFromMap[V any](m map[string]V) map[string]struct{} {
	out := make(map[string]struct{}, len(m))
	for k := range m {
		out[k] = struct{}{}
	}
	return out
}

// scopeName returns the display label for an ldap scope constant.
func scopeName(s int) string {
	switch s {
	case ldap.ScopeBaseObject:
		return "base"
	case ldap.ScopeSingleLevel:
		return "one"
	case ldap.ScopeWholeSubtree:
		return "sub"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}

// parseAttrList splits the --attrs string honouring "+" for operational attrs.
func parseAttrList(s string) []string {
	if s == "" {
		return []string{"*"}
	}
	var out []string
	for _, a := range strings.Split(s, ",") {
		a = strings.TrimSpace(a)
		if a != "" {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return []string{"*"}
	}
	return out
}

func runSearch(conn *ldap.Conn, baseDN string, c *searchCmd) error {
	if c.ldif && c.json {
		return fmt.Errorf("--ldif and --json are mutually exclusive")
	}

	base := baseDN
	if c.searchBase != "" {
		base = c.searchBase
	}
	scope, err := parseScope(c.scopeStr)
	if err != nil {
		return err
	}
	attrList := parseAttrList(c.attrs)
	controls, err := parseControls(c.controls)
	if err != nil {
		return err
	}

	output := os.Stdout
	if c.outFile != "" {
		f, err := os.OpenFile(c.outFile, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0640)
		if err != nil {
			return fmt.Errorf("--out-file: %w", err)
		}
		defer f.Close()
		output = f
	}

	if !c.noBanner {
		printSearchBanner(output, base, scope, c.filter, attrList, c, controls)
	}

	req := ldap.NewSearchRequest(
		base, scope, ldap.NeverDerefAliases,
		int(c.sizeLimit), int(c.timeLimit), false,
		c.filter, attrList, controls,
	)

	var entries []*ldap.Entry
	if c.pageSize == 0 {
		result, err := conn.Search(req)
		if err != nil {
			if ldap.IsErrorWithCode(err, 4) && c.sizeLimit != 0 {
				// log size limit exceeded but return data
				logger.Noticeln("Server reports: Size Limit Exceeded!")
			} else {
				fmt.Printf("%+v\n", err)
				return fmt.Errorf("search failed: %w", err)
			}
		}
		entries = result.Entries
	} else {
		result, err := conn.SearchWithPaging(req, uint32(c.pageSize))
		if err != nil {
			if ldap.IsErrorWithCode(err, 4) && c.sizeLimit != 0 {
				// log size limit exceeded but return data
				logger.Noticeln("Server reports: Size Limit Exceeded!")
			} else {
				fmt.Printf("%+v\n", err)
				return fmt.Errorf("search failed: %w", err)
			}
		}
		entries = result.Entries
	}

	// Auto-follow ranged attributes (member;range=0-1499, etc.).
	for _, e := range entries {
		if err := expandRangedAttrs(conn, e, controls); err != nil {
			fmt.Fprintf(os.Stderr, "warning: ranged-attr expansion for %s: %v\n", e.DN, err)
		}
	}

	// Best-effort: ask the schema only about attribute names from this
	// response that we don't already classify, so formatAttr base64-renders
	// octet-string (2.5.5.10) values even when their bytes look printable.
	// Silently ignore errors.
	if !c.noSchemaHint {
		loadSchemaBinaryAttrs(conn, entries)
	}

	switch {
	case c.ldif:
		writeLDIF(output, entries)
	case c.json:
		writeJSON(output, entries)
	default:
		writeHuman(output, entries)
	}
	return nil
}

func printSearchBanner(w io.Writer, base string, scope int, filter string, attrs []string, c *searchCmd, ctrls []ldap.Control) {
	fmt.Fprintln(w, "---- effective search request ----")
	fmt.Fprintf(w, "  base:       %s\n", base)
	fmt.Fprintf(w, "  scope:      %s\n", scopeName(scope))
	fmt.Fprintf(w, "  filter:     %s\n", filter)
	fmt.Fprintf(w, "  attrs:      %s\n", strings.Join(attrs, ", "))
	fmt.Fprintf(w, "  size-limit: %d\n", c.sizeLimit)
	fmt.Fprintf(w, "  time-limit: %d\n", c.timeLimit)
	fmt.Fprintf(w, "  page-size:  %d\n", c.pageSize)
	if len(ctrls) > 0 {
		names := make([]string, len(ctrls))
		for i, ctl := range ctrls {
			names[i] = ctl.GetControlType()
		}
		fmt.Fprintf(w, "  controls:   %s\n", strings.Join(names, ", "))
	}
	fmt.Fprintln(w, "----------------------------------")
}

func writeHuman(w io.Writer, entries []*ldap.Entry) {
	fmt.Fprintf(w, "Found %d entry(ies).\n\n", len(entries))
	for i, entry := range entries {
		fmt.Fprintf(w, "========== Entry %d ==========\n", i+1)
		fmt.Fprintf(w, "DN: %s\n", entry.DN)
		for _, attr := range entry.Attributes {
			values := formatAttr(attr)
			if len(values) == 1 {
				fmt.Fprintf(w, "  %s: %s\n", attr.Name, values[0])
			} else {
				fmt.Fprintf(w, "  %s:\n", attr.Name)
				for _, v := range values {
					fmt.Fprintf(w, "    - %s\n", v)
				}
			}
		}
		fmt.Fprintln(w, "")
	}
}

// ldifSafe reports whether a value can appear in LDIF as a plain "attr: value"
// line without base64 encoding. Per RFC 2849 §4: no NUL/LF/CR, no leading
// SPACE/`:`/`<`, no trailing SPACE, and all bytes must be printable ASCII.
func ldifSafe(v []byte) bool {
	if len(v) == 0 {
		return true
	}
	first := v[0]
	if first == ' ' || first == ':' || first == '<' {
		return false
	}
	if v[len(v)-1] == ' ' {
		return false
	}
	for _, b := range v {
		if b == 0 || b == '\n' || b == '\r' {
			return false
		}
		if b < 0x20 || b > 0x7E {
			return false
		}
	}
	return true
}

func writeLDIF(w io.Writer, entries []*ldap.Entry) {
	fmt.Fprintln(w, "version: 1")
	for _, entry := range entries {
		dnBytes := []byte(entry.DN)
		if ldifSafe(dnBytes) {
			fmt.Fprintf(w, "dn: %s\n", entry.DN)
		} else {
			fmt.Fprintf(w, "dn:: %s\n", base64.StdEncoding.EncodeToString(dnBytes))
		}
		for _, attr := range entry.Attributes {
			for _, bv := range attr.ByteValues {
				if ldifSafe(bv) {
					fmt.Fprintf(w, "%s: %s\n", attr.Name, string(bv))
				} else {
					fmt.Fprintf(w, "%s:: %s\n", attr.Name, base64.StdEncoding.EncodeToString(bv))
				}
			}
		}
		fmt.Fprintln(w)
	}
}

// jsonEntry is the shape we emit for each LDAP entry. Each attribute value is
// either a plain string (UTF-8 safe) or an object {"base64": "..."} for
// binary data.
type jsonEntry struct {
	DN         string                      `json:"dn"`
	Attributes map[string][]json.RawMessage `json:"attributes"`
}

func writeJSON(w io.Writer, entries []*ldap.Entry) {
	encoded := make([]jsonEntry, 0, len(entries))
	for _, entry := range entries {
		je := jsonEntry{DN: entry.DN, Attributes: map[string][]json.RawMessage{}}
		for _, attr := range entry.Attributes {
			vals := make([]json.RawMessage, 0, len(attr.ByteValues))
			for _, bv := range attr.ByteValues {
				if utf8.Valid(bv) && !hasControlByte(bv) {
					b, _ := json.Marshal(string(bv))
					vals = append(vals, b)
				} else {
					b, _ := json.Marshal(map[string]string{"base64": base64.StdEncoding.EncodeToString(bv)})
					vals = append(vals, b)
				}
			}
			je.Attributes[attr.Name] = vals
		}
		encoded = append(encoded, je)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(encoded); err != nil {
		fmt.Fprintf(os.Stderr, "json encode failed: %v\n", err)
	}
}

func hasControlByte(b []byte) bool {
	for _, c := range b {
		if c < 0x20 && c != '\t' {
			return true
		}
	}
	return false
}

// expandRangedAttrs walks entry.Attributes looking for ";range=" markers and
// issues follow-up base-scoped searches to collect the remaining values.
// Matching values are merged back into the original attribute name.
func expandRangedAttrs(conn *ldap.Conn, entry *ldap.Entry, controls []ldap.Control) error {
	for i := 0; i < len(entry.Attributes); i++ {
		attr := entry.Attributes[i]
		baseName, rangeSpec, ok := splitRangedAttr(attr.Name)
		if !ok {
			continue
		}
		upperStr := strings.SplitN(rangeSpec, "-", 2)[1]
		if upperStr == "*" {
			// Final chunk — rename the attribute back to its base name.
			entry.Attributes[i].Name = baseName
			continue
		}
		upper, err := strconv.Atoi(upperStr)
		if err != nil {
			return fmt.Errorf("parse range upper %q: %w", upperStr, err)
		}
		merged := attr.ByteValues
		next := upper + 1
		for {
			chunkAttr := fmt.Sprintf("%s;range=%d-*", baseName, next)
			req := ldap.NewSearchRequest(
				entry.DN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
				0, 0, false, "(objectClass=*)", []string{chunkAttr}, controls,
			)
			res, err := conn.Search(req)
			if err != nil {
				return fmt.Errorf("ranged search %s: %w", chunkAttr, err)
			}
			if len(res.Entries) != 1 {
				return fmt.Errorf("ranged search returned %d entries", len(res.Entries))
			}
			var gotAttr *ldap.EntryAttribute
			var gotUpper string
			for _, a := range res.Entries[0].Attributes {
				if bn, rs, ok := splitRangedAttr(a.Name); ok && strings.EqualFold(bn, baseName) {
					gotAttr = a
					gotUpper = strings.SplitN(rs, "-", 2)[1]
					break
				}
			}
			if gotAttr == nil {
				break
			}
			merged = append(merged, gotAttr.ByteValues...)
			if gotUpper == "*" {
				break
			}
			u, err := strconv.Atoi(gotUpper)
			if err != nil {
				return fmt.Errorf("parse follow-up range upper %q: %w", gotUpper, err)
			}
			next = u + 1
		}
		entry.Attributes[i].Name = baseName
		entry.Attributes[i].ByteValues = merged
		entry.Attributes[i].Values = byteSlicesToStrings(merged)
	}
	return nil
}

func splitRangedAttr(name string) (base, rng string, ok bool) {
	parts := strings.SplitN(name, ";", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	if !strings.HasPrefix(strings.ToLower(parts[1]), "range=") {
		return "", "", false
	}
	return parts[0], parts[1][len("range="):], true
}

// schemaDNCache holds the discovered schema NC DN, populated lazily on the
// first call that has unknown attributes to look up.
var schemaDNCache string

// knownNonBinaryAttrs records attribute names confirmed (or assumed, after a
// negative schema lookup) to NOT be octet-string syntax, so we don't re-ask
// for them on subsequent searches in the same process.
var knownNonBinaryAttrs = map[string]struct{}{}

// loadSchemaBinaryAttrs walks entries for attribute names not already
// classified, then issues a single batched schema query asking only about
// those names. Octet-string (2.5.5.10) attrs are added to knownBinaryAttrs;
// everything else is recorded in knownNonBinaryAttrs as a negative cache.
// Failures are silent — this is a rendering hint, not a correctness
// requirement.
func loadSchemaBinaryAttrs(conn *ldap.Conn, entries []*ldap.Entry) {
	unknown := map[string]struct{}{}
	for _, e := range entries {
		for _, a := range e.Attributes {
			name := strings.ToLower(a.Name)
			if i := strings.Index(name, ";"); i >= 0 {
				name = name[:i]
			}
			if name == "" {
				continue
			}
			if _, ok := knownBinaryAttrs[name]; ok {
				continue
			}
			if _, ok := knownStringAttrs[name]; ok {
				continue
			}
			if _, ok := knownNonBinaryAttrs[name]; ok {
				continue
			}
			if !isSafeAttrName(name) {
				continue
			}
			unknown[name] = struct{}{}
		}
	}
	if len(unknown) == 0 {
		return
	}

	if schemaDNCache == "" {
		rootRes, err := conn.Search(ldap.NewSearchRequest(
			"", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
			0, 0, false, "(objectClass=*)",
			[]string{"schemaNamingContext"}, nil,
		))
		if err != nil || len(rootRes.Entries) == 0 {
			return
		}
		schemaDNCache = rootRes.Entries[0].GetAttributeValue("schemaNamingContext")
		if schemaDNCache == "" {
			return
		}
	}

	names := make([]string, 0, len(unknown))
	for n := range unknown {
		names = append(names, n)
	}

	// AD's MaxFilterComponents defaults to 1024; chunk well under that.
	const chunkSize = 500
	for i := 0; i < len(names); i += chunkSize {
		end := i + chunkSize
		if end > len(names) {
			end = len(names)
		}
		chunk := names[i:end]

		var b strings.Builder
		b.WriteString("(&(objectClass=attributeSchema)(|")
		for _, n := range chunk {
			b.WriteString("(lDAPDisplayName=")
			b.WriteString(n)
			b.WriteString(")")
		}
		b.WriteString("))")

		res, err := conn.SearchWithPaging(ldap.NewSearchRequest(
			schemaDNCache, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
			0, 0, false, b.String(),
			[]string{"lDAPDisplayName", "attributeSyntax"}, nil,
		), 500)
		if err != nil {
			return
		}
		seen := map[string]struct{}{}
		for _, e := range res.Entries {
			name := strings.ToLower(e.GetAttributeValue("lDAPDisplayName"))
			if name == "" {
				continue
			}
			seen[name] = struct{}{}
			if e.GetAttributeValue("attributeSyntax") == "2.5.5.10" {
				knownBinaryAttrs[name] = struct{}{}
			} else {
				knownNonBinaryAttrs[name] = struct{}{}
			}
		}
		// Names we asked about but didn't get back (subtypes, aliases,
		// missing schema entry) — record as non-binary so we don't re-ask.
		for _, n := range chunk {
			if _, ok := seen[n]; !ok {
				knownNonBinaryAttrs[n] = struct{}{}
			}
		}
	}
}

// isSafeAttrName reports whether s is plausibly an LDAP attribute descriptor
// safe to drop into an unescaped filter (letters/digits/hyphen only).
func isSafeAttrName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-':
		default:
			return false
		}
	}
	return true
}

func byteSlicesToStrings(bs [][]byte) []string {
	out := make([]string, len(bs))
	for i, b := range bs {
		out[i] = string(b)
	}
	return out
}

type modifyCmd struct {
	dn       string
	setAttrs attrFlag
	addAttrs attrFlag
	delAttrs attrFlag
}

func init() { register(&modifyCmd{}) }

func (c *modifyCmd) Name() string     { return "modify" }
func (c *modifyCmd) Synopsis() string { return "Modify attributes on an LDAP object" }
func (c *modifyCmd) Usage() string    { return helpModifyOptions }

func (c *modifyCmd) DefineFlags(f *flag.FlagSet) {
	c.setAttrs.op = "replace"
	c.addAttrs.op = "add"
	c.delAttrs.op = "delete"
	f.StringVar(&c.dn, "dn", "", "DN of the object to modify (required)")
	f.Var(&c.setAttrs, "set", "Replace attribute: name=value (repeatable)")
	f.Var(&c.addAttrs, "add", "Add attribute value: name=value (repeatable)")
	f.Var(&c.delAttrs, "delete", "Delete attribute value: name[=value] (repeatable)")
}

func (c *modifyCmd) Run(a *connArgs) error {
	if err := ensurePassword(a); err != nil {
		return fmt.Errorf("reading password: %w", err)
	}
	conn, _, err := makeConnection(a)
	if err != nil {
		return err
	}
	defer conn.Close()
	return runModify(conn, c, os.Stdout)
}
func runModify(conn *ldap.Conn, c *modifyCmd, w io.Writer) error {
	if c.dn == "" {
		return fmt.Errorf("--dn is required for modify")
	}

	allEntries := append(append(c.setAttrs.entries, c.addAttrs.entries...), c.delAttrs.entries...)
	if len(allEntries) == 0 {
		return fmt.Errorf("at least one --set, --add, or --delete flag is required")
	}

	// Resolve "@file" indirections — value "@path" means read the bytes from
	// path and use them as the literal attribute value. Useful for binary
	// attributes (DACLs, certs).
	resolved := make([]attrEntry, len(allEntries))
	for i, e := range allEntries {
		if strings.HasPrefix(e.value, "@") {
			path := e.value[1:]
			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read %s for %s: %w", path, e.name, err)
			}
			e.value = string(data)
		}
		resolved[i] = e
	}

	modReq := ldap.NewModifyRequest(c.dn, nil)
	for _, e := range resolved {
		switch e.op {
		case "replace":
			modReq.Replace(e.name, []string{e.value})
		case "add":
			modReq.Add(e.name, []string{e.value})
		case "delete":
			attrVals := []string{}
			if e.value != "" {
				attrVals = append(attrVals, e.value)
			}
			modReq.Delete(e.name, attrVals)
		}
	}

	if err := conn.Modify(modReq); err != nil {
		return fmt.Errorf("modify failed: %w", err)
	}

	fmt.Fprintf(w, "Successfully modified: %s\n", c.dn)
	for _, e := range allEntries {
		// Show the original (unresolved) value so log output stays compact.
		display := e.value
		if len(display) > 80 {
			display = display[:77] + "..."
		}
		if display == "" {
			fmt.Fprintf(w, "  %s %s\n", e.op, e.name)
		} else {
			fmt.Fprintf(w, "  %s %s = %s\n", e.op, e.name, display)
		}
	}
	return nil
}

// formatAttr returns human-readable string values for known binary AD attributes.
func formatAttr(attr *ldap.EntryAttribute) []string {
	switch strings.ToLower(attr.Name) {
	case "objectguid":
		if len(attr.ByteValues) == 1 {
			if s, ok := decodeGUID(attr.ByteValues[0]); ok {
				return []string{s}
			}
		}
	case "objectsid":
		if len(attr.ByteValues) == 1 {
			if s, ok := decodeSID(attr.ByteValues[0]); ok {
				return []string{s}
			}
		}
	case "logonhours":
		if len(attr.ByteValues) == 1 {
			return []string{formatLogonHours(attr.ByteValues[0])}
		}
	}

	lname := strings.ToLower(attr.Name)
	if _, ok := filetimeAttrs[lname]; ok {
		out := make([]string, len(attr.Values))
		for i, v := range attr.Values {
			out[i] = formatFiletime(v)
		}
		return out
	}

	if _, ok := generalizedTimeAttrs[lname]; ok {
		out := make([]string, len(attr.Values))
		for i, v := range attr.Values {
			out[i] = formatGeneralizedTime(v)
		}
		return out
	}

	if decoder, ok := structuralDecoders[lname]; ok {
		out := make([]string, len(attr.Values))
		for i, v := range attr.Values {
			out[i] = decoder(v)
		}
		return out
	}

	if _, ok := knownBinaryAttrs[lname]; ok {
		out := make([]string, len(attr.ByteValues))
		for i, b := range attr.ByteValues {
			out[i] = renderBinary(b)
		}
		return out
	}

	for i, b := range attr.ByteValues {
		if isLikelyBinary(b) {
			out := make([]string, len(attr.ByteValues))
			for j, bb := range attr.ByteValues {
				if j < i || !isLikelyBinary(bb) {
					out[j] = attr.Values[j]
				} else {
					out[j] = renderBinary(bb)
				}
			}
			return out
		}
	}
	return attr.Values
}

// isLikelyBinary reports whether b should be treated as binary data unsuitable
// for direct terminal output. A value is considered binary if it is not valid
// UTF-8 or contains a NUL byte or non-printable control byte (other than
// tab, CR, or LF).
func isLikelyBinary(b []byte) bool {
	if !utf8.Valid(b) {
		return true
	}
	for _, c := range b {
		if c < 0x20 && c != '\t' && c != '\r' && c != '\n' {
			return true
		}
	}
	return false
}

// formatFiletime converts a Windows FILETIME decimal string (100-ns intervals
// since 1601-01-01 UTC) to an ISO 8601 timestamp. Returns "(never)" for 0 and
// "(never expires)" for 0x7FFFFFFFFFFFFFFF, the standard AD sentinel values.
func formatFiletime(s string) string {
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return s
	}
	if v == 0 {
		return "(never)"
	}
	if v == 0x7FFFFFFFFFFFFFFF {
		return "(never expires)"
	}
	// FILETIME epoch is 1601-01-01; offset to Unix epoch is 11644473600 seconds.
	const epochDiff = 11644473600
	secs := v/10000000 - epochDiff
	nsec := (v % 10000000) * 100
	t := time.Unix(secs, nsec).UTC()
	return t.Format("2006-01-02 15:04:05 UTC") + fmt.Sprintf(" (%s)", s)
}

// formatGeneralizedTime parses an LDAP GeneralizedTime value (e.g.
// "20260307120250.0Z") and returns it in the same ISO format used for
// FILETIME values. Falls back to the raw value on parse failure.
func formatGeneralizedTime(s string) string {
	layouts := []string{
		"20060102150405.0Z",
		"20060102150405Z",
		"20060102150405.0-0700",
		"20060102150405-0700",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC().Format("2006-01-02 15:04:05 UTC")
		}
	}
	return s
}

// renderBinary returns a safe display representation of a binary value.
func renderBinary(b []byte) string {
	return fmt.Sprintf("(binary, %d bytes) base64:%s", len(b), base64.StdEncoding.EncodeToString(b))
}

// decodeGUID converts a 16-byte AD objectGUID to the standard
// GUID string format. AD stores the first three components in
// little-endian byte order.
func decodeGUID(b []byte) (string, bool) {
	if len(b) != 16 {
		return "", false
	}
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.LittleEndian.Uint32(b[0:4]),
		binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]),
		b[8:10],
		b[10:16],
	), true
}

// decodeSID converts a binary SID to the S-1-... string format.
func decodeSID(b []byte) (string, bool) {
	if len(b) < 8 {
		return "", false
	}
	revision := b[0]
	subAuthCount := int(b[1])
	if len(b) < 8+4*subAuthCount {
		return "", false
	}

	var authority uint64
	for i := 2; i < 8; i++ {
		authority = authority<<8 | uint64(b[i])
	}

	s := fmt.Sprintf("S-%d-%d", revision, authority)
	for i := 0; i < subAuthCount; i++ {
		subAuth := binary.LittleEndian.Uint32(b[8+4*i:])
		s += fmt.Sprintf("-%d", subAuth)
	}
	return s, true
}

// formatLogonHours renders the 21-byte logonHours bitmap as a per-day schedule.
func formatLogonHours(b []byte) string {
	if len(b) != 21 {
		return fmt.Sprintf("(unexpected %d bytes)", len(b))
	}

	days := []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}
	allPermitted := true
	nonePermitted := true
	for _, v := range b {
		if v != 0xFF {
			allPermitted = false
		}
		if v != 0x00 {
			nonePermitted = false
		}
	}
	if allPermitted {
		return "All hours permitted"
	}
	if nonePermitted {
		return "No hours permitted"
	}

	var lines []string
	for d := 0; d < 7; d++ {
		dayBytes := b[d*3 : d*3+3]
		var hours []string
		rangeStart := -1
		for h := 0; h < 24; h++ {
			byteIdx := h / 8
			bitIdx := uint(h % 8)
			permitted := dayBytes[byteIdx]&(1<<bitIdx) != 0
			if permitted && rangeStart < 0 {
				rangeStart = h
			}
			if (!permitted || h == 23) && rangeStart >= 0 {
				end := h
				if permitted && h == 23 {
					end = 24
				}
				hours = append(hours, fmt.Sprintf("%02d:00-%02d:00", rangeStart, end))
				rangeStart = -1
			}
		}
		if len(hours) == 0 {
			hours = []string{"(denied)"}
		}
		lines = append(lines, fmt.Sprintf("%s: %s", days[d], strings.Join(hours, ", ")))
	}
	return strings.Join(lines, "; ")
}
