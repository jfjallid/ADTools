package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"strings"
	"time"

	ldap "github.com/jfjallid/ldap/v3"
)

var helpLAPSOptions = `
    Usage: ldaptool laps [options]

    Read LAPS-managed local administrator passwords. Searches for computers
    with one of:
      - ms-Mcs-AdmPwd                (legacy "Microsoft LAPS")
      - msLAPS-Password              (Windows LAPS, plaintext)
      - msLAPS-EncryptedPassword     (Windows LAPS, DPAPI-NG protected)

    The encrypted variant is reported but not decrypted — that requires
    DPAPI-NG with a domain protector key, which lives outside this tool.

    Options:
          --target   Limit to a single computer by sAMAccountName.
                     If omitted, all computers with a readable LAPS
                     attribute are returned.
` + helpConnectionOptions

type lapsCmd struct {
	target string
}

func init() { register(&lapsCmd{}) }

func (c *lapsCmd) Name() string     { return "laps" }
func (c *lapsCmd) Synopsis() string { return "Read LAPS local-admin passwords" }
func (c *lapsCmd) Usage() string    { return helpLAPSOptions }

func (c *lapsCmd) DefineFlags(f *flag.FlagSet) {
	f.StringVar(&c.target, "target", "", "Limit to one computer by sAMAccountName")
}

func (c *lapsCmd) Run(a *connArgs) error {
	if err := ensurePassword(a); err != nil {
		return fmt.Errorf("reading password: %w", err)
	}
	conn, baseDN, err := makeConnection(a)
	if err != nil {
		return err
	}
	defer conn.Close()

	const lapsAttrs = "ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime,msLAPS-Password,msLAPS-EncryptedPassword,msLAPS-PasswordExpirationTime"
	requested := strings.Split(lapsAttrs, ",")

	filterParts := []string{
		"(ms-Mcs-AdmPwd=*)",
		"(msLAPS-Password=*)",
		"(msLAPS-EncryptedPassword=*)",
	}
	filter := "(&(objectClass=computer)(|" + strings.Join(filterParts, "") + "))"
	if c.target != "" {
		sam := c.target
		if !strings.HasSuffix(sam, "$") {
			sam += "$"
		}
		filter = fmt.Sprintf("(&(objectClass=computer)(sAMAccountName=%s))", ldap.EscapeFilter(sam))
	}

	req := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter,
		append([]string{"sAMAccountName", "dNSHostName", "distinguishedName"}, requested...),
		nil,
	)
	res, err := conn.SearchWithPaging(req, 1000)
	if err != nil {
		return fmt.Errorf("LDAP search failed: %w", err)
	}
	if len(res.Entries) == 0 {
		fmt.Println("No matching entries found.")
		return nil
	}

	for _, entry := range res.Entries {
		printLAPSEntry(entry)
	}
	return nil
}

func printLAPSEntry(e *ldap.Entry) {
	sam := e.GetAttributeValue("sAMAccountName")
	host := e.GetAttributeValue("dNSHostName")
	fmt.Printf("=== %s (%s) ===\n", sam, host)
	fmt.Printf("DN: %s\n", e.DN)

	if v := e.GetAttributeValue("ms-Mcs-AdmPwd"); v != "" {
		fmt.Printf("  ms-Mcs-AdmPwd:                  %s\n", v)
		if exp := e.GetAttributeValue("ms-Mcs-AdmPwdExpirationTime"); exp != "" {
			fmt.Printf("  ms-Mcs-AdmPwdExpirationTime:    %s\n", formatFiletime(exp))
		}
	}
	if v := e.GetAttributeValue("msLAPS-Password"); v != "" {
		fmt.Printf("  msLAPS-Password:                %s\n", formatLAPSPassword(v))
	}
	if a := e.GetRawAttributeValue("msLAPS-EncryptedPassword"); len(a) > 0 {
		fmt.Printf("  msLAPS-EncryptedPassword:       %s\n", formatLAPSEncrypted(a))
	}
	if exp := e.GetAttributeValue("msLAPS-PasswordExpirationTime"); exp != "" {
		fmt.Printf("  msLAPS-PasswordExpirationTime:  %s\n", formatFiletime(exp))
	}
	fmt.Println()
}

// formatLAPSPassword decodes the JSON envelope used by Windows LAPS:
// { "n":"<account>", "t":"<filetime hex>", "p":"<password>" }
// Anything else is printed as-is.
func formatLAPSPassword(v string) string {
	if !strings.HasPrefix(v, "{") {
		return v
	}
	// Hand-roll a tiny JSON extractor — pulling encoding/json just for this
	// would be overkill, and the field set is fixed.
	parts := map[string]string{}
	for _, key := range []string{"n", "t", "p"} {
		needle := `"` + key + `":"`
		i := strings.Index(v, needle)
		if i < 0 {
			continue
		}
		rest := v[i+len(needle):]
		end := strings.IndexByte(rest, '"')
		if end < 0 {
			continue
		}
		parts[key] = rest[:end]
	}
	if parts["p"] == "" {
		return v
	}
	tStr := parts["t"]
	if tBytes, err := hex.DecodeString(tStr); err == nil && len(tBytes) == 8 {
		ticks := binary.LittleEndian.Uint64(tBytes)
		t := windowsTicksToTime(ticks)
		if !t.IsZero() {
			return fmt.Sprintf("%s (account=%s, last-changed=%s)",
				parts["p"], parts["n"], t.UTC().Format(time.RFC3339))
		}
	}
	return fmt.Sprintf("%s (account=%s)", parts["p"], parts["n"])
}

// formatLAPSEncrypted gives a one-liner summary of the DPAPI-NG-protected
// blob without attempting to decrypt it.
func formatLAPSEncrypted(b []byte) string {
	if len(b) < 16 {
		return fmt.Sprintf("(encrypted, %d bytes — too short to parse)", len(b))
	}
	// Layout per [MS-LSAD] / msLAPS spec: 8-byte FILETIME timestamp,
	// 4-byte BLOB length, 4-byte flags, then the DPAPI-NG blob.
	ticks := binary.LittleEndian.Uint64(b[0:8])
	blobLen := binary.LittleEndian.Uint32(b[8:12])
	flags := binary.LittleEndian.Uint32(b[12:16])
	t := windowsTicksToTime(ticks)
	when := "(invalid timestamp)"
	if !t.IsZero() {
		when = t.UTC().Format(time.RFC3339)
	}
	return fmt.Sprintf("(encrypted DPAPI-NG, %d bytes; timestamp=%s; blob-len=%d; flags=0x%x; not decrypted)",
		len(b), when, blobLen, flags)
}
