package main

import (
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"strings"
	"unicode/utf16"

	ldap "github.com/jfjallid/ldap/v3"
)

var helpCreateUserOptions = `
    Usage: ldaptool create-user [options]

    Create user options:
          --cn              Common name / display name (required)
          --sam             sAMAccountName (required)
          --ou              OU to create user in (full DN; default: CN=Users,<base-dn>)
          --upn             userPrincipalName
          --given-name      First name
          --sn              Last name
          --description     Description
          --user-password   Initial password (requires LDAPS or StartTLS)
          --enabled         Enable the account (default: disabled)
` + helpConnectionOptions

var helpCreateComputerOptions = `
    Usage: ldaptool create-computer [options]

    Create computer options:
          --cn              Computer name without trailing $ (required)
          --ou              OU to create computer in (full DN; default: CN=Computers,<base-dn>)
          --description     Description
          --managed-by      DN of the managing user/group
` + helpConnectionOptions

type createUserCmd struct {
	cn          string
	sam         string
	ou          string
	upn         string
	givenName   string
	sn          string
	description string
	userPass    string
	enabled     bool
}

func init() { register(&createUserCmd{}) }

func (c *createUserCmd) Name() string     { return "create-user" }
func (c *createUserCmd) Synopsis() string { return "Create a new user account" }
func (c *createUserCmd) Usage() string    { return helpCreateUserOptions }

func (c *createUserCmd) DefineFlags(f *flag.FlagSet) {
	f.StringVar(&c.cn, "cn", "", "Common name / display name (required)")
	f.StringVar(&c.sam, "sam", "", "sAMAccountName (required)")
	f.StringVar(&c.ou, "ou", "", "OU DN (default: CN=Users,<base-dn>)")
	f.StringVar(&c.upn, "upn", "", "userPrincipalName")
	f.StringVar(&c.givenName, "given-name", "", "First name")
	f.StringVar(&c.sn, "sn", "", "Last name")
	f.StringVar(&c.description, "description", "", "Description")
	f.StringVar(&c.userPass, "user-password", "", "Initial password (requires LDAPS/StartTLS)")
	f.BoolVar(&c.enabled, "enabled", false, "Enable the account")
}

func (c *createUserCmd) Run(a *connArgs) error {
	if err := ensurePassword(a); err != nil {
		return fmt.Errorf("reading password: %w", err)
	}
	conn, baseDN, err := makeConnection(a)
	if err != nil {
		return err
	}
	defer conn.Close()
	return runCreateUser(conn, baseDN, c)
}

type createComputerCmd struct {
	cn          string
	ou          string
	description string
	managedBy   string
	password    string
	domain      string
}

func init() { register(&createComputerCmd{}) }

func (c *createComputerCmd) Name() string     { return "create-computer" }
func (c *createComputerCmd) Synopsis() string { return "Create a new computer account" }
func (c *createComputerCmd) Usage() string    { return helpCreateComputerOptions }

func (c *createComputerCmd) DefineFlags(f *flag.FlagSet) {
	f.StringVar(&c.cn, "cn", "", "Computer name without $ (required)")
	f.StringVar(&c.ou, "ou", "", "OU DN (default: CN=Computers,<base-dn>)")
	f.StringVar(&c.description, "description", "", "Description")
	f.StringVar(&c.managedBy, "managed-by", "", "DN of the managing user/group")
	f.StringVar(&c.password, "password", "", "Initial password (random if omitted; requires LDAPS/StartTLS)")
	f.StringVar(&c.domain, "computer-domain", "", "Computer domain name for SPNs (default is specified auth domain")
}

func (c *createComputerCmd) Run(a *connArgs) error {
	if err := ensurePassword(a); err != nil {
		return fmt.Errorf("reading password: %w", err)
	}
	conn, baseDN, err := makeConnection(a)
	if err != nil {
		return err
	}
	defer conn.Close()
	if c.domain == "" {
		c.domain = a.domain
	}
	return runCreateComputer(conn, baseDN, c)
}

func runCreateUser(conn *ldap.Conn, baseDN string, c *createUserCmd) error {
	if c.cn == "" || c.sam == "" {
		return fmt.Errorf("--cn and --sam are required")
	}

	container := c.ou
	if container == "" {
		container = "CN=Users," + baseDN
	}

	userDN := fmt.Sprintf("CN=%s,%s", ldap.EscapeDN(c.cn), container)

	addReq := ldap.NewAddRequest(userDN, nil)
	addReq.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
	addReq.Attribute("cn", []string{c.cn})
	addReq.Attribute("sAMAccountName", []string{c.sam})

	if c.upn != "" {
		addReq.Attribute("userPrincipalName", []string{c.upn})
	}
	if c.givenName != "" {
		addReq.Attribute("givenName", []string{c.givenName})
	}
	if c.sn != "" {
		addReq.Attribute("sn", []string{c.sn})
	}
	if c.description != "" {
		addReq.Attribute("description", []string{c.description})
	}
	if c.userPass != "" {
		quoted := "\"" + c.userPass + "\""
		encoded := encodeUTF16LE(quoted)
		addReq.Attribute("unicodePwd", []string{string(encoded)})
	}

	// userAccountControl: 514 = disabled (0x202), 512 = enabled normal account (0x200)
	uac := "514"
	if c.enabled {
		if c.userPass == "" {
			logger.Errorln("Cannot create enabled user account without a password")
		} else {
			uac = "512"
		}
	}
	addReq.Attribute("userAccountControl", []string{uac})

	if err := conn.Add(addReq); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}
	fmt.Printf("User created: %s\n", userDN)
	return nil
}

func runCreateComputer(conn *ldap.Conn, baseDN string, c *createComputerCmd) error {
	if c.cn == "" {
		return fmt.Errorf("--cn is required")
	}

	container := c.ou
	if container == "" {
		container = "CN=Computers," + baseDN
	}

	computerNameUpper := strings.ToUpper(c.cn)
	computerName := strings.ToLower(c.cn)
	computerDN := fmt.Sprintf("CN=%s,%s", ldap.EscapeDN(computerNameUpper), container)
	samName := computerNameUpper + "$"

	addReq := ldap.NewAddRequest(computerDN, nil)
	addReq.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user", "computer"})
	addReq.Attribute("cn", []string{computerNameUpper})
	addReq.Attribute("sAMAccountName", []string{samName})
	// userAccountControl 4096 = WORKSTATION_TRUST_ACCOUNT
	addReq.Attribute("userAccountControl", []string{"4096"})
	addReq.Attribute("dnsHostName", []string{computerName + "." + c.domain})

	if c.description != "" {
		addReq.Attribute("description", []string{c.description})
	}
	if c.managedBy != "" {
		addReq.Attribute("managedBy", []string{c.managedBy})
	}
	spns := []string{
		fmt.Sprintf("HOST/%s", computerNameUpper),
		fmt.Sprintf("HOST/%s.%s", computerName, c.domain),
		fmt.Sprintf("RestrictedKrbHost/%s", computerNameUpper),
		fmt.Sprintf("RestrictedKrbHost/%s.%s", computerName, c.domain),
	}
	addReq.Attribute("servicePrincipalName", spns)

	pw := c.password
	if pw == "" {
		generated, err := randomComputerPassword()
		if err != nil {
			return fmt.Errorf("failed to generate computer account password: %v", err)
		}
		pw = generated
	}
	// Encode password
	quoted := "\"" + pw + "\""
	encoded := encodeUTF16LE(quoted)
	addReq.Attribute("unicodePwd", []string{string(encoded)})

	if err := conn.Add(addReq); err != nil {
		return fmt.Errorf("failed to create computer: %w", err)
	}
	if c.password == "" {
		fmt.Printf("Computer created: %s with generated password: %s\n", computerDN, pw)
	} else {
		fmt.Printf("Computer created: %s\n", computerDN)
	}
	return nil
}

// randomComputerPassword returns a 24-char alnum password sufficient for
// machine accounts. The character set excludes ambiguous characters (0/O,
// 1/l/I) to keep the printout readable.
func randomComputerPassword() (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	out := make([]byte, 24)
	buf := make([]byte, len(out))
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	for i, b := range buf {
		out[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(out), nil
}

func encodeUTF16LE(s string) []byte {
	runes := []rune(s)
	u16 := utf16.Encode(runes)
	b := make([]byte, len(u16)*2)
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(b[i*2:], v)
	}
	return b
}
