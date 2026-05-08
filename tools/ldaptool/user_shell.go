package main

import (
	"fmt"
	"strings"

	ldap "github.com/jfjallid/ldap/v3"
)

const (
	ShellCreateUser     = "createuser"
	ShellCreateComputer = "createcomputer"
)

var userUsageKeys = []string{
	ShellCreateUser,
	ShellCreateComputer,
}

func init() {
	usageMap[ShellCreateUser] = ShellCreateUser + " -cn <n> -sam <s> [-ou dn] [-upn u] [-given-name g] [-sn s] [-desc d] [-user-password p] [-enabled]"
	usageMap[ShellCreateComputer] = ShellCreateComputer + " -cn <n> [-ou dn] [-desc d] [-managed-by dn] [-domain d] [-pass pw]"

	descriptionMap[ShellCreateUser] = "Create a new AD user account"
	descriptionMap[ShellCreateComputer] = "Create a new AD computer account"

	handlers[ShellCreateUser] = shellCreateUserCmd
	handlers[ShellCreateComputer] = shellCreateComputerCmd

	allKeys = append(allKeys, userUsageKeys...)

	helpFunctions[3] = func(self *shell) {
		self.showCustomHelpFunc(90, "User & Computer", userUsageKeys)
	}
}

func shellCreateUserCmd(self *shell, argArr any) {
	if self.conn == nil || !self.authenticated {
		self.println("Not connected. Use 'connect' and 'login' first.")
		return
	}

	args := argArr.([]string)
	fs, buf := self.newFlagSet("createuser")
	cn := fs.String("cn", "", "Common name / display name (required)")
	sam := fs.String("sam", "", "sAMAccountName (required)")
	ou := fs.String("ou", "", "OU DN")
	upn := fs.String("upn", "", "userPrincipalName")
	givenName := fs.String("given-name", "", "First name")
	sn := fs.String("sn", "", "Last name")
	description := fs.String("desc", "", "Description")
	userPass := fs.String("user-password", "", "Initial password (requires LDAPS/StartTLS)")
	enabled := fs.Bool("enabled", false, "Enable the account")

	if err := fs.Parse(args); err != nil {
		if buf.Len() > 0 {
			self.printf("%s\n", buf.String())
		}
		return
	}

	if *cn == "" || *sam == "" {
		self.println("Error: -cn and -sam are required")
		self.println("Usage: " + usageMap[ShellCreateUser])
		return
	}

	container := *ou
	if container == "" {
		container = "CN=Users," + self.baseDN
	}

	userDN := fmt.Sprintf("CN=%s,%s", ldap.EscapeDN(*cn), container)

	addReq := ldap.NewAddRequest(userDN, nil)
	addReq.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
	addReq.Attribute("cn", []string{*cn})
	addReq.Attribute("sAMAccountName", []string{*sam})

	if *upn != "" {
		addReq.Attribute("userPrincipalName", []string{*upn})
	}
	if *givenName != "" {
		addReq.Attribute("givenName", []string{*givenName})
	}
	if *sn != "" {
		addReq.Attribute("sn", []string{*sn})
	}
	if *description != "" {
		addReq.Attribute("description", []string{*description})
	}
	if *userPass != "" {
		quoted := "\"" + *userPass + "\""
		encoded := encodeUTF16LE(quoted)
		addReq.Attribute("unicodePwd", []string{string(encoded)})
	}

	// userAccountControl: 514 = disabled (0x202), 512 = enabled normal account (0x200)
	uac := "514"
	if *enabled {
		if *userPass == "" {
			self.println("Cannot create enabled user account without a password")
		} else {
			uac = "512"
		}
	}
	addReq.Attribute("userAccountControl", []string{uac})

	if err := self.conn.Add(addReq); err != nil {
		self.printf("Failed to create user: %v\n", err)
		return
	}
	self.printf("User created: %s\n", userDN)
}

func shellCreateComputerCmd(self *shell, argArr any) {
	if self.conn == nil || !self.authenticated {
		self.println("Not connected. Use 'connect' and 'login' first.")
		return
	}

	args := argArr.([]string)
	fs, buf := self.newFlagSet("createcomputer")
	cn := fs.String("cn", "", "Computer name without $ (required)")
	ou := fs.String("ou", "", "OU DN")
	description := fs.String("desc", "", "Description")
	managedBy := fs.String("managed-by", "", "DN of the managing user/group")
	domain := fs.String("domain", "", "computer domain name for FQDN (default auth domain)")
	password := fs.String("pass", "", "computer password. Leave empty to generate one")

	if *domain == "" {
		*domain = self.connArgs.domain
	}

	if err := fs.Parse(args); err != nil {
		if buf.Len() > 0 {
			self.printf("%s\n", buf.String())
		}
		return
	}

	if *cn == "" {
		self.println("Error: -cn is required")
		self.println("Usage: " + usageMap[ShellCreateComputer])
		return
	}

	container := *ou
	if container == "" {
		container = "CN=Computers," + self.baseDN
	}

	computerNameUpper := strings.ToUpper(*cn)
	computerName := strings.ToLower(*cn)
	computerDN := fmt.Sprintf("CN=%s,%s", ldap.EscapeDN(computerNameUpper), container)
	samName := computerNameUpper + "$"

	addReq := ldap.NewAddRequest(computerDN, nil)
	addReq.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user", "computer"})
	addReq.Attribute("cn", []string{computerNameUpper})
	addReq.Attribute("sAMAccountName", []string{samName})
	addReq.Attribute("userAccountControl", []string{"4096"})
	addReq.Attribute("dnsHostName", []string{computerName + "." + *domain})

	if *description != "" {
		addReq.Attribute("description", []string{*description})
	}
	if *managedBy != "" {
		addReq.Attribute("managedBy", []string{*managedBy})
	}

	spns := []string{
		fmt.Sprintf("HOST/%s", computerNameUpper),
		fmt.Sprintf("HOST/%s.%s", computerName, *domain),
		fmt.Sprintf("RestrictedKrbHost/%s", computerNameUpper),
		fmt.Sprintf("RestrictedKrbHost/%s.%s", computerName, *domain),
	}
	addReq.Attribute("servicePrincipalName", spns)

	pw := *password
	if pw == "" {
		generated, err := randomComputerPassword()
		if err != nil {
			self.printf("failed to generate computer account password: %v", err)
			return
		}
		pw = generated
	}
	// Encode password
	quoted := "\"" + pw + "\""
	encoded := encodeUTF16LE(quoted)
	addReq.Attribute("unicodePwd", []string{string(encoded)})

	if err := self.conn.Add(addReq); err != nil {
		self.printf("Failed to create computer: %v\n", err)
		return
	}
	if *password == "" {
		self.printf("Computer created: %s with generated password: %s\n", computerDN, pw)
	} else {
		self.printf("Computer created: %s\n", computerDN)
	}
}
