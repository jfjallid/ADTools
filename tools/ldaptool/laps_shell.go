package main

import (
	ldap "github.com/jfjallid/ldap/v3"
)

const ShellLAPS = "laps"

var lapsUsageKeys = []string{ShellLAPS}

func init() {
	usageMap[ShellLAPS] = ShellLAPS + " [-target <sam>]"
	descriptionMap[ShellLAPS] = "Read LAPS local-admin passwords"

	handlers[ShellLAPS] = shellLAPSCmd
	allKeys = append(allKeys, lapsUsageKeys...)

	helpFunctions[8] = func(self *shell) {
		self.showCustomHelpFunc(80, "LAPS", lapsUsageKeys)
	}
}

func shellLAPSCmd(self *shell, argArr any) {
	if self.conn == nil || !self.authenticated {
		self.println("Not connected. Use 'connect' and 'login' first.")
		return
	}
	args := argArr.([]string)
	fs, buf := self.newFlagSet("laps")
	target := fs.String("target", "", "Limit to one computer by sAMAccountName")
	if err := fs.Parse(args); err != nil {
		if buf.Len() > 0 {
			self.printf("%s\n", buf.String())
		}
		return
	}

	c := &lapsCmd{target: *target}
	// Replicate run logic: build filter, search, print.
	const lapsAttrs = "ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime,msLAPS-Password,msLAPS-EncryptedPassword,msLAPS-PasswordExpirationTime"
	requested := []string{"sAMAccountName", "dNSHostName", "distinguishedName"}
	for _, a := range []string{"ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime", "msLAPS-Password", "msLAPS-EncryptedPassword", "msLAPS-PasswordExpirationTime"} {
		requested = append(requested, a)
	}
	_ = lapsAttrs

	filter := "(&(objectClass=computer)(|(ms-Mcs-AdmPwd=*)(msLAPS-Password=*)(msLAPS-EncryptedPassword=*)))"
	if c.target != "" {
		sam := c.target
		if len(sam) == 0 || sam[len(sam)-1] != '$' {
			sam = sam + "$"
		}
		filter = "(&(objectClass=computer)(sAMAccountName=" + ldap.EscapeFilter(sam) + "))"
	}

	res, err := self.conn.SearchWithPaging(ldap.NewSearchRequest(
		self.baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter, requested, nil,
	), 1000)
	if err != nil {
		self.printf("LDAP search failed: %v\n", err)
		return
	}
	if len(res.Entries) == 0 {
		self.println("No matching entries found.")
		return
	}
	w := &shellWriter{s: self}
	for _, e := range res.Entries {
		printLAPSEntryTo(w, e)
	}
}

// printLAPSEntryTo mirrors printLAPSEntry but writes to an io.Writer so the
// shell can redirect output.
func printLAPSEntryTo(w *shellWriter, e *ldap.Entry) {
	sam := e.GetAttributeValue("sAMAccountName")
	host := e.GetAttributeValue("dNSHostName")
	w.s.printf("=== %s (%s) ===\n", sam, host)
	w.s.printf("DN: %s\n", e.DN)

	if v := e.GetAttributeValue("ms-Mcs-AdmPwd"); v != "" {
		w.s.printf("  ms-Mcs-AdmPwd:                  %s\n", v)
		if exp := e.GetAttributeValue("ms-Mcs-AdmPwdExpirationTime"); exp != "" {
			w.s.printf("  ms-Mcs-AdmPwdExpirationTime:    %s\n", formatFiletime(exp))
		}
	}
	if v := e.GetAttributeValue("msLAPS-Password"); v != "" {
		w.s.printf("  msLAPS-Password:                %s\n", formatLAPSPassword(v))
	}
	if a := e.GetRawAttributeValue("msLAPS-EncryptedPassword"); len(a) > 0 {
		w.s.printf("  msLAPS-EncryptedPassword:       %s\n", formatLAPSEncrypted(a))
	}
	if exp := e.GetAttributeValue("msLAPS-PasswordExpirationTime"); exp != "" {
		w.s.printf("  msLAPS-PasswordExpirationTime:  %s\n", formatFiletime(exp))
	}
	w.s.println()
}
