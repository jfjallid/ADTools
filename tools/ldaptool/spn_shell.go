package main

import ldap "github.com/jfjallid/ldap/v3"

const (
	ShellSPN = "spn"
)

var spnUsageKeys = []string{
	ShellSPN,
}

func init() {
	usageMap[ShellSPN] = ShellSPN + " -dn <dn> [-add spn] [-remove spn] [-replace spn]"
	descriptionMap[ShellSPN] = "Manage servicePrincipalName on an LDAP object"

	handlers[ShellSPN] = shellSPNCmd

	allKeys = append(allKeys, spnUsageKeys...)

	helpFunctions[4] = func(self *shell) {
		self.showCustomHelpFunc(55, "SPN Management", spnUsageKeys)
	}
}

func shellSPNCmd(self *shell, argArr any) {
	if self.conn == nil || !self.authenticated {
		self.println("Not connected. Use 'connect' and 'login' first.")
		return
	}

	args := argArr.([]string)
	fs, buf := self.newFlagSet("setspn")
	dn := fs.String("dn", "", "DN of the object (required)")

	addSPNs := &spnFlag{}
	removeSPNs := &spnFlag{}
	replaceSPNs := &spnFlag{}

	fs.Var(addSPNs, "add", "SPN to add (repeatable)")
	fs.Var(removeSPNs, "remove", "SPN to remove (repeatable)")
	fs.Var(replaceSPNs, "replace", "Replace all SPNs with these (repeatable)")

	if err := fs.Parse(args); err != nil {
		if buf.Len() > 0 {
			self.printf("%s\n", buf.String())
		}
		return
	}

	if *dn == "" {
		self.println("Error: -dn is required")
		self.println("Usage: " + usageMap[ShellSPN])
		return
	}

	if len(addSPNs.values) == 0 && len(removeSPNs.values) == 0 && len(replaceSPNs.values) == 0 {
		self.println("Error: at least one -spn, -remove, or -replace flag is required")
		return
	}

	modReq := ldap.NewModifyRequest(*dn, nil)

	if len(replaceSPNs.values) > 0 {
		modReq.Replace("servicePrincipalName", replaceSPNs.values)
	}
	if len(addSPNs.values) > 0 {
		modReq.Add("servicePrincipalName", addSPNs.values)
	}
	if len(removeSPNs.values) > 0 {
		modReq.Delete("servicePrincipalName", removeSPNs.values)
	}

	if err := self.conn.Modify(modReq); err != nil {
		self.printf("SPN modification failed: %v\n", err)
		return
	}

	self.printf("SPN updated on: %s\n", *dn)
	for _, s := range replaceSPNs.values {
		self.printf("  replaced → %s\n", s)
	}
	for _, s := range addSPNs.values {
		self.printf("  added → %s\n", s)
	}
	for _, s := range removeSPNs.values {
		self.printf("  removed → %s\n", s)
	}
}
