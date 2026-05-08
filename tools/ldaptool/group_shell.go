package main

import ldap "github.com/jfjallid/ldap/v3"

const ShellGroup = "group"

var groupUsageKeys = []string{ShellGroup}

func init() {
	usageMap[ShellGroup] = ShellGroup + " -action add|remove -group <dn|sam> -member <dn|sam> ..."
	descriptionMap[ShellGroup] = "Add or remove group members"

	handlers[ShellGroup] = shellGroupCmd
	allKeys = append(allKeys, groupUsageKeys...)

	helpFunctions[7] = func(self *shell) {
		self.showCustomHelpFunc(80, "Group membership", groupUsageKeys)
	}
}

func shellGroupCmd(self *shell, argArr any) {
	if self.conn == nil || !self.authenticated {
		self.println("Not connected. Use 'connect' and 'login' first.")
		return
	}
	args := argArr.([]string)
	fs, buf := self.newFlagSet("group")
	c := &groupCmd{}
	c.DefineFlags(fs)
	if err := fs.Parse(args); err != nil {
		if buf.Len() > 0 {
			self.printf("%s\n", buf.String())
		}
		return
	}
	if c.action != "add" && c.action != "remove" {
		self.println("Error: -action must be add or remove")
		return
	}
	if c.group == "" || len(c.members) == 0 {
		self.println("Error: -group and at least one -member are required")
		return
	}

	groupDN, err := resolveDN(self.conn, self.baseDN, c.group)
	if err != nil {
		self.printf("resolve group: %v\n", err)
		return
	}
	var memberDNs []string
	for _, m := range c.members {
		dn, err := resolveDN(self.conn, self.baseDN, m)
		if err != nil {
			self.printf("resolve member %q: %v\n", m, err)
			return
		}
		memberDNs = append(memberDNs, dn)
	}

	mod := ldap.NewModifyRequest(groupDN, nil)
	if c.action == "add" {
		mod.Add("member", memberDNs)
	} else {
		mod.Delete("member", memberDNs)
	}
	if err := self.conn.Modify(mod); err != nil {
		self.printf("LDAP modify failed: %v\n", err)
		return
	}
	verb := "Added"
	if c.action == "remove" {
		verb = "Removed"
	}
	self.printf("%s on %s:\n", verb, groupDN)
	for _, dn := range memberDNs {
		self.printf("  %s\n", dn)
	}
}
