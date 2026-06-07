package main

const ShellOwner = "owner"

var ownerUsageKeys = []string{ShellOwner}

func init() {
	usageMap[ShellOwner] = ShellOwner + " -action read|set|backup|restore -target <sam|dn|sid> [-owner <sam|dn|sid>] [-file <path>] [-resolve-sids]"
	descriptionMap[ShellOwner] = "View and change the owner SID of an object's security descriptor"

	handlers[ShellOwner] = shellOwnerCmd
	allKeys = append(allKeys, ownerUsageKeys...)

	helpFunctions[11] = func(self *shell) {
		self.showCustomHelpFunc(80, "OWNER", ownerUsageKeys)
	}
}

func shellOwnerCmd(self *shell, argArr any) {
	if self.conn == nil || !self.authenticated {
		self.println("Not connected. Use 'connect' and 'login' first.")
		return
	}
	args := argArr.([]string)
	fs, buf := self.newFlagSet("owner")
	c := &ownerCmd{}
	c.DefineFlags(fs)
	if err := fs.Parse(args); err != nil {
		if buf.Len() > 0 {
			self.printf("%s\n", buf.String())
		}
		return
	}
	if err := c.validate(); err != nil {
		self.printf("Error: %v\n", err)
		self.println("Usage: " + usageMap[ShellOwner])
		return
	}
	if err := runOwner(self.conn, self.baseDN, c, &shellWriter{self}); err != nil {
		self.printf("%v\n", err)
	}
}
