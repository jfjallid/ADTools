package main

const ShellDACL = "dacl"

var daclUsageKeys = []string{ShellDACL}

func init() {
	usageMap[ShellDACL] = ShellDACL + " -action read|add|remove|backup|restore -target <sam|dn|sid> [-trustee <sam|dn|sid>] [-rights <preset> ...] [-mask 0x..] [-right-guid <guid> ...] [-ace-type allowed|denied] [-inheritance] [-inherit-only] [-ace-flags 0x..] [-inherited-object-guid <guid>] [-resolve-sids] [-file <path>]"
	descriptionMap[ShellDACL] = "View and modify DACLs on object security descriptors"

	handlers[ShellDACL] = shellDACLCmd
	allKeys = append(allKeys, daclUsageKeys...)

	helpFunctions[9] = func(self *shell) {
		self.showCustomHelpFunc(80, "DACL", daclUsageKeys)
	}
}

func shellDACLCmd(self *shell, argArr any) {
	if self.conn == nil || !self.authenticated {
		self.println("Not connected. Use 'connect' and 'login' first.")
		return
	}
	args := argArr.([]string)
	fs, buf := self.newFlagSet("dacl")
	c := &daclCmd{}
	c.DefineFlags(fs)
	if err := fs.Parse(args); err != nil {
		if buf.Len() > 0 {
			self.printf("%s\n", buf.String())
		}
		return
	}
	if err := c.validate(); err != nil {
		self.printf("Error: %v\n", err)
		self.println("Usage: " + usageMap[ShellDACL])
		return
	}
	if err := runDACL(self.conn, self.baseDN, c, &shellWriter{self}); err != nil {
		self.printf("%v\n", err)
	}
}
