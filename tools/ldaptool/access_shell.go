package main

const ShellAccess = "access"

var accessUsageKeys = []string{ShellAccess}

func init() {
	usageMap[ShellAccess] = ShellAccess + " -target <sam|dn|sid> -principal <sam|dn|sid> [-right <preset|maskbit|guid|write:attr|read:attr> ...] [-no-session-sids] [-show-token]"
	descriptionMap[ShellAccess] = "Compute a principal's effective access to an object"

	handlers[ShellAccess] = shellAccessCmd
	allKeys = append(allKeys, accessUsageKeys...)

	helpFunctions[10] = func(self *shell) {
		self.showCustomHelpFunc(80, "Access", accessUsageKeys)
	}
}

func shellAccessCmd(self *shell, argArr any) {
	if self.conn == nil || !self.authenticated {
		self.println("Not connected. Use 'connect' and 'login' first.")
		return
	}
	args := argArr.([]string)
	fs, buf := self.newFlagSet("access")
	c := &accessCmd{}
	c.DefineFlags(fs)
	if err := fs.Parse(args); err != nil {
		if buf.Len() > 0 {
			self.printf("%s\n", buf.String())
		}
		return
	}
	if err := c.validate(); err != nil {
		self.printf("Error: %v\n", err)
		self.println("Usage: " + usageMap[ShellAccess])
		return
	}
	if err := runAccess(self.conn, self.baseDN, c, &shellWriter{s: self}); err != nil {
		self.printf("%v\n", err)
	}
}
