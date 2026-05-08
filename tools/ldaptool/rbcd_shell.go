package main

const ShellRBCD = "rbcd"

var rbcdUsageKeys = []string{ShellRBCD}

func init() {
	usageMap[ShellRBCD] = ShellRBCD + " -action add|list|remove|clear -target <sam> [-trustee <sid|sam> ...]"
	descriptionMap[ShellRBCD] = "Manage msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)"

	handlers[ShellRBCD] = shellRBCDCmd
	allKeys = append(allKeys, rbcdUsageKeys...)

	helpFunctions[6] = func(self *shell) {
		self.showCustomHelpFunc(80, "RBCD", rbcdUsageKeys)
	}
}

func shellRBCDCmd(self *shell, argArr any) {
	if self.conn == nil || !self.authenticated {
		self.println("Not connected. Use 'connect' and 'login' first.")
		return
	}
	args := argArr.([]string)
	fs, buf := self.newFlagSet("rbcd")
	c := &rbcdCmd{}
	c.DefineFlags(fs)
	if err := fs.Parse(args); err != nil {
		if buf.Len() > 0 {
			self.printf("%s\n", buf.String())
		}
		return
	}
	if c.action == "" || c.target == "" {
		self.println("Error: -action and -target are required")
		self.println("Usage: " + usageMap[ShellRBCD])
		return
	}
	switch c.action {
	case "add", "remove":
		if len(c.trustees) == 0 {
			self.printf("Error: -trustee is required for action %q\n", c.action)
			return
		}
	case "list", "clear":
	default:
		self.printf("Unknown action: %s (valid: add, list, remove, clear)\n", c.action)
		return
	}
	if err := runRBCD(self.conn, self.baseDN, c, &shellWriter{self}); err != nil {
		self.printf("%v\n", err)
	}
}
