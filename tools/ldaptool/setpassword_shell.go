package main

import (
	ldap "github.com/jfjallid/ldap/v3"
)

const (
	ShellSetPassword = "set-password"
)

var setPasswordUsageKeys = []string{
	ShellSetPassword,
}

func init() {
	usageMap[ShellSetPassword] = ShellSetPassword + " -target <sam|dn> [-reset] [-newpass <password>] [-oldpass <password>]"
	descriptionMap[ShellSetPassword] = "Set or change an account's password (unicodePwd)"

	handlers[ShellSetPassword] = shellSetPasswordCmd

	allKeys = append(allKeys, setPasswordUsageKeys...)

	helpFunctions[12] = func(self *shell) {
		self.showCustomHelpFunc(70, "Password Management", setPasswordUsageKeys)
	}
}

func shellSetPasswordCmd(self *shell, argArr any) {
	if self.conn == nil || !self.authenticated {
		self.println("Not connected. Use 'connect' and 'login' first.")
		return
	}

	args := argArr.([]string)
	fs, buf := self.newFlagSet("set-password")
	target := fs.String("target", "", "sAMAccountName or DN of the account (required)")
	reset := fs.Bool("reset", false, "Administrative reset (overwrite) instead of a change")
	newPass := fs.String("newpass", "", "New password (prompted if omitted)")
	oldPass := fs.String("oldpass", "", "Current password, for a change (prompted if omitted unless -reset)")

	if err := fs.Parse(args); err != nil {
		if buf.Len() > 0 {
			self.printf("%s\n", buf.String())
		}
		return
	}

	if *target == "" {
		self.println("Error: -target is required")
		self.println("Usage: " + usageMap[ShellSetPassword])
		return
	}

	if self.connArgs != nil && !self.connArgs.useTLS && !self.connArgs.startTLS &&
		saslSecurityFromArgs(self.connArgs) != ldap.SASLSecuritySeal {
		self.println("Warning: password changes require a confidential connection (--tls, --starttls, or --sasl seal); the server will likely reject this.")
	}

	// A change (default, no -reset) must prove the current password; prompt
	// for any value not supplied on the command line.
	oldVal := *oldPass
	if !*reset && oldVal == "" {
		pw, err := self.t.ReadPassword("Enter current password: ")
		if err != nil {
			self.printf("reading current password: %v\n", err)
			return
		}
		oldVal = pw
	}
	newVal := *newPass
	if newVal == "" {
		pw, err := self.t.ReadPassword("Enter new password: ")
		if err != nil {
			self.printf("reading new password: %v\n", err)
			return
		}
		newVal = pw
	}

	c := &setPasswordCmd{target: *target, newPass: newVal, oldPass: oldVal, reset: *reset}
	if err := runSetPassword(self.conn, self.baseDN, c, self.t); err != nil {
		self.printf("%v\n", err)
	}
}
