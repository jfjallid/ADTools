package main

import (
	"strings"

	ldap "github.com/jfjallid/ldap/v3"
)

const (
	ShellSearch       = "search"
	ShellModify       = "modify"
	ShellDeleteObject = "deleteobject"
)

var ldapUsageKeys = []string{
	ShellSearch,
	ShellModify,
	ShellDeleteObject,
}

func init() {
	usageMap[ShellSearch] = ShellSearch + " [-filter <f>] [-search-base <dn>] [-scope base|one|sub] [-size-limit n] [-time-limit n] [-page-size n] [-attrs <list>] [-control <c>] [-ldif] [-json]"
	usageMap[ShellModify] = ShellModify + " -dn <dn> [-set name=val|@file] [-add name=val|@file] [-delete name=val]"
	usageMap[ShellDeleteObject] = ShellDeleteObject + " -dn <dn>"

	descriptionMap[ShellSearch] = "Search for LDAP objects"
	descriptionMap[ShellModify] = "Modify attributes on an LDAP object"
	descriptionMap[ShellDeleteObject] = "Delete an LDAP object by DN"

	handlers[ShellSearch] = shellSearchCmd
	handlers[ShellModify] = shellModifyCmd
	handlers[ShellDeleteObject] = shellDeleteObjectCmd

	allKeys = append(allKeys, ldapUsageKeys...)

	helpFunctions[2] = func(self *shell) {
		self.showCustomHelpFunc(100, "Search & Modify", ldapUsageKeys)
	}
}

// shellWriter bridges the terminal so runSearch's human/LDIF/JSON writers
// still land in the shell's display.
type shellWriter struct {
	s *shell
}

func (w *shellWriter) Write(p []byte) (int, error) { return w.s.t.Write(p) }

func shellSearchCmd(self *shell, argArr any) {
	if self.conn == nil || !self.authenticated {
		self.println("Not connected. Use 'connect' and 'login' first.")
		return
	}

	args := argArr.([]string)
	fs, buf := self.newFlagSet("search")
	c := &searchCmd{}
	c.DefineFlags(fs)

	if err := fs.Parse(args); err != nil {
		if buf.Len() > 0 {
			self.printf("%s\n", buf.String())
		}
		return
	}
	if c.ldif && c.json {
		self.println("Error: -ldif and -json are mutually exclusive")
		return
	}
	if c.preset != "" {
		f, ok := searchPresets[strings.ToLower(c.preset)]
		if !ok {
			self.printf("unknown -preset %q\n", c.preset)
			return
		}
		c.filter = f
	}

	base := self.baseDN
	if c.searchBase != "" {
		base = c.searchBase
	}
	filter := c.filter
	scope, err := parseScope(c.scopeStr)
	if err != nil {
		self.printf("%v\n", err)
		return
	}
	attrList := parseAttrList(c.attrs)
	controls, err := parseControls(c.controls)
	if err != nil {
		self.printf("%v\n", err)
		return
	}

	w := &shellWriter{s: self}
	if self.banner {
		printSearchBanner(w, base, scope, filter, attrList, c, controls)
	}

	req := ldap.NewSearchRequest(
		base, scope, ldap.NeverDerefAliases,
		int(c.sizeLimit), int(c.timeLimit), false,
		filter, attrList, controls,
	)

	var entries []*ldap.Entry
	if c.pageSize == 0 {
		result, err := self.conn.Search(req)
		if err != nil {
			if ldap.IsErrorWithCode(err, 4) && c.sizeLimit != 0 {
				// size limit exceeded but return data
			} else {
				self.printf("Search failed: %v\n", err)
				return
			}
		}
		entries = result.Entries
	} else {
		result, err := self.conn.SearchWithPaging(req, uint32(c.pageSize))
		if err != nil {
			if ldap.IsErrorWithCode(err, 4) && c.sizeLimit != 0 {
				// size limit exceeded but return data
			} else {
				self.printf("Search failed: %v\n", err)
				return
			}
		}
		entries = result.Entries
	}

	for _, e := range entries {
		if err := expandRangedAttrs(self.conn, e, controls); err != nil {
			self.printf("warning: ranged-attr expansion for %s: %v\n", e.DN, err)
		}
	}
	if !c.noSchemaHint {
		loadSchemaBinaryAttrs(self.conn, entries)
	}

	switch {
	case c.ldif:
		writeLDIF(w, entries)
	case c.json:
		writeJSON(w, entries)
	default:
		writeHuman(w, entries)
	}
}

func shellModifyCmd(self *shell, argArr any) {
	if self.conn == nil || !self.authenticated {
		self.println("Not connected. Use 'connect' and 'login' first.")
		return
	}

	args := argArr.([]string)
	fs, buf := self.newFlagSet("modify")
	c := &modifyCmd{}
	c.DefineFlags(fs)
	if err := fs.Parse(args); err != nil {
		if buf.Len() > 0 {
			self.printf("%s\n", buf.String())
		}
		return
	}
	if err := runModify(self.conn, c, &shellWriter{self}); err != nil {
		self.printf("%v\n", err)
	}
}

func shellDeleteObjectCmd(self *shell, argArr any) {
	if self.conn == nil || !self.authenticated {
		self.println("Not connected. Use 'connect' and 'login' first.")
		return
	}

	args := argArr.([]string)
	fs, buf := self.newFlagSet("deleteobject")
	c := &deleteCmd{}
	c.DefineFlags(fs)
	if err := fs.Parse(args); err != nil {
		if buf.Len() > 0 {
			self.printf("%s\n", buf.String())
		}
		return
	}
	if err := runDelete(self.conn, c); err != nil {
		self.printf("%v\n", err)
	}
}

