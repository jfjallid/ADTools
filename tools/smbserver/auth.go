package main

import (
	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/encoder"
	"github.com/jfjallid/go-smb/smb/server"
)

// loggingAuth wraps an Authenticator to emit a notice-level success/fail line
// per AUTHENTICATE attempt. The hashcat string is logged separately by
// credDumpHook (which fires before Verify, so it cannot know the outcome).
type loggingAuth struct {
	inner server.Authenticator
}

func (l *loggingAuth) Verify(c *server.Conn, a *ntlmssp.Authenticate, ch [8]byte) ([]byte, uint32) {
	sk, status := l.inner.Verify(c, a, ch)
	user, _ := encoder.FromUnicodeString(a.UserName)
	domain, _ := encoder.FromUnicodeString(a.DomainName)
	if status == smb.StatusOk {
		log.Noticef("[+] auth success for %s\\%s from %s", domain, user, c.RemoteAddr)
	} else {
		log.Noticef("[!] auth failure for %s\\%s from %s (status=0x%08x)", domain, user, c.RemoteAddr, status)
	}
	return sk, status
}
