package main

import (
	"github.com/jfjallid/go-smb/ntlmssp"
	ldap "github.com/jfjallid/ldap/v3"
)

// The ldap/v3 library drives NTLM token exchange through the
// ldap.NTLMNegotiator interface and builds credential-based negotiators via the
// package-level ldap.NTLMNegotiatorFactory hook. We register that hook here,
// backing it with go-smb's ntlmssp.Client, so every NTLMChallengeBind call site
// can authenticate from plain credentials.
func init() {
	ldap.NTLMNegotiatorFactory = newNTLMNegotiator
}

// smbNTLM adapts a go-smb *ntlmssp.Client to the ldap.NTLMNegotiator interface
// (plus the optional NTLMChannelBinder and NTLMSessionProvider capabilities).
type smbNTLM struct {
	c *ntlmssp.Client
}

// Negotiate returns the NTLM NEGOTIATE_MESSAGE. The domain/workstation supplied
// by the library override the credential-derived values only when non-empty, so
// a domain that arrived via the DOMAIN\user form (already split into the
// credentials) is preserved when the bind request's Domain field is blank.
func (n *smbNTLM) Negotiate(domain, workstation string) ([]byte, error) {
	if domain != "" {
		n.c.Domain = domain
	}
	if workstation != "" {
		n.c.Workstation = workstation
	}
	return n.c.Negotiate()
}

// ChallengeResponse consumes the server CHALLENGE_MESSAGE and returns the NTLM
// AUTHENTICATE_MESSAGE.
func (n *smbNTLM) ChallengeResponse(challenge []byte) ([]byte, error) {
	return n.c.Authenticate(challenge)
}

// SetChannelBindingHash supplies the RFC 5929 channel-binding hash for EPA.
func (n *smbNTLM) SetChannelBindingHash(hash [16]byte) {
	n.c.SetChannelBindingHash(hash)
}

// SecuritySession returns the negotiated NTLM SASL session for sign/seal, or nil
// when no integrity/confidentiality was negotiated. The explicit nil check
// avoids handing the library a non-nil interface wrapping a nil *Session.
func (n *smbNTLM) SecuritySession() ldap.SASLSession {
	if s := n.c.Session(); s != nil {
		return s
	}
	return nil
}

// newNTLMNegotiator builds a go-smb NTLM client from credentials. When the
// caller does not intend to negotiate a SASL sign/seal layer we strip the
// sign/seal flags and disable the MIC: AD's strict MIC validation rejects the
// bind when those flags are absent but a MIC is present.
func newNTLMNegotiator(cr ldap.NTLMCredentials) (ldap.NTLMNegotiator, error) {
	c := &ntlmssp.Client{
		Domain:      cr.Domain,
		Workstation: cr.Workstation,
		User:        cr.Username,
		Password:    cr.Password,
		Hash:        cr.Hash,
	}
	if !cr.SignSeal {
		c.StripFlags = ntlmssp.FlgNegSign | ntlmssp.FlgNegSeal
		c.DisableMIC = true
	}
	return &smbNTLM{c: c}, nil
}
