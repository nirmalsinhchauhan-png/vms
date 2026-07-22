package onvif

import (
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // required by the WS-Security UsernameToken Profile spec, not a security choice
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"time"
)

type nonceFunc func(n int) ([]byte, error)
type clockFunc func() time.Time

func defaultNonce(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func defaultClock() time.Time { return time.Now() }

const (
	wsseNS             = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
	wsuNS              = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	passwordDigestType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
	base64BinaryType   = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
)

// These structs use the literal "prefix:Local" trick as their XML tag name
// (e.g. "wsse:Security") — encoding/xml has no native fixed-prefix control,
// so the tag literal plus a manually emitted xmlns:prefix attribute on the
// outermost element is the standard workaround. Child elements inherit the
// prefix's namespace scope from their ancestor without redeclaring it.
type wsseSecurity struct {
	XMLName        xml.Name          `xml:"wsse:Security"`
	MustUnderstand string            `xml:"soap:mustUnderstand,attr"`
	XMLNSWsse      string            `xml:"xmlns:wsse,attr"`
	XMLNSWsu       string            `xml:"xmlns:wsu,attr"`
	UsernameToken  wsseUsernameToken `xml:"wsse:UsernameToken"`
}

type wsseUsernameToken struct {
	Username string       `xml:"wsse:Username"`
	Password wssePassword `xml:"wsse:Password"`
	Nonce    wsseNonce    `xml:"wsse:Nonce"`
	Created  string       `xml:"wsu:Created"`
}

type wssePassword struct {
	Type  string `xml:"Type,attr"`
	Value string `xml:",chardata"`
}

type wsseNonce struct {
	EncodingType string `xml:"EncodingType,attr"`
	Value        string `xml:",chardata"`
}

// newSecurityHeader builds the marshaled <wsse:Security> bytes for a
// WS-Security UsernameToken with PasswordDigest auth:
//
//	PasswordDigest = Base64(SHA1(nonce_bytes || created_string_bytes || password_bytes))
//
// nonceFn/clockFn default to crypto/rand and time.Now, and are only ever
// overridden in tests so a digest can be asserted against a hand-computed
// vector — production callers should pass nil, nil.
func newSecurityHeader(username, password string, nonceFn nonceFunc, clockFn clockFunc) ([]byte, error) {
	if nonceFn == nil {
		nonceFn = defaultNonce
	}
	if clockFn == nil {
		clockFn = defaultClock
	}

	nonce, err := nonceFn(16)
	if err != nil {
		return nil, fmt.Errorf("onvif: generate nonce: %w", err)
	}
	created := clockFn().UTC().Format("2006-01-02T15:04:05Z")

	h := sha1.New()
	h.Write(nonce)
	h.Write([]byte(created))
	h.Write([]byte(password))
	digest := h.Sum(nil)

	sec := wsseSecurity{
		MustUnderstand: "1",
		XMLNSWsse:      wsseNS,
		XMLNSWsu:       wsuNS,
		UsernameToken: wsseUsernameToken{
			Username: username,
			Password: wssePassword{Type: passwordDigestType, Value: base64.StdEncoding.EncodeToString(digest)},
			Nonce:    wsseNonce{EncodingType: base64BinaryType, Value: base64.StdEncoding.EncodeToString(nonce)},
			Created:  created,
		},
	}

	out, err := xml.Marshal(sec)
	if err != nil {
		return nil, fmt.Errorf("onvif: marshal security header: %w", err)
	}
	return out, nil
}
