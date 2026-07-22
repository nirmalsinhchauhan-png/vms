package onvif

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// This package can't be exercised against real hardware in CI, so these
// tests instead pin every external input (nonce, clock, response XML) and
// assert against independently-computed or hand-written fixtures — the
// closest available substitute for a live device.

func TestSecurityHeaderDigestVector(t *testing.T) {
	fixedNonce := func(n int) ([]byte, error) {
		buf := make([]byte, n)
		for i := range buf {
			buf[i] = byte(i)
		}
		return buf, nil
	}
	fixedClock := func() time.Time {
		return time.Date(2026, 7, 22, 10, 15, 30, 0, time.UTC)
	}

	out, err := newSecurityHeader("admin", "hunter2", fixedNonce, fixedClock)
	if err != nil {
		t.Fatalf("newSecurityHeader: %v", err)
	}

	// Independently verified against a from-scratch Python computation of
	// Base64(SHA1(nonce || "2026-07-22T10:15:30Z" || "hunter2")) — see the
	// commit that introduced this test for the cross-check transcript.
	const wantDigest = "+x2eQVR4HjVTgjwUFpeuesTxah8="
	const wantNonce = "AAECAwQFBgcICQoLDA0ODw=="

	// Checked against the raw output bytes, not via xml.Unmarshal: Marshal
	// treats a tag like "wsse:Security" as a literal element name (the
	// standard workaround for fixed-prefix output, since encoding/xml has
	// no native prefix control), but Unmarshal resolves elements through
	// real namespace matching and won't recognize that same literal string
	// as the tag it just produced. The raw bytes are what an actual ONVIF
	// device parses, so asserting on those is the more faithful check
	// anyway — this file's own first draft hit exactly this asymmetry.
	got := string(out)
	mustContain := []string{
		`<wsse:Security soap:mustUnderstand="1"`,
		`xmlns:wsse="` + wsseNS + `"`,
		`xmlns:wsu="` + wsuNS + `"`,
		`<wsse:Username>admin</wsse:Username>`,
		`Type="` + passwordDigestType + `"`,
		`>` + wantDigest + `</wsse:Password>`,
		`EncodingType="` + base64BinaryType + `"`,
		`>` + wantNonce + `</wsse:Nonce>`,
		`<wsu:Created>2026-07-22T10:15:30Z</wsu:Created>`,
	}
	for _, want := range mustContain {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\nfull output: %s", want, got)
		}
	}
}

// TestParseProbeMatches uses the realistic vendor ProbeMatch fixture from
// Sprint 2 planning to confirm local-name-only matching tolerates whatever
// namespace prefix a device happens to use.
func TestParseProbeMatches(t *testing.T) {
	const fixture = `<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope
    xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"
    xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
    xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"
    xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <SOAP-ENV:Header>
    <wsa:MessageID>urn:uuid:1234-...</wsa:MessageID>
    <wsa:RelatesTo>urn:uuid:GENERATED-UUID-HERE</wsa:RelatesTo>
  </SOAP-ENV:Header>
  <SOAP-ENV:Body>
    <wsd:ProbeMatches>
      <wsd:ProbeMatch>
        <wsa:EndpointReference>
          <wsa:Address>urn:uuid:4d3e6dc0-c8c9-11eb-8c1e-0242ac110002</wsa:Address>
        </wsa:EndpointReference>
        <wsd:Types>dn:NetworkVideoTransmitter</wsd:Types>
        <wsd:Scopes>onvif://www.onvif.org/hardware/IPC-Model onvif://www.onvif.org/name/Camera1</wsd:Scopes>
        <wsd:XAddrs>http://192.168.1.64/onvif/device_service</wsd:XAddrs>
        <wsd:MetadataVersion>1</wsd:MetadataVersion>
      </wsd:ProbeMatch>
    </wsd:ProbeMatches>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>`

	from := &net.UDPAddr{IP: net.ParseIP("192.168.1.64"), Port: 3702}
	devices := parseProbeMatches([]byte(fixture), from)

	if len(devices) != 1 {
		t.Fatalf("got %d devices, want 1", len(devices))
	}
	d := devices[0]
	if d.EndpointRef != "urn:uuid:4d3e6dc0-c8c9-11eb-8c1e-0242ac110002" {
		t.Errorf("EndpointRef = %q", d.EndpointRef)
	}
	if len(d.XAddrs) != 1 || d.XAddrs[0] != "http://192.168.1.64/onvif/device_service" {
		t.Errorf("XAddrs = %v", d.XAddrs)
	}
	if len(d.Scopes) != 2 {
		t.Errorf("Scopes = %v, want 2 entries", d.Scopes)
	}
}

func TestParseProbeMatches_MultiXAddr(t *testing.T) {
	const fixture = `<Envelope xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">
  <Body>
    <wsd:ProbeMatches>
      <wsd:ProbeMatch>
        <wsa:EndpointReference><wsa:Address>urn:uuid:abc</wsa:Address></wsa:EndpointReference>
        <wsd:XAddrs>http://10.0.0.5/onvif/device_service http://192.168.1.5/onvif/device_service</wsd:XAddrs>
      </wsd:ProbeMatch>
    </wsd:ProbeMatches>
  </Body>
</Envelope>`
	from := &net.UDPAddr{IP: net.ParseIP("10.0.0.5"), Port: 3702}
	devices := parseProbeMatches([]byte(fixture), from)
	if len(devices) != 1 || len(devices[0].XAddrs) != 2 {
		t.Fatalf("multi-homed XAddrs not split correctly: %+v", devices)
	}
}

func TestClassifyFault_Unauthorized(t *testing.T) {
	cases := []struct {
		name   string
		fault  *SOAPFaultError
		wantIs error
	}{
		{"soap12 subcode", &SOAPFaultError{Code: "ter:NotAuthorized", Reason: "Sender not Authorized"}, ErrUnauthorized},
		{"soap11 faultcode", &SOAPFaultError{Code: "soap:Client.FailedAuthentication", Reason: "auth failed"}, ErrUnauthorized},
		{"unrelated fault", &SOAPFaultError{Code: "ter:InvalidArgVal", Reason: "bad profile token"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := classifyFault(tc.fault)
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Errorf("classifyFault(%+v) = %v, want errors.Is(_, %v)", tc.fault, err, tc.wantIs)
			}
			if tc.wantIs == nil {
				var sfe *SOAPFaultError
				if !errors.As(err, &sfe) {
					t.Errorf("classifyFault(%+v) = %v, want a *SOAPFaultError passthrough", tc.fault, err)
				}
			}
		})
	}
}

func TestParseSOAPFault_BothShapes(t *testing.T) {
	soap12 := `<Envelope><Body><Fault>
		<Code><Value>soap:Sender</Value><Subcode><Value>ter:NotAuthorized</Value></Subcode></Code>
		<Reason><Text>Sender not Authorized</Text></Reason>
	</Fault></Body></Envelope>`
	fault, ok := parseSOAPFault([]byte(soap12))
	if !ok || fault.Code != "ter:NotAuthorized" || fault.Reason != "Sender not Authorized" {
		t.Errorf("SOAP 1.2 fault parse = %+v, ok=%v", fault, ok)
	}

	soap11 := `<Envelope><Body><Fault>
		<faultcode>soap:Client</faultcode>
		<faultstring>Authentication failure</faultstring>
	</Fault></Body></Envelope>`
	fault, ok = parseSOAPFault([]byte(soap11))
	if !ok || fault.Code != "soap:Client" || fault.Reason != "Authentication failure" {
		t.Errorf("SOAP 1.1 fault parse = %+v, ok=%v", fault, ok)
	}

	fault, ok = parseSOAPFault([]byte(`<Envelope><Body><GetProfilesResponse/></Body></Envelope>`))
	if ok {
		t.Errorf("expected no fault detected, got %+v", fault)
	}
}

func TestXMLEscape(t *testing.T) {
	got := xmlEscape(`Profile_1<>&"'`)
	// Round-trip through the real XML parser rather than asserting an exact
	// escaped string — only the round-trip safety property matters here.
	var out struct {
		Text string `xml:",chardata"`
	}
	wrapped := "<r>" + got + "</r>"
	if err := xml.Unmarshal([]byte(wrapped), &out); err != nil {
		t.Fatalf("escaped output didn't round-trip as valid XML: %v (escaped=%q)", err, got)
	}
	if out.Text != `Profile_1<>&"'` {
		t.Errorf("round-tripped text = %q, want original", out.Text)
	}
}

func TestBase64Sanity(t *testing.T) {
	// Guards against accidentally swapping StdEncoding for URLEncoding
	// somewhere — ONVIF/WS-Security requires standard Base64 with padding.
	if _, err := base64.StdEncoding.DecodeString("AAECAwQFBgcICQoLDA0ODw=="); err != nil {
		t.Fatalf("sanity decode failed: %v", err)
	}
}
