package onvif

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const envelopeTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
               xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
               xmlns:tt="http://www.onvif.org/ver10/schema">
  <soap:Header>%s</soap:Header>
  <soap:Body>%s</soap:Body>
</soap:Envelope>`

func buildEnvelope(headerXML, bodyXML []byte) []byte {
	return []byte(fmt.Sprintf(envelopeTemplate, headerXML, bodyXML))
}

func xmlEscape(s string) string {
	var buf strings.Builder
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

// soapEnvelopeFault covers both SOAP 1.2 (Code/Subcode/Value, Reason/Text)
// and SOAP 1.1 (faultcode, faultstring) fault shapes in one permissive
// struct — whichever the device used populates, the other stays zero-valued.
type soapEnvelopeFault struct {
	Body struct {
		Fault struct {
			Code struct {
				Value   string `xml:"Value"`
				Subcode struct {
					Value string `xml:"Value"`
				} `xml:"Subcode"`
			} `xml:"Code"`
			Reason struct {
				Text string `xml:"Text"`
			} `xml:"Reason"`
			FaultCode   string `xml:"faultcode"`
			FaultString string `xml:"faultstring"`
		} `xml:"Fault"`
	} `xml:"Body"`
}

func parseSOAPFault(body []byte) (*SOAPFaultError, bool) {
	var env soapEnvelopeFault
	if err := xml.Unmarshal(body, &env); err != nil {
		return nil, false
	}
	f := env.Body.Fault
	code := f.Code.Subcode.Value
	if code == "" {
		code = f.Code.Value
	}
	if code == "" {
		code = f.FaultCode
	}
	reason := f.Reason.Text
	if reason == "" {
		reason = f.FaultString
	}
	if code == "" && reason == "" {
		return nil, false
	}
	return &SOAPFaultError{Code: code, Reason: reason}, true
}

func classifyFault(fault *SOAPFaultError) error {
	haystack := strings.ToLower(fault.Code + " " + fault.Reason)
	for _, needle := range []string{"notauthorized", "failedauthentication", "sender not authorized", "not authorized"} {
		if strings.Contains(haystack, needle) {
			return fmt.Errorf("%w: %s", ErrUnauthorized, fault.Reason)
		}
	}
	return fault
}

// doSOAP posts a SOAP 1.2 envelope and returns the raw response body on a
// 2xx status, classifying failures into sentinel errors so callers can
// match them with errors.Is instead of inspecting a generic error string.
func doSOAP(ctx context.Context, hc *http.Client, targetURL, actionURI string, envelope []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, strings.NewReader(string(envelope)))
	if err != nil {
		return nil, fmt.Errorf("onvif: build request: %w", err)
	}
	req.Header.Set("Content-Type", fmt.Sprintf(`application/soap+xml; charset=utf-8; action=%q`, actionURI))
	// Defensive: some SOAP-1.1-era OEM ONVIF stacks (HiSilicon/Fullhan
	// reference firmware) expect this header even though the envelope
	// itself is SOAP 1.2. Costs nothing to include; unverified interop
	// detail, flag if a real device disagrees.
	req.Header.Set("SOAPAction", actionURI)

	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDeviceUnreachable, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // cap at 1MB — a broken/hostile LAN device shouldn't exhaust memory
	if err != nil {
		return nil, fmt.Errorf("onvif: read response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, ErrUnauthorized
	}
	if resp.StatusCode >= 300 {
		if fault, ok := parseSOAPFault(body); ok {
			return nil, classifyFault(fault)
		}
		return nil, fmt.Errorf("%w: HTTP %d", ErrMalformedResponse, resp.StatusCode)
	}

	return body, nil
}
