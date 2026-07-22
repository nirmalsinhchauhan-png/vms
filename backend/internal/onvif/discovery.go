package onvif

import (
	"context"
	"crypto/rand"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const wsDiscoveryMulticastAddr = "239.255.255.250:3702"

const probeTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope
    xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
    xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
    xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"
    xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <soap:Header>
    <wsa:MessageID>urn:uuid:%s</wsa:MessageID>
    <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
  </soap:Header>
  <soap:Body>
    <wsd:Probe>
      <wsd:Types>dn:NetworkVideoTransmitter</wsd:Types>
    </wsd:Probe>
  </soap:Body>
</soap:Envelope>`

func newMessageID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("onvif: generate message id: %w", err)
	}
	// Formatted to look like a UUID; nothing here validates strict RFC 4122
	// version/variant bits since nothing downstream checks that either.
	return fmt.Sprintf("%x-%x-%x-%x-%x", buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16]), nil
}

func buildProbeEnvelope(messageID string) []byte {
	return []byte(fmt.Sprintf(probeTemplate, messageID))
}

type probeMatchEnvelope struct {
	Body struct {
		ProbeMatches struct {
			ProbeMatch []probeMatch `xml:"ProbeMatch"`
		} `xml:"ProbeMatches"`
	} `xml:"Body"`
}

// Field tags match by local name only (no namespace/prefix pinned), which
// deliberately tolerates vendors using different prefixes (wsd:, d:, dn:,
// or none) for the same elements — only the namespace URIs are
// standardized, prefixes are not, and OEM ONVIF stacks vary here.
type probeMatch struct {
	EndpointReference struct {
		Address string `xml:"Address"`
	} `xml:"EndpointReference"`
	Types           string `xml:"Types"`
	Scopes          string `xml:"Scopes"`
	XAddrs          string `xml:"XAddrs"`
	MetadataVersion int    `xml:"MetadataVersion"`
}

// Discover sends a WS-Discovery Probe and collects ProbeMatch replies until
// timeout elapses. An empty, nil-error result is the normal outcome when no
// devices respond ("no cameras found, try manual entry") — only socket
// setup failures return a non-nil error (a real infra problem worth a log).
//
// Uses a plain UDP socket, not a multicast-joined one: per the WS-Discovery
// transport binding, a compliant device replies unicast to the probe's
// source address, so no multicast group membership is needed to receive
// replies (only to send the initial probe to the multicast group address).
func Discover(ctx context.Context, timeout time.Duration) ([]DiscoveredDevice, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("onvif: open discovery socket: %w", err)
	}
	defer conn.Close()

	dst, err := net.ResolveUDPAddr("udp4", wsDiscoveryMulticastAddr)
	if err != nil {
		return nil, fmt.Errorf("onvif: resolve multicast address: %w", err)
	}

	msgID, err := newMessageID()
	if err != nil {
		return nil, err
	}

	if _, err := conn.WriteToUDP(buildProbeEnvelope(msgID), dst); err != nil {
		return nil, fmt.Errorf("onvif: send probe: %w", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("onvif: set read deadline: %w", err)
	}

	seen := make(map[string]DiscoveredDevice)
	buf := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			return devicesFromSeen(seen), nil
		default:
		}

		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				break
			}
			return nil, fmt.Errorf("onvif: read probe match: %w", err)
		}

		for _, d := range parseProbeMatches(buf[:n], addr) {
			key := d.EndpointRef
			if key == "" {
				key = d.RemoteAddr
			}
			if _, exists := seen[key]; !exists {
				seen[key] = d
			}
		}
	}

	return devicesFromSeen(seen), nil
}

func devicesFromSeen(seen map[string]DiscoveredDevice) []DiscoveredDevice {
	result := make([]DiscoveredDevice, 0, len(seen))
	for _, d := range seen {
		result = append(result, d)
	}
	return result
}

func parseProbeMatches(data []byte, from *net.UDPAddr) []DiscoveredDevice {
	var env probeMatchEnvelope
	if err := xml.Unmarshal(data, &env); err != nil {
		return nil
	}

	devices := make([]DiscoveredDevice, 0, len(env.Body.ProbeMatches.ProbeMatch))
	for _, pm := range env.Body.ProbeMatches.ProbeMatch {
		devices = append(devices, DiscoveredDevice{
			EndpointRef: pm.EndpointReference.Address,
			XAddrs:      strings.Fields(pm.XAddrs),
			Scopes:      strings.Fields(pm.Scopes),
			RemoteAddr:  from.String(),
		})
	}
	return devices
}
