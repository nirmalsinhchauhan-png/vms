package onvif

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"sort"
	"time"
)

type Client struct {
	hc          *http.Client
	deviceXAddr string
	mediaXAddr  string
	username    string
	password    string
}

type ClientOption func(*Client)

func WithTimeout(d time.Duration) ClientOption {
	return func(c *Client) { c.hc.Timeout = d }
}

func NewClient(deviceXAddr, username, password string, opts ...ClientOption) *Client {
	c := &Client{
		hc:          &http.Client{Timeout: 5 * time.Second},
		deviceXAddr: deviceXAddr,
		username:    username,
		password:    password,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *Client) securityHeader() ([]byte, error) {
	return newSecurityHeader(c.username, c.password, nil, nil)
}

const (
	actionGetDeviceInformation = "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation"
	actionGetCapabilities      = "http://www.onvif.org/ver10/device/wsdl/GetCapabilities"
	actionGetProfiles          = "http://www.onvif.org/ver10/media/wsdl/GetProfiles"
	actionGetStreamURI         = "http://www.onvif.org/ver10/media/wsdl/GetStreamUri"
)

type getDeviceInformationResponse struct {
	Body struct {
		GetDeviceInformationResponse struct {
			Manufacturer    string `xml:"Manufacturer"`
			Model           string `xml:"Model"`
			FirmwareVersion string `xml:"FirmwareVersion"`
			SerialNumber    string `xml:"SerialNumber"`
			HardwareId      string `xml:"HardwareId"`
		} `xml:"GetDeviceInformationResponse"`
	} `xml:"Body"`
}

// GetDeviceInformation is a Device Management Service call, made directly
// at the device XAddr (no prior call needed).
func (c *Client) GetDeviceInformation(ctx context.Context) (DeviceInfo, error) {
	header, err := c.securityHeader()
	if err != nil {
		return DeviceInfo{}, err
	}
	envelope := buildEnvelope(header, []byte(`<tds:GetDeviceInformation/>`))

	body, err := doSOAP(ctx, c.hc, c.deviceXAddr, actionGetDeviceInformation, envelope)
	if err != nil {
		return DeviceInfo{}, err
	}

	var resp getDeviceInformationResponse
	if err := xml.Unmarshal(body, &resp); err != nil {
		return DeviceInfo{}, fmt.Errorf("%w: %v", ErrMalformedResponse, err)
	}

	r := resp.Body.GetDeviceInformationResponse
	return DeviceInfo{
		Manufacturer:    r.Manufacturer,
		Model:           r.Model,
		FirmwareVersion: r.FirmwareVersion,
		SerialNumber:    r.SerialNumber,
		HardwareID:      r.HardwareId,
	}, nil
}

type getCapabilitiesResponse struct {
	Body struct {
		GetCapabilitiesResponse struct {
			Capabilities struct {
				Media struct {
					XAddr string `xml:"XAddr"`
				} `xml:"Media"`
			} `xml:"Capabilities"`
		} `xml:"GetCapabilitiesResponse"`
	} `xml:"Body"`
}

// GetCapabilities finds the Media service's XAddr, which is not guaranteed
// to be the same URL as the device service — many vendors collapse
// everything onto one endpoint (routed by SOAP body, not URL), but this
// isn't spec-guaranteed, so it's looked up explicitly rather than assumed.
func (c *Client) GetCapabilities(ctx context.Context) error {
	header, err := c.securityHeader()
	if err != nil {
		return err
	}
	envelope := buildEnvelope(header, []byte(`<tds:GetCapabilities><tds:Category>All</tds:Category></tds:GetCapabilities>`))

	body, err := doSOAP(ctx, c.hc, c.deviceXAddr, actionGetCapabilities, envelope)
	if err != nil {
		return err
	}

	var resp getCapabilitiesResponse
	if err := xml.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformedResponse, err)
	}

	c.mediaXAddr = resp.Body.GetCapabilitiesResponse.Capabilities.Media.XAddr
	if c.mediaXAddr == "" {
		c.mediaXAddr = c.deviceXAddr // fallback: many vendors do collapse services onto one endpoint
	}
	return nil
}

type getProfilesResponse struct {
	Body struct {
		GetProfilesResponse struct {
			Profiles []struct {
				Token                     string `xml:"token,attr"`
				Name                      string `xml:"Name"`
				VideoEncoderConfiguration *struct {
					Encoding   string `xml:"Encoding"`
					Resolution struct {
						Width  int `xml:"Width"`
						Height int `xml:"Height"`
					} `xml:"Resolution"`
					RateControl struct {
						FrameRateLimit int `xml:"FrameRateLimit"`
						BitrateLimit   int `xml:"BitrateLimit"`
					} `xml:"RateControl"`
				} `xml:"VideoEncoderConfiguration"`
			} `xml:"Profiles"`
		} `xml:"GetProfilesResponse"`
	} `xml:"Body"`
}

// GetProfiles lazily resolves the Media XAddr via GetCapabilities on first
// use. VideoEncoderConfiguration can be absent (audio-only/unconfigured
// profile) — modeled as a pointer so those are skipped, not dereferenced.
func (c *Client) GetProfiles(ctx context.Context) ([]StreamProfile, error) {
	if c.mediaXAddr == "" {
		if err := c.GetCapabilities(ctx); err != nil {
			return nil, err
		}
	}

	header, err := c.securityHeader()
	if err != nil {
		return nil, err
	}
	envelope := buildEnvelope(header, []byte(`<trt:GetProfiles/>`))

	body, err := doSOAP(ctx, c.hc, c.mediaXAddr, actionGetProfiles, envelope)
	if err != nil {
		return nil, err
	}

	var resp getProfilesResponse
	if err := xml.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedResponse, err)
	}

	profiles := make([]StreamProfile, 0, len(resp.Body.GetProfilesResponse.Profiles))
	for _, p := range resp.Body.GetProfilesResponse.Profiles {
		sp := StreamProfile{Token: p.Token, Name: p.Name}
		if p.VideoEncoderConfiguration != nil {
			sp.HasVideo = true
			sp.Width = p.VideoEncoderConfiguration.Resolution.Width
			sp.Height = p.VideoEncoderConfiguration.Resolution.Height
			sp.BitrateKbps = p.VideoEncoderConfiguration.RateControl.BitrateLimit
			sp.FrameRate = p.VideoEncoderConfiguration.RateControl.FrameRateLimit
		}
		profiles = append(profiles, sp)
	}
	return profiles, nil
}

type getStreamURIResponse struct {
	Body struct {
		GetStreamUriResponse struct {
			MediaUri struct {
				Uri string `xml:"Uri"`
			} `xml:"MediaUri"`
		} `xml:"GetStreamUriResponse"`
	} `xml:"Body"`
}

// GetStreamURI returns the RTSP URI verbatim — never inject credentials
// into it. Credentials are stored separately via AES-GCM, matching the
// schema's existing username/password-are-not-in-the-URI contract.
func (c *Client) GetStreamURI(ctx context.Context, profileToken string) (string, error) {
	header, err := c.securityHeader()
	if err != nil {
		return "", err
	}
	bodyXML := fmt.Sprintf(`<trt:GetStreamUri>
  <trt:StreamSetup>
    <tt:Stream>RTP-Unicast</tt:Stream>
    <tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport>
  </trt:StreamSetup>
  <trt:ProfileToken>%s</trt:ProfileToken>
</trt:GetStreamUri>`, xmlEscape(profileToken))
	envelope := buildEnvelope(header, []byte(bodyXML))

	body, err := doSOAP(ctx, c.hc, c.mediaXAddr, actionGetStreamURI, envelope)
	if err != nil {
		return "", err
	}

	var resp getStreamURIResponse
	if err := xml.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("%w: %v", ErrMalformedResponse, err)
	}
	return resp.Body.GetStreamUriResponse.MediaUri.Uri, nil
}

const defaultDeviceServicePath = "/onvif/device_service"

// deviceXAddrFromIP builds a device XAddr from a bare IP for the manual-
// entry flow. "/onvif/device_service" on port 80 is a near-universal
// convention, not a spec guarantee — the "add camera" form should offer an
// optional port/path override for the rare device that differs.
func deviceXAddrFromIP(ip string, port int) string {
	if port == 0 {
		port = 80
	}
	return fmt.Sprintf("http://%s:%d%s", ip, port, defaultDeviceServicePath)
}

// degradeSingleProfilePolicy: when a camera exposes only one usable video
// profile, duplicate it as both main and sub (true) so live view still
// works, rather than leaving SubstreamURI empty (false) and silently
// breaking live view for every single-stream budget camera.
const degradeSingleProfilePolicy = true

// FetchCameraDetails is the single entry point the "add camera" handler
// calls: GetDeviceInformation -> GetProfiles (which lazily resolves the
// Media XAddr) -> rank profiles by resolution x bitrate to pick main/sub
// (ordering is convention, not spec) -> GetStreamUri per selected token.
func FetchCameraDetails(ctx context.Context, ip string, port int, username, password string) (*CameraDetails, error) {
	client := NewClient(deviceXAddrFromIP(ip, port), username, password)

	info, err := client.GetDeviceInformation(ctx)
	if err != nil {
		return nil, err
	}

	profiles, err := client.GetProfiles(ctx)
	if err != nil {
		return nil, err
	}

	usable := make([]StreamProfile, 0, len(profiles))
	for _, p := range profiles {
		if p.HasVideo {
			usable = append(usable, p)
		}
	}
	if len(usable) == 0 {
		return nil, ErrNoVideoProfiles
	}

	sort.SliceStable(usable, func(i, j int) bool {
		pi, pj := usable[i], usable[j]
		if areaI, areaJ := pi.Width*pi.Height, pj.Width*pj.Height; areaI != areaJ {
			return areaI > areaJ
		}
		if pi.BitrateKbps != pj.BitrateKbps {
			return pi.BitrateKbps > pj.BitrateKbps
		}
		return pi.FrameRate > pj.FrameRate
	})

	mainURI, err := client.GetStreamURI(ctx, usable[0].Token)
	if err != nil {
		return nil, err
	}

	subURI := mainURI
	if len(usable) > 1 {
		if subURI, err = client.GetStreamURI(ctx, usable[1].Token); err != nil {
			return nil, err
		}
	} else if !degradeSingleProfilePolicy {
		subURI = ""
	}

	return &CameraDetails{
		Manufacturer:  info.Manufacturer,
		Model:         info.Model,
		MainstreamURI: mainURI,
		SubstreamURI:  subURI,
		Profiles:      usable,
	}, nil
}
