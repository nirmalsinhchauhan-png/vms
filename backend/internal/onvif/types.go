// Package onvif is a minimal, hand-rolled ONVIF client: WS-Discovery plus
// just enough SOAP (GetDeviceInformation, GetCapabilities, GetProfiles,
// GetStreamUri) to prefill an "add camera" form. Not a full Profile S
// implementation — no PTZ, no Profile T/Media2, no PasswordText fallback.
// Stdlib only (net, net/http, encoding/xml, crypto/sha1) — no third-party
// ONVIF or SOAP library, since none with clear maintenance status exists.
package onvif

// DiscoveredDevice is one WS-Discovery ProbeMatch result.
type DiscoveredDevice struct {
	EndpointRef string   `json:"endpoint_ref"` // urn:uuid:... stable identity, used for de-dup
	XAddrs      []string `json:"xaddrs"`       // service URL(s); a device can report more than one
	Scopes      []string `json:"scopes"`
	RemoteAddr  string   `json:"remote_addr"` // source IP of the ProbeMatch, fallback display value
}

type DeviceInfo struct {
	Manufacturer    string `json:"manufacturer"`
	Model           string `json:"model"`
	FirmwareVersion string `json:"firmware_version"`
	SerialNumber    string `json:"serial_number"`
	HardwareID      string `json:"hardware_id"`
}

type StreamProfile struct {
	Token       string `json:"token"`
	Name        string `json:"name"`
	Width       int    `json:"width"`
	Height      int    `json:"height"`
	BitrateKbps int    `json:"bitrate_kbps"`
	FrameRate   int    `json:"frame_rate"`
	HasVideo    bool   `json:"has_video"`
}

type CameraDetails struct {
	Manufacturer  string          `json:"manufacturer"`
	Model         string          `json:"model"`
	MainstreamURI string          `json:"mainstream_uri"`
	SubstreamURI  string          `json:"substream_uri"` // == MainstreamURI only when the camera has just one usable profile
	Profiles      []StreamProfile `json:"profiles"`
}
