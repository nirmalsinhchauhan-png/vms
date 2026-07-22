package onvif

import (
	"errors"
	"fmt"
)

var (
	ErrUnauthorized      = errors.New("onvif: device rejected credentials")
	ErrDeviceUnreachable = errors.New("onvif: device did not respond")
	ErrNoVideoProfiles   = errors.New("onvif: device exposed no usable video profile")
	ErrMalformedResponse = errors.New("onvif: could not parse device response")
)

// SOAPFaultError wraps a SOAP fault that isn't classified as one of the
// sentinels above (i.e. not an auth failure) — a genuine, unexpected device
// error worth surfacing verbatim rather than flattening to a generic 500.
type SOAPFaultError struct {
	Code   string
	Reason string
}

func (e *SOAPFaultError) Error() string {
	return fmt.Sprintf("onvif: SOAP fault [%s]: %s", e.Code, e.Reason)
}
