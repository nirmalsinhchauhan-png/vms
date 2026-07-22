// Package go2rtc is a minimal HTTP client for go2rtc's own stream-management
// API. go2rtc has no auth of its own (see go2rtc/go2rtc.yaml's comment) —
// this client is only ever called from inside the compose network.
package go2rtc

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type Client struct {
	baseURL string
	hc      *http.Client
}

func NewClient(host, port string) *Client {
	return &Client{
		baseURL: fmt.Sprintf("http://%s:%s", host, port),
		hc:      &http.Client{Timeout: 5 * time.Second},
	}
}

// RegisterStream adds or updates a named stream pointing at src (the
// camera's substream_uri — go2rtc is the live-view pipeline only; the
// mainstream/recording path never goes through it).
func (c *Client) RegisterStream(ctx context.Context, name, src string) error {
	q := url.Values{"name": {name}, "src": {src}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+"/api/streams?"+q.Encode(), nil)
	if err != nil {
		return fmt.Errorf("go2rtc: build register request: %w", err)
	}
	return c.do(req)
}

// RemoveStream removes a previously registered stream. Removing a
// nonexistent stream is not treated as an error by go2rtc and neither here.
//
// Deliberately keyed on "src", not "name": go2rtc's DELETE handler reads
// the stream key from the src param (`delete(streams, src)` in its own
// source) — passing "name" instead is accepted with a 200 and silently
// deletes nothing. Confirmed against go2rtc 1.9.4's actual handler source,
// not assumed from the PUT side's param naming.
func (c *Client) RemoveStream(ctx context.Context, name string) error {
	q := url.Values{"src": {name}}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/api/streams?"+q.Encode(), nil)
	if err != nil {
		return fmt.Errorf("go2rtc: build remove request: %w", err)
	}
	return c.do(req)
}

func (c *Client) do(req *http.Request) error {
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("go2rtc: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("go2rtc: unexpected status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}
