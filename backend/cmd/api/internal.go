package main

import (
	"net/url"
	"regexp"

	"github.com/gofiber/fiber/v2"

	"github.com/siliconsignals/vms/backend/internal/recording"
)

// hlsSegmentPathRe extracts the camera ID from a /recordings/ path, e.g.
// "/recordings/<camera_id>/2026-07-22/seg_20260722_140530.ts".
var hlsSegmentPathRe = regexp.MustCompile(`^/recordings/([0-9a-fA-F-]{36})/`)

// registerInternalRoutes wires endpoints nginx calls internally (never
// exposed to clients directly — see nginx/nginx.conf's `internal;` block).
func registerInternalRoutes(app *fiber.App, hlsSecret []byte) {
	app.Get("/internal/v1/hls/authorize", hlsAuthorizeHandler(hlsSecret))
}

// hlsAuthorizeHandler is nginx's auth_request gate for /recordings/*: a 2xx
// response authorizes the original request, anything else denies it. It
// replaces the earlier fail-closed 501 stub now that real HMAC-SHA256
// segment tokens (internal/recording) exist.
//
// nginx never forwards the client's Authorization header here (this is an
// unauthenticated internal subrequest) — X-Original-URI carries the full
// original request path + query string instead, and that's where the
// short-lived signed token lives (?token=..., minted by the authenticated
// GET /api/v1/cameras/:id/recordings/session endpoint). The camera ID is
// parsed from the path itself and cross-checked against the token's own
// claim — signature validity alone wouldn't stop a token minted for one
// camera being replayed against another camera's segments by editing the
// URL path.
func hlsAuthorizeHandler(hlsSecret []byte) fiber.Handler {
	return func(c *fiber.Ctx) error {
		originalURI := c.Get("X-Original-URI")
		if originalURI == "" {
			return c.Status(fiber.StatusForbidden).SendString("missing request URI")
		}
		u, err := url.Parse(originalURI)
		if err != nil {
			return c.Status(fiber.StatusForbidden).SendString("malformed request URI")
		}

		m := hlsSegmentPathRe.FindStringSubmatch(u.Path)
		if m == nil {
			return c.Status(fiber.StatusForbidden).SendString("path does not identify a camera")
		}
		cameraID := m[1]

		token := u.Query().Get("token")
		if token == "" {
			return c.Status(fiber.StatusForbidden).SendString("missing token")
		}

		// Never a bare 500 for an expected bad/expired/mismatched token —
		// that's a normal outcome (an old link, a stale tab), not a server
		// fault.
		if err := recording.VerifySegmentToken(hlsSecret, token, cameraID); err != nil {
			return c.Status(fiber.StatusForbidden).SendString("unauthorized")
		}
		return c.SendStatus(fiber.StatusOK)
	}
}
