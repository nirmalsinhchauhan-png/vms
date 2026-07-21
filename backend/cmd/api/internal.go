package main

import "github.com/gofiber/fiber/v2"

// registerInternalRoutes wires endpoints nginx calls internally (never
// exposed to clients directly — see nginx/nginx.conf's `internal;` block).
func registerInternalRoutes(app *fiber.App) {
	// nginx's auth_request treats this as the gate for /recordings/*: a 2xx
	// authorizes the request, anything else denies it. HMAC-SHA256 segment
	// token verification isn't implemented yet, so this fails closed (501)
	// rather than returning a fake "always authorized" 200 — an unfinished
	// auth check must never look like a working one.
	app.Get("/internal/v1/hls/authorize", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusNotImplemented).SendString("hls segment authorization not yet implemented")
	})
}
