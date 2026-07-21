package main

import "github.com/gofiber/fiber/v2"

// registerV1Routes wires the public REST API. It's a placeholder until the
// auth, camera, and recording sprints land — real handlers replace this.
func registerV1Routes(router fiber.Router) {
	router.Get("/ping", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "pong"})
	})
}
