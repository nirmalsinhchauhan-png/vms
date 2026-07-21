package main

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// registerHealthRoutes wires liveness and readiness checks.
//
// /healthz is intentionally dependency-free: it's what the Docker healthcheck
// polls, and a slow/unavailable Postgres or Redis should not make the
// container report unhealthy and get killed — that's what /readyz is for.
func registerHealthRoutes(app *fiber.App, db *pgxpool.Pool, rdb *redis.Client) {
	app.Get("/healthz", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	app.Get("/readyz", func(c *fiber.Ctx) error {
		ctx, cancel := context.WithTimeout(c.Context(), 2*time.Second)
		defer cancel()

		checks := fiber.Map{}
		ready := true

		if err := db.Ping(ctx); err != nil {
			checks["postgres"] = err.Error()
			ready = false
		} else {
			checks["postgres"] = "ok"
		}

		if err := rdb.Ping(ctx).Err(); err != nil {
			checks["redis"] = err.Error()
			ready = false
		} else {
			checks["redis"] = "ok"
		}

		if !ready {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
				"status": "not_ready",
				"checks": checks,
			})
		}
		return c.JSON(fiber.Map{"status": "ready", "checks": checks})
	})
}
