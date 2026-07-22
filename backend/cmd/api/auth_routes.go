package main

import (
	"errors"
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/siliconsignals/vms/backend/internal/auth"
	"github.com/siliconsignals/vms/backend/internal/config"
)

// registerAuthRoutes wires POST /login, /refresh, /logout. Refresh tokens
// live in an httpOnly, Secure cookie — the frontend never touches the raw
// value directly, only the short-lived access token returned in the body.
func registerAuthRoutes(router fiber.Router, dbPool *pgxpool.Pool, issuer *auth.JWTIssuer, cfg config.Config) {
	router.Post("/login", func(c *fiber.Ctx) error {
		var body struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := c.BodyParser(&body); err != nil || body.Email == "" || body.Password == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "email and password are required"})
		}

		var (
			userID, orgID, passwordHash, fullName, roleName string
			isActive                                        bool
		)
		// No organization filter: schema uniqueness is (organization_id,
		// email), but this is a single-org-per-deployment design (see the
		// organizations table comment) — documented simplification, not a
		// bug. Revisit only if true multi-org SaaS ever ships.
		err := dbPool.QueryRow(c.Context(), `
			SELECT u.id, u.organization_id, u.password_hash, u.is_active, u.full_name, r.name
			FROM users u JOIN roles r ON r.id = u.role_id
			WHERE u.email = $1
			ORDER BY u.created_at
			LIMIT 1
		`, body.Email).Scan(&userID, &orgID, &passwordHash, &isActive, &fullName, &roleName)
		if errors.Is(err, pgx.ErrNoRows) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid email or password"})
		}
		if err != nil {
			log.Printf("auth: login lookup: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
		}

		if !isActive {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "account is disabled"})
		}
		if err := auth.VerifyPassword(passwordHash, body.Password); err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid email or password"})
		}

		accessToken, expiresAt, err := issuer.IssueAccessToken(userID, orgID, roleName)
		if err != nil {
			log.Printf("auth: issue access token: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
		}

		refreshToken, err := auth.IssueRefreshToken(c.Context(), dbPool, userID, cfg.JWTRefreshTokenTTL, c.IP(), c.Get("User-Agent"))
		if err != nil {
			log.Printf("auth: issue refresh token: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
		}

		if _, err := dbPool.Exec(c.Context(), `UPDATE users SET last_login_at = now() WHERE id = $1`, userID); err != nil {
			log.Printf("auth: update last_login_at: %v", err)
		}

		setRefreshCookie(c, refreshToken, cfg.JWTRefreshTokenTTL)
		return c.JSON(fiber.Map{
			"access_token": accessToken,
			"expires_at":   expiresAt,
			"user": fiber.Map{
				"id":        userID,
				"email":     body.Email,
				"full_name": fullName,
				"role":      roleName,
			},
		})
	})

	router.Post("/refresh", func(c *fiber.Ctx) error {
		rawToken := c.Cookies("refresh_token")
		if rawToken == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "no refresh token"})
		}

		newRaw, userID, err := auth.RotateRefreshToken(c.Context(), dbPool, rawToken, cfg.JWTRefreshRotate, cfg.JWTRefreshTokenTTL, c.IP(), c.Get("User-Agent"))
		if err != nil {
			clearRefreshCookie(c)
			if errors.Is(err, auth.ErrRefreshTokenReused) {
				log.Printf("auth: SECURITY refresh token reuse detected, user=%s ip=%s — chain revoked", userID, c.IP())
			}
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "session expired, please log in again"})
		}

		var orgID, roleName string
		if err := dbPool.QueryRow(c.Context(), `
			SELECT u.organization_id, r.name FROM users u JOIN roles r ON r.id = u.role_id WHERE u.id = $1
		`, userID).Scan(&orgID, &roleName); err != nil {
			log.Printf("auth: refresh lookup role: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
		}

		accessToken, expiresAt, err := issuer.IssueAccessToken(userID, orgID, roleName)
		if err != nil {
			log.Printf("auth: issue access token on refresh: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
		}

		setRefreshCookie(c, newRaw, cfg.JWTRefreshTokenTTL)
		return c.JSON(fiber.Map{"access_token": accessToken, "expires_at": expiresAt})
	})

	router.Post("/logout", func(c *fiber.Ctx) error {
		if rawToken := c.Cookies("refresh_token"); rawToken != "" {
			if err := auth.RevokeRefreshToken(c.Context(), dbPool, rawToken); err != nil {
				log.Printf("auth: revoke on logout: %v", err)
			}
		}
		clearRefreshCookie(c)
		return c.SendStatus(fiber.StatusNoContent)
	})

	// /refresh only returns a bare access token (no display info) — the
	// frontend calls this after a silent refresh on page load to restore
	// who's logged in, since the JWT itself only carries id/org/role, not
	// email/full_name.
	router.Get("/me", auth.RequireAuth(issuer), func(c *fiber.Ctx) error {
		userID, _ := c.Locals(auth.LocalUserID).(string)

		var email, fullName, roleName string
		err := dbPool.QueryRow(c.Context(), `
			SELECT u.email, u.full_name, r.name FROM users u JOIN roles r ON r.id = u.role_id WHERE u.id = $1
		`, userID).Scan(&email, &fullName, &roleName)
		if errors.Is(err, pgx.ErrNoRows) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "user not found"})
		}
		if err != nil {
			log.Printf("auth: me lookup: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
		}

		return c.JSON(fiber.Map{"id": userID, "email": email, "full_name": fullName, "role": roleName})
	})
}

func setRefreshCookie(c *fiber.Ctx, token string, ttl time.Duration) {
	c.Cookie(&fiber.Cookie{
		Name:     "refresh_token",
		Value:    token,
		Path:     "/api/v1/auth",
		Expires:  time.Now().Add(ttl),
		HTTPOnly: true,
		Secure:   true,
		SameSite: "Lax",
	})
}

func clearRefreshCookie(c *fiber.Ctx) {
	c.Cookie(&fiber.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/api/v1/auth",
		Expires:  time.Now().Add(-time.Hour),
		HTTPOnly: true,
		Secure:   true,
		SameSite: "Lax",
	})
}
