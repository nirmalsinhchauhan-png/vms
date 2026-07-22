package auth

import (
	"strings"

	"github.com/gofiber/fiber/v2"
)

const (
	LocalUserID         = "auth_user_id"
	LocalOrganizationID = "auth_organization_id"
	LocalRole           = "auth_role"
)

// RequireAuth verifies the Authorization: Bearer <access-token> header and,
// on success, stores the caller's identity/role in Fiber locals for
// downstream handlers and RequireRole to read.
func RequireAuth(issuer *JWTIssuer) fiber.Handler {
	return func(c *fiber.Ctx) error {
		const prefix = "Bearer "
		header := c.Get("Authorization")
		if !strings.HasPrefix(header, prefix) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing or malformed authorization header"})
		}

		claims, err := issuer.VerifyAccessToken(strings.TrimPrefix(header, prefix))
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid or expired access token"})
		}

		c.Locals(LocalUserID, claims.Subject)
		c.Locals(LocalOrganizationID, claims.OrganizationID)
		c.Locals(LocalRole, claims.Role)
		return c.Next()
	}
}

// RequireRole gates a route to a set of roles. Must run after RequireAuth.
func RequireRole(roles ...string) fiber.Handler {
	allowed := make(map[string]struct{}, len(roles))
	for _, r := range roles {
		allowed[r] = struct{}{}
	}
	return func(c *fiber.Ctx) error {
		role, _ := c.Locals(LocalRole).(string)
		if _, ok := allowed[role]; !ok {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "insufficient role"})
		}
		return c.Next()
	}
}
