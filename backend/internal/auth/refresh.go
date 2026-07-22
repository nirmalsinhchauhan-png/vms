package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrRefreshTokenInvalid = errors.New("auth: refresh token invalid or expired")
	ErrRefreshTokenReused  = errors.New("auth: refresh token reuse detected")
)

const refreshTokenBytes = 32

// Refresh tokens are opaque random values, not JWTs: refresh_tokens.token_hash
// is looked up by hash, which only makes sense for a hashed-opaque-token
// design (a JWT would be checked by signature, not database lookup).
func generateRefreshToken() (raw, hash string, err error) {
	buf := make([]byte, refreshTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("auth: generate refresh token: %w", err)
	}
	raw = hex.EncodeToString(buf)
	sum := sha256.Sum256([]byte(raw))
	hash = hex.EncodeToString(sum[:])
	return raw, hash, nil
}

// IssueRefreshToken starts a brand-new token chain (used at login).
func IssueRefreshToken(ctx context.Context, db *pgxpool.Pool, userID string, ttl time.Duration, ipAddress, userAgent string) (string, error) {
	raw, hash, err := generateRefreshToken()
	if err != nil {
		return "", err
	}
	_, err = db.Exec(ctx, `
		INSERT INTO refresh_tokens (user_id, token_hash, expires_at, ip_address, user_agent)
		VALUES ($1, $2, $3, NULLIF($4, '')::inet, $5)
	`, userID, hash, time.Now().Add(ttl), ipAddress, userAgent)
	if err != nil {
		return "", fmt.Errorf("auth: insert refresh token: %w", err)
	}
	return raw, nil
}

type refreshTokenRow struct {
	ID           string
	UserID       string
	ExpiresAt    time.Time
	RevokedAt    *time.Time
	ReplacedByID *string
}

// RotateRefreshToken verifies the presented raw token and, if valid and not
// already rotated, issues a new one in its place (revoking the old one).
//
// If the presented token has ALREADY been rotated (replaced_by_id set) or
// revoked, that's the theft-detection signal the Sprint 1 schema comment
// describes: someone is replaying a token that shouldn't exist anymore, so
// every other still-active token for that user is revoked and re-login is
// forced, rather than trusting this one request.
func RotateRefreshToken(ctx context.Context, db *pgxpool.Pool, rawToken string, rotate bool, ttl time.Duration, ipAddress, userAgent string) (newRawToken, userID string, err error) {
	sum := sha256.Sum256([]byte(rawToken))
	hash := hex.EncodeToString(sum[:])

	var row refreshTokenRow
	err = db.QueryRow(ctx, `
		SELECT id, user_id, expires_at, revoked_at, replaced_by_id
		FROM refresh_tokens WHERE token_hash = $1
	`, hash).Scan(&row.ID, &row.UserID, &row.ExpiresAt, &row.RevokedAt, &row.ReplacedByID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrRefreshTokenInvalid
	}
	if err != nil {
		return "", "", fmt.Errorf("auth: lookup refresh token: %w", err)
	}

	if row.ReplacedByID != nil || row.RevokedAt != nil {
		if _, revokeErr := db.Exec(ctx, `
			UPDATE refresh_tokens SET revoked_at = now()
			WHERE user_id = $1 AND revoked_at IS NULL
		`, row.UserID); revokeErr != nil {
			return "", "", fmt.Errorf("auth: revoke chain after reuse: %w", revokeErr)
		}
		// Surface the affected user id even on error so callers can log it
		// as a security event — this is the one error case worth an audit
		// trail beyond a generic 401.
		return "", row.UserID, ErrRefreshTokenReused
	}

	if time.Now().After(row.ExpiresAt) {
		return "", "", ErrRefreshTokenInvalid
	}

	if !rotate {
		return rawToken, row.UserID, nil
	}

	newRaw, newHash, err := generateRefreshToken()
	if err != nil {
		return "", "", err
	}

	tx, err := db.Begin(ctx)
	if err != nil {
		return "", "", fmt.Errorf("auth: begin rotation tx: %w", err)
	}
	defer tx.Rollback(ctx)

	var newID string
	err = tx.QueryRow(ctx, `
		INSERT INTO refresh_tokens (user_id, token_hash, expires_at, ip_address, user_agent)
		VALUES ($1, $2, $3, NULLIF($4, '')::inet, $5)
		RETURNING id
	`, row.UserID, newHash, time.Now().Add(ttl), ipAddress, userAgent).Scan(&newID)
	if err != nil {
		return "", "", fmt.Errorf("auth: insert rotated refresh token: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		UPDATE refresh_tokens SET replaced_by_id = $1, revoked_at = now() WHERE id = $2
	`, newID, row.ID); err != nil {
		return "", "", fmt.Errorf("auth: mark old refresh token replaced: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return "", "", fmt.Errorf("auth: commit rotation tx: %w", err)
	}

	return newRaw, row.UserID, nil
}

// RevokeRefreshToken revokes a single token by its raw value (used at logout).
func RevokeRefreshToken(ctx context.Context, db *pgxpool.Pool, rawToken string) error {
	sum := sha256.Sum256([]byte(rawToken))
	hash := hex.EncodeToString(sum[:])
	if _, err := db.Exec(ctx, `
		UPDATE refresh_tokens SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL
	`, hash); err != nil {
		return fmt.Errorf("auth: revoke refresh token: %w", err)
	}
	return nil
}
