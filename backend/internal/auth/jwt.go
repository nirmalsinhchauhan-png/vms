// Package auth implements JWT RS256 access tokens, opaque rotating refresh
// tokens, bcrypt password hashing, and the Fiber middleware that gates
// routes behind them.
package auth

import (
	"crypto/rsa"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims carries the identity/authorization data an access token asserts.
// UserID lives in the standard "sub" claim (jwt.RegisteredClaims.Subject).
type Claims struct {
	OrganizationID string `json:"org"`
	Role           string `json:"role"`
	jwt.RegisteredClaims
}

// JWTIssuer signs and verifies access tokens with a single RS256 keypair
// loaded once at startup.
type JWTIssuer struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	issuer     string
	accessTTL  time.Duration
}

func NewJWTIssuer(privateKeyPath, publicKeyPath, issuer string, accessTTL time.Duration) (*JWTIssuer, error) {
	privBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("auth: read JWT private key: %w", err)
	}
	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privBytes)
	if err != nil {
		return nil, fmt.Errorf("auth: parse JWT private key: %w", err)
	}

	pubBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("auth: read JWT public key: %w", err)
	}
	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("auth: parse JWT public key: %w", err)
	}

	return &JWTIssuer{privateKey: privKey, publicKey: pubKey, issuer: issuer, accessTTL: accessTTL}, nil
}

// IssueAccessToken signs a short-lived RS256 token asserting the given
// identity. The caller is trusted to have already verified the password.
func (j *JWTIssuer) IssueAccessToken(userID, organizationID, role string) (token string, expiresAt time.Time, err error) {
	now := time.Now()
	expiresAt = now.Add(j.accessTTL)
	claims := Claims{
		OrganizationID: organizationID,
		Role:           role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    j.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(j.privateKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("auth: sign access token: %w", err)
	}
	return signed, expiresAt, nil
}

// VerifyAccessToken checks the RS256 signature, issuer, and expiry, and
// returns the embedded claims on success.
func (j *JWTIssuer) VerifyAccessToken(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		// Explicit method check defends against alg-confusion attacks even
		// though WithValidMethods below already restricts this.
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("auth: unexpected signing method %v", t.Header["alg"])
		}
		return j.publicKey, nil
	}, jwt.WithIssuer(j.issuer), jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		return nil, fmt.Errorf("auth: verify access token: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("auth: invalid access token")
	}
	return claims, nil
}
