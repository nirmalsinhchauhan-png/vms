package recording

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SegmentClaims binds a signed HLS-segment access token to one specific
// camera. HS256 is HMAC-SHA256 — exactly what HLS_TOKEN_SECRET's own
// .env.example comment describes; golang-jwt/jwt/v5 (already a dependency
// for the RS256 access tokens in internal/auth) gives correct constant-time
// verification and expiry handling for free instead of hand-rolling it.
type SegmentClaims struct {
	CameraID string `json:"cam"`
	jwt.RegisteredClaims
}

var (
	ErrTokenInvalid   = errors.New("hlsauth: invalid or malformed token")
	ErrTokenExpired   = errors.New("hlsauth: token expired")
	ErrCameraMismatch = errors.New("hlsauth: token camera does not match requested path")
)

// MintSegmentToken issues a short-lived token authorizing playback of one
// camera's recordings. Minted by the authenticated /recordings/session
// endpoint; verified by the unauthenticated nginx auth_request callback,
// which has no access to the caller's own Bearer JWT.
func MintSegmentToken(secret []byte, cameraID string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := SegmentClaims{
		CameraID: cameraID,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("recording: sign segment token: %w", err)
	}
	return signed, nil
}

// VerifySegmentToken checks the HMAC signature and expiry, then confirms
// the token was minted for requestedCameraID specifically — this is what
// stops a token minted for camera A from being replayed against camera B's
// segments by editing the request path; signature validity alone wouldn't
// catch that; the same secret verifies every camera's tokens.
func VerifySegmentToken(secret []byte, tokenString, requestedCameraID string) error {
	claims := &SegmentClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("recording: unexpected signing method %v", t.Header["alg"])
		}
		return secret, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return ErrTokenExpired
		}
		return ErrTokenInvalid
	}
	if !token.Valid {
		return ErrTokenInvalid
	}
	if claims.CameraID != requestedCameraID {
		return ErrCameraMismatch
	}
	return nil
}
