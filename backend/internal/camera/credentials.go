// Package camera holds camera-credential encryption, decryption, and
// URL-injection logic shared by the REST API (cmd/api/camera_routes.go) and
// the recording pipeline (internal/recording) — anything that actually
// needs to connect to a camera needs this, not just the HTTP layer.
package camera

import (
	"encoding/json"
	"fmt"
	"net/url"

	appcrypto "github.com/siliconsignals/vms/backend/internal/crypto"
)

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Encrypt marshals credentials into one JSON payload and encrypts it as a
// single AES-256-GCM plaintext — one nonce, one ciphertext (see migration
// 000002: two separately-encrypted fields sharing one nonce was a real bug).
func Encrypt(key appcrypto.Key, username, password string) (ciphertext, nonce []byte, err error) {
	payload, err := json.Marshal(Credentials{Username: username, Password: password})
	if err != nil {
		return nil, nil, fmt.Errorf("camera: marshal credentials: %w", err)
	}
	return appcrypto.Encrypt(payload, key)
}

// Decrypt reverses Encrypt.
func Decrypt(key appcrypto.Key, ciphertext, nonce []byte) (Credentials, error) {
	plaintext, err := appcrypto.Decrypt(ciphertext, nonce, key)
	if err != nil {
		return Credentials{}, fmt.Errorf("camera: decrypt credentials: %w", err)
	}
	var creds Credentials
	if err := json.Unmarshal(plaintext, &creds); err != nil {
		return Credentials{}, fmt.Errorf("camera: unmarshal credentials: %w", err)
	}
	return creds, nil
}

// InjectAuth returns rawURI with username/password set as URL userinfo
// (e.g. rtsp://user:pass@host/...). net/url percent-encodes special
// characters in the credentials correctly by construction — hand-built
// URL strings are exactly what broke a manual RTSP test earlier on this
// project, over a password containing '@'.
func InjectAuth(rawURI, username, password string) (string, error) {
	u, err := url.Parse(rawURI)
	if err != nil {
		return "", fmt.Errorf("camera: parse uri: %w", err)
	}
	u.User = url.UserPassword(username, password)
	return u.String(), nil
}

// AuthenticatedURL combines Decrypt + InjectAuth for callers that only have
// the encrypted blob on hand — e.g. a startup reconciliation pass reading
// straight from the database, with no plaintext credentials in memory.
func AuthenticatedURL(key appcrypto.Key, rawURI string, ciphertext, nonce []byte) (string, error) {
	creds, err := Decrypt(key, ciphertext, nonce)
	if err != nil {
		return "", err
	}
	return InjectAuth(rawURI, creds.Username, creds.Password)
}
