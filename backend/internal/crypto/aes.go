// Package crypto provides AES-256-GCM encryption for camera credentials at
// rest. Stdlib only (crypto/aes, crypto/cipher) — no third-party dependency
// needed for a primitive this well-supported in the standard library.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// Key wraps a 32-byte AES-256 key, decoded once from the hex-encoded
// CAMERA_CREDENTIALS_ENC_KEY env var.
type Key [32]byte

func ParseKeyHex(hexKey string) (Key, error) {
	var key Key
	decoded, err := hex.DecodeString(hexKey)
	if err != nil {
		return key, fmt.Errorf("crypto: decode hex key: %w", err)
	}
	if len(decoded) != len(key) {
		return key, fmt.Errorf("crypto: key must be %d bytes (got %d) — generate with `openssl rand -hex 32`", len(key), len(decoded))
	}
	copy(key[:], decoded)
	return key, nil
}

// Encrypt returns a fresh random nonce and the AES-256-GCM ciphertext (which
// includes the auth tag). One nonce per call, per key — never reuse a nonce
// for two different plaintexts under the same key.
func Encrypt(plaintext []byte, key Key) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: new GCM: %w", err)
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("crypto: generate nonce: %w", err)
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

func Decrypt(ciphertext, nonce []byte, key Key) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("crypto: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: new GCM: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt (wrong key or tampered ciphertext): %w", err)
	}
	return plaintext, nil
}
