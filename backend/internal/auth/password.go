package auth

import "golang.org/x/crypto/bcrypt"

// Cost 10 matches the gen_salt('bf', 10) used by database/seed.sql, so
// seeded and application-created passwords use the same work factor.
const bcryptCost = 10

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// VerifyPassword returns nil if password matches hash, a bcrypt error
// (typically bcrypt.ErrMismatchedHashAndPassword) otherwise.
func VerifyPassword(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
