package users

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

// PBKDF2 key derivation parameters, aligned with the ALM (Authentication &
// Login Management) scheme: 100k iterations, SHA-256, 32-byte output.
const (
	DefaultPBKDF2Iterations = 100000
	DefaultPBKDF2KeyLength  = 32

	// SaltSuffix seeds the deterministic per-user salt derivation so the
	// resulting salts are namespaced to this application.
	SaltSuffix = "_fb_auth_salt_2026"
)

// GenerateSalt creates a fresh random salt (32 bytes, hex encoded) used as
// the key-derivation seed for a user's TOTP and JWT keys. Salts are not
// secret: they are stored alongside the user so the derived keys can be
// re-computed at login time. A new salt is generated for every new user.
func GenerateSalt() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// DeriveKey derives a key from a passphrase and a salt using PBKDF2.
func DeriveKey(passphrase, salt string, keyLength int) []byte {
	return pbkdf2.Key([]byte(passphrase), []byte(salt), DefaultPBKDF2Iterations, keyLength, sha256.New)
}

// DeriveKeyForPurpose derives a purpose-specific salt from a base salt, so a
// single stored salt can namespace multiple independent keys (TOTP vs JWT)
// derived from the same passphrase.
func DeriveKeyForPurpose(baseSalt, purpose string) string {
	purposeSalt := fmt.Sprintf("%s_%s", baseSalt, purpose)
	hash := sha256.Sum256([]byte(purposeSalt))
	return hex.EncodeToString(hash[:])
}

// DeriveTOTPKey derives the AES-GCM key protecting a user's TOTP secret.
// The passphrase is the user's plaintext password (only ever in memory),
// mixed with a purpose-specific salt so it cannot be reused anywhere else.
func DeriveTOTPKey(password, salt string) []byte {
	return DeriveKey(password, DeriveKeyForPurpose(salt, "totp"), DefaultPBKDF2KeyLength)
}

// DeriveJWTKey derives the HS256 signing key for auth tokens. It binds the
// admin's username and password: the username is a public identifier (and the
// default "admin" is predictable), so the password is what actually provides
// secrecy. Because the salt and derivation are deterministic, restarting the
// process re-derives the same key after the admin logs in again.
func DeriveJWTKey(username, password, salt string) []byte {
	passphrase := username + ":" + password
	return DeriveKey(passphrase, DeriveKeyForPurpose(salt, "jwt"), DefaultPBKDF2KeyLength)
}