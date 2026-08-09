package users

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// EncryptTOTPSecret encrypts a TOTP secret with the settings key using
// AES-256-GCM, so that the plaintext secret never touches the database.
// The settings key may be any length (GenerateKey produces 512 bits); a
// SHA-256 digest is derived from it so the cipher always gets the exact
// 32 bytes AES-256 requires. The returned value is base64url encoded and
// stored in User.TOTPSecret.
func EncryptTOTPSecret(secret string, key []byte) (string, error) {
	if secret == "" {
		return "", nil
	}

	sum := sha256.Sum256(key)
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(secret), nil)
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

// DecryptTOTPSecret decrypts a TOTP secret previously stored by
// EncryptTOTPSecret.
func DecryptTOTPSecret(stored string, key []byte) (string, error) {
	if stored == "" {
		return "", nil
	}

	data, err := base64.RawURLEncoding.DecodeString(stored)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(key)
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(data) < gcm.NonceSize() {
		return "", errors.New("invalid TOTP secret payload")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt TOTP secret: %w", err)
	}

	return string(plaintext), nil
}
