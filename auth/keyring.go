package auth

import "sync"

// JWT signing key lives only in memory. It is derived (PBKDF2) from the
// admin's username+password+salt on a successful admin login, and cleared
// whenever the admin's credentials change, forcing every client to re-login
// with fresh tokens. Nothing derived from a password ever touches the disk.
var (
	jwtKeyMu sync.RWMutex
	jwtKey   []byte
)

// SetJWTKey caches the in-memory JWT signing key after an admin login.
func SetJWTKey(key []byte) {
	jwtKeyMu.Lock()
	defer jwtKeyMu.Unlock()
	jwtKey = key
}

// GetJWTKey returns the current in-memory JWT signing key. The boolean is
// false until an admin has logged in since process start (or after a
// credential change cleared the key).
func GetJWTKey() ([]byte, bool) {
	jwtKeyMu.RLock()
	defer jwtKeyMu.RUnlock()
	return jwtKey, jwtKey != nil
}

// ClearJWTKey invalidates every outstanding token. It is called when the
// admin's username or password changes, since the derived key changes too.
func ClearJWTKey() {
	jwtKeyMu.Lock()
	defer jwtKeyMu.Unlock()
	jwtKey = nil
}
