package fbhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/asdine/storm/v3"
	"github.com/gorilla/mux"
	"github.com/pquerna/otp/totp"

	fbAuth "github.com/filebrowser/filebrowser/v2/auth"
	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/storage"
	"github.com/filebrowser/filebrowser/v2/storage/bolt"
	"github.com/filebrowser/filebrowser/v2/users"
)

// totpTestEnv builds a storage with one admin user (ID 1) using JSON auth.
// The user gets a fresh salt (as production does on save), and the derived
// JWT key is cached so authenticated requests verify.
func totpTestEnv(t *testing.T) (*storage.Storage, *settings.Server) {
	t.Helper()

	root := t.TempDir()

	db, err := storm.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	st, err := bolt.NewStorage(db)
	if err != nil {
		t.Fatalf("failed to get storage: %v", err)
	}

	if err := st.Settings.Save(&settings.Settings{
		Key:                   []byte("legacy-key-not-used-for-jwt-anymore"), // required by save validation; no longer used for signing
		AuthMethod:            fbAuth.MethodJSONAuth,
		MinimumPasswordLength: 1,
	}); err != nil {
		t.Fatalf("failed to save settings: %v", err)
	}

	if err := st.Auth.Save(&fbAuth.JSONAuth{}); err != nil {
		t.Fatalf("failed to save auther: %v", err)
	}

	pwd, err := users.ValidateAndHashPwd("test-password", 1)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	admin := &users.User{
		Username: "u",
		Password: pwd,
		Perm:     users.Permissions{Admin: true},
	}
	if err := st.Users.Save(admin); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}
	if admin.Salt == "" {
		t.Fatal("user must have a salt after Save")
	}

	// Cache the JWT key derived from the admin's credentials, as a real
	// admin login would.
	fbAuth.SetJWTKey(users.DeriveJWTKey(admin.Username, "test-password", admin.Salt))

	return st, &settings.Server{Root: root}
}

// doAuthed performs a request against handler with a signed admin token.
func doAuthed(t *testing.T, handler http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	t.Helper()

	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, path, reader)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	req.Header.Set("X-Auth", token)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// doLogin attempts a JSON login with the given username/password/totp and
// returns the raw recorder.
func doLogin(t *testing.T, st *storage.Storage, server *settings.Server, username, password, code string) *httptest.ResponseRecorder {
	t.Helper()

	body := map[string]string{"username": username, "password": password}
	if code != "" {
		body["totp"] = code
	}
	raw, _ := json.Marshal(body)

	req, err := http.NewRequest(http.MethodPost, "/login", strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("failed to build login request: %v", err)
	}

	rec := httptest.NewRecorder()
	handle(loginHandler(time.Hour), "", st, server).ServeHTTP(rec, req)
	return rec
}

// adminToken returns a signed admin token for the env's admin user. The JWT
// key cache is already set by totpTestEnv; this re-derives and signs with the
// same key that withUser will verify against.
func adminToken(t *testing.T) string {
	t.Helper()
	key, ok := fbAuth.GetJWTKey()
	if !ok {
		t.Fatal("JWT key not cached")
	}
	return signToken(t, users.Permissions{Admin: true}, key)
}

func TestTOTPFullFlow(t *testing.T) {
	st, server := totpTestEnv(t)
	tok := adminToken(t)

	// Register routes under a real router so mux.Vars populates {id}.
	muxRouter := mux.NewRouter()
	muxRouter.Handle("/users/{id:[0-9]+}", handle(userGetHandler, "", st, server)).Methods("GET")
	muxRouter.Handle("/users/{id:[0-9]+}/totp/enroll", handle(totpEnrollHandler, "", st, server)).Methods("POST")
	muxRouter.Handle("/users/{id:[0-9]+}/totp/verify", handle(totpVerifyHandler, "", st, server)).Methods("POST")
	muxRouter.Handle("/users/{id:[0-9]+}/totp/disable", handle(totpDisableHandler, "", st, server)).Methods("POST")

	getUser := func() *httptest.ResponseRecorder {
		return doAuthed(t, muxRouter, http.MethodGet, "/users/1", "", tok)
	}
	enroll := func() *httptest.ResponseRecorder {
		return doAuthed(t, muxRouter, http.MethodPost, "/users/1/totp/enroll", "", tok)
	}
	verify := func(body string) *httptest.ResponseRecorder {
		return doAuthed(t, muxRouter, http.MethodPost, "/users/1/totp/verify", body, tok)
	}
	disable := func(body string) *httptest.ResponseRecorder {
		return doAuthed(t, muxRouter, http.MethodPost, "/users/1/totp/disable", body, tok)
	}

	// TOTP must be off by default and the salt must not leak to clients.
	if rec := getUser(); rec.Code != http.StatusOK {
		t.Fatalf("get user: %d body=%q", rec.Code, rec.Body.String())
	} else {
		var u users.User
		if err := json.Unmarshal(rec.Body.Bytes(), &u); err != nil {
			t.Fatalf("unmarshal user: %v", err)
		}
		if u.TOTPEnabled {
			t.Fatal("TOTP must be disabled by default")
		}
		if u.Salt != "" {
			t.Fatal("salt must never be exposed to clients")
		}
		if u.TOTPSecret != "" {
			t.Fatal("totpSecret must never be exposed to clients")
		}
	}

	// 1. Enroll: returns a fresh secret and otpauth URL.
	rec := enroll()
	if rec.Code != http.StatusOK {
		t.Fatalf("enroll: %d body=%q", rec.Code, rec.Body.String())
	}

	var enrolled struct {
		Secret string `json:"secret"`
		KeyURL string `json:"keyUrl"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &enrolled); err != nil {
		t.Fatalf("unmarshal enroll: %v", err)
	}
	if enrolled.Secret == "" || !strings.HasPrefix(enrolled.KeyURL, "otpauth://totp/") {
		t.Fatalf("unexpected enroll response: %+v", enrolled)
	}

	// Nothing persisted yet.
	u, err := st.Users.Get(server.Root, server.FollowExternalSymlinks, uint(1))
	if err != nil {
		t.Fatalf("get stored user: %v", err)
	}
	if u.TOTPEnabled || u.TOTPSecret != "" {
		t.Fatal("enroll must not persist the secret until verify")
	}

	// 2. Verify without password is rejected.
	rec = verify(`{"secret":"` + enrolled.Secret + `","code":"000000"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("verify no password: want 400, got %d body=%q", rec.Code, rec.Body.String())
	}

	// 3. Verify with wrong password is rejected.
	rec = verify(`{"secret":"` + enrolled.Secret + `","code":"000000","password":"wrong"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("verify wrong password: want 400, got %d", rec.Code)
	}

	// 4. Verify with a wrong code is rejected.
	rec = verify(`{"secret":"` + enrolled.Secret + `","code":"000000","password":"test-password"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("verify wrong code: want 400, got %d", rec.Code)
	}

	// 5. Verify with a valid code and correct password enables TOTP.
	code, err := totp.GenerateCode(enrolled.Secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	if ok := totp.Validate(code, enrolled.Secret); !ok {
		t.Fatal("sanity check failed: valid code rejected locally")
	}
	body := `{"secret":"` + enrolled.Secret + `","code":"` + code + `","password":"test-password"}`
	t.Logf("verify body: %s", body)
	rec = verify(body)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify: %d body=%q", rec.Code, rec.Body.String())
	}

	u, err = st.Users.Get(server.Root, server.FollowExternalSymlinks, uint(1))
	if err != nil {
		t.Fatalf("get stored user: %v", err)
	}
	t.Logf("stored user after verify: enabled=%v secret_len=%d", u.TOTPEnabled, len(u.TOTPSecret))
	if !u.TOTPEnabled || u.TOTPSecret == "" {
		t.Fatal("verify must persist the encrypted secret and enable TOTP")
	}
	if strings.Contains(u.TOTPSecret, enrolled.Secret) {
		t.Fatal("TOTP secret must be stored encrypted, not in plaintext")
	}

	// 6. Login without a code: 428, second factor required.
	if rec := doLogin(t, st, server, "u", "test-password", ""); rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("login without TOTP: want 428, got %d body=%q", rec.Code, rec.Body.String())
	}

	// 7. Login with a wrong code: 403 (same as wrong password, no enumeration).
	if rec := doLogin(t, st, server, "u", "test-password", "000000"); rec.Code != http.StatusForbidden {
		t.Fatalf("login with wrong TOTP: want 403, got %d", rec.Code)
	}

	// 8. Login with a valid code: success.
	code, err = totp.GenerateCode(enrolled.Secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	if rec := doLogin(t, st, server, "u", "test-password", code); rec.Code != http.StatusOK {
		t.Fatalf("login with valid TOTP: want 200, got %d body=%q", rec.Code, rec.Body.String())
	}

	// 9. Wrong password stays rejected even with a valid code.
	code, _ = totp.GenerateCode(enrolled.Secret, time.Now())
	if rec := doLogin(t, st, server, "u", "wrong-password", code); rec.Code != http.StatusForbidden {
		t.Fatalf("login with wrong password + valid TOTP: want 403, got %d", rec.Code)
	}

	// 10. Disable without password is rejected.
	rec = disable(`{}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("disable no password: want 400, got %d", rec.Code)
	}

	// 11. Disable with wrong password is rejected.
	rec = disable(`{"password":"wrong"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("disable wrong password: want 400, got %d", rec.Code)
	}

	// 12. Disable with correct password: TOTP no longer required.
	rec = disable(`{"password":"test-password"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable: %d body=%q", rec.Code, rec.Body.String())
	}

	if rec := doLogin(t, st, server, "u", "test-password", ""); rec.Code != http.StatusOK {
		t.Fatalf("login after disable: want 200, got %d body=%q", rec.Code, rec.Body.String())
	}
}

// TestTOTPSecretEncryptionRoundTrip verifies the AES-GCM helpers directly,
// including with the PBKDF2-derived keys used in production.
func TestTOTPSecretEncryptionRoundTrip(t *testing.T) {
	cases := [][]byte{
		users.DeriveTOTPKey("test-password", "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"),
		[]byte("short"), // arbitrary length is still fine (sha256 derivation)
	}
	for _, key := range cases {
		secret := "JBSWY3DPEHPK3PXP"

		enc, err := users.EncryptTOTPSecret(secret, key)
		if err != nil {
			t.Fatalf("encrypt (keylen=%d): %v", len(key), err)
		}
		if enc == "" || enc == secret {
			t.Fatalf("encrypted output must differ from plaintext: %q", enc)
		}

		dec, err := users.DecryptTOTPSecret(enc, key)
		if err != nil {
			t.Fatalf("decrypt (keylen=%d): %v", len(key), err)
		}
		if dec != secret {
			t.Fatalf("round trip (keylen=%d) = %q, want %q", len(key), dec, secret)
		}
	}

	// Wrong key must fail.
	key := users.DeriveTOTPKey("test-password", "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899")
	enc, err := users.EncryptTOTPSecret("JBSWY3DPEHPK3PXP", key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := users.DecryptTOTPSecret(enc, users.DeriveTOTPKey("other-password", "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899")); err == nil {
		t.Fatal("decrypt with wrong key must fail")
	}

	// Empty secret round-trips to empty.
	enc, err = users.EncryptTOTPSecret("", key)
	if err != nil || enc != "" {
		t.Fatalf("empty secret: enc=%q err=%v", enc, err)
	}
}

// TestSaltKeyDerivation verifies the PBKDF2 derivation primitives that back
// the TOTP and JWT keys: same inputs → same key, different password or salt
// → different key, and TOTP/JWT purposes produce distinct keys.
func TestSaltKeyDerivation(t *testing.T) {
	salt := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"

	totpKey := users.DeriveTOTPKey("secret-password", salt)
	if len(totpKey) != 32 {
		t.Fatalf("TOTP key length = %d, want 32", len(totpKey))
	}
	if !strings.EqualFold(string(users.DeriveTOTPKey("secret-password", salt)), string(totpKey)) {
		t.Fatal("deterministic derivation must reproduce the same key")
	}
	if string(users.DeriveTOTPKey("different-password", salt)) == string(totpKey) {
		t.Fatal("different password must derive a different key")
	}
	if string(users.DeriveTOTPKey("secret-password", "another-salt")) == string(totpKey) {
		t.Fatal("different salt must derive a different key")
	}

	jwtKey := users.DeriveJWTKey("admin", "secret-password", salt)
	if len(jwtKey) != 32 {
		t.Fatalf("JWT key length = %d, want 32", len(jwtKey))
	}
	if string(jwtKey) == string(totpKey) {
		t.Fatal("TOTP and JWT purposes must derive distinct keys from the same salt")
	}

	// The JWT key binds the username too: a renamed admin gets a new key.
	if string(users.DeriveJWTKey("renamed-admin", "secret-password", salt)) == string(jwtKey) {
		t.Fatal("different username must derive a different JWT key")
	}
}
