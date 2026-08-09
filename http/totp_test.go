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

// totpTestEnv builds a storage with one admin user (ID 1) using JSON auth and
// a known signing key, mirroring a real deployment.
func totpTestEnv(t *testing.T) (*storage.Storage, *settings.Server, []byte) {
	t.Helper()

	root := t.TempDir()
	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes: AES-256

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
		Key:                   key,
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

	if err := st.Users.Save(&users.User{
		Username: "u",
		Password: pwd,
		Perm:     users.Permissions{Admin: true},
	}); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	return st, &settings.Server{Root: root}, key
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

func TestTOTPFullFlow(t *testing.T) {
	st, server, key := totpTestEnv(t)
	adminToken := signToken(t, users.Permissions{Admin: true}, key)

	// Register routes under a real router so mux.Vars populates {id}.
	muxRouter := mux.NewRouter()
	muxRouter.Handle("/users/{id:[0-9]+}", handle(userGetHandler, "", st, server)).Methods("GET")
	muxRouter.Handle("/users/{id:[0-9]+}/totp/enroll", handle(totpEnrollHandler, "", st, server)).Methods("POST")
	muxRouter.Handle("/users/{id:[0-9]+}/totp/verify", handle(totpVerifyHandler, "", st, server)).Methods("POST")
	muxRouter.Handle("/users/{id:[0-9]+}/totp/disable", handle(totpDisableHandler, "", st, server)).Methods("POST")

	getUser := func() *httptest.ResponseRecorder {
		return doAuthed(t, muxRouter, http.MethodGet, "/users/1", "", adminToken)
	}
	enroll := func() *httptest.ResponseRecorder {
		return doAuthed(t, muxRouter, http.MethodPost, "/users/1/totp/enroll", "", adminToken)
	}
	verify := func(body string) *httptest.ResponseRecorder {
		return doAuthed(t, muxRouter, http.MethodPost, "/users/1/totp/verify", body, adminToken)
	}
	disable := func() *httptest.ResponseRecorder {
		return doAuthed(t, muxRouter, http.MethodPost, "/users/1/totp/disable", "", adminToken)
	}

	// TOTP must be off by default.
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

	// 2. Verify with a wrong code is rejected.
	rec = verify(`{"secret":"` + enrolled.Secret + `","code":"000000"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("verify wrong code: want 400, got %d", rec.Code)
	}

	// 3. Verify with a valid code enables TOTP.
	code, err := totp.GenerateCode(enrolled.Secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	// Sanity: the same library call the server makes must pass locally.
	if ok := totp.Validate(code, enrolled.Secret); !ok {
		t.Fatal("sanity check failed: valid code rejected locally")
	}
	body := `{"secret":"` + enrolled.Secret + `","code":"` + code + `"}`
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

	// 4. Login without a code: 428, second factor required.
	if rec := doLogin(t, st, server, "u", "test-password", ""); rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("login without TOTP: want 428, got %d body=%q", rec.Code, rec.Body.String())
	}

	// 5. Login with a wrong code: 403 (same as wrong password, no enumeration).
	if rec := doLogin(t, st, server, "u", "test-password", "000000"); rec.Code != http.StatusForbidden {
		t.Fatalf("login with wrong TOTP: want 403, got %d", rec.Code)
	}

	// 6. Login with a valid code: success.
	code, err = totp.GenerateCode(enrolled.Secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	if rec := doLogin(t, st, server, "u", "test-password", code); rec.Code != http.StatusOK {
		t.Fatalf("login with valid TOTP: want 200, got %d body=%q", rec.Code, rec.Body.String())
	}

	// 7. Wrong password stays rejected even with a valid code.
	code, _ = totp.GenerateCode(enrolled.Secret, time.Now())
	if rec := doLogin(t, st, server, "u", "wrong-password", code); rec.Code != http.StatusForbidden {
		t.Fatalf("login with wrong password + valid TOTP: want 403, got %d", rec.Code)
	}

	// 8. Disable: TOTP no longer required.
	rec = disable()
	if rec.Code != http.StatusOK {
		t.Fatalf("disable: %d body=%q", rec.Code, rec.Body.String())
	}

	if rec := doLogin(t, st, server, "u", "test-password", ""); rec.Code != http.StatusOK {
		t.Fatalf("login after disable: want 200, got %d body=%q", rec.Code, rec.Body.String())
	}
}

// TestTOTPSecretEncryptionRoundTrip verifies the AES-GCM helpers directly,
// including with a real 512-bit settings key (settings.GenerateKey length).
func TestTOTPSecretEncryptionRoundTrip(t *testing.T) {
	cases := [][]byte{
		[]byte("0123456789abcdef0123456789abcdef"),                                 // 32 bytes
		[]byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"), // 64 bytes (GenerateKey)
		[]byte("short"), // arbitrary length
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
	key := []byte("0123456789abcdef0123456789abcdef0123456789abcdef")
	enc, err := users.EncryptTOTPSecret("JBSWY3DPEHPK3PXP", key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := users.DecryptTOTPSecret(enc, []byte("fedcba9876543210fedcba9876543210")); err == nil {
		t.Fatal("decrypt with wrong key must fail")
	}

	// Empty secret round-trips to empty.
	enc, err = users.EncryptTOTPSecret("", key)
	if err != nil || enc != "" {
		t.Fatalf("empty secret: enc=%q err=%v", enc, err)
	}
}
