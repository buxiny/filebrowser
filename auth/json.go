package auth

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/pquerna/otp/totp"

	fberrors "github.com/filebrowser/filebrowser/v2/errors"
	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/users"
)

// MethodJSONAuth is used to identify json auth.
const MethodJSONAuth settings.AuthMethod = "json"

// dummyHash is used to prevent user enumeration timing attacks.
// It MUST be a valid bcrypt hash.
const dummyHash = "$2a$10$O4mEMeOL/nit6zqe.WQXauLRbRlzb3IgLHsa26Pf0N/GiU9b.wK1m"

type jsonCred struct {
	Password  string `json:"password"`
	Username  string `json:"username"`
	ReCaptcha string `json:"recaptcha"`
	TOTP      string `json:"totp"`
}

// JSONAuth is a json implementation of an Auther.
type JSONAuth struct {
	ReCaptcha *ReCaptcha `json:"recaptcha" yaml:"recaptcha"`
}

// Auth authenticates the user via a json in content body.
func (a JSONAuth) Auth(r *http.Request, usr users.Store, stg *settings.Settings, srv *settings.Server) (*users.User, error) {
	var cred jsonCred

	if r.Body == nil {
		return nil, os.ErrPermission
	}

	err := json.NewDecoder(r.Body).Decode(&cred)
	if err != nil {
		return nil, os.ErrPermission
	}

	// If ReCaptcha is enabled, check the code.
	if a.ReCaptcha != nil && a.ReCaptcha.Secret != "" {
		ok, err := a.ReCaptcha.Ok(cred.ReCaptcha)

		if err != nil {
			return nil, err
		}

		if !ok {
			return nil, os.ErrPermission
		}
	}

	u, err := usr.Get(srv.Root, srv.FollowExternalSymlinks, cred.Username)

	hash := dummyHash
	if err == nil {
		hash = u.Password
	}

	if !users.CheckPwd(cred.Password, hash) {
		return nil, os.ErrPermission
	}

	if err != nil {
		return nil, os.ErrPermission
	}

	// Every user must have a salt for the PBKDF2 key derivation. Users
	// created before salts existed (older builds of this fork) get one
	// generated lazily on first successful login. If such a user already had
	// a TOTP secret, it was encrypted with the old settings key and cannot be
	// decrypted with the newly derived key, so the secret is migrated by
	// re-encrypting it with the fresh key; a secret that fails even the old
	// decryption is dropped and TOTP disabled (the user must re-enroll).
	if u.Salt == "" {
		salt, serr := users.GenerateSalt()
		if serr != nil {
			return nil, serr
		}
		u.Salt = salt
		if u.TOTPEnabled && u.TOTPSecret != "" {
			// Try the legacy settings-key encryption first.
			if legacy, derr := users.DecryptTOTPSecret(u.TOTPSecret, stg.Key); derr == nil {
				if enc, eerr := users.EncryptTOTPSecret(legacy, users.DeriveTOTPKey(cred.Password, u.Salt)); eerr == nil {
					u.TOTPSecret = enc
				} else {
					u.TOTPEnabled, u.TOTPSecret = false, ""
				}
			} else {
				u.TOTPEnabled, u.TOTPSecret = false, ""
			}
		}
		if uerr := usr.Update(u, "Salt", "TOTPSecret", "TOTPEnabled"); uerr != nil {
			return nil, uerr
		}
	}

	// If the user has TOTP enabled, require a valid code on top of the
	// password. A missing code is reported as ErrTOTPRequired so the API can
	// answer 428 and let the client perform the second step; a wrong code
	// degrades to the same error as a wrong password to avoid user
	// enumeration.
	if u.TOTPEnabled && u.TOTPSecret != "" {
		secret, derr := users.DecryptTOTPSecret(u.TOTPSecret, users.DeriveTOTPKey(cred.Password, u.Salt))
		if derr != nil {
			return nil, os.ErrPermission
		}

		if cred.TOTP == "" {
			return nil, fberrors.ErrTOTPRequired
		}

		if !totp.Validate(cred.TOTP, secret) {
			return nil, os.ErrPermission
		}
	}

	// Admins derive and cache the JWT signing key. It depends on the
	// admin's username, password and salt; because the salt is per-user and
	// the passphrase is the admin's, the derived key is unique to this
	// deployment and changes whenever the admin's credentials change.
	if u.Perm.Admin {
		SetJWTKey(users.DeriveJWTKey(u.Username, cred.Password, u.Salt))
	}

	return u, nil
}

// LoginPage tells that json auth doesn't require a login page.
func (a JSONAuth) LoginPage() bool {
	return true
}

const reCaptchaAPI = "/recaptcha/api/siteverify"

// ReCaptcha identifies a recaptcha connection.
type ReCaptcha struct {
	Host   string `json:"host"`
	Key    string `json:"key"`
	Secret string `json:"secret"`
}

// Ok checks if a reCaptcha responde is correct.
func (r *ReCaptcha) Ok(response string) (bool, error) {
	body := url.Values{}
	body.Set("secret", r.Secret)
	body.Add("response", response)

	client := &http.Client{}

	resp, err := client.Post(
		r.Host+reCaptchaAPI,
		"application/x-www-form-urlencoded",
		strings.NewReader(body.Encode()),
	)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	var data struct {
		Success bool `json:"success"`
	}

	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return false, err
	}

	return data.Success, nil
}
