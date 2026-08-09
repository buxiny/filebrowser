package fbhttp

import (
	"encoding/json"
	"net/http"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	fberrors "github.com/filebrowser/filebrowser/v2/errors"
	"github.com/filebrowser/filebrowser/v2/users"
)

// totpIssuer is displayed by authenticator apps when scanning the QR code.
const totpIssuer = "File Browser"

type totpEnrollResponse struct {
	Secret  string `json:"secret"`
	KeyURL  string `json:"keyUrl"`
	Issuer  string `json:"issuer"`
	Account string `json:"account"`
}

// totpEnrollHandler generates a fresh TOTP secret for a user. The secret is
// not persisted yet: the client must first display the otpauth URL (QR code),
// have the user register it in an authenticator app, and then confirm with
// totpVerifyHandler.
var totpEnrollHandler = withSelfOrAdmin(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	target, err := d.store.Users.Get(d.server.Root, d.server.FollowExternalSymlinks, d.raw.(uint))
	if err != nil {
		return errToStatus(err), err
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: target.Username,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return http.StatusInternalServerError, err
	}

	return renderJSON(w, r, totpEnrollResponse{
		Secret:  key.Secret(),
		KeyURL:  key.URL(),
		Issuer:  totpIssuer,
		Account: target.Username,
	})
})

type totpVerifyRequest struct {
	Secret string `json:"secret"`
	Code   string `json:"code"`
}

// totpVerifyHandler persists the pending TOTP secret once the user proves to
// hold a valid authenticator code generated from it.
var totpVerifyHandler = withSelfOrAdmin(func(_ http.ResponseWriter, r *http.Request, d *data) (int, error) {
	if r.Body == nil {
		return http.StatusBadRequest, fberrors.ErrEmptyRequest
	}

	var req totpVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return http.StatusBadRequest, err
	}

	if !totp.Validate(req.Code, req.Secret) {
		return http.StatusBadRequest, fberrors.ErrTOTPInvalid
	}

	encrypted, err := users.EncryptTOTPSecret(req.Secret, d.settings.Key)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	target, err := d.store.Users.Get(d.server.Root, d.server.FollowExternalSymlinks, d.raw.(uint))
	if err != nil {
		return errToStatus(err), err
	}

	target.TOTPSecret = encrypted
	target.TOTPEnabled = true

	if err := d.store.Users.Update(target, "TOTPSecret", "TOTPEnabled"); err != nil {
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
})

// totpDisableHandler removes the TOTP secret and disables two-factor auth for
// a user.
var totpDisableHandler = withSelfOrAdmin(func(_ http.ResponseWriter, _ *http.Request, d *data) (int, error) {
	target, err := d.store.Users.Get(d.server.Root, d.server.FollowExternalSymlinks, d.raw.(uint))
	if err != nil {
		return errToStatus(err), err
	}

	target.TOTPSecret = ""
	target.TOTPEnabled = false

	if err := d.store.Users.Update(target, "TOTPSecret", "TOTPEnabled"); err != nil {
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
})
