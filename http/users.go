package fbhttp

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	fbAuth "github.com/filebrowser/filebrowser/v2/auth"
	fberrors "github.com/filebrowser/filebrowser/v2/errors"
	"github.com/filebrowser/filebrowser/v2/users"
)

var (
	NonModifiableFieldsForNonAdmin = []string{"Username", "Scope", "LockPassword", "Perm", "Commands", "Rules"}
)

type modifyUserRequest struct {
	modifyRequest
	Data *users.User `json:"data"`
}

func getUserID(r *http.Request) (uint, error) {
	vars := mux.Vars(r)
	i, err := strconv.ParseUint(vars["id"], 10, 0)
	if err != nil {
		return 0, err
	}
	return uint(i), err
}

func getUser(_ http.ResponseWriter, r *http.Request) (*modifyUserRequest, error) {
	if r.Body == nil {
		return nil, fberrors.ErrEmptyRequest
	}

	req := &modifyUserRequest{}
	err := json.NewDecoder(r.Body).Decode(req)
	if err != nil {
		return nil, err
	}

	if req.What != "user" {
		return nil, fberrors.ErrInvalidDataType
	}

	return req, nil
}

func withSelfOrAdmin(fn handleFunc) handleFunc {
	return withUser(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		id, err := getUserID(r)
		if err != nil {
			return http.StatusInternalServerError, err
		}

		if d.user.ID != id && !d.user.Perm.Admin {
			return http.StatusForbidden, nil
		}

		d.raw = id
		return fn(w, r, d)
	})
}

var usersGetHandler = withAdmin(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	users, err := d.store.Users.Gets(d.server.Root, d.server.FollowExternalSymlinks)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	for _, u := range users {
		u.Password = ""
		u.TOTPSecret = ""
		u.Salt = ""
	}

	sort.Slice(users, func(i, j int) bool {
		return users[i].ID < users[j].ID
	})

	return renderJSON(w, r, users)
})

var userGetHandler = withSelfOrAdmin(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	u, err := d.store.Users.Get(d.server.Root, d.server.FollowExternalSymlinks, d.raw.(uint))
	if errors.Is(err, fberrors.ErrNotExist) {
		return http.StatusNotFound, err
	}

	if err != nil {
		return http.StatusInternalServerError, err
	}

	u.Password = ""
	u.TOTPSecret = ""
	u.Salt = ""
	if !d.user.Perm.Admin {
		u.Scope = ""
	}
	return renderJSON(w, r, u)
})

var userDeleteHandler = withSelfOrAdmin(func(_ http.ResponseWriter, r *http.Request, d *data) (int, error) {
	if r.Body == nil {
		return http.StatusBadRequest, fberrors.ErrEmptyRequest
	}

	var body struct {
		CurrentPassword string `json:"current_password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return http.StatusBadRequest, err
	}

	if d.settings.AuthMethod == fbAuth.MethodJSONAuth {
		if !users.CheckPwd(body.CurrentPassword, d.user.Password) {
			return http.StatusBadRequest, fberrors.ErrCurrentPasswordIncorrect
		}
	}

	err := d.store.Users.Delete(d.raw.(uint))
	if err != nil {
		return errToStatus(err), err
	}

	return http.StatusOK, nil
})

var userPostHandler = withAdmin(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	req, err := getUser(w, r)
	if err != nil {
		return http.StatusBadRequest, err
	}

	if d.settings.AuthMethod == fbAuth.MethodJSONAuth {
		if !users.CheckPwd(req.CurrentPassword, d.user.Password) {
			return http.StatusBadRequest, fberrors.ErrCurrentPasswordIncorrect
		}
	}

	if len(req.Which) != 0 {
		return http.StatusBadRequest, nil
	}

	if req.Data.Password == "" {
		return http.StatusBadRequest, fberrors.ErrEmptyPassword
	}

	req.Data.Password, err = users.ValidateAndHashPwd(req.Data.Password, d.settings.MinimumPasswordLength)
	if err != nil {
		return http.StatusBadRequest, err
	}

	if req.Data.Perm.Share && !req.Data.Perm.Download {
		return http.StatusBadRequest, fberrors.ErrShareRequiresDownload
	}

	userHome, err := d.settings.MakeUserDir(req.Data.Username, req.Data.Scope, d.server.Root)
	if err != nil {
		log.Printf("create user: failed to mkdir user home dir: [%s]", userHome)
		return http.StatusInternalServerError, err
	}
	req.Data.Scope = userHome
	log.Printf("user: %s, home dir: [%s].", req.Data.Username, userHome)

	err = d.store.Users.Save(req.Data)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	w.Header().Set("Location", "/settings/users/"+strconv.FormatUint(uint64(req.Data.ID), 10))
	return http.StatusCreated, nil
})

var userPutHandler = withSelfOrAdmin(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	req, err := getUser(w, r)
	if err != nil {
		return http.StatusBadRequest, err
	}

	if d.settings.AuthMethod == fbAuth.MethodJSONAuth {
		var sensibleFields = map[string]struct{}{
			"all":          {},
			"username":     {},
			"password":     {},
			"scope":        {},
			"lockPassword": {},
			"commands":     {},
			"perm":         {},
		}

		for _, field := range req.Which {
			if _, ok := sensibleFields[strings.ToLower(field)]; ok {
				if !users.CheckPwd(req.CurrentPassword, d.user.Password) {
					return http.StatusBadRequest, fberrors.ErrCurrentPasswordIncorrect
				}
				break
			}
		}
	}

	if req.Data.ID != d.raw.(uint) {
		return http.StatusBadRequest, nil
	}

	// Load the current target user: its salt and TOTP state drive the
	// credential-change bookkeeping below, and an admin's username/password
	// changes invalidate the derived JWT key.
	target, err := d.store.Users.Get(d.server.Root, d.server.FollowExternalSymlinks, d.raw.(uint))
	if err != nil {
		return http.StatusInternalServerError, err
	}

	// Detect a password change while the new plaintext is still available,
	// before the handler hashes it.
	changesPassword := false
	plainNewPwd := ""
	if len(req.Which) == 0 || (len(req.Which) == 1 && strings.EqualFold(req.Which[0], "all")) {
		changesPassword = req.Data.Password != ""
		plainNewPwd = req.Data.Password
	} else {
		for _, f := range req.Which {
			if strings.EqualFold(f, "password") {
				changesPassword = true
				plainNewPwd = req.Data.Password
			}
		}
	}
	changesUsername := false
	if len(req.Which) == 0 || (len(req.Which) == 1 && strings.EqualFold(req.Which[0], "all")) {
		changesUsername = req.Data.Username != "" && req.Data.Username != target.Username
	} else {
		for _, f := range req.Which {
			if strings.EqualFold(f, "username") {
				changesUsername = req.Data.Username != "" && req.Data.Username != target.Username
			}
		}
	}

	for _, field := range req.Which {
		if strings.ToLower(field) == "perm" || strings.ToLower(field) == "all" {
			if req.Data.Perm.Share && !req.Data.Perm.Download {
				return http.StatusBadRequest, fberrors.ErrShareRequiresDownload
			}
		}
	}

	if len(req.Which) == 0 || (len(req.Which) == 1 && req.Which[0] == "all") {
		if !d.user.Perm.Admin {
			return http.StatusForbidden, nil
		}

		if req.Data.Password != "" {
			req.Data.Password, err = users.ValidateAndHashPwd(req.Data.Password, d.settings.MinimumPasswordLength)
			if err != nil {
				return http.StatusBadRequest, err
			}
		} else {
			req.Data.Password = target.Password
		}

		req.Which = []string{}
	}

	for k, v := range req.Which {
		v = cases.Title(language.English, cases.NoLower).String(v)
		req.Which[k] = v

		if v == "Password" {
			if !d.user.Perm.Admin && d.user.LockPassword {
				return http.StatusForbidden, nil
			}

			req.Data.Password, err = users.ValidateAndHashPwd(req.Data.Password, d.settings.MinimumPasswordLength)
			if err != nil {
				return http.StatusBadRequest, err
			}
		}

		for _, f := range NonModifiableFieldsForNonAdmin {
			if !d.user.Perm.Admin && v == f {
				return http.StatusForbidden, nil
			}
		}
	}

	// Credential-change bookkeeping.
	if changesPassword {
		if d.user.ID == target.ID {
			// Changing your own password: re-encrypt the TOTP secret with a
			// key derived from the new password so two-factor stays usable.
			// The old plaintext (req.CurrentPassword) was verified above for
			// JSON auth, which is the only path that can re-derive the old
			// key.
			if target.TOTPEnabled && target.TOTPSecret != "" {
				oldPlain := req.CurrentPassword
				if d.settings.AuthMethod == fbAuth.MethodJSONAuth && oldPlain != "" && users.CheckPwd(oldPlain, target.Password) {
					if secret, derr := users.DecryptTOTPSecret(target.TOTPSecret, users.DeriveTOTPKey(oldPlain, target.Salt)); derr == nil {
						if enc, eerr := users.EncryptTOTPSecret(secret, users.DeriveTOTPKey(plainNewPwd, target.Salt)); eerr == nil {
							req.Data.TOTPSecret = enc
							req.Data.TOTPEnabled = true
						}
					}
				}
				// If the old key could not be derived (non-JSON auth), the
				// secret is unrecoverable: TOTP must be re-enrolled.
				if req.Data.TOTPSecret == "" {
					req.Data.TOTPEnabled = false
					req.Data.TOTPSecret = ""
				}
				req.Which = append(req.Which, "TOTPSecret", "TOTPEnabled")
			}
		} else {
			// Admin resetting another user's password: the old password (and
			// thus the old encryption key) is unknown, so the TOTP secret
			// cannot be migrated. Disable TOTP; the user must re-enroll.
			if target.TOTPEnabled {
				req.Data.TOTPEnabled = false
				req.Data.TOTPSecret = ""
				req.Which = append(req.Which, "TOTPSecret", "TOTPEnabled")
			}
		}
	}

	// The JWT signing key is derived from the admin's username+password;
	// changing either invalidates every outstanding token.
	if target.Perm.Admin && (changesPassword || changesUsername) {
		fbAuth.ClearJWTKey()
	}

	err = d.store.Users.Update(req.Data, req.Which...)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
})
