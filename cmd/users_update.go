package cmd

import (
	"github.com/spf13/cobra"

	fbAuth "github.com/filebrowser/filebrowser/v2/auth"
	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/users"
)

func init() {
	usersCmd.AddCommand(usersUpdateCmd)

	usersUpdateCmd.Flags().StringP("password", "p", "", "new password")
	usersUpdateCmd.Flags().StringP("username", "u", "", "new username")
	addUserFlags(usersUpdateCmd.Flags())
}

var usersUpdateCmd = &cobra.Command{
	Use:   "update <id|username>",
	Short: "Updates an existing user",
	Long: `Updates an existing user. Set the flags for the
options you want to change.`,
	Args: cobra.ExactArgs(1),
	RunE: withStore(func(cmd *cobra.Command, args []string, st *store) error {
		flags := cmd.Flags()
		username, id := parseUsernameOrID(args[0])
		password, err := flags.GetString("password")
		if err != nil {
			return err
		}

		newUsername, err := flags.GetString("username")
		if err != nil {
			return err
		}

		s, err := st.Settings.Get()
		if err != nil {
			return err
		}

		var (
			user *users.User
		)
		if id != 0 {
			user, err = st.Users.Get("", false, id)
		} else {
			user, err = st.Users.Get("", false, username)
		}
		if err != nil {
			return err
		}

		defaults := settings.UserDefaults{
			Scope:                 user.Scope,
			Locale:                user.Locale,
			ViewMode:              user.ViewMode,
			SingleClick:           user.SingleClick,
			RedirectAfterCopyMove: user.RedirectAfterCopyMove,
			Perm:                  user.Perm,
			Sorting:               user.Sorting,
			Commands:              user.Commands,
		}

		err = getUserDefaults(flags, &defaults, false)
		if err != nil {
			return err
		}

		user.Scope = defaults.Scope
		user.Locale = defaults.Locale
		user.ViewMode = defaults.ViewMode
		user.SingleClick = defaults.SingleClick
		user.RedirectAfterCopyMove = defaults.RedirectAfterCopyMove
		user.Perm = defaults.Perm
		user.Commands = defaults.Commands
		user.Sorting = defaults.Sorting
		user.LockPassword, err = flags.GetBool("lockPassword")
		if err != nil {
			return err
		}

		user.DateFormat, err = flags.GetBool("dateFormat")
		if err != nil {
			return err
		}

		user.HideDotfiles, err = flags.GetBool("hideDotfiles")
		if err != nil {
			return err
		}

		if newUsername != "" {
			user.Username = newUsername
		}

		credentialsChanged := false
		if password != "" {
			user.Password, err = users.ValidateAndHashPwd(password, s.MinimumPasswordLength)
			if err != nil {
				return err
			}
			credentialsChanged = true
		}

		if newUsername != "" && newUsername != user.Username {
			credentialsChanged = true
		}

		// The TOTP secret is encrypted with a key derived from the user's
		// password. The CLI does not have the old plaintext password, so a
		// changed password makes the existing secret undecryptable: disable
		// TOTP so the user re-enrolls, mirroring the API behavior for admin
		// password resets.
		if credentialsChanged && user.TOTPEnabled {
			user.TOTPEnabled = false
			user.TOTPSecret = ""
		}

		err = st.Users.Update(user)
		if err != nil {
			return err
		}

		// An admin credential change invalidates every derived JWT key.
		if credentialsChanged && user.Perm.Admin {
			fbAuth.ClearJWTKey()
		}

		printUsers([]*users.User{user})
		return nil
	}, storeOptions{}),
}
