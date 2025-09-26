package controllers

import (
	"log/slog"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/mbvlabs/mithlond-ce/config"
	"github.com/mbvlabs/mithlond-ce/database"
	"github.com/mbvlabs/mithlond-ce/models"
	"github.com/mbvlabs/mithlond-ce/router/routes"
	"github.com/mbvlabs/mithlond-ce/views"
)

type Sessions struct {
	cfg config.Config
	db  database.SQLite
}

func newSessions(
	cfg config.Config,
	db database.SQLite,
) Sessions {
	return Sessions{cfg, db}
}

func (a Sessions) New(c echo.Context) error {
	return render(c, views.LoginPage())
}

type StoreAuthenticatedSessionPayload struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	RememberMe string `json:"remember_me"`
}

func (a Sessions) Create(c echo.Context) error {
	var payload StoreAuthenticatedSessionPayload
	if err := c.Bind(&payload); err != nil {
		return getSSE(c).PatchElementTempl(
			views.LoginRes(),
		)
	}

	user, err := models.FindUserByEmail(c.Request().Context(), a.db.Conn(), payload.Email)
	if err != nil {
		return getSSE(c).PatchElementTempl(
			views.LoginRes(),
		)
	}

	if err := user.ValidatePassword(payload.Password, a.cfg.Auth.PasswordSalt); err != nil {
		return getSSE(c).PatchElementTempl(
			views.LoginRes(),
		)
	}

	if err := createAuthSession(
		c, payload.RememberMe == "on", user); err != nil {
		return getSSE(c).PatchElementTempl(
			views.LoginRes(),
		)
	}

	return getSSE(c).Redirect(routes.HomePage.Path)
}

const (
	oneWeekInSeconds    = 604800
	SessIsAuthenticated = "is_authenticated"
	SessUserID          = "user_id"
	SessUserEmail       = "user_email"
	SessIsAdmin         = "is_admin"
)

func createAuthSession(
	c echo.Context,
	extend bool,
	user models.User,
) error {
	slog.Info("config.AuthenticatedSessionName", "name", config.AuthenticatedSessionName)
	sess, err := session.Get(config.AuthenticatedSessionName, c)
	if err != nil {
		slog.Error("error getting session", "error", err)
		return err
	}

	// if extend {
	// 	maxAge := oneWeekInSeconds
	// 	maxAge = oneWeekInSeconds * 2
	// }

	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   oneWeekInSeconds,
		HttpOnly: true,
	}
	sess.Values[SessIsAuthenticated] = true
	sess.Values[SessUserID] = user.ID
	sess.Values[SessUserEmail] = user.Email
	sess.Values[SessIsAdmin] = user.IsAdmin

	if err := sess.Save(c.Request(), c.Response()); err != nil {
		slog.Error("error saving session", "error", err)
		return err
	}

	return nil
}

func (a Sessions) Destroy(c echo.Context) error {
	// if err := destroyAuthSession(c); err != nil {
	// 	return views.InternalError().Render(renderArgs(c))
	// }
	//
	// return redirectHx(
	// 	c.Response().Writer,
	// 	routes.LoginPage.Path,
	// )

	return nil
}
