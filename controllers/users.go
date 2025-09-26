package controllers

import (
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/mbvlabs/mithlond-ce/config"
	"github.com/mbvlabs/mithlond-ce/database"
	"github.com/mbvlabs/mithlond-ce/models"
	"github.com/mbvlabs/mithlond-ce/router/cookies"
	"github.com/mbvlabs/mithlond-ce/router/routes"
	"github.com/mbvlabs/mithlond-ce/views"
)

type Users struct {
	cfg config.Config
	db  database.SQLite
}

func newUsers(cfg config.Config, db database.SQLite) Users {
	return Users{cfg, db}
}

func (r Users) Index(c echo.Context) error {
	page := int64(1)
	if p := c.QueryParam("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = int64(parsed)
		}
	}

	perPage := int64(25)
	if pp := c.QueryParam("per_page"); pp != "" {
		if parsed, err := strconv.Atoi(pp); err == nil && parsed > 0 &&
			parsed <= 100 {
			perPage = int64(parsed)
		}
	}

	usersList, err := models.PaginateUsers(
		c.Request().Context(),
		r.db.Conn(),
		page,
		perPage,
	)
	if err != nil {
		return render(c, views.InternalError())
	}

	return render(c, views.UserIndex(usersList.Users))
}

func (r Users) Show(c echo.Context) error {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return render(c, views.BadRequest())
	}

	user, err := models.FindUser(c.Request().Context(), r.db.Conn(), userID)
	if err != nil {
		return render(c, views.NotFound())
	}

	return render(c, views.UserShow(user))
}

func (r Users) New(c echo.Context) error {
	return render(c, views.UserNew())
}

type CreateUserFormPayload struct {
	Email           string `form:"email"`
	IsAdmin         int64  `form:"is_admin"`
	Password        string `form:"password"`
	ConfirmPassword string `form:"confirm_password"`
}

func (r Users) Create(c echo.Context) error {
	var payload CreateUserFormPayload
	if err := c.Bind(&payload); err != nil {
		slog.ErrorContext(
			c.Request().Context(),
			"could not parse CreateUserFormPayload",
			"error",
			err,
		)

		return render(c, views.NotFound())
	}

	data := models.CreateUserData{
		Email:   payload.Email,
		IsAdmin: payload.IsAdmin,
		Password: models.PasswordPair{
			Password:        payload.Password,
			ConfirmPassword: payload.ConfirmPassword,
		},
	}

	user, err := models.CreateUser(
		c.Request().Context(),
		r.db.Conn(),
		r.cfg.Auth.PasswordSalt,
		data,
	)
	if err != nil {
		if flashErr := cookies.AddFlash(c, cookies.FlashError, fmt.Sprintf("Failed to create user: %v", err)); flashErr != nil {
			return flashErr
		}
		return c.Redirect(http.StatusSeeOther, routes.UserNew.Path)
	}

	if flashErr := cookies.AddFlash(c, cookies.FlashSuccess, "User created successfully"); flashErr != nil {
		return render(c, views.InternalError())
	}

	return c.Redirect(http.StatusSeeOther, routes.UserShow.GetPath(user.ID))
}

func (r Users) Edit(c echo.Context) error {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return render(c, views.BadRequest())
	}

	user, err := models.FindUser(c.Request().Context(), r.db.Conn(), userID)
	if err != nil {
		return render(c, views.NotFound())
	}

	return render(c, views.UserEdit(user))
}

type UpdateUserFormPayload struct {
	Email    string `form:"email"`
	IsAdmin  int64  `form:"is_admin"`
	Password string `form:"password"`
}

func (r Users) Update(c echo.Context) error {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return render(c, views.BadRequest())
	}

	var payload UpdateUserFormPayload
	if err := c.Bind(&payload); err != nil {
		slog.ErrorContext(
			c.Request().Context(),
			"could not parse UpdateUserFormPayload",
			"error",
			err,
		)

		return render(c, views.NotFound())
	}

	data := models.UpdateUserData{
		ID:       userID,
		Email:    payload.Email,
		IsAdmin:  payload.IsAdmin,
		Password: []byte(payload.Password),
	}

	user, err := models.UpdateUser(
		c.Request().Context(),
		r.db.Conn(),
		data,
	)
	if err != nil {
		if flashErr := cookies.AddFlash(c, cookies.FlashError, fmt.Sprintf("Failed to update user: %v", err)); flashErr != nil {
			return render(c, views.InternalError())
		}
		return c.Redirect(
			http.StatusSeeOther,
			routes.UserEdit.GetPath(userID),
		)
	}

	if flashErr := cookies.AddFlash(c, cookies.FlashSuccess, "User updated successfully"); flashErr != nil {
		return render(c, views.InternalError())
	}

	return c.Redirect(http.StatusSeeOther, routes.UserShow.GetPath(user.ID))
}

func (r Users) Destroy(c echo.Context) error {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return render(c, views.BadRequest())
	}

	err = models.DestroyUser(c.Request().Context(), r.db.Conn(), userID)
	if err != nil {
		if flashErr := cookies.AddFlash(c, cookies.FlashError, fmt.Sprintf("Failed to delete user: %v", err)); flashErr != nil {
			return render(c, views.InternalError())
		}
		return c.Redirect(http.StatusSeeOther, routes.UserIndex.Path)
	}

	if flashErr := cookies.AddFlash(c, cookies.FlashSuccess, "User destroyed successfully"); flashErr != nil {
		return render(c, views.InternalError())
	}

	return c.Redirect(http.StatusSeeOther, routes.UserIndex.Path)
}
