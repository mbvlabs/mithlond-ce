package controllers

import (
	"github.com/mbvlabs/mithlond-ce/database"
	"net/http"

	"github.com/labstack/echo/v4"
)

type API struct {
	db database.SQLite
}

func newAPI(db database.SQLite) API {
	return API{db}
}

func (a API) Health(ctx echo.Context) error {
	return ctx.JSON(http.StatusOK, "app is healthy and running")
}
