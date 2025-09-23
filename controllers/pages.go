package controllers

import (
	"log/slog"
	"net"

	"github.com/mbvlabs/mithlond-ce/database"

	"github.com/mbvlabs/mithlond-ce/views"

	"github.com/a-h/templ"
	"github.com/labstack/echo/v4"
	"github.com/maypok86/otter"
)

type Pages struct {
	db    database.SQLite
	cache otter.CacheWithVariableTTL[string, templ.Component]
}

func newPages(
	db database.SQLite,
	cache otter.CacheWithVariableTTL[string, templ.Component],
) Pages {
	return Pages{db, cache}
}

func (p Pages) Home(c echo.Context) error {
	return render(c, views.Home())
}

func (p Pages) NotFound(c echo.Context) error {
	return render(c, views.NotFound())
}

func (p Pages) UpdateApp(c echo.Context) error {
	conn, err := net.Dial("unix", "/run/mithlond-update.sock")
	slog.ErrorContext(c.Request().Context(), "error dialing conn", "err", err)
	if err != nil {
		return err
	}

	if _, err := conn.Write([]byte("update")); err != nil {
		slog.ErrorContext(c.Request().Context(), "error writing to conn", "err", err)
		return err
	}

	if err := conn.Close(); err != nil {
		slog.ErrorContext(c.Request().Context(), "error closing conn", "err", err)
		return err
	}

	return nil
}
