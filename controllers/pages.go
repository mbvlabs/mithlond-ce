package controllers

import (
	"os/exec"

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

// TODO send toast with result
func (p Pages) UpdateApp(c echo.Context) error {
	cmd := exec.Command(
		"sudo",
		"/usr/bin/systemctl",
		"start",
		"mithlond-update.service",
	)

	if err := cmd.Start(); err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to schedule update " + err.Error()})
	}

	return c.JSON(200, map[string]string{
		"message": "Update started successfully",
	})
}
