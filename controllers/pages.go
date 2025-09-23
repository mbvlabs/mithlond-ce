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

func (p Pages) UpdateApp(c echo.Context) error {
	response := c.JSON(200, map[string]string{
		"message": "Update started successfully",
	})

	go func() {
		cmd := exec.Command("sudo", "/opt/mithlond/update-app.sh")
		cmd.Start()
	}()

	return response
}
