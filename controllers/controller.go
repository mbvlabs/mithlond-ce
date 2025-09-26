package controllers

import (
	"context"
	"net/http"

	"github.com/mbvlabs/mithlond-ce/config"
	"github.com/mbvlabs/mithlond-ce/database"
	"github.com/mbvlabs/mithlond-ce/router/cookies"
	"github.com/starfederation/datastar-go/datastar"

	"github.com/a-h/templ"
	"github.com/labstack/echo/v4"
	"github.com/maypok86/otter"
)

type Controllers struct {
	Assets   Assets
	API      API
	Config   config.Config
	Pages    Pages
	Users    Users
	Sessions Sessions
}

func New(
	config config.Config,
	db database.SQLite,
) (Controllers, error) {
	cacheBuilder, err := otter.NewBuilder[string, templ.Component](20)
	if err != nil {
		return Controllers{}, err
	}

	pageCacher, err := cacheBuilder.WithVariableTTL().Build()
	if err != nil {
		return Controllers{}, err
	}

	assets := newAssets(config)
	pages := newPages(db, pageCacher)
	api := newAPI(db)
	users := newUsers(config, db)
	sessions := newSessions(config, db)

	return Controllers{
		assets,
		api,
		config,
		pages,
		users,
		sessions,
	}, nil
}

func render(ctx echo.Context, t templ.Component) error {
	buf := templ.GetBuffer()
	defer templ.ReleaseBuffer(buf)

	appCtx := ctx.Get(string(cookies.AppKey))
	withAppCtx := context.WithValue(
		ctx.Request().Context(),
		cookies.AppKey,
		appCtx,
	)

	flashCtx := ctx.Get(string(cookies.FlashKey))
	withFlashCtx := context.WithValue(
		withAppCtx,
		cookies.FlashKey,
		flashCtx,
	)

	if err := t.Render(withFlashCtx, buf); err != nil {
		return err
	}

	return ctx.HTML(http.StatusOK, buf.String())
}

func getSSE(c echo.Context) *datastar.ServerSentEventGenerator {
	return datastar.NewSSE(c.Response(), c.Request())
}
