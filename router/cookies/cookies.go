package cookies

import (
	"context"

	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/mbvlabs/mithlond-ce/config"
)

var AppKey appKey = "app_context"

type appKey string

const (
	isAuthenticated = "is_authenticated"
)

type App struct {
	echo.Context
	IsAuthenticated bool
	FlashMessages   []FlashMessage
}

func GetAppCtx(ctx context.Context) App {
	appCtx, ok := ctx.Value(AppKey).(App)
	if !ok {
		return App{}
	}

	return appCtx
}

func GetApp(c echo.Context) App {
	sess, err := session.Get(config.AuthenticatedSessionName, c)
	if err != nil {
		return App{}
	}
	app := App{Context: c}

	if _, ok := sess.Values[isAuthenticated].(bool); ok {
		app.IsAuthenticated = true
	}

	return app
}
