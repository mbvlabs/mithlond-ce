package routes

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/mbvlabs/mithlond-ce/router/middleware"
)

const sessionNamePrefix = "auth"

var SessionRoutes = []Route{
	LoginPage,
	StoreAuthSession,
	DestroyAuthSession,
}

var LoginPage = Route{
	Name:         sessionNamePrefix + ".login_page",
	Path:         "/sessions/new",
	Method:       http.MethodGet,
	Handler:      "Sessions",
	HandleMethod: "New",
}

var StoreAuthSession = Route{
	Name:         sessionNamePrefix + ".store_auth_session",
	Path:         "/sessions",
	Method:       http.MethodPost,
	Handler:      "Sessions",
	HandleMethod: "Create",
	Middleware: []func(next echo.HandlerFunc) echo.HandlerFunc{
		middleware.LoginRateLimiter(),
	},
}

var DestroyAuthSession = Route{
	Name:         sessionNamePrefix + ".destroy_auth_session",
	Path:         "/sessions",
	Method:       http.MethodDelete,
	Handler:      "Sessions",
	HandleMethod: "Destroy",
}
