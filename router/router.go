package router

import (
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"slices"
	"strings"

	"github.com/mbvlabs/mithlond-ce/config"
	"github.com/mbvlabs/mithlond-ce/controllers"
	"github.com/mbvlabs/mithlond-ce/router/cookies"
	"github.com/mbvlabs/mithlond-ce/router/routes"

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"

	echomw "github.com/labstack/echo/v4/middleware"
)

type Router struct {
	controllers controllers.Controllers
	Handler     *echo.Echo
}

func New(
	controllers controllers.Controllers,
	cfg config.Config,
) (*Router, error) {
	gob.Register(uuid.UUID{})
	gob.Register(cookies.FlashMessage{})

	router := echo.New()

	if cfg.App.Env != config.ProdEnvironment {
		router.Debug = true
	}

	authKey, err := hex.DecodeString(cfg.Auth.SessionKey)
	if err != nil {
		return nil, err
	}
	encKey, err := hex.DecodeString(cfg.Auth.SessionEncryptionKey)
	if err != nil {
		return nil, err
	}

	router.Use(
		session.Middleware(
			sessions.NewCookieStore(
				authKey,
				encKey,
			),
		),
		authOnly,
		registerAppContext,
		registerFlashMessagesContext,

		echomw.CSRFWithConfig(echomw.CSRFConfig{Skipper: func(c echo.Context) bool {
			return strings.HasPrefix(c.Request().URL.Path, routes.APIRoutePrefix) ||
				strings.HasPrefix(c.Request().URL.Path, routes.AssetsRoutePrefix)
		}, TokenLookup: "cookie:_csrf", CookiePath: "/", CookieDomain: func() string {
			if cfg.App.Env == config.ProdEnvironment {
				return cfg.App.Domain
			}

			return ""
		}(), CookieSecure: cfg.App.Env == config.ProdEnvironment, CookieHTTPOnly: true, CookieSameSite: http.SameSiteStrictMode}),

		echomw.Recover(),
		echomw.Logger(),
	)

	return &Router{
		controllers,
		router,
	}, nil
}

func (r *Router) SetupRoutes() *echo.Echo {
	registeredRoutes := []string{}
	controllersValue := reflect.ValueOf(r.controllers)

	for _, route := range routes.BuildRoutes {
		if registered := slices.Contains(registeredRoutes, route.Name); registered {
			panic(
				fmt.Sprintf(
					"%s is registered more than once",
					route.Name,
				),
			)
		}

		if route.Handler == "" || route.HandleMethod == "" {
			panic("Route must specify Handler and HandleMethod fields")
		}

		controllerField := controllersValue.FieldByName(route.Handler)
		if !controllerField.IsValid() {
			panic(
				fmt.Sprintf(
					"Controller field %s not found in controllers struct",
					route.Handler,
				),
			)
		}

		controller := controllerField.Interface()
		controllerFunc := getHandlerFunc(controller, route.HandleMethod)

		var middlewareFuncs []echo.MiddlewareFunc
		for _, mw := range route.Middleware {
			middlewareFuncs = append(middlewareFuncs, echo.MiddlewareFunc(mw))
		}

		switch route.Method {
		case http.MethodGet:
			registeredRoutes = append(registeredRoutes, route.Name)
			r.Handler.GET(route.Path, controllerFunc, middlewareFuncs...).Name = route.Name
		case http.MethodPost:
			registeredRoutes = append(registeredRoutes, route.Name)
			r.Handler.POST(route.Path, controllerFunc, middlewareFuncs...).Name = route.Name
		case http.MethodPut:
			registeredRoutes = append(registeredRoutes, route.Name)
			r.Handler.PUT(route.Path, controllerFunc, middlewareFuncs...).Name = route.Name
		case http.MethodDelete:
			registeredRoutes = append(registeredRoutes, route.Name)
			r.Handler.DELETE(route.Path, controllerFunc, middlewareFuncs...).Name = route.Name
		}
	}

	r.Handler.RouteNotFound(
		"/*",
		getHandlerFunc(r.controllers.Pages, "NotFound"),
	)

	return r.Handler
}

func getHandlerFunc(controller any, methodName string) echo.HandlerFunc {
	appType := reflect.TypeOf(controller)
	method, found := appType.MethodByName(methodName)
	if !found {
		panic(fmt.Sprintf("Controller method %s not found", methodName))
	}

	return func(c echo.Context) error {
		values := method.Func.Call([]reflect.Value{
			reflect.ValueOf(controller),
			reflect.ValueOf(c),
		})

		if len(values) != 1 {
			panic(
				fmt.Sprintf(
					"Controller method %s does not return exactly one value",
					methodName,
				),
			)
		}

		if values[0].IsNil() {
			return nil
		}

		return values[0].Interface().(error)
	}
}

func registerAppContext(
	next echo.HandlerFunc,
) echo.HandlerFunc {
	return func(c echo.Context) error {
		if strings.HasPrefix(c.Request().URL.Path, routes.AssetsRoutePrefix) ||
			strings.HasPrefix(c.Request().URL.Path, routes.APIRoutePrefix) {
			return next(c)
		}

		c.Set(string(cookies.AppKey), cookies.GetApp(c))

		return next(c)
	}
}

func registerFlashMessagesContext(
	next echo.HandlerFunc,
) echo.HandlerFunc {
	return func(c echo.Context) error {
		if strings.HasPrefix(c.Request().URL.Path, routes.AssetsRoutePrefix) ||
			strings.HasPrefix(c.Request().URL.Path, routes.APIRoutePrefix) {
			return next(c)
		}

		flashes, err := cookies.GetFlashes(c)
		if err != nil {
			slog.Error("Error getting flash messages from session", "error", err)
			return next(c)
		}

		c.Set(string(cookies.FlashKey), flashes)

		return next(c)
	}
}

func authOnly(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if strings.Contains(c.Request().URL.Path, routes.LoginPage.Path) ||
			strings.Contains(c.Request().URL.Path, routes.StoreAuthSession.Path) ||
			strings.Contains(c.Request().URL.Path, "favicon.ico") ||
			strings.Contains(c.Request().URL.Path, routes.AssetsRoutePrefix) {
			return next(c)
		}
		sess, err := session.Get(config.AuthenticatedSessionName, c)
		if err != nil {
			return next(c)
		}

		isAuth, _ := sess.Values[controllers.SessIsAuthenticated].(bool)
		if isAuth {
			return next(c)
		}

		return c.Redirect(http.StatusTemporaryRedirect, routes.LoginPage.Path)
	}
}
