package routes

import "net/http"

const (
	APIRoutePrefix = "/api"
	apiNamePrefix  = "api"
)

var apiRoutes = []Route{
	Health,
	UpdateApp,
}

var Health = Route{
	Name:         apiNamePrefix + ".health",
	Path:         APIRoutePrefix + "/health",
	Method:       http.MethodGet,
	Handler:      "API",
	HandleMethod: "Health",
}

var UpdateApp = Route{
	Name:         apiNamePrefix + ".update_app",
	Path:         APIRoutePrefix + "/update-app",
	Method:       http.MethodGet,
	Handler:      "Pages",
	HandleMethod: "UpdateApp",
}
