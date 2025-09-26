package config

import (
	"fmt"
	"strings"
)

type Config struct {
	App  app
	Auth auth
	DB   database
}

func NewConfig() Config {
	app := newAppConfig()

	AuthenticatedSessionName = fmt.Sprintf(
		"ua-%s-%s",
		strings.ToLower(app.ProjectName),
		strings.ToLower(app.Env),
	)

	return Config{
		App:  app,
		Auth: newAuthConfig(),
		DB:   newDatabaseConfig(),
	}
}
