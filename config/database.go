package config

import (
	"github.com/caarlos0/env/v10"
)

type database struct {
	DatabaseKind string `env:"DB_KIND"`
	Path         string `env:"DB_PATH"`
}

func (d database) GetDatabaseURL() string {
	return d.Path
}

func newDatabaseConfig() database {
	dataCfg := database{}

	if err := env.ParseWithOptions(&dataCfg, env.Options{
		RequiredIfNoDef: true,
	}); err != nil {
		panic(err)
	}

	return dataCfg
}
