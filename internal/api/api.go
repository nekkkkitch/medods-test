package api

import (
	"github.com/gofiber/contrib/swagger"
	"github.com/gofiber/fiber/v2"
)

type API struct {
	App     *fiber.App
	config  *Config
	service Service
}

type Config struct {
	Host string `yaml:"host"`
	Port string `yaml:"port"`
}

func New(cfg Config, service Service) (*API, error) {
	app := fiber.New()
	a := API{App: app, config: &cfg, service: service}
	app.Get("/tokens/+", a.CreateTokens)
	app.Get("/refresh", a.RefreshTokens)
	app.Get("/id", a.GetUUID)
	app.Delete("/tokens", a.KillTokens)
	app.Use(swagger.New(swagger.Config{
		Title:    "API",
		BasePath: "/",
		Path:     "docs",
		FilePath: "./swagger.json",
	}))
	app.Listen(cfg.Host + ":" + cfg.Port)
	return &a, nil
}

func (a *API) Listen() error {
	a.App.Listen(a.config.Host + ":" + a.config.Port)
	return nil
}
