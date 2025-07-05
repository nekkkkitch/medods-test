package main

import (
	"log/slog"
	"medods_test/internal/api"
	"medods_test/internal/database"
	"medods_test/internal/jwt"
	"medods_test/internal/service"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	JWTConfig *jwt.Config      `yaml:"jwt"`
	APIConfig *api.Config      `yaml:"api"`
	DBConfig  *database.Config `yaml:"db"`
}

func readConfig(filename string) (*Config, error) {
	var cfg Config
	if err := cleanenv.ReadConfig(filename, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func main() {
	cfg, err := readConfig("./cfg.yml")
	if err != nil {
		slog.Error("Can't read config", "error", err)
	}
	slog.Info("Config file read successfully")

	jwt, err := jwt.New(cfg.JWTConfig)
	if err != nil {
		slog.Error("Failed to create jwt: " + err.Error())
	}
	slog.Info("JWT created successfully")

	db, err := database.New(cfg.DBConfig)
	if err != nil {
		slog.Error("Failed to connect to db, trying again: " + err.Error())
		for range 3 {
			time.Sleep(time.Minute)
			db, err = database.New(cfg.DBConfig)
			if err != nil {
				slog.Error("Failed to connect to db, trying again: " + err.Error())
			}
		}
	}
	slog.Info("DB connected successfully")

	tokensService, _ := service.New(db, &jwt)

	api, err := api.New(*cfg.APIConfig, *tokensService)
	if err != nil {
		slog.Error("Failed to host: " + err.Error())
	}

	err = api.Listen()
	if err != nil {
		slog.Error("Failed listen to api", "error", err)
	}
	slog.Info("api is listening")
}
