package main

import (
	"flag"

	oapi "github.com/deepmap/oapi-codegen/pkg/middleware"
	"github.com/goharbor/harbor-scanner-fake/api"
	"github.com/goharbor/harbor-scanner-fake/pkg/config"
	"github.com/goharbor/harbor-scanner-fake/pkg/server"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	log "github.com/sirupsen/logrus"
)

//go:generate go run github.com/deepmap/oapi-codegen/cmd/oapi-codegen -generate types,server,spec -package api -o ./api/api.gen.go ./api/openapi.yaml

var (
	configPath string
	debug      bool
)

func init() {
	flag.StringVar(&configPath, "config", config.DefaultConfigPath, "Path to the configuration file")
	flag.StringVar(&configPath, "c", config.DefaultConfigPath, "Path to the configuration file (shorthand)")
	flag.BoolVar(&debug, "d", false, "set debug on")
}

func main() {
	flag.Parse()

	if debug {
		log.SetLevel(log.DebugLevel)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatal(err)
	}

	swagger, err := api.GetSwagger()
	if err != nil {
		log.Fatalf("failed to load swagger spec: %v\n", err)
	}

	swagger.Security = nil

	s := server.New(cfg)

	e := echo.New()

	if cfg.Server.AsscessLog {
		e.Use(middleware.Logger())
	}

	if cfg.Server.Timeout > 0 {
		e.Use(middleware.TimeoutWithConfig(middleware.TimeoutConfig{Timeout: cfg.Server.Timeout}))
	}

	e.Use(oapi.OapiRequestValidator(swagger))

	api.RegisterHandlersWithBaseURL(e, s, "/api/v1")

	e.Logger.Fatal(e.Start(cfg.Server.Address))
}
