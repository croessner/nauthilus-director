package main

import (
	"log/slog"
	"os"

	"github.com/croessner/nauthilus-director/config"
	"github.com/croessner/nauthilus-director/context"
	"github.com/croessner/nauthilus-director/log"
)

var version = "dev"

func main() {
	ctx := context.NewContext()
	cfg, err := config.NewConfig()

	log.SetupLogging(ctx, cfg)

	if err != nil {
		log.GetLogger(ctx).Error("Could not load config", slog.String(log.Error, err.Error()))

		os.Exit(1)
	}

	runServer(ctx, cfg)
}
