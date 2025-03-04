package main

import (
	"log/slog"
	"sync"

	"github.com/croessner/nauthilus-director/config"
	"github.com/croessner/nauthilus-director/context"
	"github.com/croessner/nauthilus-director/imap"
	"github.com/croessner/nauthilus-director/lmtp"
	"github.com/croessner/nauthilus-director/log"
	"github.com/croessner/nauthilus-director/version"
)

func runServer(ctx *context.Context, cfg *config.Config) {
	var wg sync.WaitGroup

	taskCount := 0
	logger := log.GetLogger(ctx)

	logger.Debug("Registered backend servers", slog.String("backends", cfg.String()))

	logger.Info("Starting server", slog.String("version", version.Version))

	for _, instance := range cfg.Server.Listen {
		if instance.ServiceName == "" {
			logger.Error("Service requires a name")

			return
		}

		switch instance.Kind {
		case "imap":
			wg.Add(1)
			taskCount++

			logger.Debug("Starting IMAP service", slog.String("instance", instance.String()))

			go imap.NewInstance(ctx, instance, &wg)
		case "lmtp":
			wg.Add(1)
			taskCount++

			logger.Debug("Starting LMTP service", slog.String("instance", instance.String()))

			go lmtp.NewInstance(ctx, instance, &wg)
		default:
			logger.Error("Unknown service kind", slog.String("kind", instance.Kind))
		}
	}

	if taskCount > 0 {
		wg.Wait()
		logger.Info("Server stopped", slog.String("version", version.Version))
	} else {
		logger.Error("No listen instances configured")
	}
}
