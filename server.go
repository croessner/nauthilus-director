package main

import (
	"log/slog"
	"sync"

	"github.com/croessner/nauthilus-director/config"
	"github.com/croessner/nauthilus-director/context"
	"github.com/croessner/nauthilus-director/imap"
	"github.com/croessner/nauthilus-director/log"
)

func runServer(ctx *context.Context, cfg *config.Config) {
	var wg sync.WaitGroup

	taskCount := 0
	logger := log.GetLogger(ctx)

	logger.Info("Starting server", slog.String("version", version))

	for _, instance := range cfg.Server.Listen {
		switch instance.Kind {

		case "imap":
			if instance.Name != "" {
				wg.Add(1)
				taskCount++

				go imap.NewInstance(ctx, instance, &wg)
			} else {
				logger.Error("IMAP service requires a name")

				return
			}
		}
	}

	if taskCount > 0 {
		wg.Wait()
		logger.Info("Server stopped", slog.String("version", version))
	} else {
		logger.Error("No listen instances configured")
	}
}
