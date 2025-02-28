package imap

import (
	"log/slog"
	"os"
	"sync"

	"github.com/croessner/nauthilus-director/config"
	"github.com/croessner/nauthilus-director/context"
	"github.com/croessner/nauthilus-director/log"
)

func NewInstance(ctx *context.Context, instance config.Listen, wg *sync.WaitGroup) {
	logger := log.GetLogger(ctx)
	proxy := NewProxy(ctx, instance, wg)

	if proxy == nil {
		logger.Error("Error creating proxy")

		os.Exit(1)
	}

	defer wg.Done()

	if err := proxy.Start(instance); err != nil {
		logger.Error("Could not start proxy", slog.String(log.KeyError, err.Error()))
		os.Exit(1)
	}
}
