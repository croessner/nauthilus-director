package lmtp

import (
	"log/slog"
	"os"
	"sync"

	"github.com/croessner/nauthilus-director/config"
	"github.com/croessner/nauthilus-director/context"
	"github.com/croessner/nauthilus-director/log"
	"github.com/croessner/nauthilus-director/proxy"
)

func NewInstance(ctx *context.Context, instance config.Listen, nauthilus config.Nauthilus, wg *sync.WaitGroup) {
	logger := log.GetLogger(ctx)
	lmtpProxy := proxy.NewProxy(ctx, instance, nauthilus, wg)

	if lmtpProxy == nil {
		logger.Error("Error creating proxy")

		os.Exit(1)
	}

	defer wg.Done()

	if err := lmtpProxy.Start(instance, Handler); err != nil {
		logger.Error("Could not start proxy", slog.String(log.KeyError, err.Error()))
		os.Exit(1)
	}
}
