package imap

import (
	"log/slog"
	"os"
	"sync"

	"github.com/croessner/nauthilus-director/auth"
	"github.com/croessner/nauthilus-director/config"
	"github.com/croessner/nauthilus-director/context"
	"github.com/croessner/nauthilus-director/log"
)

func NewInstance(ctx *context.Context, instance config.Listen, wg *sync.WaitGroup) {
	logger := log.GetLogger(ctx)
	authenticator := &auth.NauthilusAuthenticator{}
	// TODO: Replace with Nauthilus authenticator
	// TODO: IMPORTANT: Make Authenticator part of a session!
	proxy := NewProxy(ctx, instance, authenticator, wg)

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
