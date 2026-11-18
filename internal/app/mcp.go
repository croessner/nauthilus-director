// Copyright (C) 2026 Christian Rößner
//
// SPDX-License-Identifier: AGPL-3.0-only
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, version 3 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package app

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/rest/diagnostics"
	"github.com/croessner/nauthilus-director/internal/mcpserver"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/rest/adapters"
	"go.uber.org/fx"
)

// mcpHandle owns the optional MCP diagnostics endpoint and its serving lifetime.
type mcpHandle struct {
	server *mcpserver.Server
	stop   context.CancelFunc
	done   <-chan struct{}
}

// denyProtectedConfig refuses protected config reads; diagnostics never request them, and the
// MCP endpoint must not be able to reach them through any handler path.
type denyProtectedConfig struct{}

// AuthorizeProtectedConfig always refuses protected config values.
func (denyProtectedConfig) AuthorizeProtectedConfig(context.Context, adapters.ProtectedConfigRequest) (bool, error) {
	return false, nil
}

// provideMCPHandle builds the MCP diagnostics endpoint when it is enabled. It shares the control
// API handler collaborators, so tools answer exactly what the REST control API answers, and it
// validates bearer tokens through the configured authority's OIDC introspection.
func provideMCPHandle(
	cfg config.Config,
	options runtimeOptions,
	handlerOptions adapters.HandlerOptions,
	recorder observability.Recorder,
) (*mcpHandle, error) {
	settings := cfg.Runtime.Servers.MCP
	if !settings.Enabled {
		return &mcpHandle{}, nil
	}

	authority, ok := cfg.Auth.Authorities[strings.TrimSpace(settings.Authority)]
	if !ok {
		return nil, fmt.Errorf("mcp authority %q is not configured", settings.Authority)
	}

	if err := settings.IntrospectionClient.CheckMaterial(); err != nil {
		return nil, fmt.Errorf("mcp introspection client: %w", err)
	}

	introspector, err := nauthilus.NewOIDCIntrospector(settings.IntrospectionOIDC(authority.OIDC),
		&http.Client{Timeout: cfg.Runtime.Timeouts.Nauthilus.Std()})
	if err != nil {
		return nil, fmt.Errorf("mcp token introspection: %w", err)
	}

	handlerOptions.ProtectedConfigAuthorizer = denyProtectedConfig{}

	server, err := mcpserver.New(mcpserver.Deps{
		Settings:    settings,
		Tokens:      introspector,
		Diagnostics: diagnostics.NewExecutor(adapters.NewHandler(handlerOptions)),
		Recorder:    recorder,
		Issuer:      authority.OIDC.Issuer,
		Version:     options.Version,
	})
	if err != nil {
		return nil, fmt.Errorf("build mcp endpoint: %w", err)
	}

	return &mcpHandle{server: server}, nil
}

// Start binds the MCP listener and serves until Stop. The serving context is detached from the
// Fx start context, which ends when startup completes.
func (h *mcpHandle) Start(ctx context.Context) error {
	serveCtx, stop := context.WithCancel(context.WithoutCancel(ctx))

	done, err := h.server.Start(serveCtx)
	if err != nil {
		stop()

		return fmt.Errorf("start mcp listener: %w", err)
	}

	h.stop, h.done = stop, done

	return nil
}

// Stop stops accepting requests and waits until in-flight tool calls drained or ctx ends.
func (h *mcpHandle) Stop(ctx context.Context) error {
	if h.stop == nil {
		return nil
	}

	h.stop()

	select {
	case <-h.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// registerMCPLifecycle starts the MCP endpoint with the control listener when it is enabled.
func registerMCPLifecycle(lifecycle fx.Lifecycle, handle *mcpHandle) {
	if handle == nil || handle.server == nil {
		return
	}

	lifecycle.Append(fx.Hook{OnStart: handle.Start, OnStop: handle.Stop})
}
