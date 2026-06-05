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

// Package pop3 owns POP3 protocol behavior after the generic listener accepts a stream.
//
//nolint:wsl_v5 // Handler setup keeps immutable listener defaults in one auditable block.
package pop3

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/placement"
	"github.com/croessner/nauthilus-director/internal/proxy"
	"github.com/croessner/nauthilus-director/internal/routing"
	runtimectl "github.com/croessner/nauthilus-director/internal/runtime"
)

// ErrBackendReadinessUnavailable reports that POP3 backend/proxy readiness failed after frontend auth.
var ErrBackendReadinessUnavailable = errors.New("pop3: backend readiness continuation unavailable")

// SessionConfig contains immutable listener settings for one POP3 handler.
type SessionConfig struct {
	ListenerName           string
	AuthorityName          string
	AuthorityTransport     string
	ServiceName            string
	Network                string
	BackendPool            string
	DirectorInstanceID     string
	DefaultTenant          string
	DefaultShard           string
	TLSMode                string
	AuthMechanisms         []string
	Capabilities           []string
	PreauthTimeout         time.Duration
	AuthTimeout            time.Duration
	BackendConnectTimeout  time.Duration
	ProxyIdleTimeout       time.Duration
	SessionLeaseTTL        time.Duration
	SessionIdleGrace       time.Duration
	BackendRetentionTTL    time.Duration
	MaxPreauthLineBytes    int
	MaxPreauthLiteralBytes int
	MaxBearerTokenBytes    int
	FrontendTLSConfig      *tls.Config
	Authenticator          nauthilus.Authenticator
	RoutingResolver        routing.RoutingResolver
	PlacementService       placement.SessionPlacer
	PlacementGate          runtimectl.PlacementGate
	BackendConnector       BackendConnector
	ProxyRunner            proxy.Runner
	LocalSessions          *runtimectl.LocalSessionRegistry
	Observability          observability.Recorder
}

// Handler owns one configured POP3 listener's session construction policy.
type Handler struct {
	config SessionConfig
}

// NewHandler creates a POP3 handler from typed listener configuration.
func NewHandler(config SessionConfig) *Handler {
	config.AuthMechanisms = cloneStrings(config.AuthMechanisms)
	config.Capabilities = cloneStrings(config.Capabilities)
	config.FrontendTLSConfig = cloneTLSConfig(config.FrontendTLSConfig)
	if config.ProxyRunner == nil {
		config.ProxyRunner = proxy.NewPipe()
	}

	return &Handler{config: config}
}

// Config returns a detached copy of the handler's immutable config.
func (h *Handler) Config() SessionConfig {
	if h == nil {
		return SessionConfig{}
	}

	config := h.config
	config.AuthMechanisms = cloneStrings(config.AuthMechanisms)
	config.Capabilities = cloneStrings(config.Capabilities)
	config.FrontendTLSConfig = cloneTLSConfig(config.FrontendTLSConfig)

	return config
}

// Serve accepts one frontend connection and runs the bounded POP3 authorization-state machine.
func (h *Handler) Serve(ctx context.Context, conn net.Conn) error {
	session, err := NewSession(h.config, conn)
	if err != nil {
		return err
	}

	return session.Serve(ctx)
}

// cloneStrings detaches mutable string slices from caller-owned config.
func cloneStrings(values []string) []string {
	cloned := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			cloned = append(cloned, value)
		}
	}

	return cloned
}
