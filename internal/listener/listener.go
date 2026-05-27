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

// Package listener owns frontend listener lifecycle, transport preparation and
// graceful shutdown before protocol-specific handlers take over.
package listener

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/protocol/imap"
	runtimectl "github.com/croessner/nauthilus-director/internal/runtime"
	"go.uber.org/fx"
)

const (
	protocolIMAP      = "imap"
	tlsModeImplicit   = "implicit"
	tlsModeStartTLS   = "starttls"
	networkTCP        = "tcp"
	networkTCP4       = "tcp4"
	networkTCP6       = "tcp6"
	defaultTLSMinName = "TLS1.2"
)

// SessionHandler owns one accepted frontend stream.
type SessionHandler interface {
	Serve(ctx context.Context, conn net.Conn) error
}

// SessionHandlerFactory builds a protocol handler for one configured listener.
type SessionHandlerFactory func(options SessionOptions) SessionHandler

// NauthilusClientFactory builds the selected authority client for one listener.
type NauthilusClientFactory func(authority config.AuthorityConfig) (nauthilus.Authenticator, error)

// SessionOptions contains the typed listener values passed into a protocol handler.
type SessionOptions struct {
	ListenerName        string
	Config              config.ListenerConfig
	AuthorityTransport  string
	Timeouts            config.RuntimeTimeouts
	Security            config.DirectorSecurityConfig
	Authenticator       nauthilus.Authenticator
	BearerTokenMaxBytes int
	DirectorInstanceID  string
	DefaultTenant       string
	DefaultShard        string
	SessionLeaseTTL     time.Duration
	SessionIdleGrace    time.Duration
	FrontendTLSConfig   *tls.Config
	LocalSessions       *runtimectl.LocalSessionRegistry
	Observability       observability.Recorder
}

// ManagerOption customizes listener manager construction in tests and future assembly code.
type ManagerOption func(*managerOptions)

// Snapshot is a secret-safe summary of configured listener lifecycle state.
type Snapshot struct {
	Name          string
	Protocol      string
	ServiceName   string
	Network       string
	Address       string
	TLSMode       string
	ImplicitTLS   bool
	ProxyProtocol bool
	BoundAddress  string
}

// Manager starts, stops and tracks the configured IMAP-family frontend listeners.
type Manager struct {
	listeners       []*managedListener
	shutdownTimeout time.Duration
	startMu         sync.Mutex
	started         bool
}

type managerOptions struct {
	handlerFactory    SessionHandlerFactory
	authClientFactory NauthilusClientFactory
	listenConfig      net.ListenConfig
	localSessions     *runtimectl.LocalSessionRegistry
	observability     observability.Recorder
}

// Module wires the listener lifecycle into an Fx application.
func Module() fx.Option {
	return fx.Options(
		fx.Provide(NewManager),
		fx.Invoke(RegisterLifecycle),
	)
}

// RegisterLifecycle attaches listener startup and shutdown to the Fx lifecycle.
func RegisterLifecycle(lifecycle fx.Lifecycle, manager *Manager) {
	lifecycle.Append(fx.Hook{
		OnStart: manager.Start,
		OnStop:  manager.Stop,
	})
}

// NewManager creates a listener manager from the immutable typed config snapshot.
func NewManager(snapshot config.Snapshot, localSessions *runtimectl.LocalSessionRegistry) (*Manager, error) {
	return NewManagerWithConfig(snapshot.Config, WithLocalSessionRegistry(localSessions))
}

// NewManagerWithConfig creates a listener manager from typed config and optional test hooks.
func NewManagerWithConfig(cfg config.Config, opts ...ManagerOption) (*Manager, error) {
	cfg = cfg.Normalize()

	options := managerOptions{
		handlerFactory:    defaultSessionHandlerFactory,
		authClientFactory: defaultNauthilusClientFactory,
		observability:     observability.NoopRecorder{},
	}
	for _, opt := range opts {
		opt(&options)
	}

	listenerNames := sortedIMAPListenerNames(cfg.Director.Listeners)

	managed := make([]*managedListener, 0, len(listenerNames))
	for _, name := range listenerNames {
		listener := cfg.Director.Listeners[name]

		authority, ok := cfg.Auth.Authorities[listener.Authority]
		if !ok {
			return nil, errors.New("listener " + name + ": authority not found")
		}

		entry, err := newManagedListener(
			name,
			listener,
			authority,
			cfg.Runtime,
			cfg.Director.Security,
			cfg.Director.Affinity.ActiveUserPinning.Key.Tenant,
			cfg.Director.Routing.EffectiveDefaultShard(),
			cfg.Director.Affinity.ActiveUserPinning.IdleGrace.Std(),
			options,
		)
		if err != nil {
			return nil, err
		}

		managed = append(managed, entry)
	}

	return &Manager{
		listeners:       managed,
		shutdownTimeout: cfg.Runtime.Process.ShutdownTimeout.Std(),
	}, nil
}

// WithSessionHandlerFactory replaces the default IMAP session handler factory.
func WithSessionHandlerFactory(factory SessionHandlerFactory) ManagerOption {
	return func(options *managerOptions) {
		if factory != nil {
			options.handlerFactory = factory
		}
	}
}

// WithNauthilusClientFactory replaces authority client construction for tests or later app wiring.
func WithNauthilusClientFactory(factory NauthilusClientFactory) ManagerOption {
	return func(options *managerOptions) {
		if factory != nil {
			options.authClientFactory = factory
		}
	}
}

// WithObservabilityRecorder installs listener and session observability hooks.
func WithObservabilityRecorder(recorder observability.Recorder) ManagerOption {
	return func(options *managerOptions) {
		options.observability = observability.NormalizeRecorder(recorder)
	}
}

// WithLocalSessionRegistry installs the process-local active-session accelerator.
func WithLocalSessionRegistry(registry *runtimectl.LocalSessionRegistry) ManagerOption {
	return func(options *managerOptions) {
		options.localSessions = registry
	}
}

// Start binds all configured listeners and starts their accept loops.
func (m *Manager) Start(ctx context.Context) error {
	m.startMu.Lock()
	defer m.startMu.Unlock()

	if m.started {
		return nil
	}

	var started []*managedListener

	for _, entry := range m.listeners {
		if err := entry.start(ctx); err != nil {
			_ = stopManagedListeners(context.Background(), started)

			return err
		}

		started = append(started, entry)
	}

	m.started = true

	return nil
}

// Stop stops accepting new connections and drains active sessions until the shutdown deadline.
func (m *Manager) Stop(ctx context.Context) error {
	m.startMu.Lock()
	if !m.started {
		m.startMu.Unlock()

		return nil
	}

	m.started = false

	m.startMu.Unlock()

	stopCtx, cancel := contextWithShutdownTimeout(ctx, m.shutdownTimeout)
	defer cancel()

	return stopManagedListeners(stopCtx, m.listeners)
}

// Snapshots returns the configured listeners without exposing high-cardinality session data.
func (m *Manager) Snapshots() []Snapshot {
	snapshots := make([]Snapshot, 0, len(m.listeners))

	for _, entry := range m.listeners {
		snapshots = append(snapshots, entry.snapshot())
	}

	return snapshots
}

// BoundAddress returns the bound address for a started listener.
func (m *Manager) BoundAddress(name string) (string, bool) {
	for _, entry := range m.listeners {
		if entry.name == name && entry.boundAddress() != "" {
			return entry.boundAddress(), true
		}
	}

	return "", false
}

// ListenerNames returns configured IMAP listener names in deterministic order.
func (m *Manager) ListenerNames() []string {
	names := make([]string, 0, len(m.listeners))
	for _, entry := range m.listeners {
		names = append(names, entry.name)
	}

	return names
}

// defaultSessionHandlerFactory creates the first IMAP session boundary.
func defaultSessionHandlerFactory(options SessionOptions) SessionHandler {
	var (
		capabilities        []string
		authMechanisms      []string
		requireIDBeforeAuth bool
	)

	if options.Config.IMAP != nil {
		capabilities = options.Config.IMAP.Capabilities
		authMechanisms = options.Config.IMAP.AuthMechanisms
		requireIDBeforeAuth = options.Config.IMAP.RequireIDBeforeAuth
	}

	return imap.NewHandler(imap.SessionConfig{
		ListenerName:           options.ListenerName,
		AuthorityName:          options.Config.Authority,
		ServiceName:            options.Config.ServiceName,
		Network:                options.Config.Network,
		BackendPool:            options.Config.BackendPool,
		DirectorInstanceID:     options.DirectorInstanceID,
		DefaultTenant:          options.DefaultTenant,
		DefaultShard:           options.DefaultShard,
		TLSMode:                options.Config.TLS.Mode,
		Capabilities:           capabilities,
		AuthMechanisms:         authMechanisms,
		MaxBearerTokenBytes:    options.BearerTokenMaxBytes,
		RequireIDBeforeAuth:    requireIDBeforeAuth,
		SessionLeaseTTL:        options.SessionLeaseTTL,
		SessionIdleGrace:       options.SessionIdleGrace,
		FrontendTLSConfig:      options.FrontendTLSConfig,
		PreauthTimeout:         options.Timeouts.Preauth.Std(),
		AuthTimeout:            options.Timeouts.Auth.Std(),
		BackendConnectTimeout:  options.Timeouts.BackendConnect.Std(),
		ProxyIdleTimeout:       options.Timeouts.ProxyIdle.Std(),
		MaxPreauthLineBytes:    options.Security.MaxPreauthLineBytes,
		MaxPreauthLiteralBytes: options.Security.MaxPreauthLiteralBytes,
		Authenticator:          options.Authenticator,
		LocalSessions:          options.LocalSessions,
		Observability:          options.Observability,
	})
}

// defaultNauthilusClientFactory creates the configured Nauthilus authority transport.
func defaultNauthilusClientFactory(authority config.AuthorityConfig) (nauthilus.Authenticator, error) {
	return nauthilus.NewClient(authority, nauthilus.ClientOptions{})
}

// sortedIMAPListenerNames selects configured IMAP protocol listeners deterministically.
func sortedIMAPListenerNames(listeners map[string]config.ListenerConfig) []string {
	names := make([]string, 0, len(listeners))
	for name, entry := range listeners {
		if entry.Protocol == protocolIMAP {
			names = append(names, name)
		}
	}

	sort.Strings(names)

	return names
}

// stopManagedListeners stops all listeners and joins their accept/session loops.
func stopManagedListeners(ctx context.Context, listeners []*managedListener) error {
	var errs []error

	for _, entry := range listeners {
		if err := entry.stop(ctx); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// contextWithShutdownTimeout applies the configured shutdown timeout when Fx gives no deadline.
func contextWithShutdownTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}

	if _, ok := ctx.Deadline(); ok || timeout <= 0 {
		return ctx, func() {}
	}

	return context.WithTimeout(ctx, timeout)
}
