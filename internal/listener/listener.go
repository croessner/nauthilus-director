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
	"errors"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/protocol/imap"
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

// SessionOptions contains the typed listener values passed into a protocol handler.
type SessionOptions struct {
	ListenerName        string
	Config              config.ListenerConfig
	Timeouts            config.RuntimeTimeouts
	Security            config.DirectorSecurityConfig
	BearerTokenMaxBytes int
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
	handlerFactory SessionHandlerFactory
	listenConfig   net.ListenConfig
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
func NewManager(snapshot config.Snapshot) (*Manager, error) {
	return NewManagerWithConfig(snapshot.Config)
}

// NewManagerWithConfig creates a listener manager from typed config and optional test hooks.
func NewManagerWithConfig(cfg config.Config, opts ...ManagerOption) (*Manager, error) {
	options := managerOptions{
		handlerFactory: defaultSessionHandlerFactory,
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

		entry, err := newManagedListener(name, listener, authority, cfg.Runtime, cfg.Director.Security, options)
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
		ServiceName:            options.Config.ServiceName,
		Network:                options.Config.Network,
		TLSMode:                options.Config.TLS.Mode,
		Capabilities:           capabilities,
		AuthMechanisms:         authMechanisms,
		MaxBearerTokenBytes:    options.BearerTokenMaxBytes,
		RequireIDBeforeAuth:    requireIDBeforeAuth,
		PreauthTimeout:         options.Timeouts.Preauth.Std(),
		AuthTimeout:            options.Timeouts.Auth.Std(),
		BackendConnectTimeout:  options.Timeouts.BackendConnect.Std(),
		ProxyIdleTimeout:       options.Timeouts.ProxyIdle.Std(),
		MaxPreauthLineBytes:    options.Security.MaxPreauthLineBytes,
		MaxPreauthLiteralBytes: options.Security.MaxPreauthLiteralBytes,
	})
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
