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
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/observability"
	runtimectl "github.com/croessner/nauthilus-director/internal/runtime"
	"go.uber.org/fx"
)

const (
	protocolIMAP      = "imap"
	protocolLMTP      = "lmtp"
	tlsModeImplicit   = "implicit"
	tlsModeStartTLS   = "starttls"
	networkTCP        = "tcp"
	networkTCP4       = "tcp4"
	networkTCP6       = "tcp6"
	defaultTLSMinName = "TLS1.2"
)

var (
	// ErrListenerNotFound reports a runtime operation for an unknown configured listener.
	ErrListenerNotFound = runtimectl.ErrListenerNotFound
	// ErrListenerManagerStopped reports a runtime operation while the manager is not running.
	ErrListenerManagerStopped = runtimectl.ErrListenerManagerUnavailable
)

// State describes one listener's process-local runtime state.
type State = runtimectl.ListenerState

const (
	// StateAccepting means the listener socket is bound and accepting sockets.
	StateAccepting = runtimectl.ListenerStateAccepting
	// StateDraining means accepts are stopped while active local sessions remain.
	StateDraining = runtimectl.ListenerStateDraining
	// StateDrained means accepts are stopped and no local sessions remain.
	StateDrained = runtimectl.ListenerStateDrained
	// StateStopped means startup or resume failed and the listener is not bound.
	StateStopped = runtimectl.ListenerStateStopped
)

// DrainMode describes how listener runtime drain handles active local sessions.
type DrainMode = runtimectl.ListenerDrainMode

const (
	// DrainModeSoft closes only the accept socket and keeps active streams running.
	DrainModeSoft = runtimectl.ListenerDrainModeSoft
	// DrainModeHard closes the accept socket and then closes active streams after grace.
	DrainModeHard = runtimectl.ListenerDrainModeHard
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
	IdentityLookuper    nauthilus.IdentityLookuper
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

type unavailableSessionHandler struct {
	protocol string
}

// Serve closes sessions when no app-level protocol factory was supplied.
func (h unavailableSessionHandler) Serve(context.Context, net.Conn) error {
	return errors.New("protocol handler unavailable for " + h.protocol)
}

// ManagerOption customizes listener manager construction in tests and application assembly code.
type ManagerOption func(*managerOptions)

// Snapshot is a secret-safe summary of configured listener lifecycle state.
type Snapshot = runtimectl.ListenerDetail

// DrainRequest asks the manager to runtime-drain one configured listener.
type DrainRequest = runtimectl.ListenerManagerDrainRequest

// Manager starts, stops and tracks configured frontend protocol listeners.
type Manager struct {
	listeners       []*managedListener
	shutdownTimeout time.Duration
	cfg             config.Config
	options         managerOptions
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

	managed, err := managedListenersFromConfig(cfg, options)
	if err != nil {
		return nil, err
	}

	return &Manager{
		listeners:       managed,
		shutdownTimeout: cfg.Runtime.Process.ShutdownTimeout.Std(),
		cfg:             cfg,
		options:         options,
	}, nil
}

// managedListenersFromConfig builds detached listener lifecycle objects from one snapshot.
func managedListenersFromConfig(cfg config.Config, options managerOptions) ([]*managedListener, error) {
	listenerNames, err := sortedSupportedListenerNames(cfg.Director.Listeners)
	if err != nil {
		return nil, err
	}

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

	return managed, nil
}

// WithSessionHandlerFactory replaces the default protocol session handler factory.
func WithSessionHandlerFactory(factory SessionHandlerFactory) ManagerOption {
	return func(options *managerOptions) {
		if factory != nil {
			options.handlerFactory = factory
		}
	}
}

// WithNauthilusClientFactory replaces authority client construction for tests or application wiring.
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

// Reload adds new listeners and gracefully drains listeners removed from the snapshot.
func (m *Manager) Reload(ctx context.Context, cfg config.Config) error {
	if m == nil {
		return errors.New("listener manager unavailable")
	}

	cfg = cfg.Normalize()

	nextListeners, err := managedListenersFromConfig(cfg, m.options)
	if err != nil {
		return err
	}

	m.startMu.Lock()
	defer m.startMu.Unlock()

	if err := rejectChangedListeners(m.listeners, nextListeners); err != nil {
		return err
	}

	if !m.started {
		m.listeners = nextListeners
		m.shutdownTimeout = cfg.Runtime.Process.ShutdownTimeout.Std()
		m.cfg = cfg

		return nil
	}

	oldByName := listenersByName(m.listeners)

	started, err := startAddedListeners(ctx, oldByName, nextListeners)
	if err != nil {
		_ = stopManagedListeners(context.Background(), started)

		return err
	}

	stopCtx, cancel := contextWithShutdownTimeout(ctx, m.shutdownTimeout)
	defer cancel()

	if err := stopRemovedListeners(stopCtx, oldByName, nextListeners); err != nil {
		return err
	}

	m.listeners = mergedReloadListeners(m.listeners, nextListeners, started)
	m.shutdownTimeout = cfg.Runtime.Process.ShutdownTimeout.Std()
	m.cfg = cfg

	return nil
}

// Drain stops accepts for one configured listener without editing configuration.
func (m *Manager) Drain(ctx context.Context, request DrainRequest) (Snapshot, error) {
	request, err := request.Normalize()
	if err != nil {
		return Snapshot{}, err
	}

	if m == nil {
		return Snapshot{}, ErrListenerManagerStopped
	}

	m.startMu.Lock()
	defer m.startMu.Unlock()

	if !m.started {
		return Snapshot{}, ErrListenerManagerStopped
	}

	entry := m.listenerByName(request.Name)
	if entry == nil {
		return Snapshot{}, ErrListenerNotFound
	}

	switch request.Mode {
	case DrainModeSoft:
		err = entry.softDrain()
	case DrainModeHard:
		err = entry.hardDrain(ctx, *request.Grace, m.options.localSessions)
	default:
		err = errors.New("unsupported listener drain mode")
	}

	if err != nil {
		return Snapshot{}, err
	}

	return entry.snapshot(), nil
}

// Resume rebinds one configured listener from the current typed config snapshot.
func (m *Manager) Resume(ctx context.Context, name string) (Snapshot, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Snapshot{}, errors.New("listener name required")
	}

	if m == nil {
		return Snapshot{}, ErrListenerManagerStopped
	}

	m.startMu.Lock()
	defer m.startMu.Unlock()

	if !m.started {
		return Snapshot{}, ErrListenerManagerStopped
	}

	entry := m.listenerByName(name)
	if entry == nil {
		return Snapshot{}, ErrListenerNotFound
	}

	if err := entry.resume(ctx); err != nil {
		return entry.snapshot(), err
	}

	return entry.snapshot(), nil
}

// Snapshots returns the configured listeners without exposing high-cardinality session data.
func (m *Manager) Snapshots() []Snapshot {
	m.startMu.Lock()
	defer m.startMu.Unlock()

	snapshots := make([]Snapshot, 0, len(m.listeners))

	for _, entry := range m.listeners {
		snapshots = append(snapshots, entry.snapshot())
	}

	return snapshots
}

// BoundAddress returns the bound address for a started listener.
func (m *Manager) BoundAddress(name string) (string, bool) {
	m.startMu.Lock()
	defer m.startMu.Unlock()

	for _, entry := range m.listeners {
		if entry.name == name && entry.boundAddress() != "" {
			return entry.boundAddress(), true
		}
	}

	return "", false
}

// ListenerNames returns configured supported listener names in deterministic order.
func (m *Manager) ListenerNames() []string {
	m.startMu.Lock()
	defer m.startMu.Unlock()

	names := make([]string, 0, len(m.listeners))
	for _, entry := range m.listeners {
		names = append(names, entry.name)
	}

	return names
}

// listenerByName returns the manager-owned listener with a matching configured name.
func (m *Manager) listenerByName(name string) *managedListener {
	for _, entry := range m.listeners {
		if entry.name == name {
			return entry
		}
	}

	return nil
}

// rejectChangedListeners rejects in-place listener changes that need a restart.
func rejectChangedListeners(current []*managedListener, next []*managedListener) error {
	currentByName := listenersByName(current)
	for _, entry := range next {
		existing, ok := currentByName[entry.name]
		if !ok {
			continue
		}

		if !reflect.DeepEqual(existing.config.listener, entry.config.listener) {
			return errors.New("listener " + entry.name + ": existing listener changes require restart")
		}
	}

	return nil
}

// listenersByName indexes listener objects by their stable configured name.
func listenersByName(listeners []*managedListener) map[string]*managedListener {
	index := make(map[string]*managedListener, len(listeners))
	for _, entry := range listeners {
		index[entry.name] = entry
	}

	return index
}

// startAddedListeners starts sockets that are present only in the next snapshot.
func startAddedListeners(ctx context.Context, oldByName map[string]*managedListener, next []*managedListener) ([]*managedListener, error) {
	started := make([]*managedListener, 0)

	for _, entry := range next {
		if _, exists := oldByName[entry.name]; exists {
			continue
		}

		if err := entry.start(ctx); err != nil {
			return started, err
		}

		started = append(started, entry)
	}

	return started, nil
}

// stopRemovedListeners drains sockets that disappeared from the next snapshot.
func stopRemovedListeners(ctx context.Context, oldByName map[string]*managedListener, next []*managedListener) error {
	nextByName := listenersByName(next)

	var removed []*managedListener

	for name, entry := range oldByName {
		if _, exists := nextByName[name]; !exists {
			removed = append(removed, entry)
		}
	}

	sort.Slice(removed, func(left int, right int) bool {
		return removed[left].name < removed[right].name
	})

	return stopManagedListeners(ctx, removed)
}

// mergedReloadListeners keeps unchanged listeners and installs newly started listeners in config order.
func mergedReloadListeners(current []*managedListener, next []*managedListener, started []*managedListener) []*managedListener {
	currentByName := listenersByName(current)
	startedByName := listenersByName(started)

	merged := make([]*managedListener, 0, len(next))
	for _, entry := range next {
		if existing, ok := currentByName[entry.name]; ok {
			merged = append(merged, existing)

			continue
		}

		if replacement, ok := startedByName[entry.name]; ok {
			merged = append(merged, replacement)
		}
	}

	return merged
}

// defaultSessionHandlerFactory returns a fail-closed handler when app wiring does not provide one.
func defaultSessionHandlerFactory(options SessionOptions) SessionHandler {
	return unavailableSessionHandler{protocol: options.Config.Protocol}
}

// defaultNauthilusClientFactory creates the configured Nauthilus authority transport.
func defaultNauthilusClientFactory(authority config.AuthorityConfig) (nauthilus.Authenticator, error) {
	return nauthilus.NewClient(authority, nauthilus.ClientOptions{})
}

// sortedSupportedListenerNames selects supported protocol listeners deterministically.
func sortedSupportedListenerNames(listeners map[string]config.ListenerConfig) ([]string, error) {
	names := make([]string, 0, len(listeners))
	for name, entry := range listeners {
		switch entry.Protocol {
		case protocolIMAP, protocolLMTP:
			names = append(names, name)
		default:
			return nil, errors.New("listener " + name + ": unsupported protocol " + entry.Protocol)
		}
	}

	sort.Strings(names)

	return names, nil
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
