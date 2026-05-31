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

package listener

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/observability"
	runtimectl "github.com/croessner/nauthilus-director/internal/runtime"
)

// managedListener owns one configured network listener and its active sessions.
type managedListener struct {
	name          string
	config        configListener
	handler       SessionHandler
	tlsConfig     *tls.Config
	proxyProtocol *proxyProtocolPolicy
	listenConfig  net.ListenConfig
	observability observability.Recorder

	mu        sync.Mutex
	listener  net.Listener
	active    map[net.Conn]context.CancelFunc
	state     State
	drainMode DrainMode
	acceptWG  sync.WaitGroup
	sessionWG sync.WaitGroup
}

type configListener struct {
	listener config.ListenerConfig
	timeouts config.RuntimeTimeouts
	security config.DirectorSecurityConfig
}

// newManagedListener builds one listener lifecycle object from typed config.
func newManagedListener(
	name string,
	entry config.ListenerConfig,
	authority config.AuthorityConfig,
	runtime config.RuntimeConfig,
	security config.DirectorSecurityConfig,
	defaultTenant string,
	defaultShard string,
	sessionIdleGrace time.Duration,
	options managerOptions,
) (*managedListener, error) {
	if err := validateNetwork(entry.Network); err != nil {
		return nil, fmt.Errorf("listener %s: %w", name, err)
	}

	if err := validateTLSMode(entry.TLS.Mode); err != nil {
		return nil, fmt.Errorf("listener %s: %w", name, err)
	}

	proxyPolicy, err := newProxyProtocolPolicy(entry.ProxyProtocol, runtime.Timeouts.Preauth.Std())
	if err != nil {
		return nil, fmt.Errorf("listener %s: %w", name, err)
	}

	if _, err := tlsMinVersion(entry.TLS.MinTLSVersion); err != nil {
		return nil, fmt.Errorf("listener %s: %w", name, err)
	}

	tlsConfig, err := buildListenerTLSConfig(entry)
	if err != nil {
		return nil, fmt.Errorf("listener %s: %w", name, err)
	}

	configured := configListener{
		listener: entry,
		timeouts: runtime.Timeouts,
		security: security,
	}

	authenticator, err := options.authClientFactory(authority)
	if err != nil {
		return nil, fmt.Errorf("listener %s: %w", name, err)
	}

	identityLookuper, _ := authenticator.(nauthilus.IdentityLookuper)

	authenticator = nauthilus.ObserveAuthenticator(authenticator, nauthilus.ObservationConfig{
		AuthorityName: entry.Authority,
		BackendPool:   entry.BackendPool,
		ListenerName:  name,
		Recorder:      options.observability,
		ServiceName:   entry.ServiceName,
		Transport:     authority.Transport,
	})

	return &managedListener{
		name:   name,
		config: configured,
		handler: options.handlerFactory(SessionOptions{
			ListenerName:        name,
			Config:              entry,
			AuthorityTransport:  authority.Transport,
			Timeouts:            runtime.Timeouts,
			Security:            security,
			Authenticator:       authenticator,
			IdentityLookuper:    identityLookuper,
			BearerTokenMaxBytes: authority.Mechanisms.Bearer.TokenMaxBytes,
			DirectorInstanceID:  runtime.InstanceName,
			DefaultTenant:       defaultTenant,
			DefaultShard:        defaultShard,
			SessionLeaseTTL:     runtime.Timeouts.ProxyIdle.Std(),
			SessionIdleGrace:    sessionIdleGrace,
			FrontendTLSConfig:   tlsConfig,
			LocalSessions:       options.localSessions,
			Observability:       options.observability,
		}),
		tlsConfig:     tlsConfig,
		proxyProtocol: proxyPolicy,
		listenConfig:  options.listenConfig,
		observability: observability.NormalizeRecorder(options.observability),
		active:        map[net.Conn]context.CancelFunc{},
		state:         StateStopped,
	}, nil
}

// start binds the configured address and starts the accept loop.
func (l *managedListener) start(ctx context.Context) error {
	l.mu.Lock()
	if l.listener != nil {
		l.mu.Unlock()

		return nil
	}
	l.mu.Unlock()

	ln, err := l.listenConfig.Listen(ctx, l.config.listener.Network, l.config.listener.Address)
	if err != nil {
		l.markStopped()
		l.recordListenerEvent(ctx, observability.EventListenerStart, "failure", "bind_failed")

		return fmt.Errorf("start listener %s on %s/%s: %w", l.name, l.config.listener.Network, l.config.listener.Address, err)
	}

	l.mu.Lock()
	l.listener = ln
	l.state = StateAccepting
	l.drainMode = ""
	l.mu.Unlock()

	l.acceptWG.Add(1)
	go l.acceptLoop(ln)

	l.recordListenerEvent(ctx, observability.EventListenerStart, listenerResultOK, "")

	return nil
}

// stop closes the listener and waits for active sessions or the shutdown context.
func (l *managedListener) stop(ctx context.Context) error {
	l.closeAcceptSocket("")
	l.acceptWG.Wait()

	if waitGroupDone(ctx, &l.sessionWG) {
		l.markStopped()
		l.recordListenerEvent(ctx, observability.EventListenerStop, listenerResultOK, "")

		return nil
	}

	l.closeActiveConnections()

	if waitGroupDone(context.Background(), &l.sessionWG) {
		l.markStopped()
		l.recordListenerEvent(ctx, observability.EventListenerStop, listenerResultOK, "")

		return nil
	}

	l.markStopped()
	l.recordListenerEvent(ctx, observability.EventListenerStop, "failure", "shutdown_timeout")

	return ctx.Err()
}

// snapshot returns secret-safe listener state for tests and manager diagnostics.
func (l *managedListener) snapshot() Snapshot {
	l.mu.Lock()
	defer l.mu.Unlock()

	boundAddress := ""
	if l.listener != nil && l.state == StateAccepting {
		boundAddress = l.listener.Addr().String()
	}

	return Snapshot{
		Name:                l.name,
		Protocol:            l.config.listener.Protocol,
		ServiceName:         l.config.listener.ServiceName,
		Network:             l.config.listener.Network,
		Address:             l.config.listener.Address,
		TLSMode:             l.config.listener.TLS.Mode,
		ImplicitTLS:         l.config.listener.TLS.Mode == tlsModeImplicit,
		ProxyProtocol:       l.config.listener.ProxyProtocol.Enabled,
		BoundAddress:        boundAddress,
		State:               l.state,
		ActiveLocalSessions: len(l.active),
		DrainMode:           l.drainMode,
	}
}

// boundAddress returns the current socket address after a successful start.
func (l *managedListener) boundAddress() string {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.listener == nil {
		return ""
	}

	return l.listener.Addr().String()
}

// acceptLoop accepts frontend sockets from one bound listener until it closes.
func (l *managedListener) acceptLoop(ln net.Listener) {
	defer l.acceptWG.Done()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				l.recordAcceptLoopStop(listenerResultOK, "closed")

				return
			}

			l.recordAcceptLoopStop("failure", "transport")

			return
		}

		l.sessionWG.Add(1)
		go l.serveConnection(conn)
	}
}

// serveConnection prepares transport boundaries before handing a stream to the protocol handler.
func (l *managedListener) serveConnection(conn net.Conn) {
	defer l.sessionWG.Done()

	sessionCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	l.trackConnection(conn, cancel)
	defer l.untrackConnection(conn)
	defer func() { _ = conn.Close() }()

	prepared, err := l.prepareConnection(conn)
	if err != nil {
		return
	}

	_ = l.handler.Serve(sessionCtx, prepared)
}

// prepareConnection validates optional PROXY metadata before optional TLS wrapping.
func (l *managedListener) prepareConnection(conn net.Conn) (net.Conn, error) {
	prepared := conn
	if l.proxyProtocol != nil {
		proxyConn, err := l.proxyProtocol.apply(conn)
		if err != nil {
			l.recordProxyProtocol(listenerResultRejected, proxyProtocolReasonClass(err))

			return nil, err
		}

		l.recordProxyProtocol(listenerResultAccepted, "ok")
		prepared = proxyConn
	}

	if l.config.listener.TLS.Mode == tlsModeImplicit {
		tlsConn := tls.Server(prepared, l.tlsConfig.Clone())
		if err := tlsConn.Handshake(); err != nil {
			return nil, err
		}

		prepared = tlsConn
	}

	return prepared, nil
}

// trackConnection records an active connection for deadline-enforced shutdown.
func (l *managedListener) trackConnection(conn net.Conn, cancel context.CancelFunc) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.active[conn] = cancel
}

// untrackConnection removes a connection from the shutdown tracking set.
func (l *managedListener) untrackConnection(conn net.Conn) {
	l.mu.Lock()
	defer l.mu.Unlock()

	delete(l.active, conn)
	l.refreshDrainedStateLocked()
}

// closeActiveConnections closes every active connection after the graceful drain expires.
func (l *managedListener) closeActiveConnections() {
	l.mu.Lock()

	active := make([]activeConnection, 0, len(l.active))
	for conn, cancel := range l.active {
		active = append(active, activeConnection{conn: conn, cancel: cancel})
	}
	l.mu.Unlock()

	for _, entry := range active {
		entry.cancel()
		_ = entry.conn.Close()
	}
}

// activeConnection couples one tracked transport with its protocol context canceler.
type activeConnection struct {
	conn   net.Conn
	cancel context.CancelFunc
}

// softDrain closes only the accept socket while preserving active streams.
func (l *managedListener) softDrain() error {
	l.closeAcceptSocket(DrainModeSoft)
	l.acceptWG.Wait()

	return nil
}

// hardDrain closes accepts, waits grace and closes active local streams.
func (l *managedListener) hardDrain(
	ctx context.Context,
	grace time.Duration,
	localSessions *runtimectl.LocalSessionRegistry,
) error {
	if ctx == nil {
		ctx = context.Background()
	}

	l.closeAcceptSocket(DrainModeHard)
	l.acceptWG.Wait()

	if err := waitForDrainGrace(ctx, grace); err != nil {
		return err
	}

	if localSessions != nil {
		_, err := localSessions.CloseListener(ctx, l.name, runtimectl.LocalSessionControl{
			Action: "listener_hard_drain",
			Reason: "listener hard drain",
		})
		if err != nil {
			return err
		}
	}

	l.closeActiveConnections()

	if waitGroupDone(ctx, &l.sessionWG) {
		l.markDrained()

		return nil
	}

	return ctx.Err()
}

// resume rebinds the configured address for a previously drained listener.
func (l *managedListener) resume(ctx context.Context) error {
	l.mu.Lock()
	alreadyAccepting := l.listener != nil && l.state == StateAccepting
	l.mu.Unlock()

	if alreadyAccepting {
		return nil
	}

	return l.start(ctx)
}

// closeAcceptSocket detaches and closes the current accept socket.
func (l *managedListener) closeAcceptSocket(mode DrainMode) net.Listener {
	l.mu.Lock()
	ln := l.listener
	l.listener = nil

	switch mode {
	case DrainModeSoft, DrainModeHard:
		l.drainMode = mode
		l.refreshDrainedStateLocked()
	default:
		l.drainMode = ""
		l.state = StateStopped
	}
	l.mu.Unlock()

	if ln != nil {
		_ = ln.Close()
	}

	return ln
}

// markStopped records a non-accepting listener after startup, resume or full stop failure.
func (l *managedListener) markStopped() {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.listener = nil
	l.drainMode = ""
	l.state = StateStopped
}

// markDrained records completion of a runtime drain after active streams close.
func (l *managedListener) markDrained() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.listener == nil && l.state != StateStopped {
		l.state = StateDrained
	}
}

// refreshDrainedStateLocked updates runtime drain state while l.mu is held.
func (l *managedListener) refreshDrainedStateLocked() {
	if l.listener != nil || l.drainMode == "" || l.state == StateStopped {
		return
	}

	if len(l.active) > 0 {
		l.state = StateDraining

		return
	}

	l.state = StateDrained
}

// waitForDrainGrace waits for the explicit hard-drain grace duration.
func waitForDrainGrace(ctx context.Context, grace time.Duration) error {
	if grace <= 0 {
		return ctx.Err()
	}

	timer := time.NewTimer(grace)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// validateNetwork accepts only stream TCP listener networks for mail listeners.
func validateNetwork(network string) error {
	switch network {
	case networkTCP, networkTCP4, networkTCP6:
		return nil
	default:
		return fmt.Errorf("unsupported listener network %q", network)
	}
}

// validateTLSMode accepts the frontend TLS modes supported by mail protocol listeners.
func validateTLSMode(mode string) error {
	switch mode {
	case tlsModeStartTLS, tlsModeImplicit:
		return nil
	default:
		return fmt.Errorf("unsupported listener TLS mode %q", mode)
	}
}

// waitGroupDone reports whether the wait group completed before the context ended.
func waitGroupDone(ctx context.Context, wg *sync.WaitGroup) bool {
	done := make(chan struct{})

	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return true
	case <-ctx.Done():
		return false
	}
}
