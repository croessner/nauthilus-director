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
	"github.com/croessner/nauthilus-director/internal/observability"
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
	active    map[net.Conn]struct{}
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

	configured := configListener{
		listener: entry,
		timeouts: runtime.Timeouts,
		security: security,
	}

	authenticator, err := options.authClientFactory(authority)
	if err != nil {
		return nil, fmt.Errorf("listener %s: %w", name, err)
	}

	return &managedListener{
		name:   name,
		config: configured,
		handler: options.handlerFactory(SessionOptions{
			ListenerName:        name,
			Config:              entry,
			Timeouts:            runtime.Timeouts,
			Security:            security,
			Authenticator:       authenticator,
			BearerTokenMaxBytes: authority.Mechanisms.Bearer.TokenMaxBytes,
			DirectorInstanceID:  runtime.InstanceName,
			DefaultTenant:       defaultTenant,
			DefaultShard:        defaultShard,
			SessionLeaseTTL:     runtime.Timeouts.ProxyIdle.Std(),
			SessionIdleGrace:    sessionIdleGrace,
			LocalSessions:       options.localSessions,
			Observability:       options.observability,
		}),
		proxyProtocol: proxyPolicy,
		listenConfig:  options.listenConfig,
		observability: observability.NormalizeRecorder(options.observability),
		active:        map[net.Conn]struct{}{},
	}, nil
}

// start binds the configured address and starts the accept loop.
func (l *managedListener) start(ctx context.Context) error {
	if l.config.listener.TLS.Mode == tlsModeImplicit {
		tlsConfig, err := buildListenerTLSConfig(l.config.listener)
		if err != nil {
			return fmt.Errorf("listener %s: %w", l.name, err)
		}

		l.tlsConfig = tlsConfig
	}

	ln, err := l.listenConfig.Listen(ctx, l.config.listener.Network, l.config.listener.Address)
	if err != nil {
		l.recordListenerEvent(ctx, observability.EventListenerStart, "failure", "bind_failed")

		return fmt.Errorf("start listener %s on %s/%s: %w", l.name, l.config.listener.Network, l.config.listener.Address, err)
	}

	l.mu.Lock()
	l.listener = ln
	l.mu.Unlock()

	l.acceptWG.Add(1)
	go l.acceptLoop(ln)

	l.recordListenerEvent(ctx, observability.EventListenerStart, listenerResultOK, "")

	return nil
}

// stop closes the listener and waits for active sessions or the shutdown context.
func (l *managedListener) stop(ctx context.Context) error {
	l.mu.Lock()
	ln := l.listener
	l.listener = nil
	l.mu.Unlock()

	if ln != nil {
		_ = ln.Close()
	}

	l.acceptWG.Wait()

	if waitGroupDone(ctx, &l.sessionWG) {
		l.recordListenerEvent(ctx, observability.EventListenerStop, listenerResultOK, "")

		return nil
	}

	l.closeActiveConnections()

	if waitGroupDone(context.Background(), &l.sessionWG) {
		l.recordListenerEvent(ctx, observability.EventListenerStop, listenerResultOK, "")

		return nil
	}

	l.recordListenerEvent(ctx, observability.EventListenerStop, "failure", "shutdown_timeout")

	return ctx.Err()
}

// snapshot returns secret-safe listener state for tests and future diagnostics.
func (l *managedListener) snapshot() Snapshot {
	return Snapshot{
		Name:          l.name,
		Protocol:      l.config.listener.Protocol,
		ServiceName:   l.config.listener.ServiceName,
		Network:       l.config.listener.Network,
		Address:       l.config.listener.Address,
		TLSMode:       l.config.listener.TLS.Mode,
		ImplicitTLS:   l.config.listener.TLS.Mode == tlsModeImplicit,
		ProxyProtocol: l.config.listener.ProxyProtocol.Enabled,
		BoundAddress:  l.boundAddress(),
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
				return
			}

			return
		}

		l.sessionWG.Add(1)
		go l.serveConnection(conn)
	}
}

// serveConnection prepares transport boundaries before handing a stream to IMAP.
func (l *managedListener) serveConnection(conn net.Conn) {
	defer l.sessionWG.Done()

	l.trackConnection(conn)
	defer l.untrackConnection(conn)
	defer func() { _ = conn.Close() }()

	prepared, err := l.prepareConnection(conn)
	if err != nil {
		return
	}

	_ = l.handler.Serve(context.Background(), prepared)
}

// prepareConnection validates optional PROXY metadata before optional TLS wrapping.
func (l *managedListener) prepareConnection(conn net.Conn) (net.Conn, error) {
	prepared := conn
	if l.proxyProtocol != nil {
		proxyConn, err := l.proxyProtocol.apply(conn)
		if err != nil {
			return nil, err
		}

		prepared = proxyConn
	}

	if l.config.listener.TLS.Mode == tlsModeImplicit {
		prepared = tls.Server(prepared, l.tlsConfig.Clone())
	}

	return prepared, nil
}

// trackConnection records an active connection for deadline-enforced shutdown.
func (l *managedListener) trackConnection(conn net.Conn) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.active[conn] = struct{}{}
}

// untrackConnection removes a connection from the shutdown tracking set.
func (l *managedListener) untrackConnection(conn net.Conn) {
	l.mu.Lock()
	defer l.mu.Unlock()

	delete(l.active, conn)
}

// closeActiveConnections closes every active connection after the graceful drain expires.
func (l *managedListener) closeActiveConnections() {
	l.mu.Lock()

	active := make([]net.Conn, 0, len(l.active))
	for conn := range l.active {
		active = append(active, conn)
	}
	l.mu.Unlock()

	for _, conn := range active {
		_ = conn.Close()
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

// validateTLSMode accepts the frontend TLS modes supported by IMAP listeners.
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
