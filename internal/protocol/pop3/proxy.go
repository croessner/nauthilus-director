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

//nolint:funlen,wsl_v5 // The proxy transition keeps the required handoff ordering explicit.
package pop3

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/placement"
	"github.com/croessner/nauthilus-director/internal/proxy"
	runtimectl "github.com/croessner/nauthilus-director/internal/runtime"
	"github.com/croessner/nauthilus-director/internal/state"
)

// ProxyHandoff carries the frontend stream and read-ahead bytes into transparent proxy mode.
type ProxyHandoff struct {
	frontend net.Conn
	buffered []byte
}

// transitionAuthenticatedSession proves backend access, sends frontend success, and starts proxy mode.
func (s *Session) transitionAuthenticatedSession(
	ctx context.Context,
	credentials *frontendCredentials,
	result nauthilus.AuthResult,
) (commandOutcome, error) {
	frontendMechanism := ""
	if credentials != nil {
		frontendMechanism = credentials.Method()
	}

	if s.backendConnector == nil {
		s.recordBackendConnect(ctx, pop3ObservationResultFailure, pop3ReasonTemporaryFailure, 0)
		s.recordAuthenticate(ctx, pop3ObservationResultFailure, pop3ReasonTemporaryFailure, frontendMechanism)
		_ = s.closePlacedSession(context.Background())

		return commandOutcome{}, s.writeBackendReadinessERR()
	}

	if s.proxyRunner == nil {
		s.recordObservation(ctx, observability.EventProxyPipe, observability.TraceBoundaryProxyPipe, pop3ObservationOperationProxy, pop3ObservationResultFailure, pop3ReasonState, nil)
		s.recordAuthenticate(ctx, pop3ObservationResultFailure, pop3ReasonState, frontendMechanism)
		_ = s.closePlacedSession(context.Background())

		return commandOutcome{}, s.writeBackendReadinessERR()
	}

	connectCtx, connectSpan := s.startObservationSpan(ctx, observability.TraceBoundaryBackendConnect, pop3ObservationOperationBackendConn, pop3ObservationResultStart, "", map[string]string{
		pop3ObsFieldBackendIdentifier: s.placement.Backend.Backend.Identifier,
		pop3ObsFieldShardTag:          s.placement.SelectedShardTag,
	})
	connectCtx, cancel := backendConnectContext(connectCtx, s.backendConnectTimeout)
	defer cancel()

	connectStarted := time.Now()
	connection, err := s.backendConnector.Connect(connectCtx, s.sessionBackendConnectRequest())
	connectDuration := time.Since(connectStarted)
	if err != nil {
		connectReason := pop3ReasonClass(err)
		s.recordBackendConnect(connectCtx, pop3ObservationResultFailure, connectReason, connectDuration)
		s.recordAuthenticate(ctx, pop3ObservationResultFailure, connectReason, frontendMechanism)
		connectSpan.End(pop3ObservationResultFailure, connectReason)
		_ = s.closePlacedSession(context.Background())

		return commandOutcome{}, s.writeBackendReadinessERR()
	}

	s.recordBackendConnect(connectCtx, pop3ObservationResultOK, pop3ReasonOK, connectDuration)

	selectedUser := selectedBackendUsername(result, s.placement.Routing.AccountKey)
	if err := AuthenticateBackend(connection, s.placement.Backend.Backend, credentials, selectedUser); err != nil {
		authReason := pop3ReasonClass(err)
		s.recordBackendAuth(connectCtx, pop3ObservationResultFailure, authReason, backendAuthObservationMechanism(s.placement.Backend.Backend.Auth.Mode, credentials))
		s.recordAuthenticate(ctx, pop3ObservationResultFailure, authReason, frontendMechanism)
		connectSpan.End(pop3ObservationResultFailure, authReason)
		_ = connection.Conn().Close()
		_ = s.closePlacedSession(context.Background())

		return commandOutcome{}, s.writeBackendReadinessERR()
	}

	s.recordBackendAuth(connectCtx, pop3ObservationResultOK, pop3ReasonOK, backendAuthObservationMechanism(s.placement.Backend.Backend.Auth.Mode, credentials))
	connectSpan.End(pop3ObservationResultOK, pop3ReasonOK)

	credentials.Clear()

	if err := s.writeOK("Authentication successful"); err != nil {
		s.recordAuthenticate(ctx, pop3ObservationResultFailure, pop3ReasonClass(err), frontendMechanism)
		_ = connection.Conn().Close()
		_ = s.closePlacedSession(context.Background())

		return commandOutcome{}, err
	}

	if err := s.writer.Flush(); err != nil {
		s.recordAuthenticate(ctx, pop3ObservationResultFailure, pop3ReasonClass(err), frontendMechanism)
		_ = connection.Conn().Close()
		_ = s.closePlacedSession(context.Background())

		return commandOutcome{}, err
	}

	s.recordAuthenticate(ctx, pop3ObservationResultOK, pop3ReasonOK, frontendMechanism)

	handoff := s.BufferedProxyHandoff()
	unregister := s.registerLocalProxySession(handoff.Frontend(), connection.Conn())
	defer unregister()

	proxyCtx, proxySpan := s.startObservationSpan(ctx, observability.TraceBoundaryProxyPipe, pop3ObservationOperationProxy, pop3ObservationResultStart, "", map[string]string{
		pop3ObsFieldBackendIdentifier: s.placement.Backend.Backend.Identifier,
		pop3ObsFieldShardTag:          s.placement.SelectedShardTag,
	})
	_, err = s.proxyRunner.Run(proxyCtx, proxy.PipeConfig{
		Frontend:          handoff.Frontend(),
		Backend:           connection.Conn(),
		BufferedToBackend: handoff.Buffered(),
		BufferedToClient:  connection.Buffered(),
		IdleTimeout:       s.proxyIdleTimeout,
		HeartbeatInterval: s.proxyHeartbeatInterval(),
		Lease:             s.proxyLease(),
		Observability:     s.observability,
	})
	proxySpan.End(pop3ResultLabel(err), pop3ReasonClass(err))

	return commandOutcome{closeSession: true, flushed: true}, err
}

// BufferedProxyHandoff drains frontend bytes already read by the authorization parser.
func (s *Session) BufferedProxyHandoff() ProxyHandoff {
	buffered := make([]byte, s.reader.Buffered())
	if len(buffered) > 0 {
		_, _ = io.ReadFull(s.reader, buffered)
	}

	return ProxyHandoff{frontend: s.conn, buffered: buffered}
}

// Buffered returns a detached copy of bytes that must reach the backend first.
func (h ProxyHandoff) Buffered() []byte {
	copied := make([]byte, len(h.buffered))
	copy(copied, h.buffered)

	return copied
}

// Frontend returns the frontend connection that transparent proxy mode owns.
func (h ProxyHandoff) Frontend() net.Conn {
	return h.frontend
}

// registerLocalProxySession exposes the proxied stream to local runtime controls.
func (s *Session) registerLocalProxySession(frontend net.Conn, backendConn net.Conn) func() {
	if s.localSessions == nil {
		return func() {}
	}

	var closeOnce sync.Once

	handle := runtimectl.LocalSessionHandleFunc(func(context.Context, runtimectl.LocalSessionControl) error {
		closeOnce.Do(func() {
			_ = frontend.Close()
			_ = backendConn.Close()
		})

		return nil
	})

	unregister, err := s.localSessions.Register(runtimectl.LocalSessionInfo{
		SessionID:         s.sessionID,
		ListenerName:      s.listenerName,
		Tenant:            s.placementAffinityKey().Tenant,
		UserHash:          s.placementAffinityKey().AccountKey,
		BackendIdentifier: s.placement.Backend.Backend.Identifier,
		DirectorInstance:  s.directorInstanceID,
	}, handle)
	if err != nil {
		return func() {}
	}

	return unregister
}

// proxyLease builds the active placement lifecycle used by transparent proxy mode.
func (s *Session) proxyLease() proxy.LeaseLifecycle {
	if !s.placed || s.placementLease == nil {
		return nil
	}

	return &placementLeaseLifecycle{
		lease:       s.placementLease,
		ttl:         s.sessionLeaseTTL,
		afterClose:  s.clearPlacedSession,
		recordClose: s.recordSessionClose,
	}
}

// proxyHeartbeatInterval derives a stable heartbeat cadence below the lease TTL.
func (s *Session) proxyHeartbeatInterval() time.Duration {
	ttl := s.sessionLeaseTTL
	if ttl <= 0 {
		ttl = s.proxyIdleTimeout
	}

	if ttl <= 0 {
		return defaultSessionLeaseTTL
	}

	interval := ttl / 2
	if interval <= 0 {
		return ttl
	}

	return interval
}

// placementAffinityKey returns the key for the opened placement lease.
func (s *Session) placementAffinityKey() state.AffinityKey {
	if s.placement.Affinity.Key != (state.AffinityKey{}) {
		return s.placement.Affinity.Key
	}

	return state.AffinityKey{
		Tenant:     normalizedRoutingFact(s.placement.Routing.Tenant),
		AccountKey: normalizedAccount(s.placement.Routing.AccountKey),
	}
}

// placementLeaseLifecycle adapts placement leases to the proxy lifecycle.
type placementLeaseLifecycle struct {
	lease       placement.LeaseHandle
	ttl         time.Duration
	afterClose  func()
	recordClose func(context.Context, string, string)
	closeOnce   sync.Once
	closeErr    error
}

// Heartbeat refreshes the placement lease while proxy mode is running.
func (l *placementLeaseLifecycle) Heartbeat(ctx context.Context) error {
	record, err := l.lease.Heartbeat(ctx, l.ttl)
	if err != nil {
		return err
	}

	switch record.ControlAction {
	case "", state.ControlActionNone:
		return nil
	case state.ControlActionKick, state.ControlActionDrain, state.ControlActionMoveGenerationChanged:
		return proxy.NewControlActionError(string(record.ControlAction))
	default:
		return errors.New("pop3: ambiguous heartbeat control action")
	}
}

// Close releases the placement lease at proxy end.
func (l *placementLeaseLifecycle) Close(ctx context.Context) error {
	l.closeOnce.Do(func() {
		l.closeErr = l.lease.Close(ctx)
		if l.recordClose != nil {
			l.recordClose(ctx, pop3ResultLabel(l.closeErr), pop3CloseReasonClass(l.closeErr, l.lease.Affinity()))
		}

		if l.afterClose != nil {
			l.afterClose()
		}
	})

	return l.closeErr
}

// backendAuthObservationMechanism returns the bounded backend auth mechanism class.
func backendAuthObservationMechanism(mode string, credentials *frontendCredentials) string {
	if strings.EqualFold(strings.TrimSpace(mode), backendAuthModeMasterUser) {
		return authMethodUserPass
	}

	if credentials != nil {
		return credentials.Method()
	}

	return ""
}

// selectedBackendUsername chooses the authenticated account name for backend auth.
func selectedBackendUsername(result nauthilus.AuthResult, routingAccount string) string {
	selected := strings.TrimSpace(result.Account)
	if selected != "" {
		return selected
	}

	return strings.TrimSpace(routingAccount)
}

// defaultProxyIdleTimeout returns the configured proxy timeout or the lease fallback.
func defaultProxyIdleTimeout(configured time.Duration, lease time.Duration) time.Duration {
	if configured > 0 {
		return configured
	}

	return defaultSessionLease(lease)
}
