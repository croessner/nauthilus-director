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

//nolint:funlen,wsl_v5 // Proxy transition keeps backend auth and handoff ordering visible.
package sieve

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

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
) (commandOutcome, error) {
	if s.backendConnector == nil {
		s.recordBackendConnect(ctx, sieveObservationResultFailure, sieveReasonTemporaryFailure, 0)
		_ = s.closePlacedSession(context.Background())

		return commandOutcome{}, s.writeNo(codeTryLater, "Backend service temporarily unavailable")
	}

	if s.proxyRunner == nil {
		s.recordObservation(ctx, observability.EventProxyPipe, observability.TraceBoundaryProxyPipe, sieveObservationOperationProxy, sieveObservationResultFailure, sieveReasonState, nil)
		_ = s.closePlacedSession(context.Background())

		return commandOutcome{}, s.writeNo(codeTryLater, "Backend service temporarily unavailable")
	}

	connectCtx, connectSpan := s.startObservationSpan(ctx, observability.TraceBoundaryBackendConnect, sieveObservationOperationBackendConn, sieveObservationResultStart, "", map[string]string{
		sieveObsFieldBackendIdentifier: s.placement.Backend.Backend.Identifier,
		sieveObsFieldShardTag:          s.placement.SelectedShardTag,
	})
	connectCtx, cancel := backendConnectContext(connectCtx, s.backendConnectTimeout)
	defer cancel()

	connectStarted := time.Now()
	connection, err := s.backendConnector.Connect(connectCtx, s.sessionBackendConnectRequest())
	connectDuration := time.Since(connectStarted)
	if err != nil {
		connectReason := sieveReasonClass(err)
		s.recordBackendConnect(connectCtx, sieveObservationResultFailure, connectReason, connectDuration)
		connectSpan.End(sieveObservationResultFailure, connectReason)
		_ = s.closePlacedSession(context.Background())

		return commandOutcome{}, s.writeNo(codeTryLater, "Backend service temporarily unavailable")
	}

	s.recordBackendConnect(connectCtx, sieveObservationResultOK, sieveReasonOK, connectDuration)

	backendCredentials, err := credentials.BackendCredentials(s.placement.AuthResult.Account)
	if err != nil {
		authReason := sieveReasonClass(err)
		s.recordBackendAuth(connectCtx, sieveObservationResultFailure, authReason, credentials.Mechanism().Normalized())
		connectSpan.End(sieveObservationResultFailure, authReason)
		_ = connection.Conn().Close()
		_ = s.closePlacedSession(context.Background())

		return commandOutcome{}, s.writeNo(codeTryLater, "Backend service temporarily unavailable")
	}

	if err := AuthenticateBackend(connection, s.placement.Backend.Backend, backendCredentials); err != nil {
		authReason := sieveReasonClass(err)
		s.recordBackendAuth(connectCtx, sieveObservationResultFailure, authReason, credentials.Mechanism().Normalized())
		connectSpan.End(sieveObservationResultFailure, authReason)
		_ = connection.Conn().Close()
		_ = s.closePlacedSession(context.Background())

		return commandOutcome{}, s.writeNo(codeTryLater, "Backend service temporarily unavailable")
	}

	s.recordBackendAuth(connectCtx, sieveObservationResultOK, sieveReasonOK, credentials.Mechanism().Normalized())
	connectSpan.End(sieveObservationResultOK, sieveReasonOK)

	credentials.Clear()
	connection.DiscardBufferedCapabilityResponse()

	if err := s.writeOK("Authentication successful"); err != nil {
		_ = connection.Conn().Close()
		_ = s.closePlacedSession(context.Background())

		return commandOutcome{}, err
	}

	if err := s.writer.Flush(); err != nil {
		_ = connection.Conn().Close()
		_ = s.closePlacedSession(context.Background())

		return commandOutcome{}, err
	}

	handoff := s.BufferedProxyHandoff()
	unregister := s.registerLocalProxySession(handoff.Frontend(), connection.Conn())
	defer unregister()

	proxyCtx, proxySpan := s.startObservationSpan(ctx, observability.TraceBoundaryProxyPipe, sieveObservationOperationProxy, sieveObservationResultStart, "", map[string]string{
		sieveObsFieldBackendIdentifier: s.placement.Backend.Backend.Identifier,
		sieveObsFieldShardTag:          s.placement.SelectedShardTag,
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
	proxySpan.End(sieveResultLabel(err), sieveReasonClass(err))

	return commandOutcome{closeSession: true, flushed: true}, err
}

// BufferedProxyHandoff drains frontend bytes already consumed by the pre-auth reader.
func (s *Session) BufferedProxyHandoff() ProxyHandoff {
	buffered := make([]byte, s.reader.Buffered())
	if len(buffered) > 0 {
		_, _ = io.ReadFull(s.reader, buffered)
	}

	return ProxyHandoff{frontend: s.conn, buffered: buffered}
}

// Buffered returns a detached copy of the bytes that must reach the backend first.
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
		return defaultSieveSessionLease
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

// clearPlacedSession forgets active placement ownership after the lease has closed.
func (s *Session) clearPlacedSession() {
	s.placement = Placement{}
	s.placementLease = nil
	s.placed = false
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
		return errors.New("sieve: ambiguous heartbeat control action")
	}
}

// Close releases the placement lease at proxy end.
func (l *placementLeaseLifecycle) Close(ctx context.Context) error {
	l.closeOnce.Do(func() {
		l.closeErr = l.lease.Close(ctx)
		if l.recordClose != nil {
			l.recordClose(ctx, sieveResultLabel(l.closeErr), sieveCloseReasonClass(l.closeErr, l.lease.Affinity()))
		}

		if l.afterClose != nil {
			l.afterClose()
		}
	})

	return l.closeErr
}

// defaultProxyIdleTimeout returns the configured proxy timeout or the lease fallback.
func defaultProxyIdleTimeout(configured time.Duration, lease time.Duration) time.Duration {
	if configured > 0 {
		return configured
	}

	return defaultSessionLease(lease)
}
