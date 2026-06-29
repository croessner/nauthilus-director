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

package imap

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/placement"
	"github.com/croessner/nauthilus-director/internal/protocol/authbinding"
	"github.com/croessner/nauthilus-director/internal/proxy"
	"github.com/croessner/nauthilus-director/internal/routing"
	runtimectl "github.com/croessner/nauthilus-director/internal/runtime"
	"github.com/croessner/nauthilus-director/internal/state"
)

// authenticateAndPlace maps frontend credentials through Nauthilus and director placement.
func (s *Session) authenticateAndPlace(ctx context.Context, tag string, credentials *frontendCredentials) (commandOutcome, error) {
	result, err := s.authenticateWithAuthority(ctx, credentials)
	if err != nil {
		return commandOutcome{}, s.writeTagged(tag, responseNo, authUnavailableText)
	}

	switch result.Decision {
	case nauthilus.DecisionAuthenticated:
		if err := s.placeAuthenticatedSession(ctx, credentials, result); err != nil {
			s.recordRoutingResolve(ctx, observationResultFailure, reasonClass(err), "", 0)

			return commandOutcome{}, s.writeTagged(tag, responseNo, authUnavailableText)
		}

		return s.transitionAuthenticatedSession(ctx, tag, credentials)
	case nauthilus.DecisionRejected:
		return commandOutcome{}, s.writeTagged(tag, responseNo, rejectedAuthResponseText(result.StatusMessage))
	case nauthilus.DecisionTemporaryFailure:
		return commandOutcome{}, s.writeTagged(tag, responseNo, authUnavailableText)
	default:
		return commandOutcome{}, s.writeTagged(tag, responseNo, authUnavailableText)
	}
}

// authenticateWithAuthority sends short-lived credentials to the configured Nauthilus authority.
func (s *Session) authenticateWithAuthority(
	ctx context.Context,
	credentials *frontendCredentials,
) (nauthilus.AuthResult, error) {
	if credentials == nil {
		return nauthilus.AuthResult{Decision: nauthilus.DecisionTemporaryFailure}, errors.New("imap: credentials unavailable")
	}

	authCtx, cancel := s.authContext(ctx)
	defer cancel()

	method := credentials.Mechanism().Normalized()
	if credentials.Kind() == credentialKindBearer {
		if s.bearerIntrospector == nil {
			return nauthilus.AuthResult{Decision: nauthilus.DecisionTemporaryFailure}, errors.New("imap: bearer introspector unavailable")
		}

		request := credentials.BearerIntrospectionRequest(
			s.NauthilusRequestContext(method),
			protocolIMAP,
			s.context.ListenerName,
			s.context.AuthorityName,
		)

		return s.bearerIntrospector.Introspect(authCtx, request)
	}

	if s.authenticator == nil {
		return nauthilus.AuthResult{Decision: nauthilus.DecisionTemporaryFailure}, errors.New("imap: authenticator unavailable")
	}

	request := credentials.NauthilusAuthRequest(s.NauthilusRequestContext(method))

	return s.authenticator.Authenticate(authCtx, request)
}

// authContext derives the bounded authority call context for one authentication attempt.
func (s *Session) authContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}

	if s.context.AuthTimeout <= 0 {
		return ctx, func() {}
	}

	return context.WithTimeout(ctx, s.context.AuthTimeout)
}

// placeAuthenticatedSession applies side-effect-free routing before opening session state.
func (s *Session) placeAuthenticatedSession(
	ctx context.Context,
	credentials *frontendCredentials,
	result nauthilus.AuthResult,
) error {
	if err := s.ensurePlacementDependencies(); err != nil {
		return err
	}

	routingRequest, err := s.routingRequest(credentials, result)
	if err != nil {
		return err
	}

	routingCtx, routingSpan := s.startObservationSpan(ctx, observability.TraceBoundaryRoutingResolve, observationOperationRouting, observationResultStart, "", nil)

	routingStarted := time.Now()
	routingResult, err := s.routingResolver.Resolve(routingCtx, routingRequest)

	routingDuration := time.Since(routingStarted)
	if err != nil {
		s.recordRoutingResolve(routingCtx, observationResultFailure, reasonClass(err), "", routingDuration)
		routingSpan.End(observationResultFailure, reasonClass(err))

		return err
	}

	routingResult = s.withEffectiveDefaultShard(routingResult)

	if !routingResult.Complete() {
		s.recordRoutingResolve(routingCtx, observationResultFailure, "incomplete", routingResult.RoutingSource, routingDuration)
		routingSpan.SetAttributes(map[string]string{
			obsFieldRoutingSource: routingResult.RoutingSource,
		})
		routingSpan.End(observationResultFailure, "incomplete")

		return errors.New("imap: incomplete routing result")
	}

	routingSpan.SetAttributes(map[string]string{
		obsFieldRoutingSource: routingResult.RoutingSource,
		obsFieldShardTag:      routingResult.ShardTag,
	})
	s.recordRoutingResolve(routingCtx, observationResultOK, "", routingResult.RoutingSource, routingDuration)
	routingSpan.End(observationResultOK, "")

	if err := s.waitForPlacementGate(ctx, routingResult); err != nil {
		return err
	}

	selectCtx, selectSpan := s.startObservationSpan(ctx, observability.TraceBoundaryBackendSelect, observationOperationBackendSelect, observationResultStart, "", map[string]string{
		obsFieldShardTag: routingResult.ShardTag,
	})

	selectStarted := time.Now()
	lease, err := s.placementService.PlaceSession(selectCtx, s.sessionPlacementRequest(routingResult))

	selectDuration := time.Since(selectStarted)
	if err != nil {
		s.recordBackendSelect(selectCtx, observationResultFailure, reasonClass(err), routingResult.ShardTag, selectDuration)
		selectSpan.End(observationResultFailure, reasonClass(err))

		return err
	}

	affinity := lease.Affinity()
	binding := lease.Binding()
	backendResult := lease.Backend()
	selectedShardTag := binding.ShardTag
	bindingReason := observability.BackendBindingReasonClass(string(binding.Source))

	s.recordAffinityOpen(ctx, observationResultOK, bindingReason, string(binding.Source), selectedShardTag, binding.BackendNode)

	selectSpan.SetAttributes(map[string]string{
		obsFieldBackendIdentifier: backendResult.Backend.Identifier,
		obsFieldBackendNode:       backendResult.Backend.BackendNode,
		obsFieldShardTag:          selectedShardTag,
	})
	s.recordSessionAttach(selectCtx, observationResultOK, bindingReason, backendResult.Backend.Identifier, backendResult.Backend.BackendNode, selectedShardTag)

	s.recordBackendSelectWithNode(selectCtx, observationResultOK, bindingReason, selectedShardTag, backendResult.Backend.BackendNode, time.Since(selectStarted))
	selectSpan.End(observationResultOK, bindingReason)

	s.placement = Placement{
		AuthResult:       cloneAuthResult(result),
		Routing:          routingResult.Clone(),
		Affinity:         affinity,
		Backend:          backendResult,
		Binding:          binding,
		SelectedShardTag: selectedShardTag,
	}
	s.placementLease = lease
	s.placed = true

	return nil
}

// waitForPlacementGate applies the shared user-hold gate before runtime placement reads.
func (s *Session) waitForPlacementGate(ctx context.Context, result routing.RoutingResult) error {
	if s.placementGate == nil {
		return nil
	}

	_, err := s.placementGate.WaitForPlacement(ctx, runtimectl.PlacementGateRequest{
		Key: runtimectl.UserKey{
			Tenant:   normalizedRoutingFact(result.Tenant),
			UserHash: normalizedAccount(result.AccountKey),
		},
		Protocol:     protocolIMAP,
		ListenerName: s.context.ListenerName,
		ServiceName:  s.context.ServiceName,
	})

	return err
}

// withEffectiveDefaultShard fills an omitted route shard from the immutable config snapshot.
func (s *Session) withEffectiveDefaultShard(result routing.RoutingResult) routing.RoutingResult {
	if normalizedRoutingFact(result.ShardTag) != "" {
		return result
	}

	result.ShardTag = s.context.DefaultShard

	return result
}

// routingRequest builds the side-effect-free routing input from authenticated facts.
func (s *Session) routingRequest(
	credentials *frontendCredentials,
	result nauthilus.AuthResult,
) (routing.RoutingRequest, error) {
	account, err := authbinding.CanonicalAccount(result.Account)
	if err != nil {
		return routing.RoutingRequest{}, errors.New("imap: authenticated account unavailable")
	}

	clientIP, _ := splitSessionAddr(s.context.RemoteAddr)
	loginName := account

	if credentials != nil {
		loginName = normalizedRoutingFact(credentials.Username())
	}

	return routing.RoutingRequest{
		Tenant:            normalizedRoutingFact(s.context.DefaultTenant),
		Protocol:          protocolIMAP,
		ListenerName:      s.context.ListenerName,
		ServiceName:       s.context.ServiceName,
		BackendPool:       s.context.BackendPool,
		LoginName:         loginName,
		NormalizedAccount: account,
		AuthAttributes:    cloneStringSlices(result.Attributes),
		ClientIP:          clientIP,
	}, nil
}

// sessionPlacementRequest builds the shared placement-domain input.
func (s *Session) sessionPlacementRequest(result routing.RoutingResult) placement.SessionRequest {
	ttl := result.TTL
	if ttl <= 0 {
		ttl = s.context.SessionLeaseTTL
	}

	return placement.SessionRequest{
		Key: state.AffinityKey{
			Tenant:     normalizedRoutingFact(result.Tenant),
			AccountKey: normalizedAccount(result.AccountKey),
		},
		SessionID:          s.context.ID,
		Protocol:           protocolIMAP,
		BackendPool:        s.context.BackendPool,
		ShardTag:           normalizedRoutingFact(result.ShardTag),
		ListenerName:       s.context.ListenerName,
		ServiceName:        s.context.ServiceName,
		DirectorInstanceID: s.context.DirectorInstanceID,
		HolderKind:         state.HolderKindSession,
		LeaseTTL:           ttl,
		IdleGrace:          s.context.SessionIdleGrace,
		RetentionTTL:       s.context.BackendRetentionTTL,
	}
}

// normalizedAccount returns the canonical account key used for routing and affinity.
func normalizedAccount(value string) string {
	return strings.ToLower(normalizedRoutingFact(value))
}

// normalizedRoutingFact trims a routing fact without exposing it in errors.
func normalizedRoutingFact(value string) string {
	return strings.TrimSpace(value)
}

// splitSessionAddr extracts host and port from TCP-style session addresses.
func splitSessionAddr(addr net.Addr) (string, string) {
	if addr == nil {
		return "", ""
	}

	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "", ""
	}

	return host, port
}

// cloneAuthResult returns detached auth result attributes for placement retention.
func cloneAuthResult(result nauthilus.AuthResult) nauthilus.AuthResult {
	result.Attributes = cloneStringSlices(result.Attributes)

	return result
}

// ensurePlacementDependencies verifies that successful auth can continue into placement.
func (s *Session) ensurePlacementDependencies() error {
	if s.routingResolver == nil {
		return errors.New("imap: routing resolver unavailable")
	}

	if s.placementService == nil {
		return errors.New("imap: placement service unavailable")
	}

	return nil
}

// transitionAuthenticatedSession connects, authenticates to the backend and enters proxy mode.
func (s *Session) transitionAuthenticatedSession(
	ctx context.Context,
	tag string,
	credentials *frontendCredentials,
) (commandOutcome, error) {
	connectCtx, connectSpan := s.startObservationSpan(ctx, observability.TraceBoundaryBackendConnect, observationOperationBackendConnect, observationResultStart, "", map[string]string{
		obsFieldBackendIdentifier: s.placement.Backend.Backend.Identifier,
		obsFieldShardTag:          s.placement.SelectedShardTag,
	})

	connectStarted := time.Now()
	connection, err := s.backendConnector.Connect(connectCtx, s.sessionBackendConnectRequest())

	connectDuration := time.Since(connectStarted)
	if err != nil {
		connectReason := reasonClass(err)
		s.recordBackendConnect(connectCtx, observationResultFailure, connectReason, connectDuration)
		connectSpan.End(observationResultFailure, connectReason)
		_ = s.closePlacedSession(context.Background())

		return commandOutcome{}, s.writeTagged(tag, responseNo, authUnavailableText)
	}

	s.recordBackendConnect(connectCtx, observationResultOK, "", connectDuration)

	backendCredentials, err := credentials.BackendCredentials(s.placement.AuthResult.Account)
	if err != nil {
		s.recordBackendAuth(connectCtx, observationResultFailure, reasonClass(err), credentials.Mechanism().Normalized())
		connectSpan.End(observationResultFailure, reasonClass(err))

		_ = connection.Conn().Close()
		_ = s.closePlacedSession(context.Background())

		return commandOutcome{}, s.writeTagged(tag, responseNo, authUnavailableText)
	}

	if err := AuthenticateBackend(connection, s.placement.Backend.Backend, backendCredentials); err != nil {
		s.recordBackendAuth(connectCtx, observationResultFailure, reasonClass(err), credentials.Mechanism().Normalized())
		connectSpan.End(observationResultFailure, reasonClass(err))

		_ = connection.Conn().Close()
		_ = s.closePlacedSession(context.Background())

		return commandOutcome{}, s.writeTagged(tag, responseNo, authUnavailableText)
	}

	s.recordBackendAuth(connectCtx, observationResultOK, "", credentials.Mechanism().Normalized())
	connectSpan.End(observationResultOK, "")

	credentials.Clear()

	if err := s.writeTagged(tag, responseOK, authSuccessText); err != nil {
		_ = connection.Conn().Close()
		_ = s.closePlacedSession(context.Background())

		return commandOutcome{}, err
	}

	if err := s.writer.Flush(); err != nil {
		_ = connection.Conn().Close()
		_ = s.closePlacedSession(context.Background())

		return commandOutcome{}, err
	}

	s.authenticated = true

	handoff := s.BufferedProxyHandoff()

	unregister := s.registerLocalProxySession(handoff.Frontend(), connection.Conn())
	defer unregister()

	proxyCtx, proxySpan := s.startObservationSpan(ctx, observability.TraceBoundaryProxyPipe, observationOperationProxy, observationResultStart, "", map[string]string{
		obsFieldBackendIdentifier: s.placement.Backend.Backend.Identifier,
		obsFieldShardTag:          s.placement.SelectedShardTag,
	})
	_, err = s.proxyRunner.Run(proxyCtx, proxy.PipeConfig{
		Frontend:          handoff.Frontend(),
		Backend:           connection.Conn(),
		BufferedToBackend: handoff.Buffered(),
		BufferedToClient:  connection.Buffered(),
		IdleTimeout:       s.context.ProxyIdleTimeout,
		HeartbeatInterval: s.proxyHeartbeatInterval(),
		Lease:             s.proxyLease(),
		Observability:     s.observability,
	})
	proxySpan.End(resultLabel(err), reasonClass(err))

	return commandOutcome{closeSession: true, flushed: true}, err
}

// sessionBackendConnectRequest carries selected backend and effective frontend tuple.
func (s *Session) sessionBackendConnectRequest() backend.ConnectRequest {
	return backend.ConnectRequest{
		Target:        s.placement.Backend.Backend,
		Timeout:       s.context.BackendConnectTimeout,
		Purpose:       backend.ConnectPurposeSession,
		Observability: s.observability,
		ProxyAddresses: &backend.ProxyAddresses{
			Source:      s.context.RemoteAddr,
			Destination: s.context.LocalAddr,
		},
	}
}

// registerLocalProxySession exposes a local stream handle for runtime control actions.
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
		SessionID:         s.context.ID,
		ListenerName:      s.context.ListenerName,
		Tenant:            s.placementAffinityKey().Tenant,
		UserHash:          s.placementAffinityKey().AccountKey,
		BackendIdentifier: s.placement.Backend.Backend.Identifier,
		DirectorInstance:  s.context.DirectorInstanceID,
	}, handle)
	if err != nil {
		return func() {}
	}

	return unregister
}

// closePlacedSession closes a Redis lease when backend setup fails before proxy mode owns it.
func (s *Session) closePlacedSession(ctx context.Context) error {
	if !s.placed {
		return nil
	}

	var err error
	if s.placementLease != nil {
		err = s.placementLease.Close(ctx)
		affinity := s.placementLease.Affinity()
		s.recordSessionClose(ctx, resultLabel(err), closeReasonClass(err, affinity))
	} else if s.sessionStore != nil {
		var affinity state.AffinityRecord

		affinity, err = s.sessionStore.CloseSession(ctx, s.placementAffinityKey(), s.context.ID)
		s.recordSessionClose(ctx, resultLabel(err), closeReasonClass(err, affinity))
	} else {
		s.recordSessionClose(ctx, resultLabel(err), reasonClass(err))
	}

	return err
}

// proxyLease builds the state lifecycle hook used by transparent proxy mode.
func (s *Session) proxyLease() proxy.LeaseLifecycle {
	if !s.placed {
		return nil
	}

	if s.placementLease != nil {
		return &placementLeaseLifecycle{
			lease:       s.placementLease,
			ttl:         s.context.SessionLeaseTTL,
			recordClose: s.recordSessionClose,
		}
	}

	if s.sessionStore == nil {
		return nil
	}

	return &sessionLeaseLifecycle{
		store:       s.sessionStore,
		key:         s.placementAffinityKey(),
		sessionID:   s.context.ID,
		ttl:         s.context.SessionLeaseTTL,
		recordClose: s.recordSessionClose,
	}
}

// proxyHeartbeatInterval derives a stable heartbeat cadence below the lease TTL.
func (s *Session) proxyHeartbeatInterval() time.Duration {
	ttl := s.context.SessionLeaseTTL
	if ttl <= 0 {
		ttl = s.context.ProxyIdleTimeout
	}

	if ttl <= 0 {
		return time.Minute
	}

	interval := ttl / 2
	if interval <= 0 {
		return ttl
	}

	return interval
}

// placementAffinityKey returns the Redis key for the opened session lease.
func (s *Session) placementAffinityKey() state.AffinityKey {
	if s.placement.Affinity.Key != (state.AffinityKey{}) {
		return s.placement.Affinity.Key
	}

	return state.AffinityKey{
		Tenant:     normalizedRoutingFact(s.placement.Routing.Tenant),
		AccountKey: normalizedAccount(s.placement.Routing.AccountKey),
	}
}

// sessionLeaseLifecycle adapts Redis session methods to the proxy lifecycle.
type sessionLeaseLifecycle struct {
	store       state.SessionStore
	key         state.AffinityKey
	sessionID   string
	ttl         time.Duration
	recordClose func(context.Context, string, string)
	closeOnce   sync.Once
	closeErr    error
}

// placementLeaseLifecycle adapts placement leases to the proxy lifecycle.
type placementLeaseLifecycle struct {
	lease       placement.LeaseHandle
	ttl         time.Duration
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
		return errors.New("imap: ambiguous heartbeat control action")
	}
}

// Close releases the placement lease at proxy end.
func (l *placementLeaseLifecycle) Close(ctx context.Context) error {
	l.closeOnce.Do(func() {
		l.closeErr = l.lease.Close(ctx)
		if l.recordClose != nil {
			l.recordClose(ctx, resultLabel(l.closeErr), closeReasonClass(l.closeErr, l.lease.Affinity()))
		}
	})

	return l.closeErr
}

// Heartbeat refreshes the active session lease while proxy mode is running.
func (l *sessionLeaseLifecycle) Heartbeat(ctx context.Context) error {
	record, err := l.store.HeartbeatSession(ctx, l.key, l.sessionID, l.ttl)
	if err != nil {
		return err
	}

	switch record.ControlAction {
	case "", state.ControlActionNone:
		return nil
	case state.ControlActionKick, state.ControlActionDrain, state.ControlActionMoveGenerationChanged:
		return proxy.NewControlActionError(string(record.ControlAction))
	default:
		return errors.New("imap: ambiguous heartbeat control action")
	}

}

// Close releases the active session lease at proxy end.
func (l *sessionLeaseLifecycle) Close(ctx context.Context) error {
	l.closeOnce.Do(func() {
		var affinity state.AffinityRecord

		affinity, l.closeErr = l.store.CloseSession(ctx, l.key, l.sessionID)
		if l.recordClose != nil {
			l.recordClose(ctx, resultLabel(l.closeErr), closeReasonClass(l.closeErr, affinity))
		}
	})

	return l.closeErr
}
