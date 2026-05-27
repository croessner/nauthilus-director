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

		s.authenticated = true

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
	if s.authenticator == nil {
		return nauthilus.AuthResult{Decision: nauthilus.DecisionTemporaryFailure}, errors.New("imap: authenticator unavailable")
	}

	if credentials == nil {
		return nauthilus.AuthResult{Decision: nauthilus.DecisionTemporaryFailure}, errors.New("imap: credentials unavailable")
	}

	authCtx, cancel := s.authContext(ctx)
	defer cancel()

	method := credentials.Mechanism().Normalized()
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

	sessionRecord := s.sessionRecord(routingResult)

	affinity, err := s.sessionStore.OpenSession(ctx, sessionRecord)
	if err != nil {
		s.recordAffinityOpen(ctx, observationResultFailure, reasonClass(err), "", routingResult.ShardTag)

		return err
	}

	if affinity.Key == (state.AffinityKey{}) {
		affinity.Key = sessionRecord.Key
	}

	selectedShardTag := selectedAffinityShard(routingResult, affinity)

	s.recordAffinityOpen(ctx, observationResultOK, "", affinity.Status, selectedShardTag)

	selectionRequest := s.selectionRequest(routingResult, selectedShardTag, affinity)
	selectCtx, selectSpan := s.startObservationSpan(ctx, observability.TraceBoundaryBackendSelect, observationOperationBackendSelect, observationResultStart, "", map[string]string{
		obsFieldShardTag: selectedShardTag,
	})

	selectStarted := time.Now()
	backendResult, err := s.backendSelector.Select(selectCtx, selectionRequest)

	selectDuration := time.Since(selectStarted)
	if err != nil {
		s.recordBackendSelect(selectCtx, observationResultFailure, reasonClass(err), selectedShardTag, selectDuration)
		selectSpan.End(observationResultFailure, reasonClass(err))
		_, _ = s.sessionStore.CloseSession(context.Background(), sessionRecord.Key, s.context.ID)

		return err
	}

	backendResult, err = s.attachSelectedBackend(selectCtx, sessionRecord.Key, selectionRequest, backendResult)
	if err != nil {
		s.recordBackendSelect(selectCtx, observationResultFailure, reasonClass(err), selectedShardTag, time.Since(selectStarted))
		s.recordSessionAttach(selectCtx, observationResultFailure, reasonClass(err), backendResult.Backend.Identifier, selectedShardTag)
		selectSpan.SetAttributes(map[string]string{
			obsFieldBackendIdentifier: backendResult.Backend.Identifier,
			obsFieldShardTag:          selectedShardTag,
		})
		selectSpan.End(observationResultFailure, reasonClass(err))
		_, _ = s.sessionStore.CloseSession(context.Background(), sessionRecord.Key, s.context.ID)

		return err
	}

	selectSpan.SetAttributes(map[string]string{
		obsFieldBackendIdentifier: backendResult.Backend.Identifier,
		obsFieldShardTag:          selectedShardTag,
	})
	s.recordSessionAttach(selectCtx, observationResultOK, "", backendResult.Backend.Identifier, selectedShardTag)
	s.recordBackendSelect(selectCtx, observationResultOK, "", selectedShardTag, time.Since(selectStarted))
	selectSpan.End(observationResultOK, "")

	s.placement = Placement{
		AuthResult:       cloneAuthResult(result),
		Routing:          routingResult.Clone(),
		Affinity:         affinity,
		Backend:          backendResult,
		SelectedShardTag: selectedShardTag,
	}
	s.placed = true

	return nil
}

// attachSelectedBackend registers backend counts and retries same-shard placement on attach races.
func (s *Session) attachSelectedBackend(
	ctx context.Context,
	key state.AffinityKey,
	request backend.SelectionRequest,
	initial backend.SelectionResult,
) (backend.SelectionResult, error) {
	if _, err := s.sessionStore.AttachSelectedBackend(ctx, state.SessionBackendAttachment{
		Key:               key,
		SessionID:         s.context.ID,
		BackendIdentifier: initial.Backend.Identifier,
		MaxConnections:    initial.Backend.MaxConnections,
	}); err != nil {
		retrySelector, ok := s.backendSelector.(interface {
			RetryAfterAttachFailure(context.Context, backend.SelectionRequest, string) (backend.SelectionResult, error)
		})
		if !ok {
			return backend.SelectionResult{}, err
		}

		retry, retryErr := retrySelector.RetryAfterAttachFailure(ctx, request, initial.Backend.Identifier)
		if retryErr != nil {
			return backend.SelectionResult{}, retryErr
		}

		if _, attachErr := s.sessionStore.AttachSelectedBackend(ctx, state.SessionBackendAttachment{
			Key:               key,
			SessionID:         s.context.ID,
			BackendIdentifier: retry.Backend.Identifier,
			MaxConnections:    retry.Backend.MaxConnections,
		}); attachErr != nil {
			return backend.SelectionResult{}, attachErr
		}

		return retry, nil
	}

	return initial, nil
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
	account := normalizedAccount(result.Account)
	if account == "" && credentials != nil {
		account = normalizedAccount(credentials.Username())
	}

	if account == "" {
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

// sessionRecord builds the Redis session-open request after logical routing completes.
func (s *Session) sessionRecord(result routing.RoutingResult) state.SessionRecord {
	ttl := result.TTL
	if ttl <= 0 {
		ttl = s.context.SessionLeaseTTL
	}

	return state.SessionRecord{
		ID: s.context.ID,
		Key: state.AffinityKey{
			Tenant:     normalizedRoutingFact(result.Tenant),
			AccountKey: normalizedAccount(result.AccountKey),
		},
		Protocol:           protocolIMAP,
		ListenerName:       s.context.ListenerName,
		ServiceName:        s.context.ServiceName,
		ShardTag:           normalizedRoutingFact(result.ShardTag),
		DirectorInstanceID: s.context.DirectorInstanceID,
		LeaseTTL:           ttl,
		IdleGrace:          s.context.SessionIdleGrace,
	}
}

// selectionRequest builds the backend selector input from the final active shard.
func (s *Session) selectionRequest(result routing.RoutingResult, shardTag string, affinity state.AffinityRecord) backend.SelectionRequest {
	return backend.SelectionRequest{
		AccountKey:              normalizedAccount(result.AccountKey),
		Tenant:                  normalizedRoutingFact(result.Tenant),
		ShardTag:                normalizedRoutingFact(shardTag),
		Protocol:                protocolIMAP,
		BackendPool:             s.context.BackendPool,
		ActiveAffinity:          affinityActiveForSelection(result, affinity),
		PinnedBackendIdentifier: normalizedRoutingFact(affinity.BackendIdentifier),
	}
}

// selectedAffinityShard applies active affinity precedence over initial placement.
func selectedAffinityShard(result routing.RoutingResult, affinity state.AffinityRecord) string {
	if shardTag := normalizedRoutingFact(affinity.ShardTag); shardTag != "" {
		return shardTag
	}

	return normalizedRoutingFact(result.ShardTag)
}

// affinityActiveForSelection reports whether Redis returned an existing pin.
func affinityActiveForSelection(result routing.RoutingResult, affinity state.AffinityRecord) bool {
	switch affinity.Status {
	case "created", "":
		return normalizedRoutingFact(affinity.ShardTag) != "" && normalizedRoutingFact(affinity.ShardTag) != normalizedRoutingFact(result.ShardTag)
	default:
		return affinity.Present
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

	if s.sessionStore == nil {
		return errors.New("imap: session store unavailable")
	}

	if s.backendSelector == nil {
		return errors.New("imap: backend selector unavailable")
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
	connection, err := s.backendConnector.Connect(connectCtx, s.placement.Backend.Backend, s.context.BackendConnectTimeout)

	connectDuration := time.Since(connectStarted)
	if err != nil {
		s.recordBackendConnect(connectCtx, observationResultFailure, reasonBackendConnect, connectDuration)
		connectSpan.End(observationResultFailure, reasonBackendConnect)
		_ = s.closePlacedSession(context.Background())

		return commandOutcome{}, s.writeTagged(tag, responseNo, authUnavailableText)
	}

	s.recordBackendConnect(connectCtx, observationResultOK, "", connectDuration)

	if err := AuthenticateBackend(connection, s.placement.Backend.Backend, credentials); err != nil {
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
	if s.sessionStore == nil || !s.placed {
		return nil
	}

	_, err := s.sessionStore.CloseSession(ctx, s.placementAffinityKey(), s.context.ID)
	s.recordSessionClose(ctx, resultLabel(err), reasonClass(err))

	return err
}

// proxyLease builds the state lifecycle hook used by transparent proxy mode.
func (s *Session) proxyLease() proxy.LeaseLifecycle {
	if s.sessionStore == nil || !s.placed {
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
		_, l.closeErr = l.store.CloseSession(ctx, l.key, l.sessionID)
		if l.recordClose != nil {
			l.recordClose(ctx, resultLabel(l.closeErr), reasonClass(l.closeErr))
		}
	})

	return l.closeErr
}
