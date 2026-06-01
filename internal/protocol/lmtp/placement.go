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

package lmtp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/observability"
	placementpkg "github.com/croessner/nauthilus-director/internal/placement"
	"github.com/croessner/nauthilus-director/internal/routing"
	runtimectl "github.com/croessner/nauthilus-director/internal/runtime"
	"github.com/croessner/nauthilus-director/internal/state"
)

const (
	affinityStatusReused    = "reused"
	defaultDeliveryLeaseTTL = 5 * time.Minute
	deliveryHoldIDBytes     = 16
	deliveryStatusCreated   = "created"
	recipientDefaultTenant  = "default"
	recipientLookupMethod   = "recipient_lookup"
)

var errDifferentBackendRecipient = errors.New("lmtp: recipient routes to different backend")

// RecipientPlacement records one accepted recipient's routing and delivery hold.
type RecipientPlacement struct {
	Recipient        RecipientPath
	AccountKey       string
	Tenant           string
	Routing          routing.RoutingResult
	Affinity         state.AffinityRecord
	Backend          backend.SelectionResult
	Binding          placementpkg.BackendBinding
	SelectedShardTag string
	HoldID           string
	BackendCounted   bool
	hold             *deliveryHold
}

type deliveryHold struct {
	sessionID string
	lease     placementpkg.LeaseHandle
	cancel    context.CancelFunc
	closeOnce sync.Once
	done      chan struct{}
}

// handleRecipientPlacement resolves, routes and holds one recipient before acceptance.
func (s *Session) handleRecipientPlacement(ctx context.Context, recipient RecipientPath) (RecipientPlacement, error) {
	ctx = s.transactionContext(ctx)

	if !s.recipientPlacementRequired {
		return RecipientPlacement{Recipient: recipient}, nil
	}

	if err := s.ensureRecipientPlacementDependencies(); err != nil {
		return RecipientPlacement{}, err
	}

	lookupCtx, lookupSpan := s.startObservationSpan(ctx, observability.TraceBoundaryNauthilusAuth, recipientLookupMethod, lmtpObservationResultStart, "", map[string]string{
		lmtpObsFieldMechanism: recipientLookupMethod,
		lmtpObsFieldTransport: strings.ToLower(strings.TrimSpace(s.authorityTransport)),
	})
	lookupStarted := time.Now()
	identity, err := s.lookupRecipientIdentity(lookupCtx, recipient.LookupName)

	lookupDuration := time.Since(lookupStarted)
	if err != nil {
		s.recordAuthorityLookup(lookupCtx, lmtpObservationResultFailure, lmtpReasonAuth, lookupDuration)
		lookupSpan.End(lmtpObservationResultFailure, lmtpReasonAuth)

		return RecipientPlacement{}, err
	}

	s.recordAuthorityLookup(lookupCtx, lmtpObservationResultOK, lmtpReasonOK, lookupDuration)
	lookupSpan.End(lmtpObservationResultOK, lmtpReasonOK)

	routeCtx, routeSpan := s.startObservationSpan(ctx, observability.TraceBoundaryRoutingResolve, lmtpObservationOperationRouting, lmtpObservationResultStart, "", nil)
	routeStarted := time.Now()
	routingResult, err := s.resolveRecipientRoute(routeCtx, recipient, identity)

	routeDuration := time.Since(routeStarted)
	if err != nil {
		s.recordRoutingResolve(routeCtx, lmtpObservationResultFailure, lmtpReasonRouting, "", routeDuration)
		routeSpan.End(lmtpObservationResultFailure, lmtpReasonRouting)

		return RecipientPlacement{}, err
	}

	routeSpan.SetAttributes(map[string]string{
		lmtpObsFieldShardTag: routingResult.ShardTag,
	})
	s.recordRoutingResolve(routeCtx, lmtpObservationResultOK, lmtpReasonOK, routingResult.ShardTag, routeDuration)
	routeSpan.End(lmtpObservationResultOK, lmtpReasonOK)

	if err := s.waitForPlacementGate(ctx, routingResult); err != nil {
		return RecipientPlacement{}, err
	}

	selectCtx, selectSpan := s.startObservationSpan(ctx, observability.TraceBoundaryBackendSelect, lmtpObservationOperationBackendSelect, lmtpObservationResultStart, "", map[string]string{
		lmtpObsFieldShardTag: routingResult.ShardTag,
	})
	selectStarted := time.Now()

	placementRequest, err := s.deliveryPlacementRequest(routingResult)
	if err != nil {
		s.recordBackendSelect(selectCtx, lmtpObservationResultFailure, lmtpReasonClass(err), routingResult.ShardTag, time.Since(selectStarted))
		selectSpan.End(lmtpObservationResultFailure, lmtpReasonClass(err))

		return RecipientPlacement{}, err
	}

	lease, err := s.placementService.PlaceDeliveryHold(selectCtx, placementRequest)

	selectDuration := time.Since(selectStarted)
	if err != nil {
		s.recordBackendSelect(selectCtx, lmtpObservationResultFailure, lmtpReasonClass(err), routingResult.ShardTag, selectDuration)
		selectSpan.End(lmtpObservationResultFailure, lmtpReasonClass(err))

		return RecipientPlacement{}, err
	}

	placement := s.recipientPlacementFromLease(ctx, recipient, routingResult, lease)

	if !s.transaction.acceptsConcreteBackend(placement.Backend.Backend) {
		_ = s.closeRecipientPlacement(ctx, &placement)
		s.recordBackendSelect(selectCtx, lmtpObservationResultTempfail, lmtpReasonSameBackend, placement.SelectedShardTag, time.Since(selectStarted))
		selectSpan.End(lmtpObservationResultTempfail, lmtpReasonSameBackend)

		return RecipientPlacement{}, errDifferentBackendRecipient
	}

	if err := s.accountRecipientBackend(ctx, &placement); err != nil {
		_ = s.closeRecipientPlacement(ctx, &placement)
		s.recordBackendSelect(selectCtx, lmtpObservationResultFailure, lmtpReasonClass(err), placement.SelectedShardTag, time.Since(selectStarted))
		selectSpan.End(lmtpObservationResultFailure, lmtpReasonClass(err))

		return RecipientPlacement{}, err
	}

	if !s.transaction.acceptsConcreteBackend(placement.Backend.Backend) {
		_ = s.closeRecipientPlacement(ctx, &placement)
		s.recordBackendSelect(selectCtx, lmtpObservationResultTempfail, lmtpReasonSameBackend, placement.SelectedShardTag, time.Since(selectStarted))
		selectSpan.End(lmtpObservationResultTempfail, lmtpReasonSameBackend)

		return RecipientPlacement{}, errDifferentBackendRecipient
	}

	selectSpan.SetAttributes(map[string]string{
		lmtpObsFieldBackendIdentifier: placement.Backend.Backend.Identifier,
		lmtpObsFieldBackendNode:       placement.Backend.Backend.BackendNode,
		lmtpObsFieldShardTag:          placement.SelectedShardTag,
	})

	selectionReason := observability.BackendBindingReasonClass(string(placement.Binding.Source))

	s.recordBackendSelectWithNode(selectCtx, lmtpObservationResultOK, selectionReason, placement.SelectedShardTag, placement.Backend.Backend.BackendNode, time.Since(selectStarted))
	selectSpan.End(lmtpObservationResultOK, selectionReason)

	return placement, nil
}

// ensureRecipientPlacementDependencies checks that production recipient routing can run.
func (s *Session) ensureRecipientPlacementDependencies() error {
	if s.identityLookuper == nil {
		return errors.New("lmtp: identity lookup unavailable")
	}

	if s.routingResolver == nil {
		return errors.New("lmtp: routing resolver unavailable")
	}

	if s.placementService == nil {
		return errors.New("lmtp: placement service unavailable")
	}

	return nil
}

// lookupRecipientIdentity asks Nauthilus for canonical account and routing facts.
func (s *Session) lookupRecipientIdentity(ctx context.Context, lookupName string) (nauthilus.AuthResult, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, defaultAuthTimeout(s.authTimeout))
	defer cancel()

	request := nauthilus.IdentityLookupRequest{Context: s.recipientLookupContext(lookupName)}

	result, err := s.identityLookuper.LookupIdentity(lookupCtx, request)
	if err != nil {
		return nauthilus.AuthResult{}, err
	}

	if result.Decision != nauthilus.DecisionAuthenticated {
		return nauthilus.AuthResult{}, errors.New("lmtp: recipient identity rejected")
	}

	if normalizedAccount(result.Account) == "" {
		return nauthilus.AuthResult{}, errors.New("lmtp: recipient account unavailable")
	}

	return result, nil
}

// recipientLookupContext builds the no-auth authority context for recipient lookup.
func (s *Session) recipientLookupContext(lookupName string) nauthilus.RequestContext {
	requestContext := s.nauthilusRequestContext()
	requestContext.Username = lookupName
	requestContext.Method = recipientLookupMethod

	clientIP, clientPort := splitAddr(s.conn.RemoteAddr())
	requestContext.ClientIP = clientIP
	requestContext.ClientPort = clientPort

	return requestContext
}

// resolveRecipientRoute maps identity facts through the director-owned routing resolver.
func (s *Session) resolveRecipientRoute(ctx context.Context, recipient RecipientPath, identity nauthilus.AuthResult) (routing.RoutingResult, error) {
	result, err := s.routingResolver.Resolve(ctx, routing.RoutingRequest{
		Tenant:            normalizedRoutingFact(s.defaultTenant),
		Protocol:          protocolLMTP,
		ListenerName:      s.listenerName,
		ServiceName:       s.serviceName,
		BackendPool:       s.backendPool,
		LoginName:         recipient.LookupName,
		NormalizedAccount: normalizedAccount(identity.Account),
		AuthAttributes:    cloneStringSlices(identity.Attributes),
		ClientIP:          clientIPFromAddr(s.conn.RemoteAddr()),
	})
	if err != nil {
		return routing.RoutingResult{}, err
	}

	result = s.withDefaultRecipientShard(result)
	if !result.Complete() {
		return routing.RoutingResult{}, errors.New("lmtp: incomplete recipient routing result")
	}

	return result, nil
}

// withDefaultRecipientShard fills omitted route shards from the immutable listener config.
func (s *Session) withDefaultRecipientShard(result routing.RoutingResult) routing.RoutingResult {
	if normalizedRoutingFact(result.ShardTag) != "" {
		return result
	}

	result.ShardTag = s.defaultShard

	return result
}

// waitForPlacementGate applies the shared user-hold gate before delivery placement reads.
func (s *Session) waitForPlacementGate(ctx context.Context, result routing.RoutingResult) error {
	if s.placementGate == nil {
		return nil
	}

	_, err := s.placementGate.WaitForPlacement(ctx, runtimectl.PlacementGateRequest{
		Key: runtimectl.UserKey{
			Tenant:   normalizedRoutingFact(result.Tenant),
			UserHash: normalizedAccount(result.AccountKey),
		},
		Protocol:     protocolLMTP,
		ListenerName: s.listenerName,
		ServiceName:  s.serviceName,
	})

	return err
}

// deliveryPlacementRequest builds the shared placement-domain input.
func (s *Session) deliveryPlacementRequest(result routing.RoutingResult) (placementpkg.DeliveryRequest, error) {
	holdID, err := newDeliveryHoldID()
	if err != nil {
		return placementpkg.DeliveryRequest{}, err
	}

	return placementpkg.DeliveryRequest{
		Key: state.AffinityKey{
			Tenant:     normalizedRoutingFact(result.Tenant),
			AccountKey: normalizedAccount(result.AccountKey),
		},
		SessionID:          holdID,
		Protocol:           protocolLMTP,
		BackendPool:        s.backendPool,
		ShardTag:           normalizedRoutingFact(result.ShardTag),
		ListenerName:       s.listenerName,
		ServiceName:        s.serviceName,
		DirectorInstanceID: s.directorInstanceID,
		HolderKind:         state.HolderKindDelivery,
		LeaseTTL:           s.sessionLeaseTTL,
		IdleGrace:          s.sessionIdleGrace,
		RetentionTTL:       s.backendRetentionTTL,
	}, nil
}

// recipientPlacementFromLease adapts a placement lease to LMTP transaction state.
func (s *Session) recipientPlacementFromLease(
	ctx context.Context,
	recipient RecipientPath,
	result routing.RoutingResult,
	lease placementpkg.LeaseHandle,
) RecipientPlacement {
	binding := lease.Binding()
	hold := s.startDeliveryHeartbeat(ctx, lease)

	return RecipientPlacement{
		Recipient:        recipient,
		AccountKey:       normalizedAccount(result.AccountKey),
		Tenant:           normalizedRoutingFact(result.Tenant),
		Routing:          result.Clone(),
		Affinity:         lease.Affinity(),
		Backend:          lease.Backend(),
		Binding:          binding,
		SelectedShardTag: binding.ShardTag,
		HoldID:           lease.SessionID(),
		hold:             hold,
	}
}

// accountRecipientBackend attaches exactly one delivery hold to backend active-use state.
func (s *Session) accountRecipientBackend(ctx context.Context, placement *RecipientPlacement) error {
	if placement == nil || placement.hold == nil || placement.BackendCounted {
		return nil
	}

	if s.transaction.backendAccountedHoldID != "" {
		return nil
	}

	if err := placement.hold.lease.AttachBackend(ctx); err != nil {
		return err
	}

	placement.Backend = placement.hold.lease.Backend()
	placement.BackendCounted = true
	s.transaction.backendAccountedHoldID = placement.HoldID

	return nil
}

// startDeliveryHeartbeat refreshes a delivery hold until it is closed.
func (s *Session) startDeliveryHeartbeat(ctx context.Context, lease placementpkg.LeaseHandle) *deliveryHold {
	if ctx == nil {
		ctx = context.Background()
	}

	heartbeatCtx, cancel := context.WithCancel(ctx)
	hold := &deliveryHold{
		sessionID: lease.SessionID(),
		lease:     lease,
		cancel:    cancel,
		done:      make(chan struct{}),
	}

	go s.heartbeatDeliveryHold(heartbeatCtx, hold)

	return hold
}

// heartbeatDeliveryHold periodically refreshes one delivery-scoped lease.
func (s *Session) heartbeatDeliveryHold(ctx context.Context, hold *deliveryHold) {
	defer close(hold.done)

	ticker := time.NewTicker(heartbeatInterval(s.sessionLeaseTTL))
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = hold.lease.Heartbeat(ctx, s.sessionLeaseTTL)
		}
	}
}

// closeRecipientPlacement releases a placement through its shared placement lease.
func (s *Session) closeRecipientPlacement(ctx context.Context, placement *RecipientPlacement) error {
	if placement == nil || placement.hold == nil {
		return nil
	}

	var closeErr error

	placement.hold.closeOnce.Do(func() {
		placement.hold.cancel()
		<-placement.hold.done
		closeErr = placement.hold.lease.Close(ctx)
		affinity := placement.hold.lease.Affinity()
		s.recordDeliveryHoldClose(ctx, lmtpResultLabel(closeErr), lmtpCloseReasonClass(closeErr, affinity), placement.SelectedShardTag, placement.Binding.BackendNode)
		if placement.BackendCounted && placement.HoldID == s.transaction.backendAccountedHoldID {
			s.transaction.backendAccountedHoldID = ""
			placement.BackendCounted = false
		}
	})

	return closeErr
}

// closeTransactionHolds releases all accepted recipient holds for the transaction.
func (s *Session) closeTransactionHolds(ctx context.Context) {
	for index := range s.transaction.recipients {
		_ = s.closeRecipientPlacement(ctx, &s.transaction.recipients[index])
	}
}

// newDeliveryHoldID creates an opaque identifier for a delivery-scoped hold.
func newDeliveryHoldID() (string, error) {
	var raw [deliveryHoldIDBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("lmtp: create delivery hold id: %w", err)
	}

	return hex.EncodeToString(raw[:]), nil
}

// normalizedAccount returns the canonical account key used for routing and affinity.
func normalizedAccount(value string) string {
	return strings.ToLower(normalizedRoutingFact(value))
}

// normalizedRoutingFact trims a routing fact without exposing it in errors.
func normalizedRoutingFact(value string) string {
	return strings.TrimSpace(value)
}

// cloneStringSlices returns detached routing attributes from authority results.
func cloneStringSlices(values map[string][]string) map[string][]string {
	if values == nil {
		return nil
	}

	cloned := make(map[string][]string, len(values))
	for key, value := range values {
		cloned[key] = append([]string(nil), value...)
	}

	return cloned
}

// heartbeatInterval derives a stable heartbeat cadence below the lease TTL.
func heartbeatInterval(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		return time.Minute
	}

	interval := ttl / 2
	if interval <= 0 {
		return ttl
	}

	return interval
}

// splitAddr extracts host and port from TCP-style addresses.
func splitAddr(addr net.Addr) (string, string) {
	if addr == nil {
		return "", ""
	}

	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "", ""
	}

	return host, port
}

// clientIPFromAddr returns only the host part used by routing requests.
func clientIPFromAddr(addr net.Addr) string {
	host, _ := splitAddr(addr)

	return host
}

// defaultLookupTenant returns the configured tenant fallback for recipient lookup.
func defaultLookupTenant(value string) string {
	if normalized := normalizedRoutingFact(value); normalized != "" {
		return normalized
	}

	return recipientDefaultTenant
}

// defaultLookupShard returns the configured shard fallback for incomplete routes.
func defaultLookupShard(value string) string {
	if normalized := normalizedRoutingFact(value); normalized != "" {
		return normalized
	}

	return recipientDefaultTenant
}

// defaultDeliveryLease returns a conservative delivery hold lease.
func defaultDeliveryLease(value time.Duration) time.Duration {
	if value > 0 {
		return value
	}

	return defaultDeliveryLeaseTTL
}

// defaultDeliveryGrace returns the grace period for delivery hold affinity state.
func defaultDeliveryGrace(value time.Duration, lease time.Duration) time.Duration {
	if value >= 0 {
		return value
	}

	return defaultDeliveryLease(lease)
}
