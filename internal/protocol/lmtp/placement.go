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
	"github.com/croessner/nauthilus-director/internal/routing"
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
	SelectedShardTag string
	HoldID           string
	BackendCounted   bool
	hold             *deliveryHold
	selectionRequest backend.SelectionRequest
}

type deliveryHold struct {
	key       state.AffinityKey
	sessionID string
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

	backendPin, err := s.lookupOperatorBackendPin(ctx, routingResult)
	if err != nil {
		return RecipientPlacement{}, err
	}

	selectCtx, selectSpan := s.startObservationSpan(ctx, observability.TraceBoundaryBackendSelect, lmtpObservationOperationBackendSelect, lmtpObservationResultStart, "", map[string]string{
		lmtpObsFieldShardTag: routingResult.ShardTag,
	})
	selectStarted := time.Now()
	initialRequest, initial, err := s.selectRecipientBackend(selectCtx, routingResult, state.AffinityRecord{}, backendPin)

	selectDuration := time.Since(selectStarted)
	if err != nil {
		s.recordBackendSelect(selectCtx, lmtpObservationResultFailure, lmtpReasonClass(err), routingResult.ShardTag, selectDuration)
		selectSpan.End(lmtpObservationResultFailure, lmtpReasonClass(err))

		return RecipientPlacement{}, err
	}

	placement, err := s.openRecipientHold(ctx, recipient, routingResult, initialRequest, initial, backendPin)
	if err != nil {
		s.recordBackendSelect(selectCtx, lmtpObservationResultFailure, lmtpReasonClass(err), routingResult.ShardTag, time.Since(selectStarted))
		selectSpan.End(lmtpObservationResultFailure, lmtpReasonClass(err))

		return RecipientPlacement{}, err
	}

	if !s.transaction.acceptsBackend(placement.Backend.Backend.Identifier) {
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

	if !s.transaction.acceptsBackend(placement.Backend.Backend.Identifier) {
		_ = s.closeRecipientPlacement(ctx, &placement)
		s.recordBackendSelect(selectCtx, lmtpObservationResultTempfail, lmtpReasonSameBackend, placement.SelectedShardTag, time.Since(selectStarted))
		selectSpan.End(lmtpObservationResultTempfail, lmtpReasonSameBackend)

		return RecipientPlacement{}, errDifferentBackendRecipient
	}

	selectSpan.SetAttributes(map[string]string{
		lmtpObsFieldBackendIdentifier: placement.Backend.Backend.Identifier,
		lmtpObsFieldShardTag:          placement.SelectedShardTag,
	})

	selectionReason := lmtpReasonOK
	if placement.Backend.Reason == lmtpReasonOperatorPin {
		selectionReason = placement.Backend.Reason
	}

	s.recordBackendSelect(selectCtx, lmtpObservationResultOK, selectionReason, placement.SelectedShardTag, time.Since(selectStarted))
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

	if s.sessionStore == nil {
		return errors.New("lmtp: session store unavailable")
	}

	if s.backendSelector == nil {
		return errors.New("lmtp: backend selector unavailable")
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
	context := s.nauthilusRequestContext()
	context.Username = lookupName
	context.Method = recipientLookupMethod

	clientIP, clientPort := splitAddr(s.conn.RemoteAddr())
	context.ClientIP = clientIP
	context.ClientPort = clientPort

	return context
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

// selectRecipientBackend selects through the shared runtime-aware backend selector.
func (s *Session) selectRecipientBackend(
	ctx context.Context,
	result routing.RoutingResult,
	affinity state.AffinityRecord,
	backendPin state.UserBackendPinRecord,
) (backend.SelectionRequest, backend.SelectionResult, error) {
	selectedShard := s.selectedPlacementShard(result, affinity, backendPin)
	operatorBackend := s.operatorBackendPinIdentifier(backendPin, selectedShard, affinity)
	request := s.selectionRequest(result, selectedShard, affinity, operatorBackend)

	selected, err := s.backendSelector.Select(ctx, request)

	return request, selected, err
}

// openRecipientHold creates and attaches a delivery-scoped active-affinity hold.
func (s *Session) openRecipientHold(
	ctx context.Context,
	recipient RecipientPath,
	result routing.RoutingResult,
	initialRequest backend.SelectionRequest,
	initial backend.SelectionResult,
	backendPin state.UserBackendPinRecord,
) (RecipientPlacement, error) {
	holdID, err := newDeliveryHoldID()
	if err != nil {
		return RecipientPlacement{}, err
	}

	record := s.deliverySessionRecord(result, holdID, backendPin)

	affinity, err := s.sessionStore.OpenSession(ctx, record)
	if err != nil {
		return RecipientPlacement{}, err
	}

	if affinity.Key == (state.AffinityKey{}) {
		affinity.Key = record.Key
	}

	selected := initial
	selectedShard := s.selectedPlacementShard(result, affinity, backendPin)

	operatorBackend := s.operatorBackendPinIdentifier(backendPin, selectedShard, affinity)

	selectionRequest := s.selectionRequest(result, selectedShard, affinity, operatorBackend)
	if !samePlacementSelectionRequest(initialRequest, selectionRequest) {
		selected, err = s.backendSelector.Select(ctx, selectionRequest)
		if err != nil {
			_, _ = s.sessionStore.CloseSession(context.Background(), record.Key, holdID)

			return RecipientPlacement{}, err
		}
	}

	hold := s.startDeliveryHeartbeat(ctx, record.Key, holdID)

	return RecipientPlacement{
		Recipient:        recipient,
		AccountKey:       normalizedAccount(result.AccountKey),
		Tenant:           normalizedRoutingFact(result.Tenant),
		Routing:          result.Clone(),
		Affinity:         affinity,
		Backend:          selected,
		SelectedShardTag: selectedShard,
		HoldID:           holdID,
		hold:             hold,
		selectionRequest: selectionRequest,
	}, nil
}

// accountRecipientBackend attaches exactly one delivery hold to backend active-use state.
func (s *Session) accountRecipientBackend(ctx context.Context, placement *RecipientPlacement) error {
	if placement == nil || placement.hold == nil || placement.BackendCounted {
		return nil
	}

	if s.transaction.backendAccountedHoldID != "" {
		return nil
	}

	selectionRequest := placement.selectionRequest
	if selectionRequest.AccountKey == "" {
		selectionRequest = s.selectionRequest(placement.Routing, placement.SelectedShardTag, placement.Affinity, "")
	}

	selected, err := s.attachSelectedBackend(ctx, placement.hold.key, selectionRequest, placement.Backend, placement.HoldID, defaultDeliveryLease(s.sessionLeaseTTL))
	if err != nil {
		return err
	}

	placement.Backend = selected
	placement.BackendCounted = true
	s.transaction.backendAccountedHoldID = placement.HoldID

	return nil
}

// attachSelectedBackend registers backend counts and retries same-shard placement on attach races.
func (s *Session) attachSelectedBackend(
	ctx context.Context,
	key state.AffinityKey,
	request backend.SelectionRequest,
	initial backend.SelectionResult,
	holdID string,
	reservationTTL time.Duration,
) (backend.SelectionResult, error) {
	if err := s.reserveAndAttachSelectedBackend(ctx, key, initial, holdID, reservationTTL); err != nil {
		if request.OperatorBackendIdentifier != "" {
			return backend.SelectionResult{}, err
		}

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

		if attachErr := s.reserveAndAttachSelectedBackend(ctx, key, retry, holdID, reservationTTL); attachErr != nil {
			return backend.SelectionResult{}, attachErr
		}

		return retry, nil
	}

	return initial, nil
}

// reserveAndAttachSelectedBackend claims backend capacity before storing a delivery pin.
func (s *Session) reserveAndAttachSelectedBackend(
	ctx context.Context,
	key state.AffinityKey,
	selected backend.SelectionResult,
	holdID string,
	reservationTTL time.Duration,
) error {
	reservations, ok := s.sessionStore.(state.BackendReservationStore)
	if !ok {
		return errors.New("lmtp: backend reservation store unavailable")
	}

	reservation, err := reservations.ReserveBackendCapacity(ctx, state.BackendReservationRequest{
		BackendIdentifier: selected.Backend.Identifier,
		ReservationID:     holdID,
		MaxConnections:    selected.Backend.MaxConnections,
		LeaseTTL:          reservationTTL,
	})
	if err != nil {
		return err
	}

	if _, err = s.sessionStore.AttachSelectedBackend(ctx, state.SessionBackendAttachment{
		Key:               key,
		SessionID:         holdID,
		BackendIdentifier: selected.Backend.Identifier,
		ReservationID:     reservation.ReservationID,
		MaxConnections:    selected.Backend.MaxConnections,
	}); err != nil {
		_, _ = reservations.ReleaseBackendReservation(context.Background(), state.BackendReservationReleaseRequest{
			BackendIdentifier: selected.Backend.Identifier,
			ReservationID:     reservation.ReservationID,
		})

		return err
	}

	return nil
}

// deliverySessionRecord builds the Redis lease used for one delivery hold.
func (s *Session) deliverySessionRecord(result routing.RoutingResult, holdID string, backendPin state.UserBackendPinRecord) state.SessionRecord {
	return state.SessionRecord{
		ID: holdID,
		Key: state.AffinityKey{
			Tenant:     normalizedRoutingFact(result.Tenant),
			AccountKey: normalizedAccount(result.AccountKey),
		},
		HolderKind:         state.HolderKindDelivery,
		Protocol:           protocolLMTP,
		ListenerName:       s.listenerName,
		ServiceName:        s.serviceName,
		ShardTag:           s.selectedPlacementShard(result, state.AffinityRecord{}, backendPin),
		DirectorInstanceID: s.directorInstanceID,
		LeaseTTL:           s.sessionLeaseTTL,
		IdleGrace:          s.sessionIdleGrace,
	}
}

// selectionRequest builds backend selector input from recipient routing facts.
func (s *Session) selectionRequest(
	result routing.RoutingResult,
	shardTag string,
	affinity state.AffinityRecord,
	operatorBackend string,
) backend.SelectionRequest {
	return backend.SelectionRequest{
		AccountKey:                normalizedAccount(result.AccountKey),
		Tenant:                    normalizedRoutingFact(result.Tenant),
		ShardTag:                  normalizedRoutingFact(shardTag),
		Protocol:                  protocolLMTP,
		BackendPool:               s.backendPool,
		ActiveAffinity:            affinityActiveForSelection(result, affinity),
		PinnedBackendIdentifier:   normalizedRoutingFact(affinity.BackendIdentifier),
		OperatorBackendIdentifier: normalizedRoutingFact(operatorBackend),
	}
}

type backendPinReader interface {
	GetUserBackendPin(context.Context, state.UserBackendPinGetRequest) (state.UserBackendPinRecord, error)
}

// lookupOperatorBackendPin reads a concrete user backend pin when the store supports it.
func (s *Session) lookupOperatorBackendPin(ctx context.Context, result routing.RoutingResult) (state.UserBackendPinRecord, error) {
	reader, ok := s.sessionStore.(backendPinReader)
	if !ok {
		return state.UserBackendPinRecord{}, nil
	}

	return reader.GetUserBackendPin(ctx, state.UserBackendPinGetRequest{
		Key: state.AffinityKey{
			Tenant:     normalizedRoutingFact(result.Tenant),
			AccountKey: normalizedAccount(result.AccountKey),
		},
	})
}

// selectedPlacementShard applies active affinity first, then a matching backend pin.
func (s *Session) selectedPlacementShard(
	result routing.RoutingResult,
	affinity state.AffinityRecord,
	backendPin state.UserBackendPinRecord,
) string {
	if shardTag := normalizedRoutingFact(affinity.ShardTag); shardTag != "" {
		return shardTag
	}

	if backendPinMatchesScope(backendPin, protocolLMTP, s.backendPool) {
		return normalizedRoutingFact(backendPin.ShardTag)
	}

	return normalizedRoutingFact(result.ShardTag)
}

// operatorBackendPinIdentifier returns the exact backend target for this selection.
func (s *Session) operatorBackendPinIdentifier(backendPin state.UserBackendPinRecord, shardTag string, affinity state.AffinityRecord) string {
	if !backendPinMatchesScope(backendPin, protocolLMTP, s.backendPool) {
		return ""
	}

	if normalizedRoutingFact(backendPin.ShardTag) != normalizedRoutingFact(shardTag) {
		return ""
	}

	if normalizedRoutingFact(affinity.BackendIdentifier) != "" {
		return ""
	}

	if activeAffinityBlocksOperatorBackendPin(backendPin, affinity) {
		return ""
	}

	return normalizedRoutingFact(backendPin.BackendIdentifier)
}

// activeAffinityBlocksOperatorBackendPin preserves active placement for deferred pin strategies.
func activeAffinityBlocksOperatorBackendPin(backendPin state.UserBackendPinRecord, affinity state.AffinityRecord) bool {
	if normalizedRoutingFact(backendPin.Strategy) == "kick_existing" {
		return false
	}

	return affinity.Status == affinityStatusReused || affinity.ActiveSessionCount > 1
}

// samePlacementSelectionRequest reports whether an opened hold needs reselection.
func samePlacementSelectionRequest(left backend.SelectionRequest, right backend.SelectionRequest) bool {
	return left.AccountKey == right.AccountKey &&
		left.Tenant == right.Tenant &&
		left.ShardTag == right.ShardTag &&
		left.Protocol == right.Protocol &&
		left.BackendPool == right.BackendPool &&
		left.ActiveAffinity == right.ActiveAffinity &&
		left.PinnedBackendIdentifier == right.PinnedBackendIdentifier &&
		left.OperatorBackendIdentifier == right.OperatorBackendIdentifier
}

// backendPinMatchesScope checks protocol and pool before applying a concrete pin.
func backendPinMatchesScope(backendPin state.UserBackendPinRecord, protocol string, backendPool string) bool {
	return backendPin.Present &&
		normalizedRoutingFact(backendPin.BackendIdentifier) != "" &&
		strings.EqualFold(normalizedRoutingFact(backendPin.Protocol), normalizedRoutingFact(protocol)) &&
		normalizedRoutingFact(backendPin.BackendPool) == normalizedRoutingFact(backendPool) &&
		normalizedRoutingFact(backendPin.ShardTag) != ""
}

// selectedAffinityShard applies active affinity precedence over recipient routing.
func selectedAffinityShard(result routing.RoutingResult, affinity state.AffinityRecord) string {
	if shardTag := normalizedRoutingFact(affinity.ShardTag); shardTag != "" {
		return shardTag
	}

	return normalizedRoutingFact(result.ShardTag)
}

// affinityActiveForSelection reports whether Redis returned an existing active pin.
func affinityActiveForSelection(result routing.RoutingResult, affinity state.AffinityRecord) bool {
	switch affinity.Status {
	case deliveryStatusCreated, "":
		return normalizedRoutingFact(affinity.ShardTag) != "" && normalizedRoutingFact(affinity.ShardTag) != normalizedRoutingFact(result.ShardTag)
	default:
		return affinity.Present
	}
}

// startDeliveryHeartbeat refreshes a delivery hold until it is closed.
func (s *Session) startDeliveryHeartbeat(ctx context.Context, key state.AffinityKey, holdID string) *deliveryHold {
	if ctx == nil {
		ctx = context.Background()
	}

	heartbeatCtx, cancel := context.WithCancel(ctx)
	hold := &deliveryHold{
		key:       key,
		sessionID: holdID,
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
			_, _ = s.sessionStore.HeartbeatSession(ctx, hold.key, hold.sessionID, s.sessionLeaseTTL)
		}
	}
}

// closeRecipientPlacement releases a placement with access to the session store.
func (s *Session) closeRecipientPlacement(ctx context.Context, placement *RecipientPlacement) error {
	if placement == nil || placement.hold == nil {
		return nil
	}

	var closeErr error

	placement.hold.closeOnce.Do(func() {
		placement.hold.cancel()
		<-placement.hold.done
		_, closeErr = s.sessionStore.CloseSession(ctx, placement.hold.key, placement.hold.sessionID)
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
