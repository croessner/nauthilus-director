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
	"github.com/croessner/nauthilus-director/internal/routing"
	"github.com/croessner/nauthilus-director/internal/state"
)

const (
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
	if !s.recipientPlacementRequired {
		return RecipientPlacement{Recipient: recipient}, nil
	}

	if err := s.ensureRecipientPlacementDependencies(); err != nil {
		return RecipientPlacement{}, err
	}

	identity, err := s.lookupRecipientIdentity(ctx, recipient.LookupName)
	if err != nil {
		return RecipientPlacement{}, err
	}

	routingResult, err := s.resolveRecipientRoute(ctx, recipient, identity)
	if err != nil {
		return RecipientPlacement{}, err
	}

	initial, err := s.selectRecipientBackend(ctx, routingResult, state.AffinityRecord{})
	if err != nil {
		return RecipientPlacement{}, err
	}

	placement, err := s.openRecipientHold(ctx, recipient, routingResult, initial)
	if err != nil {
		return RecipientPlacement{}, err
	}

	if !s.transaction.acceptsBackend(placement.Backend.Backend.Identifier) {
		_ = s.closeRecipientPlacement(ctx, &placement)

		return RecipientPlacement{}, errDifferentBackendRecipient
	}

	if err := s.accountRecipientBackend(ctx, &placement); err != nil {
		_ = s.closeRecipientPlacement(ctx, &placement)

		return RecipientPlacement{}, err
	}

	if !s.transaction.acceptsBackend(placement.Backend.Backend.Identifier) {
		_ = s.closeRecipientPlacement(ctx, &placement)

		return RecipientPlacement{}, errDifferentBackendRecipient
	}

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
func (s *Session) selectRecipientBackend(ctx context.Context, result routing.RoutingResult, affinity state.AffinityRecord) (backend.SelectionResult, error) {
	request := s.selectionRequest(result, selectedAffinityShard(result, affinity), affinity)

	return s.backendSelector.Select(ctx, request)
}

// openRecipientHold creates and attaches a delivery-scoped active-affinity hold.
func (s *Session) openRecipientHold(
	ctx context.Context,
	recipient RecipientPath,
	result routing.RoutingResult,
	initial backend.SelectionResult,
) (RecipientPlacement, error) {
	holdID, err := newDeliveryHoldID()
	if err != nil {
		return RecipientPlacement{}, err
	}

	record := s.deliverySessionRecord(result, holdID)

	affinity, err := s.sessionStore.OpenSession(ctx, record)
	if err != nil {
		return RecipientPlacement{}, err
	}

	if affinity.Key == (state.AffinityKey{}) {
		affinity.Key = record.Key
	}

	selected := initial
	selectedShard := selectedAffinityShard(result, affinity)

	selectionRequest := s.selectionRequest(result, selectedShard, affinity)
	if selectedShard != result.ShardTag || affinityActiveForSelection(result, affinity) {
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

	selectionRequest := s.selectionRequest(placement.Routing, placement.SelectedShardTag, placement.Affinity)

	selected, err := s.attachSelectedBackend(ctx, placement.hold.key, selectionRequest, placement.Backend, placement.HoldID)
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
) (backend.SelectionResult, error) {
	if _, err := s.sessionStore.AttachSelectedBackend(ctx, state.SessionBackendAttachment{
		Key:               key,
		SessionID:         holdID,
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
			SessionID:         holdID,
			BackendIdentifier: retry.Backend.Identifier,
			MaxConnections:    retry.Backend.MaxConnections,
		}); attachErr != nil {
			return backend.SelectionResult{}, attachErr
		}

		return retry, nil
	}

	return initial, nil
}

// deliverySessionRecord builds the Redis lease used for one delivery hold.
func (s *Session) deliverySessionRecord(result routing.RoutingResult, holdID string) state.SessionRecord {
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
		ShardTag:           normalizedRoutingFact(result.ShardTag),
		DirectorInstanceID: s.directorInstanceID,
		LeaseTTL:           s.sessionLeaseTTL,
		IdleGrace:          s.sessionIdleGrace,
	}
}

// selectionRequest builds backend selector input from recipient routing facts.
func (s *Session) selectionRequest(result routing.RoutingResult, shardTag string, affinity state.AffinityRecord) backend.SelectionRequest {
	return backend.SelectionRequest{
		AccountKey:              normalizedAccount(result.AccountKey),
		Tenant:                  normalizedRoutingFact(result.Tenant),
		ShardTag:                normalizedRoutingFact(shardTag),
		Protocol:                protocolLMTP,
		BackendPool:             s.backendPool,
		ActiveAffinity:          affinityActiveForSelection(result, affinity),
		PinnedBackendIdentifier: normalizedRoutingFact(affinity.BackendIdentifier),
	}
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
