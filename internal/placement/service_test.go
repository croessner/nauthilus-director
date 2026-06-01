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

//nolint:dupl,goconst // Placement matrix cases intentionally mirror protocol directions.
package placement

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/state"
)

const (
	placementAccountKey       = "alice@example.test"
	placementBackendA         = "mailstore-a-imap"
	placementBackendALMTP     = "mailstore-a-lmtp"
	placementBackendB         = "mailstore-b-imap"
	placementBackendSameShard = "mailstore-a-other-imap"
	placementNodeA            = "mailstore-a-node"
	placementNodeB            = "mailstore-b-node"
	placementNodeSameShard    = "mailstore-a-other-node"
	placementPool             = "imap-default"
	placementProtocol         = "imap"
	placementShardA           = "mailstore-a"
	placementShardB           = "mailstore-b"
	placementTenant           = "blue"
)

// TestServiceReusesActiveBackendNodeForSession verifies bound-node reuse precedes normal selection.
func TestServiceReusesActiveBackendNodeForSession(t *testing.T) {
	store := &placementStoreFixture{
		affinity: state.AffinityRecord{
			Key:                placementKey(),
			ShardTag:           placementShardA,
			BackendNode:        placementNodeA,
			Status:             "found",
			Present:            true,
			BindingStatus:      state.BindingStatusActive,
			ActiveSessionCount: 1,
			ActiveHolderCount:  1,
		},
	}
	selector := &placementSelectorFixture{registry: placementRegistryFixture()}
	service := mustPlacementService(t, selector, store)

	lease, err := service.PlaceSession(context.Background(), placementRequest("session-1", placementShardB))
	if err != nil {
		t.Fatalf("PlaceSession returned error: %v", err)
	}

	if selector.selectCalls != 0 || selector.nodeCalls != 1 {
		t.Fatalf("selector calls select=%d node=%d, want node-only reuse", selector.selectCalls, selector.nodeCalls)
	}

	if lease.Backend().Backend.Identifier != placementBackendA {
		t.Fatalf("selected backend = %q, want active node backend", lease.Backend().Backend.Identifier)
	}

	if got := lease.Binding().Source; got != BindingSourceActiveAffinity {
		t.Fatalf("binding source = %q, want %q", got, BindingSourceActiveAffinity)
	}

	if store.opened[0].BackendNode != placementNodeA || store.reserveCalls != 1 || store.attachCalls != 1 {
		t.Fatalf("state mutation opened=%#v reserve=%d attach=%d", store.opened, store.reserveCalls, store.attachCalls)
	}
}

// TestServiceReusesActiveLMTPDeliveryBindingForIMAPSession verifies delivery holders drive IMAP node reuse.
func TestServiceReusesActiveLMTPDeliveryBindingForIMAPSession(t *testing.T) {
	store := &placementStoreFixture{
		affinity: state.AffinityRecord{
			Key:                placementKey(),
			ShardTag:           placementShardA,
			BackendNode:        placementNodeA,
			Status:             "found",
			Present:            true,
			BindingStatus:      state.BindingStatusActive,
			ActiveHolderCount:  1,
			ActiveSessionCount: 0,
		},
	}
	selector := &placementSelectorFixture{registry: placementRegistryFixture()}
	service := mustPlacementService(t, selector, store)

	lease, err := service.PlaceSession(context.Background(), placementRequest("session-from-lmtp", placementShardA))
	if err != nil {
		t.Fatalf("PlaceSession returned error: %v", err)
	}

	if selector.selectCalls != 0 || selector.nodeCalls != 1 {
		t.Fatalf("selector calls select=%d node=%d, want node-only reuse", selector.selectCalls, selector.nodeCalls)
	}

	if lease.Backend().Backend.Identifier != placementBackendA {
		t.Fatalf("selected backend = %q, want IMAP backend in active LMTP node", lease.Backend().Backend.Identifier)
	}

	if store.opened[0].BackendNode != placementNodeA || store.attachments[0].BackendNode != placementNodeA {
		t.Fatalf("opened/attached node = %q/%q, want active LMTP node", store.opened[0].BackendNode, store.attachments[0].BackendNode)
	}
}

// TestServiceReusesRetainedLMTPBindingForIMAPSession verifies idle delivery retention stays authoritative.
func TestServiceReusesRetainedLMTPBindingForIMAPSession(t *testing.T) {
	store := &placementStoreFixture{
		affinity: state.AffinityRecord{
			Key:                placementKey(),
			ShardTag:           placementShardA,
			BackendNode:        placementNodeA,
			Status:             "retained",
			Present:            true,
			BindingStatus:      state.BindingStatusRetained,
			RetentionExpiresAt: time.Now().Add(time.Minute),
		},
	}
	selector := &placementSelectorFixture{registry: placementRegistryFixture()}
	service := mustPlacementService(t, selector, store)

	lease, err := service.PlaceSession(context.Background(), placementRequest("session-from-retention", placementShardB))
	if err != nil {
		t.Fatalf("PlaceSession returned error: %v", err)
	}

	if selector.selectCalls != 0 || selector.nodeCalls != 1 {
		t.Fatalf("selector calls select=%d node=%d, want retained node reuse", selector.selectCalls, selector.nodeCalls)
	}

	if lease.Backend().Backend.Identifier != placementBackendA {
		t.Fatalf("selected backend = %q, want IMAP backend in retained LMTP node", lease.Backend().Backend.Identifier)
	}

	if got := lease.Binding().Source; got != BindingSourceRetainedBinding {
		t.Fatalf("binding source = %q, want %q", got, BindingSourceRetainedBinding)
	}
}

// TestServiceReusesActiveIMAPBindingForLMTPDelivery verifies LMTP delivery uses active login nodes.
func TestServiceReusesActiveIMAPBindingForLMTPDelivery(t *testing.T) {
	store := &placementStoreFixture{
		affinity: state.AffinityRecord{
			Key:                placementKey(),
			ShardTag:           placementShardA,
			BackendNode:        placementNodeA,
			Status:             "found",
			Present:            true,
			BindingStatus:      state.BindingStatusActive,
			ActiveSessionCount: 1,
			ActiveHolderCount:  1,
		},
	}
	selector := &placementSelectorFixture{registry: placementRegistryFixture()}
	service := mustPlacementService(t, selector, store)

	lease, err := service.PlaceDeliveryHold(context.Background(), placementDeliveryRequest("delivery-from-imap", placementShardB))
	if err != nil {
		t.Fatalf("PlaceDeliveryHold returned error: %v", err)
	}

	if selector.selectCalls != 0 || selector.nodeCalls != 1 {
		t.Fatalf("selector calls select=%d node=%d, want node-only reuse", selector.selectCalls, selector.nodeCalls)
	}

	if lease.Backend().Backend.Identifier != placementBackendALMTP {
		t.Fatalf("selected backend = %q, want LMTP backend in active IMAP node", lease.Backend().Backend.Identifier)
	}

	if store.opened[0].HolderKind != state.HolderKindDelivery || store.opened[0].BackendNode != placementNodeA {
		t.Fatalf("opened delivery hold = %#v, want active IMAP backend node", store.opened[0])
	}

	if store.reserveCalls != 0 || store.attachCalls != 0 {
		t.Fatalf("delivery placement counted backend reserve=%d attach=%d, want caller-controlled accounting", store.reserveCalls, store.attachCalls)
	}
}

// TestServiceReusesRetainedIMAPBindingForLMTPDelivery verifies LMTP delivery observes idle retention.
func TestServiceReusesRetainedIMAPBindingForLMTPDelivery(t *testing.T) {
	store := &placementStoreFixture{
		affinity: state.AffinityRecord{
			Key:                placementKey(),
			ShardTag:           placementShardA,
			BackendNode:        placementNodeA,
			Status:             "retained",
			Present:            true,
			BindingStatus:      state.BindingStatusRetained,
			RetentionExpiresAt: time.Now().Add(time.Minute),
		},
	}
	selector := &placementSelectorFixture{registry: placementRegistryFixture()}
	service := mustPlacementService(t, selector, store)

	lease, err := service.PlaceDeliveryHold(context.Background(), placementDeliveryRequest("delivery-from-retention", placementShardB))
	if err != nil {
		t.Fatalf("PlaceDeliveryHold returned error: %v", err)
	}

	if selector.selectCalls != 0 || selector.nodeCalls != 1 {
		t.Fatalf("selector calls select=%d node=%d, want retained node reuse", selector.selectCalls, selector.nodeCalls)
	}

	if lease.Backend().Backend.Identifier != placementBackendALMTP {
		t.Fatalf("selected backend = %q, want LMTP backend in retained IMAP node", lease.Backend().Backend.Identifier)
	}

	if got := lease.Binding().Source; got != BindingSourceRetainedBinding {
		t.Fatalf("binding source = %q, want %q", got, BindingSourceRetainedBinding)
	}
}

// TestServiceUsesMovementOverrideBeforeRetainedBinding verifies explicit moves supersede idle retention.
func TestServiceUsesMovementOverrideBeforeRetainedBinding(t *testing.T) {
	store := &placementStoreFixture{
		affinity: state.AffinityRecord{
			Key:                placementKey(),
			ShardTag:           placementShardA,
			BackendNode:        placementNodeA,
			Status:             "retained",
			Present:            true,
			BindingStatus:      state.BindingStatusRetained,
			MoveTargetShard:    placementShardB,
			MoveStrategy:       "new_sessions_only",
			RetentionExpiresAt: time.Now().Add(time.Minute),
		},
	}
	selector := &placementSelectorFixture{registry: placementRegistryFixture()}
	service := mustPlacementService(t, selector, store)

	lease, err := service.PlaceSession(context.Background(), placementRequest("session-2", placementShardA))
	if err != nil {
		t.Fatalf("PlaceSession returned error: %v", err)
	}

	if selector.selectCalls != 1 || selector.nodeCalls != 0 {
		t.Fatalf("selector calls select=%d node=%d, want movement initial selection", selector.selectCalls, selector.nodeCalls)
	}

	if selector.lastSelect.ShardTag != placementShardB {
		t.Fatalf("initial selection shard = %q, want movement target", selector.lastSelect.ShardTag)
	}

	if lease.Backend().Backend.Identifier != placementBackendB {
		t.Fatalf("selected backend = %q, want moved shard backend", lease.Backend().Backend.Identifier)
	}

	if got := lease.Binding().Source; got != BindingSourceMovementOverride {
		t.Fatalf("binding source = %q, want %q", got, BindingSourceMovementOverride)
	}
}

// TestServiceRejectsPinOutsideBoundBackendNode verifies pins cannot override active binding.
func TestServiceRejectsPinOutsideBoundBackendNode(t *testing.T) {
	store := &placementStoreFixture{
		affinity: state.AffinityRecord{
			Key:                placementKey(),
			ShardTag:           placementShardA,
			BackendNode:        placementNodeA,
			Status:             "found",
			Present:            true,
			BindingStatus:      state.BindingStatusActive,
			ActiveSessionCount: 1,
			ActiveHolderCount:  1,
		},
		pin: state.UserBackendPinRecord{
			Present:           true,
			Key:               placementKey(),
			BackendIdentifier: placementBackendB,
			Protocol:          placementProtocol,
			BackendPool:       placementPool,
			ShardTag:          placementShardB,
		},
	}
	service := mustPlacementService(t, &placementSelectorFixture{registry: placementRegistryFixture()}, store)

	_, err := service.PlaceSession(context.Background(), placementRequest("session-3", placementShardA))
	if !IsErrorKind(err, ErrorKindBackendNodeMismatch) {
		t.Fatalf("PlaceSession error = %v, want backend-node mismatch", err)
	}

	if len(store.opened) != 0 {
		t.Fatalf("store opened %d session(s), want fail before mutation", len(store.opened))
	}
}

// TestServiceRollsBackBackendReservationOnAttachFailure verifies counted attach rollback.
func TestServiceRollsBackBackendReservationOnAttachFailure(t *testing.T) {
	store := &placementStoreFixture{attachErr: errors.New("attach failed")}
	service := mustPlacementService(t, &placementSelectorFixture{registry: placementRegistryFixture()}, store)

	_, err := service.PlaceSession(context.Background(), placementRequest("session-4", placementShardA))
	if err == nil {
		t.Fatal("PlaceSession returned nil error, want attach failure")
	}

	if store.reserveCalls != 1 || store.releaseCalls != 1 || store.closeCalls != 1 {
		t.Fatalf("rollback calls reserve=%d release=%d close=%d, want 1/1/1", store.reserveCalls, store.releaseCalls, store.closeCalls)
	}
}

// TestServiceCloseLeavesRetainedBinding verifies final IMAP close reports retention metadata.
func TestServiceCloseLeavesRetainedBinding(t *testing.T) {
	retentionExpiresAt := time.Now().Add(15 * time.Minute).UTC()
	store := &placementStoreFixture{
		closeAffinity: state.AffinityRecord{
			Key:                placementKey(),
			ShardTag:           placementShardA,
			BackendNode:        placementNodeA,
			Status:             "idle",
			Present:            true,
			BindingStatus:      state.BindingStatusRetained,
			RetentionExpiresAt: retentionExpiresAt,
		},
	}
	service := mustPlacementService(t, &placementSelectorFixture{registry: placementRegistryFixture()}, store)

	lease, err := service.PlaceSession(context.Background(), placementRequest("session-close", placementShardA))
	if err != nil {
		t.Fatalf("PlaceSession returned error: %v", err)
	}

	if err := lease.Close(context.Background()); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	if store.closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1", store.closeCalls)
	}

	if got := lease.Binding().RetentionExpiresAt; !got.Equal(retentionExpiresAt) {
		t.Fatalf("retention expiry = %v, want %v", got, retentionExpiresAt)
	}

	if got := lease.Binding().ActiveHolderCount; got != 0 {
		t.Fatalf("active holder count after close = %d, want 0", got)
	}
}

// TestServiceFailsClosedWhenRetainedProtocolEntryIsMissing verifies node-local absence is fatal.
func TestServiceFailsClosedWhenRetainedProtocolEntryIsMissing(t *testing.T) {
	registry := placementRegistryFixture()
	delete(registry.backends, placementBackendA)
	registry.backends[placementBackendSameShard] = placementBackend(placementBackendSameShard, placementNodeSameShard, placementShardA)
	store := &placementStoreFixture{
		affinity: state.AffinityRecord{
			Key:                placementKey(),
			ShardTag:           placementShardA,
			BackendNode:        placementNodeA,
			Status:             "retained",
			Present:            true,
			BindingStatus:      state.BindingStatusRetained,
			RetentionExpiresAt: time.Now().Add(time.Minute),
		},
	}
	selector := &placementSelectorFixture{registry: registry}
	service := mustPlacementService(t, selector, store)

	_, err := service.PlaceSession(context.Background(), placementRequest("session-5", placementShardA))
	if err == nil {
		t.Fatal("PlaceSession returned nil error, want fail-closed missing endpoint")
	}

	if selector.selectCalls != 0 || selector.nodeCalls != 1 {
		t.Fatalf("selector calls select=%d node=%d, want no same-shard fallback", selector.selectCalls, selector.nodeCalls)
	}

	if len(store.opened) != 0 {
		t.Fatalf("store opened %d session(s), want fail before mutation", len(store.opened))
	}
}

// mustPlacementService builds a service fixture for placement unit tests.
func mustPlacementService(t *testing.T, selector *placementSelectorFixture, store *placementStoreFixture) *Service {
	t.Helper()

	service, err := NewService(selector.registry, selector, store)
	if err != nil {
		t.Fatalf("NewService returned error: %v", err)
	}

	return service
}

// placementRequest creates one complete placement request fixture.
func placementRequest(sessionID string, shardTag string) Request {
	return Request{
		Key:                placementKey(),
		SessionID:          sessionID,
		Protocol:           placementProtocol,
		BackendPool:        placementPool,
		ShardTag:           shardTag,
		ListenerName:       "imap",
		ServiceName:        "imap",
		DirectorInstanceID: "director-a",
		LeaseTTL:           time.Minute,
		RetentionTTL:       15 * time.Minute,
	}
}

// placementDeliveryRequest creates one complete LMTP delivery placement request fixture.
func placementDeliveryRequest(sessionID string, shardTag string) DeliveryRequest {
	request := placementRequest(sessionID, shardTag)
	request.Protocol = "lmtp"
	request.BackendPool = "lmtp-default"
	request.ListenerName = "lmtp"
	request.ServiceName = "delivery"
	request.HolderKind = state.HolderKindDelivery

	return request
}

// placementKey returns the stable user-affinity key used by unit tests.
func placementKey() state.AffinityKey {
	return state.AffinityKey{Tenant: placementTenant, AccountKey: placementAccountKey}
}

// placementRegistryFixture creates a two-shard backend-node registry fixture.
func placementRegistryFixture() *placementRegistry {
	return &placementRegistry{
		backends: map[string]backend.Backend{
			placementBackendA:     placementBackend(placementBackendA, placementNodeA, placementShardA),
			placementBackendALMTP: placementBackendWithProtocol(placementBackendALMTP, placementNodeA, placementShardA, "lmtp", "lmtp-default"),
			placementBackendB:     placementBackend(placementBackendB, placementNodeB, placementShardB),
		},
	}
}

// placementBackend returns one configured backend fixture.
func placementBackend(identifier string, node string, shard string) backend.Backend {
	return placementBackendWithProtocol(identifier, node, shard, placementProtocol, placementPool)
}

// placementBackendWithProtocol returns one configured backend fixture for a protocol.
func placementBackendWithProtocol(identifier string, node string, shard string, protocol string, pool string) backend.Backend {
	return backend.Backend{
		Identifier:      identifier,
		Protocol:        protocol,
		BackendPool:     pool,
		ShardTag:        shard,
		BackendNode:     node,
		Address:         "127.0.0.1:1143",
		MaintenanceMode: backend.MaintenanceModeDisabled,
		Weight:          100,
		MaxConnections:  100,
	}
}

type placementStoreFixture struct {
	affinity      state.AffinityRecord
	closeAffinity state.AffinityRecord
	pin           state.UserBackendPinRecord
	opened        []state.SessionRecord
	attachments   []state.SessionBackendAttachment
	attachErr     error
	reserveCalls  int
	releaseCalls  int
	attachCalls   int
	closeCalls    int
}

// OpenSession records the holder proposal and returns accepted affinity state.
func (s *placementStoreFixture) OpenSession(_ context.Context, record state.SessionRecord) (state.AffinityRecord, error) {
	s.opened = append(s.opened, record)

	status := "created"
	if s.affinity.Present {
		status = "reused"
		if s.affinity.Status == "retained" || s.affinity.BindingStatus == state.BindingStatusRetained {
			status = "retained"
		}
	}

	if s.affinity.MoveTargetShard != "" && s.affinity.ActiveHolderCount == 0 && s.affinity.ActiveSessionCount == 0 {
		status = "moved_from_override"
	}

	return state.AffinityRecord{
		Key:                record.Key,
		ShardTag:           record.ShardTag,
		BackendNode:        record.BackendNode,
		Status:             status,
		Present:            true,
		BindingStatus:      state.BindingStatusActive,
		ActiveSessionCount: 1,
		ActiveHolderCount:  1,
	}, nil
}

// LookupAffinity returns the configured active or retained affinity snapshot.
func (s *placementStoreFixture) LookupAffinity(_ context.Context, key state.AffinityKey) (state.AffinityRecord, error) {
	if !s.affinity.Present {
		return state.AffinityRecord{Key: key, BindingStatus: state.BindingStatusNone}, nil
	}

	record := s.affinity
	record.Key = key

	return record, nil
}

// GetUserBackendPin returns the configured operator backend pin.
func (s *placementStoreFixture) GetUserBackendPin(
	_ context.Context,
	request state.UserBackendPinGetRequest,
) (state.UserBackendPinRecord, error) {
	if !s.pin.Present {
		return state.UserBackendPinRecord{Key: request.Key}, nil
	}

	pin := s.pin
	pin.Key = request.Key

	return pin, nil
}

// ReserveBackendCapacity records one counted backend reservation.
func (s *placementStoreFixture) ReserveBackendCapacity(
	_ context.Context,
	request state.BackendReservationRequest,
) (state.BackendReservationRecord, error) {
	s.reserveCalls++

	return state.BackendReservationRecord{
		Status:             "reserved",
		BackendIdentifier:  request.BackendIdentifier,
		ReservationID:      request.ReservationID,
		BackendActiveCount: 1,
		LeaseExpiresAt:     time.Now().Add(request.LeaseTTL),
	}, nil
}

// ReleaseBackendReservation records one rollback release.
func (s *placementStoreFixture) ReleaseBackendReservation(
	context.Context,
	state.BackendReservationReleaseRequest,
) (state.BackendReservationRecord, error) {
	s.releaseCalls++

	return state.BackendReservationRecord{Status: "released", RepairedCount: 1}, nil
}

// ReapBackendReservations satisfies the backend reservation store contract.
func (s *placementStoreFixture) ReapBackendReservations(
	context.Context,
	state.BackendReservationReapRequest,
) (state.BackendReservationRecord, error) {
	return state.BackendReservationRecord{}, nil
}

// AttachSelectedBackend records selected backend accounting.
func (s *placementStoreFixture) AttachSelectedBackend(
	_ context.Context,
	attachment state.SessionBackendAttachment,
) (state.SessionBackendRecord, error) {
	s.attachCalls++

	s.attachments = append(s.attachments, attachment)
	if s.attachErr != nil {
		return state.SessionBackendRecord{}, s.attachErr
	}

	return state.SessionBackendRecord{
		Status:             "attached",
		BackendIdentifier:  attachment.BackendIdentifier,
		BackendNode:        attachment.BackendNode,
		ReservationID:      attachment.ReservationID,
		BackendActiveCount: 1,
	}, nil
}

// HeartbeatSession returns a stable active affinity snapshot.
func (s *placementStoreFixture) HeartbeatSession(
	context.Context,
	state.AffinityKey,
	string,
	time.Duration,
) (state.AffinityRecord, error) {
	return s.affinity, nil
}

// CloseSession records holder closure for rollback and lease cleanup.
func (s *placementStoreFixture) CloseSession(context.Context, state.AffinityKey, string) (state.AffinityRecord, error) {
	s.closeCalls++

	if s.closeAffinity != (state.AffinityRecord{}) {
		return s.closeAffinity, nil
	}

	return state.AffinityRecord{Present: false, BindingStatus: state.BindingStatusNone}, nil
}

type placementSelectorFixture struct {
	registry    *placementRegistry
	selectCalls int
	nodeCalls   int
	lastSelect  backend.SelectionRequest
	lastNode    backend.NodeSelectionRequest
}

// Select chooses a backend in the requested shard.
func (s *placementSelectorFixture) Select(_ context.Context, request backend.SelectionRequest) (backend.SelectionResult, error) {
	s.selectCalls++
	s.lastSelect = request

	backends, err := s.registry.BackendsForShard(context.Background(), backend.RegistryRequest{
		Protocol:    request.Protocol,
		BackendPool: request.BackendPool,
		ShardTag:    request.ShardTag,
	})
	if err != nil {
		return backend.SelectionResult{}, err
	}

	return placementSelectionResult(backends[0], "rendezvous_hash"), nil
}

// SelectInBackendNode chooses the protocol endpoint inside a bound backend node.
func (s *placementSelectorFixture) SelectInBackendNode(
	_ context.Context,
	request backend.NodeSelectionRequest,
) (backend.SelectionResult, error) {
	s.nodeCalls++
	s.lastNode = request

	selected, err := s.registry.LookupInBackendNode(context.Background(), backend.NodeLookupRequest{
		BackendNode: request.BackendNode,
		Protocol:    request.Protocol,
		BackendPool: request.BackendPool,
	})
	if err != nil {
		return backend.SelectionResult{}, err
	}

	return placementSelectionResult(selected, backend.SelectionReasonBackendBinding), nil
}

type placementRegistry struct {
	backends map[string]backend.Backend
}

// AllBackends returns all configured backend fixtures.
func (r *placementRegistry) AllBackends(context.Context) ([]backend.Backend, error) {
	result := make([]backend.Backend, 0, len(r.backends))

	for _, entry := range r.backends {
		result = append(result, entry)
	}

	return result, nil
}

// BackendsForShard returns backend fixtures matching a shard request.
func (r *placementRegistry) BackendsForShard(_ context.Context, request backend.RegistryRequest) ([]backend.Backend, error) {
	result := []backend.Backend{}

	for _, entry := range r.backends {
		if entry.Protocol == request.Protocol && entry.BackendPool == request.BackendPool && entry.ShardTag == request.ShardTag {
			result = append(result, entry)
		}
	}

	if len(result) == 0 {
		return nil, placementBackendError("no shard backend")
	}

	return result, nil
}

// Lookup returns one backend fixture by identifier.
func (r *placementRegistry) Lookup(_ context.Context, identifier string) (backend.Backend, error) {
	entry, ok := r.backends[identifier]
	if !ok {
		return backend.Backend{}, placementBackendError("backend missing")
	}

	return entry, nil
}

// LookupInBackendNode resolves one backend fixture inside a backend node.
func (r *placementRegistry) LookupInBackendNode(_ context.Context, request backend.NodeLookupRequest) (backend.Backend, error) {
	for _, entry := range r.backends {
		if entry.BackendNode == request.BackendNode && entry.Protocol == request.Protocol && entry.BackendPool == request.BackendPool {
			return entry, nil
		}
	}

	return backend.Backend{}, placementBackendError("backend node endpoint missing")
}

// Pool returns the single IMAP backend pool fixture.
func (r *placementRegistry) Pool(_ context.Context, name string) (backend.Pool, error) {
	return backend.Pool{Name: name, Protocol: placementProtocol, Selector: "rendezvous_hash", Backends: []string{placementBackendA, placementBackendB}}, nil
}

// placementSelectionResult wraps a backend fixture as a successful selection.
func placementSelectionResult(selected backend.Backend, reason string) backend.SelectionResult {
	return backend.SelectionResult{
		Backend: selected,
		EffectiveBackend: backend.EffectiveBackendState{
			Backend:           selected,
			Identifier:        selected.Identifier,
			Protocol:          selected.Protocol,
			BackendPool:       selected.BackendPool,
			EffectiveShardTag: selected.ShardTag,
			MaxConnections:    selected.MaxConnections,
			AllowsNewSessions: true,
			AllowsActivePins:  true,
		},
		Reason:         reason,
		ActiveAffinity: reason == backend.SelectionReasonBackendBinding,
	}
}

// placementBackendError returns a bounded backend fixture error.
func placementBackendError(message string) error {
	return &backend.Error{Kind: backend.ErrorKindNoBackend, Operation: "placement_test", Message: message}
}
