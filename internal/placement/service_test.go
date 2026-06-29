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

//nolint:dupl,funlen,goconst,wsl_v5 // Placement matrix cases intentionally mirror protocol directions.
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
	placementAccountKey         = "alice@example.test"
	placementBackendA           = "mailstore-a-imap"
	placementBackendALMTP       = "mailstore-a-lmtp"
	placementBackendAPOP3       = "mailstore-a-pop3"
	placementBackendASieve      = "mailstore-a-sieve"
	placementBackendB           = "mailstore-b-imap"
	placementBackendBPOP3       = "mailstore-b-pop3"
	placementBackendBSieve      = "mailstore-b-sieve"
	placementBackendCanaryIMAP  = "mailstack-canary-imap"
	placementBackendCanaryLMTP  = "mailstack-canary-lmtp"
	placementBackendCanaryPOP3  = "mailstack-canary-pop3"
	placementBackendCanarySieve = "mailstack-canary-sieve"
	placementBackendNode2IMAP   = "node2-imap"
	placementBackendNode2LMTP   = "node2-lmtp"
	placementBackendNode2POP3   = "node2-pop3"
	placementBackendNode2Sieve  = "node2-sieve"
	placementBackendSameShard   = "mailstore-a-other-imap"
	placementCanaryNode         = "mailstack-canary"
	placementCanaryShard        = "mailstack-canary"
	placementLMTPPool           = "lmtp-default"
	placementLMTPProtocol       = "lmtp"
	placementNodeA              = "mailstore-a-node"
	placementNodeB              = "mailstore-b-node"
	placementNode2              = "node2"
	placementNode2Shard         = "node2"
	placementNodeSameShard      = "mailstore-a-other-node"
	placementPool               = "imap-default"
	placementPOP3Pool           = "pop3-default"
	placementPOP3Protocol       = "pop3"
	placementProtocol           = "imap"
	placementShardA             = "mailstore-a"
	placementShardB             = "mailstore-b"
	placementSievePool          = "sieve-default"
	placementSieveProtocol      = "sieve"
	placementTenant             = "blue"
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

// TestServiceRepairsStaleRetainedBindingWithoutActiveHolders verifies idle obsolete bindings do not block recovery.
func TestServiceRepairsStaleRetainedBindingWithoutActiveHolders(t *testing.T) {
	store := &placementStoreFixture{
		affinity: state.AffinityRecord{
			Key:                placementKey(),
			ShardTag:           placementNode2Shard,
			BackendNode:        placementNode2,
			Status:             affinityStatusRetained,
			Present:            true,
			BindingStatus:      state.BindingStatusRetained,
			ActiveHolderCount:  0,
			ActiveSessionCount: 0,
			RetentionExpiresAt: time.Now().Add(time.Minute),
		},
	}
	selector := &placementSelectorFixture{registry: placementRegistryFixture()}
	service := mustPlacementService(t, selector, store)

	lease, err := service.PlaceSession(context.Background(), placementRequest("session-after-stale-retention", placementShardA))
	if err != nil {
		t.Fatalf("PlaceSession returned error: %v", err)
	}

	if selector.nodeCalls != 1 || selector.selectCalls != 1 {
		t.Fatalf("selector calls node=%d select=%d, want failed retained lookup then normal selection", selector.nodeCalls, selector.selectCalls)
	}

	if lease.Backend().Backend.Identifier != placementBackendA {
		t.Fatalf("selected backend = %q, want healthy initial IMAP backend", lease.Backend().Backend.Identifier)
	}

	if got := lease.Binding().Source; got != BindingSourceInitialPlacement {
		t.Fatalf("binding source = %q, want %q", got, BindingSourceInitialPlacement)
	}

	if !store.opened[0].RepairRetainedBinding || store.opened[0].BackendNode != placementNodeA {
		t.Fatalf("opened repair proposal = %#v, want retained repair onto healthy backend node", store.opened[0])
	}
}

// TestServicePreservesActiveBindingWhenBackendNodeIsUnavailable verifies active holders stay fail-closed.
func TestServicePreservesActiveBindingWhenBackendNodeIsUnavailable(t *testing.T) {
	store := &placementStoreFixture{
		affinity: state.AffinityRecord{
			Key:                placementKey(),
			ShardTag:           placementNode2Shard,
			BackendNode:        placementNode2,
			Status:             affinityStatusFound,
			Present:            true,
			BindingStatus:      state.BindingStatusActive,
			ActiveHolderCount:  1,
			ActiveSessionCount: 1,
		},
	}
	selector := &placementSelectorFixture{registry: placementRegistryFixture()}
	service := mustPlacementService(t, selector, store)

	_, err := service.PlaceSession(context.Background(), placementRequest("session-active-unavailable", placementShardA))
	if err == nil {
		t.Fatal("PlaceSession returned nil error, want fail-closed active binding")
	}

	if !IsErrorKind(err, ErrorKindBackendNodeUnusable) {
		t.Fatalf("PlaceSession error = %v, want %s", err, ErrorKindBackendNodeUnusable)
	}

	if selector.nodeCalls != 1 || selector.selectCalls != 0 {
		t.Fatalf("selector calls node=%d select=%d, want active binding only", selector.nodeCalls, selector.selectCalls)
	}

	if len(store.opened) != 0 {
		t.Fatalf("opened sessions = %#v, want no placement mutation", store.opened)
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

// TestServiceReusesActiveIMAPBindingForSieveSession verifies Sieve resolves bound IMAP nodes.
func TestServiceReusesActiveIMAPBindingForSieveSession(t *testing.T) {
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

	lease, err := service.PlaceSession(context.Background(), placementSieveRequest("sieve-from-imap", placementShardB))
	if err != nil {
		t.Fatalf("PlaceSession returned error: %v", err)
	}

	if selector.selectCalls != 0 || selector.nodeCalls != 1 {
		t.Fatalf("selector calls select=%d node=%d, want node-only reuse", selector.selectCalls, selector.nodeCalls)
	}

	if lease.Backend().Backend.Identifier != placementBackendASieve {
		t.Fatalf("selected backend = %q, want Sieve backend in active IMAP node", lease.Backend().Backend.Identifier)
	}

	if store.opened[0].Protocol != placementSieveProtocol || store.opened[0].BackendNode != placementNodeA {
		t.Fatalf("opened Sieve session = %#v, want active IMAP backend node", store.opened[0])
	}
}

// TestServiceReusesRetainedLMTPBindingForSieveSession verifies retained delivery nodes drive Sieve.
func TestServiceReusesRetainedLMTPBindingForSieveSession(t *testing.T) {
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

	lease, err := service.PlaceSession(context.Background(), placementSieveRequest("sieve-from-lmtp-retention", placementShardB))
	if err != nil {
		t.Fatalf("PlaceSession returned error: %v", err)
	}

	if selector.selectCalls != 0 || selector.nodeCalls != 1 {
		t.Fatalf("selector calls select=%d node=%d, want retained node reuse", selector.selectCalls, selector.nodeCalls)
	}

	if lease.Backend().Backend.Identifier != placementBackendASieve {
		t.Fatalf("selected backend = %q, want Sieve backend in retained LMTP node", lease.Backend().Backend.Identifier)
	}

	if got := lease.Binding().Source; got != BindingSourceRetainedBinding {
		t.Fatalf("binding source = %q, want %q", got, BindingSourceRetainedBinding)
	}
}

// TestServiceAppliesMatchingIMAPBackendPin verifies normal-weight pins stay scoped.
func TestServiceAppliesMatchingIMAPBackendPin(t *testing.T) {
	store := &placementStoreFixture{
		pin: state.UserBackendPinRecord{
			Present:           true,
			Key:               placementKey(),
			BackendIdentifier: placementBackendB,
			Protocol:          placementProtocol,
			BackendPool:       placementPool,
			ShardTag:          placementShardB,
			BackendNode:       placementNodeB,
		},
	}
	selector := &placementSelectorFixture{registry: placementRegistryFixture()}
	service := mustPlacementService(t, selector, store)

	lease, err := service.PlaceSession(context.Background(), placementRequest("imap-pinned", placementShardB))
	if err != nil {
		t.Fatalf("PlaceSession returned error: %v", err)
	}

	if selector.lastSelect.OperatorBackendIdentifier != placementBackendB {
		t.Fatalf("operator backend = %q, want matching IMAP pin", selector.lastSelect.OperatorBackendIdentifier)
	}

	if lease.Backend().Backend.Identifier != placementBackendB {
		t.Fatalf("selected backend = %q, want pinned IMAP backend", lease.Backend().Backend.Identifier)
	}

	if got := lease.Binding().Source; got != BindingSourceOperatorBackendPin {
		t.Fatalf("binding source = %q, want %q", got, BindingSourceOperatorBackendPin)
	}

	if store.reserveCalls != 1 || store.attachCalls != 1 {
		t.Fatalf("reserve/attach calls = %d/%d, want 1/1", store.reserveCalls, store.attachCalls)
	}
}

// TestServiceAppliesMatchingSieveBackendPin verifies Sieve pins stay protocol and pool scoped.
func TestServiceAppliesMatchingSieveBackendPin(t *testing.T) {
	store := &placementStoreFixture{
		pin: state.UserBackendPinRecord{
			Present:           true,
			Key:               placementKey(),
			BackendIdentifier: placementBackendBSieve,
			Protocol:          placementSieveProtocol,
			BackendPool:       placementSievePool,
			ShardTag:          placementShardB,
			BackendNode:       placementNodeB,
		},
	}
	selector := &placementSelectorFixture{registry: placementRegistryFixture()}
	service := mustPlacementService(t, selector, store)

	lease, err := service.PlaceSession(context.Background(), placementSieveRequest("sieve-pinned", placementShardB))
	if err != nil {
		t.Fatalf("PlaceSession returned error: %v", err)
	}

	if selector.lastSelect.OperatorBackendIdentifier != placementBackendBSieve {
		t.Fatalf("operator backend = %q, want matching Sieve pin", selector.lastSelect.OperatorBackendIdentifier)
	}

	if lease.Backend().Backend.Identifier != placementBackendBSieve {
		t.Fatalf("selected backend = %q, want pinned Sieve backend", lease.Backend().Backend.Identifier)
	}

	if got := lease.Binding().Source; got != BindingSourceOperatorBackendPin {
		t.Fatalf("binding source = %q, want %q", got, BindingSourceOperatorBackendPin)
	}
}

// TestServiceRepairsReservationsBeforeInitialSelection verifies stale capacity state is repaired first.
func TestServiceRepairsReservationsBeforeInitialSelection(t *testing.T) {
	store := &placementStoreFixture{}
	selector := &placementSelectorFixture{registry: placementRegistryFixture()}
	service := mustPlacementService(t, selector, store)

	lease, err := service.PlaceSession(context.Background(), placementRequest("session-after-reservation-repair", placementShardA))
	if err != nil {
		t.Fatalf("PlaceSession returned error: %v", err)
	}

	if lease.Backend().Backend.Identifier != placementBackendA {
		t.Fatalf("selected backend = %q, want initial backend", lease.Backend().Backend.Identifier)
	}

	if store.reapBackendCalls != 1 {
		t.Fatalf("backend reservation reap calls = %d, want one candidate repair", store.reapBackendCalls)
	}
}

// TestServiceFailsClosedWhenReservationRepairFails verifies Redis repair failures block placement.
func TestServiceFailsClosedWhenReservationRepairFails(t *testing.T) {
	store := &placementStoreFixture{reapBackendErr: errors.New("redis unavailable")}
	selector := &placementSelectorFixture{registry: placementRegistryFixture()}
	service := mustPlacementService(t, selector, store)

	_, err := service.PlaceSession(context.Background(), placementRequest("session-repair-failure", placementShardA))
	if err == nil {
		t.Fatal("PlaceSession returned nil error, want repair failure")
	}

	if selector.selectCalls != 0 || len(store.opened) != 0 {
		t.Fatalf("selector/open calls = %d/%d, want fail before selection and mutation", selector.selectCalls, len(store.opened))
	}
}

// TestServiceIgnoresCrossProtocolBackendPinForSieve verifies IMAP pins do not name Sieve targets.
func TestServiceIgnoresCrossProtocolBackendPinForSieve(t *testing.T) {
	store := &placementStoreFixture{
		pin: state.UserBackendPinRecord{
			Present:           true,
			Key:               placementKey(),
			BackendIdentifier: placementBackendA,
			Protocol:          placementProtocol,
			BackendPool:       placementPool,
			ShardTag:          placementShardA,
		},
	}
	selector := &placementSelectorFixture{registry: placementRegistryFixture()}
	service := mustPlacementService(t, selector, store)

	lease, err := service.PlaceSession(context.Background(), placementSieveRequest("sieve-cross-pin", placementShardA))
	if err != nil {
		t.Fatalf("PlaceSession returned error: %v", err)
	}

	if selector.lastSelect.OperatorBackendIdentifier != "" {
		t.Fatalf("operator backend = %q, want cross-protocol pin ignored", selector.lastSelect.OperatorBackendIdentifier)
	}

	if lease.Backend().Backend.Identifier != placementBackendASieve {
		t.Fatalf("selected backend = %q, want normal Sieve backend", lease.Backend().Backend.Identifier)
	}
}

// TestServiceReusesCrossProtocolBindingForPOP3Session verifies POP3 resolves existing protocol-neutral bindings by backend node.
func TestServiceReusesCrossProtocolBindingForPOP3Session(t *testing.T) {
	tests := []struct {
		name                string
		status              string
		bindingStatus       state.BindingStatus
		activeSessionCount  int
		activeHolderCount   int
		retentionExpiresAt  time.Time
		wantBindingSource   BindingSource
		wantOpenedSessionID string
	}{
		{
			name:                "active IMAP",
			status:              affinityStatusFound,
			bindingStatus:       state.BindingStatusActive,
			activeSessionCount:  1,
			activeHolderCount:   1,
			wantBindingSource:   BindingSourceActiveAffinity,
			wantOpenedSessionID: "pop3-from-active-imap",
		},
		{
			name:                "active ManageSieve",
			status:              affinityStatusFound,
			bindingStatus:       state.BindingStatusActive,
			activeSessionCount:  1,
			activeHolderCount:   1,
			wantBindingSource:   BindingSourceActiveAffinity,
			wantOpenedSessionID: "pop3-from-active-sieve",
		},
		{
			name:                "active LMTP delivery hold",
			status:              affinityStatusFound,
			bindingStatus:       state.BindingStatusActive,
			activeSessionCount:  0,
			activeHolderCount:   1,
			wantBindingSource:   BindingSourceActiveAffinity,
			wantOpenedSessionID: "pop3-from-active-lmtp",
		},
		{
			name:                "retained IMAP",
			status:              affinityStatusRetained,
			bindingStatus:       state.BindingStatusRetained,
			retentionExpiresAt:  time.Now().Add(time.Minute),
			wantBindingSource:   BindingSourceRetainedBinding,
			wantOpenedSessionID: "pop3-from-retained-imap",
		},
		{
			name:                "retained ManageSieve",
			status:              affinityStatusRetained,
			bindingStatus:       state.BindingStatusRetained,
			retentionExpiresAt:  time.Now().Add(time.Minute),
			wantBindingSource:   BindingSourceRetainedBinding,
			wantOpenedSessionID: "pop3-from-retained-sieve",
		},
		{
			name:                "retained LMTP",
			status:              affinityStatusRetained,
			bindingStatus:       state.BindingStatusRetained,
			retentionExpiresAt:  time.Now().Add(time.Minute),
			wantBindingSource:   BindingSourceRetainedBinding,
			wantOpenedSessionID: "pop3-from-retained-lmtp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &placementStoreFixture{
				affinity: state.AffinityRecord{
					Key:                placementKey(),
					ShardTag:           placementShardA,
					BackendNode:        placementNodeA,
					Status:             tt.status,
					Present:            true,
					BindingStatus:      tt.bindingStatus,
					ActiveSessionCount: tt.activeSessionCount,
					ActiveHolderCount:  tt.activeHolderCount,
					RetentionExpiresAt: tt.retentionExpiresAt,
				},
			}
			selector := &placementSelectorFixture{registry: placementRegistryFixture()}
			service := mustPlacementService(t, selector, store)

			lease, err := service.PlaceSession(context.Background(), placementPOP3Request(tt.wantOpenedSessionID, placementShardB))
			if err != nil {
				t.Fatalf("PlaceSession returned error: %v", err)
			}

			if selector.selectCalls != 0 || selector.nodeCalls != 1 {
				t.Fatalf("selector calls select=%d node=%d, want node-only POP3 reuse", selector.selectCalls, selector.nodeCalls)
			}

			if lease.Backend().Backend.Identifier != placementBackendAPOP3 {
				t.Fatalf("selected backend = %q, want POP3 backend in existing node", lease.Backend().Backend.Identifier)
			}

			if got := lease.Binding().Source; got != tt.wantBindingSource {
				t.Fatalf("binding source = %q, want %q", got, tt.wantBindingSource)
			}

			if store.opened[0].Protocol != placementPOP3Protocol || store.opened[0].BackendNode != placementNodeA {
				t.Fatalf("opened POP3 session = %#v, want existing backend node", store.opened[0])
			}
		})
	}
}

// TestServiceAppliesMatchingPOP3BackendPin verifies POP3 pins stay protocol and pool scoped.
func TestServiceAppliesMatchingPOP3BackendPin(t *testing.T) {
	store := &placementStoreFixture{
		pin: state.UserBackendPinRecord{
			Present:           true,
			Key:               placementKey(),
			BackendIdentifier: placementBackendBPOP3,
			Protocol:          placementPOP3Protocol,
			BackendPool:       placementPOP3Pool,
			ShardTag:          placementShardB,
			BackendNode:       placementNodeB,
		},
	}
	selector := &placementSelectorFixture{registry: placementRegistryFixture()}
	service := mustPlacementService(t, selector, store)

	lease, err := service.PlaceSession(context.Background(), placementPOP3Request("pop3-pinned", placementShardB))
	if err != nil {
		t.Fatalf("PlaceSession returned error: %v", err)
	}

	if selector.lastSelect.OperatorBackendIdentifier != placementBackendBPOP3 {
		t.Fatalf("operator backend = %q, want matching POP3 pin", selector.lastSelect.OperatorBackendIdentifier)
	}

	if lease.Backend().Backend.Identifier != placementBackendBPOP3 {
		t.Fatalf("selected backend = %q, want pinned POP3 backend", lease.Backend().Backend.Identifier)
	}

	if got := lease.Binding().Source; got != BindingSourceOperatorBackendPin {
		t.Fatalf("binding source = %q, want %q", got, BindingSourceOperatorBackendPin)
	}
}

// TestServiceIgnoresCrossProtocolBackendPinForPOP3 verifies non-POP3 pins do not name POP3 targets.
func TestServiceIgnoresCrossProtocolBackendPinForPOP3(t *testing.T) {
	store := &placementStoreFixture{
		pin: state.UserBackendPinRecord{
			Present:           true,
			Key:               placementKey(),
			BackendIdentifier: placementBackendA,
			Protocol:          placementProtocol,
			BackendPool:       placementPool,
			ShardTag:          placementShardA,
		},
	}
	selector := &placementSelectorFixture{registry: placementRegistryFixture()}
	service := mustPlacementService(t, selector, store)

	lease, err := service.PlaceSession(context.Background(), placementPOP3Request("pop3-cross-pin", placementShardA))
	if err != nil {
		t.Fatalf("PlaceSession returned error: %v", err)
	}

	if selector.lastSelect.OperatorBackendIdentifier != "" {
		t.Fatalf("operator backend = %q, want cross-protocol pin ignored", selector.lastSelect.OperatorBackendIdentifier)
	}

	if lease.Backend().Backend.Identifier != placementBackendAPOP3 {
		t.Fatalf("selected backend = %q, want normal POP3 backend", lease.Backend().Backend.Identifier)
	}
}

// TestServiceReadsOnlyMatchingBackendPinScope verifies placement requests a scoped pin read.
func TestServiceReadsOnlyMatchingBackendPinScope(t *testing.T) {
	registry := placementRegistryFixture()
	store := &placementStoreFixture{
		pins: []state.UserBackendPinRecord{
			placementBackendPinFromRegistry(t, registry, placementBackendB),
			placementBackendPinFromRegistry(t, registry, placementBackendBSieve),
		},
	}
	selector := &placementSelectorFixture{registry: registry}
	service := mustPlacementService(t, selector, store)

	lease, err := service.PlaceSession(context.Background(), placementSieveRequest("sieve-scoped-read", placementShardB))
	if err != nil {
		t.Fatalf("PlaceSession returned error: %v", err)
	}

	if store.pinReadCalls != 1 {
		t.Fatalf("pin read calls = %d, want 1", store.pinReadCalls)
	}

	if store.lastPinRead.Protocol != placementSieveProtocol || store.lastPinRead.BackendPool != placementSievePool {
		t.Fatalf("pin read scope = %s/%s, want %s/%s", store.lastPinRead.Protocol, store.lastPinRead.BackendPool, placementSieveProtocol, placementSievePool)
	}

	if lease.Backend().Backend.Identifier != placementBackendBSieve {
		t.Fatalf("selected backend = %q, want scoped Sieve pin", lease.Backend().Backend.Identifier)
	}
}

// TestServiceIgnoresOtherProtocolBackendPinsForAllProtocols verifies non-matching pins stay diagnostic state only.
func TestServiceIgnoresOtherProtocolBackendPinsForAllProtocols(t *testing.T) {
	registry := placementRegistryFixture()

	tests := []struct {
		name        string
		request     Request
		place       func(context.Context, *Service, Request) (LeaseHandle, error)
		pins        []state.UserBackendPinRecord
		wantBackend string
	}{
		{
			name:    "imap ignores non-imap pins",
			request: placementRequest("ignore-imap", placementShardA),
			place: func(ctx context.Context, service *Service, request Request) (LeaseHandle, error) {
				return service.PlaceSession(ctx, request)
			},
			pins: []state.UserBackendPinRecord{
				placementBackendPinFromRegistry(t, registry, placementBackendBSieve),
				placementBackendPinFromRegistry(t, registry, placementBackendALMTP),
				placementBackendPinFromRegistry(t, registry, placementBackendBPOP3),
			},
			wantBackend: placementBackendA,
		},
		{
			name:    "sieve ignores non-sieve pins",
			request: placementSieveRequest("ignore-sieve", placementShardA),
			place: func(ctx context.Context, service *Service, request Request) (LeaseHandle, error) {
				return service.PlaceSession(ctx, request)
			},
			pins: []state.UserBackendPinRecord{
				placementBackendPinFromRegistry(t, registry, placementBackendB),
				placementBackendPinFromRegistry(t, registry, placementBackendALMTP),
				placementBackendPinFromRegistry(t, registry, placementBackendBPOP3),
			},
			wantBackend: placementBackendASieve,
		},
		{
			name:    "lmtp ignores non-lmtp pins",
			request: placementDeliveryRequest("ignore-lmtp", placementShardA),
			place: func(ctx context.Context, service *Service, request Request) (LeaseHandle, error) {
				return service.PlaceDeliveryHold(ctx, request)
			},
			pins: []state.UserBackendPinRecord{
				placementBackendPinFromRegistry(t, registry, placementBackendB),
				placementBackendPinFromRegistry(t, registry, placementBackendBSieve),
				placementBackendPinFromRegistry(t, registry, placementBackendBPOP3),
			},
			wantBackend: placementBackendALMTP,
		},
		{
			name:    "pop3 ignores non-pop3 pins",
			request: placementPOP3Request("ignore-pop3", placementShardA),
			place: func(ctx context.Context, service *Service, request Request) (LeaseHandle, error) {
				return service.PlaceSession(ctx, request)
			},
			pins: []state.UserBackendPinRecord{
				placementBackendPinFromRegistry(t, registry, placementBackendB),
				placementBackendPinFromRegistry(t, registry, placementBackendBSieve),
				placementBackendPinFromRegistry(t, registry, placementBackendALMTP),
			},
			wantBackend: placementBackendAPOP3,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			store := &placementStoreFixture{pins: testCase.pins}
			selector := &placementSelectorFixture{registry: registry}
			service := mustPlacementService(t, selector, store)

			lease, err := testCase.place(context.Background(), service, testCase.request)
			if err != nil {
				t.Fatalf("placement returned error: %v", err)
			}

			if selector.lastSelect.OperatorBackendIdentifier != "" {
				t.Fatalf("operator backend = %q, want non-matching pins ignored", selector.lastSelect.OperatorBackendIdentifier)
			}

			if lease.Backend().Backend.Identifier != testCase.wantBackend {
				t.Fatalf("selected backend = %q, want %q", lease.Backend().Backend.Identifier, testCase.wantBackend)
			}
		})
	}
}

// TestServiceRejectsMatchingBackendPinFactMismatches verifies stale scoped facts fail closed.
func TestServiceRejectsMatchingBackendPinFactMismatches(t *testing.T) {
	tests := []struct {
		name     string
		registry func() *placementRegistry
		pin      state.UserBackendPinRecord
	}{
		{
			name:     "selected shard mismatch",
			registry: placementRegistryFixture,
			pin: state.UserBackendPinRecord{
				Present:           true,
				Key:               placementKey(),
				BackendIdentifier: placementBackendB,
				Protocol:          placementProtocol,
				BackendPool:       placementPool,
				ShardTag:          placementShardB,
				BackendNode:       placementNodeB,
			},
		},
		{
			name:     "stored backend node mismatch",
			registry: placementRegistryFixture,
			pin: state.UserBackendPinRecord{
				Present:           true,
				Key:               placementKey(),
				BackendIdentifier: placementBackendA,
				Protocol:          placementProtocol,
				BackendPool:       placementPool,
				ShardTag:          placementShardA,
				BackendNode:       placementNodeB,
			},
		},
		{
			name:     "target protocol mismatch",
			registry: placementRegistryFixture,
			pin: state.UserBackendPinRecord{
				Present:           true,
				Key:               placementKey(),
				BackendIdentifier: placementBackendALMTP,
				Protocol:          placementProtocol,
				BackendPool:       placementPool,
				ShardTag:          placementShardA,
				BackendNode:       placementNodeA,
			},
		},
		{
			name: "target backend pool mismatch",
			registry: func() *placementRegistry {
				registry := placementRegistryFixture()
				registry.backends["mailstore-a-imap-alt"] = placementBackendWithProtocol("mailstore-a-imap-alt", placementNodeA, placementShardA, placementProtocol, "imap-alt")

				return registry
			},
			pin: state.UserBackendPinRecord{
				Present:           true,
				Key:               placementKey(),
				BackendIdentifier: "mailstore-a-imap-alt",
				Protocol:          placementProtocol,
				BackendPool:       placementPool,
				ShardTag:          placementShardA,
				BackendNode:       placementNodeA,
			},
		},
		{
			name:     "configured backend missing",
			registry: placementRegistryFixture,
			pin: state.UserBackendPinRecord{
				Present:           true,
				Key:               placementKey(),
				BackendIdentifier: "missing-imap",
				Protocol:          placementProtocol,
				BackendPool:       placementPool,
				ShardTag:          placementShardA,
				BackendNode:       placementNodeA,
			},
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			registry := testCase.registry()
			store := &placementStoreFixture{pin: testCase.pin}
			selector := &placementSelectorFixture{registry: registry}
			service := mustPlacementService(t, selector, store)

			_, err := service.PlaceSession(context.Background(), placementRequest("stale-pin", placementShardA))
			if err == nil {
				t.Fatal("PlaceSession returned nil error, want stale pin rejection")
			}

			if selector.selectCalls != 0 || selector.nodeCalls != 0 {
				t.Fatalf("selector calls select=%d node=%d, want fail before selection", selector.selectCalls, selector.nodeCalls)
			}

			if len(store.opened) != 0 {
				t.Fatalf("store opened %d session(s), want fail before mutation", len(store.opened))
			}
		})
	}
}

// TestServiceRetainsScopedPinsForWeightZeroCanaryMove reproduces the overwritten canary pin flow.
func TestServiceRetainsScopedPinsForWeightZeroCanaryMove(t *testing.T) {
	tests := []struct {
		name        string
		request     Request
		place       func(context.Context, *Service, Request) (LeaseHandle, error)
		wantBackend string
	}{
		{
			name:    "imap",
			request: placementRequest("canary-imap", placementNode2Shard),
			place: func(ctx context.Context, service *Service, request Request) (LeaseHandle, error) {
				return service.PlaceSession(ctx, request)
			},
			wantBackend: placementBackendCanaryIMAP,
		},
		{
			name:    "sieve",
			request: placementSieveRequest("canary-sieve", placementNode2Shard),
			place: func(ctx context.Context, service *Service, request Request) (LeaseHandle, error) {
				return service.PlaceSession(ctx, request)
			},
			wantBackend: placementBackendCanarySieve,
		},
		{
			name:    "lmtp",
			request: placementDeliveryRequest("canary-lmtp", placementNode2Shard),
			place: func(ctx context.Context, service *Service, request Request) (LeaseHandle, error) {
				return service.PlaceDeliveryHold(ctx, request)
			},
			wantBackend: placementBackendCanaryLMTP,
		},
		{
			name:    "pop3",
			request: placementPOP3Request("canary-pop3", placementNode2Shard),
			place: func(ctx context.Context, service *Service, request Request) (LeaseHandle, error) {
				return service.PlaceSession(ctx, request)
			},
			wantBackend: placementBackendCanaryPOP3,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			registry := placementCanaryRegistryFixture()
			selector, err := backend.NewStaticSelector(registry, backend.SelectionPolicy{DefaultShard: placementNode2Shard})
			if err != nil {
				t.Fatalf("NewStaticSelector returned error: %v", err)
			}

			store := &placementStoreFixture{
				affinity: state.AffinityRecord{
					Key:             placementKey(),
					Present:         true,
					MoveTargetShard: placementCanaryShard,
					MoveStrategy:    moveStrategyNew,
					BindingStatus:   state.BindingStatusNone,
				},
				pins: []state.UserBackendPinRecord{
					placementBackendPinFromRegistry(t, registry, placementBackendCanaryIMAP),
					placementBackendPinFromRegistry(t, registry, placementBackendCanarySieve),
					placementBackendPinFromRegistry(t, registry, placementBackendCanaryLMTP),
					placementBackendPinFromRegistry(t, registry, placementBackendCanaryPOP3),
				},
			}

			service, err := NewService(registry, selector, store)
			if err != nil {
				t.Fatalf("NewService returned error: %v", err)
			}

			lease, err := testCase.place(context.Background(), service, testCase.request)
			if err != nil {
				t.Fatalf("placement with scoped %s canary pin returned error: %v", testCase.name, err)
			}

			if lease.Backend().Backend.Identifier != testCase.wantBackend {
				t.Fatalf("selected backend = %q, want %q", lease.Backend().Backend.Identifier, testCase.wantBackend)
			}

			if got := lease.Binding().Source; got != BindingSourceOperatorBackendPin {
				t.Fatalf("binding source = %q, want %q", got, BindingSourceOperatorBackendPin)
			}
		})
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
			BackendNode:       placementNodeB,
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

// TestServiceRepairsRetainedBindingWhenProtocolEntryIsMissing verifies idle node-local absence can recover.
func TestServiceRepairsRetainedBindingWhenProtocolEntryIsMissing(t *testing.T) {
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

	lease, err := service.PlaceSession(context.Background(), placementRequest("session-5", placementShardA))
	if err != nil {
		t.Fatalf("PlaceSession returned error: %v", err)
	}

	if selector.selectCalls != 1 || selector.nodeCalls != 1 {
		t.Fatalf("selector calls select=%d node=%d, want failed retained lookup then normal selection", selector.selectCalls, selector.nodeCalls)
	}

	if lease.Backend().Backend.Identifier != placementBackendSameShard {
		t.Fatalf("selected backend = %q, want repaired same-shard backend", lease.Backend().Backend.Identifier)
	}

	if len(store.opened) != 1 || !store.opened[0].RepairRetainedBinding {
		t.Fatalf("opened sessions = %#v, want explicit retained repair proposal", store.opened)
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

// placementSieveRequest creates one complete ManageSieve session placement request fixture.
func placementSieveRequest(sessionID string, shardTag string) Request {
	request := placementRequest(sessionID, shardTag)
	request.Protocol = placementSieveProtocol
	request.BackendPool = placementSievePool
	request.ListenerName = "sieve"
	request.ServiceName = "sieve"

	return request
}

// placementPOP3Request creates one complete POP3 session placement request fixture.
func placementPOP3Request(sessionID string, shardTag string) Request {
	request := placementRequest(sessionID, shardTag)
	request.Protocol = placementPOP3Protocol
	request.BackendPool = placementPOP3Pool
	request.ListenerName = "pop3"
	request.ServiceName = "pop3"

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
			placementBackendA:      placementBackend(placementBackendA, placementNodeA, placementShardA),
			placementBackendALMTP:  placementBackendWithProtocol(placementBackendALMTP, placementNodeA, placementShardA, "lmtp", "lmtp-default"),
			placementBackendAPOP3:  placementBackendWithProtocol(placementBackendAPOP3, placementNodeA, placementShardA, placementPOP3Protocol, placementPOP3Pool),
			placementBackendASieve: placementBackendWithProtocol(placementBackendASieve, placementNodeA, placementShardA, placementSieveProtocol, placementSievePool),
			placementBackendB:      placementBackend(placementBackendB, placementNodeB, placementShardB),
			placementBackendBPOP3:  placementBackendWithProtocol(placementBackendBPOP3, placementNodeB, placementShardB, placementPOP3Protocol, placementPOP3Pool),
			placementBackendBSieve: placementBackendWithProtocol(placementBackendBSieve, placementNodeB, placementShardB, placementSieveProtocol, placementSievePool),
		},
	}
}

// placementCanaryRegistryFixture returns the observed node2 and weight-zero canary topology.
func placementCanaryRegistryFixture() *placementRegistry {
	return &placementRegistry{
		backends: map[string]backend.Backend{
			placementBackendNode2IMAP:   placementBackendWithProtocol(placementBackendNode2IMAP, placementNode2, placementNode2Shard, placementProtocol, placementPool),
			placementBackendNode2Sieve:  placementBackendWithProtocol(placementBackendNode2Sieve, placementNode2, placementNode2Shard, placementSieveProtocol, placementSievePool),
			placementBackendNode2LMTP:   placementBackendWithProtocol(placementBackendNode2LMTP, placementNode2, placementNode2Shard, placementLMTPProtocol, placementLMTPPool),
			placementBackendNode2POP3:   placementBackendWithProtocol(placementBackendNode2POP3, placementNode2, placementNode2Shard, placementPOP3Protocol, placementPOP3Pool),
			placementBackendCanaryIMAP:  placementWeightZeroBackend(placementBackendCanaryIMAP, placementCanaryNode, placementCanaryShard, placementProtocol, placementPool),
			placementBackendCanarySieve: placementWeightZeroBackend(placementBackendCanarySieve, placementCanaryNode, placementCanaryShard, placementSieveProtocol, placementSievePool),
			placementBackendCanaryLMTP:  placementWeightZeroBackend(placementBackendCanaryLMTP, placementCanaryNode, placementCanaryShard, placementLMTPProtocol, placementLMTPPool),
			placementBackendCanaryPOP3:  placementWeightZeroBackend(placementBackendCanaryPOP3, placementCanaryNode, placementCanaryShard, placementPOP3Protocol, placementPOP3Pool),
		},
	}
}

// placementBackendPinFromRegistry derives stored pin facts from the backend registry.
func placementBackendPinFromRegistry(t *testing.T, registry backend.Registry, backendID string) state.UserBackendPinRecord {
	t.Helper()

	entry, err := registry.Lookup(context.Background(), backendID)
	if err != nil {
		t.Fatalf("Lookup(%s) returned error: %v", backendID, err)
	}

	facts := entry.PlacementFacts()

	return state.UserBackendPinRecord{
		Present:           true,
		Key:               placementKey(),
		BackendIdentifier: facts.BackendIdentifier,
		Protocol:          facts.Protocol,
		BackendPool:       facts.BackendPool,
		ShardTag:          facts.EffectiveShard,
		BackendNode:       facts.BackendNode,
	}
}

// placementBackend returns one configured backend fixture.
func placementBackend(identifier string, node string, shard string) backend.Backend {
	return placementBackendWithProtocol(identifier, node, shard, placementProtocol, placementPool)
}

// placementWeightZeroBackend returns one canary backend excluded from normal placement.
func placementWeightZeroBackend(identifier string, node string, shard string, protocol string, pool string) backend.Backend {
	entry := placementBackendWithProtocol(identifier, node, shard, protocol, pool)
	entry.Weight = 0

	return entry
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
	affinity         state.AffinityRecord
	closeAffinity    state.AffinityRecord
	pin              state.UserBackendPinRecord
	pins             []state.UserBackendPinRecord
	opened           []state.SessionRecord
	attachments      []state.SessionBackendAttachment
	attachErr        error
	lastPinRead      state.UserBackendPinGetRequest
	pinReadCalls     int
	reserveCalls     int
	reapBackendErr   error
	reapBackendCalls int
	releaseCalls     int
	attachCalls      int
	closeCalls       int
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

	if record.RepairRetainedBinding {
		status = "retained_binding_repaired"
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
	s.lastPinRead = request
	s.pinReadCalls++

	if len(s.pins) > 0 {
		for _, candidate := range s.pins {
			if pinMatchesProtocolPool(candidate, request.Protocol, request.BackendPool) {
				pin := candidate
				pin.Key = request.Key

				return pin, nil
			}
		}

		return state.UserBackendPinRecord{Key: request.Key}, nil
	}

	if !s.pin.Present || !pinMatchesProtocolPool(s.pin, request.Protocol, request.BackendPool) {
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
	s.reapBackendCalls++
	if s.reapBackendErr != nil {
		return state.BackendReservationRecord{}, s.reapBackendErr
	}

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

	if request.OperatorBackendIdentifier != "" {
		selected, err := s.registry.Lookup(context.Background(), request.OperatorBackendIdentifier)
		if err != nil {
			return backend.SelectionResult{}, err
		}

		return placementSelectionResult(selected, backend.SelectionReasonOperatorBackendPin), nil
	}

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

// Pool returns the backend pool fixture for the requested protocol scope.
func (r *placementRegistry) Pool(_ context.Context, name string) (backend.Pool, error) {
	switch name {
	case placementPool:
		return backend.Pool{Name: name, Protocol: placementProtocol, Selector: "rendezvous_hash", Backends: []string{placementBackendA, placementBackendB, placementBackendNode2IMAP, placementBackendCanaryIMAP}}, nil
	case placementSievePool:
		return backend.Pool{Name: name, Protocol: placementSieveProtocol, Selector: "rendezvous_hash", Backends: []string{placementBackendASieve, placementBackendBSieve, placementBackendNode2Sieve, placementBackendCanarySieve}}, nil
	case placementPOP3Pool:
		return backend.Pool{Name: name, Protocol: placementPOP3Protocol, Selector: "rendezvous_hash", Backends: []string{placementBackendAPOP3, placementBackendBPOP3, placementBackendNode2POP3, placementBackendCanaryPOP3}}, nil
	case placementLMTPPool:
		return backend.Pool{Name: name, Protocol: placementLMTPProtocol, Selector: "rendezvous_hash", Backends: []string{placementBackendALMTP, placementBackendNode2LMTP, placementBackendCanaryLMTP}}, nil
	default:
		return backend.Pool{}, placementBackendError("pool missing")
	}
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
