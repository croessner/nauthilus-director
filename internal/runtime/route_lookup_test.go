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

//nolint:dupl,funlen,goconst,wsl_v5 // Route lookup fixtures repeat public diagnostic strings intentionally.
package runtime

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/routing"
	"github.com/croessner/nauthilus-director/internal/state"
)

const (
	routeLookupAccount        = "alice@example.test"
	routeLookupAttributeShard = "mailShard"
	routeLookupAttributeTier  = "tier"
	routeLookupAttributeToken = "token"
	routeLookupBackendA       = "mailstore-a-imap"
	routeLookupBackendALMTP   = "mailstore-a-lmtp"
	routeLookupBackendAPOP3   = "mailstore-a-pop3"
	routeLookupBackendASieve  = "mailstore-a-sieve"
	routeLookupBackendB       = "mailstore-b-imap"
	routeLookupBackendBPOP3   = "mailstore-b-pop3"
	routeLookupBackendBSieve  = "mailstore-b-sieve"
	routeLookupCanonicalLMTP  = "canonical@example.test"
	routeLookupDefaultPool    = "imap-default"
	routeLookupHoldGeneration = "hold-7"
	routeLookupListener       = "imap"
	routeLookupPoolLMTP       = "lmtp-default"
	routeLookupPoolPOP3       = "pop3-default"
	routeLookupPoolSieve      = "sieve-default"
	routeLookupProtocol       = "imap"
	routeLookupProtocolPOP3   = "pop3"
	routeLookupProtocolSieve  = "sieve"
	routeLookupSecretValue    = "super-secret-value"
	routeLookupShardA         = "mailstore-a"
	routeLookupShardB         = "mailstore-b"
	routeLookupTenantAttr     = "tenant"
	routeLookupTenantBlue     = "blue"
)

// routeLookupExclusionCase describes one runtime exclusion explanation scenario.
type routeLookupExclusionCase struct {
	name       string
	snapshot   backend.RuntimeSnapshot
	health     bool
	wantEffect func(RouteLookupEffects) bool
	wantReason backend.EffectiveExclusionReason
}

// TestRouteLookupAcceptsSieveProtocol verifies ManageSieve diagnostics use shared selector input.
func TestRouteLookupAcceptsSieveProtocol(t *testing.T) {
	service := newRouteLookupTestService(t, &countingRouteState{}, false)

	response, err := service.Lookup(context.Background(), RouteLookupRequest{
		Protocol:     routeLookupProtocolSieve,
		ListenerName: routeLookupProtocolSieve,
		AccountKey:   routeLookupAccount,
		Attributes: map[string][]string{
			routeLookupAttributeShard: {routeLookupShardA},
		},
	})
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}

	if response.SelectedBackend != routeLookupBackendASieve {
		t.Fatalf("selected backend = %q, want %s", response.SelectedBackend, routeLookupBackendASieve)
	}

	foundPool := false
	for _, candidate := range response.Backends {
		if candidate.Identifier == routeLookupBackendASieve && candidate.BackendPool == routeLookupPoolSieve && candidate.Protocol == routeLookupProtocolSieve {
			foundPool = true
		}
	}
	if !foundPool {
		t.Fatalf("backends = %#v, want selected Sieve backend in sieve-default pool", response.Backends)
	}
}

// TestRouteLookupAcceptsPOP3Protocol verifies POP3 diagnostics use shared selector input.
func TestRouteLookupAcceptsPOP3Protocol(t *testing.T) {
	service := newRouteLookupTestService(t, &countingRouteState{}, false)

	response, err := service.Lookup(context.Background(), RouteLookupRequest{
		Protocol:     routeLookupProtocolPOP3,
		ListenerName: routeLookupProtocolPOP3,
		AccountKey:   routeLookupAccount,
		Attributes: map[string][]string{
			routeLookupAttributeShard: {routeLookupShardA},
		},
	})
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}

	if response.SelectedBackend != routeLookupBackendAPOP3 {
		t.Fatalf("selected backend = %q, want %s", response.SelectedBackend, routeLookupBackendAPOP3)
	}

	foundPool := false
	for _, candidate := range response.Backends {
		if candidate.Identifier == routeLookupBackendAPOP3 && candidate.BackendPool == routeLookupPoolPOP3 && candidate.Protocol == routeLookupProtocolPOP3 {
			foundPool = true
		}
	}
	if !foundPool {
		t.Fatalf("backends = %#v, want selected POP3 backend in pop3-default pool", response.Backends)
	}
}

// TestRouteLookupDefaultsBackendPoolByProtocol verifies listener defaults support bare user lookups.
func TestRouteLookupDefaultsBackendPoolByProtocol(t *testing.T) {
	for _, test := range []struct {
		name         string
		protocol     string
		wantSelected string
	}{
		{name: "sieve", protocol: routeLookupProtocolSieve, wantSelected: routeLookupBackendASieve},
		{name: "pop3", protocol: routeLookupProtocolPOP3, wantSelected: routeLookupBackendAPOP3},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := newRouteLookupTestService(t, &countingRouteState{}, false)

			response, err := service.Lookup(context.Background(), RouteLookupRequest{
				Protocol:   test.protocol,
				AccountKey: routeLookupAccount,
				Attributes: map[string][]string{
					routeLookupAttributeShard: {routeLookupShardA},
				},
			})
			if err != nil {
				t.Fatalf("Lookup returned error: %v", err)
			}

			if response.SelectedBackend != test.wantSelected {
				t.Fatalf("selected backend = %q, want %s from protocol default pool", response.SelectedBackend, test.wantSelected)
			}
		})
	}
}

// TestRouteLookupReportsSieveBackendPinContexts verifies Sieve pin diagnostics stay shared.
func TestRouteLookupReportsSieveBackendPinContexts(t *testing.T) {
	tests := []struct {
		name         string
		pin          state.UserBackendPinRecord
		snapshots    map[string]backend.RuntimeSnapshot
		shard        string
		wantSelected string
		wantPresent  bool
		wantApplied  bool
		wantReason   string
		wantFail     bool
	}{
		{
			name: "matching",
			pin: state.UserBackendPinRecord{
				Present:           true,
				BackendIdentifier: routeLookupBackendBSieve,
				Protocol:          routeLookupProtocolSieve,
				BackendPool:       routeLookupPoolSieve,
				ShardTag:          routeLookupShardB,
				BackendNode:       "mailstore-b-node-1",
				Generation:        "sieve-pin-1",
			},
			shard:        routeLookupShardB,
			wantSelected: routeLookupBackendBSieve,
			wantPresent:  true,
			wantApplied:  true,
			wantReason:   routeLookupBackendPinApplied,
		},
		{
			name: "other protocol",
			pin: state.UserBackendPinRecord{
				Present:           true,
				BackendIdentifier: routeLookupBackendA,
				Protocol:          routeLookupProtocol,
				BackendPool:       routeLookupDefaultPool,
				ShardTag:          routeLookupShardA,
				BackendNode:       "mailstore-a-node-1",
				Generation:        "imap-pin-1",
			},
			shard:        routeLookupShardA,
			wantSelected: routeLookupBackendASieve,
			wantReason:   routeLookupBackendPinOtherScopes,
		},
		{
			name: "unusable",
			pin: state.UserBackendPinRecord{
				Present:           true,
				BackendIdentifier: routeLookupBackendASieve,
				Protocol:          routeLookupProtocolSieve,
				BackendPool:       routeLookupPoolSieve,
				ShardTag:          routeLookupShardA,
				BackendNode:       "mailstore-a-node-1",
				Generation:        "sieve-pin-2",
			},
			snapshots: map[string]backend.RuntimeSnapshot{
				routeLookupBackendASieve: {
					RuntimeOverride: backend.RuntimeOverride{
						InService: new(false),
					},
				},
			},
			shard:       routeLookupShardA,
			wantPresent: true,
			wantReason:  string(backend.EffectiveExclusionRuntimeOut),
			wantFail:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &countingRouteState{backendPin: test.pin, snapshots: test.snapshots}
			service := newRouteLookupTestService(t, store, false)

			response, err := service.Lookup(context.Background(), RouteLookupRequest{
				Protocol:     routeLookupProtocolSieve,
				ListenerName: routeLookupProtocolSieve,
				AccountKey:   routeLookupAccount,
				Attributes: map[string][]string{
					routeLookupAttributeShard: {test.shard},
				},
			})
			if err != nil {
				t.Fatalf("Lookup returned error: %v", err)
			}

			if response.SelectedBackend != test.wantSelected || response.FailClosed != test.wantFail {
				t.Fatalf("response selected/fail = %q/%t, want %q/%t", response.SelectedBackend, response.FailClosed, test.wantSelected, test.wantFail)
			}

			if response.BackendPin.Present != test.wantPresent || response.BackendPin.Applied != test.wantApplied || response.BackendPin.ReasonClass != test.wantReason {
				t.Fatalf("backend pin = %#v, want present=%t applied=%t reason=%s", response.BackendPin, test.wantPresent, test.wantApplied, test.wantReason)
			}

			assertNoRouteLookupMutations(t, store)
		})
	}
}

// TestRouteLookupReportsPOP3BackendPinContexts verifies POP3 pin diagnostics stay shared.
func TestRouteLookupReportsPOP3BackendPinContexts(t *testing.T) {
	tests := []struct {
		name         string
		pin          state.UserBackendPinRecord
		snapshots    map[string]backend.RuntimeSnapshot
		shard        string
		wantSelected string
		wantPresent  bool
		wantApplied  bool
		wantReason   string
		wantFail     bool
	}{
		{
			name: "matching",
			pin: state.UserBackendPinRecord{
				Present:           true,
				BackendIdentifier: routeLookupBackendBPOP3,
				Protocol:          routeLookupProtocolPOP3,
				BackendPool:       routeLookupPoolPOP3,
				ShardTag:          routeLookupShardB,
				BackendNode:       "mailstore-b-node-1",
				Generation:        "pop3-pin-1",
			},
			shard:        routeLookupShardB,
			wantSelected: routeLookupBackendBPOP3,
			wantPresent:  true,
			wantApplied:  true,
			wantReason:   routeLookupBackendPinApplied,
		},
		{
			name: "other protocol",
			pin: state.UserBackendPinRecord{
				Present:           true,
				BackendIdentifier: routeLookupBackendA,
				Protocol:          routeLookupProtocol,
				BackendPool:       routeLookupDefaultPool,
				ShardTag:          routeLookupShardA,
				BackendNode:       "mailstore-a-node-1",
				Generation:        "imap-pin-1",
			},
			shard:        routeLookupShardA,
			wantSelected: routeLookupBackendAPOP3,
			wantReason:   routeLookupBackendPinOtherScopes,
		},
		{
			name: "unusable",
			pin: state.UserBackendPinRecord{
				Present:           true,
				BackendIdentifier: routeLookupBackendAPOP3,
				Protocol:          routeLookupProtocolPOP3,
				BackendPool:       routeLookupPoolPOP3,
				ShardTag:          routeLookupShardA,
				BackendNode:       "mailstore-a-node-1",
				Generation:        "pop3-pin-2",
			},
			snapshots: map[string]backend.RuntimeSnapshot{
				routeLookupBackendAPOP3: {
					RuntimeOverride: backend.RuntimeOverride{
						InService: new(false),
					},
				},
			},
			shard:       routeLookupShardA,
			wantPresent: true,
			wantReason:  string(backend.EffectiveExclusionRuntimeOut),
			wantFail:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &countingRouteState{backendPin: test.pin, snapshots: test.snapshots}
			service := newRouteLookupTestService(t, store, false)

			response, err := service.Lookup(context.Background(), RouteLookupRequest{
				Protocol:     routeLookupProtocolPOP3,
				ListenerName: routeLookupProtocolPOP3,
				AccountKey:   routeLookupAccount,
				Attributes: map[string][]string{
					routeLookupAttributeShard: {test.shard},
				},
			})
			if err != nil {
				t.Fatalf("Lookup returned error: %v", err)
			}

			if response.SelectedBackend != test.wantSelected || response.FailClosed != test.wantFail {
				t.Fatalf("response selected/fail = %q/%t, want %q/%t", response.SelectedBackend, response.FailClosed, test.wantSelected, test.wantFail)
			}

			if response.BackendPin.Present != test.wantPresent || response.BackendPin.Applied != test.wantApplied || response.BackendPin.ReasonClass != test.wantReason {
				t.Fatalf("backend pin = %#v, want present=%t applied=%t reason=%s", response.BackendPin, test.wantPresent, test.wantApplied, test.wantReason)
			}

			assertNoRouteLookupMutations(t, store)
		})
	}
}

// TestRouteLookupUsesResolverSelectorAndReadOnlyAffinity verifies the shared read-only path.
func TestRouteLookupUsesResolverSelectorAndReadOnlyAffinity(t *testing.T) {
	store := &countingRouteState{
		affinity: state.AffinityRecord{
			Present:            true,
			Status:             "found",
			ShardTag:           routeLookupShardB,
			BackendNode:        "mailstore-b-node-1",
			BackendIdentifier:  routeLookupBackendB,
			Generation:         "affinity-7",
			BindingStatus:      state.BindingStatusActive,
			ActiveSessionCount: 2,
			ActiveHolderCount:  2,
		},
	}
	recorder := &recordingRuntimeObservation{}
	service := newRouteLookupTestService(t, store, false, recorder)

	response, err := service.Lookup(context.Background(), RouteLookupRequest{
		Protocol:        routeLookupProtocol,
		ListenerName:    routeLookupListener,
		AccountKey:      routeLookupAccount,
		IncludeAffinity: true,
		Attributes: map[string][]string{
			routeLookupAttributeShard: {routeLookupShardA},
		},
	})
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}

	if response.Routing.RoutingSource != routing.SourceAuthAttribute {
		t.Fatalf("routing source = %q, want auth_attribute", response.Routing.RoutingSource)
	}

	if response.Affinity.ActiveSessions != 2 || !response.Affinity.Active {
		t.Fatalf("affinity = %#v, want active read-only context", response.Affinity)
	}

	if response.SelectedBackend != routeLookupBackendB || response.Routing.EffectiveShard != routeLookupShardB {
		t.Fatalf("selected %q shard %q, want active affinity backend %q shard %q", response.SelectedBackend, response.Routing.EffectiveShard, routeLookupBackendB, routeLookupShardB)
	}

	if response.Source != routeLookupSourceActiveAffinity || response.Affinity.BackendNode != "mailstore-b-node-1" || response.Affinity.ActiveHolders != 2 {
		t.Fatalf("source/affinity = %q/%#v, want active backend-node binding", response.Source, response.Affinity)
	}

	if store.lookupAffinityCalls != 1 {
		t.Fatalf("LookupAffinity calls = %d, want 1", store.lookupAffinityCalls)
	}

	if store.backendSnapshotCalls == 0 {
		t.Fatal("BackendSnapshot was not read")
	}

	assertNoRouteLookupMutations(t, store)
}

// TestRouteLookupReportsOutboundProxyRequirement verifies transport diagnostics stay read-only.
func TestRouteLookupReportsOutboundProxyRequirement(t *testing.T) {
	store := &countingRouteState{}
	service := newRouteLookupTestService(t, store, false)

	response, err := service.Lookup(context.Background(), RouteLookupRequest{
		Protocol:     routeLookupProtocol,
		ListenerName: routeLookupListener,
		AccountKey:   routeLookupAccount,
		Attributes: map[string][]string{
			routeLookupAttributeShard: {routeLookupShardA},
		},
	})
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}

	if response.SelectedBackend != routeLookupBackendA {
		t.Fatalf("selected backend = %q, want %q", response.SelectedBackend, routeLookupBackendA)
	}

	if !routeLookupBackendHasOutboundProxy(response.Backends, routeLookupBackendA) {
		t.Fatalf("route lookup backends = %#v, want outbound PROXY diagnostic for %s", response.Backends, routeLookupBackendA)
	}

	if store.backendSnapshotCalls == 0 {
		t.Fatal("BackendSnapshot was not read")
	}

	assertNoRouteLookupMutations(t, store)
}

// TestRouteLookupReportsRetainedBackendBinding verifies retained backend-node reuse is diagnostic only.
func TestRouteLookupReportsRetainedBackendBinding(t *testing.T) {
	retentionExpiresAt := time.Now().Add(15 * time.Minute).UTC()
	store := &countingRouteState{
		affinity: state.AffinityRecord{
			Present:            true,
			Status:             "retained",
			ShardTag:           routeLookupShardA,
			BackendNode:        "mailstore-a-node-1",
			BindingStatus:      state.BindingStatusRetained,
			ActiveSessionCount: 0,
			ActiveHolderCount:  0,
			RetentionExpiresAt: retentionExpiresAt,
			ServerTime:         time.Now().UTC(),
		},
	}
	recorder := &recordingRuntimeObservation{}
	service := newRouteLookupTestService(t, store, false, recorder)

	response, err := service.Lookup(context.Background(), RouteLookupRequest{
		Protocol:        routeLookupProtocol,
		AccountKey:      routeLookupAccount,
		IncludeAffinity: true,
		Attributes: map[string][]string{
			routeLookupAttributeShard: {routeLookupShardB},
		},
	})
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}

	if response.SelectedBackend != routeLookupBackendA || response.Source != routeLookupSourceRetainedBinding {
		t.Fatalf("selected/source = %q/%q, want retained binding on %s", response.SelectedBackend, response.Source, routeLookupBackendA)
	}

	if !response.Affinity.Retained || !response.Affinity.RetentionExpiresAt.Equal(retentionExpiresAt) {
		t.Fatalf("affinity = %#v, want retained expiry context", response.Affinity)
	}

	assertNoRouteLookupMutations(t, store)
}

// TestRouteLookupFailClosesWhenBoundBackendNodeLacksProtocol verifies no same-shard fallback occurs.
func TestRouteLookupFailClosesWhenBoundBackendNodeLacksProtocol(t *testing.T) {
	store := &countingRouteState{
		affinity: state.AffinityRecord{
			Present:       true,
			Status:        "retained",
			ShardTag:      routeLookupShardA,
			BackendNode:   "missing-node",
			BindingStatus: state.BindingStatusRetained,
			ServerTime:    time.Now().UTC(),
		},
	}
	recorder := &recordingRuntimeObservation{}
	service := newRouteLookupTestService(t, store, false, recorder)

	response, err := service.Lookup(context.Background(), RouteLookupRequest{
		Protocol:        routeLookupProtocol,
		AccountKey:      routeLookupAccount,
		BackendPool:     routeLookupDefaultPool,
		IncludeAffinity: true,
	})
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}

	if !response.FailClosed || response.Source != routeLookupSourceFailClosed || response.ReasonClass != routeLookupReasonBindingMissing {
		t.Fatalf("response = %#v, want fail-closed missing backend-node protocol", response)
	}

	assertNoRouteLookupMutations(t, store)
}

// TestRouteLookupExplanationsReflectRuntimeExclusions verifies selector explanations.
func TestRouteLookupExplanationsReflectRuntimeExclusions(t *testing.T) {
	for _, test := range routeLookupExclusionCases(time.Now().UTC()) {
		t.Run(test.name, func(t *testing.T) {
			store := &countingRouteState{
				snapshots: map[string]backend.RuntimeSnapshot{
					routeLookupBackendA: test.snapshot,
				},
			}
			service := newRouteLookupTestService(t, store, test.health)

			response, err := service.Lookup(context.Background(), RouteLookupRequest{
				Protocol:   routeLookupProtocol,
				AccountKey: routeLookupAccount,
				Attributes: map[string][]string{
					routeLookupAttributeShard: {routeLookupShardA},
				},
			})
			if err != nil {
				t.Fatalf("Lookup returned error: %v", err)
			}

			if !response.FailClosed || response.ReasonClass != string(backend.ErrorKindNoBackend) {
				t.Fatalf("response fail closed = %t reason = %q, want no backend", response.FailClosed, response.ReasonClass)
			}

			if !test.wantEffect(response.Effects) {
				t.Fatalf("effects = %#v, want %s marked", response.Effects, test.name)
			}

			if !routeLookupHasExclusion(response.Backends, test.wantReason) {
				t.Fatalf("backends = %#v, want exclusion %q", response.Backends, test.wantReason)
			}

			assertNoRouteLookupMutations(t, store)
		})
	}
}

// TestRouteLookupRejectsCredentialAndMailboxBearingAttributes verifies unsafe fields fail closed.
func TestRouteLookupRejectsCredentialAndMailboxBearingAttributes(t *testing.T) {
	for _, attributeName := range []string{
		routeLookupAttributeToken,
		"password",
		"sasl_blob",
		"uidl",
		"message_number",
		"message_size",
		"message_content",
		"mailbox",
	} {
		t.Run(attributeName, func(t *testing.T) {
			store := &countingRouteState{}
			service := newRouteLookupTestService(t, store, false)

			_, err := service.Lookup(context.Background(), RouteLookupRequest{
				Protocol:   routeLookupProtocolPOP3,
				AccountKey: routeLookupAccount,
				Attributes: map[string][]string{
					attributeName: {routeLookupSecretValue},
				},
			})
			if !IsErrorKind(err, ErrorKindInvalidRequest) {
				t.Fatalf("Lookup error = %v, want invalid request", err)
			}

			if store.backendSnapshotCalls != 0 || store.lookupAffinityCalls != 0 || store.backendPinGetCalls != 0 || store.userHoldCheckCalls != 0 {
				t.Fatalf("route lookup performed reads after rejected input: %#v", store)
			}

			assertNoRouteLookupMutations(t, store)
		})
	}
}

// TestRouteLookupRejectsRecipientOutsideLMTP keeps POP3 user-key diagnostics mailbox-free.
func TestRouteLookupRejectsRecipientOutsideLMTP(t *testing.T) {
	store := &countingRouteState{}
	service := newRouteLookupTestService(t, store, false)

	_, err := service.Lookup(context.Background(), RouteLookupRequest{
		Protocol:   routeLookupProtocolPOP3,
		AccountKey: routeLookupAccount,
		Recipient:  "<user@example.test>",
	})
	if !IsErrorKind(err, ErrorKindInvalidRequest) {
		t.Fatalf("Lookup error = %v, want invalid request", err)
	}

	if store.backendSnapshotCalls != 0 || store.lookupAffinityCalls != 0 || store.backendPinGetCalls != 0 || store.userHoldCheckCalls != 0 {
		t.Fatalf("route lookup performed reads after rejected recipient input: %#v", store)
	}

	assertNoRouteLookupMutations(t, store)
}

// TestRouteLookupResponseOmitsBenignAttributeValues verifies safe output.
func TestRouteLookupResponseOmitsBenignAttributeValues(t *testing.T) {
	store := &countingRouteState{}
	service := newRouteLookupTestService(t, store, false)

	response, err := service.Lookup(context.Background(), RouteLookupRequest{
		Protocol:   routeLookupProtocol,
		AccountKey: routeLookupAccount,
		Attributes: map[string][]string{
			routeLookupAttributeShard: {routeLookupShardA},
			routeLookupAttributeTier:  {routeLookupSecretValue},
		},
	})
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}

	rendered := fmt.Sprintf("%#v", response)
	if strings.Contains(rendered, routeLookupSecretValue) || strings.Contains(rendered, routeLookupAttributeTier) {
		t.Fatalf("route lookup response leaked attribute input: %s", rendered)
	}

	assertNoRouteLookupMutations(t, store)
}

// defaultRouteLookupRequest returns the common shard-scoped diagnostic request.
func defaultRouteLookupRequest() RouteLookupRequest {
	return RouteLookupRequest{
		Protocol:   routeLookupProtocol,
		AccountKey: routeLookupAccount,
		Attributes: map[string][]string{
			routeLookupAttributeShard: {routeLookupShardA},
		},
	}
}

// lookupDefaultRoute performs the common successful lookup assertion path.
func lookupDefaultRoute(t *testing.T, service *RouteLookupService) RouteLookupResponse {
	t.Helper()

	response, err := service.Lookup(context.Background(), defaultRouteLookupRequest())
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}

	return response
}

// lookupDefaultRouteError returns the expected common lookup failure.
func lookupDefaultRouteError(t *testing.T, service *RouteLookupService) error {
	t.Helper()

	_, err := service.Lookup(context.Background(), defaultRouteLookupRequest())
	if err == nil {
		t.Fatal("Lookup returned nil error, want read failure")
	}

	return err
}

// assertRouteLookupObservationLabels verifies the bounded operation labels.
func assertRouteLookupObservationLabels(t *testing.T, recorder *recordingRuntimeObservation, eventName string, operation string, reasonClass string, result string) observability.Event {
	t.Helper()

	event, ok := recorder.last(eventName)
	if !ok {
		t.Fatalf("%s observation missing: %#v", eventName, recorder.events)
	}

	if got := event.MetricLabels["operation"]; got != operation {
		t.Fatalf("operation = %q, want %q", got, operation)
	}

	if got := event.MetricLabels["reason_class"]; got != reasonClass {
		t.Fatalf("reason class = %q, want %q", got, reasonClass)
	}

	if got := event.MetricLabels["result"]; got != result {
		t.Fatalf("result = %q, want %q", got, result)
	}

	return event
}

// assertRouteLookupMetricLabelsSafe verifies high-cardinality pin facts stay out of labels.
func assertRouteLookupMetricLabelsSafe(t *testing.T, event observability.Event) {
	t.Helper()

	for _, forbidden := range []string{
		runtimeObservationFieldBackendID,
		runtimeObservationFieldBackendNode,
		runtimeObservationFieldUserHash,
		"username",
		"recipient",
		"session_id",
		"trace_id",
		"request_id",
		"client_ip",
		"raw_error",
	} {
		if _, ok := event.MetricLabels[forbidden]; ok {
			t.Fatalf("metric labels contain forbidden %q: %#v", forbidden, event.MetricLabels)
		}
	}
}

// assertActiveUserHoldContext verifies diagnostic hold deferral facts.
func assertActiveUserHoldContext(t *testing.T, response RouteLookupResponse) {
	t.Helper()

	if !response.UserHold.Present ||
		!response.UserHold.PlacementDeferred ||
		response.UserHold.ReasonClass != routeLookupUserHoldActive ||
		response.UserHold.Remaining != 5*time.Minute ||
		response.UserHold.Generation != routeLookupHoldGeneration {
		t.Fatalf("user hold = %#v, want active deferral context", response.UserHold)
	}

	if !response.Effects.UserHold {
		t.Fatalf("effects = %#v, want user hold marked", response.Effects)
	}
}

// TestRouteLookupReportsAbsentBackendPinContext verifies absent pin diagnostics.
func TestRouteLookupReportsAbsentBackendPinContext(t *testing.T) {
	store := &countingRouteState{}
	service := newRouteLookupTestService(t, store, false)

	response, err := service.Lookup(context.Background(), RouteLookupRequest{
		Protocol:   routeLookupProtocol,
		AccountKey: routeLookupAccount,
		Attributes: map[string][]string{
			routeLookupAttributeShard: {routeLookupShardA},
		},
	})
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}

	if response.BackendPin.Present || response.BackendPin.Applied || response.BackendPin.ReasonClass != routeLookupBackendPinAbsent {
		t.Fatalf("backend pin = %#v, want absent context", response.BackendPin)
	}

	if store.backendPinGetCalls != 1 {
		t.Fatalf("backend pin reads = %d, want 1", store.backendPinGetCalls)
	}

	assertNoRouteLookupMutations(t, store)
}

// TestRouteLookupReportsAppliedBackendPinContext verifies matching pins constrain selection.
func TestRouteLookupReportsAppliedBackendPinContext(t *testing.T) {
	store := &countingRouteState{
		backendPin: state.UserBackendPinRecord{
			Present:           true,
			BackendIdentifier: routeLookupBackendA,
			Protocol:          routeLookupProtocol,
			BackendPool:       routeLookupDefaultPool,
			ShardTag:          routeLookupShardA,
			BackendNode:       "mailstore-a-node-1",
			Generation:        "pin-1",
		},
	}
	recorder := &recordingRuntimeObservation{}
	service := newRouteLookupTestService(t, store, false, recorder)

	response, err := service.Lookup(context.Background(), RouteLookupRequest{
		Protocol:   routeLookupProtocol,
		AccountKey: routeLookupAccount,
		Attributes: map[string][]string{
			routeLookupAttributeShard: {routeLookupShardA},
		},
	})
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}

	if response.SelectedBackend != routeLookupBackendA || response.ReasonClass != routeLookupReasonOperatorPin {
		t.Fatalf("selected backend = %q reason = %q, want pinned backend", response.SelectedBackend, response.ReasonClass)
	}

	if !response.BackendPin.Present || !response.BackendPin.Applied || response.BackendPin.ReasonClass != routeLookupBackendPinApplied {
		t.Fatalf("backend pin = %#v, want applied context", response.BackendPin)
	}
	if response.BackendPin.BackendNode != "mailstore-a-node-1" || response.BackendPin.ScopeCount != 1 {
		t.Fatalf("backend pin = %#v, want backend-node and scope count context", response.BackendPin)
	}

	event := assertRouteLookupObservationLabels(t, recorder, observability.EventUserBackendPin, operationRouteLookup, routeLookupBackendPinApplied, "applied")
	assertRouteLookupMetricLabelsSafe(t, event)

	assertNoRouteLookupMutations(t, store)
}

// TestRouteLookupReportsAppliedBackendPinWithOtherScopes verifies aggregate pin diagnostics stay bounded.
func TestRouteLookupReportsAppliedBackendPinWithOtherScopes(t *testing.T) {
	store := &countingRouteState{
		backendPins: []state.UserBackendPinRecord{
			{
				Present:           true,
				BackendIdentifier: routeLookupBackendA,
				Protocol:          routeLookupProtocol,
				BackendPool:       routeLookupDefaultPool,
				ShardTag:          routeLookupShardA,
				BackendNode:       "mailstore-a-node-1",
				Generation:        "pin-imap",
			},
			{
				Present:           true,
				BackendIdentifier: routeLookupBackendALMTP,
				Protocol:          routeLookupProtocolLMTP,
				BackendPool:       routeLookupPoolLMTP,
				ShardTag:          routeLookupShardA,
				BackendNode:       "mailstore-a-node-1",
				Generation:        "pin-lmtp",
			},
			{
				Present:           true,
				BackendIdentifier: routeLookupBackendASieve,
				Protocol:          routeLookupProtocolSieve,
				BackendPool:       routeLookupPoolSieve,
				ShardTag:          routeLookupShardA,
				BackendNode:       "mailstore-a-node-1",
				Generation:        "pin-sieve",
			},
		},
	}
	recorder := &recordingRuntimeObservation{}
	service := newRouteLookupTestService(t, store, false, recorder)

	response, err := service.Lookup(context.Background(), RouteLookupRequest{
		Protocol:   routeLookupProtocol,
		AccountKey: routeLookupAccount,
		Attributes: map[string][]string{
			routeLookupAttributeShard: {routeLookupShardA},
		},
	})
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}

	if !response.BackendPin.Present || !response.BackendPin.Applied || response.BackendPin.ScopeCount != 3 {
		t.Fatalf("backend pin = %#v, want applied matching pin with aggregate count", response.BackendPin)
	}

	if response.BackendPin.CurrentScopeUnpinned {
		t.Fatalf("backend pin = %#v, want current scope pinned", response.BackendPin)
	}

	wantOther := []RouteLookupBackendPinScope{
		{Protocol: routeLookupProtocolLMTP, BackendPool: routeLookupPoolLMTP},
		{Protocol: routeLookupProtocolSieve, BackendPool: routeLookupPoolSieve},
	}
	if fmt.Sprintf("%#v", response.BackendPin.OtherScopes) != fmt.Sprintf("%#v", wantOther) {
		t.Fatalf("other scopes = %#v, want %#v", response.BackendPin.OtherScopes, wantOther)
	}

	assertNoRouteLookupMutations(t, store)
}

// TestRouteLookupDefersBackendPinDuringActiveAffinity verifies deferred strategies stay diagnostic.
func TestRouteLookupDefersBackendPinDuringActiveAffinity(t *testing.T) {
	store := &countingRouteState{
		affinity: state.AffinityRecord{
			Present:            true,
			Status:             "found",
			ShardTag:           routeLookupShardA,
			BackendNode:        "mailstore-a-node-1",
			BackendIdentifier:  routeLookupBackendA,
			BindingStatus:      state.BindingStatusActive,
			ActiveSessionCount: 1,
			ActiveHolderCount:  1,
		},
		backendPin: state.UserBackendPinRecord{
			Present:           true,
			BackendIdentifier: routeLookupBackendA,
			Protocol:          routeLookupProtocol,
			BackendPool:       routeLookupDefaultPool,
			ShardTag:          routeLookupShardA,
			BackendNode:       "mailstore-a-node-1",
			Strategy:          string(MoveStrategyDrainExisting),
			Generation:        "pin-active",
		},
	}
	recorder := &recordingRuntimeObservation{}
	service := newRouteLookupTestService(t, store, false, recorder)

	response, err := service.Lookup(context.Background(), RouteLookupRequest{
		Protocol:        routeLookupProtocol,
		AccountKey:      routeLookupAccount,
		IncludeAffinity: true,
		Attributes: map[string][]string{
			routeLookupAttributeShard: {routeLookupShardA},
		},
	})
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}

	if response.BackendPin.Applied || response.BackendPin.ReasonClass != routeLookupIdentityActiveAffinity {
		t.Fatalf("backend pin = %#v, want active-affinity diagnostic deferral", response.BackendPin)
	}

	if response.ReasonClass == routeLookupReasonOperatorPin {
		t.Fatalf("route reason = %q, want normal active-affinity selection", response.ReasonClass)
	}

	assertNoRouteLookupMutations(t, store)
}

// TestRouteLookupReportsBackendPinScopeMismatch verifies non-matching pins stay diagnostic.
func TestRouteLookupReportsBackendPinScopeMismatch(t *testing.T) {
	store := &countingRouteState{
		backendPin: state.UserBackendPinRecord{
			Present:           true,
			BackendIdentifier: routeLookupBackendALMTP,
			Protocol:          routeLookupProtocolLMTP,
			BackendPool:       routeLookupPoolLMTP,
			ShardTag:          routeLookupShardA,
			BackendNode:       "mailstore-a-node-1",
			Generation:        "pin-2",
		},
	}
	recorder := &recordingRuntimeObservation{}
	service := newRouteLookupTestService(t, store, false, recorder)

	response, err := service.Lookup(context.Background(), RouteLookupRequest{
		Protocol:   routeLookupProtocol,
		AccountKey: routeLookupAccount,
		Attributes: map[string][]string{
			routeLookupAttributeShard: {routeLookupShardA},
		},
	})
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}

	if response.BackendPin.Present || response.BackendPin.Applied || !response.BackendPin.CurrentScopeUnpinned || response.BackendPin.ReasonClass != routeLookupBackendPinOtherScopes {
		t.Fatalf("backend pin = %#v, want other-scope context", response.BackendPin)
	}
	if response.BackendPin.ScopeCount != 1 || len(response.BackendPin.OtherScopes) != 1 || response.BackendPin.OtherScopes[0].Protocol != routeLookupProtocolLMTP {
		t.Fatalf("backend pin = %#v, want bounded LMTP other-scope diagnostics", response.BackendPin)
	}
	if response.SelectedBackend != routeLookupBackendA {
		t.Fatalf("selected backend = %q, want normal IMAP placement", response.SelectedBackend)
	}

	event := assertRouteLookupObservationLabels(t, recorder, observability.EventUserBackendPin, operationRouteLookup, routeLookupBackendPinOtherScopes, "diagnostic")
	assertRouteLookupMetricLabelsSafe(t, event)

	assertNoRouteLookupMutations(t, store)
}

// TestRouteLookupReportsBackendPinShardMismatch verifies pins cannot move diagnostics across shards.
func TestRouteLookupReportsBackendPinShardMismatch(t *testing.T) {
	store := &countingRouteState{
		backendPin: state.UserBackendPinRecord{
			Present:           true,
			BackendIdentifier: routeLookupBackendB,
			Protocol:          routeLookupProtocol,
			BackendPool:       routeLookupDefaultPool,
			ShardTag:          routeLookupShardB,
			BackendNode:       "mailstore-b-node-1",
			Generation:        "pin-shard-mismatch",
		},
	}
	recorder := &recordingRuntimeObservation{}
	service := newRouteLookupTestService(t, store, false, recorder)

	response, err := service.Lookup(context.Background(), RouteLookupRequest{
		Protocol:   routeLookupProtocol,
		AccountKey: routeLookupAccount,
		Attributes: map[string][]string{
			routeLookupAttributeShard: {routeLookupShardA},
		},
	})
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}

	if response.Routing.EffectiveShard != routeLookupShardA {
		t.Fatalf("effective shard = %q, want routed shard %q", response.Routing.EffectiveShard, routeLookupShardA)
	}

	if !response.BackendPin.Present || response.BackendPin.Applied || response.BackendPin.ReasonClass != routeLookupBackendPinMismatch {
		t.Fatalf("backend pin = %#v, want cross-shard mismatch context", response.BackendPin)
	}

	assertNoRouteLookupMutations(t, store)
}

// TestRouteLookupReportsBackendPinExclusion verifies unusable pin reasons are bounded.
func TestRouteLookupReportsBackendPinExclusion(t *testing.T) {
	store := &countingRouteState{
		backendPin: state.UserBackendPinRecord{
			Present:           true,
			BackendIdentifier: routeLookupBackendA,
			Protocol:          routeLookupProtocol,
			BackendPool:       routeLookupDefaultPool,
			ShardTag:          routeLookupShardA,
			BackendNode:       "mailstore-a-node-1",
			Generation:        "pin-3",
		},
		snapshots: map[string]backend.RuntimeSnapshot{
			routeLookupBackendA: {
				RuntimeOverride: backend.RuntimeOverride{
					InService: new(false),
				},
			},
		},
	}
	recorder := &recordingRuntimeObservation{}
	service := newRouteLookupTestService(t, store, false, recorder)

	response, err := service.Lookup(context.Background(), RouteLookupRequest{
		Protocol:   routeLookupProtocol,
		AccountKey: routeLookupAccount,
		Attributes: map[string][]string{
			routeLookupAttributeShard: {routeLookupShardA},
		},
	})
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}

	if !response.FailClosed || response.BackendPin.Applied || response.BackendPin.ReasonClass != string(backend.EffectiveExclusionRuntimeOut) {
		t.Fatalf("response = %#v, want fail-closed runtime_out pin exclusion", response)
	}

	event := assertRouteLookupObservationLabels(t, recorder, observability.EventUserBackendPin, operationRouteLookup, string(backend.EffectiveExclusionRuntimeOut), runtimeObservationResultFailClosed)
	assertRouteLookupMetricLabelsSafe(t, event)

	assertNoRouteLookupMutations(t, store)
}

// TestRouteLookupReportsBackendPinMismatchAgainstRetainedBinding verifies pins cannot move retained nodes silently.
func TestRouteLookupReportsBackendPinMismatchAgainstRetainedBinding(t *testing.T) {
	store := &countingRouteState{
		affinity: state.AffinityRecord{
			Present:       true,
			Status:        "retained",
			ShardTag:      routeLookupShardA,
			BackendNode:   "mailstore-a-node-1",
			BindingStatus: state.BindingStatusRetained,
			ServerTime:    time.Now().UTC(),
		},
		backendPin: state.UserBackendPinRecord{
			Present:           true,
			BackendIdentifier: routeLookupBackendB,
			Protocol:          routeLookupProtocol,
			BackendPool:       routeLookupDefaultPool,
			ShardTag:          routeLookupShardA,
			BackendNode:       "mailstore-b-node-1",
			Strategy:          string(MoveStrategyKickExisting),
			Generation:        "pin-retained",
		},
	}
	service := newRouteLookupTestService(t, store, false)

	response, err := service.Lookup(context.Background(), RouteLookupRequest{
		Protocol:        routeLookupProtocol,
		AccountKey:      routeLookupAccount,
		IncludeAffinity: true,
	})
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}

	if !response.FailClosed || response.BackendPin.ReasonClass != routeLookupReasonBindingMismatch {
		t.Fatalf("response = %#v, want backend pin backend-node mismatch", response)
	}

	assertNoRouteLookupMutations(t, store)
}

// TestRouteLookupRecordsBackendPinReadFailure verifies failed pin reads are observable.
func TestRouteLookupRecordsBackendPinReadFailure(t *testing.T) {
	store := &countingRouteState{
		backendPinErr: newRuntimeError(ErrorKindUnavailable, operationUserBackendPinGet, "pin read unavailable"),
	}
	recorder := &recordingRuntimeObservation{}
	service := newRouteLookupTestService(t, store, false, recorder)

	_, err := service.Lookup(context.Background(), RouteLookupRequest{
		Protocol:   routeLookupProtocol,
		AccountKey: routeLookupAccount,
		Attributes: map[string][]string{
			routeLookupAttributeShard: {routeLookupShardA},
		},
	})
	if err == nil {
		t.Fatal("Lookup returned nil error, want backend-pin read failure")
	}

	assertRouteLookupObservationLabels(t, recorder, observability.EventUserBackendPin, operationUserBackendPinGet, routeLookupBackendPinReadFailed, runtimeObservationResultFailure)

	assertNoRouteLookupMutations(t, store)
}

// TestRouteLookupReportsAbsentUserHoldContext verifies absent holds are explicit.
func TestRouteLookupReportsAbsentUserHoldContext(t *testing.T) {
	store := &countingRouteState{}
	service := newRouteLookupTestService(t, store, false)

	response := lookupDefaultRoute(t, service)

	if response.UserHold.Present || response.UserHold.PlacementDeferred || response.UserHold.ReasonClass != routeLookupUserHoldAbsent {
		t.Fatalf("user hold = %#v, want absent non-blocking context", response.UserHold)
	}

	if store.userHoldCheckCalls != 1 {
		t.Fatalf("hold checks = %d, want 1", store.userHoldCheckCalls)
	}

	assertNoRouteLookupMutations(t, store)
}

// TestRouteLookupReportsActiveUserHoldContext verifies holds defer placement diagnostically.
func TestRouteLookupReportsActiveUserHoldContext(t *testing.T) {
	now := time.Unix(1_780_000_000, 0).UTC()
	store := &countingRouteState{
		userHold: state.UserHoldRecord{
			Present:           true,
			Generation:        routeLookupHoldGeneration,
			CreatedAt:         now.Add(-time.Minute),
			ExpiresAt:         now.Add(5 * time.Minute),
			RequestedDuration: 10 * time.Minute,
			ServerTime:        now,
		},
	}
	recorder := &recordingRuntimeObservation{}
	service := newRouteLookupTestService(t, store, false, recorder)

	response := lookupDefaultRoute(t, service)
	assertActiveUserHoldContext(t, response)

	event := assertRouteLookupObservationLabels(t, recorder, observability.EventUserHold, operationRouteLookup, routeLookupUserHoldActive, "affected")

	rendered := fmt.Sprintf("%#v", event)
	if strings.Contains(rendered, routeLookupAccount) {
		t.Fatalf("user-hold observation leaked raw account: %s", rendered)
	}

	assertNoRouteLookupMutations(t, store)
}

// TestRouteLookupReportsPOP3ActiveUserHoldWithoutWaiting verifies POP3 hold context is read-only.
func TestRouteLookupReportsPOP3ActiveUserHoldWithoutWaiting(t *testing.T) {
	now := time.Unix(1_780_000_000, 0).UTC()
	store := &countingRouteState{
		userHold: state.UserHoldRecord{
			Present:           true,
			Generation:        routeLookupHoldGeneration,
			CreatedAt:         now.Add(-time.Minute),
			ExpiresAt:         now.Add(5 * time.Minute),
			RequestedDuration: 10 * time.Minute,
			ServerTime:        now,
		},
	}
	service := newRouteLookupTestService(t, store, false)

	response, err := service.Lookup(context.Background(), RouteLookupRequest{
		Protocol:     routeLookupProtocolPOP3,
		ListenerName: routeLookupProtocolPOP3,
		AccountKey:   routeLookupAccount,
		Attributes: map[string][]string{
			routeLookupAttributeShard: {routeLookupShardA},
		},
	})
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}

	if response.SelectedBackend != routeLookupBackendAPOP3 {
		t.Fatalf("selected backend = %q, want %s", response.SelectedBackend, routeLookupBackendAPOP3)
	}

	assertActiveUserHoldContext(t, response)
	assertNoRouteLookupMutations(t, store)
}

// TestRouteLookupTreatsExpiredUserHoldAsNonBlocking verifies stale records do not defer.
func TestRouteLookupTreatsExpiredUserHoldAsNonBlocking(t *testing.T) {
	now := time.Unix(1_780_000_000, 0).UTC()
	store := &countingRouteState{
		userHold: state.UserHoldRecord{
			Present:    true,
			Generation: "hold-expired",
			ExpiresAt:  now.Add(-time.Second),
			ServerTime: now,
		},
	}
	service := newRouteLookupTestService(t, store, false)

	response := lookupDefaultRoute(t, service)

	if response.UserHold.Present ||
		response.UserHold.PlacementDeferred ||
		response.UserHold.ReasonClass != routeLookupUserHoldExpired ||
		response.Effects.UserHold {
		t.Fatalf("user hold = %#v effects=%#v, want expired non-blocking context", response.UserHold, response.Effects)
	}

	assertNoRouteLookupMutations(t, store)
}

// TestRouteLookupRecordsUserHoldReadFailure verifies hold read errors are bounded.
func TestRouteLookupRecordsUserHoldReadFailure(t *testing.T) {
	store := &countingRouteState{
		userHoldErr: newRuntimeError(ErrorKindUnavailable, operationUserHoldCheck, "hold read unavailable"),
	}
	recorder := &recordingRuntimeObservation{}
	service := newRouteLookupTestService(t, store, false, recorder)

	_ = lookupDefaultRouteError(t, service)
	assertRouteLookupObservationLabels(t, recorder, observability.EventUserHold, operationUserHoldCheck, routeLookupUserHoldReadFailed, runtimeObservationResultFailure)

	assertNoRouteLookupMutations(t, store)
}

// TestRouteLookupObservationIncludesDuration verifies diagnostic lookup latency is measured.
func TestRouteLookupObservationIncludesDuration(t *testing.T) {
	store := &countingRouteState{}
	recorder := &recordingRuntimeObservation{}
	service := newRouteLookupTestService(t, store, false, recorder)

	_, err := service.Lookup(context.Background(), RouteLookupRequest{
		Protocol:   routeLookupProtocol,
		AccountKey: routeLookupAccount,
		Attributes: map[string][]string{
			routeLookupAttributeShard: {routeLookupShardA},
		},
	})
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}

	event, ok := recorder.last(observability.EventRouteLookup)
	if !ok {
		t.Fatalf("route lookup observation missing: %#v", recorder.events)
	}

	if got := event.MetricLabels["operation"]; got != operationRouteLookup {
		t.Fatalf("operation = %q, want %q", got, operationRouteLookup)
	}

	if got := event.Measurements[observability.MetricMeasurementDurationSeconds]; got <= 0 {
		t.Fatalf("duration = %f, want positive", got)
	}
}

// TestRouteLookupResolvesLMTPRecipientWithoutMutations verifies hybrid recipient diagnostics.
func TestRouteLookupResolvesLMTPRecipientWithoutMutations(t *testing.T) {
	store := &countingRouteState{}
	identity := &recordingRouteIdentityLookup{
		result: RouteLookupIdentityLookupResult{
			Authenticated: true,
			Account:       "Canonical@EXAMPLE.TEST",
			Attributes: map[string][]string{
				routeLookupAttributeShard: {routeLookupShardA},
				routeLookupTenantAttr:     {routeLookupTenantBlue},
			},
		},
	}
	service := newLMTPRouteLookupTestService(t, store, identity)

	response, err := service.Lookup(context.Background(), RouteLookupRequest{
		Protocol:        routeLookupProtocolLMTP,
		ListenerName:    routeLookupProtocolLMTP,
		Recipient:       "<Alias@EXAMPLE.TEST>",
		IncludeAffinity: true,
	})
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}

	lookup := identity.singleRequest(t)
	if lookup.Username != "Alias@example.test" || lookup.Protocol != routeLookupProtocolLMTP || lookup.Method != routeLookupIdentityMethod {
		t.Fatalf("lookup context = %#v, want LMTP no-auth recipient lookup", lookup)
	}

	if response.Identity.Source != routeLookupIdentityNauthilus || !response.Identity.Authoritative || !response.Identity.NauthilusUsed || !response.Identity.AccountResolved {
		t.Fatalf("identity state = %#v, want authoritative Nauthilus lookup", response.Identity)
	}

	if response.Routing.AccountKey != routeLookupCanonicalLMTP || response.Routing.Tenant != routeLookupTenantBlue {
		t.Fatalf("routing = %#v, want resolved account and tenant", response.Routing)
	}

	if response.SelectedBackend != routeLookupBackendALMTP {
		t.Fatalf("selected backend = %q, want %s", response.SelectedBackend, routeLookupBackendALMTP)
	}

	assertNoRouteLookupMutations(t, store)
}

// TestRouteLookupUsesActiveAffinityBeforeNauthilus verifies hybrid recipient lookup ordering.
func TestRouteLookupUsesActiveAffinityBeforeNauthilus(t *testing.T) {
	store := &countingRouteState{
		affinity: state.AffinityRecord{
			Present:            true,
			Status:             "found",
			ShardTag:           routeLookupShardA,
			Generation:         "affinity-lmtp-1",
			ActiveSessionCount: 1,
		},
	}
	identity := &recordingRouteIdentityLookup{
		result: RouteLookupIdentityLookupResult{
			Authenticated: true,
			Account:       "should-not-be-used@example.test",
		},
	}
	service := newLMTPRouteLookupTestService(t, store, identity)

	response, err := service.Lookup(context.Background(), RouteLookupRequest{
		Protocol:     routeLookupProtocolLMTP,
		ListenerName: routeLookupProtocolLMTP,
		Recipient:    "<Canonical@EXAMPLE.TEST>",
	})
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}

	if len(identity.requests) != 0 {
		t.Fatalf("identity lookup calls = %d, want 0", len(identity.requests))
	}

	if response.Identity.Source != routeLookupIdentityActiveAffinity || response.Identity.Authoritative || response.Identity.NauthilusUsed || !response.Identity.AccountResolved {
		t.Fatalf("identity state = %#v, want active-affinity resolution without Nauthilus", response.Identity)
	}

	if response.Routing.AccountKey != routeLookupCanonicalLMTP {
		t.Fatalf("routing account = %q, want normalized recipient account", response.Routing.AccountKey)
	}

	if !response.Affinity.Requested || !response.Affinity.Active || response.Affinity.ShardTag != routeLookupShardA {
		t.Fatalf("affinity = %#v, want active delivery affinity", response.Affinity)
	}

	assertNoRouteLookupMutations(t, store)
}

// routeLookupExclusionCases returns runtime states that should explain exclusions.
func routeLookupExclusionCases(now time.Time) []routeLookupExclusionCase {
	return []routeLookupExclusionCase{
		{
			name: "health",
			snapshot: backend.RuntimeSnapshot{
				Health: backend.HealthState{
					Enabled:   true,
					Status:    backend.HealthStatusUnhealthy,
					ExpiresAt: now.Add(time.Hour),
				},
			},
			health:     true,
			wantEffect: func(e RouteLookupEffects) bool { return e.Health },
			wantReason: backend.EffectiveExclusionHealth,
		},
		{
			name: "maintenance",
			snapshot: backend.RuntimeSnapshot{
				RuntimeOverride: backend.RuntimeOverride{
					Maintenance: &backend.MaintenanceState{Mode: backend.MaintenanceModeSoft},
					Generation:  "runtime-1",
				},
			},
			wantEffect: func(e RouteLookupEffects) bool { return e.Maintenance && e.RuntimeOverride },
			wantReason: backend.EffectiveExclusionRuntimeSoftMaintenance,
		},
		{
			name: "runtime out",
			snapshot: backend.RuntimeSnapshot{
				RuntimeOverride: backend.RuntimeOverride{
					InService:  new(false),
					Generation: "runtime-2",
				},
			},
			wantEffect: func(e RouteLookupEffects) bool { return e.RuntimeOverride },
			wantReason: backend.EffectiveExclusionRuntimeOut,
		},
		{
			name: "max connections",
			snapshot: backend.RuntimeSnapshot{
				ActiveSessions: 1000,
			},
			wantEffect: func(e RouteLookupEffects) bool { return e.MaxConnections },
			wantReason: backend.EffectiveExclusionMaxConnections,
		},
	}
}

// newRouteLookupTestService builds the production route lookup service over fakes.
func newRouteLookupTestService(t *testing.T, store *countingRouteState, enforceHealth bool, recorders ...observability.Recorder) *RouteLookupService {
	t.Helper()

	cfg := config.DefaultConfig()
	proxyBackend := cfg.Director.Backends[routeLookupBackendA]
	proxyBackend.HAProxy.Enabled = true
	cfg.Director.Backends[routeLookupBackendA] = proxyBackend
	cfg = cfg.Normalize()

	registry, err := backend.NewStaticRegistry(cfg.Director)
	if err != nil {
		t.Fatalf("NewStaticRegistry returned error: %v", err)
	}

	effective := backend.NewEffectiveBackendPolicy(cfg.Director)
	effective.EnforceHealth = enforceHealth
	policy := backend.SelectionPolicy{
		SoftAllowsActivePins:     cfg.Director.Maintenance.SoftAllowsActivePins,
		DefaultShard:             cfg.Director.Routing.EffectiveDefaultShard(),
		EffectiveBackend:         effective,
		AllowHardDownFailover:    cfg.Director.Affinity.ActiveUserPinning.Failover.AllowOnHardDown,
		AllowHardMaintenanceMove: cfg.Director.Affinity.ActiveUserPinning.Failover.AllowOnHardMaintenance,
	}

	selector, err := backend.NewRuntimeSelector(registry, store, policy)
	if err != nil {
		t.Fatalf("NewRuntimeSelector returned error: %v", err)
	}

	reader, err := NewBackendReadService(BackendReadServiceOptions{
		Registry:  registry,
		Snapshots: store,
		Policy:    effective,
	})
	if err != nil {
		t.Fatalf("NewBackendReadService returned error: %v", err)
	}

	options := RouteLookupServiceOptions{
		Resolver:       mustRouteLookupTestResolver(t),
		Selector:       selector,
		BackendRead:    reader,
		AffinityRead:   store,
		BackendPinRead: store,
		UserHoldRead:   store,
		ListenerContexts: []RouteLookupListenerContext{
			{
				Name:        routeLookupListener,
				Protocol:    routeLookupProtocol,
				ServiceName: routeLookupListener,
				BackendPool: routeLookupDefaultPool,
			},
			{
				Name:        routeLookupProtocolSieve,
				Protocol:    routeLookupProtocolSieve,
				ServiceName: routeLookupProtocolSieve,
				BackendPool: routeLookupPoolSieve,
			},
			{
				Name:        routeLookupProtocolPOP3,
				Protocol:    routeLookupProtocolPOP3,
				ServiceName: routeLookupProtocolPOP3,
				BackendPool: routeLookupPoolPOP3,
			},
		},
		DefaultPool:   routeLookupDefaultPool,
		DefaultShard:  cfg.Director.Routing.EffectiveDefaultShard(),
		DefaultTenant: "default",
	}
	if len(recorders) > 0 {
		options.Observability = recorders[0]
	}

	service, err := NewRouteLookupService(options)
	if err != nil {
		t.Fatalf("NewRouteLookupService returned error: %v", err)
	}

	return service
}

// newLMTPRouteLookupTestService builds a service with LMTP recipient lookup enabled.
func newLMTPRouteLookupTestService(t *testing.T, store *countingRouteState, identity RouteLookupIdentityLookuper) *RouteLookupService {
	t.Helper()

	cfg := config.DefaultConfig().Normalize()

	registry, err := backend.NewStaticRegistry(cfg.Director)
	if err != nil {
		t.Fatalf("NewStaticRegistry returned error: %v", err)
	}

	effective := backend.NewEffectiveBackendPolicy(cfg.Director)
	effective.EnforceHealth = false

	selector, err := backend.NewRuntimeSelector(registry, store, backend.SelectionPolicy{
		SoftAllowsActivePins:     cfg.Director.Maintenance.SoftAllowsActivePins,
		DefaultShard:             cfg.Director.Routing.EffectiveDefaultShard(),
		EffectiveBackend:         effective,
		AllowHardDownFailover:    cfg.Director.Affinity.ActiveUserPinning.Failover.AllowOnHardDown,
		AllowHardMaintenanceMove: cfg.Director.Affinity.ActiveUserPinning.Failover.AllowOnHardMaintenance,
	})
	if err != nil {
		t.Fatalf("NewRuntimeSelector returned error: %v", err)
	}

	reader, err := NewBackendReadService(BackendReadServiceOptions{
		Registry:  registry,
		Snapshots: store,
		Policy:    effective,
	})
	if err != nil {
		t.Fatalf("NewBackendReadService returned error: %v", err)
	}

	service, err := NewRouteLookupService(RouteLookupServiceOptions{
		Resolver:       mustRouteLookupTestResolver(t),
		Selector:       selector,
		BackendRead:    reader,
		AffinityRead:   store,
		BackendPinRead: store,
		UserHoldRead:   store,
		ListenerContexts: []RouteLookupListenerContext{
			{
				Name:        routeLookupProtocolLMTP,
				Protocol:    routeLookupProtocolLMTP,
				ServiceName: routeLookupProtocolLMTP,
				BackendPool: routeLookupPoolLMTP,
			},
		},
		DefaultPool:    routeLookupPoolLMTP,
		DefaultShard:   cfg.Director.Routing.EffectiveDefaultShard(),
		DefaultTenant:  "default",
		IdentityLookup: identity,
	})
	if err != nil {
		t.Fatalf("NewRouteLookupService returned error: %v", err)
	}

	return service
}

// mustRouteLookupTestResolver creates the same auth-attribute/hash chain used by lookup.
func mustRouteLookupTestResolver(t *testing.T) routing.RoutingResolver {
	t.Helper()

	authResolver, err := routing.NewAuthAttributeResolver(routing.AuthAttributeResolverConfig{
		AccountKeyAttribute: "account",
		TenantAttribute:     "tenant",
		ShardTagAttribute:   routeLookupAttributeShard,
		Sticky:              true,
	})
	if err != nil {
		t.Fatalf("NewAuthAttributeResolver returned error: %v", err)
	}

	hashResolver, err := routing.NewHashResolver(routing.HashResolverConfig{
		ShardTags: []string{routeLookupShardA, routeLookupShardB},
		Sticky:    true,
	})
	if err != nil {
		t.Fatalf("NewHashResolver returned error: %v", err)
	}

	resolver, err := routing.NewChainResolver(authResolver, hashResolver)
	if err != nil {
		t.Fatalf("NewChainResolver returned error: %v", err)
	}

	return resolver
}

// routeLookupHasExclusion reports whether a response contains an exclusion reason.
func routeLookupHasExclusion(backends []RouteLookupBackendState, reason backend.EffectiveExclusionReason) bool {
	for _, candidate := range backends {
		for _, exclusion := range candidate.Exclusions {
			if exclusion.Reason == reason {
				return true
			}
		}
	}

	return false
}

// routeLookupBackendHasOutboundProxy reports whether one candidate would use outbound PROXY.
func routeLookupBackendHasOutboundProxy(backends []RouteLookupBackendState, identifier string) bool {
	for _, candidate := range backends {
		if candidate.Identifier == identifier && candidate.OutboundProxyProtocol {
			return true
		}
	}

	return false
}

// assertNoRouteLookupMutations verifies all Redis mutation-like fake paths stayed unused.
func assertNoRouteLookupMutations(t *testing.T, store *countingRouteState) {
	t.Helper()

	if store.openSessionCalls != 0 ||
		store.attachBackendCalls != 0 ||
		store.heartbeatCalls != 0 ||
		store.closeSessionCalls != 0 ||
		store.reapCalls != 0 ||
		store.moveUserCalls != 0 ||
		store.kickUserCalls != 0 ||
		store.clearUserCalls != 0 ||
		store.killSessionCalls != 0 ||
		store.reserveBackendCalls != 0 ||
		store.releaseBackendCalls != 0 ||
		store.reapBackendCalls != 0 ||
		store.setBackendCalls != 0 ||
		store.clearBackendCalls != 0 ||
		store.backendPinSetCalls != 0 ||
		store.backendPinsSetCalls != 0 ||
		store.backendPinClearCalls != 0 ||
		store.backendPinsClearCalls != 0 ||
		store.userHoldSetCalls != 0 ||
		store.userHoldClearCalls != 0 ||
		store.waitForPlacementCalls != 0 {
		t.Fatalf("route lookup used mutating state path: %#v", store)
	}
}

// countingRouteState records route lookup reads and forbidden mutation attempts.
type countingRouteState struct {
	snapshots     map[string]backend.RuntimeSnapshot
	affinity      state.AffinityRecord
	backendPin    state.UserBackendPinRecord
	backendPins   []state.UserBackendPinRecord
	backendPinErr error
	userHold      state.UserHoldRecord
	userHoldErr   error

	backendSnapshotCalls  int
	lookupAffinityCalls   int
	backendPinGetCalls    int
	backendPinSetCalls    int
	backendPinsSetCalls   int
	backendPinClearCalls  int
	backendPinsClearCalls int
	userHoldCheckCalls    int
	userHoldSetCalls      int
	userHoldClearCalls    int
	waitForPlacementCalls int
	openSessionCalls      int
	attachBackendCalls    int
	heartbeatCalls        int
	closeSessionCalls     int
	reapCalls             int
	moveUserCalls         int
	kickUserCalls         int
	clearUserCalls        int
	killSessionCalls      int
	reserveBackendCalls   int
	releaseBackendCalls   int
	reapBackendCalls      int
	setBackendCalls       int
	clearBackendCalls     int
}

type recordingRouteIdentityLookup struct {
	requests []RouteLookupIdentityLookupRequest
	result   RouteLookupIdentityLookupResult
	err      error
}

// LookupRouteIdentity records route-lookup recipient resolution input.
func (r *recordingRouteIdentityLookup) LookupRouteIdentity(_ context.Context, request RouteLookupIdentityLookupRequest) (RouteLookupIdentityLookupResult, error) {
	r.requests = append(r.requests, request)
	if r.err != nil {
		return RouteLookupIdentityLookupResult{}, r.err
	}

	return r.result, nil
}

// singleRequest returns the only recorded identity lookup request.
func (r *recordingRouteIdentityLookup) singleRequest(t *testing.T) RouteLookupIdentityLookupRequest {
	t.Helper()

	if len(r.requests) != 1 {
		t.Fatalf("identity lookup requests = %d, want 1", len(r.requests))
	}

	return r.requests[0]
}

type recordingRuntimeObservation struct {
	mu     sync.Mutex
	events []observability.Event
}

// Record stores a runtime observation for assertions.
func (r *recordingRuntimeObservation) Record(_ context.Context, event observability.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.events = append(r.events, event)
}

// last returns the latest runtime event with the supplied name.
func (r *recordingRuntimeObservation) last(name string) (observability.Event, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for index := len(r.events) - 1; index >= 0; index-- {
		if r.events[index].Name == name {
			return r.events[index], true
		}
	}

	return observability.Event{}, false
}

// eventsByName returns recorded events with the supplied name.
func (r *recordingRuntimeObservation) eventsByName(name string) []observability.Event {
	r.mu.Lock()
	defer r.mu.Unlock()

	events := make([]observability.Event, 0)
	for _, event := range r.events {
		if event.Name == name {
			events = append(events, event)
		}
	}

	return events
}

// BackendSnapshot records a read-only backend runtime state lookup.
func (s *countingRouteState) BackendSnapshot(_ context.Context, backendIdentifier string) (backend.RuntimeSnapshot, error) {
	s.backendSnapshotCalls++
	if s.snapshots == nil {
		return backend.RuntimeSnapshot{}, nil
	}

	return s.snapshots[backendIdentifier], nil
}

// LookupAffinity records a read-only affinity lookup.
func (s *countingRouteState) LookupAffinity(_ context.Context, _ state.AffinityKey) (state.AffinityRecord, error) {
	s.lookupAffinityCalls++

	return s.affinity, nil
}

// ListUserBackendPins records a read-only backend-pin set lookup.
func (s *countingRouteState) ListUserBackendPins(_ context.Context, request state.UserBackendPinsListRequest) (state.UserBackendPinsRecord, error) {
	s.backendPinGetCalls++
	if s.backendPinErr != nil {
		return state.UserBackendPinsRecord{}, s.backendPinErr
	}

	pins := append([]state.UserBackendPinRecord(nil), s.backendPins...)
	if len(pins) == 0 && s.backendPin != (state.UserBackendPinRecord{}) {
		pins = append(pins, s.backendPin)
	}

	for index := range pins {
		if pins[index].Key == (state.AffinityKey{}) {
			pins[index].Key = request.Key
		}
	}

	return state.UserBackendPinsRecord{
		Present: len(pins) > 0,
		Key:     request.Key,
		Pins:    pins,
	}, nil
}

// SetUserBackendPin records an unexpected single-scope backend-pin mutation path.
func (s *countingRouteState) SetUserBackendPin(context.Context, state.UserBackendPinSetRequest) (state.UserBackendPinRecord, error) {
	s.backendPinSetCalls++

	return state.UserBackendPinRecord{}, nil
}

// SetUserBackendPins records an unexpected multi-scope backend-pin mutation path.
func (s *countingRouteState) SetUserBackendPins(context.Context, state.UserBackendPinsSetRequest) (state.UserBackendPinsRecord, error) {
	s.backendPinsSetCalls++

	return state.UserBackendPinsRecord{}, nil
}

// ClearUserBackendPin records an unexpected single-scope backend-pin clear path.
func (s *countingRouteState) ClearUserBackendPin(context.Context, state.UserBackendPinClearRequest) (state.UserBackendPinRecord, error) {
	s.backendPinClearCalls++

	return state.UserBackendPinRecord{}, nil
}

// ClearUserBackendPins records an unexpected aggregate backend-pin clear path.
func (s *countingRouteState) ClearUserBackendPins(context.Context, state.UserBackendPinsClearRequest) (state.UserBackendPinsRecord, error) {
	s.backendPinsClearCalls++

	return state.UserBackendPinsRecord{}, nil
}

// CheckUserHold records a read-only placement-hold lookup.
func (s *countingRouteState) CheckUserHold(_ context.Context, request state.UserHoldCheckRequest) (state.UserHoldRecord, error) {
	s.userHoldCheckCalls++
	if s.userHoldErr != nil {
		return state.UserHoldRecord{}, s.userHoldErr
	}

	hold := s.userHold
	if hold.Key == (state.AffinityKey{}) {
		hold.Key = request.Key
	}

	return hold, nil
}

// SetUserHold records an unexpected placement-hold mutation path.
func (s *countingRouteState) SetUserHold(context.Context, state.UserHoldSetRequest) (state.UserHoldRecord, error) {
	s.userHoldSetCalls++

	return state.UserHoldRecord{}, nil
}

// ClearUserHold records an unexpected placement-hold clear path.
func (s *countingRouteState) ClearUserHold(context.Context, state.UserHoldClearRequest) (state.UserHoldRecord, error) {
	s.userHoldClearCalls++

	return state.UserHoldRecord{}, nil
}

// WaitForPlacement records an unexpected placement waiter path.
func (s *countingRouteState) WaitForPlacement(context.Context, PlacementGateRequest) (PlacementGateResult, error) {
	s.waitForPlacementCalls++

	return PlacementGateResult{}, nil
}

// OpenSession records an unexpected session-open mutation path.
func (s *countingRouteState) OpenSession(context.Context, state.SessionRecord) (state.AffinityRecord, error) {
	s.openSessionCalls++

	return state.AffinityRecord{}, nil
}

// AttachSelectedBackend records an unexpected backend-attachment mutation path.
func (s *countingRouteState) AttachSelectedBackend(context.Context, state.SessionBackendAttachment) (state.SessionBackendRecord, error) {
	s.attachBackendCalls++

	return state.SessionBackendRecord{}, nil
}

// HeartbeatSession records an unexpected session-heartbeat mutation path.
func (s *countingRouteState) HeartbeatSession(context.Context, state.AffinityKey, string, time.Duration) (state.AffinityRecord, error) {
	s.heartbeatCalls++

	return state.AffinityRecord{}, nil
}

// CloseSession records an unexpected session-close mutation path.
func (s *countingRouteState) CloseSession(context.Context, state.AffinityKey, string) (state.AffinityRecord, error) {
	s.closeSessionCalls++

	return state.AffinityRecord{}, nil
}

// ReapSessions records an unexpected expired-session repair mutation path.
func (s *countingRouteState) ReapSessions(context.Context, state.ReapRequest) (state.ReapRecord, error) {
	s.reapCalls++

	return state.ReapRecord{}, nil
}

// MoveUser records an unexpected user move mutation path.
func (s *countingRouteState) MoveUser(context.Context, state.UserMoveRequest) (state.UserRuntimeRecord, error) {
	s.moveUserCalls++

	return state.UserRuntimeRecord{}, nil
}

// KickUser records an unexpected user kick mutation path.
func (s *countingRouteState) KickUser(context.Context, state.UserKickRequest) (state.UserRuntimeRecord, error) {
	s.kickUserCalls++

	return state.UserRuntimeRecord{}, nil
}

// ClearUserAffinity records an unexpected affinity clear mutation path.
func (s *countingRouteState) ClearUserAffinity(context.Context, state.UserClearRequest) (state.UserRuntimeRecord, error) {
	s.clearUserCalls++

	return state.UserRuntimeRecord{}, nil
}

// KillSession records an unexpected session-kill mutation path.
func (s *countingRouteState) KillSession(context.Context, state.SessionKillRequest) (state.SessionKillRecord, error) {
	s.killSessionCalls++

	return state.SessionKillRecord{}, nil
}

// ReserveBackendCapacity records an unexpected backend reservation mutation path.
func (s *countingRouteState) ReserveBackendCapacity(context.Context, state.BackendReservationRequest) (state.BackendReservationRecord, error) {
	s.reserveBackendCalls++

	return state.BackendReservationRecord{}, nil
}

// ReleaseBackendReservation records an unexpected backend reservation release path.
func (s *countingRouteState) ReleaseBackendReservation(context.Context, state.BackendReservationReleaseRequest) (state.BackendReservationRecord, error) {
	s.releaseBackendCalls++

	return state.BackendReservationRecord{}, nil
}

// ReapBackendReservations records an unexpected backend reservation reap path.
func (s *countingRouteState) ReapBackendReservations(context.Context, state.BackendReservationReapRequest) (state.BackendReservationRecord, error) {
	s.reapBackendCalls++

	return state.BackendReservationRecord{}, nil
}

// SetBackendRuntime records an unexpected backend runtime mutation path.
func (s *countingRouteState) SetBackendRuntime(context.Context, state.BackendRuntimeMutation) (state.BackendRuntimeRecord, error) {
	s.setBackendCalls++

	return state.BackendRuntimeRecord{}, nil
}

// ClearBackendRuntime records an unexpected backend runtime clear mutation path.
func (s *countingRouteState) ClearBackendRuntime(context.Context, state.BackendRuntimeClearRequest) (state.BackendRuntimeRecord, error) {
	s.clearBackendCalls++

	return state.BackendRuntimeRecord{}, nil
}
