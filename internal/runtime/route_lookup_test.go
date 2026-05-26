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

package runtime

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/routing"
	"github.com/croessner/nauthilus-director/internal/state"
)

const (
	routeLookupAccount        = "alice@example.test"
	routeLookupAttributeShard = "mailShard"
	routeLookupAttributeToken = "token"
	routeLookupBackendA       = "mailstore-a-imap"
	routeLookupBackendB       = "mailstore-b-imap"
	routeLookupDefaultPool    = "imap-default"
	routeLookupListener       = "imap"
	routeLookupProtocol       = "imap"
	routeLookupSecretValue    = "super-secret-value"
	routeLookupShardA         = "mailstore-a"
	routeLookupShardB         = "mailstore-b"
)

// routeLookupExclusionCase describes one runtime exclusion explanation scenario.
type routeLookupExclusionCase struct {
	name       string
	snapshot   backend.RuntimeSnapshot
	health     bool
	wantEffect func(RouteLookupEffects) bool
	wantReason backend.EffectiveExclusionReason
}

// TestRouteLookupUsesResolverSelectorAndReadOnlyAffinity verifies the shared read-only path.
func TestRouteLookupUsesResolverSelectorAndReadOnlyAffinity(t *testing.T) {
	store := &countingRouteState{
		affinity: state.AffinityRecord{
			Present:            true,
			Status:             "found",
			ShardTag:           routeLookupShardB,
			BackendIdentifier:  routeLookupBackendB,
			Generation:         "affinity-7",
			ActiveSessionCount: 2,
		},
	}
	service := newRouteLookupTestService(t, store, false)

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

	if store.lookupAffinityCalls != 1 {
		t.Fatalf("LookupAffinity calls = %d, want 1", store.lookupAffinityCalls)
	}

	if store.backendSnapshotCalls == 0 {
		t.Fatal("BackendSnapshot was not read")
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

// TestRouteLookupResponseOmitsSecretBearingAttributeValues verifies safe output.
func TestRouteLookupResponseOmitsSecretBearingAttributeValues(t *testing.T) {
	store := &countingRouteState{}
	service := newRouteLookupTestService(t, store, false)

	response, err := service.Lookup(context.Background(), RouteLookupRequest{
		Protocol:   routeLookupProtocol,
		AccountKey: routeLookupAccount,
		Attributes: map[string][]string{
			routeLookupAttributeShard: {routeLookupShardA},
			routeLookupAttributeToken: {routeLookupSecretValue},
		},
	})
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}

	rendered := fmt.Sprintf("%#v", response)
	if strings.Contains(rendered, routeLookupSecretValue) || strings.Contains(rendered, routeLookupAttributeToken) {
		t.Fatalf("route lookup response leaked secret-bearing attributes: %s", rendered)
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
func newRouteLookupTestService(t *testing.T, store *countingRouteState, enforceHealth bool) *RouteLookupService {
	t.Helper()

	cfg := config.DefaultConfig().Normalize()

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

	service, err := NewRouteLookupService(RouteLookupServiceOptions{
		Resolver:     mustRouteLookupTestResolver(t),
		Selector:     selector,
		BackendRead:  reader,
		AffinityRead: store,
		ListenerContexts: []RouteLookupListenerContext{
			{
				Name:        routeLookupListener,
				Protocol:    routeLookupProtocol,
				ServiceName: routeLookupListener,
				BackendPool: routeLookupDefaultPool,
			},
		},
		DefaultPool:   routeLookupDefaultPool,
		DefaultShard:  cfg.Director.Routing.EffectiveDefaultShard(),
		DefaultTenant: "default",
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
		store.setBackendCalls != 0 ||
		store.clearBackendCalls != 0 {
		t.Fatalf("route lookup used mutating state path: %#v", store)
	}
}

// countingRouteState records route lookup reads and forbidden mutation attempts.
type countingRouteState struct {
	snapshots map[string]backend.RuntimeSnapshot
	affinity  state.AffinityRecord

	backendSnapshotCalls int
	lookupAffinityCalls  int
	openSessionCalls     int
	attachBackendCalls   int
	heartbeatCalls       int
	closeSessionCalls    int
	reapCalls            int
	moveUserCalls        int
	kickUserCalls        int
	clearUserCalls       int
	killSessionCalls     int
	setBackendCalls      int
	clearBackendCalls    int
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
