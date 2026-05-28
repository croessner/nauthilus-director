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

package backend

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/observability"
)

const testBackendIDB = "mailstore-b-imap"

// TestRuntimeSelectorExcludesRuntimeOutAndDrain verifies runtime state blocks new placement.
func TestRuntimeSelectorExcludesRuntimeOutAndDrain(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		snapshot RuntimeSnapshot
	}{
		{
			name: "runtime out",
			snapshot: RuntimeSnapshot{RuntimeOverride: RuntimeOverride{
				InService: new(false),
			}},
		},
		{
			name: "runtime drain",
			snapshot: RuntimeSnapshot{RuntimeOverride: RuntimeOverride{
				Drain: &DrainState{Enabled: true, Mode: DrainModeSoft},
			}},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			selector := mustRuntimeSelector(t, singleBackendConfig(string(MaintenanceModeDisabled), 100), fakeSnapshots{
				testBackendID: testCase.snapshot,
			}, runtimeSelectionPolicy(true))

			_, err := selector.Select(context.Background(), defaultSelectionRequest(testAccountKey))
			if !IsErrorKind(err, ErrorKindNoBackend) {
				t.Fatalf("Select error = %v, want no_backend", err)
			}
		})
	}
}

// TestRuntimeSelectorSupportsLMTPRecipientHash verifies LMTP uses shared runtime selection.
func TestRuntimeSelectorSupportsLMTPRecipientHash(t *testing.T) {
	selector := mustRuntimeSelector(t, config.DefaultConfig(), nil, runtimeSelectionPolicy(true))

	result, err := selector.Select(context.Background(), lmtpSelectionRequest(testAccountKey))
	if err != nil {
		t.Fatalf("Select returned error: %v", err)
	}

	if result.Backend.Identifier != testBackendIDLMTP {
		t.Fatalf("selected backend = %q, want %q", result.Backend.Identifier, testBackendIDLMTP)
	}

	if result.Backend.Protocol != testProtocolLMTP {
		t.Fatalf("selected protocol = %q, want lmtp", result.Backend.Protocol)
	}
}

// TestRuntimeSelectorAppliesRuntimeConstraintsToLMTP verifies recipient_hash keeps shared constraints.
func TestRuntimeSelectorAppliesRuntimeConstraintsToLMTP(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		snapshot RuntimeSnapshot
	}{
		{
			name: "runtime out",
			snapshot: RuntimeSnapshot{RuntimeOverride: RuntimeOverride{
				InService: new(false),
			}},
		},
		{
			name:     "max connections",
			snapshot: RuntimeSnapshot{ActiveSessions: 1000},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			selector := mustRuntimeSelector(t, config.DefaultConfig(), fakeSnapshots{
				testBackendIDLMTP: testCase.snapshot,
			}, runtimeSelectionPolicy(true))

			_, err := selector.Select(context.Background(), lmtpSelectionRequest(testAccountKey))
			if !IsErrorKind(err, ErrorKindNoBackend) {
				t.Fatalf("Select error = %v, want no_backend", err)
			}
		})
	}
}

// TestRuntimeWeightOverrideChangesDeterministicPlacement verifies weight overlays affect hashing.
func TestRuntimeWeightOverrideChangesDeterministicPlacement(t *testing.T) {
	cfg := sameShardBackendsConfig()
	selector := mustRuntimeSelector(t, cfg, fakeSnapshots{
		testBackendIDB: {RuntimeOverride: RuntimeOverride{Weight: new(10000)}},
	}, runtimeSelectionPolicy(true))

	account := accountChangedByRuntimeWeight(t, cfg, testBackendID, testBackendIDB)

	result, err := selector.Select(context.Background(), defaultSelectionRequest(account))
	if err != nil {
		t.Fatalf("Select returned error: %v", err)
	}

	if result.Backend.Identifier != testBackendIDB {
		t.Fatalf("selected backend = %q, want runtime weighted %q", result.Backend.Identifier, testBackendIDB)
	}
}

// TestRuntimeWeightZeroExcludesInitialPlacementButAllowsActivePins verifies weight-zero precedence.
func TestRuntimeWeightZeroExcludesInitialPlacementButAllowsActivePins(t *testing.T) {
	snapshots := fakeSnapshots{
		testBackendID: {RuntimeOverride: RuntimeOverride{Weight: new(0)}},
	}
	selector := mustRuntimeSelector(t, singleBackendConfig(string(MaintenanceModeDisabled), 100), snapshots, runtimeSelectionPolicy(true))

	_, err := selector.Select(context.Background(), defaultSelectionRequest(testAccountKey))
	if !IsErrorKind(err, ErrorKindNoBackend) {
		t.Fatalf("initial Select error = %v, want no_backend", err)
	}

	request := defaultSelectionRequest(testAccountKey)
	request.ActiveAffinity = true
	request.PinnedBackendIdentifier = testBackendID

	result, err := selector.Select(context.Background(), request)
	if err != nil {
		t.Fatalf("active Select returned error: %v", err)
	}

	if result.Backend.Identifier != testBackendID {
		t.Fatalf("active pin selected %q, want %q", result.Backend.Identifier, testBackendID)
	}
}

// TestRuntimeSelectorMaxConnectionsExcludesFullBackend verifies Redis counts feed eligibility.
func TestRuntimeSelectorMaxConnectionsExcludesFullBackend(t *testing.T) {
	backendConfig := singleBackendConfig(string(MaintenanceModeDisabled), 100)
	selector := mustRuntimeSelector(t, backendConfig, fakeSnapshots{
		testBackendID: {ActiveSessions: 1000},
	}, runtimeSelectionPolicy(true))

	_, err := selector.Select(context.Background(), defaultSelectionRequest(testAccountKey))
	if !IsErrorKind(err, ErrorKindNoBackend) {
		t.Fatalf("Select error = %v, want no_backend", err)
	}
}

// TestRuntimeSelectorActiveAffinityOverridesWeightedPlacement verifies active pins are first-class.
func TestRuntimeSelectorActiveAffinityOverridesWeightedPlacement(t *testing.T) {
	cfg := sameShardBackendsConfig()
	selector := mustRuntimeSelector(t, cfg, fakeSnapshots{
		testBackendIDB: {RuntimeOverride: RuntimeOverride{Weight: new(10000)}},
	}, runtimeSelectionPolicy(true))

	account := accountChangedByRuntimeWeight(t, cfg, testBackendID, testBackendIDB)
	request := defaultSelectionRequest(account)
	request.ActiveAffinity = true
	request.PinnedBackendIdentifier = testBackendID

	result, err := selector.Select(context.Background(), request)
	if err != nil {
		t.Fatalf("Select returned error: %v", err)
	}

	if result.Backend.Identifier != testBackendID {
		t.Fatalf("active pin selected %q, want %q", result.Backend.Identifier, testBackendID)
	}
}

// TestRuntimeSelectorHardMaintenanceFailoverRequiresPolicy verifies same-shard active failover.
func TestRuntimeSelectorHardMaintenanceFailoverRequiresPolicy(t *testing.T) {
	cfg := sameShardBackendsConfig()
	snapshots := fakeSnapshots{
		testBackendID: {RuntimeOverride: RuntimeOverride{Maintenance: &MaintenanceState{Mode: MaintenanceModeHard}}},
	}
	request := defaultSelectionRequest(testAccountKey)
	request.ActiveAffinity = true
	request.PinnedBackendIdentifier = testBackendID

	blocked := mustRuntimeSelector(t, cfg, snapshots, runtimeSelectionPolicy(true))

	_, err := blocked.Select(context.Background(), request)
	if !IsErrorKind(err, ErrorKindNoBackend) {
		t.Fatalf("blocked Select error = %v, want no_backend", err)
	}

	allowedPolicy := runtimeSelectionPolicy(true)
	allowedPolicy.AllowHardMaintenanceMove = true
	allowed := mustRuntimeSelector(t, cfg, snapshots, allowedPolicy)

	result, err := allowed.Select(context.Background(), request)
	if err != nil {
		t.Fatalf("allowed Select returned error: %v", err)
	}

	if result.Backend.Identifier == testBackendID {
		t.Fatalf("failover selected pinned backend %q", result.Backend.Identifier)
	}
}

// TestRuntimeSelectorStaleHealthFailsClosedAfterStartupGrace verifies health freshness input.
func TestRuntimeSelectorStaleHealthFailsClosedAfterStartupGrace(t *testing.T) {
	now := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
	selector := mustRuntimeSelector(t, singleBackendConfig(string(MaintenanceModeDisabled), 100), fakeSnapshots{
		testBackendID: {
			Health: HealthState{
				Enabled:   true,
				Status:    HealthStatusHealthy,
				CheckedAt: now.Add(-time.Minute),
				ExpiresAt: now.Add(-time.Second),
			},
		},
	}, SelectionPolicy{
		SoftAllowsActivePins:       true,
		EffectiveBackend:           healthEffectivePolicy(true),
		HealthEnforcementStartedAt: now.Add(-time.Minute),
	})
	selector.WithClock(func() time.Time { return now })

	_, err := selector.Select(context.Background(), defaultSelectionRequest(testAccountKey))
	if !IsErrorKind(err, ErrorKindNoBackend) {
		t.Fatalf("Select error = %v, want no_backend", err)
	}
}

// TestHealthTransitionThresholdsRequireConsecutiveResults verifies health flapping thresholds.
func TestHealthTransitionThresholdsRequireConsecutiveResults(t *testing.T) {
	tracker := NewHealthTransitionTracker(HealthThresholds{UnhealthyAfter: 2, HealthyAfter: 2}, HealthStatusHealthy)
	now := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)

	firstFailure := tracker.Observe(false, "connect", now, time.Second)
	if firstFailure.Status != HealthStatusHealthy {
		t.Fatalf("first failure status = %q, want healthy until threshold", firstFailure.Status)
	}

	secondFailure := tracker.Observe(false, "connect", now.Add(time.Second), time.Second)
	if secondFailure.Status != HealthStatusUnhealthy {
		t.Fatalf("second failure status = %q, want unhealthy", secondFailure.Status)
	}

	firstSuccess := tracker.Observe(true, "", now.Add(2*time.Second), time.Second)
	if firstSuccess.Status != HealthStatusUnhealthy {
		t.Fatalf("first success status = %q, want unhealthy until threshold", firstSuccess.Status)
	}

	secondSuccess := tracker.Observe(true, "", now.Add(3*time.Second), time.Second)
	if secondSuccess.Status != HealthStatusHealthy {
		t.Fatalf("second success status = %q, want healthy", secondSuccess.Status)
	}
}

// TestHealthRunnerOnlyCurrentOwnerPerformsDeepCheck verifies credentialed checks are owner-only.
func TestHealthRunnerOnlyCurrentOwnerPerformsDeepCheck(t *testing.T) {
	cfg := singleBackendConfig(string(MaintenanceModeDisabled), 100)
	registry := mustStaticRegistry(t, cfg)
	checker := &recordingHealthChecker{}
	coordinator := &fakeHealthCoordinator{owned: false}
	recorder := &recordingObservability{}

	runner, err := NewHealthRunner(registry, coordinator, checker, HealthRunnerConfig{
		InstanceID:    "director-a",
		Interval:      time.Second,
		Timeout:       time.Second,
		StateTTL:      time.Second,
		Observability: recorder,
	})
	if err != nil {
		t.Fatalf("NewHealthRunner returned error: %v", err)
	}

	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce without ownership returned error: %v", err)
	}

	if checker.deepChecks != 0 {
		t.Fatalf("deep checks without ownership = %d, want 0", checker.deepChecks)
	}

	coordinator.owned = true

	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce with ownership returned error: %v", err)
	}

	if checker.deepChecks != 1 || coordinator.published != 1 {
		t.Fatalf("deep checks/published = %d/%d, want 1/1", checker.deepChecks, coordinator.published)
	}

	if !recorder.Has(observability.EventBackendHealthTransition) {
		t.Fatal("backend health transition event was not recorded")
	}
}

type fakeSnapshots map[string]RuntimeSnapshot

// BackendSnapshot returns the configured runtime snapshot fixture.
func (s fakeSnapshots) BackendSnapshot(_ context.Context, backendIdentifier string) (RuntimeSnapshot, error) {
	return s[backendIdentifier], nil
}

type recordingObservability struct {
	events []observability.Event
}

// Record captures one normalized event for health-runner tests.
func (r *recordingObservability) Record(_ context.Context, event observability.Event) {
	r.events = append(r.events, event)
}

// Has reports whether an event with the given name was captured.
func (r *recordingObservability) Has(name string) bool {
	for _, event := range r.events {
		if event.Name == name {
			return true
		}
	}

	return false
}

type recordingHealthChecker struct {
	deepChecks int
}

// CheckBackend records deep-check attempts without touching credentials.
func (c *recordingHealthChecker) CheckBackend(_ context.Context, _ Backend, request HealthCheckRequest) HealthCheckResult {
	if request.Deep {
		c.deepChecks++
	}

	return HealthCheckResult{Healthy: true}
}

type fakeHealthCoordinator struct {
	owned     bool
	published int
}

// PublishInstanceHeartbeat records instance liveness for the fake coordinator.
func (c *fakeHealthCoordinator) PublishInstanceHeartbeat(context.Context, string, time.Duration) error {
	return nil
}

// AcquireHealthOwner returns the configured owner state for the fake coordinator.
func (c *fakeHealthCoordinator) AcquireHealthOwner(_ context.Context, request HealthOwnershipRequest) (HealthOwnershipRecord, error) {
	return HealthOwnershipRecord{
		InstanceID:        request.InstanceID,
		OwnerInstanceID:   request.InstanceID,
		BackendIdentifier: request.BackendIdentifier,
		FencingToken:      1,
		Owned:             c.owned,
	}, nil
}

// RenewHealthOwner is unused by the current runner but satisfies the coordinator contract.
func (c *fakeHealthCoordinator) RenewHealthOwner(context.Context, HealthOwnershipRequest) (HealthOwnershipRecord, error) {
	return HealthOwnershipRecord{}, nil
}

// PublishHealthState records that a fenced state publication was attempted.
func (c *fakeHealthCoordinator) PublishHealthState(_ context.Context, request HealthPublishRequest) (HealthState, error) {
	c.published++

	return request.State, nil
}

// mustRuntimeSelector creates a runtime selector fixture.
func mustRuntimeSelector(t *testing.T, cfg config.Config, snapshots RuntimeSnapshotReader, policy SelectionPolicy) *RuntimeSelector {
	t.Helper()

	selector, err := NewRuntimeSelector(mustStaticRegistry(t, cfg), snapshots, policy)
	if err != nil {
		t.Fatalf("NewRuntimeSelector returned error: %v", err)
	}

	return selector
}

// defaultSelectionRequest returns a complete IMAP selection request fixture.
func defaultSelectionRequest(account string) SelectionRequest {
	return SelectionRequest{
		AccountKey:  account,
		Tenant:      testTenant,
		ShardTag:    testShardTag,
		Protocol:    protocolIMAP,
		BackendPool: testPoolIMAP,
	}
}

// lmtpSelectionRequest returns a complete LMTP selection request fixture.
func lmtpSelectionRequest(account string) SelectionRequest {
	return SelectionRequest{
		AccountKey:  account,
		Tenant:      testTenant,
		ShardTag:    testShardTag,
		Protocol:    testProtocolLMTP,
		BackendPool: testPoolLMTP,
	}
}

// sameShardBackendsConfig returns two IMAP backends serving one effective shard.
func sameShardBackendsConfig() config.Config {
	cfg := config.DefaultConfig()
	first := cfg.Director.Backends[testBackendID]
	second := cfg.Director.Backends[testBackendIDB]
	second.ShardTag = first.ShardTag
	cfg.Director.Backends[testBackendID] = first
	cfg.Director.Backends[testBackendIDB] = second

	return cfg
}

// accountChangedByRuntimeWeight finds an account whose weighted placement changes.
func accountChangedByRuntimeWeight(t *testing.T, cfg config.Config, before string, after string) string {
	t.Helper()

	selector := mustRuntimeSelector(t, cfg, nil, runtimeSelectionPolicy(true))
	weighted := mustRuntimeSelector(t, cfg, fakeSnapshots{
		after: {RuntimeOverride: RuntimeOverride{Weight: new(10000)}},
	}, runtimeSelectionPolicy(true))

	for index := range 2048 {
		account := fmt.Sprintf("user-%d@example.test", index)

		result, err := selector.Select(context.Background(), defaultSelectionRequest(account))
		if err != nil {
			t.Fatalf("Select fixture returned error: %v", err)
		}

		changed, err := weighted.Select(context.Background(), defaultSelectionRequest(account))
		if err != nil {
			t.Fatalf("weighted Select fixture returned error: %v", err)
		}

		if result.Backend.Identifier == before && changed.Backend.Identifier == after {
			return account
		}
	}

	t.Fatalf("could not find account moving from %s to %s", before, after)

	return ""
}

// runtimeSelectionPolicy creates a runtime-enabled selection policy fixture.
func runtimeSelectionPolicy(softPins bool) SelectionPolicy {
	return SelectionPolicy{
		SoftAllowsActivePins: softPins,
		EffectiveBackend:     runtimeEffectivePolicy(softPins),
	}
}

// healthEffectivePolicy creates a runtime-enabled policy with health enforcement.
func healthEffectivePolicy(softPins bool) EffectiveBackendPolicy {
	policy := runtimeEffectivePolicy(softPins)
	policy.EnforceHealth = true

	return policy
}
