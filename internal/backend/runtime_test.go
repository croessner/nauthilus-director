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
	"testing"

	"github.com/croessner/nauthilus-director/internal/config"
)

// TestEffectiveBackendStateConfigOnlyDefaults verifies config-only overlay behavior.
func TestEffectiveBackendStateConfigOnlyDefaults(t *testing.T) {
	state := mustEffectiveBackendState(t, EffectiveBackendInput{
		Backend: defaultRuntimeBackend(t),
		Policy:  runtimeEffectivePolicy(true),
	})

	if !state.AllowsNewSessions || !state.AllowsActivePins {
		t.Fatalf("config-only state excluded placement: %#v", state)
	}

	if state.EffectiveWeight != 100 || state.ConfiguredWeight != 100 {
		t.Fatalf("effective weight = %d/%d, want 100/100", state.EffectiveWeight, state.ConfiguredWeight)
	}

	if state.EffectiveShardTag != testShardTag {
		t.Fatalf("effective shard = %q, want %q", state.EffectiveShardTag, testShardTag)
	}

	if state.EffectiveMaintenance != MaintenanceModeDisabled || !state.RuntimeInService {
		t.Fatalf("maintenance/runtime state = %#v", state)
	}
}

// TestStaticSelectorRoutingToUnservedShardFailsClosed verifies unserved shard failure.
func TestStaticSelectorRoutingToUnservedShardFailsClosed(t *testing.T) {
	selector := mustStaticSelector(t, config.DefaultConfig(), SelectionPolicy{
		SoftAllowsActivePins: true,
		DefaultShard:         selectorDefaultShard,
		EffectiveBackend:     runtimeEffectivePolicy(true),
	})

	_, err := selector.Select(context.Background(), SelectionRequest{
		AccountKey:  testAccountKey,
		Tenant:      testTenant,
		ShardTag:    "unserved-shard",
		Protocol:    protocolIMAP,
		BackendPool: testPoolIMAP,
	})
	if !IsErrorKind(err, ErrorKindNoBackend) {
		t.Fatalf("Select error = %v, want no_backend", err)
	}
}

// TestRuntimeWeightOverrideRangeValidation verifies configured weight limits.
func TestRuntimeWeightOverrideRangeValidation(t *testing.T) {
	policy := RuntimeOverridePolicy{
		Enabled:             true,
		AllowWeightOverride: true,
		MinWeight:           10,
		MaxWeight:           20,
	}

	for _, weight := range []int{9, 21} {
		override := RuntimeOverride{Weight: new(weight)}
		if err := override.Validate(policy); !IsErrorKind(err, ErrorKindInvalidRequest) {
			t.Fatalf("Validate weight %d error = %v, want invalid_request", weight, err)
		}
	}

	override := RuntimeOverride{Weight: new(15)}
	if err := override.Validate(policy); err != nil {
		t.Fatalf("Validate accepted-range weight returned error: %v", err)
	}
}

// TestRuntimeClearRemovesOnlyRuntimeOverrides verifies clear preserves config baseline.
func TestRuntimeClearRemovesOnlyRuntimeOverrides(t *testing.T) {
	configured := defaultRuntimeBackend(t)
	runtimeMaintenance := MaintenanceState{Mode: MaintenanceModeHard}
	override := RuntimeOverride{
		InService:   new(false),
		Weight:      new(5),
		Maintenance: &runtimeMaintenance,
		Generation:  "7",
	}
	policy := runtimeEffectivePolicy(true)

	overridden := mustEffectiveBackendState(t, EffectiveBackendInput{
		Backend:         configured,
		RuntimeOverride: override,
		Policy:          policy,
	})
	if overridden.EffectiveWeight != 5 || overridden.RuntimeInService {
		t.Fatalf("override did not apply: %#v", overridden)
	}

	cleared := mustEffectiveBackendState(t, EffectiveBackendInput{
		Backend:         configured,
		RuntimeOverride: override.Clear(),
		Policy:          policy,
	})
	if cleared.EffectiveWeight != configured.Weight || cleared.EffectiveMaintenance != configured.MaintenanceMode {
		t.Fatalf("clear changed config baseline: %#v", cleared)
	}

	if cleared.Backend.TLS != configured.TLS || cleared.Backend.Auth.Mode != configured.Auth.Mode {
		t.Fatalf("clear changed transport or auth config: %#v", cleared.Backend)
	}
}

// TestStaticHardMaintenanceCannotBeWeakenedByRuntimeInService verifies precedence.
func TestStaticHardMaintenanceCannotBeWeakenedByRuntimeInService(t *testing.T) {
	configured := defaultRuntimeBackend(t)
	configured.MaintenanceMode = MaintenanceModeHard

	state := mustEffectiveBackendState(t, EffectiveBackendInput{
		Backend: configured,
		RuntimeOverride: RuntimeOverride{
			InService: new(true),
		},
		Policy: runtimeEffectivePolicy(true),
	})

	if state.AllowsNewSessions || state.AllowsActivePins {
		t.Fatalf("static hard maintenance was weakened: %#v", state)
	}

	if !state.HasExclusion(EffectiveExclusionStaticHardMaintenance) {
		t.Fatalf("state missing static hard exclusion: %#v", state.Exclusions)
	}
}

// TestRuntimeHardMaintenanceExcludesAllNewSessions verifies runtime hard mode.
func TestRuntimeHardMaintenanceExcludesAllNewSessions(t *testing.T) {
	maintenance := MaintenanceState{Mode: MaintenanceModeHard}
	state := mustEffectiveBackendState(t, EffectiveBackendInput{
		Backend: defaultRuntimeBackend(t),
		RuntimeOverride: RuntimeOverride{
			Maintenance: &maintenance,
		},
		Policy: runtimeEffectivePolicy(true),
	})

	if state.AllowsNewSessions || state.AllowsActivePins {
		t.Fatalf("runtime hard maintenance did not exclude placement: %#v", state)
	}
}

// TestRuntimeSoftMaintenancePreservesActivePinsByPolicy verifies soft pin policy.
func TestRuntimeSoftMaintenancePreservesActivePinsByPolicy(t *testing.T) {
	maintenance := MaintenanceState{Mode: MaintenanceModeSoft}

	for _, testCase := range []struct {
		name       string
		allowPins  bool
		wantActive bool
	}{
		{name: "active pins allowed", allowPins: true, wantActive: true},
		{name: "active pins blocked", allowPins: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			state := mustEffectiveBackendState(t, EffectiveBackendInput{
				Backend: defaultRuntimeBackend(t),
				RuntimeOverride: RuntimeOverride{
					Maintenance: &maintenance,
				},
				Policy: runtimeEffectivePolicy(testCase.allowPins),
			})

			if state.AllowsNewSessions {
				t.Fatalf("runtime soft maintenance allowed new sessions: %#v", state)
			}

			if state.AllowsActivePins != testCase.wantActive {
				t.Fatalf("active pins = %v, want %v", state.AllowsActivePins, testCase.wantActive)
			}
		})
	}
}

// runtimeEffectivePolicy creates a runtime-enabled effective-state policy fixture.
func runtimeEffectivePolicy(softPins bool) EffectiveBackendPolicy {
	return EffectiveBackendPolicy{
		RuntimeOverrides: RuntimeOverridePolicy{
			Enabled:             true,
			AllowWeightOverride: true,
			AllowInOut:          true,
			AllowDrain:          true,
			MinWeight:           0,
			MaxWeight:           10000,
		},
		SoftAllowsActivePins: softPins,
	}
}

// defaultRuntimeBackend returns the default IMAP backend fixture.
func defaultRuntimeBackend(t *testing.T) Backend {
	t.Helper()

	registry := mustStaticRegistry(t, config.DefaultConfig())

	entry, err := registry.Lookup(context.Background(), testBackendID)
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}

	return entry
}

// mustEffectiveBackendState creates an effective-state fixture.
func mustEffectiveBackendState(t *testing.T, input EffectiveBackendInput) EffectiveBackendState {
	t.Helper()

	state, err := NewEffectiveBackendState(input)
	if err != nil {
		t.Fatalf("NewEffectiveBackendState returned error: %v", err)
	}

	return state
}
