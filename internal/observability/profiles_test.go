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

package observability

import (
	"context"
	"testing"

	"github.com/croessner/nauthilus-director/internal/config"
)

// TestProfileRuntimeDisablesSamplersByDefault verifies profile sampling starts closed.
func TestProfileRuntimeDisablesSamplersByDefault(t *testing.T) {
	recorder := &recordingProfileConfigurator{}
	profiles := newProfileRuntime(config.DefaultConfig().Observability.Profiles, recorder)

	profiles.Apply()

	if profiles.PProfEnabled() || profiles.BlockEnabled() || profiles.MutexEnabled() || profiles.GoroutineEnabled() {
		t.Fatalf("default runtime profiles enabled unexpectedly")
	}

	recorder.expectBlockRates(t, []int{runtimeProfileSamplingOff})
	recorder.expectMutexFractions(t, []int{runtimeProfileSamplingOff})
}

// TestProfileRuntimeAppliesExplicitSamplers verifies block and mutex toggles affect runtime rates.
func TestProfileRuntimeAppliesExplicitSamplers(t *testing.T) {
	cfg := config.DefaultConfig().Observability.Profiles
	cfg.PProf.Enabled = true
	cfg.Block.Enabled = true
	cfg.Mutex.Enabled = true
	cfg.Goroutine.Enabled = true

	recorder := &recordingProfileConfigurator{}
	profiles := newProfileRuntime(cfg, recorder)

	profiles.Apply()

	if !profiles.PProfEnabled() || !profiles.BlockEnabled() || !profiles.MutexEnabled() || !profiles.GoroutineEnabled() {
		t.Fatalf("explicit profile runtime flags were not enabled")
	}

	recorder.expectBlockRates(t, []int{runtimeBlockProfileRate})
	recorder.expectMutexFractions(t, []int{runtimeMutexProfileFraction})
}

// TestProfileRuntimeShutdownDisablesSamplers verifies shutdown removes process sampling overhead.
func TestProfileRuntimeShutdownDisablesSamplers(t *testing.T) {
	cfg := config.DefaultConfig().Observability.Profiles
	cfg.PProf.Enabled = true
	cfg.Block.Enabled = true
	cfg.Mutex.Enabled = true

	recorder := &recordingProfileConfigurator{}
	profiles := newProfileRuntime(cfg, recorder)

	profiles.Apply()

	if err := profiles.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown returned error: %v", err)
	}

	recorder.expectBlockRates(t, []int{runtimeBlockProfileRate, runtimeProfileSamplingOff})
	recorder.expectMutexFractions(t, []int{runtimeMutexProfileFraction, runtimeProfileSamplingOff})
}

// TestNewRuntimeRejectsProfilesWithoutPProf verifies direct runtime construction fails closed.
func TestNewRuntimeRejectsProfilesWithoutPProf(t *testing.T) {
	cfg := config.DefaultConfig().Observability
	cfg.Tracing.Enabled = false
	cfg.Profiles.Block.Enabled = true

	if _, err := NewRuntime(cfg); err == nil {
		t.Fatal("NewRuntime accepted block profiling without pprof")
	}
}

type recordingProfileConfigurator struct {
	blockRates     []int
	mutexFractions []int
}

// SetBlockProfileRate records one requested block-profile sampling rate.
func (r *recordingProfileConfigurator) SetBlockProfileRate(rate int) {
	r.blockRates = append(r.blockRates, rate)
}

// SetMutexProfileFraction records one requested mutex-profile sampling fraction.
func (r *recordingProfileConfigurator) SetMutexProfileFraction(fraction int) int {
	r.mutexFractions = append(r.mutexFractions, fraction)

	return 0
}

// expectBlockRates compares recorded block-profile rate changes.
func (r *recordingProfileConfigurator) expectBlockRates(t *testing.T, want []int) {
	t.Helper()

	if len(r.blockRates) != len(want) {
		t.Fatalf("block rates = %#v, want %#v", r.blockRates, want)
	}

	for index, value := range want {
		if r.blockRates[index] != value {
			t.Fatalf("block rates = %#v, want %#v", r.blockRates, want)
		}
	}
}

// expectMutexFractions compares recorded mutex-profile fraction changes.
func (r *recordingProfileConfigurator) expectMutexFractions(t *testing.T, want []int) {
	t.Helper()

	if len(r.mutexFractions) != len(want) {
		t.Fatalf("mutex fractions = %#v, want %#v", r.mutexFractions, want)
	}

	for index, value := range want {
		if r.mutexFractions[index] != value {
			t.Fatalf("mutex fractions = %#v, want %#v", r.mutexFractions, want)
		}
	}
}
