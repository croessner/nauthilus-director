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
	"slices"
	"strings"
	"testing"

	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/observability"
)

// TestSafeReloadAppliesSupportedChanges verifies live-safe changes update the active snapshot.
func TestSafeReloadAppliesSupportedChanges(t *testing.T) {
	current := config.DefaultConfig()
	next := config.DefaultConfig()
	backendConfig := next.Director.Backends["mailstore-a-imap"]
	backendConfig.Weight = 250
	next.Director.Backends["mailstore-a-imap"] = backendConfig

	service := NewSafeReloadService(current, func(context.Context) (config.Config, error) {
		return next, nil
	})

	result, err := service.Reload(context.Background())
	if err != nil {
		t.Fatalf("Reload returned error for supported change: %v", err)
	}

	if result.Generation == "" {
		t.Fatal("Reload returned empty generation")
	}

	if !slices.Contains(result.Applied, "director.backends") {
		t.Fatalf("Reload did not report applied backend changes: %#v", result.Applied)
	}
}

// TestSafeReloadRejectsUnsafeChanges verifies unsafe changes fail without partial apply.
func TestSafeReloadRejectsUnsafeChanges(t *testing.T) {
	current := config.DefaultConfig()
	next := config.DefaultConfig()
	backendConfig := next.Director.Backends["mailstore-a-imap"]
	backendConfig.Weight = 300
	next.Director.Backends["mailstore-a-imap"] = backendConfig
	next.Runtime.Servers.Control.Address = "127.0.0.1:19090"

	service := NewSafeReloadService(current, func(context.Context) (config.Config, error) {
		return next, nil
	})

	_, err := service.Reload(context.Background())
	if !IsErrorKind(err, ErrorKindConflict) {
		t.Fatalf("Reload error kind = %v, want conflict", err)
	}

	if !strings.Contains(err.Error(), "runtime.servers.control.address requires restart") {
		t.Fatalf("Reload error does not explain unsafe control listener change: %v", err)
	}

	next = config.DefaultConfig()
	backendConfig = next.Director.Backends["mailstore-a-imap"]
	backendConfig.Weight = 300
	next.Director.Backends["mailstore-a-imap"] = backendConfig

	result, err := service.Reload(context.Background())
	if err != nil {
		t.Fatalf("Reload returned error after unsafe change was removed: %v", err)
	}

	if !slices.Contains(result.Applied, "director.backends") {
		t.Fatalf("Reload appears to have partially applied the rejected backend change: %#v", result.Applied)
	}
}

// TestRuntimeObservationOperationsMatchControlVocabulary verifies public operation names stay stable.
func TestRuntimeObservationOperationsMatchControlVocabulary(t *testing.T) {
	recorder := &recordingRuntimeObservation{}
	required := []string{
		operationBackendInOut,
		operationBackendWeight,
		operationBackendMaintenance,
		operationBackendDrain,
		operationBackendRuntimeClear,
		operationUserMove,
		operationUserKick,
		operationUserAffinityClear,
		operationUserBackendPinSet,
		operationUserBackendPinGet,
		operationUserBackendPinClear,
		operationUserHoldSet,
		operationUserHoldGet,
		operationUserHoldClear,
		operationUserHoldCheck,
		operationSessionKill,
		operationSessionReap,
		operationRouteLookup,
		operationListenerList,
		operationListenerGet,
		operationListenerDrain,
		operationListenerResume,
		operationReload,
	}

	for _, operation := range required {
		recordRuntimeObservation(
			context.Background(),
			recorder,
			observability.EventReload,
			observability.TraceBoundaryRESTRequest,
			operation,
			runtimeObservationResultOK,
			runtimeObservationResultOK,
			nil,
			nil,
		)
	}

	seen := map[string]bool{}
	for _, event := range recorder.events {
		seen[event.MetricLabels["operation"]] = true
	}

	for _, operation := range required {
		if !seen[operation] {
			t.Fatalf("operation %q was not observed in runtime labels: %#v", operation, recorder.events)
		}
	}
}
