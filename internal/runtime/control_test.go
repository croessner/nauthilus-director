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
	"time"

	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/observability"
)

type safeReloadRejectCase struct {
	name   string
	mutate func(*config.Config)
	want   string
}

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

// TestSafeReloadAppliesListenerInventoryChanges verifies listener add/remove reload reporting.
func TestSafeReloadAppliesListenerInventoryChanges(t *testing.T) {
	current := config.DefaultConfig()
	next := config.DefaultConfig()
	delete(next.Director.Listeners, "pop3")

	service := NewSafeReloadService(current, func(context.Context) (config.Config, error) {
		return next, nil
	})

	result, err := service.Reload(context.Background())
	if err != nil {
		t.Fatalf("Reload returned error for listener removal: %v", err)
	}

	if !slices.Contains(result.Applied, "director.listeners") {
		t.Fatalf("Reload did not report applied listener changes: %#v", result.Applied)
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

// TestSafeReloadRejectsProfileChanges verifies diagnostic profile routes remain restart-scoped.
func TestSafeReloadRejectsProfileChanges(t *testing.T) {
	current := config.DefaultConfig()
	next := config.DefaultConfig()
	next.Observability.Profiles.PProf.Enabled = true
	next.Observability.Profiles.Goroutine.Enabled = true

	service := NewSafeReloadService(current, func(context.Context) (config.Config, error) {
		return next, nil
	})

	_, err := service.Reload(context.Background())
	if !IsErrorKind(err, ErrorKindConflict) {
		t.Fatalf("Reload error kind = %v, want conflict", err)
	}

	if !strings.Contains(err.Error(), "observability.profiles requires restart") {
		t.Fatalf("Reload error does not explain profile restart requirement: %v", err)
	}
}

// TestSafeReloadRejectsNonReloadableRuntimeOwners keeps accepted snapshots honest.
func TestSafeReloadRejectsNonReloadableRuntimeOwners(t *testing.T) {
	for _, test := range safeReloadNonReloadableRuntimeOwnerCases() {
		t.Run(test.name, func(t *testing.T) {
			current := config.DefaultConfig()
			next := config.DefaultConfig()
			test.mutate(&next)

			service := NewSafeReloadService(current, func(context.Context) (config.Config, error) {
				return next, nil
			})

			_, err := service.Reload(context.Background())
			if !IsErrorKind(err, ErrorKindConflict) {
				t.Fatalf("Reload error kind = %v, want conflict", err)
			}

			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Reload error = %v, want %q", err, test.want)
			}
		})
	}
}

// safeReloadNonReloadableRuntimeOwnerCases returns restart-required config mutations.
func safeReloadNonReloadableRuntimeOwnerCases() []safeReloadRejectCase {
	return []safeReloadRejectCase{
		{
			name:   "runtime timeout",
			mutate: mutateRuntimeTimeoutForReload,
			want:   "runtime.timeouts requires restart",
		},
		{
			name:   "routing resolver",
			mutate: mutateRoutingResolverForReload,
			want:   "director.routing requires restart",
		},
		{
			name:   "observability tracing",
			mutate: mutateTracingForReload,
			want:   "observability.tracing requires restart",
		},
		{
			name:   "control auth",
			mutate: mutateControlAuthForReload,
			want:   "runtime.servers.control.auth requires restart",
		},
		{
			name:   "authority transport",
			mutate: mutateAuthorityTransportForReload,
			want:   "auth requires restart",
		},
		{
			name:   "existing listener socket",
			mutate: mutateExistingListenerSocketForReload,
			want:   "director.listeners.",
		},
	}
}

// mutateRuntimeTimeoutForReload changes process-wide timeout behavior.
func mutateRuntimeTimeoutForReload(next *config.Config) {
	next.Runtime.Timeouts.ProxyIdle = config.NewDuration(2 * time.Minute)
}

// mutateRoutingResolverForReload changes routing fact interpretation.
func mutateRoutingResolverForReload(next *config.Config) {
	next.Director.Routing.AuthAttributes.ShardTag = "mailboxShard"
}

// mutateTracingForReload changes observability exporter identity.
func mutateTracingForReload(next *config.Config) {
	next.Observability.Tracing.ServiceName += "-reload"
}

// mutateControlAuthForReload changes control-plane authentication.
func mutateControlAuthForReload(next *config.Config) {
	next.Runtime.Servers.Control.Auth.Bearer.Enabled = false
}

// mutateAuthorityTransportForReload changes the Nauthilus authority transport.
func mutateAuthorityTransportForReload(next *config.Config) {
	authority := next.Auth.Authorities["default"]
	authority.Transport = "grpc"
	next.Auth.Authorities["default"] = authority
}

// mutateExistingListenerSocketForReload changes an already-open listener socket.
func mutateExistingListenerSocketForReload(next *config.Config) {
	listener := next.Director.Listeners["imap"]
	listener.Address = "127.0.0.1:11143"
	next.Director.Listeners["imap"] = listener
}

// TestSafeReloadObservationIncludesActorAuditFields verifies reload attempts are attributable.
func TestSafeReloadObservationIncludesActorAuditFields(t *testing.T) {
	recorder := &recordingRuntimeObservation{}
	actor := Actor{ID: runtimeTestHoldActorSet, AuthMethod: "oidc", Authenticated: true}

	service := NewSafeReloadService(config.DefaultConfig(), func(context.Context) (config.Config, error) {
		return config.DefaultConfig(), nil
	}, WithObservabilityRecorder(recorder))

	_, err := service.Reload(WithActor(context.Background(), actor))
	if err != nil {
		t.Fatalf("Reload returned error: %v", err)
	}

	event, ok := recorder.last(observability.EventReload)
	if !ok {
		t.Fatal("reload observation was not recorded")
	}

	if event.LogFields[runtimeObservationFieldActorID] != actor.ID ||
		event.LogFields[runtimeObservationFieldAuthMethod] != actor.AuthMethod ||
		event.LogFields[runtimeObservationFieldActorAuthenticated] != auditValueTrue {
		t.Fatalf("reload audit fields = %#v, want actor attribution", event.LogFields)
	}

	if _, ok := event.MetricLabels[runtimeObservationFieldActorID]; ok {
		t.Fatalf("reload metric labels leaked actor identity: %#v", event.MetricLabels)
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
