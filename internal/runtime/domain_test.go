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
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/state"
)

const (
	runtimeTestBackendIdentifier = "backend-a"
	runtimeTestSessionA          = "session-a"
	runtimeTestSessionB          = "session-b"
	runtimeTestSessionC          = "session-c"
	runtimeTestTenant            = "default"
	runtimeTestUserHash          = "hash-a"
)

// runtimeValidationCase couples a validation name with the request under test.
type runtimeValidationCase struct {
	name     string
	validate func() error
}

// TestAuditMetadataDoesNotIncludeSecretBearingValues verifies audit sanitization.
func TestAuditMetadataDoesNotIncludeSecretBearingValues(t *testing.T) {
	audit, err := NewAuditMetadata(AuditInput{
		Operation:  AuditOperationBackendRuntimeSet,
		Reason:     "maintenance window",
		ServerTime: time.Unix(100, 0),
		Fields: map[string]string{
			"password": "secret-password",
			"token":    "secret-token",
			"username": "alice@example.test",
			"mode":     "hard",
		},
	})
	if err != nil {
		t.Fatalf("NewAuditMetadata returned error: %v", err)
	}

	rendered := strings.Join(mapValues(audit.SafeFields()), "\n")
	if strings.Contains(rendered, "secret-password") || strings.Contains(rendered, "secret-token") {
		t.Fatalf("audit metadata leaked secret values: %#v", audit.SafeFields())
	}

	if audit.Fields["password"] != observability.RedactedValue || audit.Fields["token"] != observability.RedactedValue {
		t.Fatalf("secret fields were not redacted: %#v", audit.Fields)
	}

	if audit.Fields["username_present"] != "true" {
		t.Fatalf("high-cardinality username was not collapsed: %#v", audit.Fields)
	}
}

// TestBackendRuntimeRequestsRejectEmptyReasons verifies backend mutation validation.
func TestBackendRuntimeRequestsRejectEmptyReasons(t *testing.T) {
	policy := backend.RuntimeOverridePolicy{
		Enabled:             true,
		AllowWeightOverride: true,
		MinWeight:           0,
		MaxWeight:           100,
	}

	assertInvalidRuntimeRequests(t, []runtimeValidationCase{
		{
			name: "backend in out",
			validate: func() error {
				return SetBackendInServiceRequest{BackendIdentifier: runtimeTestBackendIdentifier, InService: true}.Validate()
			},
		},
		{
			name: "backend weight",
			validate: func() error {
				return SetBackendWeightRequest{BackendIdentifier: runtimeTestBackendIdentifier, Weight: 10}.Validate(policy)
			},
		},
		{
			name: "backend maintenance",
			validate: func() error {
				return SetBackendMaintenanceRequest{
					BackendIdentifier: runtimeTestBackendIdentifier,
					Maintenance:       backend.MaintenanceState{Mode: backend.MaintenanceModeSoft},
				}.Validate()
			},
		},
		{
			name: "backend drain",
			validate: func() error {
				return StartBackendDrainRequest{
					BackendIdentifier: runtimeTestBackendIdentifier,
					Drain:             backend.DrainState{Enabled: true, Mode: backend.DrainModeSoft},
				}.Validate()
			},
		},
		{
			name: "backend clear",
			validate: func() error {
				return ClearBackendRuntimeRequest{BackendIdentifier: runtimeTestBackendIdentifier}.Validate()
			},
		},
	})
}

// TestUserAndSessionRuntimeRequestsRejectEmptyReasons verifies user/session mutation validation.
func TestUserAndSessionRuntimeRequestsRejectEmptyReasons(t *testing.T) {
	userKey := UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash}

	assertInvalidRuntimeRequests(t, []runtimeValidationCase{
		{
			name: "user move",
			validate: func() error {
				return MoveUserRequest{
					Key:         userKey,
					TargetShard: "shard-a",
					Strategy:    MoveStrategyNewSessionsOnly,
				}.Validate()
			},
		},
		{
			name: "user kick",
			validate: func() error {
				return KickUserRequest{Key: userKey}.Validate()
			},
		},
		{
			name: "user affinity clear",
			validate: func() error {
				return ClearUserAffinityRequest{Key: userKey}.Validate()
			},
		},
		{
			name: "session kill",
			validate: func() error {
				return KillSessionRequest{SessionID: runtimeTestSessionA}.Validate()
			},
		},
	})
}

// TestUserKickClosesEveryLocalSessionForAffinity verifies local acceleration is user-scoped.
func TestUserKickClosesEveryLocalSessionForAffinity(t *testing.T) {
	registry := NewLocalSessionRegistry()
	userKey := UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash}
	first := &recordingLocalHandle{}
	second := &recordingLocalHandle{}
	other := &recordingLocalHandle{}

	registerTestLocalSession(t, registry, LocalSessionInfo{SessionID: runtimeTestSessionA, Tenant: userKey.Tenant, UserHash: userKey.UserHash}, first)
	registerTestLocalSession(t, registry, LocalSessionInfo{SessionID: runtimeTestSessionB, Tenant: userKey.Tenant, UserHash: userKey.UserHash}, second)
	registerTestLocalSession(t, registry, LocalSessionInfo{SessionID: runtimeTestSessionC, Tenant: userKey.Tenant, UserHash: "other"}, other)

	service := NewUserService(&recordingUserStateStore{
		kickRecord: state.UserRuntimeRecord{
			Status:        "kicked",
			Key:           userKey.affinityKey(),
			Generation:    "7",
			ControlAction: state.ControlActionKick,
			ServerTime:    time.Unix(100, 0),
		},
	}, registry)

	if _, err := service.KickUser(context.Background(), KickUserRequest{
		Key:    userKey,
		Reason: "operator requested reconnect",
	}); err != nil {
		t.Fatalf("KickUser returned error: %v", err)
	}

	if first.closed != 1 || second.closed != 1 {
		t.Fatalf("user sessions closed = %d/%d, want both closed once", first.closed, second.closed)
	}

	if other.closed != 0 {
		t.Fatalf("unrelated session closed = %d, want 0", other.closed)
	}
}

// TestSessionKillClosesOnlyTargetLocalSession verifies session-specific acceleration.
func TestSessionKillClosesOnlyTargetLocalSession(t *testing.T) {
	registry := NewLocalSessionRegistry()
	target := &recordingLocalHandle{}
	other := &recordingLocalHandle{}

	registerTestLocalSession(t, registry, LocalSessionInfo{SessionID: runtimeTestSessionA}, target)
	registerTestLocalSession(t, registry, LocalSessionInfo{SessionID: runtimeTestSessionB}, other)

	service := NewSessionService(&recordingSessionStateStore{
		killRecord: state.SessionKillRecord{
			Status:            "marked",
			SessionID:         runtimeTestSessionA,
			ControlAction:     state.ControlActionKick,
			ControlGeneration: "3",
			ServerTime:        time.Unix(100, 0),
		},
	}, registry)

	if _, err := service.KillSession(context.Background(), KillSessionRequest{
		SessionID: runtimeTestSessionA,
		Reason:    "operator killed one session",
	}); err != nil {
		t.Fatalf("KillSession returned error: %v", err)
	}

	if target.closed != 1 {
		t.Fatalf("target session closed = %d, want 1", target.closed)
	}

	if other.closed != 0 {
		t.Fatalf("other session closed = %d, want 0", other.closed)
	}
}

// TestBackendDrainClosesEveryLocalSessionForBackend verifies backend membership bulk behavior.
func TestBackendDrainClosesEveryLocalSessionForBackend(t *testing.T) {
	registry := NewLocalSessionRegistry()
	first := &recordingLocalHandle{}
	second := &recordingLocalHandle{}
	other := &recordingLocalHandle{}

	registerTestLocalSession(t, registry, LocalSessionInfo{SessionID: runtimeTestSessionA, BackendIdentifier: runtimeTestBackendIdentifier}, first)
	registerTestLocalSession(t, registry, LocalSessionInfo{SessionID: runtimeTestSessionB, BackendIdentifier: runtimeTestBackendIdentifier}, second)
	registerTestLocalSession(t, registry, LocalSessionInfo{SessionID: runtimeTestSessionC, BackendIdentifier: "backend-b"}, other)

	service := NewBackendService(&recordingBackendStateStore{
		record: state.BackendRuntimeRecord{
			Status:             "updated",
			BackendIdentifier:  runtimeTestBackendIdentifier,
			Generation:         "11",
			MarkedSessionCount: 2,
			ServerTime:         time.Unix(100, 0),
		},
	}, registry)

	if _, err := service.StartDrain(context.Background(), StartBackendDrainRequest{
		BackendIdentifier: runtimeTestBackendIdentifier,
		Drain:             backend.DrainState{Enabled: true, Mode: backend.DrainModeHard},
		Reason:            "host drain",
	}); err != nil {
		t.Fatalf("StartDrain returned error: %v", err)
	}

	if first.closed != 1 || second.closed != 1 {
		t.Fatalf("backend sessions closed = %d/%d, want both closed once", first.closed, second.closed)
	}

	if other.closed != 0 {
		t.Fatalf("unrelated backend session closed = %d, want 0", other.closed)
	}
}

// TestReaperRunOnceReportsRepairCounts verifies lifecycle repair delegates through the service.
func TestReaperRunOnceReportsRepairCounts(t *testing.T) {
	store := &recordingSessionStateStore{
		reapRecord: state.ReapRecord{
			Status:           "reaped",
			ScannedSessions:  4,
			ExpiredSessions:  2,
			RepairedBackends: 1,
			ServerTime:       time.Unix(100, 0),
		},
	}

	service := NewSessionService(store, nil)

	reaper, err := NewReaper(service, ReaperConfig{Interval: time.Second, Limit: 10})
	if err != nil {
		t.Fatalf("NewReaper returned error: %v", err)
	}

	result, err := reaper.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}

	if result.ExpiredSessions != 2 || result.RepairedBackends != 1 {
		t.Fatalf("reap result = %#v, want repair counts", result)
	}

	if store.reapRequest.Limit != 10 {
		t.Fatalf("reap limit = %d, want 10", store.reapRequest.Limit)
	}
}

// assertInvalidRuntimeRequests checks that each mutation rejects its missing reason.
func assertInvalidRuntimeRequests(t *testing.T, testCases []runtimeValidationCase) {
	t.Helper()

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if err := testCase.validate(); !IsErrorKind(err, ErrorKindInvalidRequest) {
				t.Fatalf("Validate error = %v, want invalid_request", err)
			}
		})
	}
}

// mapValues returns map values for compact leak checks.
func mapValues(values map[string]string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}

	return out
}

// registerTestLocalSession records one local session in the test registry.
func registerTestLocalSession(
	t *testing.T,
	registry *LocalSessionRegistry,
	info LocalSessionInfo,
	handle LocalSessionHandle,
) {
	t.Helper()

	unregister, err := registry.Register(info, handle)
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	t.Cleanup(unregister)
}

type recordingLocalHandle struct {
	closed int
}

// CloseRuntimeSession records one local stream close request.
func (h *recordingLocalHandle) CloseRuntimeSession(context.Context, LocalSessionControl) error {
	h.closed++

	return nil
}

type recordingUserStateStore struct {
	moveRecord  state.UserRuntimeRecord
	kickRecord  state.UserRuntimeRecord
	clearRecord state.UserRuntimeRecord
}

// MoveUser returns the configured user move record.
func (s *recordingUserStateStore) MoveUser(context.Context, state.UserMoveRequest) (state.UserRuntimeRecord, error) {
	return s.moveRecord, nil
}

// KickUser returns the configured user kick record.
func (s *recordingUserStateStore) KickUser(context.Context, state.UserKickRequest) (state.UserRuntimeRecord, error) {
	return s.kickRecord, nil
}

// ClearUserAffinity returns the configured user clear record.
func (s *recordingUserStateStore) ClearUserAffinity(
	context.Context,
	state.UserClearRequest,
) (state.UserRuntimeRecord, error) {
	return s.clearRecord, nil
}

type recordingSessionStateStore struct {
	killRecord  state.SessionKillRecord
	reapRecord  state.ReapRecord
	reapRequest state.ReapRequest
}

// KillSession returns the configured session kill record.
func (s *recordingSessionStateStore) KillSession(
	context.Context,
	state.SessionKillRequest,
) (state.SessionKillRecord, error) {
	return s.killRecord, nil
}

// ReapSessions records and returns the configured reap request.
func (s *recordingSessionStateStore) ReapSessions(
	_ context.Context,
	request state.ReapRequest,
) (state.ReapRecord, error) {
	s.reapRequest = request

	return s.reapRecord, nil
}

type recordingBackendStateStore struct {
	record state.BackendRuntimeRecord
}

// SetBackendRuntime returns the configured backend runtime record.
func (s *recordingBackendStateStore) SetBackendRuntime(
	context.Context,
	state.BackendRuntimeMutation,
) (state.BackendRuntimeRecord, error) {
	return s.record, nil
}

// ClearBackendRuntime returns the configured backend runtime clear record.
func (s *recordingBackendStateStore) ClearBackendRuntime(
	context.Context,
	state.BackendRuntimeClearRequest,
) (state.BackendRuntimeRecord, error) {
	return s.record, nil
}
