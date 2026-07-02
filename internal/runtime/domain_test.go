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

//nolint:goconst,wsl_v5 // Runtime domain fixtures repeat protocol and backend identifiers intentionally.
package runtime

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/state"
)

const (
	runtimeTestBackendIdentifier = "backend-a"
	runtimeTestBackendNodeA      = "mailstore-a-node-1"
	runtimeTestBackendPinReason  = "commission backend"
	runtimeTestFieldBackendID    = "BackendIdentifier"
	runtimeTestFieldToBackend    = "ToBackend"
	runtimeTestFieldToBackendID  = "ToBackendIdentifier"
	runtimeTestHoldActorClear    = "operator-b"
	runtimeTestHoldActorSet      = "operator-a"
	runtimeTestHoldGenerationSet = "hold-1"
	runtimeTestHoldGenerationEnd = "hold-2"
	runtimeTestHoldReason        = "hold user placement"
	runtimeTestMTLSAuthMethod    = "mtls"
	runtimeTestMoveReason        = "move user"
	runtimeTestPinnedStatus      = "pinned"
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
				return SetBackendInServiceRequest{BackendIdentifier: runtimeTestBackendIdentifier, InService: true}.Validate(policy)
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
				}.Validate(policy)
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

// TestBackendRuntimePolicyRejectsDisabledOperations keeps configured override switches fail-closed.
//
//nolint:funlen,dupl // The table intentionally enumerates backend policy denial cases.
func TestBackendRuntimePolicyRejectsDisabledOperations(t *testing.T) {
	testCases := []struct {
		name   string
		policy backend.RuntimeOverridePolicy
		mutate func(*BackendService, backend.RuntimeOverridePolicy) error
	}{
		{
			name:   "global weight disabled",
			policy: backend.RuntimeOverridePolicy{},
			mutate: func(service *BackendService, policy backend.RuntimeOverridePolicy) error {
				_, err := service.SetWeight(context.Background(), SetBackendWeightRequest{
					BackendIdentifier: runtimeTestBackendIdentifier,
					Weight:            10,
					Reason:            "adjust weight",
				}, policy)

				return err
			},
		},
		{
			name:   "global in out disabled",
			policy: backend.RuntimeOverridePolicy{},
			mutate: func(service *BackendService, policy backend.RuntimeOverridePolicy) error {
				_, err := service.SetInService(context.Background(), SetBackendInServiceRequest{
					BackendIdentifier: runtimeTestBackendIdentifier,
					InService:         false,
					Reason:            "stop placement",
				}, policy)

				return err
			},
		},
		{
			name:   "global drain disabled",
			policy: backend.RuntimeOverridePolicy{},
			mutate: func(service *BackendService, policy backend.RuntimeOverridePolicy) error {
				_, err := service.StartDrain(context.Background(), StartBackendDrainRequest{
					BackendIdentifier: runtimeTestBackendIdentifier,
					Drain:             backend.DrainState{Enabled: true, Mode: backend.DrainModeSoft},
					Reason:            "host drain",
				}, policy)

				return err
			},
		},
		{
			name: "weight override disabled",
			policy: backend.RuntimeOverridePolicy{
				Enabled:             true,
				AllowWeightOverride: false,
				MinWeight:           0,
				MaxWeight:           100,
			},
			mutate: func(service *BackendService, policy backend.RuntimeOverridePolicy) error {
				_, err := service.SetWeight(context.Background(), SetBackendWeightRequest{
					BackendIdentifier: runtimeTestBackendIdentifier,
					Weight:            10,
					Reason:            "adjust weight",
				}, policy)

				return err
			},
		},
		{
			name: "weight outside bounds",
			policy: backend.RuntimeOverridePolicy{
				Enabled:             true,
				AllowWeightOverride: true,
				MinWeight:           10,
				MaxWeight:           20,
			},
			mutate: func(service *BackendService, policy backend.RuntimeOverridePolicy) error {
				_, err := service.SetWeight(context.Background(), SetBackendWeightRequest{
					BackendIdentifier: runtimeTestBackendIdentifier,
					Weight:            25,
					Reason:            "adjust weight",
				}, policy)

				return err
			},
		},
		{
			name: "in out override disabled",
			policy: backend.RuntimeOverridePolicy{
				Enabled:             true,
				AllowWeightOverride: true,
				AllowInOut:          false,
				AllowDrain:          true,
			},
			mutate: func(service *BackendService, policy backend.RuntimeOverridePolicy) error {
				_, err := service.SetInService(context.Background(), SetBackendInServiceRequest{
					BackendIdentifier: runtimeTestBackendIdentifier,
					InService:         false,
					Reason:            "stop placement",
				}, policy)

				return err
			},
		},
		{
			name: "drain override disabled",
			policy: backend.RuntimeOverridePolicy{
				Enabled:             true,
				AllowWeightOverride: true,
				AllowInOut:          true,
				AllowDrain:          false,
			},
			mutate: func(service *BackendService, policy backend.RuntimeOverridePolicy) error {
				_, err := service.StartDrain(context.Background(), StartBackendDrainRequest{
					BackendIdentifier: runtimeTestBackendIdentifier,
					Drain:             backend.DrainState{Enabled: true, Mode: backend.DrainModeSoft},
					Reason:            "host drain",
				}, policy)

				return err
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			store := &recordingBackendStateStore{record: backendRuntimeRecord()}
			service := NewBackendService(store, nil)

			err := testCase.mutate(service, testCase.policy)
			if !backend.IsErrorKind(err, backend.ErrorKindInvalidRequest) {
				t.Fatalf("mutation error = %v, want backend invalid request", err)
			}

			if store.setCalls != 0 {
				t.Fatalf("store calls = %d, want policy denial before persistence", store.setCalls)
			}
		})
	}
}

// TestBackendRuntimePolicyAllowsConfiguredMutations verifies allowed backend operations reach persistence.
//
//nolint:funlen // The table keeps allowed backend mutation assertions together.
func TestBackendRuntimePolicyAllowsConfiguredMutations(t *testing.T) {
	policy := backend.RuntimeOverridePolicy{
		Enabled:             true,
		AllowWeightOverride: true,
		AllowInOut:          true,
		AllowDrain:          true,
		MinWeight:           0,
		MaxWeight:           100,
	}

	testCases := []struct {
		name   string
		mutate func(*BackendService) error
		assert func(*testing.T, state.BackendRuntimeMutation)
	}{
		{
			name: "weight",
			mutate: func(service *BackendService) error {
				_, err := service.SetWeight(context.Background(), SetBackendWeightRequest{
					BackendIdentifier: " " + runtimeTestBackendIdentifier + " ",
					Weight:            50,
					Reason:            "adjust weight",
				}, policy)

				return err
			},
			assert: func(t *testing.T, mutation state.BackendRuntimeMutation) {
				t.Helper()
				if mutation.Weight == nil || *mutation.Weight != 50 {
					t.Fatalf("weight mutation = %#v, want weight 50", mutation)
				}
			},
		},
		{
			name: "in out",
			mutate: func(service *BackendService) error {
				_, err := service.SetInService(context.Background(), SetBackendInServiceRequest{
					BackendIdentifier: " " + runtimeTestBackendIdentifier + " ",
					InService:         false,
					Reason:            "stop placement",
				}, policy)

				return err
			},
			assert: func(t *testing.T, mutation state.BackendRuntimeMutation) {
				t.Helper()
				if mutation.InService == nil || *mutation.InService {
					t.Fatalf("in/out mutation = %#v, want in_service=false", mutation)
				}
			},
		},
		{
			name: "drain",
			mutate: func(service *BackendService) error {
				_, err := service.StartDrain(context.Background(), StartBackendDrainRequest{
					BackendIdentifier: " " + runtimeTestBackendIdentifier + " ",
					Drain:             backend.DrainState{Enabled: true, Mode: backend.DrainModeSoft},
					Reason:            "host drain",
				}, policy)

				return err
			},
			assert: func(t *testing.T, mutation state.BackendRuntimeMutation) {
				t.Helper()
				if !mutation.DrainEnabled || mutation.DrainMode != string(backend.DrainModeSoft) {
					t.Fatalf("drain mutation = %#v, want enabled soft drain", mutation)
				}
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			store := &recordingBackendStateStore{record: backendRuntimeRecord()}
			service := NewBackendService(store, nil)

			if err := testCase.mutate(service); err != nil {
				t.Fatalf("mutation returned error: %v", err)
			}

			if store.setCalls != 1 {
				t.Fatalf("store calls = %d, want 1", store.setCalls)
			}
			if store.mutation.BackendIdentifier != runtimeTestBackendIdentifier {
				t.Fatalf("backend identifier = %q, want trimmed %q", store.mutation.BackendIdentifier, runtimeTestBackendIdentifier)
			}
			testCase.assert(t, store.mutation)
		})
	}
}

// TestUserRuntimePolicyRejectsDisabledOperations keeps user override switches fail-closed.
//
//nolint:funlen,dupl // The table intentionally enumerates user policy denial cases.
func TestUserRuntimePolicyRejectsDisabledOperations(t *testing.T) {
	testCases := []struct {
		name   string
		policy UserRuntimeOverridePolicy
		mutate func(*UserService, *UserBackendPinService, UserRuntimeOverridePolicy) error
		assert func(*testing.T, *recordingUserStateStore, *recordingBackendPinStateStore)
	}{
		{
			name:   "global move disabled",
			policy: UserRuntimeOverridePolicy{},
			mutate: func(user *UserService, _ *UserBackendPinService, policy UserRuntimeOverridePolicy) error {
				_, err := user.MoveUser(context.Background(), MoveUserRequest{
					Key:         UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
					TargetShard: routeLookupShardA,
					Strategy:    MoveStrategyNewSessionsOnly,
					Reason:      "move user",
				}, policy)

				return err
			},
			assert: assertNoUserOrBackendPinMutation,
		},
		{
			name: "move disabled",
			policy: UserRuntimeOverridePolicy{
				Enabled:               true,
				AllowMove:             false,
				AllowKick:             true,
				AllowAffinityClear:    true,
				AllowedMoveStrategies: []MoveStrategy{MoveStrategyNewSessionsOnly},
			},
			mutate: func(user *UserService, _ *UserBackendPinService, policy UserRuntimeOverridePolicy) error {
				_, err := user.MoveUser(context.Background(), MoveUserRequest{
					Key:         UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
					TargetShard: routeLookupShardA,
					Strategy:    MoveStrategyNewSessionsOnly,
					Reason:      "move user",
				}, policy)

				return err
			},
			assert: assertNoUserOrBackendPinMutation,
		},
		{
			name: "move strategy disabled",
			policy: UserRuntimeOverridePolicy{
				Enabled:               true,
				AllowMove:             true,
				AllowKick:             true,
				AllowAffinityClear:    true,
				AllowedMoveStrategies: []MoveStrategy{MoveStrategyNewSessionsOnly},
			},
			mutate: func(user *UserService, _ *UserBackendPinService, policy UserRuntimeOverridePolicy) error {
				_, err := user.MoveUser(context.Background(), MoveUserRequest{
					Key:         UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
					TargetShard: routeLookupShardA,
					Strategy:    MoveStrategyKickExisting,
					Reason:      "move user",
				}, policy)

				return err
			},
			assert: assertNoUserOrBackendPinMutation,
		},
		{
			name: "kick disabled",
			policy: UserRuntimeOverridePolicy{
				Enabled:               true,
				AllowMove:             true,
				AllowKick:             false,
				AllowAffinityClear:    true,
				AllowedMoveStrategies: []MoveStrategy{MoveStrategyNewSessionsOnly, MoveStrategyKickExisting},
			},
			mutate: func(user *UserService, _ *UserBackendPinService, policy UserRuntimeOverridePolicy) error {
				_, err := user.KickUser(context.Background(), KickUserRequest{
					Key:    UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
					Reason: "kick user",
				}, policy)

				return err
			},
			assert: assertNoUserOrBackendPinMutation,
		},
		{
			name: "affinity clear disabled",
			policy: UserRuntimeOverridePolicy{
				Enabled:               true,
				AllowMove:             true,
				AllowKick:             true,
				AllowAffinityClear:    false,
				AllowedMoveStrategies: []MoveStrategy{MoveStrategyNewSessionsOnly, MoveStrategyKickExisting},
			},
			mutate: func(user *UserService, _ *UserBackendPinService, policy UserRuntimeOverridePolicy) error {
				_, err := user.ClearUserAffinity(context.Background(), ClearUserAffinityRequest{
					Key:    UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
					Reason: "clear affinity",
				}, policy)

				return err
			},
			assert: assertNoUserOrBackendPinMutation,
		},
		{
			name:   "global backend pin disabled",
			policy: UserRuntimeOverridePolicy{},
			mutate: func(_ *UserService, pins *UserBackendPinService, policy UserRuntimeOverridePolicy) error {
				_, err := pins.SetUserBackendPinTarget(context.Background(), SetUserBackendPinTargetRequest{
					Key:               UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
					BackendIdentifier: routeLookupBackendA,
					Strategy:          MoveStrategyNewSessionsOnly,
					Reason:            runtimeTestBackendPinReason,
				}, policy)

				return err
			},
			assert: assertNoUserOrBackendPinMutation,
		},
		{
			name: "backend pin move disabled",
			policy: UserRuntimeOverridePolicy{
				Enabled:               true,
				AllowMove:             false,
				AllowKick:             true,
				AllowAffinityClear:    true,
				AllowedMoveStrategies: []MoveStrategy{MoveStrategyNewSessionsOnly},
			},
			mutate: func(_ *UserService, pins *UserBackendPinService, policy UserRuntimeOverridePolicy) error {
				_, err := pins.SetUserBackendPinTarget(context.Background(), SetUserBackendPinTargetRequest{
					Key:               UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
					BackendIdentifier: routeLookupBackendA,
					Strategy:          MoveStrategyNewSessionsOnly,
					Reason:            runtimeTestBackendPinReason,
				}, policy)

				return err
			},
			assert: assertNoUserOrBackendPinMutation,
		},
		{
			name: "backend pin strategy disabled",
			policy: UserRuntimeOverridePolicy{
				Enabled:               true,
				AllowMove:             true,
				AllowKick:             true,
				AllowAffinityClear:    true,
				AllowedMoveStrategies: []MoveStrategy{MoveStrategyNewSessionsOnly},
			},
			mutate: func(_ *UserService, pins *UserBackendPinService, policy UserRuntimeOverridePolicy) error {
				_, err := pins.SetUserBackendPinTarget(context.Background(), SetUserBackendPinTargetRequest{
					Key:               UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
					BackendIdentifier: routeLookupBackendA,
					Strategy:          MoveStrategyKickExisting,
					Reason:            runtimeTestBackendPinReason,
				}, policy)

				return err
			},
			assert: assertNoUserOrBackendPinMutation,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			userStore := &recordingUserStateStore{}
			pinStore := &recordingBackendPinStateStore{}
			user := NewUserService(userStore, nil)
			pins := NewUserBackendPinService(pinStore, nil)

			err := testCase.mutate(user, pins, testCase.policy)
			if !IsErrorKind(err, ErrorKindInvalidRequest) {
				t.Fatalf("mutation error = %v, want invalid_request", err)
			}

			testCase.assert(t, userStore, pinStore)
		})
	}
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
		{
			name: "session reap",
			validate: func() error {
				return ReapSessionsRequest{Limit: 1, MaxPassDuration: time.Second}.Validate()
			},
		},
	})
}

// TestRuntimeReapRepairValidation captures the explicit public reap request contract.
//
//nolint:funlen // The validation table keeps all bounded reap constraints visible together.
func TestRuntimeReapRepairValidation(t *testing.T) {
	assertInvalidRuntimeRequests(t, []runtimeValidationCase{
		{
			name: "missing reason",
			validate: func() error {
				return ReapSessionsRequest{Limit: 1, MaxPassDuration: time.Second}.Validate()
			},
		},
		{
			name: "missing limit",
			validate: func() error {
				return ReapSessionsRequest{Reason: "operator runtime reap", MaxPassDuration: time.Second}.Validate()
			},
		},
		{
			name: "missing max pass duration",
			validate: func() error {
				return ReapSessionsRequest{Reason: "operator runtime reap", Limit: 1}.Validate()
			},
		},
		{
			name: "limit above bound",
			validate: func() error {
				return ReapSessionsRequest{Reason: "operator runtime reap", Limit: maxRuntimeReapLimit + 1, MaxPassDuration: time.Second}.Validate()
			},
		},
		{
			name: "max pass duration above bound",
			validate: func() error {
				return ReapSessionsRequest{Reason: "operator runtime reap", Limit: 1, MaxPassDuration: maxRuntimeReapPassDuration + time.Nanosecond}.Validate()
			},
		},
	})

	request := ReapSessionsRequest{
		Reason:          "operator runtime reap preview",
		Limit:           1,
		MaxPassDuration: time.Second,
	}
	if err := request.Validate(); err != nil {
		t.Fatalf("valid ReapSessionsRequest returned error: %v", err)
	}

	requestValue := reflect.ValueOf(&request).Elem()
	dryRun := requestValue.FieldByName("DryRun")
	if !dryRun.IsValid() {
		t.Fatal("ReapSessionsRequest missing DryRun field for explicit public runtime reap preview")
	}
	if dryRun.Kind() != reflect.Bool || !dryRun.CanSet() {
		t.Fatalf("ReapSessionsRequest DryRun field kind/settable = %s/%t, want bool/true", dryRun.Kind(), dryRun.CanSet())
	}

	dryRun.SetBool(true)

	store := &recordingSessionStateStore{
		reapRecord: state.ReapRecord{Status: "preview", ServerTime: time.Unix(100, 0)},
	}
	service := NewSessionService(store, nil)

	if _, err := service.ReapSessions(context.Background(), request); err != nil {
		t.Fatalf("dry-run ReapSessions returned error: %v", err)
	}

	if store.reapCalls != 0 {
		t.Fatalf("dry-run ReapSessions called mutating store path %d times, want preview without mutation", store.reapCalls)
	}

	if got, want := store.reapRequest.Limit, 0; got != want {
		t.Fatalf("dry-run reap request limit = %d, want untouched store request", got)
	}
}

// TestRuntimeAggregateReconcileRepairValidation captures the missing aggregate reconcile domain contract.
func TestRuntimeAggregateReconcileRepairValidation(t *testing.T) {
	request, typeName, ok := runtimeStructTypeAny(t, "AggregateReconcileRequest", "RuntimeAggregateReconcileRequest")
	if !ok {
		t.Fatal("aggregate reconcile request missing; want reason, limit, max pass duration, dry-run and scope validation")
	}

	assertRuntimeStructFields(t, request, "Reason", "Limit", "MaxPassDuration", "DryRun", "Scope")

	if !runtimeMethodDeclared(t, typeName, "Validate") {
		t.Fatalf("%s.Validate missing; invalid reconcile scopes must be rejected before state repair", typeName)
	}
}

// TestUserHoldSetRejectsEmptyUserKey verifies holds require a normalized affinity key.
func TestUserHoldSetRejectsEmptyUserKey(t *testing.T) {
	err := SetUserHoldRequest{
		Key:      UserKey{Tenant: runtimeTestTenant},
		Duration: time.Minute,
		Reason:   runtimeTestHoldReason,
	}.Validate(30 * time.Minute)
	if !IsErrorKind(err, ErrorKindInvalidRequest) {
		t.Fatalf("Validate error = %v, want invalid_request", err)
	}
}

// TestUserHoldSetRejectsMissingReason verifies mutating hold requests remain auditable.
func TestUserHoldSetRejectsMissingReason(t *testing.T) {
	err := SetUserHoldRequest{
		Key:      UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
		Duration: time.Minute,
	}.Validate(30 * time.Minute)
	if !IsErrorKind(err, ErrorKindInvalidRequest) {
		t.Fatalf("Validate error = %v, want invalid_request", err)
	}
}

// TestUserHoldSetRejectsInvalidDuration verifies hold lifetimes are bounded.
func TestUserHoldSetRejectsInvalidDuration(t *testing.T) {
	userKey := UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash}

	for name, request := range map[string]SetUserHoldRequest{
		"zero": {
			Key:    userKey,
			Reason: runtimeTestHoldReason,
		},
		"negative": {
			Key:      userKey,
			Duration: -time.Second,
			Reason:   runtimeTestHoldReason,
		},
		"above maximum": {
			Key:      userKey,
			Duration: 31 * time.Minute,
			Reason:   runtimeTestHoldReason,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := request.Validate(30 * time.Minute); !IsErrorKind(err, ErrorKindInvalidRequest) {
				t.Fatalf("Validate error = %v, want invalid_request", err)
			}
		})
	}
}

// TestUserHoldSetRejectsUnavailableMaximum verifies bad policy input fails closed.
func TestUserHoldSetRejectsUnavailableMaximum(t *testing.T) {
	err := SetUserHoldRequest{
		Key:      UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
		Duration: time.Minute,
		Reason:   runtimeTestHoldReason,
	}.Validate(0)
	if !IsErrorKind(err, ErrorKindUnavailable) {
		t.Fatalf("Validate error = %v, want unavailable", err)
	}
}

// TestUserHoldClearRejectsMissingReason verifies hold clears stay auditable.
func TestUserHoldClearRejectsMissingReason(t *testing.T) {
	err := ClearUserHoldRequest{
		Key: UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
	}.Validate()
	if !IsErrorKind(err, ErrorKindInvalidRequest) {
		t.Fatalf("Validate error = %v, want invalid_request", err)
	}
}

// TestUserHoldReadRequestsRejectEmptyUserKey verifies read paths still need affinity keys.
func TestUserHoldReadRequestsRejectEmptyUserKey(t *testing.T) {
	for name, validate := range map[string]func() error{
		"get": func() error {
			return GetUserHoldRequest{Key: UserKey{Tenant: runtimeTestTenant}}.Validate()
		},
		"check": func() error {
			return CheckUserHoldRequest{Key: UserKey{Tenant: runtimeTestTenant}}.Validate()
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validate(); !IsErrorKind(err, ErrorKindInvalidRequest) {
				t.Fatalf("Validate error = %v, want invalid_request", err)
			}
		})
	}
}

// TestUserHoldAuditMetadataIsBounded verifies hold audits carry actor without secrets.
func TestUserHoldAuditMetadataIsBounded(t *testing.T) {
	actor := Actor{ID: runtimeTestHoldActorSet, AuthMethod: runtimeTestMTLSAuthMethod, Authenticated: true}
	hold := UserHold{
		Present:           true,
		Key:               UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
		Generation:        runtimeTestHoldGenerationSet,
		CreatedAt:         time.Unix(100, 0),
		ExpiresAt:         time.Unix(700, 0),
		RequestedDuration: 10 * time.Minute,
		UpdatedAt:         time.Unix(101, 0),
	}

	audit, err := (SetUserHoldRequest{
		Key:      hold.Key,
		Duration: 10 * time.Minute,
		Reason:   runtimeTestHoldReason,
		Actor:    actor,
	}).AuditMetadata(hold)
	if err != nil {
		t.Fatalf("AuditMetadata returned error: %v", err)
	}

	if audit.Operation != AuditOperationUserHoldSet ||
		audit.Actor.ID != actor.ID ||
		audit.Generation != runtimeTestHoldGenerationSet ||
		audit.UserHash != runtimeTestUserHash {
		t.Fatalf("hold audit metadata = %#v", audit)
	}

	fields := audit.SafeFields()
	if fields[auditFieldHoldDuration] != "600" ||
		fields[auditFieldHoldPresent] != auditValueTrue ||
		fields[auditFieldHoldExpiresAt] == "" {
		t.Fatalf("hold audit fields = %#v", fields)
	}

	rendered := strings.Join(mapValues(fields), "\n")
	if strings.Contains(rendered, runtimeTestHoldReason) || strings.Contains(rendered, runtimeTestHoldActorSet) {
		t.Fatalf("hold audit fields leaked reason or actor: %#v", fields)
	}
}

// TestUserHoldClearAuditMetadataIncludesActor verifies clear audits carry operator context.
func TestUserHoldClearAuditMetadataIncludesActor(t *testing.T) {
	actor := Actor{ID: runtimeTestHoldActorClear, Authenticated: true}
	hold := UserHold{
		Key:        UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
		Generation: runtimeTestHoldGenerationEnd,
		UpdatedAt:  time.Unix(200, 0),
	}

	audit, err := (ClearUserHoldRequest{
		Key:    hold.Key,
		Reason: "migration complete",
		Actor:  actor,
	}).AuditMetadata(hold)
	if err != nil {
		t.Fatalf("AuditMetadata returned error: %v", err)
	}

	if audit.Operation != AuditOperationUserHoldClear ||
		audit.Actor.ID != actor.ID ||
		audit.Generation != runtimeTestHoldGenerationEnd ||
		audit.Fields[auditFieldHoldPresent] != auditValueFalse {
		t.Fatalf("clear audit metadata = %#v", audit)
	}
}

// TestUserHoldTypesRemainTargetFree verifies holds do not carry routing targets.
func TestUserHoldTypesRemainTargetFree(t *testing.T) {
	types := []reflect.Type{
		reflect.TypeFor[UserHold](),
		reflect.TypeFor[SetUserHoldRequest](),
		reflect.TypeFor[GetUserHoldRequest](),
		reflect.TypeFor[ClearUserHoldRequest](),
		reflect.TypeFor[CheckUserHoldRequest](),
	}

	for _, holdType := range types {
		for _, field := range []string{"TargetShard", "ShardTag", runtimeTestFieldBackendID, runtimeTestFieldToBackend, runtimeTestFieldToBackendID} {
			if _, ok := holdType.FieldByName(field); ok {
				t.Fatalf("%s gained routing target field %s", holdType.Name(), field)
			}
		}
	}
}

// TestUserBackendPinSetRejectsEmptyUserKey verifies pinning needs a normalized affinity key.
func TestUserBackendPinSetRejectsEmptyUserKey(t *testing.T) {
	err := SetUserBackendPinRequest{
		Key:               UserKey{Tenant: runtimeTestTenant},
		BackendIdentifier: routeLookupBackendA,
		Strategy:          MoveStrategyNewSessionsOnly,
		Reason:            runtimeTestBackendPinReason,
	}.Validate()
	if !IsErrorKind(err, ErrorKindInvalidRequest) {
		t.Fatalf("Validate error = %v, want invalid_request", err)
	}
}

// TestUserBackendPinSetRejectsEmptyBackendIdentifier verifies pins require a concrete backend.
func TestUserBackendPinSetRejectsEmptyBackendIdentifier(t *testing.T) {
	err := SetUserBackendPinRequest{
		Key:      UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
		Strategy: MoveStrategyNewSessionsOnly,
		Reason:   runtimeTestBackendPinReason,
	}.Validate()
	if !IsErrorKind(err, ErrorKindInvalidRequest) {
		t.Fatalf("Validate error = %v, want invalid_request", err)
	}
}

// TestUserBackendPinSetRejectsMissingReason verifies mutating pin requests remain auditable.
func TestUserBackendPinSetRejectsMissingReason(t *testing.T) {
	err := SetUserBackendPinRequest{
		Key:               UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
		BackendIdentifier: routeLookupBackendA,
		Strategy:          MoveStrategyNewSessionsOnly,
	}.Validate()
	if !IsErrorKind(err, ErrorKindInvalidRequest) {
		t.Fatalf("Validate error = %v, want invalid_request", err)
	}
}

// TestUserBackendPinSetRejectsUnsupportedStrategy verifies pin moves share the move vocabulary.
func TestUserBackendPinSetRejectsUnsupportedStrategy(t *testing.T) {
	err := SetUserBackendPinRequest{
		Key:               UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
		BackendIdentifier: routeLookupBackendA,
		Strategy:          MoveStrategy("teleport_existing"),
		Reason:            runtimeTestBackendPinReason,
	}.Validate()
	if !IsErrorKind(err, ErrorKindInvalidRequest) {
		t.Fatalf("Validate error = %v, want invalid_request", err)
	}
}

// TestUserBackendPinTargetRejectsInvalidTargetShape verifies the operator request shape.
func TestUserBackendPinTargetRejectsInvalidTargetShape(t *testing.T) {
	userKey := UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash}
	for name, request := range map[string]SetUserBackendPinTargetRequest{
		"missing target": {
			Key:      userKey,
			Strategy: MoveStrategyNewSessionsOnly,
			Reason:   runtimeTestBackendPinReason,
		},
		"both targets": {
			Key:               userKey,
			BackendIdentifier: routeLookupBackendA,
			BackendNode:       runtimeTestBackendNodeA,
			Strategy:          MoveStrategyNewSessionsOnly,
			Reason:            runtimeTestBackendPinReason,
		},
		"backend with scope filter": {
			Key:               userKey,
			BackendIdentifier: routeLookupBackendA,
			Protocol:          routeLookupProtocol,
			BackendPool:       routeLookupDefaultPool,
			Strategy:          MoveStrategyNewSessionsOnly,
			Reason:            runtimeTestBackendPinReason,
		},
		"pool without protocol": {
			Key:         userKey,
			BackendNode: runtimeTestBackendNodeA,
			BackendPool: routeLookupDefaultPool,
			Strategy:    MoveStrategyNewSessionsOnly,
			Reason:      runtimeTestBackendPinReason,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := request.Normalize().Validate(); !IsErrorKind(err, ErrorKindInvalidRequest) {
				t.Fatalf("Validate error = %v, want invalid_request", err)
			}
		})
	}
}

// TestUserBackendPinClearRejectsMissingReason verifies pin clear requests remain auditable.
func TestUserBackendPinClearRejectsMissingReason(t *testing.T) {
	err := ClearUserBackendPinRequest{
		Key: UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
	}.Validate()
	if !IsErrorKind(err, ErrorKindInvalidRequest) {
		t.Fatalf("Validate error = %v, want invalid_request", err)
	}
}

// TestUserBackendPinDerivesTargetFromRegistry verifies operator target facts are not trusted input.
func TestUserBackendPinDerivesTargetFromRegistry(t *testing.T) {
	registry, err := backend.NewStaticRegistry(config.DefaultConfig().Director)
	if err != nil {
		t.Fatalf("NewStaticRegistry returned error: %v", err)
	}

	store := &recordingBackendPinStateStore{
		setRecord: state.UserBackendPinRecord{
			Status:             runtimeTestPinnedStatus,
			Generation:         "19",
			ActiveSessionCount: 2,
			ServerTime:         time.Unix(100, 0),
		},
	}
	service := NewUserBackendPinService(store, registry)

	result, err := service.SetUserBackendPin(context.Background(), SetUserBackendPinRequest{
		Key:               UserKey{Tenant: " " + runtimeTestTenant + " ", UserHash: " " + runtimeTestUserHash + " "},
		BackendIdentifier: " " + routeLookupBackendA + " ",
		Strategy:          MoveStrategyKickExisting,
		Reason:            runtimeTestBackendPinReason,
	}, defaultUserRuntimeOverridePolicy())
	if err != nil {
		t.Fatalf("SetUserBackendPin returned error: %v", err)
	}

	if !store.setCalled {
		t.Fatal("SetUserBackendPin did not call the state boundary")
	}

	if store.setRequest.BackendIdentifier != routeLookupBackendA ||
		store.setRequest.Protocol != routeLookupProtocol ||
		store.setRequest.BackendPool != routeLookupDefaultPool ||
		store.setRequest.ShardTag != routeLookupShardA ||
		store.setRequest.BackendNode == "" {
		t.Fatalf("derived state request = %#v", store.setRequest)
	}

	if store.setRequest.Key.Tenant != runtimeTestTenant || store.setRequest.Key.AccountKey != runtimeTestUserHash {
		t.Fatalf("normalized user key = %#v", store.setRequest.Key)
	}

	if result.Target.EffectiveShard != routeLookupShardA || result.Pin.EffectiveShard != routeLookupShardA {
		t.Fatalf("target/result shard = %#v %#v", result.Target, result.Pin)
	}
}

// TestUserBackendPinUnknownBackendMapsToRuntimeNotFound verifies REST-ready classification.
func TestUserBackendPinUnknownBackendMapsToRuntimeNotFound(t *testing.T) {
	registry, err := backend.NewStaticRegistry(config.DefaultConfig().Director)
	if err != nil {
		t.Fatalf("NewStaticRegistry returned error: %v", err)
	}

	store := &recordingBackendPinStateStore{}
	service := NewUserBackendPinService(store, registry)

	_, err = service.SetUserBackendPin(context.Background(), SetUserBackendPinRequest{
		Key:               UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
		BackendIdentifier: "missing-backend",
		Strategy:          MoveStrategyNewSessionsOnly,
		Reason:            runtimeTestBackendPinReason,
	}, defaultUserRuntimeOverridePolicy())
	if !IsErrorKind(err, ErrorKindNotFound) {
		t.Fatalf("SetUserBackendPin error = %v, want not_found", err)
	}

	if store.setCalled {
		t.Fatal("unknown backend should not reach the state boundary")
	}
}

// TestUserBackendPinTargetConcreteBackendDerivesOneScopedPin verifies compatibility.
func TestUserBackendPinTargetConcreteBackendDerivesOneScopedPin(t *testing.T) {
	registry, err := backend.NewStaticRegistry(config.DefaultConfig().Director)
	if err != nil {
		t.Fatalf("NewStaticRegistry returned error: %v", err)
	}

	store := &recordingBackendPinStateStore{
		setRecord: backendPinObservationRecord(runtimeTestPinnedStatus, "51", 400),
	}
	service := NewUserBackendPinService(store, registry)

	result, err := service.SetUserBackendPinTarget(context.Background(), SetUserBackendPinTargetRequest{
		Key:               UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
		BackendIdentifier: routeLookupBackendA,
		Strategy:          MoveStrategyNewSessionsOnly,
		Reason:            runtimeTestBackendPinReason,
	}, defaultUserRuntimeOverridePolicy())
	if err != nil {
		t.Fatalf("SetUserBackendPinTarget returned error: %v", err)
	}

	if !store.setCalled || store.setAllCalled {
		t.Fatalf("state calls set=%v setAll=%v, want concrete single-scope set", store.setCalled, store.setAllCalled)
	}
	if len(result.Targets) != 1 || result.Targets[0].BackendIdentifier != routeLookupBackendA {
		t.Fatalf("targets = %#v, want one concrete backend target", result.Targets)
	}
	if result.Audit.Fields[auditFieldScopeCount] != "1" {
		t.Fatalf("audit fields = %#v, want scope_count=1", result.Audit.Fields)
	}
}

// TestUserBackendPinTargetBackendNodeResolvesConfiguredScopes verifies all-protocol resolution.
func TestUserBackendPinTargetBackendNodeResolvesConfiguredScopes(t *testing.T) {
	cfg := config.DefaultConfig()
	registry, err := backend.NewStaticRegistry(cfg.Director)
	if err != nil {
		t.Fatalf("NewStaticRegistry returned error: %v", err)
	}

	store := &recordingBackendPinStateStore{setRecordsFromRequest: true}
	service := NewUserBackendPinService(
		store,
		registry,
		WithUserBackendPinRequiredScopes(runtimeBackendPinRequiredScopes(t, cfg.Director)),
	)

	result, err := service.SetUserBackendPinTarget(context.Background(), SetUserBackendPinTargetRequest{
		Key:         UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
		BackendNode: runtimeTestBackendNodeA,
		Strategy:    MoveStrategyKickExisting,
		Reason:      runtimeTestBackendPinReason,
	}, defaultUserRuntimeOverridePolicy())
	if err != nil {
		t.Fatalf("SetUserBackendPinTarget returned error: %v", err)
	}

	if !store.setAllCalled || store.setCalled {
		t.Fatalf("state calls set=%v setAll=%v, want one atomic multi-scope set", store.setCalled, store.setAllCalled)
	}
	if got, want := backendPinSetScopeNames(store.setRequests.Pins), []string{
		"imap/imap-default/mailstore-a-imap",
		"lmtp/lmtp-default/mailstore-a-lmtp",
		"pop3/pop3-default/mailstore-a-pop3",
		"sieve/sieve-default/mailstore-a-sieve",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("resolved scopes = %#v, want %#v", got, want)
	}
	if len(result.Targets) != 4 || result.Audit.Fields[auditFieldScopeCount] != "4" ||
		result.Audit.Fields[auditFieldBackendNode] != runtimeTestBackendNodeA {
		t.Fatalf("result/audit = %#v %#v, want four scoped node pins", result.Targets, result.Audit.Fields)
	}
}

// TestUserBackendPinTargetBackendNodeScopedFilterResolvesOnePin verifies scoped node pins.
func TestUserBackendPinTargetBackendNodeScopedFilterResolvesOnePin(t *testing.T) {
	cfg := config.DefaultConfig()
	registry, err := backend.NewStaticRegistry(cfg.Director)
	if err != nil {
		t.Fatalf("NewStaticRegistry returned error: %v", err)
	}

	store := &recordingBackendPinStateStore{setRecordsFromRequest: true}
	service := NewUserBackendPinService(
		store,
		registry,
		WithUserBackendPinRequiredScopes(runtimeBackendPinRequiredScopes(t, cfg.Director)),
	)

	_, err = service.SetUserBackendPinTarget(context.Background(), SetUserBackendPinTargetRequest{
		Key:         UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
		BackendNode: runtimeTestBackendNodeA,
		Protocol:    routeLookupProtocolSieve,
		BackendPool: routeLookupPoolSieve,
		Strategy:    MoveStrategyNewSessionsOnly,
		Reason:      runtimeTestBackendPinReason,
	}, defaultUserRuntimeOverridePolicy())
	if err != nil {
		t.Fatalf("SetUserBackendPinTarget returned error: %v", err)
	}

	if got, want := backendPinSetScopeNames(store.setRequests.Pins), []string{
		"sieve/sieve-default/mailstore-a-sieve",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("resolved scopes = %#v, want %#v", got, want)
	}
}

// TestUserBackendPinTargetBackendNodeRejectsUnknownNode verifies missing nodes classify as absent.
func TestUserBackendPinTargetBackendNodeRejectsUnknownNode(t *testing.T) {
	cfg := config.DefaultConfig()
	registry, err := backend.NewStaticRegistry(cfg.Director)
	if err != nil {
		t.Fatalf("NewStaticRegistry returned error: %v", err)
	}

	store := &recordingBackendPinStateStore{}
	service := NewUserBackendPinService(
		store,
		registry,
		WithUserBackendPinRequiredScopes(runtimeBackendPinRequiredScopes(t, cfg.Director)),
	)

	_, err = service.SetUserBackendPinTarget(context.Background(), SetUserBackendPinTargetRequest{
		Key:         UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
		BackendNode: "missing-node",
		Strategy:    MoveStrategyNewSessionsOnly,
		Reason:      runtimeTestBackendPinReason,
	}, defaultUserRuntimeOverridePolicy())
	if !IsErrorKind(err, ErrorKindNotFound) {
		t.Fatalf("SetUserBackendPinTarget error = %v, want not_found", err)
	}

	assertNoBackendPinMutation(t, store)
}

// TestUserBackendPinTargetBackendNodeRejectsDuplicateScope avoids partial writes.
func TestUserBackendPinTargetBackendNodeRejectsDuplicateScope(t *testing.T) {
	store := &recordingBackendPinStateStore{}
	service := NewUserBackendPinService(
		store,
		fakeBackendRegistry{backends: []backend.Backend{
			fakeBackendPinBackend("node-a-imap-1", "imap", "imap-default", "shard-a", "node-a"),
			fakeBackendPinBackend("node-a-imap-2", "imap", "imap-default", "shard-a", "node-a"),
		}},
		WithUserBackendPinRequiredScopes([]UserBackendPinScope{{Protocol: "imap", BackendPool: "imap-default"}}),
	)

	_, err := service.SetUserBackendPinTarget(context.Background(), SetUserBackendPinTargetRequest{
		Key:         UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
		BackendNode: "node-a",
		Strategy:    MoveStrategyNewSessionsOnly,
		Reason:      runtimeTestBackendPinReason,
	}, defaultUserRuntimeOverridePolicy())
	if !IsErrorKind(err, ErrorKindConflict) {
		t.Fatalf("SetUserBackendPinTarget error = %v, want conflict", err)
	}

	assertNoBackendPinMutation(t, store)
}

// TestUserBackendPinTargetBackendNodeRejectsMissingRequiredScope avoids partial writes.
func TestUserBackendPinTargetBackendNodeRejectsMissingRequiredScope(t *testing.T) {
	cfg := config.DefaultConfig()
	store := &recordingBackendPinStateStore{}
	service := NewUserBackendPinService(
		store,
		fakeBackendRegistry{backends: []backend.Backend{
			fakeBackendPinBackend("mailstore-a-imap", "imap", "imap-default", routeLookupShardA, runtimeTestBackendNodeA),
			fakeBackendPinBackend("mailstore-a-lmtp", "lmtp", "lmtp-default", routeLookupShardA, runtimeTestBackendNodeA),
			fakeBackendPinBackend("mailstore-a-sieve", "sieve", "sieve-default", routeLookupShardA, runtimeTestBackendNodeA),
		}},
		WithUserBackendPinRequiredScopes(runtimeBackendPinRequiredScopes(t, cfg.Director)),
	)

	_, err := service.SetUserBackendPinTarget(context.Background(), SetUserBackendPinTargetRequest{
		Key:         UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
		BackendNode: runtimeTestBackendNodeA,
		Strategy:    MoveStrategyNewSessionsOnly,
		Reason:      runtimeTestBackendPinReason,
	}, defaultUserRuntimeOverridePolicy())
	if !IsErrorKind(err, ErrorKindConflict) {
		t.Fatalf("SetUserBackendPinTarget error = %v, want conflict", err)
	}

	assertNoBackendPinMutation(t, store)
}

// TestUserBackendPinTargetBackendNodeRejectsCrossShardData avoids unsafe node pins.
func TestUserBackendPinTargetBackendNodeRejectsCrossShardData(t *testing.T) {
	store := &recordingBackendPinStateStore{}
	service := NewUserBackendPinService(
		store,
		fakeBackendRegistry{backends: []backend.Backend{
			fakeBackendPinBackend("node-a-imap", "imap", "imap-default", "shard-a", "node-a"),
			fakeBackendPinBackend("node-a-sieve", "sieve", "sieve-default", "shard-b", "node-a"),
		}},
		WithUserBackendPinRequiredScopes([]UserBackendPinScope{
			{Protocol: "imap", BackendPool: "imap-default"},
			{Protocol: "sieve", BackendPool: "sieve-default"},
		}),
	)

	_, err := service.SetUserBackendPinTarget(context.Background(), SetUserBackendPinTargetRequest{
		Key:         UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
		BackendNode: "node-a",
		Strategy:    MoveStrategyNewSessionsOnly,
		Reason:      runtimeTestBackendPinReason,
	}, defaultUserRuntimeOverridePolicy())
	if !IsErrorKind(err, ErrorKindConflict) {
		t.Fatalf("SetUserBackendPinTarget error = %v, want conflict", err)
	}

	assertNoBackendPinMutation(t, store)
}

// TestUserBackendPinTargetBackendNodeRejectsInvalidRegistryData fails closed before state.
func TestUserBackendPinTargetBackendNodeRejectsInvalidRegistryData(t *testing.T) {
	store := &recordingBackendPinStateStore{}
	service := NewUserBackendPinService(
		store,
		fakeBackendRegistry{backends: []backend.Backend{{
			Identifier:  "bad-node-imap",
			Protocol:    "imap",
			BackendPool: "imap-default",
			BackendNode: "node-a",
		}}},
		WithUserBackendPinRequiredScopes([]UserBackendPinScope{{Protocol: "imap", BackendPool: "imap-default"}}),
	)

	_, err := service.SetUserBackendPinTarget(context.Background(), SetUserBackendPinTargetRequest{
		Key:         UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
		BackendNode: "node-a",
		Strategy:    MoveStrategyNewSessionsOnly,
		Reason:      runtimeTestBackendPinReason,
	}, defaultUserRuntimeOverridePolicy())
	if !IsErrorKind(err, ErrorKindUnavailable) {
		t.Fatalf("SetUserBackendPinTarget error = %v, want unavailable", err)
	}

	assertNoBackendPinMutation(t, store)
}

// TestUserBackendPinTargetBackendNodeRejectsAmbiguousProtocolFilter requires pool disambiguation.
func TestUserBackendPinTargetBackendNodeRejectsAmbiguousProtocolFilter(t *testing.T) {
	store := &recordingBackendPinStateStore{}
	service := NewUserBackendPinService(
		store,
		fakeBackendRegistry{},
		WithUserBackendPinRequiredScopes([]UserBackendPinScope{
			{Protocol: "imap", BackendPool: "imap-default"},
			{Protocol: "imap", BackendPool: "imap-blue"},
		}),
	)

	_, err := service.SetUserBackendPinTarget(context.Background(), SetUserBackendPinTargetRequest{
		Key:         UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
		BackendNode: "node-a",
		Protocol:    "imap",
		Strategy:    MoveStrategyNewSessionsOnly,
		Reason:      runtimeTestBackendPinReason,
	}, defaultUserRuntimeOverridePolicy())
	if !IsErrorKind(err, ErrorKindInvalidRequest) {
		t.Fatalf("SetUserBackendPinTarget error = %v, want invalid_request", err)
	}

	assertNoBackendPinMutation(t, store)
}

// TestUserBackendPinClearWithoutProtocolRemovesEveryScopedPin verifies explicit all-clear.
func TestUserBackendPinClearWithoutProtocolRemovesEveryScopedPin(t *testing.T) {
	store := &recordingBackendPinStateStore{
		clearRecords: state.UserBackendPinsRecord{
			Status:     runtimeObservationReasonCleared,
			Generation: "63",
			ServerTime: time.Unix(500, 0),
		},
	}
	service := NewUserBackendPinService(store, nil)

	_, err := service.ClearUserBackendPins(context.Background(), ClearUserBackendPinsRequest{
		Key:    UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
		Reason: runtimeTestBackendPinReason,
	})
	if err != nil {
		t.Fatalf("ClearUserBackendPins returned error: %v", err)
	}

	if !store.clearAllCalled || store.clearCalled {
		t.Fatalf("clear calls scoped=%v all=%v, want all-scope clear", store.clearCalled, store.clearAllCalled)
	}
}

// TestUserBackendPinClearWithProtocolAndPoolRemovesOnlyScope verifies scoped clear.
func TestUserBackendPinClearWithProtocolAndPoolRemovesOnlyScope(t *testing.T) {
	store := &recordingBackendPinStateStore{
		clearRecord: backendPinObservationRecord(runtimeObservationReasonCleared, "64", 501),
	}
	service := NewUserBackendPinService(store, nil)

	_, err := service.ClearUserBackendPin(context.Background(), ClearUserBackendPinRequest{
		Key:         UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
		Protocol:    routeLookupProtocolSieve,
		BackendPool: routeLookupPoolSieve,
		Reason:      runtimeTestBackendPinReason,
	})
	if err != nil {
		t.Fatalf("ClearUserBackendPin returned error: %v", err)
	}

	if !store.clearCalled || store.clearAllCalled {
		t.Fatalf("clear calls scoped=%v all=%v, want scoped clear", store.clearCalled, store.clearAllCalled)
	}
	if store.clearRequest.Protocol != routeLookupProtocolSieve || store.clearRequest.BackendPool != routeLookupPoolSieve {
		t.Fatalf("clear request = %#v, want Sieve scope", store.clearRequest)
	}
}

// TestUserBackendPinTargetKickExistingUsesOneControlledMutation verifies one generation boundary.
func TestUserBackendPinTargetKickExistingUsesOneControlledMutation(t *testing.T) {
	cfg := config.DefaultConfig()
	registry, err := backend.NewStaticRegistry(cfg.Director)
	if err != nil {
		t.Fatalf("NewStaticRegistry returned error: %v", err)
	}

	store := &recordingBackendPinStateStore{setRecordsFromRequest: true}
	service := NewUserBackendPinService(
		store,
		registry,
		WithUserBackendPinRequiredScopes(runtimeBackendPinRequiredScopes(t, cfg.Director)),
	)

	result, err := service.SetUserBackendPinTarget(context.Background(), SetUserBackendPinTargetRequest{
		Key:         UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
		BackendNode: runtimeTestBackendNodeA,
		Strategy:    MoveStrategyKickExisting,
		Reason:      runtimeTestBackendPinReason,
	}, defaultUserRuntimeOverridePolicy())
	if err != nil {
		t.Fatalf("SetUserBackendPinTarget returned error: %v", err)
	}

	if !store.setAllCalled || store.setRequests.Strategy != string(MoveStrategyKickExisting) ||
		result.Audit.Generation != "multi-1" {
		t.Fatalf("mutation request/audit = %#v %#v, want one controlled kick_existing set", store.setRequests, result.Audit)
	}
}

// TestUserBackendPinTargetNonKickStrategiesDoNotCloseLocalSessions preserves state ownership.
func TestUserBackendPinTargetNonKickStrategiesDoNotCloseLocalSessions(t *testing.T) {
	cfg := config.DefaultConfig()
	registry, err := backend.NewStaticRegistry(cfg.Director)
	if err != nil {
		t.Fatalf("NewStaticRegistry returned error: %v", err)
	}

	local := NewLocalSessionRegistry()
	handle := &recordingLocalHandle{}
	registerTestLocalSession(t, local, LocalSessionInfo{
		SessionID:         runtimeTestSessionA,
		Tenant:            runtimeTestTenant,
		UserHash:          runtimeTestUserHash,
		BackendIdentifier: routeLookupBackendA,
	}, handle)

	for _, strategy := range []MoveStrategy{MoveStrategyNewSessionsOnly, MoveStrategyDrainExisting} {
		t.Run(string(strategy), func(t *testing.T) {
			store := &recordingBackendPinStateStore{setRecordsFromRequest: true}
			service := NewUserBackendPinService(
				store,
				registry,
				WithUserBackendPinRequiredScopes(runtimeBackendPinRequiredScopes(t, cfg.Director)),
			)

			_, err := service.SetUserBackendPinTarget(context.Background(), SetUserBackendPinTargetRequest{
				Key:         UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
				BackendNode: runtimeTestBackendNodeA,
				Protocol:    routeLookupProtocol,
				BackendPool: routeLookupDefaultPool,
				Strategy:    strategy,
				Reason:      runtimeTestBackendPinReason,
			}, defaultUserRuntimeOverridePolicy())
			if err != nil {
				t.Fatalf("SetUserBackendPinTarget returned error: %v", err)
			}

			if handle.closed != 0 {
				t.Fatalf("local session closed = %d, want 0", handle.closed)
			}
		})
	}
}

// TestUserBackendPinAuditMetadataIsBounded verifies pin audit carries safe target facts.
func TestUserBackendPinAuditMetadataIsBounded(t *testing.T) {
	registry, err := backend.NewStaticRegistry(config.DefaultConfig().Director)
	if err != nil {
		t.Fatalf("NewStaticRegistry returned error: %v", err)
	}

	store := &recordingBackendPinStateStore{
		setRecord: state.UserBackendPinRecord{
			Status:             runtimeTestPinnedStatus,
			Generation:         "41",
			ActiveSessionCount: 3,
			ServerTime:         time.Unix(200, 0),
		},
	}
	service := NewUserBackendPinService(store, registry)
	actor := Actor{ID: "operator-a", AuthMethod: "mtls", Authenticated: true}

	result, err := service.SetUserBackendPin(context.Background(), SetUserBackendPinRequest{
		Key:               UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
		BackendIdentifier: routeLookupBackendA,
		Strategy:          MoveStrategyKickExisting,
		Reason:            runtimeTestBackendPinReason,
		Actor:             actor,
	}, defaultUserRuntimeOverridePolicy())
	if err != nil {
		t.Fatalf("SetUserBackendPin returned error: %v", err)
	}

	assertBackendPinAuditBase(t, result.Audit, actor)
	assertBackendPinAuditFields(t, result.Audit.SafeFields())
}

// TestUserBackendPinOperationsRecordBoundedObservability verifies pin mutations emit safe events.
func TestUserBackendPinOperationsRecordBoundedObservability(t *testing.T) {
	service, recorder := newBackendPinObservationService(t)

	_, err := service.SetUserBackendPin(context.Background(), SetUserBackendPinRequest{
		Key:               UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
		BackendIdentifier: routeLookupBackendA,
		Strategy:          MoveStrategyKickExisting,
		Reason:            runtimeTestBackendPinReason,
	}, defaultUserRuntimeOverridePolicy())
	if err != nil {
		t.Fatalf("SetUserBackendPin returned error: %v", err)
	}

	_, err = service.ClearUserBackendPin(context.Background(), ClearUserBackendPinRequest{
		Key:    UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
		Reason: runtimeTestBackendPinReason,
	})
	if err != nil {
		t.Fatalf("ClearUserBackendPin returned error: %v", err)
	}

	events := recorder.eventsByName(observability.EventUserBackendPin)
	if len(events) != 2 {
		t.Fatalf("backend-pin events = %#v, want set and clear", recorder.events)
	}

	assertBackendPinObservation(t, events[0], operationUserBackendPinSet, runtimeObservationReasonBackendPinSet)
	assertBackendPinObservation(t, events[1], operationUserBackendPinClear, runtimeObservationReasonBackendPinClear)

	rendered := strings.Join(eventValues(events), "\n")
	if strings.Contains(rendered, runtimeTestBackendPinReason) || strings.Contains(rendered, runtimeTestUserHash) {
		t.Fatalf("backend-pin observation leaked reason or user hash: %s", rendered)
	}
}

// newBackendPinObservationService builds a backend-pin service with recording dependencies.
func newBackendPinObservationService(t *testing.T) (*UserBackendPinService, *recordingRuntimeObservation) {
	t.Helper()

	registry, err := backend.NewStaticRegistry(config.DefaultConfig().Director)
	if err != nil {
		t.Fatalf("NewStaticRegistry returned error: %v", err)
	}

	store := &recordingBackendPinStateStore{
		setRecord:   backendPinObservationRecord(runtimeTestPinnedStatus, "43", 300),
		clearRecord: backendPinObservationRecord(runtimeObservationReasonCleared, "44", 301),
	}
	recorder := &recordingRuntimeObservation{}

	return NewUserBackendPinService(store, registry, WithObservabilityRecorder(recorder)), recorder
}

// backendPinObservationRecord returns a bounded fixture for observability assertions.
func backendPinObservationRecord(status string, generation string, unixSecond int64) state.UserBackendPinRecord {
	return state.UserBackendPinRecord{
		Status:             status,
		Generation:         generation,
		BackendIdentifier:  routeLookupBackendA,
		Protocol:           routeLookupProtocol,
		BackendPool:        routeLookupDefaultPool,
		ShardTag:           routeLookupShardA,
		BackendNode:        runtimeTestBackendNodeA,
		Strategy:           string(MoveStrategyKickExisting),
		ActiveSessionCount: 1,
		ServerTime:         time.Unix(unixSecond, 0),
	}
}

// TestUserBackendPinClearAuditMetadataIncludesActor verifies clear audits carry operator context.
func TestUserBackendPinClearAuditMetadataIncludesActor(t *testing.T) {
	store := &recordingBackendPinStateStore{
		clearRecord: state.UserBackendPinRecord{
			Status:            runtimeObservationReasonCleared,
			Key:               state.AffinityKey{Tenant: runtimeTestTenant, AccountKey: runtimeTestUserHash},
			BackendIdentifier: routeLookupBackendA,
			Protocol:          routeLookupProtocol,
			BackendPool:       routeLookupDefaultPool,
			ShardTag:          routeLookupShardA,
			BackendNode:       runtimeTestBackendNodeA,
			Strategy:          string(MoveStrategyDrainExisting),
			Generation:        "42",
			ServerTime:        time.Unix(300, 0),
		},
	}
	service := NewUserBackendPinService(store, nil)
	actor := Actor{ID: "operator-b", Authenticated: true}

	result, err := service.ClearUserBackendPin(context.Background(), ClearUserBackendPinRequest{
		Key:    UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
		Reason: "commissioning complete",
		Actor:  actor,
	})
	if err != nil {
		t.Fatalf("ClearUserBackendPin returned error: %v", err)
	}

	if result.Audit.Operation != AuditOperationUserBackendPinClear ||
		result.Audit.Actor.ID != actor.ID ||
		result.Audit.Generation != "42" ||
		result.Audit.BackendIdentifier != routeLookupBackendA {
		t.Fatalf("clear audit metadata = %#v", result.Audit)
	}
}

// TestExistingUserMoveValidationRemainsShardOnly verifies move stays separate from backend pinning.
func TestExistingUserMoveValidationRemainsShardOnly(t *testing.T) {
	userKey := UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash}
	if err := (MoveUserRequest{
		Key:         userKey,
		TargetShard: routeLookupShardA,
		Strategy:    MoveStrategyNewSessionsOnly,
		Reason:      runtimeTestMoveReason,
	}).Validate(); err != nil {
		t.Fatalf("MoveUserRequest validation changed: %v", err)
	}

	if err := (MoveUserRequest{
		Key:      userKey,
		Strategy: MoveStrategyNewSessionsOnly,
		Reason:   runtimeTestMoveReason,
	}).Validate(); !IsErrorKind(err, ErrorKindInvalidRequest) {
		t.Fatalf("MoveUserRequest without target shard error = %v, want invalid_request", err)
	}

	moveType := reflect.TypeFor[MoveUserRequest]()
	for _, field := range []string{runtimeTestFieldToBackend, runtimeTestFieldToBackendID, runtimeTestFieldBackendID} {
		if _, ok := moveType.FieldByName(field); ok {
			t.Fatalf("MoveUserRequest gained backend field %s", field)
		}
	}
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
	}, defaultUserRuntimeOverridePolicy()); err != nil {
		t.Fatalf("KickUser returned error: %v", err)
	}

	if first.closed != 1 || second.closed != 1 {
		t.Fatalf("user sessions closed = %d/%d, want both closed once", first.closed, second.closed)
	}

	if other.closed != 0 {
		t.Fatalf("unrelated session closed = %d, want 0", other.closed)
	}
}

// TestUserHoldSetDoesNotCloseAttachedLocalSession verifies holds are not retroactive kicks.
func TestUserHoldSetDoesNotCloseAttachedLocalSession(t *testing.T) {
	registry := NewLocalSessionRegistry()
	userKey := UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash}
	active := &recordingLocalHandle{}

	registerTestLocalSession(t, registry, LocalSessionInfo{
		SessionID:         runtimeTestSessionA,
		ListenerName:      routeLookupListener,
		Tenant:            userKey.Tenant,
		UserHash:          userKey.UserHash,
		BackendIdentifier: runtimeTestBackendIdentifier,
	}, active)

	service := newTestUserHoldService(t, newTestUserHoldStore(false), UserHoldServiceConfig{
		Enabled:                true,
		MaxDuration:            time.Minute,
		MaxWait:                time.Second,
		PollInterval:           10 * time.Millisecond,
		MaxLocalWaiters:        2,
		MaxLocalWaitersPerUser: 1,
	})

	if _, err := service.SetUserHold(context.Background(), SetUserHoldRequest{
		Key:      userKey,
		Duration: time.Minute,
		Reason:   runtimeTestHoldReason,
	}); err != nil {
		t.Fatalf("SetUserHold returned error: %v", err)
	}

	if active.closed != 0 {
		t.Fatalf("attached local session closed after hold set = %d, want 0", active.closed)
	}

	closed, err := registry.CloseUser(context.Background(), userKey, LocalSessionControl{Action: "test_cleanup"})
	if err != nil {
		t.Fatalf("CloseUser returned error: %v", err)
	}

	if closed != 1 || active.closed != 1 {
		t.Fatalf("explicit close after hold set = count:%d handle:%d, want one", closed, active.closed)
	}
}

// TestUserHoldOperationsRecordBoundedObservability verifies hold mutations emit safe events.
func TestUserHoldOperationsRecordBoundedObservability(t *testing.T) {
	recorder := &recordingRuntimeObservation{}
	service := newObservedTestUserHoldService(t, newTestUserHoldStore(false), UserHoldServiceConfig{
		Enabled:                true,
		MaxDuration:            time.Minute,
		MaxWait:                time.Second,
		PollInterval:           10 * time.Millisecond,
		MaxLocalWaiters:        2,
		MaxLocalWaitersPerUser: 1,
	}, recorder)

	_, err := service.SetUserHold(context.Background(), SetUserHoldRequest{
		Key:      UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
		Duration: time.Minute,
		Reason:   runtimeTestHoldReason,
	})
	if err != nil {
		t.Fatalf("SetUserHold returned error: %v", err)
	}

	_, err = service.ClearUserHold(context.Background(), ClearUserHoldRequest{
		Key:    UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash},
		Reason: runtimeTestHoldReason,
	})
	if err != nil {
		t.Fatalf("ClearUserHold returned error: %v", err)
	}

	events := recorder.eventsByName(observability.EventUserHold)
	if len(events) != 2 {
		t.Fatalf("user-hold events = %#v, want set and clear", recorder.events)
	}

	assertBackendPinObservation(t, events[0], operationUserHoldSet, runtimeObservationReasonUserHoldSet)
	assertBackendPinObservation(t, events[1], operationUserHoldClear, runtimeObservationReasonUserHoldClear)

	rendered := strings.Join(eventValues(events), "\n")
	if strings.Contains(rendered, runtimeTestHoldReason) || strings.Contains(rendered, runtimeTestUserHash) {
		t.Fatalf("user-hold observation leaked reason or user hash: %s", rendered)
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
			Status:            state.SessionKillStatusMarked,
			SessionID:         runtimeTestSessionA,
			ControlAction:     state.ControlActionKick,
			ControlGeneration: "3",
			ServerTime:        time.Unix(100, 0),
		},
	}, registry)

	result, err := service.KillSession(context.Background(), KillSessionRequest{
		SessionID: runtimeTestSessionA,
		Reason:    "operator killed one session",
	})
	if err != nil {
		t.Fatalf("KillSession returned error: %v", err)
	}

	if result.Outcome != SessionMutationOutcomeMarked ||
		result.State.SessionID != runtimeTestSessionA ||
		result.State.ControlGeneration != "3" ||
		result.ControlAction != SessionMutationControlActionKick ||
		result.Lifecycle != SessionMutationLifecycleLocalOrHeartbeatClose ||
		result.StaleIndexRepaired {
		t.Fatalf("result = %#v, want marked kill outcome with control generation", result)
	}

	if target.closed != 1 {
		t.Fatalf("target session closed = %d, want 1", target.closed)
	}

	if other.closed != 0 {
		t.Fatalf("other session closed = %d, want 0", other.closed)
	}
}

// TestSessionKillMissingDoesNotCloseLocalSession preserves bounded missing semantics.
func TestSessionKillMissingDoesNotCloseLocalSession(t *testing.T) {
	registry := NewLocalSessionRegistry()
	target := &recordingLocalHandle{}

	registerTestLocalSession(t, registry, LocalSessionInfo{SessionID: runtimeTestSessionA}, target)

	service := NewSessionService(&recordingSessionStateStore{
		killRecord: state.SessionKillRecord{
			Status:        state.SessionKillStatusMissing,
			SessionID:     runtimeTestSessionA,
			ServerTime:    time.Unix(100, 0),
			ControlAction: state.ControlActionNone,
		},
	}, registry)

	result, err := service.KillSession(context.Background(), KillSessionRequest{
		SessionID: runtimeTestSessionA,
		Reason:    "operator killed missing session",
	})
	if err != nil {
		t.Fatalf("KillSession returned error: %v", err)
	}

	if target.closed != 0 {
		t.Fatalf("missing session closed local handle %d times, want 0", target.closed)
	}

	if result.Outcome != SessionMutationOutcomeMissing ||
		result.State.Status != SessionStatusExpired ||
		result.ControlAction != SessionMutationControlActionNone ||
		result.Lifecycle != SessionMutationLifecycleAlreadyAbsent ||
		result.StaleIndexRepaired {
		t.Fatalf("result = %#v, want missing outcome without closing", result)
	}
}

// TestSessionKillStaleIndexRepairedCarriesBoundedOutcome preserves repair evidence.
func TestSessionKillStaleIndexRepairedCarriesBoundedOutcome(t *testing.T) {
	registry := NewLocalSessionRegistry()
	target := &recordingLocalHandle{}

	registerTestLocalSession(t, registry, LocalSessionInfo{SessionID: runtimeTestSessionA}, target)

	service := NewSessionService(&recordingSessionStateStore{
		killRecord: state.SessionKillRecord{
			Status:        state.SessionKillStatusStaleIndexRepaired,
			SessionID:     runtimeTestSessionA,
			ServerTime:    time.Unix(100, 0),
			ControlAction: state.ControlActionNone,
		},
	}, registry)

	result, err := service.KillSession(context.Background(), KillSessionRequest{
		SessionID: runtimeTestSessionA,
		Reason:    "operator killed stale session",
	})
	if err != nil {
		t.Fatalf("KillSession returned error: %v", err)
	}

	if target.closed != 0 {
		t.Fatalf("stale session closed local handle %d times, want 0", target.closed)
	}

	if result.Outcome != SessionMutationOutcomeStaleIndexRepaired ||
		result.State.SessionID != runtimeTestSessionA ||
		result.State.Status != SessionStatusExpired ||
		result.ControlAction != SessionMutationControlActionNone ||
		result.Lifecycle != SessionMutationLifecycleStaleLocatorRepaired ||
		!result.StaleIndexRepaired {
		t.Fatalf("result = %#v, want stale-index repair outcome", result)
	}
}

// TestSessionKillAmbiguousStateFailsClosed keeps corrupt state out of normal results.
func TestSessionKillAmbiguousStateFailsClosed(t *testing.T) {
	service := NewSessionService(&recordingSessionStateStore{
		killRecord: state.SessionKillRecord{
			Status:        state.SessionKillStatusAmbiguousState,
			SessionID:     runtimeTestSessionA,
			ServerTime:    time.Unix(100, 0),
			ControlAction: state.ControlActionNone,
		},
	}, nil)

	_, err := service.KillSession(context.Background(), KillSessionRequest{
		SessionID: runtimeTestSessionA,
		Reason:    "operator killed ambiguous session",
	})
	if !IsErrorKind(err, ErrorKindUnavailable) {
		t.Fatalf("KillSession error = %v, want unavailable fail-closed error", err)
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
	}, backend.RuntimeOverridePolicy{Enabled: true, AllowDrain: true}); err != nil {
		t.Fatalf("StartDrain returned error: %v", err)
	}

	if first.closed != 1 || second.closed != 1 {
		t.Fatalf("backend sessions closed = %d/%d, want both closed once", first.closed, second.closed)
	}

	if other.closed != 0 {
		t.Fatalf("unrelated backend session closed = %d, want 0", other.closed)
	}
}

// TestCloseListenerClosesOnlyListenerLocalSessions verifies listener-scoped local acceleration.
func TestCloseListenerClosesOnlyListenerLocalSessions(t *testing.T) {
	registry := NewLocalSessionRegistry()
	first := &recordingLocalHandle{}
	second := &recordingLocalHandle{}
	other := &recordingLocalHandle{}

	registerTestLocalSession(t, registry, LocalSessionInfo{SessionID: runtimeTestSessionA, ListenerName: routeLookupListener}, first)
	registerTestLocalSession(t, registry, LocalSessionInfo{SessionID: runtimeTestSessionB, ListenerName: routeLookupListener}, second)
	registerTestLocalSession(t, registry, LocalSessionInfo{SessionID: runtimeTestSessionC, ListenerName: routeLookupProtocolLMTP}, other)

	closed, err := registry.CloseListener(context.Background(), routeLookupListener, LocalSessionControl{Action: "listener_hard_drain"})
	if err != nil {
		t.Fatalf("CloseListener returned error: %v", err)
	}

	if closed != 2 || first.closed != 1 || second.closed != 1 {
		t.Fatalf("listener sessions closed = count:%d handles:%d/%d, want two", closed, first.closed, second.closed)
	}

	if other.closed != 0 {
		t.Fatalf("unrelated listener session closed = %d, want 0", other.closed)
	}
}

// TestReaperRunOnceReportsRepairCounts verifies lifecycle repair delegates through the service.
func TestReaperRunOnceReportsRepairCounts(t *testing.T) {
	store := &recordingSessionStateStore{
		reapRecord: state.ReapRecord{
			Status:                  "reaped",
			ScannedSessions:         4,
			ExpiredSessions:         2,
			StaleIndexEntries:       3,
			RepairedBackends:        1,
			AggregateMarkersRemoved: 2,
			IdleAffinitiesAdded:     1,
			ServerTime:              time.Unix(100, 0),
		},
	}

	service := NewSessionService(store, nil)

	reaper, err := NewReaper(service, ReaperConfig{Interval: time.Second, Limit: 10, MaxPassDuration: time.Second})
	if err != nil {
		t.Fatalf("NewReaper returned error: %v", err)
	}

	result, err := reaper.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}

	if result.Status != "reaped" ||
		result.ExpiredSessions != 2 ||
		result.RepairedBackends != 1 ||
		result.StaleIndexEntries != 3 ||
		result.AggregateMarkersRemoved != 2 ||
		result.IdleAffinitiesAdded != 1 {
		t.Fatalf("reap result = %#v, want repair counts", result)
	}

	if store.reapRequest.Limit != 10 {
		t.Fatalf("reap limit = %d, want 10", store.reapRequest.Limit)
	}

	if store.reapRequest.MaxPassDuration != time.Second {
		t.Fatalf("reap max pass duration = %s, want 1s", store.reapRequest.MaxPassDuration)
	}
}

// TestReaperRunOnceRespectsMaxPassDuration verifies slow repair stops by context deadline.
func TestReaperRunOnceRespectsMaxPassDuration(t *testing.T) {
	service := NewSessionService(blockingSessionStateStore{}, nil)

	reaper, err := NewReaper(service, ReaperConfig{
		Interval:        time.Second,
		Limit:           10,
		MaxPassDuration: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewReaper returned error: %v", err)
	}

	started := time.Now()

	_, err = reaper.RunOnce(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("RunOnce error = %v, want deadline exceeded", err)
	}

	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("RunOnce elapsed %s, want short deadline", elapsed)
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

// runtimeStructType returns one production struct declaration from this package.
func runtimeStructType(t *testing.T, name string) (*ast.StructType, bool) {
	t.Helper()

	for _, file := range runtimeProductionAST(t) {
		for _, declaration := range file.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if !ok {
				continue
			}

			for _, spec := range general.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if !ok || typeSpec.Name.Name != name {
					continue
				}

				structType, ok := typeSpec.Type.(*ast.StructType)

				return structType, ok
			}
		}
	}

	return nil, false
}

// runtimeStructTypeAny returns the first matching production struct declaration.
func runtimeStructTypeAny(t *testing.T, names ...string) (*ast.StructType, string, bool) {
	t.Helper()

	for _, name := range names {
		structType, ok := runtimeStructType(t, name)
		if ok {
			return structType, name, true
		}
	}

	return nil, "", false
}

// runtimeMethodDeclared reports whether a production receiver method exists.
func runtimeMethodDeclared(t *testing.T, receiverType string, method string) bool {
	t.Helper()

	for _, file := range runtimeProductionAST(t) {
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Recv == nil || function.Name.Name != method {
				continue
			}

			if runtimeReceiverType(function.Recv) == receiverType {
				return true
			}
		}
	}

	return false
}

// assertRuntimeStructFields verifies the named struct exposes expected contract fields.
func assertRuntimeStructFields(t *testing.T, structType *ast.StructType, fields ...string) {
	t.Helper()

	present := make(map[string]struct{}, len(structType.Fields.List))
	for _, field := range structType.Fields.List {
		for _, name := range field.Names {
			present[name.Name] = struct{}{}
		}
	}

	for _, field := range fields {
		if _, ok := present[field]; !ok {
			t.Fatalf("runtime struct missing field %q", field)
		}
	}
}

// runtimeProductionAST parses non-test Go files in the runtime package.
func runtimeProductionAST(t *testing.T) []*ast.File {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read runtime package directory: %v", err)
	}

	files := make([]*ast.File, 0, len(entries))
	fileSet := token.NewFileSet()

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		file, err := parser.ParseFile(fileSet, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}

		files = append(files, file)
	}

	return files
}

// runtimeReceiverType normalizes value and pointer method receiver names.
func runtimeReceiverType(receivers *ast.FieldList) string {
	if receivers == nil || len(receivers.List) == 0 {
		return ""
	}

	switch expr := receivers.List[0].Type.(type) {
	case *ast.Ident:
		return expr.Name
	case *ast.StarExpr:
		if ident, ok := expr.X.(*ast.Ident); ok {
			return ident.Name
		}
	}

	return ""
}

// backendRuntimeRecord returns a valid backend runtime mutation result for tests.
func backendRuntimeRecord() state.BackendRuntimeRecord {
	return state.BackendRuntimeRecord{
		Status:            "updated",
		BackendIdentifier: runtimeTestBackendIdentifier,
		Generation:        "11",
		ServerTime:        time.Unix(100, 0),
	}
}

// defaultUserRuntimeOverridePolicy returns the repository default user mutation policy.
func defaultUserRuntimeOverridePolicy() UserRuntimeOverridePolicy {
	return NewUserRuntimeOverridePolicy(config.DefaultConfig().Director.RuntimeOverrides)
}

// assertBackendPinAuditBase checks core backend-pin audit fields.
func assertBackendPinAuditBase(t *testing.T, audit AuditMetadata, actor Actor) {
	t.Helper()

	if audit.Operation != AuditOperationUserBackendPinSet ||
		audit.Reason != runtimeTestBackendPinReason ||
		audit.Actor.ID != actor.ID ||
		audit.Generation != "41" {
		t.Fatalf("audit metadata = %#v", audit)
	}

	if audit.BackendIdentifier != routeLookupBackendA {
		t.Fatalf("audit backend identifier = %q", audit.BackendIdentifier)
	}
}

// assertBackendPinAuditFields checks bounded backend facts without secrets.
func assertBackendPinAuditFields(t *testing.T, fields map[string]string) {
	t.Helper()

	if fields[auditFieldBackendIdentifier] != routeLookupBackendA ||
		fields[auditFieldBackendNode] != runtimeTestBackendNodeA ||
		fields[auditFieldProtocol] != routeLookupProtocol ||
		fields[auditFieldBackendPool] != routeLookupDefaultPool ||
		fields[auditFieldEffectiveShard] != routeLookupShardA ||
		fields[auditFieldStrategy] != string(MoveStrategyKickExisting) {
		t.Fatalf("audit fields = %#v", fields)
	}

	for _, forbidden := range []string{"address", "password", "token", "private_key"} {
		if _, ok := fields[forbidden]; ok {
			t.Fatalf("audit fields included forbidden backend metadata %q: %#v", forbidden, fields)
		}
	}
}

// runtimeBackendPinRequiredScopes converts config scopes into runtime scope fixtures.
func runtimeBackendPinRequiredScopes(t *testing.T, director config.DirectorConfig) []UserBackendPinScope {
	t.Helper()

	scopes, err := director.BackendPinRequiredScopes()
	if err != nil {
		t.Fatalf("BackendPinRequiredScopes returned error: %v", err)
	}

	return runtimeBackendPinScopes(scopes)
}

// runtimeBackendPinScopes adapts config scope records for service options.
func runtimeBackendPinScopes(scopes []config.BackendPinScope) []UserBackendPinScope {
	converted := make([]UserBackendPinScope, 0, len(scopes))
	for _, scope := range scopes {
		converted = append(converted, UserBackendPinScope{Protocol: scope.Protocol, BackendPool: scope.BackendPool})
	}

	return converted
}

// backendPinSetScopeNames renders multi-scope set requests for deterministic assertions.
func backendPinSetScopeNames(pins []state.UserBackendPinScope) []string {
	names := make([]string, 0, len(pins))
	for _, pin := range pins {
		names = append(names, pin.Protocol+"/"+pin.BackendPool+"/"+pin.BackendIdentifier)
	}
	sort.Strings(names)

	return names
}

// assertNoBackendPinMutation verifies validation failed before state mutation.
func assertNoBackendPinMutation(t *testing.T, store *recordingBackendPinStateStore) {
	t.Helper()

	if store.setCalled || store.setAllCalled || store.clearCalled || store.clearAllCalled {
		t.Fatalf("unexpected backend-pin mutation calls: %#v", store)
	}
}

// assertNoUserOrBackendPinMutation verifies validation failed before state mutation.
func assertNoUserOrBackendPinMutation(t *testing.T, userStore *recordingUserStateStore, pinStore *recordingBackendPinStateStore) {
	t.Helper()

	if userStore.moveCalled || userStore.kickCalled || userStore.clearCalled {
		t.Fatalf("unexpected user mutation calls: %#v", userStore)
	}

	assertNoBackendPinMutation(t, pinStore)
}

// fakeBackendPinBackend creates registry identity records for resolution tests.
func fakeBackendPinBackend(identifier string, protocol string, pool string, shard string, node string) backend.Backend {
	return backend.Backend{
		Identifier:  identifier,
		Protocol:    protocol,
		BackendPool: pool,
		ShardTag:    shard,
		BackendNode: node,
	}
}

// backendPinRecordsFromSetRequest mirrors state output for aggregate runtime tests.
func backendPinRecordsFromSetRequest(request state.UserBackendPinsSetRequest) state.UserBackendPinsRecord {
	pins := make([]state.UserBackendPinRecord, 0, len(request.Pins))
	for _, pin := range request.Pins {
		pins = append(pins, state.UserBackendPinRecord{
			Present:           true,
			Key:               request.Key,
			BackendIdentifier: pin.BackendIdentifier,
			Protocol:          pin.Protocol,
			BackendPool:       pin.BackendPool,
			ShardTag:          pin.ShardTag,
			BackendNode:       pin.BackendNode,
			Strategy:          request.Strategy,
			Generation:        "multi-1",
			ServerTime:        time.Unix(410, 0),
		})
	}

	return state.UserBackendPinsRecord{
		Present:    len(pins) > 0,
		Key:        request.Key,
		Pins:       pins,
		Status:     runtimeTestPinnedStatus,
		Generation: "multi-1",
		ServerTime: time.Unix(410, 0),
	}
}

type fakeBackendRegistry struct {
	backends []backend.Backend
}

// AllBackends returns configured fake backend entries.
func (r fakeBackendRegistry) AllBackends(context.Context) ([]backend.Backend, error) {
	return append([]backend.Backend(nil), r.backends...), nil
}

// BackendsForShard is unused by backend-pin resolution tests.
func (r fakeBackendRegistry) BackendsForShard(context.Context, backend.RegistryRequest) ([]backend.Backend, error) {
	return nil, errors.New("fake registry shard lookup unused")
}

// Lookup is unused by backend-node resolution tests.
func (r fakeBackendRegistry) Lookup(context.Context, string) (backend.Backend, error) {
	return backend.Backend{}, errors.New("fake registry lookup unused")
}

// LookupInBackendNode is unused by all-protocol resolution tests.
func (r fakeBackendRegistry) LookupInBackendNode(context.Context, backend.NodeLookupRequest) (backend.Backend, error) {
	return backend.Backend{}, errors.New("fake registry node lookup unused")
}

// Pool is unused by backend-pin resolution tests.
func (r fakeBackendRegistry) Pool(context.Context, string) (backend.Pool, error) {
	return backend.Pool{}, errors.New("fake registry pool lookup unused")
}

// assertBackendPinObservation verifies operation and bounded reason labels.
func assertBackendPinObservation(t *testing.T, event observability.Event, operation string, reason string) {
	t.Helper()

	if event.MetricLabels["operation"] != operation {
		t.Fatalf("operation = %q, want %q", event.MetricLabels["operation"], operation)
	}

	if event.MetricLabels["reason_class"] != reason {
		t.Fatalf("reason class = %q, want %q", event.MetricLabels["reason_class"], reason)
	}

	if event.MetricLabels["result"] != runtimeObservationResultOK {
		t.Fatalf("result = %q, want ok", event.MetricLabels["result"])
	}
}

// eventValues returns log and label values for leakage checks.
func eventValues(events []observability.Event) []string {
	values := make([]string, 0)

	for _, event := range events {
		for _, value := range event.LogFields {
			values = append(values, value)
		}

		for _, value := range event.MetricLabels {
			values = append(values, value)
		}
	}

	return values
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
	moveCalled  bool
	kickCalled  bool
	clearCalled bool
}

// MoveUser returns the configured user move record.
func (s *recordingUserStateStore) MoveUser(context.Context, state.UserMoveRequest) (state.UserRuntimeRecord, error) {
	s.moveCalled = true

	return s.moveRecord, nil
}

// KickUser returns the configured user kick record.
func (s *recordingUserStateStore) KickUser(context.Context, state.UserKickRequest) (state.UserRuntimeRecord, error) {
	s.kickCalled = true

	return s.kickRecord, nil
}

// ClearUserAffinity returns the configured user clear record.
func (s *recordingUserStateStore) ClearUserAffinity(
	context.Context,
	state.UserClearRequest,
) (state.UserRuntimeRecord, error) {
	s.clearCalled = true

	return s.clearRecord, nil
}

type recordingBackendPinStateStore struct {
	setRecord             state.UserBackendPinRecord
	setRecords            state.UserBackendPinsRecord
	getRecord             state.UserBackendPinRecord
	listRecords           state.UserBackendPinsRecord
	clearRecord           state.UserBackendPinRecord
	clearRecords          state.UserBackendPinsRecord
	setRequest            state.UserBackendPinSetRequest
	setRequests           state.UserBackendPinsSetRequest
	getRequest            state.UserBackendPinGetRequest
	listRequest           state.UserBackendPinsListRequest
	clearRequest          state.UserBackendPinClearRequest
	clearAll              state.UserBackendPinsClearRequest
	setCalled             bool
	setAllCalled          bool
	setRecordsFromRequest bool
	getCalled             bool
	listCalled            bool
	clearCalled           bool
	clearAllCalled        bool
}

// SetUserBackendPin records and returns the configured backend-pin mutation.
func (s *recordingBackendPinStateStore) SetUserBackendPin(
	_ context.Context,
	request state.UserBackendPinSetRequest,
) (state.UserBackendPinRecord, error) {
	s.setCalled = true
	s.setRequest = request

	return s.setRecord, nil
}

// SetUserBackendPins records and returns the configured backend-pin set mutation.
func (s *recordingBackendPinStateStore) SetUserBackendPins(
	_ context.Context,
	request state.UserBackendPinsSetRequest,
) (state.UserBackendPinsRecord, error) {
	s.setAllCalled = true
	s.setRequests = request
	if s.setRecordsFromRequest {
		return backendPinRecordsFromSetRequest(request), nil
	}

	return s.setRecords, nil
}

// GetUserBackendPin records and returns the configured backend-pin read.
func (s *recordingBackendPinStateStore) GetUserBackendPin(
	_ context.Context,
	request state.UserBackendPinGetRequest,
) (state.UserBackendPinRecord, error) {
	s.getCalled = true
	s.getRequest = request

	return s.getRecord, nil
}

// ListUserBackendPins records and returns the configured backend-pin set read.
func (s *recordingBackendPinStateStore) ListUserBackendPins(
	_ context.Context,
	request state.UserBackendPinsListRequest,
) (state.UserBackendPinsRecord, error) {
	s.listCalled = true
	s.listRequest = request

	return s.listRecords, nil
}

// ClearUserBackendPin records and returns the configured backend-pin clear.
func (s *recordingBackendPinStateStore) ClearUserBackendPin(
	_ context.Context,
	request state.UserBackendPinClearRequest,
) (state.UserBackendPinRecord, error) {
	s.clearCalled = true
	s.clearRequest = request

	return s.clearRecord, nil
}

// ClearUserBackendPins records and returns the configured backend-pin all-clear.
func (s *recordingBackendPinStateStore) ClearUserBackendPins(
	_ context.Context,
	request state.UserBackendPinsClearRequest,
) (state.UserBackendPinsRecord, error) {
	s.clearAllCalled = true
	s.clearAll = request

	return s.clearRecords, nil
}

type recordingSessionStateStore struct {
	killRecord  state.SessionKillRecord
	reapRecord  state.ReapRecord
	reapRequest state.ReapRequest
	reapCalls   int
}

type blockingSessionStateStore struct{}

// KillSession returns an empty result because the blocking store is reap-only.
func (blockingSessionStateStore) KillSession(context.Context, state.SessionKillRequest) (state.SessionKillRecord, error) {
	return state.SessionKillRecord{}, nil
}

// ReapSessions blocks until the caller's pass context is cancelled.
func (blockingSessionStateStore) ReapSessions(ctx context.Context, _ state.ReapRequest) (state.ReapRecord, error) {
	<-ctx.Done()

	return state.ReapRecord{}, ctx.Err()
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
	s.reapCalls++
	s.reapRequest = request

	return s.reapRecord, nil
}

type recordingBackendStateStore struct {
	record    state.BackendRuntimeRecord
	mutation  state.BackendRuntimeMutation
	setCalls  int
	clearCall int
}

// SetBackendRuntime returns the configured backend runtime record.
func (s *recordingBackendStateStore) SetBackendRuntime(
	_ context.Context,
	mutation state.BackendRuntimeMutation,
) (state.BackendRuntimeRecord, error) {
	s.setCalls++
	s.mutation = mutation

	return s.record, nil
}

// ClearBackendRuntime returns the configured backend runtime clear record.
func (s *recordingBackendStateStore) ClearBackendRuntime(
	context.Context,
	state.BackendRuntimeClearRequest,
) (state.BackendRuntimeRecord, error) {
	s.clearCall++

	return s.record, nil
}
