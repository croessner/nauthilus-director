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
	"errors"
	"reflect"
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
	})
	if err != nil {
		t.Fatalf("SetUserBackendPin returned error: %v", err)
	}

	if !store.setCalled {
		t.Fatal("SetUserBackendPin did not call the state boundary")
	}

	if store.setRequest.BackendIdentifier != routeLookupBackendA ||
		store.setRequest.Protocol != routeLookupProtocol ||
		store.setRequest.BackendPool != routeLookupDefaultPool ||
		store.setRequest.ShardTag != routeLookupShardA {
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
	})
	if !IsErrorKind(err, ErrorKindNotFound) {
		t.Fatalf("SetUserBackendPin error = %v, want not_found", err)
	}

	if store.setCalled {
		t.Fatal("unknown backend should not reach the state boundary")
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
	})
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
	})
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
			Status:           "reaped",
			ScannedSessions:  4,
			ExpiredSessions:  2,
			RepairedBackends: 1,
			ServerTime:       time.Unix(100, 0),
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

	if result.ExpiredSessions != 2 || result.RepairedBackends != 1 {
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
		t.Fatalf("RunOnce elapsed %s, want prompt deadline", elapsed)
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

type recordingBackendPinStateStore struct {
	setRecord    state.UserBackendPinRecord
	getRecord    state.UserBackendPinRecord
	clearRecord  state.UserBackendPinRecord
	setRequest   state.UserBackendPinSetRequest
	getRequest   state.UserBackendPinGetRequest
	clearRequest state.UserBackendPinClearRequest
	setCalled    bool
	getCalled    bool
	clearCalled  bool
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

// GetUserBackendPin records and returns the configured backend-pin read.
func (s *recordingBackendPinStateStore) GetUserBackendPin(
	_ context.Context,
	request state.UserBackendPinGetRequest,
) (state.UserBackendPinRecord, error) {
	s.getCalled = true
	s.getRequest = request

	return s.getRecord, nil
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

type recordingSessionStateStore struct {
	killRecord  state.SessionKillRecord
	reapRecord  state.ReapRecord
	reapRequest state.ReapRequest
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
