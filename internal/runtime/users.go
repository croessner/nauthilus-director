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
	"maps"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/state"
)

const (
	operationUserAffinityClear   = "user_affinity_clear"
	operationUserBackendPinSet   = "user_backend_pin_set"
	operationUserBackendPinGet   = "user_backend_pin_get"
	operationUserBackendPinClear = "user_backend_pin_clear"
	operationUserHoldSet         = "user_hold_set"
	operationUserHoldGet         = "user_hold_get"
	operationUserHoldClear       = "user_hold_clear"
	operationUserHoldCheck       = "user_hold_check"
	operationUserKick            = "user_kick"
	operationUserMove            = "user_move"
)

// MoveStrategy describes how a user move treats existing sessions.
type MoveStrategy string

const (
	// MoveStrategyDrainExisting moves future placement while existing sessions drain.
	MoveStrategyDrainExisting MoveStrategy = "drain_existing"
	// MoveStrategyKickExisting moves future placement and marks active sessions for closure.
	MoveStrategyKickExisting MoveStrategy = "kick_existing"
	// MoveStrategyNewSessionsOnly waits for active sessions to close before moving.
	MoveStrategyNewSessionsOnly MoveStrategy = "new_sessions_only"
)

// UserKey identifies user runtime state without storing a raw username.
type UserKey struct {
	Tenant   string
	UserHash string
}

// UserRuntimeState describes mutable user placement and control state.
type UserRuntimeState struct {
	Key                UserKey
	ActiveShard        string
	PendingShard       string
	MoveStrategy       MoveStrategy
	ActiveSessionCount int
	KickGeneration     string
	MoveGeneration     string
	Generation         string
	UpdatedAt          time.Time
}

// UserBackendPinTarget describes the registry-derived backend facts for a pin.
type UserBackendPinTarget struct {
	BackendIdentifier string
	Protocol          string
	BackendPool       string
	EffectiveShard    string
}

// UserBackendPin describes one user-scoped concrete backend runtime override.
type UserBackendPin struct {
	Present            bool
	Key                UserKey
	BackendIdentifier  string
	Protocol           string
	BackendPool        string
	EffectiveShard     string
	Strategy           MoveStrategy
	Generation         string
	ActiveSessionCount int
	UpdatedAt          time.Time
}

// UserHold describes one temporary user placement gate without a routing target.
type UserHold struct {
	Present           bool
	Key               UserKey
	Generation        string
	CreatedAt         time.Time
	ExpiresAt         time.Time
	RequestedDuration time.Duration
	UpdatedAt         time.Time
}

// UserListRequest describes one bounded runtime user read.
type UserListRequest struct {
	Cursor string
	Limit  int
}

// UserListResult contains one bounded runtime user page.
type UserListResult struct {
	Users      []UserRuntimeState
	NextCursor string
}

// MoveUserRequest asks runtime state to move one affinity key.
type MoveUserRequest struct {
	Key                UserKey
	TargetShard        string
	Strategy           MoveStrategy
	Reason             string
	Actor              Actor
	ExpectedGeneration string
}

// KickUserRequest asks runtime state to mark one user's active sessions for closure.
type KickUserRequest struct {
	Key                UserKey
	Reason             string
	Actor              Actor
	ExpectedGeneration string
}

// ClearUserAffinityRequest asks runtime state to clear inactive affinity.
type ClearUserAffinityRequest struct {
	Key                UserKey
	AllowActiveClear   bool
	Reason             string
	Actor              Actor
	ExpectedGeneration string
}

// SetUserBackendPinRequest asks runtime state to pin one affinity key to one backend.
type SetUserBackendPinRequest struct {
	Key                UserKey
	BackendIdentifier  string
	Strategy           MoveStrategy
	Reason             string
	Actor              Actor
	ExpectedGeneration string
}

// GetUserBackendPinRequest asks runtime state for one affinity key backend pin.
type GetUserBackendPinRequest struct {
	Key UserKey
}

// ClearUserBackendPinRequest asks runtime state to clear one backend pin.
type ClearUserBackendPinRequest struct {
	Key                UserKey
	Reason             string
	Actor              Actor
	ExpectedGeneration string
}

// SetUserHoldRequest asks runtime state to block new placement for one affinity key.
type SetUserHoldRequest struct {
	Key      UserKey
	Duration time.Duration
	Reason   string
	Actor    Actor
}

// GetUserHoldRequest asks runtime state for one user placement hold.
type GetUserHoldRequest struct {
	Key UserKey
}

// ClearUserHoldRequest asks runtime state to remove one user placement hold.
type ClearUserHoldRequest struct {
	Key    UserKey
	Reason string
	Actor  Actor
}

// CheckUserHoldRequest asks placement to read the hold gate for one affinity key.
type CheckUserHoldRequest struct {
	Key UserKey
}

// UserMutationResult describes a runtime user mutation outcome.
type UserMutationResult struct {
	State UserRuntimeState
	Audit AuditMetadata
}

// UserBackendPinReadResult describes a backend-pin read outcome.
type UserBackendPinReadResult struct {
	Pin UserBackendPin
}

// UserBackendPinMutationResult describes a backend-pin mutation outcome.
type UserBackendPinMutationResult struct {
	Pin    UserBackendPin
	Target UserBackendPinTarget
	Audit  AuditMetadata
}

// SetUserHoldResult describes an audited hold-set outcome.
type SetUserHoldResult struct {
	Hold  UserHold
	Audit AuditMetadata
}

// GetUserHoldResult describes a hold read outcome.
type GetUserHoldResult struct {
	Hold UserHold
}

// ClearUserHoldResult describes an audited hold-clear outcome.
type ClearUserHoldResult struct {
	Hold  UserHold
	Audit AuditMetadata
}

// CheckUserHoldResult describes a placement hold-gate read.
type CheckUserHoldResult struct {
	Hold UserHold
}

// UserHoldServiceConfig bounds user-hold mutations and local placement waiters.
type UserHoldServiceConfig struct {
	Enabled                bool
	MaxDuration            time.Duration
	MaxWait                time.Duration
	PollInterval           time.Duration
	MaxLocalWaiters        int
	MaxLocalWaitersPerUser int
}

// PlacementGateOutcome describes how the hold gate released placement.
type PlacementGateOutcome string

const (
	// PlacementGateOutcomeAllowed means no active hold delayed placement.
	PlacementGateOutcomeAllowed PlacementGateOutcome = "allowed"
	// PlacementGateOutcomeReleased means placement waited and must re-read runtime state.
	PlacementGateOutcomeReleased PlacementGateOutcome = "released"
)

// PlacementGateRequest identifies one post-identity placement attempt.
type PlacementGateRequest struct {
	Key          UserKey
	Protocol     string
	ListenerName string
	ServiceName  string
	Deadline     time.Time
}

// PlacementGateResult describes a protocol-neutral hold-gate outcome.
type PlacementGateResult struct {
	Outcome                     PlacementGateOutcome
	Hold                        UserHold
	RuntimeStateRecheckRequired bool
}

// PlacementGate is the shared protocol-neutral user placement gate.
type PlacementGate interface {
	WaitForPlacement(ctx context.Context, request PlacementGateRequest) (PlacementGateResult, error)
}

// UserStateStore persists Redis-backed user runtime operations.
type UserStateStore interface {
	MoveUser(ctx context.Context, request state.UserMoveRequest) (state.UserRuntimeRecord, error)
	KickUser(ctx context.Context, request state.UserKickRequest) (state.UserRuntimeRecord, error)
	ClearUserAffinity(ctx context.Context, request state.UserClearRequest) (state.UserRuntimeRecord, error)
}

// UserBackendPinStateStore persists Redis-backed backend-pin operations.
type UserBackendPinStateStore interface {
	SetUserBackendPin(ctx context.Context, request state.UserBackendPinSetRequest) (state.UserBackendPinRecord, error)
	GetUserBackendPin(ctx context.Context, request state.UserBackendPinGetRequest) (state.UserBackendPinRecord, error)
	ClearUserBackendPin(ctx context.Context, request state.UserBackendPinClearRequest) (state.UserBackendPinRecord, error)
}

// UserService coordinates user runtime operations with local session acceleration.
type UserService struct {
	store    UserStateStore
	local    *LocalSessionRegistry
	recorder observability.Recorder
}

// UserBackendPinService coordinates user backend-pin runtime operations.
type UserBackendPinService struct {
	store    UserBackendPinStateStore
	registry backend.Registry
	recorder observability.Recorder
}

// UserHoldService coordinates user placement holds and local waiters.
type UserHoldService struct {
	store    state.UserHoldStore
	config   UserHoldServiceConfig
	waiters  *userHoldWaiterRegistry
	recorder observability.Recorder
}

type userHoldWaiter struct {
	key  UserKey
	wake chan struct{}
}

type userHoldWaiterRegistry struct {
	mu         sync.Mutex
	total      int
	byUser     map[UserKey]int
	waiters    map[UserKey]map[*userHoldWaiter]struct{}
	maxTotal   int
	maxPerUser int
}

// NewUserService creates the runtime user operation service.
func NewUserService(store UserStateStore, local *LocalSessionRegistry, options ...ServiceOption) *UserService {
	applied := applyServiceOptions(options)

	return &UserService{store: store, local: local, recorder: applied.recorder}
}

// NewUserBackendPinService creates the runtime backend-pin operation service.
func NewUserBackendPinService(
	store UserBackendPinStateStore,
	registry backend.Registry,
	options ...ServiceOption,
) *UserBackendPinService {
	applied := applyServiceOptions(options)

	return &UserBackendPinService{store: store, registry: registry, recorder: applied.recorder}
}

// NewUserHoldService creates the shared placement-hold service.
func NewUserHoldService(
	store state.UserHoldStore,
	serviceConfig UserHoldServiceConfig,
	options ...ServiceOption,
) (*UserHoldService, error) {
	applied := applyServiceOptions(options)

	serviceConfig, err := serviceConfig.normalize()
	if err != nil {
		return nil, err
	}

	return &UserHoldService{
		store:    store,
		config:   serviceConfig,
		waiters:  newUserHoldWaiterRegistry(serviceConfig.MaxLocalWaiters, serviceConfig.MaxLocalWaitersPerUser),
		recorder: applied.recorder,
	}, nil
}

// SetUserHold records one audited placement hold.
func (s *UserHoldService) SetUserHold(ctx context.Context, request SetUserHoldRequest) (SetUserHoldResult, error) {
	if s == nil {
		return SetUserHoldResult{}, newRuntimeError(ErrorKindUnavailable, operationUserHoldSet, "user hold service required")
	}

	request.Key = request.Key.Normalize()
	if err := request.Validate(s.config.MaxDuration); err != nil {
		return SetUserHoldResult{}, err
	}

	if s.store == nil {
		return SetUserHoldResult{}, newRuntimeError(ErrorKindUnavailable, operationUserHoldSet, "user hold store required")
	}

	record, err := s.store.SetUserHold(ctx, state.UserHoldSetRequest{
		Key:         request.Key.affinityKey(),
		Duration:    request.Duration,
		MaxDuration: s.config.MaxDuration,
		Reason:      request.Reason,
		Actor:       actorAuditValue(request.Actor),
	})
	if err != nil {
		return SetUserHoldResult{}, err
	}

	hold := userHoldFromRecord(userHoldRecordWithKey(record, request.Key))

	audit, err := request.AuditMetadata(hold)
	if err != nil {
		return SetUserHoldResult{}, err
	}

	return SetUserHoldResult{Hold: hold, Audit: audit}, nil
}

// GetUserHold reads one placement hold without mutating runtime state.
func (s *UserHoldService) GetUserHold(ctx context.Context, request GetUserHoldRequest) (GetUserHoldResult, error) {
	request.Key = request.Key.Normalize()
	if err := request.Validate(); err != nil {
		return GetUserHoldResult{}, err
	}

	if s == nil || s.store == nil {
		return GetUserHoldResult{}, newRuntimeError(ErrorKindUnavailable, operationUserHoldGet, "user hold store required")
	}

	record, err := s.store.GetUserHold(ctx, state.UserHoldGetRequest{Key: request.Key.affinityKey()})
	if err != nil {
		return GetUserHoldResult{}, err
	}

	return GetUserHoldResult{Hold: userHoldFromRecord(userHoldRecordWithKey(record, request.Key))}, nil
}

// ClearUserHold removes one placement hold and wakes same-process waiters.
func (s *UserHoldService) ClearUserHold(ctx context.Context, request ClearUserHoldRequest) (ClearUserHoldResult, error) {
	request.Key = request.Key.Normalize()
	if err := request.Validate(); err != nil {
		return ClearUserHoldResult{}, err
	}

	if s == nil || s.store == nil {
		return ClearUserHoldResult{}, newRuntimeError(ErrorKindUnavailable, operationUserHoldClear, "user hold store required")
	}

	record, err := s.store.ClearUserHold(ctx, state.UserHoldClearRequest{
		Key:    request.Key.affinityKey(),
		Reason: request.Reason,
		Actor:  actorAuditValue(request.Actor),
	})
	if err != nil {
		return ClearUserHoldResult{}, err
	}

	hold := userHoldFromRecord(userHoldRecordWithKey(record, request.Key))
	if s.waiters != nil {
		s.waiters.wake(request.Key)
	}

	audit, err := request.AuditMetadata(hold)
	if err != nil {
		return ClearUserHoldResult{}, err
	}

	return ClearUserHoldResult{Hold: hold, Audit: audit}, nil
}

// CheckUserHold reads the placement gate without waiting.
func (s *UserHoldService) CheckUserHold(ctx context.Context, request CheckUserHoldRequest) (CheckUserHoldResult, error) {
	request.Key = request.Key.Normalize()
	if err := request.Validate(); err != nil {
		return CheckUserHoldResult{}, err
	}

	hold, err := s.checkUserHold(ctx, request.Key)
	if err != nil {
		return CheckUserHoldResult{}, err
	}

	return CheckUserHoldResult{Hold: hold}, nil
}

// WaitForPlacement blocks placement behind an active hold with bounded local waiters.
func (s *UserHoldService) WaitForPlacement(ctx context.Context, request PlacementGateRequest) (PlacementGateResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	request = request.Normalize()
	if err := request.Validate(); err != nil {
		return PlacementGateResult{}, err
	}

	if s == nil {
		return PlacementGateResult{}, newRuntimeError(ErrorKindUnavailable, operationUserHoldCheck, "user hold service required")
	}

	if !s.config.Enabled {
		return PlacementGateResult{Outcome: PlacementGateOutcomeAllowed}, nil
	}

	hold, err := s.checkUserHold(ctx, request.Key)
	if err != nil {
		return PlacementGateResult{}, err
	}

	if !hold.Present {
		return PlacementGateResult{Outcome: PlacementGateOutcomeAllowed, Hold: hold}, nil
	}

	return s.waitForActiveUserHold(ctx, request)
}

// waitForActiveUserHold waits locally after the initial hold check observed an active hold.
func (s *UserHoldService) waitForActiveUserHold(
	ctx context.Context,
	request PlacementGateRequest,
) (PlacementGateResult, error) {
	if s.waiters == nil {
		return PlacementGateResult{}, newRuntimeError(ErrorKindUnavailable, operationUserHoldCheck, "user hold waiter registry required")
	}

	waiter, err := s.waiters.register(request.Key)
	if err != nil {
		return PlacementGateResult{}, newRuntimeError(ErrorKindUnavailable, operationUserHoldCheck, err.Error())
	}
	defer s.waiters.unregister(waiter)

	waitCtx, cancel := s.placementWaitContext(ctx, request)
	defer cancel()

	for {
		hold, err := s.checkUserHold(waitCtx, request.Key)
		if err != nil {
			if waitCtx.Err() != nil {
				return PlacementGateResult{}, placementGateWaitError(ctx)
			}

			return PlacementGateResult{}, err
		}

		if !hold.Present {
			return PlacementGateResult{
				Outcome:                     PlacementGateOutcomeReleased,
				Hold:                        hold,
				RuntimeStateRecheckRequired: true,
			}, nil
		}

		if err := s.waitForHoldRecheck(waitCtx, waiter); err != nil {
			return PlacementGateResult{}, placementGateWaitError(ctx)
		}
	}
}

// SetUserBackendPin derives target facts and records one concrete backend pin.
func (s *UserBackendPinService) SetUserBackendPin(
	ctx context.Context,
	request SetUserBackendPinRequest,
) (UserBackendPinMutationResult, error) {
	request.Key = request.Key.Normalize()
	request.BackendIdentifier = strings.TrimSpace(request.BackendIdentifier)
	request.Strategy = MoveStrategy(strings.TrimSpace(string(request.Strategy)))

	if err := request.Validate(); err != nil {
		return UserBackendPinMutationResult{}, err
	}

	if s == nil {
		return UserBackendPinMutationResult{}, newRuntimeError(ErrorKindInvalidRequest, operationUserBackendPinSet, "backend pin service required")
	}

	target, err := s.resolveBackendPinTarget(ctx, request.BackendIdentifier, operationUserBackendPinSet)
	if err != nil {
		return UserBackendPinMutationResult{}, err
	}

	if s.store == nil {
		return UserBackendPinMutationResult{}, newRuntimeError(ErrorKindInvalidRequest, operationUserBackendPinSet, "backend pin store required")
	}

	record, err := s.store.SetUserBackendPin(ctx, backendPinSetStoreRequest(request, target))
	if err != nil {
		s.recordBackendPinOperation(ctx, operationUserBackendPinSet, runtimeObservationResultFailure, runtimeObservationReasonBackendPinSet, state.UserBackendPinRecord{
			Key:               request.Key.affinityKey(),
			BackendIdentifier: target.BackendIdentifier,
			Protocol:          target.Protocol,
			BackendPool:       target.BackendPool,
			ShardTag:          target.EffectiveShard,
			Strategy:          string(request.Strategy),
		})

		return UserBackendPinMutationResult{}, err
	}

	record = backendPinRecordWithTarget(record, request.Key, target, request.Strategy)

	audit, err := userBackendPinAuditMetadata(AuditOperationUserBackendPinSet, request.Reason, request.Actor, record)
	if err != nil {
		return UserBackendPinMutationResult{}, err
	}

	s.recordBackendPinOperation(ctx, operationUserBackendPinSet, runtimeObservationResultOK, runtimeObservationReasonBackendPinSet, record)

	return UserBackendPinMutationResult{
		Pin:    userBackendPinFromRecord(record),
		Target: target,
		Audit:  audit,
	}, nil
}

// backendPinSetStoreRequest maps validated operator input into store shape.
func backendPinSetStoreRequest(request SetUserBackendPinRequest, target UserBackendPinTarget) state.UserBackendPinSetRequest {
	return state.UserBackendPinSetRequest{
		Key:               request.Key.affinityKey(),
		BackendIdentifier: target.BackendIdentifier,
		Protocol:          target.Protocol,
		BackendPool:       target.BackendPool,
		ShardTag:          target.EffectiveShard,
		Strategy:          string(request.Strategy),
		Reason:            request.Reason,
		Actor:             actorAuditValue(request.Actor),
	}
}

// GetUserBackendPin reads one backend pin without mutating runtime state.
func (s *UserBackendPinService) GetUserBackendPin(
	ctx context.Context,
	request GetUserBackendPinRequest,
) (UserBackendPinReadResult, error) {
	request.Key = request.Key.Normalize()
	if err := request.Validate(); err != nil {
		return UserBackendPinReadResult{}, err
	}

	if s == nil || s.store == nil {
		return UserBackendPinReadResult{}, newRuntimeError(ErrorKindInvalidRequest, operationUserBackendPinGet, "backend pin store required")
	}

	record, err := s.store.GetUserBackendPin(ctx, state.UserBackendPinGetRequest{
		Key: request.Key.affinityKey(),
	})
	if err != nil {
		s.recordBackendPinOperation(ctx, operationUserBackendPinGet, runtimeObservationResultFailure, "backend_pin_read_failed", state.UserBackendPinRecord{Key: request.Key.affinityKey()})

		return UserBackendPinReadResult{}, err
	}

	record = backendPinRecordWithKey(record, request.Key)

	return UserBackendPinReadResult{Pin: userBackendPinFromRecord(record)}, nil
}

// ClearUserBackendPin removes the concrete backend override without closing sessions.
func (s *UserBackendPinService) ClearUserBackendPin(
	ctx context.Context,
	request ClearUserBackendPinRequest,
) (UserBackendPinMutationResult, error) {
	request.Key = request.Key.Normalize()
	if err := request.Validate(); err != nil {
		return UserBackendPinMutationResult{}, err
	}

	if s == nil || s.store == nil {
		return UserBackendPinMutationResult{}, newRuntimeError(ErrorKindInvalidRequest, operationUserBackendPinClear, "backend pin store required")
	}

	record, err := s.store.ClearUserBackendPin(ctx, state.UserBackendPinClearRequest{
		Key:    request.Key.affinityKey(),
		Reason: request.Reason,
		Actor:  actorAuditValue(request.Actor),
	})
	if err != nil {
		s.recordBackendPinOperation(ctx, operationUserBackendPinClear, runtimeObservationResultFailure, runtimeObservationReasonBackendPinClear, state.UserBackendPinRecord{Key: request.Key.affinityKey()})

		return UserBackendPinMutationResult{}, err
	}

	record = backendPinRecordWithKey(record, request.Key)

	audit, err := userBackendPinAuditMetadata(AuditOperationUserBackendPinClear, request.Reason, request.Actor, record)
	if err != nil {
		return UserBackendPinMutationResult{}, err
	}

	s.recordBackendPinOperation(ctx, operationUserBackendPinClear, runtimeObservationResultOK, runtimeObservationReasonBackendPinClear, record)

	return UserBackendPinMutationResult{
		Pin:    userBackendPinFromRecord(record),
		Target: backendPinTargetFromRecord(record),
		Audit:  audit,
	}, nil
}

// MoveUser records a placement move and locally closes streams for kick-existing moves.
func (s *UserService) MoveUser(ctx context.Context, request MoveUserRequest) (UserMutationResult, error) {
	request.Key = request.Key.Normalize()
	if err := request.Validate(); err != nil {
		return UserMutationResult{}, err
	}

	request.Strategy = MoveStrategy(strings.TrimSpace(string(request.Strategy)))
	request.TargetShard = strings.TrimSpace(request.TargetShard)

	if s == nil || s.store == nil {
		return UserMutationResult{}, newRuntimeError(ErrorKindInvalidRequest, operationUserMove, "user store required")
	}

	record, err := s.store.MoveUser(ctx, state.UserMoveRequest{
		Key:         request.Key.affinityKey(),
		TargetShard: request.TargetShard,
		Strategy:    strings.TrimSpace(string(request.Strategy)),
		Reason:      request.Reason,
		Actor:       actorAuditValue(request.Actor),
	})
	if err != nil {
		return UserMutationResult{}, err
	}

	audit, err := userAuditMetadata(AuditOperationUserMove, request.Reason, request.Actor, record, map[string]string{
		auditFieldStrategy:    string(request.Strategy),
		auditFieldTargetShard: strings.TrimSpace(request.TargetShard),
		auditFieldStatus:      record.Status,
	})
	if err != nil {
		return UserMutationResult{}, err
	}

	if request.Strategy == MoveStrategyKickExisting && s.local != nil {
		_, closeErr := s.local.CloseUser(ctx, request.Key, LocalSessionControl{
			Action: string(record.ControlAction),
			Reason: request.Reason,
		})
		if closeErr != nil {
			return UserMutationResult{}, closeErr
		}
	}

	s.recordUserOperation(ctx, observability.EventUserMove, operationUserMove, runtimeObservationResultOK, "moved", record, map[string]string{
		auditFieldStrategy:    string(request.Strategy),
		auditFieldTargetShard: strings.TrimSpace(request.TargetShard),
	})

	return UserMutationResult{State: userRuntimeStateFromRecord(record), Audit: audit}, nil
}

// KickUser marks all active sessions for one affinity key and closes local streams promptly.
func (s *UserService) KickUser(ctx context.Context, request KickUserRequest) (UserMutationResult, error) {
	request.Key = request.Key.Normalize()
	if err := request.Validate(); err != nil {
		return UserMutationResult{}, err
	}

	if s == nil || s.store == nil {
		return UserMutationResult{}, newRuntimeError(ErrorKindInvalidRequest, operationUserKick, "user store required")
	}

	record, err := s.store.KickUser(ctx, state.UserKickRequest{
		Key:    request.Key.affinityKey(),
		Reason: request.Reason,
		Actor:  actorAuditValue(request.Actor),
	})
	if err != nil {
		return UserMutationResult{}, err
	}

	audit, err := userAuditMetadata(AuditOperationUserKick, request.Reason, request.Actor, record, map[string]string{
		auditFieldControlAction: string(record.ControlAction),
		auditFieldStatus:        record.Status,
	})
	if err != nil {
		return UserMutationResult{}, err
	}

	if s.local != nil {
		_, closeErr := s.local.CloseUser(ctx, request.Key, LocalSessionControl{
			Action: string(record.ControlAction),
			Reason: request.Reason,
		})
		if closeErr != nil {
			return UserMutationResult{}, closeErr
		}
	}

	s.recordUserOperation(ctx, observability.EventUserKick, operationUserKick, runtimeObservationResultOK, "kicked", record, map[string]string{
		auditFieldControlAction: string(record.ControlAction),
	})

	return UserMutationResult{State: userRuntimeStateFromRecord(record), Audit: audit}, nil
}

// ClearUserAffinity clears inactive affinity state without closing active sessions.
func (s *UserService) ClearUserAffinity(ctx context.Context, request ClearUserAffinityRequest) (UserMutationResult, error) {
	request.Key = request.Key.Normalize()
	if err := request.Validate(); err != nil {
		return UserMutationResult{}, err
	}

	if s == nil || s.store == nil {
		return UserMutationResult{}, newRuntimeError(ErrorKindInvalidRequest, operationUserAffinityClear, "user store required")
	}

	record, err := s.store.ClearUserAffinity(ctx, state.UserClearRequest{
		Key:              request.Key.affinityKey(),
		AllowActiveClear: request.AllowActiveClear,
		Reason:           request.Reason,
		Actor:            actorAuditValue(request.Actor),
	})
	if err != nil {
		return UserMutationResult{}, err
	}

	audit, err := userAuditMetadata(AuditOperationUserAffinityClear, request.Reason, request.Actor, record, map[string]string{
		auditFieldAllowActiveClear: boolAuditValue(request.AllowActiveClear),
		auditFieldStatus:           record.Status,
	})
	if err != nil {
		return UserMutationResult{}, err
	}

	s.recordUserOperation(ctx, observability.EventAffinityClear, operationUserAffinityClear, runtimeObservationResultOK, runtimeObservationReasonCleared, record, map[string]string{
		auditFieldAllowActiveClear: boolAuditValue(request.AllowActiveClear),
	})

	return UserMutationResult{State: userRuntimeStateFromRecord(record), Audit: audit}, nil
}

// Validate checks the move request before it crosses a persistence boundary.
func (r MoveUserRequest) Validate() error {
	if err := r.Key.Validate(operationUserMove); err != nil {
		return err
	}

	if strings.TrimSpace(r.TargetShard) == "" {
		return newRuntimeError(ErrorKindInvalidRequest, operationUserMove, "target shard required")
	}

	if !validMoveStrategy(r.Strategy) {
		return newRuntimeError(ErrorKindInvalidRequest, operationUserMove, "unsupported move strategy")
	}

	return requireReason(operationUserMove, r.Reason)
}

// Validate checks the kick request before it crosses a persistence boundary.
func (r KickUserRequest) Validate() error {
	if err := r.Key.Validate(operationUserKick); err != nil {
		return err
	}

	return requireReason(operationUserKick, r.Reason)
}

// Validate checks the affinity clear request before it crosses a persistence boundary.
func (r ClearUserAffinityRequest) Validate() error {
	if err := r.Key.Validate(operationUserAffinityClear); err != nil {
		return err
	}

	return requireReason(operationUserAffinityClear, r.Reason)
}

// Validate checks the backend-pin set request before registry or state access.
func (r SetUserBackendPinRequest) Validate() error {
	if err := r.Key.Validate(operationUserBackendPinSet); err != nil {
		return err
	}

	if strings.TrimSpace(r.BackendIdentifier) == "" {
		return newRuntimeError(ErrorKindInvalidRequest, operationUserBackendPinSet, "backend identifier required")
	}

	if !validMoveStrategy(r.Strategy) {
		return newRuntimeError(ErrorKindInvalidRequest, operationUserBackendPinSet, "unsupported move strategy")
	}

	return requireReason(operationUserBackendPinSet, r.Reason)
}

// Validate checks the backend-pin read request before state access.
func (r GetUserBackendPinRequest) Validate() error {
	return r.Key.Validate(operationUserBackendPinGet)
}

// Validate checks the backend-pin clear request before state access.
func (r ClearUserBackendPinRequest) Validate() error {
	if err := r.Key.Validate(operationUserBackendPinClear); err != nil {
		return err
	}

	return requireReason(operationUserBackendPinClear, r.Reason)
}

// Validate checks the hold set request against the configured duration ceiling.
func (r SetUserHoldRequest) Validate(maxDuration time.Duration) error {
	if err := r.Key.Validate(operationUserHoldSet); err != nil {
		return err
	}

	if r.Duration <= 0 {
		return newRuntimeError(ErrorKindInvalidRequest, operationUserHoldSet, "hold duration must be greater than zero")
	}

	if maxDuration <= 0 {
		return newRuntimeError(ErrorKindUnavailable, operationUserHoldSet, "hold maximum duration unavailable")
	}

	if r.Duration > maxDuration {
		return newRuntimeError(ErrorKindInvalidRequest, operationUserHoldSet, "hold duration exceeds configured maximum")
	}

	return requireReason(operationUserHoldSet, r.Reason)
}

// AuditMetadata creates secret-safe metadata for an accepted hold set.
func (r SetUserHoldRequest) AuditMetadata(hold UserHold) (AuditMetadata, error) {
	return userHoldAuditMetadata(AuditOperationUserHoldSet, r.Reason, r.Actor, hold)
}

// Validate checks the hold read request before state access.
func (r GetUserHoldRequest) Validate() error {
	return r.Key.Validate(operationUserHoldGet)
}

// Validate checks the hold clear request before state access.
func (r ClearUserHoldRequest) Validate() error {
	if err := r.Key.Validate(operationUserHoldClear); err != nil {
		return err
	}

	return requireReason(operationUserHoldClear, r.Reason)
}

// AuditMetadata creates secret-safe metadata for an accepted hold clear.
func (r ClearUserHoldRequest) AuditMetadata(hold UserHold) (AuditMetadata, error) {
	return userHoldAuditMetadata(AuditOperationUserHoldClear, r.Reason, r.Actor, hold)
}

// Validate checks the placement hold-gate request before state access.
func (r CheckUserHoldRequest) Validate() error {
	return r.Key.Validate(operationUserHoldCheck)
}

// Normalize returns a placement-gate request with canonical comparable fields.
func (r PlacementGateRequest) Normalize() PlacementGateRequest {
	r.Key = r.Key.Normalize()
	r.Protocol = strings.TrimSpace(r.Protocol)
	r.ListenerName = strings.TrimSpace(r.ListenerName)
	r.ServiceName = strings.TrimSpace(r.ServiceName)

	return r
}

// Validate checks the placement-gate request before waiting or state reads.
func (r PlacementGateRequest) Validate() error {
	if err := r.Key.Validate(operationUserHoldCheck); err != nil {
		return err
	}

	if strings.TrimSpace(r.Protocol) == "" {
		return newRuntimeError(ErrorKindInvalidRequest, operationUserHoldCheck, "protocol required")
	}

	return nil
}

// normalize validates the hold gate policy before it is shared with protocols.
func (c UserHoldServiceConfig) normalize() (UserHoldServiceConfig, error) {
	if c.MaxDuration <= 0 {
		return UserHoldServiceConfig{}, newRuntimeError(ErrorKindUnavailable, operationUserHoldSet, "hold maximum duration unavailable")
	}

	if c.MaxWait <= 0 {
		return UserHoldServiceConfig{}, newRuntimeError(ErrorKindUnavailable, operationUserHoldCheck, "hold maximum wait unavailable")
	}

	if c.PollInterval <= 0 {
		return UserHoldServiceConfig{}, newRuntimeError(ErrorKindUnavailable, operationUserHoldCheck, "hold poll interval unavailable")
	}

	if c.PollInterval > c.MaxWait {
		return UserHoldServiceConfig{}, newRuntimeError(ErrorKindUnavailable, operationUserHoldCheck, "hold poll interval exceeds maximum wait")
	}

	if c.MaxLocalWaiters <= 0 {
		return UserHoldServiceConfig{}, newRuntimeError(ErrorKindUnavailable, operationUserHoldCheck, "hold waiter limit unavailable")
	}

	if c.MaxLocalWaitersPerUser <= 0 || c.MaxLocalWaitersPerUser > c.MaxLocalWaiters {
		return UserHoldServiceConfig{}, newRuntimeError(ErrorKindUnavailable, operationUserHoldCheck, "hold per-user waiter limit unavailable")
	}

	return c, nil
}

// Validate checks derived backend-pin target facts before persistence.
func (t UserBackendPinTarget) Validate(operation string) error {
	if strings.TrimSpace(t.BackendIdentifier) == "" {
		return newRuntimeError(ErrorKindUnavailable, operation, "backend target identifier required")
	}

	if strings.TrimSpace(t.Protocol) == "" {
		return newRuntimeError(ErrorKindUnavailable, operation, "backend target protocol required")
	}

	if strings.TrimSpace(t.BackendPool) == "" {
		return newRuntimeError(ErrorKindUnavailable, operation, "backend target pool required")
	}

	if strings.TrimSpace(t.EffectiveShard) == "" {
		return newRuntimeError(ErrorKindUnavailable, operation, "backend target shard required")
	}

	return nil
}

// Validate checks that the user key is suitable for Redis-backed runtime state.
func (k UserKey) Validate(operation string) error {
	if strings.TrimSpace(k.Tenant) == "" {
		return newRuntimeError(ErrorKindInvalidRequest, operation, "tenant required")
	}

	if strings.TrimSpace(k.UserHash) == "" {
		return newRuntimeError(ErrorKindInvalidRequest, operation, "user hash required")
	}

	return nil
}

// Normalize returns a user key with insignificant whitespace removed.
func (k UserKey) Normalize() UserKey {
	k.Tenant = strings.TrimSpace(k.Tenant)
	k.UserHash = strings.TrimSpace(k.UserHash)

	return k
}

// affinityKey adapts the runtime user key to the Redis affinity key.
func (k UserKey) affinityKey() state.AffinityKey {
	return state.AffinityKey{Tenant: k.Tenant, AccountKey: k.UserHash}
}

// validMoveStrategy reports whether a strategy matches the public runtime vocabulary.
func validMoveStrategy(strategy MoveStrategy) bool {
	switch MoveStrategy(strings.TrimSpace(string(strategy))) {
	case MoveStrategyNewSessionsOnly, MoveStrategyKickExisting, MoveStrategyDrainExisting:
		return true
	default:
		return false
	}
}

// resolveBackendPinTarget resolves operator input through the configured registry.
func (s *UserBackendPinService) resolveBackendPinTarget(
	ctx context.Context,
	identifier string,
	operation string,
) (UserBackendPinTarget, error) {
	if s == nil || s.registry == nil {
		return UserBackendPinTarget{}, newRuntimeError(ErrorKindUnavailable, operation, "backend registry required")
	}

	entry, err := s.registry.Lookup(ctx, identifier)
	if err != nil {
		return UserBackendPinTarget{}, runtimeErrorFromBackendRegistry(operation, err)
	}

	target := userBackendPinTargetFromFacts(entry.PlacementFacts())
	if err := target.Validate(operation); err != nil {
		return UserBackendPinTarget{}, err
	}

	return target, nil
}

// runtimeErrorFromBackendRegistry maps registry failures into runtime control classes.
func runtimeErrorFromBackendRegistry(operation string, err error) error {
	if err == nil {
		return nil
	}

	var backendErr *backend.Error
	if !errors.As(err, &backendErr) {
		return newRuntimeError(ErrorKindUnavailable, operation, "backend registry unavailable")
	}

	switch backendErr.Kind {
	case backend.ErrorKindInvalidRequest:
		return newRuntimeError(ErrorKindInvalidRequest, operation, backendErr.Message)
	case backend.ErrorKindNoBackend:
		return newRuntimeError(ErrorKindNotFound, operation, "backend not found")
	case backend.ErrorKindAmbiguous, backend.ErrorKindConfig:
		return newRuntimeError(ErrorKindUnavailable, operation, backendErr.Message)
	default:
		return newRuntimeError(ErrorKindUnavailable, operation, "backend registry unavailable")
	}
}

// userBackendPinTargetFromFacts adapts registry facts into runtime pin metadata.
func userBackendPinTargetFromFacts(facts backend.PlacementFacts) UserBackendPinTarget {
	return UserBackendPinTarget{
		BackendIdentifier: strings.TrimSpace(facts.BackendIdentifier),
		Protocol:          strings.TrimSpace(facts.Protocol),
		BackendPool:       strings.TrimSpace(facts.BackendPool),
		EffectiveShard:    strings.TrimSpace(facts.EffectiveShard),
	}
}

// backendPinRecordWithTarget preserves registry-derived facts in mutation output.
func backendPinRecordWithTarget(
	record state.UserBackendPinRecord,
	key UserKey,
	target UserBackendPinTarget,
	strategy MoveStrategy,
) state.UserBackendPinRecord {
	record = backendPinRecordWithKey(record, key)
	record.Present = true

	if strings.TrimSpace(record.BackendIdentifier) == "" {
		record.BackendIdentifier = target.BackendIdentifier
	}

	if strings.TrimSpace(record.Protocol) == "" {
		record.Protocol = target.Protocol
	}

	if strings.TrimSpace(record.BackendPool) == "" {
		record.BackendPool = target.BackendPool
	}

	if strings.TrimSpace(record.ShardTag) == "" {
		record.ShardTag = target.EffectiveShard
	}

	if strings.TrimSpace(record.Strategy) == "" {
		record.Strategy = string(strategy)
	}

	return record
}

// backendPinRecordWithKey preserves the requested affinity key in sparse records.
func backendPinRecordWithKey(record state.UserBackendPinRecord, key UserKey) state.UserBackendPinRecord {
	if strings.TrimSpace(record.Key.Tenant) == "" {
		record.Key.Tenant = key.Tenant
	}

	if strings.TrimSpace(record.Key.AccountKey) == "" {
		record.Key.AccountKey = key.UserHash
	}

	return record
}

// userBackendPinFromRecord maps state output into runtime backend-pin state.
func userBackendPinFromRecord(record state.UserBackendPinRecord) UserBackendPin {
	return UserBackendPin{
		Present:            record.Present,
		Key:                UserKey{Tenant: record.Key.Tenant, UserHash: record.Key.AccountKey}.Normalize(),
		BackendIdentifier:  strings.TrimSpace(record.BackendIdentifier),
		Protocol:           strings.TrimSpace(record.Protocol),
		BackendPool:        strings.TrimSpace(record.BackendPool),
		EffectiveShard:     strings.TrimSpace(record.ShardTag),
		Strategy:           MoveStrategy(strings.TrimSpace(record.Strategy)),
		Generation:         strings.TrimSpace(record.Generation),
		ActiveSessionCount: record.ActiveSessionCount,
		UpdatedAt:          record.ServerTime,
	}
}

// backendPinTargetFromRecord returns bounded target metadata from a stored pin.
func backendPinTargetFromRecord(record state.UserBackendPinRecord) UserBackendPinTarget {
	return UserBackendPinTarget{
		BackendIdentifier: strings.TrimSpace(record.BackendIdentifier),
		Protocol:          strings.TrimSpace(record.Protocol),
		BackendPool:       strings.TrimSpace(record.BackendPool),
		EffectiveShard:    strings.TrimSpace(record.ShardTag),
	}
}

// checkUserHold reads one placement hold through the shared state boundary.
func (s *UserHoldService) checkUserHold(ctx context.Context, key UserKey) (UserHold, error) {
	if s == nil || s.store == nil {
		return UserHold{}, newRuntimeError(ErrorKindUnavailable, operationUserHoldCheck, "user hold store required")
	}

	key = key.Normalize()

	record, err := s.store.CheckUserHold(ctx, state.UserHoldCheckRequest{Key: key.affinityKey()})
	if err != nil {
		return UserHold{}, err
	}

	return userHoldFromRecord(userHoldRecordWithKey(record, key)), nil
}

// placementWaitContext derives the bounded waiter context for one placement attempt.
func (s *UserHoldService) placementWaitContext(
	ctx context.Context,
	request PlacementGateRequest,
) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}

	deadline := time.Now().Add(s.config.MaxWait)
	if !request.Deadline.IsZero() && request.Deadline.Before(deadline) {
		deadline = request.Deadline
	}

	return context.WithDeadline(ctx, deadline)
}

// waitForHoldRecheck waits for a local clear wake-up, polling cadence or cancellation.
func (s *UserHoldService) waitForHoldRecheck(ctx context.Context, waiter *userHoldWaiter) error {
	timer := time.NewTimer(s.config.PollInterval)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-waiter.wake:
		return nil
	case <-timer.C:
		return nil
	}
}

// placementGateWaitError classifies hold wait exits for protocol-neutral callers.
func placementGateWaitError(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.Canceled) {
		return ctx.Err()
	}

	return newRuntimeError(ErrorKindUnavailable, operationUserHoldCheck, "user hold wait timeout")
}

// userHoldRecordWithKey preserves the requested affinity key in sparse hold records.
func userHoldRecordWithKey(record state.UserHoldRecord, key UserKey) state.UserHoldRecord {
	if strings.TrimSpace(record.Key.Tenant) == "" {
		record.Key.Tenant = key.Tenant
	}

	if strings.TrimSpace(record.Key.AccountKey) == "" {
		record.Key.AccountKey = key.UserHash
	}

	return record
}

// userHoldFromRecord maps Redis output into the runtime placement-hold state.
func userHoldFromRecord(record state.UserHoldRecord) UserHold {
	return UserHold{
		Present:           record.Present,
		Key:               UserKey{Tenant: record.Key.Tenant, UserHash: record.Key.AccountKey}.Normalize(),
		Generation:        strings.TrimSpace(record.Generation),
		CreatedAt:         record.CreatedAt,
		ExpiresAt:         record.ExpiresAt,
		RequestedDuration: record.RequestedDuration,
		UpdatedAt:         record.ServerTime,
	}
}

// userRuntimeStateFromRecord maps Redis mutation output into runtime domain state.
func userRuntimeStateFromRecord(record state.UserRuntimeRecord) UserRuntimeState {
	runtimeState := UserRuntimeState{
		Key: UserKey{
			Tenant:   record.Key.Tenant,
			UserHash: record.Key.AccountKey,
		}.Normalize(),
		ActiveShard:        record.ShardTag,
		PendingShard:       record.TargetShard,
		MoveStrategy:       MoveStrategy(record.Strategy),
		ActiveSessionCount: record.ActiveSessionCount,
		Generation:         record.Generation,
		UpdatedAt:          record.ServerTime,
	}

	switch record.ControlAction {
	case state.ControlActionKick:
		runtimeState.KickGeneration = record.Generation
	case state.ControlActionMoveGenerationChanged:
		runtimeState.MoveGeneration = record.Generation
	}

	return runtimeState
}

// userAuditMetadata creates secret-safe audit metadata for a user mutation.
func userAuditMetadata(
	operation AuditOperation,
	reason string,
	actor Actor,
	record state.UserRuntimeRecord,
	fields map[string]string,
) (AuditMetadata, error) {
	return NewAuditMetadata(AuditInput{
		Operation:  operation,
		Reason:     reason,
		Actor:      actor,
		Generation: record.Generation,
		ServerTime: record.ServerTime,
		UserHash:   record.Key.AccountKey,
		Fields:     fields,
	})
}

// userBackendPinAuditMetadata creates secret-safe audit metadata for backend pins.
func userBackendPinAuditMetadata(
	operation AuditOperation,
	reason string,
	actor Actor,
	record state.UserBackendPinRecord,
) (AuditMetadata, error) {
	return NewAuditMetadata(AuditInput{
		Operation:         operation,
		Reason:            reason,
		Actor:             actor,
		Generation:        record.Generation,
		ServerTime:        record.ServerTime,
		BackendIdentifier: record.BackendIdentifier,
		UserHash:          record.Key.AccountKey,
		Fields:            backendPinAuditFields(record),
	})
}

// userHoldAuditMetadata creates secret-safe audit metadata for placement holds.
func userHoldAuditMetadata(operation AuditOperation, reason string, actor Actor, hold UserHold) (AuditMetadata, error) {
	return NewAuditMetadata(AuditInput{
		Operation:  operation,
		Reason:     reason,
		Actor:      actor,
		Generation: strings.TrimSpace(hold.Generation),
		ServerTime: userHoldAuditTime(hold),
		UserHash:   hold.Key.UserHash,
		Fields:     userHoldAuditFields(hold),
	})
}

// userHoldAuditTime selects the most specific server-derived hold timestamp.
func userHoldAuditTime(hold UserHold) time.Time {
	switch {
	case !hold.UpdatedAt.IsZero():
		return hold.UpdatedAt
	case !hold.CreatedAt.IsZero():
		return hold.CreatedAt
	default:
		return time.Time{}
	}
}

// userHoldAuditFields returns bounded placement-hold context without operator secrets.
func userHoldAuditFields(hold UserHold) map[string]string {
	fields := map[string]string{
		auditFieldHoldPresent: boolAuditValue(hold.Present),
	}

	if hold.RequestedDuration > 0 {
		fields[auditFieldHoldDuration] = strconv.FormatInt(int64(hold.RequestedDuration/time.Second), 10)
	}

	if !hold.ExpiresAt.IsZero() {
		fields[auditFieldHoldExpiresAt] = hold.ExpiresAt.UTC().Format(time.RFC3339)
	}

	return fields
}

// backendPinAuditFields returns bounded backend-pin context without transport secrets.
func backendPinAuditFields(record state.UserBackendPinRecord) map[string]string {
	fields := map[string]string{
		auditFieldActiveSessionCount: strconv.Itoa(record.ActiveSessionCount),
		auditFieldBackendIdentifier:  strings.TrimSpace(record.BackendIdentifier),
		auditFieldBackendPool:        strings.TrimSpace(record.BackendPool),
		auditFieldEffectiveShard:     strings.TrimSpace(record.ShardTag),
		auditFieldProtocol:           strings.TrimSpace(record.Protocol),
		auditFieldStatus:             strings.TrimSpace(record.Status),
		auditFieldStrategy:           strings.TrimSpace(record.Strategy),
	}

	for key, value := range fields {
		if value == "" {
			delete(fields, key)
		}
	}

	return fields
}

// boolAuditValue serializes booleans for audit metadata.
func boolAuditValue(value bool) string {
	if value {
		return auditValueTrue
	}

	return auditValueFalse
}

// newUserHoldWaiterRegistry creates local waiter accounting for one process.
func newUserHoldWaiterRegistry(maxTotal int, maxPerUser int) *userHoldWaiterRegistry {
	return &userHoldWaiterRegistry{
		byUser:     map[UserKey]int{},
		waiters:    map[UserKey]map[*userHoldWaiter]struct{}{},
		maxTotal:   maxTotal,
		maxPerUser: maxPerUser,
	}
}

// register accounts for one local placement waiter before it can block.
func (r *userHoldWaiterRegistry) register(key UserKey) (*userHoldWaiter, error) {
	key = key.Normalize()

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.total >= r.maxTotal {
		return nil, errors.New("user hold waiter limit exceeded")
	}

	if r.byUser[key] >= r.maxPerUser {
		return nil, errors.New("user hold per-user waiter limit exceeded")
	}

	waiter := &userHoldWaiter{key: key, wake: make(chan struct{}, 1)}
	if r.waiters[key] == nil {
		r.waiters[key] = map[*userHoldWaiter]struct{}{}
	}

	r.waiters[key][waiter] = struct{}{}
	r.total++
	r.byUser[key]++

	return waiter, nil
}

// unregister releases one local placement waiter on every exit path.
func (r *userHoldWaiterRegistry) unregister(waiter *userHoldWaiter) {
	if r == nil || waiter == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	waiters := r.waiters[waiter.key]
	if _, ok := waiters[waiter]; !ok {
		return
	}

	delete(waiters, waiter)

	if len(waiters) == 0 {
		delete(r.waiters, waiter.key)
	}

	r.total--

	r.byUser[waiter.key]--
	if r.byUser[waiter.key] <= 0 {
		delete(r.byUser, waiter.key)
	}
}

// wake notifies same-process waiters without relying on Redis pub/sub correctness.
func (r *userHoldWaiterRegistry) wake(key UserKey) {
	if r == nil {
		return
	}

	key = key.Normalize()

	r.mu.Lock()

	waiters := make([]*userHoldWaiter, 0, len(r.waiters[key]))
	for waiter := range r.waiters[key] {
		waiters = append(waiters, waiter)
	}
	r.mu.Unlock()

	for _, waiter := range waiters {
		select {
		case waiter.wake <- struct{}{}:
		default:
		}
	}
}

// counts returns current waiter totals for focused domain tests.
func (r *userHoldWaiterRegistry) counts(key UserKey) (int, int) {
	if r == nil {
		return 0, 0
	}

	key = key.Normalize()

	r.mu.Lock()
	defer r.mu.Unlock()

	return r.total, r.byUser[key]
}

// recordUserOperation emits one secret-safe user runtime observation.
func (s *UserService) recordUserOperation(
	ctx context.Context,
	event string,
	operation string,
	result string,
	reasonClass string,
	record state.UserRuntimeRecord,
	fields map[string]string,
) {
	if s == nil {
		return
	}

	eventFields := map[string]string{
		auditFieldControlAction:                  string(record.ControlAction),
		auditFieldTargetShard:                    record.TargetShard,
		runtimeObservationFieldActiveSessions:    strconv.Itoa(record.ActiveSessionCount),
		runtimeObservationFieldRuntimeGeneration: record.Generation,
		runtimeObservationFieldRuntimeStatus:     record.Status,
		runtimeObservationFieldShardTag:          record.ShardTag,
		runtimeObservationFieldUserHash:          record.Key.AccountKey,
	}
	maps.Copy(eventFields, fields)

	recordRuntimeObservation(ctx, s.recorder, event, observability.TraceBoundaryRESTRequest, operation, result, reasonClass, eventFields, nil)
}

// recordBackendPinOperation emits one secret-safe backend-pin runtime observation.
func (s *UserBackendPinService) recordBackendPinOperation(
	ctx context.Context,
	operation string,
	result string,
	reasonClass string,
	record state.UserBackendPinRecord,
) {
	if s == nil {
		return
	}

	eventFields := map[string]string{
		runtimeObservationFieldActiveSessions:    strconv.Itoa(record.ActiveSessionCount),
		runtimeObservationFieldBackendID:         strings.TrimSpace(record.BackendIdentifier),
		runtimeObservationFieldBackendPool:       strings.TrimSpace(record.BackendPool),
		runtimeObservationFieldProtocol:          strings.TrimSpace(record.Protocol),
		runtimeObservationFieldRuntimeGeneration: strings.TrimSpace(record.Generation),
		runtimeObservationFieldRuntimeStatus:     strings.TrimSpace(record.Status),
		runtimeObservationFieldServerTime:        boolAuditValue(!record.ServerTime.IsZero()),
		runtimeObservationFieldShardTag:          strings.TrimSpace(record.ShardTag),
		auditFieldStrategy:                       strings.TrimSpace(record.Strategy),
		runtimeObservationFieldUserHash:          strings.TrimSpace(record.Key.AccountKey),
	}

	recordRuntimeObservation(ctx, s.recorder, observability.EventUserBackendPin, observability.TraceBoundaryRESTRequest, operation, result, reasonClass, eventFields, nil)
}
