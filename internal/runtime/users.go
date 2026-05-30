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
