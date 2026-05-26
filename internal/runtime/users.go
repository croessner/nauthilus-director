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
	"time"

	"github.com/croessner/nauthilus-director/internal/state"
)

const (
	operationUserAffinityClear = "user_affinity_clear"
	operationUserKick          = "user_kick"
	operationUserMove          = "user_move"
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

// UserMutationResult describes a runtime user mutation outcome.
type UserMutationResult struct {
	State UserRuntimeState
	Audit AuditMetadata
}

// UserStateStore persists Redis-backed user runtime operations.
type UserStateStore interface {
	MoveUser(ctx context.Context, request state.UserMoveRequest) (state.UserRuntimeRecord, error)
	KickUser(ctx context.Context, request state.UserKickRequest) (state.UserRuntimeRecord, error)
	ClearUserAffinity(ctx context.Context, request state.UserClearRequest) (state.UserRuntimeRecord, error)
}

// UserService coordinates user runtime operations with local session acceleration.
type UserService struct {
	store UserStateStore
	local *LocalSessionRegistry
}

// NewUserService creates the runtime user operation service.
func NewUserService(store UserStateStore, local *LocalSessionRegistry) *UserService {
	return &UserService{store: store, local: local}
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

// boolAuditValue serializes booleans for audit metadata.
func boolAuditValue(value bool) string {
	if value {
		return auditValueTrue
	}

	return auditValueFalse
}
