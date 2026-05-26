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
	"strings"
	"time"
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

// validMoveStrategy reports whether a strategy matches the public runtime vocabulary.
func validMoveStrategy(strategy MoveStrategy) bool {
	switch MoveStrategy(strings.TrimSpace(string(strategy))) {
	case MoveStrategyNewSessionsOnly, MoveStrategyKickExisting, MoveStrategyDrainExisting:
		return true
	default:
		return false
	}
}
