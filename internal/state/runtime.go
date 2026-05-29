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

package state

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	scriptBackendRuntimeClear = "backend_runtime_clear"
	scriptBackendRuntimeSet   = "backend_runtime_set"
	scriptClear               = "clear"
	scriptKick                = "kick"
	scriptMove                = "move"
	scriptSessionKill         = "session_kill"

	moveStrategyDrainExisting   = "drain_existing"
	moveStrategyKickExisting    = "kick_existing"
	moveStrategyNewSessionsOnly = "new_sessions_only"
)

// MoveUser records a user move strategy in Redis-backed affinity runtime state.
func (s *RedisSessionStore) MoveUser(ctx context.Context, request UserMoveRequest) (UserRuntimeRecord, error) {
	if err := validateUserMoveRequest(request); err != nil {
		return UserRuntimeRecord{}, err
	}

	keys, err := s.keys.AffinityKeys(request.Key.Tenant, request.Key.AccountKey)
	if err != nil {
		return UserRuntimeRecord{}, err
	}

	value, err := s.runScript(ctx, scriptMove, s.moveUserScriptKeys(keys),
		normalizedStateValue(request.TargetShard),
		normalizedStateValue(request.Strategy),
		normalizedStateValue(request.Reason),
		normalizedStateValue(request.Actor),
	)
	if err != nil {
		return UserRuntimeRecord{}, err
	}

	return parseUserRuntimeRecord(request.Key, value)
}

// KickUser marks active sessions for one affinity key for heartbeat-observed closure.
func (s *RedisSessionStore) KickUser(ctx context.Context, request UserKickRequest) (UserRuntimeRecord, error) {
	if err := validateUserAction(request.Key, request.Reason, scriptKick); err != nil {
		return UserRuntimeRecord{}, err
	}

	keys, err := s.keys.AffinityKeys(request.Key.Tenant, request.Key.AccountKey)
	if err != nil {
		return UserRuntimeRecord{}, err
	}

	value, err := s.runScript(ctx, scriptKick, s.kickUserScriptKeys(keys),
		normalizedStateValue(request.Reason),
		normalizedStateValue(request.Actor),
	)
	if err != nil {
		return UserRuntimeRecord{}, err
	}

	return parseUserRuntimeRecord(request.Key, value)
}

// ClearUserAffinity clears inactive affinity and pending override state.
func (s *RedisSessionStore) ClearUserAffinity(ctx context.Context, request UserClearRequest) (UserRuntimeRecord, error) {
	if err := validateUserAction(request.Key, request.Reason, scriptClear); err != nil {
		return UserRuntimeRecord{}, err
	}

	keys, err := s.keys.AffinityKeys(request.Key.Tenant, request.Key.AccountKey)
	if err != nil {
		return UserRuntimeRecord{}, err
	}

	allowActive := "0"
	if request.AllowActiveClear {
		allowActive = "1"
	}

	value, err := s.runScript(ctx, scriptClear, s.clearUserAffinityScriptKeys(keys),
		allowActive,
		normalizedStateValue(request.Reason),
		normalizedStateValue(request.Actor),
	)
	if err != nil {
		return UserRuntimeRecord{}, err
	}

	return parseUserRuntimeRecord(request.Key, value)
}

// KillSession marks one indexed session for heartbeat-observed closure.
func (s *RedisSessionStore) KillSession(ctx context.Context, request SessionKillRequest) (SessionKillRecord, error) {
	if strings.TrimSpace(request.SessionID) == "" {
		return SessionKillRecord{}, newStateError(RedisErrorKindAmbiguousState, scriptSessionKill, "session id required", nil)
	}

	if strings.TrimSpace(request.Reason) == "" {
		return SessionKillRecord{}, newStateError(RedisErrorKindAmbiguousState, scriptSessionKill, "reason required", nil)
	}

	sessionIndexKey, err := s.keys.SessionIndexShardKey(request.SessionID)
	if err != nil {
		return SessionKillRecord{}, err
	}

	value, err := s.runScript(ctx, scriptSessionKill, []string{sessionIndexKey},
		normalizedStateValue(request.SessionID),
		normalizedStateValue(request.Reason),
		normalizedStateValue(request.Actor),
	)
	if err != nil {
		return SessionKillRecord{}, err
	}

	return parseSessionKillRecord(value)
}

// SetBackendRuntime stores backend runtime overrides and marks affected sessions.
func (s *RedisSessionStore) SetBackendRuntime(
	ctx context.Context,
	mutation BackendRuntimeMutation,
) (BackendRuntimeRecord, error) {
	if err := validateBackendRuntimeMutation(mutation); err != nil {
		return BackendRuntimeRecord{}, err
	}

	backendRuntimeKey, _, err := s.backendRuntimeKeys(mutation.BackendIdentifier)
	if err != nil {
		return BackendRuntimeRecord{}, err
	}

	value, err := s.runScript(ctx, scriptBackendRuntimeSet, []string{
		backendRuntimeKey,
		s.keys.BackendIndexKey(),
	},
		normalizedStateValue(mutation.BackendIdentifier),
		optionalBool(mutation.InService),
		optionalInt(mutation.Weight),
		normalizedStateValue(mutation.MaintenanceMode),
		boolString(mutation.DrainEnabled),
		normalizedStateValue(mutation.DrainMode),
		normalizedStateValue(mutation.Reason),
		normalizedStateValue(mutation.Actor),
	)
	if err != nil {
		return BackendRuntimeRecord{}, err
	}

	record, err := parseBackendRuntimeRecord(value)
	if err != nil {
		return BackendRuntimeRecord{}, err
	}

	if backendRuntimeMutationMarksSessions(mutation) {
		marked, markErr := s.markBackendRuntimeSessions(ctx, mutation.BackendIdentifier)
		if markErr != nil {
			return BackendRuntimeRecord{}, markErr
		}

		record.MarkedSessionCount = marked
	}

	return record, nil
}

// ClearBackendRuntime removes runtime-only backend overrides without touching counts.
func (s *RedisSessionStore) ClearBackendRuntime(
	ctx context.Context,
	request BackendRuntimeClearRequest,
) (BackendRuntimeRecord, error) {
	if strings.TrimSpace(request.BackendIdentifier) == "" {
		return BackendRuntimeRecord{}, newStateError(RedisErrorKindAmbiguousState, scriptBackendRuntimeClear, "backend id required", nil)
	}

	if strings.TrimSpace(request.Reason) == "" {
		return BackendRuntimeRecord{}, newStateError(RedisErrorKindAmbiguousState, scriptBackendRuntimeClear, "reason required", nil)
	}

	backendRuntimeKey, _, err := s.backendRuntimeKeys(request.BackendIdentifier)
	if err != nil {
		return BackendRuntimeRecord{}, err
	}

	value, err := s.runScript(ctx, scriptBackendRuntimeClear, []string{backendRuntimeKey, s.keys.BackendIndexKey()},
		normalizedStateValue(request.BackendIdentifier),
		normalizedStateValue(request.Reason),
		normalizedStateValue(request.Actor),
	)
	if err != nil {
		return BackendRuntimeRecord{}, err
	}

	return parseBackendRuntimeRecord(value)
}

// moveUserScriptKeys returns the same-slot key list for user move mutations.
func (s *RedisSessionStore) moveUserScriptKeys(keys AffinityKeys) []string {
	return []string{keys.State, keys.Sessions, keys.Override}
}

// kickUserScriptKeys returns the same-slot key list for user kick mutations.
func (s *RedisSessionStore) kickUserScriptKeys(keys AffinityKeys) []string {
	return []string{keys.State, keys.Sessions}
}

// clearUserAffinityScriptKeys returns the same-slot key list for affinity clears.
func (s *RedisSessionStore) clearUserAffinityScriptKeys(keys AffinityKeys) []string {
	return []string{keys.State, keys.Sessions, keys.Override}
}

// backendRuntimeKeys returns the runtime state and membership index for a backend.
func (s *RedisSessionStore) backendRuntimeKeys(backendIdentifier string) (string, string, error) {
	backendRuntimeKey, err := s.keys.BackendRuntimeKey(backendIdentifier)
	if err != nil {
		return "", "", err
	}

	backendSessionIndexKey, err := s.keys.BackendSessionIndexKey(backendIdentifier)
	if err != nil {
		return "", "", err
	}

	return backendRuntimeKey, backendSessionIndexKey, nil
}

// backendRuntimeMutationMarksSessions reports whether active streams must observe drain.
func backendRuntimeMutationMarksSessions(mutation BackendRuntimeMutation) bool {
	if strings.EqualFold(strings.TrimSpace(mutation.MaintenanceMode), "hard") {
		return true
	}

	return mutation.DrainEnabled
}

// markBackendRuntimeSessions applies heartbeat-observed drain to indexed backend sessions.
func (s *RedisSessionStore) markBackendRuntimeSessions(ctx context.Context, backendIdentifier string) (int, error) {
	indexKeys, err := s.keys.BackendSessionIndexShardKeys(backendIdentifier)
	if err != nil {
		return 0, err
	}

	redisCtx := redisContext(ctx)
	total := 0

	for _, indexKey := range indexKeys {
		cursor := uint64(0)

		for {
			started := time.Now()

			sessionIDs, next, scanErr := s.client.SScan(redisCtx, indexKey, cursor, "*", int64(s.indexPageMax)).Result()
			if scanErr != nil {
				classified := ClassifyRedisError(scriptBackendRuntimeSet, scanErr)
				s.recordRedisOperation(redisCtx, "backend_session_index_scan", started, classified)

				return total, classified
			}

			s.recordRedisOperation(redisCtx, "backend_session_index_scan", started, nil)

			for _, sessionID := range sessionIDs {
				marked, markErr := s.markBackendRuntimeSession(ctx, indexKey, sessionID)
				if markErr != nil {
					return total, markErr
				}

				if marked {
					total++
				}
			}

			if next == 0 {
				break
			}

			cursor = next
		}
	}

	return total, nil
}

// markBackendRuntimeSession marks one indexed session or removes stale membership.
//
//nolint:gocyclo,funlen // The repair path keeps locator, existence and generation handling together.
func (s *RedisSessionStore) markBackendRuntimeSession(ctx context.Context, backendSessionsKey string, sessionID string) (bool, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return false, nil
	}

	sessionIndexKey, err := s.keys.SessionIndexShardKey(sessionID)
	if err != nil {
		return false, err
	}

	redisCtx := redisContext(ctx)
	started := time.Now()

	sessionKey, err := s.client.HGet(redisCtx, sessionIndexKey, sessionID).Result()
	if errors.Is(err, redis.Nil) {
		s.recordRedisOperation(redisCtx, "backend_session_locator_get", started, nil)
		s.removeStaleBackendSessionIndex(ctx, backendSessionsKey, sessionID)

		return false, nil
	}

	if err != nil {
		classified := ClassifyRedisError(scriptBackendRuntimeSet, err)
		s.recordRedisOperation(redisCtx, "backend_session_locator_get", started, classified)

		return false, classified
	}

	s.recordRedisOperation(redisCtx, "backend_session_locator_get", started, nil)

	if strings.TrimSpace(sessionKey) == "" {
		s.removeStaleBackendSessionIndex(ctx, backendSessionsKey, sessionID)

		return false, nil
	}

	exists, err := s.client.Exists(redisCtx, sessionKey).Result()
	if err != nil {
		classified := ClassifyRedisError(scriptBackendRuntimeSet, err)
		s.recordRedisOperation(redisCtx, "backend_session_exists", time.Now(), classified)

		return false, classified
	}

	if exists == 0 {
		s.removeStaleBackendSessionIndex(ctx, backendSessionsKey, sessionID)
		s.removeStaleSessionLocator(ctx, sessionIndexKey, sessionID)

		return false, nil
	}

	observed, err := s.client.HGet(redisCtx, sessionKey, scriptFieldControlGeneration).Result()
	if errors.Is(err, redis.Nil) {
		observed = "0"
	} else if err != nil {
		classified := ClassifyRedisError(scriptBackendRuntimeSet, err)
		s.recordRedisOperation(redisCtx, "backend_session_generation_get", time.Now(), classified)

		return false, classified
	}

	generation, err := strconv.Atoi(strings.TrimSpace(observed))
	if err != nil || generation < 0 {
		return false, newStateError(RedisErrorKindAmbiguousState, scriptBackendRuntimeSet, "session control generation invalid", err)
	}

	started = time.Now()

	err = s.client.HSet(redisCtx, sessionKey,
		"session_control_generation", generation+1,
		"session_control_action", "drain",
	).Err()
	if err != nil {
		classified := ClassifyRedisError(scriptBackendRuntimeSet, err)
		s.recordRedisOperation(redisCtx, "backend_session_mark", started, classified)

		return false, classified
	}

	s.recordRedisOperation(redisCtx, "backend_session_mark", started, nil)

	return true, nil
}

// removeStaleBackendSessionIndex removes one stale backend membership entry.
func (s *RedisSessionStore) removeStaleBackendSessionIndex(ctx context.Context, backendSessionsKey string, sessionID string) {
	s.runRepairableIndexCommand(ctx, "backend_session_index_stale_remove", func(redisCtx context.Context) error {
		return s.client.SRem(redisCtx, backendSessionsKey, sessionID).Err()
	})
}

// removeStaleSessionLocator removes one stale session locator entry.
func (s *RedisSessionStore) removeStaleSessionLocator(ctx context.Context, sessionIndexKey string, sessionID string) {
	s.runRepairableIndexCommand(ctx, "session_index_stale_remove", func(redisCtx context.Context) error {
		return s.client.HDel(redisCtx, sessionIndexKey, sessionID).Err()
	})
}

// validateUserMoveRequest rejects ambiguous move payloads before Redis mutation.
func validateUserMoveRequest(request UserMoveRequest) error {
	if err := validateAffinityKey(request.Key, scriptMove); err != nil {
		return err
	}

	if strings.TrimSpace(request.TargetShard) == "" {
		return newStateError(RedisErrorKindAmbiguousState, scriptMove, "target shard required", nil)
	}

	switch strings.TrimSpace(request.Strategy) {
	case moveStrategyNewSessionsOnly, moveStrategyKickExisting, moveStrategyDrainExisting:
	default:
		return newStateError(RedisErrorKindAmbiguousState, scriptMove, "strategy invalid", nil)
	}

	if strings.TrimSpace(request.Reason) == "" {
		return newStateError(RedisErrorKindAmbiguousState, scriptMove, "reason required", nil)
	}

	return nil
}

// validateUserAction checks common user mutation fields.
func validateUserAction(key AffinityKey, reason string, operation string) error {
	if err := validateAffinityKey(key, operation); err != nil {
		return err
	}

	if strings.TrimSpace(reason) == "" {
		return newStateError(RedisErrorKindAmbiguousState, operation, "reason required", nil)
	}

	return nil
}

// validateAffinityKey rejects user operations that cannot build private keys.
func validateAffinityKey(key AffinityKey, operation string) error {
	if strings.TrimSpace(key.Tenant) == "" {
		return newStateError(RedisErrorKindAmbiguousState, operation, "tenant required", nil)
	}

	if strings.TrimSpace(key.AccountKey) == "" {
		return newStateError(RedisErrorKindAmbiguousState, operation, "account key required", nil)
	}

	return nil
}

// validateBackendRuntimeMutation rejects ambiguous backend runtime payloads.
func validateBackendRuntimeMutation(mutation BackendRuntimeMutation) error {
	if strings.TrimSpace(mutation.BackendIdentifier) == "" {
		return newStateError(RedisErrorKindAmbiguousState, scriptBackendRuntimeSet, "backend id required", nil)
	}

	if strings.TrimSpace(mutation.Reason) == "" {
		return newStateError(RedisErrorKindAmbiguousState, scriptBackendRuntimeSet, "reason required", nil)
	}

	if mutation.InService == nil && mutation.Weight == nil && strings.TrimSpace(mutation.MaintenanceMode) == "" && !mutation.DrainEnabled {
		return newStateError(RedisErrorKindAmbiguousState, scriptBackendRuntimeSet, "runtime mutation required", nil)
	}

	return nil
}

// parseUserRuntimeRecord converts a user operation script result.
func parseUserRuntimeRecord(key AffinityKey, value any) (UserRuntimeRecord, error) {
	fields, err := parseScriptFields(value)
	if err != nil {
		return UserRuntimeRecord{}, err
	}

	action, err := parseOptionalControlAction(fields["control_action"])
	if err != nil {
		return UserRuntimeRecord{}, err
	}

	record := UserRuntimeRecord{
		Status:        fields["status"],
		Key:           key,
		ShardTag:      fields["shard_tag"],
		TargetShard:   fields["target_shard"],
		Strategy:      fields["strategy"],
		Generation:    fields["generation"],
		ControlAction: action,
	}

	if record.Status == "" {
		return UserRuntimeRecord{}, newStateError(RedisErrorKindAmbiguousState, "script_result", "status required", nil)
	}

	record.ActiveSessionCount, err = parseIntField(fields, "active_session_count")
	if err != nil {
		return UserRuntimeRecord{}, err
	}

	record.ServerTime, err = parseTimeField(fields, "server_time_ms")
	if err != nil {
		return UserRuntimeRecord{}, err
	}

	return record, nil
}

// parseSessionKillRecord converts a session kill script result.
func parseSessionKillRecord(value any) (SessionKillRecord, error) {
	fields, err := parseScriptFields(value)
	if err != nil {
		return SessionKillRecord{}, err
	}

	action, err := parseOptionalControlAction(fields["control_action"])
	if err != nil {
		return SessionKillRecord{}, err
	}

	record := SessionKillRecord{
		Status:            fields["status"],
		SessionID:         fields["session_id"],
		ControlAction:     action,
		ControlGeneration: fields["control_generation"],
	}

	if record.Status == "" {
		return SessionKillRecord{}, newStateError(RedisErrorKindAmbiguousState, "script_result", "status required", nil)
	}

	if record.SessionID == "" {
		return SessionKillRecord{}, newStateError(RedisErrorKindAmbiguousState, "script_result", "session id required", nil)
	}

	record.ServerTime, err = parseTimeField(fields, "server_time_ms")
	if err != nil {
		return SessionKillRecord{}, err
	}

	return record, nil
}

// parseBackendRuntimeRecord converts backend runtime script output.
func parseBackendRuntimeRecord(value any) (BackendRuntimeRecord, error) {
	parsed, err := parseBackendScriptFields(value)
	if err != nil {
		return BackendRuntimeRecord{}, err
	}

	record := BackendRuntimeRecord{
		Status:            parsed.Status,
		BackendIdentifier: parsed.BackendIdentifier,
		Generation:        parsed.Fields["generation"],
		ServerTime:        parsed.ServerTime,
	}

	record.ActiveSessionCount, err = parseIntField(parsed.Fields, "active_session_count")
	if err != nil {
		return BackendRuntimeRecord{}, err
	}

	record.MarkedSessionCount, err = parseIntField(parsed.Fields, "marked_session_count")
	if err != nil {
		return BackendRuntimeRecord{}, err
	}

	return record, nil
}

// optionalBool serializes optional booleans for Lua arguments.
func optionalBool(value *bool) string {
	if value == nil {
		return ""
	}

	return boolString(*value)
}

// optionalInt serializes optional integers for Lua arguments.
func optionalInt(value *int) string {
	if value == nil {
		return ""
	}

	return strconv.Itoa(*value)
}

// boolString serializes a boolean using script vocabulary.
func boolString(value bool) string {
	if value {
		return stateBoolTrue
	}

	return stateBoolFalse
}
