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
	"sort"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const operationRuntimeRead = "runtime_read"

// ListRuntimeSessions returns active sessions from repairable Redis indexes.
func (s *RedisSessionStore) ListRuntimeSessions(ctx context.Context, protocol string) ([]RuntimeSessionRecord, error) {
	redisCtx := redisContext(ctx)
	started := time.Now()

	entries, err := s.client.HGetAll(redisCtx, s.keys.SessionIndexKey()).Result()
	if err != nil {
		classified := ClassifyRedisError(operationRuntimeRead, err)
		s.recordRedisOperation(redisCtx, "runtime_session_list", started, classified)

		return nil, classified
	}

	s.recordRedisOperation(redisCtx, "runtime_session_list", started, nil)

	protocol = strings.ToLower(strings.TrimSpace(protocol))

	records := make([]RuntimeSessionRecord, 0, len(entries))
	for sessionID, sessionKey := range entries {
		record, ok, readErr := s.readRuntimeSession(ctx, sessionID, sessionKey)
		if readErr != nil {
			return nil, readErr
		}

		if !ok || (protocol != "" && record.Protocol != protocol) {
			continue
		}

		records = append(records, record)
	}

	sortRuntimeSessions(records)

	return records, nil
}

// GetRuntimeSession returns one active session from the Redis session index.
func (s *RedisSessionStore) GetRuntimeSession(ctx context.Context, sessionID string) (RuntimeSessionRecord, bool, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return RuntimeSessionRecord{}, false, newStateError(RedisErrorKindAmbiguousState, operationRuntimeRead, "session id required", nil)
	}

	redisCtx := redisContext(ctx)
	started := time.Now()

	sessionKey, err := s.client.HGet(redisCtx, s.keys.SessionIndexKey(), sessionID).Result()
	if errors.Is(err, redis.Nil) {
		s.recordRedisOperation(redisCtx, "runtime_session_get", started, nil)

		return RuntimeSessionRecord{}, false, nil
	}

	if err != nil {
		classified := ClassifyRedisError(operationRuntimeRead, err)
		s.recordRedisOperation(redisCtx, "runtime_session_get", started, classified)

		return RuntimeSessionRecord{}, false, classified
	}

	s.recordRedisOperation(redisCtx, "runtime_session_get", started, nil)

	return s.readRuntimeSession(ctx, sessionID, sessionKey)
}

// ListRuntimeSessionsForUser returns active sessions indexed for one affinity key.
func (s *RedisSessionStore) ListRuntimeSessionsForUser(ctx context.Context, key AffinityKey) ([]RuntimeSessionRecord, error) {
	userSessionsKey, err := s.keys.UserSessionIndexKey(key.Tenant, key.AccountKey)
	if err != nil {
		return nil, err
	}

	redisCtx := redisContext(ctx)
	started := time.Now()

	sessionIDs, err := s.client.SMembers(redisCtx, userSessionsKey).Result()
	if err != nil {
		classified := ClassifyRedisError(operationRuntimeRead, err)
		s.recordRedisOperation(redisCtx, "runtime_user_sessions_list", started, classified)

		return nil, classified
	}

	s.recordRedisOperation(redisCtx, "runtime_user_sessions_list", started, nil)

	records := make([]RuntimeSessionRecord, 0, len(sessionIDs))
	for _, sessionID := range sessionIDs {
		record, ok, readErr := s.GetRuntimeSession(ctx, sessionID)
		if readErr != nil {
			return nil, readErr
		}

		if ok {
			records = append(records, record)
		}
	}

	sortRuntimeSessions(records)

	return records, nil
}

// ListRuntimeUsers derives user runtime views from active Redis session records.
func (s *RedisSessionStore) ListRuntimeUsers(ctx context.Context) ([]RuntimeUserReadRecord, error) {
	sessions, err := s.ListRuntimeSessions(ctx, "")
	if err != nil {
		return nil, err
	}

	groups := make(map[AffinityKey]RuntimeUserReadRecord)

	for _, session := range sessions {
		key := session.Key
		record := groups[key]
		record.Key = key
		record.ShardTag = firstNonEmptyState(record.ShardTag, session.ShardTag)
		record.ActiveSessionCount++
		record.Present = true
		groups[key] = record
	}

	records := make([]RuntimeUserReadRecord, 0, len(groups))
	for key, fallback := range groups {
		record, ok, readErr := s.GetRuntimeUser(ctx, key)
		if readErr != nil {
			return nil, readErr
		}

		if !ok {
			record = fallback
		}

		records = append(records, record)
	}

	sort.Slice(records, func(left int, right int) bool {
		if records[left].Key.Tenant == records[right].Key.Tenant {
			return records[left].Key.AccountKey < records[right].Key.AccountKey
		}

		return records[left].Key.Tenant < records[right].Key.Tenant
	})

	return records, nil
}

// GetRuntimeUser reads one affinity record without refreshing session leases.
func (s *RedisSessionStore) GetRuntimeUser(ctx context.Context, key AffinityKey) (RuntimeUserReadRecord, bool, error) {
	record, err := s.LookupAffinity(ctx, key)
	if err != nil {
		return RuntimeUserReadRecord{}, false, err
	}

	if !record.Present {
		return RuntimeUserReadRecord{}, false, nil
	}

	return RuntimeUserReadRecord{
		Key:                key,
		ShardTag:           record.ShardTag,
		ActiveSessionCount: record.ActiveSessionCount,
		Generation:         record.Generation,
		UpdatedAt:          record.ServerTime,
		Present:            true,
	}, true, nil
}

// readRuntimeSession reads one indexed session hash without repairing indexes.
func (s *RedisSessionStore) readRuntimeSession(ctx context.Context, sessionID string, sessionKey string) (RuntimeSessionRecord, bool, error) {
	sessionKey = strings.TrimSpace(sessionKey)
	if sessionKey == "" {
		return RuntimeSessionRecord{}, false, nil
	}

	redisCtx := redisContext(ctx)
	started := time.Now()

	fields, err := s.client.HGetAll(redisCtx, sessionKey).Result()
	if err != nil {
		classified := ClassifyRedisError(operationRuntimeRead, err)
		s.recordRedisOperation(redisCtx, "runtime_session_read", started, classified)

		return RuntimeSessionRecord{}, false, classified
	}

	s.recordRedisOperation(redisCtx, "runtime_session_read", started, nil)

	if len(fields) == 0 {
		return RuntimeSessionRecord{}, false, nil
	}

	record, err := parseRuntimeSessionFields(sessionID, fields)
	if err != nil {
		return RuntimeSessionRecord{}, false, err
	}

	if strings.EqualFold(strings.TrimSpace(fields["holder_kind"]), HolderKindDelivery) {
		return RuntimeSessionRecord{}, false, nil
	}

	return record, true, nil
}

// parseRuntimeSessionFields converts a Redis session hash into a control-read record.
func parseRuntimeSessionFields(sessionID string, fields map[string]string) (RuntimeSessionRecord, error) {
	record := RuntimeSessionRecord{
		SessionID:         firstNonEmptyState(fields["session_id"], strings.TrimSpace(sessionID)),
		Key:               AffinityKey{Tenant: fields["tenant"], AccountKey: fields["account_key"]},
		Protocol:          strings.ToLower(strings.TrimSpace(fields["protocol"])),
		ListenerName:      strings.TrimSpace(fields["listener_name"]),
		ServiceName:       strings.TrimSpace(fields["service_name"]),
		ShardTag:          strings.TrimSpace(fields["shard_tag"]),
		BackendIdentifier: strings.TrimSpace(fields["selected_backend_id"]),
		DirectorInstance:  strings.TrimSpace(fields["director_instance_id"]),
		ControlGeneration: strings.TrimSpace(fields["control_generation"]),
		Status:            runtimeSessionStatus(fields),
	}

	if record.SessionID == "" {
		return RuntimeSessionRecord{}, newStateError(RedisErrorKindAmbiguousState, operationRuntimeRead, "session id required", nil)
	}

	if record.Key.Tenant == "" {
		return RuntimeSessionRecord{}, newStateError(RedisErrorKindAmbiguousState, operationRuntimeRead, "tenant required", nil)
	}

	if record.Key.AccountKey == "" {
		record.Key.AccountKey = strings.TrimSpace(fields["affinity_hash"])
	}

	if record.Protocol == "" {
		return RuntimeSessionRecord{}, newStateError(RedisErrorKindAmbiguousState, operationRuntimeRead, "protocol required", nil)
	}

	if record.ShardTag == "" {
		return RuntimeSessionRecord{}, newStateError(RedisErrorKindAmbiguousState, operationRuntimeRead, "shard tag required", nil)
	}

	var err error

	record.OpenedAt, err = parseRuntimeTimeField(fields, "opened_at_ms")
	if err != nil {
		return RuntimeSessionRecord{}, err
	}

	record.LeaseExpiresAt, err = parseRuntimeTimeField(fields, "lease_expires_at_ms")
	if err != nil {
		return RuntimeSessionRecord{}, err
	}

	return record, nil
}

// runtimeSessionStatus reports whether a session is active or awaiting control closure.
func runtimeSessionStatus(fields map[string]string) string {
	if strings.TrimSpace(fields["session_control_action"]) != "" && strings.TrimSpace(fields["session_control_action"]) != string(ControlActionNone) {
		return "closing"
	}

	return firstNonEmptyState(strings.TrimSpace(fields["status"]), "active")
}

// parseRuntimeTimeField reads a required millisecond timestamp from session hashes.
func parseRuntimeTimeField(fields map[string]string, name string) (time.Time, error) {
	value, ok := fields[name]
	if !ok {
		return time.Time{}, newStateError(RedisErrorKindAmbiguousState, operationRuntimeRead, name+" required", nil)
	}

	return parseTimeField(map[string]string{name: value}, name)
}

// sortRuntimeSessions orders sessions for deterministic REST and CLI output.
func sortRuntimeSessions(records []RuntimeSessionRecord) {
	sort.Slice(records, func(left int, right int) bool {
		return records[left].SessionID < records[right].SessionID
	})
}

// firstNonEmptyState returns the first non-empty string after trimming whitespace.
func firstNonEmptyState(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}

	return ""
}
