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
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const operationRuntimeRead = "runtime_read"

const (
	runtimeReadCursorVersion   = 1
	runtimeReadFamilySessions  = "sessions"
	runtimeReadFamilyUser      = "user_sessions"
	runtimeReadFamilyBackend   = "backend_sessions"
	runtimeReadFamilyUsers     = "users"
	runtimeReadUserIndexFields = 2
)

// RuntimeSessionPageRequest describes one bounded runtime session index read.
type RuntimeSessionPageRequest struct {
	Protocol string
	Limit    int
	Cursor   string
}

// RuntimeSessionPage contains one bounded runtime session page.
type RuntimeSessionPage struct {
	Records    []RuntimeSessionRecord
	NextCursor string
}

// RuntimeUserPageRequest describes one bounded runtime user index read.
type RuntimeUserPageRequest struct {
	Limit  int
	Cursor string
}

// RuntimeUserPage contains one bounded runtime user page.
type RuntimeUserPage struct {
	Records    []RuntimeUserReadRecord
	NextCursor string
}

type runtimeReadCursor struct {
	Version     int    `json:"v"`
	Family      string `json:"f"`
	Shard       int    `json:"s"`
	RedisCursor uint64 `json:"c"`
}

// ListRuntimeSessions returns active sessions from repairable Redis indexes.
func (s *RedisSessionStore) ListRuntimeSessions(ctx context.Context, protocol string) ([]RuntimeSessionRecord, error) {
	page, err := s.ListRuntimeSessionsPage(ctx, RuntimeSessionPageRequest{Protocol: protocol, Limit: s.defaultRuntimeIndexPageLimit()})
	if err != nil {
		return nil, err
	}

	sortRuntimeSessions(page.Records)

	return page.Records, nil
}

// ListRuntimeSessionsPage returns a bounded page from sharded session locators.
//
//nolint:gocyclo,funlen // The cursor walk keeps shard, stale-index repair and filtering together.
func (s *RedisSessionStore) ListRuntimeSessionsPage(ctx context.Context, request RuntimeSessionPageRequest) (RuntimeSessionPage, error) {
	cursor, err := s.decodeRuntimeReadCursor(request.Cursor, runtimeReadFamilySessions, s.keys.sessionIndexShards)
	if err != nil {
		return RuntimeSessionPage{}, err
	}

	limit := s.runtimeReadLimit(request.Limit)
	protocol := strings.ToLower(strings.TrimSpace(request.Protocol))
	records := make([]RuntimeSessionRecord, 0, limit)
	redisCtx := redisContext(ctx)

	for shard := cursor.Shard; shard < s.keys.sessionIndexShards && len(records) < limit; shard++ {
		scanCursor := uint64(0)
		if shard == cursor.Shard {
			scanCursor = cursor.RedisCursor
		}

		indexKey, keyErr := s.keys.SessionIndexShardKeyByNumber(shard)
		if keyErr != nil {
			return RuntimeSessionPage{}, keyErr
		}

		started := time.Now()

		entries, next, scanErr := s.client.HScan(redisCtx, indexKey, scanCursor, "*", int64(limit)).Result()
		if scanErr != nil {
			classified := ClassifyRedisError(operationRuntimeRead, scanErr)
			s.recordRedisOperation(redisCtx, "runtime_session_index_scan", started, classified)

			return RuntimeSessionPage{}, classified
		}

		s.recordRedisOperation(redisCtx, "runtime_session_index_scan", started, nil)

		for index := 0; index+1 < len(entries); index += 2 {
			sessionID := entries[index]
			sessionKey := entries[index+1]

			record, visible, present, readErr := s.readRuntimeSession(ctx, sessionID, sessionKey)
			if readErr != nil {
				return RuntimeSessionPage{}, readErr
			}

			if !present {
				s.removeStaleSessionLocator(ctx, indexKey, sessionID)

				continue
			}

			if !visible || (protocol != "" && record.Protocol != protocol) {
				continue
			}

			records = append(records, record)
		}

		if next != 0 {
			return RuntimeSessionPage{
				Records:    records,
				NextCursor: s.encodeRuntimeReadCursor(runtimeReadFamilySessions, shard, next),
			}, nil
		}

		if len(records) >= limit && shard+1 < s.keys.sessionIndexShards {
			return RuntimeSessionPage{
				Records:    records,
				NextCursor: s.encodeRuntimeReadCursor(runtimeReadFamilySessions, shard+1, 0),
			}, nil
		}
	}

	return RuntimeSessionPage{Records: records}, nil
}

// GetRuntimeSession returns one active session from the Redis session index.
func (s *RedisSessionStore) GetRuntimeSession(ctx context.Context, sessionID string) (RuntimeSessionRecord, bool, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return RuntimeSessionRecord{}, false, newStateError(RedisErrorKindAmbiguousState, operationRuntimeRead, "session id required", nil)
	}

	redisCtx := redisContext(ctx)
	started := time.Now()

	sessionIndexKey, err := s.keys.SessionIndexShardKey(sessionID)
	if err != nil {
		return RuntimeSessionRecord{}, false, err
	}

	sessionKey, err := s.client.HGet(redisCtx, sessionIndexKey, sessionID).Result()
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

	record, visible, present, err := s.readRuntimeSession(ctx, sessionID, sessionKey)
	if err != nil || !present || !visible {
		return RuntimeSessionRecord{}, false, err
	}

	return record, true, nil
}

// ListRuntimeSessionsForUser returns active sessions indexed for one affinity key.
func (s *RedisSessionStore) ListRuntimeSessionsForUser(ctx context.Context, key AffinityKey) ([]RuntimeSessionRecord, error) {
	page, err := s.ListRuntimeSessionsForUserPage(ctx, key, RuntimeSessionPageRequest{Limit: s.defaultRuntimeIndexPageLimit()})
	if err != nil {
		return nil, err
	}

	sortRuntimeSessions(page.Records)

	return page.Records, nil
}

// ListRuntimeSessionsForUserPage returns a bounded page from sharded user membership.
func (s *RedisSessionStore) ListRuntimeSessionsForUserPage(
	ctx context.Context,
	key AffinityKey,
	request RuntimeSessionPageRequest,
) (RuntimeSessionPage, error) {
	indexKeys, err := s.keys.UserSessionIndexShardKeys(key.Tenant, key.AccountKey)
	if err != nil {
		return RuntimeSessionPage{}, err
	}

	return s.listRuntimeSessionSetPage(ctx, indexKeys, runtimeReadFamilyUser, request)
}

// ListRuntimeSessionsForBackendPage returns a bounded page from sharded backend membership.
func (s *RedisSessionStore) ListRuntimeSessionsForBackendPage(
	ctx context.Context,
	backendIdentifier string,
	request RuntimeSessionPageRequest,
) (RuntimeSessionPage, error) {
	indexKeys, err := s.keys.BackendSessionIndexShardKeys(backendIdentifier)
	if err != nil {
		return RuntimeSessionPage{}, err
	}

	return s.listRuntimeSessionSetPage(ctx, indexKeys, runtimeReadFamilyBackend, request)
}

// ListRuntimeUsers derives user runtime views from active Redis session records.
func (s *RedisSessionStore) ListRuntimeUsers(ctx context.Context) ([]RuntimeUserReadRecord, error) {
	page, err := s.ListRuntimeUsersPage(ctx, RuntimeUserPageRequest{Limit: s.defaultRuntimeIndexPageLimit()})
	if err != nil {
		return nil, err
	}

	sort.Slice(page.Records, func(left int, right int) bool {
		if page.Records[left].Key.Tenant == page.Records[right].Key.Tenant {
			return page.Records[left].Key.AccountKey < page.Records[right].Key.AccountKey
		}

		return page.Records[left].Key.Tenant < page.Records[right].Key.Tenant
	})

	return page.Records, nil
}

// ListRuntimeUsersPage returns a bounded page from sharded user indexes.
//
//nolint:gocyclo,funlen // The cursor walk keeps user-index repair and page continuation together.
func (s *RedisSessionStore) ListRuntimeUsersPage(ctx context.Context, request RuntimeUserPageRequest) (RuntimeUserPage, error) {
	cursor, err := s.decodeRuntimeReadCursor(request.Cursor, runtimeReadFamilyUsers, s.keys.userIndexShards)
	if err != nil {
		return RuntimeUserPage{}, err
	}

	limit := s.runtimeReadLimit(request.Limit)
	records := make([]RuntimeUserReadRecord, 0, limit)
	redisCtx := redisContext(ctx)

	for shard := cursor.Shard; shard < s.keys.userIndexShards && len(records) < limit; shard++ {
		scanCursor := uint64(0)
		if shard == cursor.Shard {
			scanCursor = cursor.RedisCursor
		}

		indexKey, keyErr := s.keys.UserIndexShardKeyByNumber(shard)
		if keyErr != nil {
			return RuntimeUserPage{}, keyErr
		}

		started := time.Now()

		entries, next, scanErr := s.client.HScan(redisCtx, indexKey, scanCursor, "*", int64(limit)).Result()
		if scanErr != nil {
			classified := ClassifyRedisError(operationRuntimeRead, scanErr)
			s.recordRedisOperation(redisCtx, "runtime_user_index_scan", started, classified)

			return RuntimeUserPage{}, classified
		}

		s.recordRedisOperation(redisCtx, "runtime_user_index_scan", started, nil)

		for index := 0; index+1 < len(entries); index += 2 {
			key, parseErr := parseUserIndexValue(entries[index+1])
			if parseErr != nil {
				s.removeStaleUserIndex(ctx, indexKey, entries[index])

				continue
			}

			record, ok, readErr := s.GetRuntimeUser(ctx, key)
			if readErr != nil {
				return RuntimeUserPage{}, readErr
			}

			if !ok {
				s.removeStaleUserIndex(ctx, indexKey, entries[index])

				continue
			}

			records = append(records, record)
		}

		if next != 0 {
			return RuntimeUserPage{
				Records:    records,
				NextCursor: s.encodeRuntimeReadCursor(runtimeReadFamilyUsers, shard, next),
			}, nil
		}

		if len(records) >= limit && shard+1 < s.keys.userIndexShards {
			return RuntimeUserPage{
				Records:    records,
				NextCursor: s.encodeRuntimeReadCursor(runtimeReadFamilyUsers, shard+1, 0),
			}, nil
		}
	}

	return RuntimeUserPage{Records: records}, nil
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
func (s *RedisSessionStore) readRuntimeSession(ctx context.Context, sessionID string, sessionKey string) (RuntimeSessionRecord, bool, bool, error) {
	sessionKey = strings.TrimSpace(sessionKey)
	if sessionKey == "" {
		return RuntimeSessionRecord{}, false, false, nil
	}

	redisCtx := redisContext(ctx)
	started := time.Now()

	fields, err := s.client.HGetAll(redisCtx, sessionKey).Result()
	if err != nil {
		classified := ClassifyRedisError(operationRuntimeRead, err)
		s.recordRedisOperation(redisCtx, "runtime_session_read", started, classified)

		return RuntimeSessionRecord{}, false, false, classified
	}

	s.recordRedisOperation(redisCtx, "runtime_session_read", started, nil)

	if len(fields) == 0 {
		return RuntimeSessionRecord{}, false, false, nil
	}

	record, err := parseRuntimeSessionFields(sessionID, fields)
	if err != nil {
		return RuntimeSessionRecord{}, false, true, err
	}

	if strings.EqualFold(strings.TrimSpace(fields["holder_kind"]), HolderKindDelivery) {
		return RuntimeSessionRecord{}, false, true, nil
	}

	return record, true, true, nil
}

// listRuntimeSessionSetPage returns one bounded page from sharded set membership.
//
//nolint:gocyclo,funlen // The set cursor walk handles stale repair and visibility filtering atomically.
func (s *RedisSessionStore) listRuntimeSessionSetPage(
	ctx context.Context,
	indexKeys []string,
	family string,
	request RuntimeSessionPageRequest,
) (RuntimeSessionPage, error) {
	cursor, err := s.decodeRuntimeReadCursor(request.Cursor, family, len(indexKeys))
	if err != nil {
		return RuntimeSessionPage{}, err
	}

	limit := s.runtimeReadLimit(request.Limit)
	protocol := strings.ToLower(strings.TrimSpace(request.Protocol))
	records := make([]RuntimeSessionRecord, 0, limit)
	redisCtx := redisContext(ctx)

	for shard := cursor.Shard; shard < len(indexKeys) && len(records) < limit; shard++ {
		scanCursor := uint64(0)
		if shard == cursor.Shard {
			scanCursor = cursor.RedisCursor
		}

		started := time.Now()

		sessionIDs, next, scanErr := s.client.SScan(redisCtx, indexKeys[shard], scanCursor, "*", int64(limit)).Result()
		if scanErr != nil {
			classified := ClassifyRedisError(operationRuntimeRead, scanErr)
			s.recordRedisOperation(redisCtx, "runtime_session_membership_scan", started, classified)

			return RuntimeSessionPage{}, classified
		}

		s.recordRedisOperation(redisCtx, "runtime_session_membership_scan", started, nil)

		for _, sessionID := range sessionIDs {
			record, visible, present, readErr := s.readRuntimeSessionByID(ctx, sessionID)
			if readErr != nil {
				return RuntimeSessionPage{}, readErr
			}

			if !present {
				s.removeStaleSetMember(ctx, indexKeys[shard], sessionID)

				continue
			}

			if !visible || (protocol != "" && record.Protocol != protocol) {
				continue
			}

			records = append(records, record)
		}

		if next != 0 {
			return RuntimeSessionPage{
				Records:    records,
				NextCursor: s.encodeRuntimeReadCursor(family, shard, next),
			}, nil
		}

		if len(records) >= limit && shard+1 < len(indexKeys) {
			return RuntimeSessionPage{
				Records:    records,
				NextCursor: s.encodeRuntimeReadCursor(family, shard+1, 0),
			}, nil
		}
	}

	return RuntimeSessionPage{Records: records}, nil
}

// readRuntimeSessionByID resolves a sharded locator and reads one session hash.
func (s *RedisSessionStore) readRuntimeSessionByID(ctx context.Context, sessionID string) (RuntimeSessionRecord, bool, bool, error) {
	sessionIndexKey, err := s.keys.SessionIndexShardKey(sessionID)
	if err != nil {
		return RuntimeSessionRecord{}, false, false, err
	}

	redisCtx := redisContext(ctx)
	started := time.Now()

	sessionKey, err := s.client.HGet(redisCtx, sessionIndexKey, sessionID).Result()
	if errors.Is(err, redis.Nil) {
		s.recordRedisOperation(redisCtx, "runtime_session_get", started, nil)

		return RuntimeSessionRecord{}, false, false, nil
	}

	if err != nil {
		classified := ClassifyRedisError(operationRuntimeRead, err)
		s.recordRedisOperation(redisCtx, "runtime_session_get", started, classified)

		return RuntimeSessionRecord{}, false, false, classified
	}

	s.recordRedisOperation(redisCtx, "runtime_session_get", started, nil)

	record, visible, present, err := s.readRuntimeSession(ctx, sessionID, sessionKey)
	if !present {
		s.removeStaleSessionLocator(ctx, sessionIndexKey, sessionID)
	}

	return record, visible, present, err
}

// removeStaleSetMember removes one stale secondary membership entry.
func (s *RedisSessionStore) removeStaleSetMember(ctx context.Context, indexKey string, sessionID string) {
	s.runRepairableIndexCommand(ctx, "runtime_session_membership_stale_remove", func(redisCtx context.Context) error {
		return s.client.SRem(redisCtx, indexKey, sessionID).Err()
	})
}

// removeStaleUserIndex removes one stale user index entry.
func (s *RedisSessionStore) removeStaleUserIndex(ctx context.Context, indexKey string, affinityHash string) {
	s.runRepairableIndexCommand(ctx, "runtime_user_index_stale_remove", func(redisCtx context.Context) error {
		return s.client.HDel(redisCtx, indexKey, affinityHash).Err()
	})
}

// defaultRuntimeIndexPageLimit returns the default control-read bound.
func (s *RedisSessionStore) defaultRuntimeIndexPageLimit() int {
	if s == nil || s.indexPageDefault <= 0 {
		return 100
	}

	return s.indexPageDefault
}

// runtimeReadLimit clamps requested page size to configured bounds.
func (s *RedisSessionStore) runtimeReadLimit(limit int) int {
	if limit <= 0 {
		limit = s.defaultRuntimeIndexPageLimit()
	}

	maximum := 1000
	if s != nil && s.indexPageMax > 0 {
		maximum = s.indexPageMax
	}

	if limit > maximum {
		return maximum
	}

	return limit
}

// encodeRuntimeReadCursor serializes bounded position data without raw identifiers.
func (s *RedisSessionStore) encodeRuntimeReadCursor(family string, shard int, redisCursor uint64) string {
	payload, err := json.Marshal(runtimeReadCursor{
		Version:     runtimeReadCursorVersion,
		Family:      family,
		Shard:       shard,
		RedisCursor: redisCursor,
	})
	if err != nil {
		return ""
	}

	return base64.RawURLEncoding.EncodeToString(payload)
}

// decodeRuntimeReadCursor validates an opaque runtime read cursor.
func (s *RedisSessionStore) decodeRuntimeReadCursor(raw string, family string, shardCount int) (runtimeReadCursor, error) {
	if shardCount <= 0 {
		return runtimeReadCursor{}, newStateError(RedisErrorKindConfig, operationRuntimeRead, "index shards required", nil)
	}

	if strings.TrimSpace(raw) == "" {
		return runtimeReadCursor{Version: runtimeReadCursorVersion, Family: family}, nil
	}

	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return runtimeReadCursor{}, newStateError(RedisErrorKindAmbiguousState, operationRuntimeRead, "cursor invalid", err)
	}

	var cursor runtimeReadCursor
	if err := json.Unmarshal(payload, &cursor); err != nil {
		return runtimeReadCursor{}, newStateError(RedisErrorKindAmbiguousState, operationRuntimeRead, "cursor invalid", err)
	}

	if cursor.Version != runtimeReadCursorVersion || cursor.Family != family {
		return runtimeReadCursor{}, newStateError(RedisErrorKindAmbiguousState, operationRuntimeRead, "cursor family invalid", nil)
	}

	if cursor.Shard < 0 || cursor.Shard >= shardCount {
		return runtimeReadCursor{}, newStateError(RedisErrorKindAmbiguousState, operationRuntimeRead, "cursor shard invalid", nil)
	}

	return cursor, nil
}

// parseUserIndexValue converts a repairable user-index value into an affinity key.
func parseUserIndexValue(value string) (AffinityKey, error) {
	parts := strings.SplitN(value, "\t", runtimeReadUserIndexFields)
	if len(parts) != runtimeReadUserIndexFields {
		return AffinityKey{}, newStateError(RedisErrorKindAmbiguousState, operationRuntimeRead, "user index value invalid", nil)
	}

	key := AffinityKey{Tenant: strings.TrimSpace(parts[0]), AccountKey: strings.TrimSpace(parts[1])}
	if key.Tenant == "" || key.AccountKey == "" {
		return AffinityKey{}, newStateError(RedisErrorKindAmbiguousState, operationRuntimeRead, "user index value incomplete", nil)
	}

	return key, nil
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
