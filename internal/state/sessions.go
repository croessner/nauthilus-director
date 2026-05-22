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
	"strconv"
	"strings"
	"time"
)

const (
	scriptOpen      = "open"
	scriptHeartbeat = "heartbeat"
	scriptClose     = "close"
	scriptLookup    = "lookup"
)

// RedisSessionStore coordinates active affinity and session leases through Redis scripts.
type RedisSessionStore struct {
	client   RedisClient
	keys     KeyBuilder
	registry *ScriptRegistry
}

// NewRedisSessionStore creates a Redis-backed session store with embedded scripts.
func NewRedisSessionStore(client RedisClient, keys KeyBuilder, registry *ScriptRegistry) (*RedisSessionStore, error) {
	if client == nil {
		return nil, newStateError(RedisErrorKindConfig, "session_store", "redis client required", nil)
	}

	if keys.prefix == "" || keys.schemaVersion <= 0 {
		return nil, newStateError(RedisErrorKindConfig, "session_store", "key builder required", nil)
	}

	if registry == nil {
		loaded, err := LoadEmbeddedScripts()
		if err != nil {
			return nil, err
		}

		registry = loaded
	}

	return &RedisSessionStore{client: client, keys: keys, registry: registry}, nil
}

// OpenSession creates or refreshes a lease while preserving existing active affinity.
func (s *RedisSessionStore) OpenSession(ctx context.Context, record SessionRecord) (AffinityRecord, error) {
	if err := validateSessionRecord(record); err != nil {
		return AffinityRecord{}, err
	}

	keys, sessionKey, err := s.sessionKeys(record.Key, record.ID)
	if err != nil {
		return AffinityRecord{}, err
	}

	value, err := s.runScript(ctx, scriptOpen, []string{keys.State, keys.Sessions, sessionKey},
		record.ID,
		normalizedStateValue(record.Protocol),
		normalizedStateValue(record.ShardTag),
		durationMilliseconds(record.LeaseTTL),
		nonNegativeDurationMilliseconds(record.IdleGrace),
		s.keys.schemaVersion,
	)
	if err != nil {
		return AffinityRecord{}, err
	}

	return parseAffinityRecord(record.Key, value)
}

// HeartbeatSession extends one existing session lease using Redis server time.
func (s *RedisSessionStore) HeartbeatSession(
	ctx context.Context,
	key AffinityKey,
	sessionID string,
	ttl time.Duration,
) (AffinityRecord, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return AffinityRecord{}, newStateError(RedisErrorKindAmbiguousState, scriptHeartbeat, "session id required", nil)
	}

	if ttl <= 0 {
		return AffinityRecord{}, newStateError(RedisErrorKindAmbiguousState, scriptHeartbeat, "lease ttl required", nil)
	}

	keys, sessionKey, err := s.sessionKeys(key, sessionID)
	if err != nil {
		return AffinityRecord{}, err
	}

	value, err := s.runScript(ctx, scriptHeartbeat, []string{keys.State, keys.Sessions, sessionKey},
		sessionID,
		durationMilliseconds(ttl),
	)
	if err != nil {
		return AffinityRecord{}, err
	}

	return parseAffinityRecord(key, value)
}

// CloseSession releases one session lease and expires the affinity after the configured idle grace.
func (s *RedisSessionStore) CloseSession(ctx context.Context, key AffinityKey, sessionID string) (AffinityRecord, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return AffinityRecord{}, newStateError(RedisErrorKindAmbiguousState, scriptClose, "session id required", nil)
	}

	keys, sessionKey, err := s.sessionKeys(key, sessionID)
	if err != nil {
		return AffinityRecord{}, err
	}

	value, err := s.runScript(ctx, scriptClose, []string{keys.State, keys.Sessions, sessionKey}, sessionID)
	if err != nil {
		return AffinityRecord{}, err
	}

	return parseAffinityRecord(key, value)
}

// LookupAffinity reads the current affinity state without refreshing leases.
func (s *RedisSessionStore) LookupAffinity(ctx context.Context, key AffinityKey) (AffinityRecord, error) {
	keys, err := s.keys.AffinityKeys(key.Tenant, key.AccountKey)
	if err != nil {
		return AffinityRecord{}, err
	}

	value, err := s.runScript(ctx, scriptLookup, []string{keys.State, keys.Sessions})
	if err != nil {
		return AffinityRecord{}, err
	}

	return parseAffinityRecord(key, value)
}

// sessionKeys returns the per-affinity key group plus the session lease key.
func (s *RedisSessionStore) sessionKeys(key AffinityKey, sessionID string) (AffinityKeys, string, error) {
	keys, err := s.keys.AffinityKeys(key.Tenant, key.AccountKey)
	if err != nil {
		return AffinityKeys{}, "", err
	}

	sessionKey, err := s.keys.SessionKey(key.Tenant, key.AccountKey, sessionID)
	if err != nil {
		return AffinityKeys{}, "", err
	}

	return keys, sessionKey, nil
}

// runScript executes a registered script with EVALSHA and a controlled EVAL fallback.
func (s *RedisSessionStore) runScript(ctx context.Context, name string, keys []string, args ...any) (any, error) {
	script, ok := s.registry.Get(name)
	if !ok {
		return nil, newStateError(RedisErrorKindConfig, name, "script not registered", nil)
	}

	ctx = redisContext(ctx)

	value, err := s.client.EvalSha(ctx, script.SHA, keys, args...).Result()
	if err == nil {
		return value, nil
	}

	classified := ClassifyRedisError(name, err)
	if !ShouldFallbackToEval(classified) {
		return nil, classified
	}

	value, err = s.client.Eval(ctx, script.Source, keys, args...).Result()
	if err != nil {
		return nil, ClassifyRedisError(name, err)
	}

	return value, nil
}

// validateSessionRecord checks the secret-free fields required by the open script.
func validateSessionRecord(record SessionRecord) error {
	if strings.TrimSpace(record.ID) == "" {
		return newStateError(RedisErrorKindAmbiguousState, scriptOpen, "session id required", nil)
	}

	if normalizedStateValue(record.Protocol) == "" {
		return newStateError(RedisErrorKindAmbiguousState, scriptOpen, "protocol required", nil)
	}

	if normalizedStateValue(record.ShardTag) == "" {
		return newStateError(RedisErrorKindAmbiguousState, scriptOpen, "shard tag required", nil)
	}

	if record.LeaseTTL <= 0 {
		return newStateError(RedisErrorKindAmbiguousState, scriptOpen, "lease ttl required", nil)
	}

	if record.IdleGrace < 0 {
		return newStateError(RedisErrorKindAmbiguousState, scriptOpen, "idle grace must not be negative", nil)
	}

	return nil
}

// parseAffinityRecord converts the flat Lua response into a typed affinity snapshot.
func parseAffinityRecord(key AffinityKey, value any) (AffinityRecord, error) {
	fields, err := parseScriptFields(value)
	if err != nil {
		return AffinityRecord{}, err
	}

	record := AffinityRecord{
		Key:        key,
		Status:     fields["status"],
		ShardTag:   fields["shard_tag"],
		Generation: fields["generation"],
		Present:    fields["present"] == "1",
	}

	if record.Status == "" {
		return AffinityRecord{}, newStateError(RedisErrorKindAmbiguousState, "script_result", "status required", nil)
	}

	if record.Present && record.ShardTag == "" {
		return AffinityRecord{}, newStateError(RedisErrorKindAmbiguousState, "script_result", "shard tag required", nil)
	}

	record.ActiveSessionCount, err = parseIntField(fields, "active_session_count")
	if err != nil {
		return AffinityRecord{}, err
	}

	record.ServerTime, err = parseTimeField(fields, "server_time_ms")
	if err != nil {
		return AffinityRecord{}, err
	}

	record.ExpiresAt, err = parseTimeField(fields, "expires_at_ms")
	if err != nil {
		return AffinityRecord{}, err
	}

	record.LeaseExpiresAt, err = parseTimeField(fields, "lease_expires_at_ms")
	if err != nil {
		return AffinityRecord{}, err
	}

	return record, nil
}

// parseScriptFields reads alternating key/value entries returned by Lua scripts.
func parseScriptFields(value any) (map[string]string, error) {
	values, ok := value.([]any)
	if !ok {
		return nil, newStateError(RedisErrorKindAmbiguousState, "script_result", "flat array required", nil)
	}

	if len(values)%2 != 0 {
		return nil, newStateError(RedisErrorKindAmbiguousState, "script_result", "even field count required", nil)
	}

	fields := make(map[string]string, len(values)/2)
	for index := 0; index < len(values); index += 2 {
		name, err := scriptValueString(values[index])
		if err != nil {
			return nil, err
		}

		fieldValue, err := scriptValueString(values[index+1])
		if err != nil {
			return nil, err
		}

		fields[name] = fieldValue
	}

	return fields, nil
}

// scriptValueString converts Redis scalar script output into strings.
func scriptValueString(value any) (string, error) {
	switch typed := value.(type) {
	case string:
		return typed, nil
	case []byte:
		return string(typed), nil
	case int64:
		return strconv.FormatInt(typed, 10), nil
	default:
		return "", newStateError(RedisErrorKindAmbiguousState, "script_result", "unsupported scalar", nil)
	}
}

// parseIntField extracts an integer field from a script result.
func parseIntField(fields map[string]string, name string) (int, error) {
	value, ok := fields[name]
	if !ok {
		return 0, newStateError(RedisErrorKindAmbiguousState, "script_result", name+" required", nil)
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, newStateError(RedisErrorKindAmbiguousState, "script_result", name+" invalid", err)
	}

	return parsed, nil
}

// parseTimeField extracts a millisecond Unix timestamp from a script result.
func parseTimeField(fields map[string]string, name string) (time.Time, error) {
	value, ok := fields[name]
	if !ok {
		return time.Time{}, newStateError(RedisErrorKindAmbiguousState, "script_result", name+" required", nil)
	}

	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return time.Time{}, newStateError(RedisErrorKindAmbiguousState, "script_result", name+" invalid", err)
	}

	if parsed <= 0 {
		return time.Time{}, nil
	}

	return time.UnixMilli(parsed).UTC(), nil
}

// durationMilliseconds returns a positive millisecond duration for Redis lease scripts.
func durationMilliseconds(duration time.Duration) int64 {
	milliseconds := duration.Milliseconds()
	if milliseconds <= 0 {
		return 1
	}

	return milliseconds
}

// nonNegativeDurationMilliseconds returns a Redis millisecond duration that may be zero.
func nonNegativeDurationMilliseconds(duration time.Duration) int64 {
	if duration <= 0 {
		return 0
	}

	return durationMilliseconds(duration)
}

// normalizedStateValue trims protocol and shard values before they cross the Redis boundary.
func normalizedStateValue(value string) string {
	return strings.TrimSpace(value)
}

// redisContext returns a usable context for Redis commands.
func redisContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}

	return ctx
}
