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

	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/redis/go-redis/v9"
)

const (
	scriptAttach         = "attach"
	scriptBackendReap    = "backend_reap"
	scriptBackendRelease = "backend_release"
	scriptBackendReserve = "backend_reserve"
	scriptClose          = "close"
	scriptHeartbeat      = "heartbeat"
	scriptLookup         = "lookup"
	scriptOpen           = "open"
)

const (
	scriptFieldAccountKey         = "account_key"
	scriptFieldActiveSessionCount = "active_session_count"
	scriptFieldAffinityHash       = "affinity_hash"
	scriptFieldBackendCounted     = "backend_counted"
	scriptFieldBackendID          = "backend_id"
	scriptFieldBackendMaxConn     = "backend_max_connections"
	scriptFieldBackendPool        = "backend_pool"
	scriptFieldBackendReservation = "backend_reservation_id"
	scriptFieldControlAction      = "control_action"
	scriptFieldControlGeneration  = "control_generation"
	scriptFieldCreatedAtMS        = "created_at_ms"
	scriptFieldExpiresAtMS        = "expires_at_ms"
	scriptFieldGeneration         = "generation"
	scriptFieldHolderKind         = "holder_kind"
	scriptFieldIdleExpiresAtMS    = "idle_expires_at_ms"
	scriptFieldLeaseExpiresAtMS   = "lease_expires_at_ms"
	scriptFieldListenerName       = "listener_name"
	scriptFieldPresent            = "present"
	scriptFieldProtocol           = "protocol"
	scriptFieldServerTimeMS       = "server_time_ms"
	scriptFieldServiceName        = "service_name"
	scriptFieldSessionID          = "session_id"
	scriptFieldSessionIndexKey    = "session_index_key"
	scriptFieldSessionDueIndexKey = "session_due_index_key"
	scriptFieldShardTag           = "shard_tag"
	scriptFieldStatus             = "status"
	scriptFieldStrategy           = "strategy"
	scriptFieldTenant             = "tenant"
	scriptFieldRequestedDuration  = "requested_duration_ms"
	scriptFieldUpdatedAtMS        = "updated_at_ms"
	scriptFieldUserSessionsKey    = "user_sessions_key"
)

// RedisSessionStore coordinates active affinity and session leases through Redis scripts.
type RedisSessionStore struct {
	client           RedisClient
	keys             KeyBuilder
	registry         *ScriptRegistry
	recorder         observability.Recorder
	redisMode        string
	indexPageDefault int
	indexPageMax     int
}

// affinityMutationResult keeps authoritative affinity state and repair deltas together.
type affinityMutationResult struct {
	Record AffinityRecord
	Delta  sessionMutationDelta
}

// sessionMutationDelta describes idempotent secondary work after an affinity mutation.
type sessionMutationDelta struct {
	SessionID          string
	AffinityHash       string
	Tenant             string
	AccountKey         string
	HolderKind         string
	Protocol           string
	ListenerName       string
	ServiceName        string
	ShardTag           string
	BackendIdentifier  string
	BackendReservation string
	BackendMaxConn     int
	BackendCounted     bool
	Generation         string
	ControlGeneration  string
	LeaseExpiresAt     time.Time
	IdleExpiresAt      time.Time
}

// NewRedisSessionStore creates a Redis-backed session store with embedded scripts.
func NewRedisSessionStore(client RedisClient, keys KeyBuilder, registry *ScriptRegistry, options ...RedisSessionStoreOption) (*RedisSessionStore, error) {
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

	applied := applyRedisStoreOptions(options)

	return &RedisSessionStore{
		client:           client,
		keys:             keys,
		registry:         registry,
		recorder:         applied.recorder,
		redisMode:        applied.redisMode,
		indexPageDefault: applied.indexPageDefault,
		indexPageMax:     applied.indexPageMax,
	}, nil
}

// OpenSession creates or refreshes a lease while preserving existing active affinity.
func (s *RedisSessionStore) OpenSession(ctx context.Context, record SessionRecord) (AffinityRecord, error) {
	if err := validateSessionRecord(record); err != nil {
		return AffinityRecord{}, err
	}

	_, sessionKey, scriptKeys, err := s.openSessionScriptKeys(record.Key, record.ID)
	if err != nil {
		return AffinityRecord{}, err
	}

	affinityHash, err := s.keys.AffinityHash(record.Key.Tenant, record.Key.AccountKey)
	if err != nil {
		return AffinityRecord{}, err
	}

	value, err := s.runScript(ctx, scriptOpen, scriptKeys,
		record.ID,
		normalizedStateValue(record.Protocol),
		normalizedStateValue(record.ShardTag),
		durationMilliseconds(record.LeaseTTL),
		nonNegativeDurationMilliseconds(record.IdleGrace),
		s.keys.schemaVersion,
		affinityHash,
		normalizedStateValue(record.Key.Tenant),
		normalizedStateValue(record.Key.AccountKey),
		normalizedStateValue(record.ListenerName),
		normalizedStateValue(record.ServiceName),
		normalizedStateValue(record.DirectorInstanceID),
		normalizedHolderKind(record.HolderKind),
	)
	if err != nil {
		return AffinityRecord{}, err
	}

	result, err := parseAffinityMutationResult(record.Key, value)
	if err != nil {
		return AffinityRecord{}, err
	}

	s.writeRepairableOpenIndexes(ctx, result.Delta, sessionKey)

	if dimensions, ok := aggregateSessionDimensionsFromDelta(result.Delta); ok {
		s.upsertSessionAggregate(ctx, dimensions)
	}

	s.updateIdleAffinityAggregate(ctx, result)

	return result.Record, nil
}

// AttachSelectedBackend atomically registers the selected backend after placement.
func (s *RedisSessionStore) AttachSelectedBackend(
	ctx context.Context,
	attachment SessionBackendAttachment,
) (SessionBackendRecord, error) {
	if err := validateSessionBackendAttachment(attachment); err != nil {
		return SessionBackendRecord{}, err
	}

	_, sessionKey, scriptKeys, err := s.attachSelectedBackendScriptKeys(attachment.Key, attachment.SessionID)
	if err != nil {
		return SessionBackendRecord{}, err
	}

	value, err := s.runScript(ctx, scriptAttach, scriptKeys,
		attachment.SessionID,
		attachment.BackendIdentifier,
		attachment.ReservationID,
		attachment.MaxConnections,
	)
	if err != nil {
		return SessionBackendRecord{}, err
	}

	record, err := parseSessionBackendRecord(value)
	if err != nil {
		return SessionBackendRecord{}, err
	}

	activeCount, countErr := s.backendReservationActiveCount(ctx, attachment.BackendIdentifier)
	if countErr != nil {
		return SessionBackendRecord{}, countErr
	}

	record.BackendActiveCount = activeCount
	s.writeRepairableAttachIndexes(ctx, attachment, sessionKey, record.LeaseExpiresAt)
	s.upsertSessionAggregateFromSession(ctx, attachment.SessionID, sessionKey)

	return record, nil
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

	_, sessionKey, scriptKeys, err := s.heartbeatSessionScriptKeys(key, sessionID)
	if err != nil {
		return AffinityRecord{}, err
	}

	value, err := s.runScript(ctx, scriptHeartbeat, scriptKeys,
		sessionID,
		durationMilliseconds(ttl),
	)
	if err != nil {
		return AffinityRecord{}, err
	}

	result, err := parseAffinityMutationResult(key, value)
	if err != nil {
		return AffinityRecord{}, err
	}

	s.writeRepairableOpenIndexes(ctx, result.Delta, sessionKey)

	if dimensions, ok := aggregateSessionDimensionsFromDelta(result.Delta); ok {
		s.upsertSessionAggregate(ctx, dimensions)
	}

	s.updateIdleAffinityAggregate(ctx, result)

	if err := s.refreshRepairableBackendReservation(ctx, result.Delta, ttl); err != nil {
		return AffinityRecord{}, err
	}

	return result.Record, nil
}

// CloseSession releases one session lease and expires the affinity after the configured idle grace.
func (s *RedisSessionStore) CloseSession(ctx context.Context, key AffinityKey, sessionID string) (AffinityRecord, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return AffinityRecord{}, newStateError(RedisErrorKindAmbiguousState, scriptClose, "session id required", nil)
	}

	_, _, scriptKeys, err := s.closeSessionScriptKeys(key, sessionID)
	if err != nil {
		return AffinityRecord{}, err
	}

	value, err := s.runScript(ctx, scriptClose, scriptKeys, sessionID)
	if err != nil {
		return AffinityRecord{}, err
	}

	result, err := parseAffinityMutationResult(key, value)
	if err != nil {
		return AffinityRecord{}, err
	}

	s.writeRepairableCloseIndexes(ctx, result.Delta)
	s.removeSessionAggregate(ctx, result.Delta.SessionID)
	s.updateIdleAffinityAggregate(ctx, result)

	return result.Record, nil
}

// LookupAffinity reads the current affinity state without refreshing leases.
func (s *RedisSessionStore) LookupAffinity(ctx context.Context, key AffinityKey) (AffinityRecord, error) {
	keys, err := s.keys.AffinityKeys(key.Tenant, key.AccountKey)
	if err != nil {
		return AffinityRecord{}, err
	}

	scriptKeys := s.lookupAffinityScriptKeys(keys)

	value, err := s.runScript(ctx, scriptLookup, scriptKeys)
	if err != nil {
		return AffinityRecord{}, err
	}

	return parseAffinityRecord(key, value)
}

// openSessionScriptKeys returns the same-slot key list for session opens.
func (s *RedisSessionStore) openSessionScriptKeys(key AffinityKey, sessionID string) (AffinityKeys, string, []string, error) {
	keys, sessionKey, err := s.sessionKeys(key, sessionID)
	if err != nil {
		return AffinityKeys{}, "", nil, err
	}

	return keys, sessionKey, []string{keys.State, keys.Sessions, sessionKey, keys.Override}, nil
}

// heartbeatSessionScriptKeys returns the same-slot key list for lease heartbeats.
func (s *RedisSessionStore) heartbeatSessionScriptKeys(key AffinityKey, sessionID string) (AffinityKeys, string, []string, error) {
	keys, sessionKey, err := s.sessionKeys(key, sessionID)
	if err != nil {
		return AffinityKeys{}, "", nil, err
	}

	return keys, sessionKey, []string{keys.State, keys.Sessions, sessionKey}, nil
}

// closeSessionScriptKeys returns the same-slot key list for session closes.
func (s *RedisSessionStore) closeSessionScriptKeys(key AffinityKey, sessionID string) (AffinityKeys, string, []string, error) {
	return s.heartbeatSessionScriptKeys(key, sessionID)
}

// attachSelectedBackendScriptKeys returns the same-slot key list for backend attach.
func (s *RedisSessionStore) attachSelectedBackendScriptKeys(key AffinityKey, sessionID string) (AffinityKeys, string, []string, error) {
	keys, sessionKey, err := s.sessionKeys(key, sessionID)
	if err != nil {
		return AffinityKeys{}, "", nil, err
	}

	return keys, sessionKey, []string{keys.State, keys.Sessions, sessionKey}, nil
}

// lookupAffinityScriptKeys returns the same-slot key list for read-only affinity lookup.
func (s *RedisSessionStore) lookupAffinityScriptKeys(keys AffinityKeys) []string {
	return []string{keys.State, keys.Sessions}
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

	if err := s.validateScriptKeys(name, keys); err != nil {
		return nil, err
	}

	ctx = redisContext(ctx)
	started := time.Now()

	value, err := s.client.EvalSha(ctx, script.SHA, keys, args...).Result()
	if err == nil {
		s.recordRedisOperation(ctx, name, started, nil)

		return value, nil
	}

	classified := ClassifyRedisError(name, err)
	if !ShouldFallbackToEval(classified) {
		s.recordRedisOperation(ctx, name, started, classified)

		return nil, classified
	}

	value, err = s.client.Eval(ctx, script.Source, keys, args...).Result()
	if err != nil {
		classified = ClassifyRedisError(name, err)
		s.recordRedisOperation(ctx, name, started, classified)

		return nil, classified
	}

	s.recordRedisOperation(ctx, name, started, nil)

	return value, nil
}

// validateScriptKeys applies local Cluster-safety checks before script dispatch.
func (s *RedisSessionStore) validateScriptKeys(name string, keys []string) error {
	if isPerAffinityScript(name) {
		return s.keys.validateAffinityOwnedKeys(name, keys)
	}

	if isBackendReservationScript(name) {
		return s.keys.validateBackendReservationOwnedKeys(name, keys)
	}

	return nil
}

// isPerAffinityScript reports whether a script must stay inside one affinity slot.
func isPerAffinityScript(name string) bool {
	switch name {
	case scriptAttach, scriptOpen, scriptHeartbeat, scriptClose, scriptLookup, scriptMove, scriptKick, scriptClear,
		scriptBackendPinSet, scriptBackendPinGet, scriptBackendPinClear,
		scriptUserHoldSet, scriptUserHoldGet, scriptUserHoldClear:
		return true
	default:
		return false
	}
}

// isBackendReservationScript reports whether a script must stay inside one backend slot.
func isBackendReservationScript(name string) bool {
	switch name {
	case scriptBackendReserve, scriptBackendRelease, scriptBackendReap:
		return true
	default:
		return false
	}
}

// validateSessionRecord checks the secret-free fields required by the open script.
func validateSessionRecord(record SessionRecord) error {
	if strings.TrimSpace(record.ID) == "" {
		return newStateError(RedisErrorKindAmbiguousState, scriptOpen, "session id required", nil)
	}

	if normalizedHolderKind(record.HolderKind) == "" {
		return newStateError(RedisErrorKindAmbiguousState, scriptOpen, "holder kind required", nil)
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

// normalizedHolderKind returns the stable holder kind stored with a lease.
func normalizedHolderKind(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", HolderKindSession:
		return HolderKindSession
	case HolderKindDelivery:
		return HolderKindDelivery
	default:
		return ""
	}
}

// validateSessionBackendAttachment checks fields needed for backend count registration.
func validateSessionBackendAttachment(attachment SessionBackendAttachment) error {
	if strings.TrimSpace(attachment.SessionID) == "" {
		return newStateError(RedisErrorKindAmbiguousState, scriptAttach, "session id required", nil)
	}

	if strings.TrimSpace(attachment.BackendIdentifier) == "" {
		return newStateError(RedisErrorKindAmbiguousState, scriptAttach, "backend id required", nil)
	}

	if strings.TrimSpace(attachment.ReservationID) == "" {
		return newStateError(RedisErrorKindAmbiguousState, scriptAttach, "reservation id required", nil)
	}

	if attachment.MaxConnections <= 0 {
		return newStateError(RedisErrorKindAmbiguousState, scriptAttach, "max connections required", nil)
	}

	return nil
}

// parseAffinityRecord converts the flat Lua response into a typed affinity snapshot.
func parseAffinityRecord(key AffinityKey, value any) (AffinityRecord, error) {
	fields, err := parseScriptFields(value)
	if err != nil {
		return AffinityRecord{}, err
	}

	return parseAffinityRecordFields(key, fields)
}

// parseAffinityMutationResult converts a mutation response and requires its repair delta.
func parseAffinityMutationResult(key AffinityKey, value any) (affinityMutationResult, error) {
	fields, err := parseScriptFields(value)
	if err != nil {
		return affinityMutationResult{}, err
	}

	record, err := parseAffinityRecordFields(key, fields)
	if err != nil {
		return affinityMutationResult{}, err
	}

	delta, err := parseSessionMutationDelta(fields)
	if err != nil {
		return affinityMutationResult{}, err
	}

	return affinityMutationResult{Record: record, Delta: delta}, nil
}

// parseAffinityRecordFields converts script fields into a typed affinity snapshot.
func parseAffinityRecordFields(key AffinityKey, fields map[string]string) (AffinityRecord, error) {
	record := AffinityRecord{
		Key:        key,
		Status:     fields[scriptFieldStatus],
		ShardTag:   fields[scriptFieldShardTag],
		Generation: fields[scriptFieldGeneration],
		Present:    fields[scriptFieldPresent] == "1",
	}

	if record.Status == "" {
		return AffinityRecord{}, newStateError(RedisErrorKindAmbiguousState, "script_result", "status required", nil)
	}

	if record.Present && record.ShardTag == "" {
		return AffinityRecord{}, newStateError(RedisErrorKindAmbiguousState, "script_result", "shard tag required", nil)
	}

	var err error

	record.ActiveSessionCount, err = parseIntField(fields, scriptFieldActiveSessionCount)
	if err != nil {
		return AffinityRecord{}, err
	}

	record.ServerTime, err = parseTimeField(fields, scriptFieldServerTimeMS)
	if err != nil {
		return AffinityRecord{}, err
	}

	record.ExpiresAt, err = parseTimeField(fields, scriptFieldExpiresAtMS)
	if err != nil {
		return AffinityRecord{}, err
	}

	record.LeaseExpiresAt, err = parseTimeField(fields, scriptFieldLeaseExpiresAtMS)
	if err != nil {
		return AffinityRecord{}, err
	}

	record.ControlAction, err = parseOptionalControlAction(fields[scriptFieldControlAction])
	if err != nil {
		return AffinityRecord{}, err
	}

	record.ControlGeneration = fields[scriptFieldControlGeneration]
	record.BackendIdentifier = fields[scriptFieldBackendID]

	return record, nil
}

// parseSessionMutationDelta converts required session delta fields from a mutation response.
func parseSessionMutationDelta(fields map[string]string) (sessionMutationDelta, error) {
	delta := sessionMutationDelta{
		SessionID:          strings.TrimSpace(fields[scriptFieldSessionID]),
		AffinityHash:       strings.TrimSpace(fields[scriptFieldAffinityHash]),
		Tenant:             strings.TrimSpace(fields[scriptFieldTenant]),
		AccountKey:         strings.TrimSpace(fields[scriptFieldAccountKey]),
		HolderKind:         strings.TrimSpace(fields[scriptFieldHolderKind]),
		Protocol:           strings.TrimSpace(fields[scriptFieldProtocol]),
		ListenerName:       strings.TrimSpace(fields[scriptFieldListenerName]),
		ServiceName:        strings.TrimSpace(fields[scriptFieldServiceName]),
		ShardTag:           strings.TrimSpace(fields[scriptFieldShardTag]),
		BackendIdentifier:  strings.TrimSpace(fields[scriptFieldBackendID]),
		BackendReservation: strings.TrimSpace(fields[scriptFieldBackendReservation]),
		Generation:         strings.TrimSpace(fields[scriptFieldGeneration]),
		ControlGeneration:  strings.TrimSpace(fields[scriptFieldControlGeneration]),
	}

	if err := validateSessionMutationDeltaIdentity(delta); err != nil {
		return sessionMutationDelta{}, err
	}

	backendCounted, ok := fields[scriptFieldBackendCounted]
	if !ok {
		return sessionMutationDelta{}, newStateError(RedisErrorKindAmbiguousState, "script_result", "backend_counted required", nil)
	}

	switch backendCounted {
	case "0", "":
		delta.BackendCounted = false
	case "1":
		delta.BackendCounted = true
	default:
		return sessionMutationDelta{}, newStateError(RedisErrorKindAmbiguousState, "script_result", "backend_counted invalid", nil)
	}

	if delta.BackendCounted && delta.BackendIdentifier == "" {
		return sessionMutationDelta{}, newStateError(RedisErrorKindAmbiguousState, "script_result", "backend id required for counted session", nil)
	}

	var err error

	delta.BackendMaxConn, err = parseOptionalIntField(fields, scriptFieldBackendMaxConn)
	if err != nil {
		return sessionMutationDelta{}, err
	}

	delta.LeaseExpiresAt, err = parseTimeField(fields, scriptFieldLeaseExpiresAtMS)
	if err != nil {
		return sessionMutationDelta{}, err
	}

	delta.IdleExpiresAt, err = parseTimeField(fields, scriptFieldIdleExpiresAtMS)
	if err != nil {
		return sessionMutationDelta{}, err
	}

	return delta, nil
}

// validateSessionMutationDeltaIdentity rejects incomplete repair payload identity.
func validateSessionMutationDeltaIdentity(delta sessionMutationDelta) error {
	for name, value := range map[string]string{
		scriptFieldAccountKey:        delta.AccountKey,
		scriptFieldAffinityHash:      delta.AffinityHash,
		scriptFieldControlGeneration: delta.ControlGeneration,
		scriptFieldGeneration:        delta.Generation,
		scriptFieldHolderKind:        delta.HolderKind,
		scriptFieldProtocol:          delta.Protocol,
		scriptFieldSessionID:         delta.SessionID,
		scriptFieldShardTag:          delta.ShardTag,
		scriptFieldTenant:            delta.Tenant,
	} {
		if value == "" {
			return newStateError(RedisErrorKindAmbiguousState, "script_result", name+" required", nil)
		}
	}

	return nil
}

// parseSessionBackendRecord converts the selected-backend attach payload.
func parseSessionBackendRecord(value any) (SessionBackendRecord, error) {
	parsed, err := parseBackendScriptFields(value)
	if err != nil {
		return SessionBackendRecord{}, err
	}

	record := SessionBackendRecord{
		Status:            parsed.Status,
		BackendIdentifier: parsed.BackendIdentifier,
		ReservationID:     parsed.Fields[scriptFieldBackendReservation],
		ServerTime:        parsed.ServerTime,
		ControlGeneration: parsed.Fields[scriptFieldControlGeneration],
	}

	record.BackendActiveCount, err = parseIntField(parsed.Fields, "backend_active_session_count")
	if err != nil {
		return SessionBackendRecord{}, err
	}

	record.LeaseExpiresAt, err = parseTimeField(parsed.Fields, scriptFieldLeaseExpiresAtMS)
	if err != nil {
		return SessionBackendRecord{}, err
	}

	return record, nil
}

// writeRepairableOpenIndexes updates secondary indexes after authoritative open.
func (s *RedisSessionStore) writeRepairableOpenIndexes(ctx context.Context, delta sessionMutationDelta, sessionKey string) {
	userSessionIndexKey, err := s.keys.UserSessionIndexShardKey(delta.Tenant, delta.AccountKey, delta.SessionID)
	if err != nil {
		s.recordRedisOperation(redisContext(ctx), "open_repairable_indexes", time.Now(), err)

		return
	}

	sessionIndexKey, err := s.keys.SessionIndexShardKey(delta.SessionID)
	if err != nil {
		s.recordRedisOperation(redisContext(ctx), "open_session_index", time.Now(), err)

		return
	}

	sessionDueIndexKey, err := s.keys.SessionDueIndexShardKey(delta.SessionID)
	if err != nil {
		s.recordRedisOperation(redisContext(ctx), "open_session_due_index", time.Now(), err)

		return
	}

	userIndexKey, err := s.keys.UserIndexShardKey(delta.AffinityHash)
	if err != nil {
		s.recordRedisOperation(redisContext(ctx), "open_user_index", time.Now(), err)

		return
	}

	s.runRepairableIndexCommand(ctx, "open_session_index", func(redisCtx context.Context) error {
		return s.client.HSet(redisCtx, sessionIndexKey, delta.SessionID, sessionKey).Err()
	})
	s.runRepairableIndexCommand(ctx, "open_session_due_index", func(redisCtx context.Context) error {
		return s.client.ZAdd(redisCtx, sessionDueIndexKey, redisZ(delta.LeaseExpiresAt, delta.SessionID)).Err()
	})
	s.runRepairableIndexCommand(ctx, "open_user_index", func(redisCtx context.Context) error {
		return s.client.HSet(redisCtx, userIndexKey, delta.AffinityHash, userIndexValue(delta.Tenant, delta.AccountKey)).Err()
	})
	s.runRepairableIndexCommand(ctx, "open_user_session_index", func(redisCtx context.Context) error {
		return s.client.SAdd(redisCtx, userSessionIndexKey, delta.SessionID).Err()
	})
	s.runRepairableIndexCommand(ctx, "open_session_index_metadata", func(redisCtx context.Context) error {
		return s.client.HSet(redisCtx, sessionKey,
			scriptFieldSessionIndexKey, sessionIndexKey,
			scriptFieldSessionDueIndexKey, sessionDueIndexKey,
			scriptFieldUserSessionsKey, userSessionIndexKey,
		).Err()
	})
}

// writeRepairableAttachIndexes updates secondary indexes after selected-backend attach.
func (s *RedisSessionStore) writeRepairableAttachIndexes(
	ctx context.Context,
	attachment SessionBackendAttachment,
	sessionKey string,
	leaseExpiresAt time.Time,
) {
	backendSessionIndexKey, err := s.keys.BackendSessionIndexShardKey(attachment.BackendIdentifier, attachment.SessionID)
	if err != nil {
		s.recordRedisOperation(redisContext(ctx), "attach_backend_session_index", time.Now(), err)

		return
	}

	userSessionIndexKey, err := s.keys.UserSessionIndexShardKey(attachment.Key.Tenant, attachment.Key.AccountKey, attachment.SessionID)
	if err != nil {
		s.recordRedisOperation(redisContext(ctx), "attach_user_session_index", time.Now(), err)

		return
	}

	sessionIndexKey, err := s.keys.SessionIndexShardKey(attachment.SessionID)
	if err != nil {
		s.recordRedisOperation(redisContext(ctx), "attach_session_index", time.Now(), err)

		return
	}

	sessionDueIndexKey, err := s.keys.SessionDueIndexShardKey(attachment.SessionID)
	if err != nil {
		s.recordRedisOperation(redisContext(ctx), "attach_session_due_index", time.Now(), err)

		return
	}

	s.runRepairableIndexCommand(ctx, "attach_backend_index", func(redisCtx context.Context) error {
		return s.client.SAdd(redisCtx, s.keys.BackendIndexKey(), attachment.BackendIdentifier).Err()
	})
	s.runRepairableIndexCommand(ctx, "attach_backend_session_index", func(redisCtx context.Context) error {
		return s.client.SAdd(redisCtx, backendSessionIndexKey, attachment.SessionID).Err()
	})
	s.runRepairableIndexCommand(ctx, "attach_user_session_index", func(redisCtx context.Context) error {
		return s.client.SAdd(redisCtx, userSessionIndexKey, attachment.SessionID).Err()
	})
	s.runRepairableIndexCommand(ctx, "attach_session_due_index", func(redisCtx context.Context) error {
		return s.client.ZAdd(redisCtx, sessionDueIndexKey, redisZ(leaseExpiresAt, attachment.SessionID)).Err()
	})
	s.runRepairableIndexCommand(ctx, "attach_session_index", func(redisCtx context.Context) error {
		return s.client.HSet(redisCtx, sessionIndexKey, attachment.SessionID, sessionKey).Err()
	})
	s.runRepairableIndexCommand(ctx, "attach_session_index_metadata", func(redisCtx context.Context) error {
		return s.client.HSet(redisCtx, sessionKey,
			scriptFieldSessionIndexKey, sessionIndexKey,
			scriptFieldSessionDueIndexKey, sessionDueIndexKey,
			scriptFieldUserSessionsKey, userSessionIndexKey,
			"backend_sessions_key", backendSessionIndexKey,
		).Err()
	})
}

// writeRepairableCloseIndexes updates secondary indexes after authoritative close.
func (s *RedisSessionStore) writeRepairableCloseIndexes(ctx context.Context, delta sessionMutationDelta) {
	userSessionIndexKey, err := s.keys.UserSessionIndexShardKey(delta.Tenant, delta.AccountKey, delta.SessionID)
	if err != nil {
		s.recordRedisOperation(redisContext(ctx), "close_repairable_indexes", time.Now(), err)

		return
	}

	sessionIndexKey, err := s.keys.SessionIndexShardKey(delta.SessionID)
	if err != nil {
		s.recordRedisOperation(redisContext(ctx), "close_session_index", time.Now(), err)

		return
	}

	sessionDueIndexKey, err := s.keys.SessionDueIndexShardKey(delta.SessionID)
	if err != nil {
		s.recordRedisOperation(redisContext(ctx), "close_session_due_index", time.Now(), err)

		return
	}

	s.runRepairableIndexCommand(ctx, "close_session_index", func(redisCtx context.Context) error {
		return s.client.HDel(redisCtx, sessionIndexKey, delta.SessionID).Err()
	})
	s.runRepairableIndexCommand(ctx, "close_session_due_index", func(redisCtx context.Context) error {
		return s.client.ZRem(redisCtx, sessionDueIndexKey, delta.SessionID).Err()
	})
	s.runRepairableIndexCommand(ctx, "close_user_session_index", func(redisCtx context.Context) error {
		return s.client.SRem(redisCtx, userSessionIndexKey, delta.SessionID).Err()
	})

	if delta.BackendIdentifier == "" {
		return
	}

	backendSessionIndexKey, err := s.keys.BackendSessionIndexShardKey(delta.BackendIdentifier, delta.SessionID)
	if err != nil {
		s.recordRedisOperation(redisContext(ctx), "close_backend_session_index", time.Now(), err)

		return
	}

	s.runRepairableIndexCommand(ctx, "close_backend_session_index", func(redisCtx context.Context) error {
		return s.client.SRem(redisCtx, backendSessionIndexKey, delta.SessionID).Err()
	})

	if delta.BackendCounted {
		s.releaseRepairableBackendReservation(ctx, delta)
	}
}

// releaseRepairableBackendReservation releases one backend reservation after a close delta.
func (s *RedisSessionStore) releaseRepairableBackendReservation(ctx context.Context, delta sessionMutationDelta) {
	if delta.BackendReservation == "" {
		s.decrementLegacyBackendCount(ctx, delta.BackendIdentifier)

		return
	}

	_, err := s.ReleaseBackendReservation(ctx, BackendReservationReleaseRequest{
		BackendIdentifier: delta.BackendIdentifier,
		ReservationID:     delta.BackendReservation,
	})
	if err != nil {
		s.recordRedisOperation(redisContext(ctx), "close_backend_reservation", time.Now(), err)
	}
}

// refreshRepairableBackendReservation extends the backend reservation with the session lease.
func (s *RedisSessionStore) refreshRepairableBackendReservation(ctx context.Context, delta sessionMutationDelta, ttl time.Duration) error {
	if !delta.BackendCounted || delta.BackendReservation == "" {
		return nil
	}

	if delta.BackendMaxConn <= 0 {
		return newStateError(RedisErrorKindAmbiguousState, scriptHeartbeat, "backend max connections required", nil)
	}

	_, err := s.ReserveBackendCapacity(ctx, BackendReservationRequest{
		BackendIdentifier: delta.BackendIdentifier,
		ReservationID:     delta.BackendReservation,
		MaxConnections:    delta.BackendMaxConn,
		LeaseTTL:          ttl,
	})

	return err
}

// decrementLegacyBackendCount prevents negative counts for older counted sessions.
func (s *RedisSessionStore) decrementLegacyBackendCount(ctx context.Context, backendIdentifier string) {
	backendRuntimeKey, err := s.keys.BackendRuntimeKey(backendIdentifier)
	if err != nil {
		s.recordRedisOperation(redisContext(ctx), "close_backend_count", time.Now(), err)

		return
	}

	s.runRepairableIndexCommand(ctx, "close_backend_count", func(redisCtx context.Context) error {
		count, countErr := s.client.HIncrBy(redisCtx, backendRuntimeKey, scriptFieldActiveSessionCount, -1).Result()
		if countErr != nil {
			return countErr
		}

		if count < 0 {
			return s.client.HSet(redisCtx, backendRuntimeKey, scriptFieldActiveSessionCount, 0).Err()
		}

		return nil
	})
}

// runRepairableIndexCommand records a non-authoritative repair Redis write.
func (s *RedisSessionStore) runRepairableIndexCommand(ctx context.Context, operation string, command func(context.Context) error) {
	redisCtx := redisContext(ctx)
	started := time.Now()
	err := ClassifyRedisError(operation, command(redisCtx))
	s.recordRedisOperation(redisCtx, operation, started, err)
}

// runRepairableIndexCountCommand records a repairable write and counts successful removals.
func (s *RedisSessionStore) runRepairableIndexCountCommand(
	ctx context.Context,
	operation string,
	command func(context.Context) (int64, error),
) {
	redisCtx := redisContext(ctx)
	started := time.Now()
	count, err := command(redisCtx)
	classified := ClassifyRedisError(operation, err)
	s.recordRedisOperation(redisCtx, operation, started, classified)

	if classified == nil && count > 0 {
		s.incrementAggregateRepairCount(ctx, aggregateFieldStaleIndexEntries, int(count))
	}
}

// redisZ converts a millisecond timestamp into a Redis sorted-set score.
func redisZ(score time.Time, member string) redis.Z {
	return redis.Z{Score: float64(score.UnixMilli()), Member: member}
}

// userIndexValue stores enough identity to read one affinity without key material.
func userIndexValue(tenant string, accountKey string) string {
	return strings.TrimSpace(tenant) + "\t" + strings.TrimSpace(accountKey)
}

type parsedBackendScriptFields struct {
	Fields            map[string]string
	Status            string
	BackendIdentifier string
	ServerTime        time.Time
}

// parseBackendScriptFields reads common backend script fields and server time.
func parseBackendScriptFields(value any) (parsedBackendScriptFields, error) {
	fields, err := parseScriptFields(value)
	if err != nil {
		return parsedBackendScriptFields{}, err
	}

	status, backendIdentifier, err := parseScriptStatusAndBackend(fields)
	if err != nil {
		return parsedBackendScriptFields{}, err
	}

	serverTime, err := parseTimeField(fields, scriptFieldServerTimeMS)
	if err != nil {
		return parsedBackendScriptFields{}, err
	}

	return parsedBackendScriptFields{
		Fields:            fields,
		Status:            status,
		BackendIdentifier: backendIdentifier,
		ServerTime:        serverTime,
	}, nil
}

// parseScriptStatusAndBackend reads common backend script identity fields.
func parseScriptStatusAndBackend(fields map[string]string) (string, string, error) {
	status := fields[scriptFieldStatus]
	if status == "" {
		return "", "", newStateError(RedisErrorKindAmbiguousState, "script_result", "status required", nil)
	}

	backendIdentifier := fields[scriptFieldBackendID]
	if backendIdentifier == "" {
		return "", "", newStateError(RedisErrorKindAmbiguousState, "script_result", "backend id required", nil)
	}

	return status, backendIdentifier, nil
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

// parseOptionalControlAction normalizes and validates script control actions.
func parseOptionalControlAction(value string) (ControlAction, error) {
	action := ControlAction(strings.TrimSpace(value))
	if action == "" {
		return ControlActionNone, nil
	}

	switch action {
	case ControlActionNone, ControlActionKick, ControlActionDrain, ControlActionMoveGenerationChanged:
		return action, nil
	default:
		return "", newStateError(RedisErrorKindAmbiguousState, "script_result", "unsupported control action", nil)
	}
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
