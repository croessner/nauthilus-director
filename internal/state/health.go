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

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/redis/go-redis/v9"
)

const (
	scriptHealthOwnerAcquire = "health_owner_acquire"
	scriptHealthOwnerRenew   = "health_owner_renew"
	scriptHealthStatePublish = "health_state_publish"
	stateBoolFalse           = "false"
	stateBoolTrue            = "true"
)

// HealthOwnershipRequest aliases the backend health-owner request contract.
type HealthOwnershipRequest = backend.HealthOwnershipRequest

// HealthOwnershipRecord aliases the backend health-owner result contract.
type HealthOwnershipRecord = backend.HealthOwnershipRecord

// HealthPublishRequest aliases the backend health publication contract.
type HealthPublishRequest = backend.HealthPublishRequest

// PublishInstanceHeartbeat records this director instance as live for health ownership.
func (s *RedisSessionStore) PublishInstanceHeartbeat(ctx context.Context, instanceID string, ttl time.Duration) error {
	instanceKey, err := s.keys.InstanceKey(instanceID)
	if err != nil {
		return err
	}

	if ttl <= 0 {
		return newStateError(RedisErrorKindAmbiguousState, "instance_heartbeat", "ttl required", nil)
	}

	return ClassifyRedisError("instance_heartbeat", s.client.Set(redisContext(ctx), instanceKey, "1", ttl).Err())
}

// AcquireHealthOwner creates or renews a fenced deep-health owner lease.
func (s *RedisSessionStore) AcquireHealthOwner(ctx context.Context, request HealthOwnershipRequest) (HealthOwnershipRecord, error) {
	if err := validateHealthOwnershipRequest(request, false); err != nil {
		return HealthOwnershipRecord{}, err
	}

	instanceKey, ownerKey, stateKey, err := s.healthOwnershipKeys(request)
	if err != nil {
		return HealthOwnershipRecord{}, err
	}

	value, err := s.runScript(ctx, scriptHealthOwnerAcquire, []string{instanceKey, ownerKey, stateKey},
		normalizedStateValue(request.InstanceID),
		normalizedStateValue(request.BackendIdentifier),
		durationMilliseconds(request.LeaseTTL),
	)
	if err != nil {
		return HealthOwnershipRecord{}, err
	}

	return parseHealthOwnershipRecord(value)
}

// RenewHealthOwner extends a fenced owner lease only for the current owner.
func (s *RedisSessionStore) RenewHealthOwner(ctx context.Context, request HealthOwnershipRequest) (HealthOwnershipRecord, error) {
	if err := validateHealthOwnershipRequest(request, true); err != nil {
		return HealthOwnershipRecord{}, err
	}

	instanceKey, ownerKey, _, err := s.healthOwnershipKeys(request)
	if err != nil {
		return HealthOwnershipRecord{}, err
	}

	value, err := s.runScript(ctx, scriptHealthOwnerRenew, []string{instanceKey, ownerKey},
		normalizedStateValue(request.InstanceID),
		normalizedStateValue(request.BackendIdentifier),
		request.FencingToken,
		durationMilliseconds(request.LeaseTTL),
	)
	if err != nil {
		return HealthOwnershipRecord{}, err
	}

	return parseHealthOwnershipRecord(value)
}

// PublishHealthState writes a fenced deep-health result after a credentialed check.
func (s *RedisSessionStore) PublishHealthState(ctx context.Context, request HealthPublishRequest) (backend.HealthState, error) {
	if err := validateHealthPublishRequest(request); err != nil {
		return backend.HealthState{}, err
	}

	ownerKey, stateKey, err := s.healthStateKeys(request.BackendIdentifier)
	if err != nil {
		return backend.HealthState{}, err
	}

	value, err := s.runScript(ctx, scriptHealthStatePublish, []string{ownerKey, stateKey},
		normalizedStateValue(request.BackendIdentifier),
		normalizedStateValue(request.InstanceID),
		request.FencingToken,
		string(request.State.Status),
		normalizedStateValue(request.State.ReasonClass),
		durationMilliseconds(request.TTL),
	)
	if err != nil {
		return backend.HealthState{}, err
	}

	return parsePublishedHealthState(value)
}

// ReadHealthState reads the last published deep-health result without mutating it.
func (s *RedisSessionStore) ReadHealthState(ctx context.Context, backendIdentifier string) (backend.HealthState, error) {
	_, stateKey, err := s.healthStateKeys(backendIdentifier)
	if err != nil {
		return backend.HealthState{}, err
	}

	fields, err := s.client.HGetAll(redisContext(ctx), stateKey).Result()
	if err != nil && !isRedisNil(err) {
		return backend.HealthState{}, ClassifyRedisError("health_state_read", err)
	}

	return parseHealthStateFields(fields)
}

// BackendSnapshot reads runtime override, active count and health state for selector input.
func (s *RedisSessionStore) BackendSnapshot(ctx context.Context, backendIdentifier string) (backend.RuntimeSnapshot, error) {
	runtimeKey, _, err := s.backendRuntimeKeys(backendIdentifier)
	if err != nil {
		return backend.RuntimeSnapshot{}, err
	}

	fields, err := s.client.HGetAll(redisContext(ctx), runtimeKey).Result()
	if err != nil && !isRedisNil(err) {
		return backend.RuntimeSnapshot{}, ClassifyRedisError("backend_snapshot", err)
	}

	override, activeSessions, err := parseRuntimeSnapshotFields(fields)
	if err != nil {
		return backend.RuntimeSnapshot{}, err
	}

	health, err := s.ReadHealthState(ctx, backendIdentifier)
	if err != nil {
		return backend.RuntimeSnapshot{}, err
	}

	return backend.RuntimeSnapshot{
		RuntimeOverride: override,
		Health:          health,
		ActiveSessions:  activeSessions,
	}, nil
}

// healthOwnershipKeys returns all keys needed for an ownership acquisition.
func (s *RedisSessionStore) healthOwnershipKeys(request HealthOwnershipRequest) (string, string, string, error) {
	instanceKey, err := s.keys.InstanceKey(request.InstanceID)
	if err != nil {
		return "", "", "", err
	}

	ownerKey, stateKey, err := s.healthStateKeys(request.BackendIdentifier)
	if err != nil {
		return "", "", "", err
	}

	return instanceKey, ownerKey, stateKey, nil
}

// healthStateKeys returns the owner and state keys for one backend.
func (s *RedisSessionStore) healthStateKeys(backendIdentifier string) (string, string, error) {
	ownerKey, err := s.keys.HealthOwnerKey(backendIdentifier)
	if err != nil {
		return "", "", err
	}

	stateKey, err := s.keys.HealthStateKey(backendIdentifier)
	if err != nil {
		return "", "", err
	}

	return ownerKey, stateKey, nil
}

// validateHealthOwnershipRequest rejects owner lease payloads that cannot be fenced.
func validateHealthOwnershipRequest(request HealthOwnershipRequest, requireToken bool) error {
	if strings.TrimSpace(request.InstanceID) == "" {
		return newStateError(RedisErrorKindAmbiguousState, "health_owner", "instance id required", nil)
	}

	if strings.TrimSpace(request.BackendIdentifier) == "" {
		return newStateError(RedisErrorKindAmbiguousState, "health_owner", "backend id required", nil)
	}

	if request.LeaseTTL <= 0 {
		return newStateError(RedisErrorKindAmbiguousState, "health_owner", "lease ttl required", nil)
	}

	if requireToken && request.FencingToken <= 0 {
		return newStateError(RedisErrorKindAmbiguousState, "health_owner", "fencing token required", nil)
	}

	return nil
}

// validateHealthPublishRequest rejects stale or incomplete health publication attempts.
func validateHealthPublishRequest(request HealthPublishRequest) error {
	if strings.TrimSpace(request.InstanceID) == "" {
		return newStateError(RedisErrorKindAmbiguousState, "health_publish", "instance id required", nil)
	}

	if strings.TrimSpace(request.BackendIdentifier) == "" {
		return newStateError(RedisErrorKindAmbiguousState, "health_publish", "backend id required", nil)
	}

	if request.FencingToken <= 0 {
		return newStateError(RedisErrorKindAmbiguousState, "health_publish", "fencing token required", nil)
	}

	if request.TTL <= 0 {
		return newStateError(RedisErrorKindAmbiguousState, "health_publish", "ttl required", nil)
	}

	_, err := request.State.Normalize(time.Now().UTC())

	return err
}

// parseHealthOwnershipRecord converts flat Lua owner output into a typed record.
func parseHealthOwnershipRecord(value any) (HealthOwnershipRecord, error) {
	fields, err := parseScriptFields(value)
	if err != nil {
		return HealthOwnershipRecord{}, err
	}

	record := HealthOwnershipRecord{
		Status:            fields["status"],
		InstanceID:        fields["instance_id"],
		OwnerInstanceID:   fields["owner_instance_id"],
		BackendIdentifier: fields["backend_id"],
		Owned:             fields["owner_instance_id"] != "" && fields["owner_instance_id"] == fields["instance_id"],
	}

	if record.Status == "" {
		return HealthOwnershipRecord{}, newStateError(RedisErrorKindAmbiguousState, "script_result", "status required", nil)
	}

	if record.BackendIdentifier == "" {
		return HealthOwnershipRecord{}, newStateError(RedisErrorKindAmbiguousState, "script_result", "backend id required", nil)
	}

	fencingToken, err := parseInt64Field(fields, "fencing_token")
	if err != nil {
		return HealthOwnershipRecord{}, err
	}

	serverTime, err := parseTimeField(fields, "server_time_ms")
	if err != nil {
		return HealthOwnershipRecord{}, err
	}

	expiresAt, err := parseTimeField(fields, "expires_at_ms")
	if err != nil {
		return HealthOwnershipRecord{}, err
	}

	record.FencingToken = fencingToken
	record.ServerTime = serverTime
	record.ExpiresAt = expiresAt

	return record, nil
}

// parsePublishedHealthState converts flat Lua health publication output.
func parsePublishedHealthState(value any) (backend.HealthState, error) {
	fields, err := parseScriptFields(value)
	if err != nil {
		return backend.HealthState{}, err
	}

	return parseHealthStateFields(fields)
}

// parseHealthStateFields converts Redis hash fields into backend health state.
func parseHealthStateFields(fields map[string]string) (backend.HealthState, error) {
	if len(fields) == 0 || strings.TrimSpace(fields["status"]) == "" {
		return backend.HealthState{}, nil
	}

	checkedAt, err := parseTimeField(fields, "checked_at_ms")
	if err != nil {
		return backend.HealthState{}, err
	}

	expiresAt, err := parseTimeField(fields, "expires_at_ms")
	if err != nil {
		return backend.HealthState{}, err
	}

	state := backend.HealthState{
		Enabled:     true,
		Status:      backend.HealthStatus(fields["status"]),
		ReasonClass: fields["reason_class"],
		Generation:  fields["generation"],
		CheckedAt:   checkedAt,
		ExpiresAt:   expiresAt,
	}

	return state.Normalize(time.Now().UTC())
}

// parseRuntimeSnapshotFields converts backend runtime hash fields into selector input.
func parseRuntimeSnapshotFields(fields map[string]string) (backend.RuntimeOverride, int, error) {
	override := backend.RuntimeOverride{Generation: fields["generation"]}

	inService, err := parseRuntimeInServiceOverride(fields)
	if err != nil {
		return backend.RuntimeOverride{}, 0, err
	}

	weight, err := parseRuntimeWeightOverride(fields)
	if err != nil {
		return backend.RuntimeOverride{}, 0, err
	}

	activeSessions, err := parseRuntimeActiveSessions(fields)
	if err != nil {
		return backend.RuntimeOverride{}, 0, err
	}

	override.InService = inService
	override.Weight = weight
	override.Maintenance = parseRuntimeMaintenanceOverride(fields)
	override.Drain = parseRuntimeDrainOverride(fields)

	return override, activeSessions, nil
}

// parseRuntimeInServiceOverride extracts an optional runtime in-service flag.
func parseRuntimeInServiceOverride(fields map[string]string) (*bool, error) {
	if value, ok := fields["in_service"]; ok && value != "" {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return nil, newStateError(RedisErrorKindAmbiguousState, "backend_snapshot", "in_service invalid", err)
		}

		return &parsed, nil
	}

	return nil, nil
}

// parseRuntimeWeightOverride extracts an optional runtime weight override.
func parseRuntimeWeightOverride(fields map[string]string) (*int, error) {
	if value, ok := fields["weight"]; ok && value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return nil, newStateError(RedisErrorKindAmbiguousState, "backend_snapshot", "weight invalid", err)
		}

		return &parsed, nil
	}

	return nil, nil
}

// parseRuntimeMaintenanceOverride extracts an optional runtime maintenance mode.
func parseRuntimeMaintenanceOverride(fields map[string]string) *backend.MaintenanceState {
	if value, ok := fields["maintenance_mode"]; ok && value != "" {
		maintenance := backend.MaintenanceState{
			Mode:       backend.MaintenanceMode(value),
			Generation: fields["generation"],
		}

		return &maintenance
	}

	return nil
}

// parseRuntimeDrainOverride extracts an optional runtime drain state.
func parseRuntimeDrainOverride(fields map[string]string) *backend.DrainState {
	if fields["drain_enabled"] != stateBoolTrue {
		return nil
	}

	drain := backend.DrainState{
		Enabled:    true,
		Mode:       backend.DrainMode(fields["drain_mode"]),
		Generation: fields["generation"],
	}

	if startedAt, err := parseTimeField(fields, "drain_started_at_ms"); err == nil {
		drain.StartedAt = startedAt
	}

	return &drain
}

// parseRuntimeActiveSessions extracts the backend active-session counter.
func parseRuntimeActiveSessions(fields map[string]string) (int, error) {
	if value, ok := fields["active_session_count"]; ok && value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 0 {
			return 0, newStateError(RedisErrorKindAmbiguousState, "backend_snapshot", "active session count invalid", err)
		}

		return parsed, nil
	}

	return 0, nil
}

// parseInt64Field extracts a signed integer field from a script result.
func parseInt64Field(fields map[string]string, name string) (int64, error) {
	value, ok := fields[name]
	if !ok {
		return 0, newStateError(RedisErrorKindAmbiguousState, "script_result", name+" required", nil)
	}

	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, newStateError(RedisErrorKindAmbiguousState, "script_result", name+" invalid", err)
	}

	return parsed, nil
}

// isRedisNil reports whether err is Redis' missing-key sentinel.
func isRedisNil(err error) bool {
	return err == redis.Nil
}
