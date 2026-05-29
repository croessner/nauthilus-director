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
	backendReservationReapCount = "backend_reservation_reap_count"
	backendReservationScan      = "backend_reservation_scan"
)

// ReserveBackendCapacity reserves one backend capacity slot before affinity attach.
func (s *RedisSessionStore) ReserveBackendCapacity(
	ctx context.Context,
	request BackendReservationRequest,
) (BackendReservationRecord, error) {
	if err := validateBackendReservationRequest(request); err != nil {
		return BackendReservationRecord{}, err
	}

	keys, err := s.keys.BackendReservationKeys(request.BackendIdentifier)
	if err != nil {
		return BackendReservationRecord{}, err
	}

	value, err := s.runScript(ctx, scriptBackendReserve, []string{keys.State, keys.Due},
		normalizedStateValue(request.BackendIdentifier),
		normalizedStateValue(request.ReservationID),
		request.MaxConnections,
		durationMilliseconds(request.LeaseTTL),
	)
	if err != nil {
		return BackendReservationRecord{}, err
	}

	record, err := parseBackendReservationRecord(value)
	if err != nil {
		return BackendReservationRecord{}, err
	}

	s.writeRepairableBackendReservationIndex(ctx, request.BackendIdentifier)
	s.setBackendReservedAggregate(ctx, record.BackendIdentifier, record.BackendActiveCount)

	return record, nil
}

// ReleaseBackendReservation idempotently releases one reserved backend slot.
func (s *RedisSessionStore) ReleaseBackendReservation(
	ctx context.Context,
	request BackendReservationReleaseRequest,
) (BackendReservationRecord, error) {
	if err := validateBackendReservationReleaseRequest(request); err != nil {
		return BackendReservationRecord{}, err
	}

	keys, err := s.keys.BackendReservationKeys(request.BackendIdentifier)
	if err != nil {
		return BackendReservationRecord{}, err
	}

	value, err := s.runScript(ctx, scriptBackendRelease, []string{keys.State, keys.Due},
		normalizedStateValue(request.BackendIdentifier),
		normalizedStateValue(request.ReservationID),
	)
	if err != nil {
		return BackendReservationRecord{}, err
	}

	record, err := parseBackendReservationRecord(value)
	if err != nil {
		return BackendReservationRecord{}, err
	}

	s.setBackendReservedAggregate(ctx, record.BackendIdentifier, record.BackendActiveCount)

	return record, nil
}

// ReapBackendReservations repairs expired reservation leases for one backend slot.
func (s *RedisSessionStore) ReapBackendReservations(
	ctx context.Context,
	request BackendReservationReapRequest,
) (BackendReservationRecord, error) {
	if err := validateBackendReservationReapRequest(request); err != nil {
		return BackendReservationRecord{}, err
	}

	keys, err := s.keys.BackendReservationKeys(request.BackendIdentifier)
	if err != nil {
		return BackendReservationRecord{}, err
	}

	value, err := s.runScript(ctx, scriptBackendReap, []string{keys.State, keys.Due},
		normalizedStateValue(request.BackendIdentifier),
		request.Limit,
	)
	if err != nil {
		return BackendReservationRecord{}, err
	}

	record, err := parseBackendReservationRecord(value)
	if err != nil {
		return BackendReservationRecord{}, err
	}

	s.setBackendReservedAggregate(ctx, record.BackendIdentifier, record.BackendActiveCount)
	s.incrementAggregateRepairCount(ctx, aggregateFieldBackendReservations, record.RepairedCount)

	return record, nil
}

// backendReservationActiveCount reads the Redis-coordinated backend capacity count.
func (s *RedisSessionStore) backendReservationActiveCount(ctx context.Context, backendIdentifier string) (int, error) {
	keys, err := s.keys.BackendReservationKeys(backendIdentifier)
	if err != nil {
		return 0, err
	}

	redisCtx := redisContext(ctx)
	started := time.Now()

	value, err := s.client.HGet(redisCtx, keys.State, scriptFieldActiveSessionCount).Result()
	if errors.Is(err, redis.Nil) {
		s.recordRedisOperation(redisCtx, "backend_reservation_count", started, nil)

		return 0, nil
	}

	if err != nil {
		classified := ClassifyRedisError("backend_reservation_count", err)
		s.recordRedisOperation(redisCtx, "backend_reservation_count", started, classified)

		return 0, classified
	}

	s.recordRedisOperation(redisCtx, "backend_reservation_count", started, nil)

	return parseBackendReservationActiveCount(value)
}

// reapIndexedBackendReservations repairs expired reservations from the backend index.
func (s *RedisSessionStore) reapIndexedBackendReservations(ctx context.Context, limit int) (int, error) {
	if limit <= 0 {
		return 0, nil
	}

	redisCtx := redisContext(ctx)
	cursor := uint64(0)
	repaired := 0

	for repaired < limit {
		started := time.Now()

		backendIDs, next, err := s.client.SScan(redisCtx, s.keys.BackendIndexKey(), cursor, "*", int64(limit-repaired)).Result()
		if err != nil {
			classified := ClassifyRedisError(backendReservationScan, err)
			s.recordRedisOperation(redisCtx, backendReservationScan, started, classified)

			return repaired, classified
		}

		s.recordRedisOperation(redisCtx, backendReservationScan, started, nil)

		for _, backendID := range backendIDs {
			record, reapErr := s.ReapBackendReservations(ctx, BackendReservationReapRequest{
				BackendIdentifier: backendID,
				Limit:             limit - repaired,
			})
			if reapErr != nil {
				return repaired, reapErr
			}

			repaired += record.RepairedCount
			if repaired >= limit {
				break
			}
		}

		if next == 0 || len(backendIDs) == 0 {
			break
		}

		cursor = next
	}

	return repaired, nil
}

// writeRepairableBackendReservationIndex makes stale reservation repair discoverable.
func (s *RedisSessionStore) writeRepairableBackendReservationIndex(ctx context.Context, backendIdentifier string) {
	s.runRepairableIndexCommand(ctx, "backend_reservation_index", func(redisCtx context.Context) error {
		return s.client.SAdd(redisCtx, s.keys.BackendIndexKey(), backendIdentifier).Err()
	})
}

// validateBackendReservationRequest checks capacity reservation input.
func validateBackendReservationRequest(request BackendReservationRequest) error {
	if strings.TrimSpace(request.BackendIdentifier) == "" {
		return newStateError(RedisErrorKindAmbiguousState, scriptBackendReserve, "backend id required", nil)
	}

	if strings.TrimSpace(request.ReservationID) == "" {
		return newStateError(RedisErrorKindAmbiguousState, scriptBackendReserve, "reservation id required", nil)
	}

	if request.MaxConnections <= 0 {
		return newStateError(RedisErrorKindAmbiguousState, scriptBackendReserve, "max connections required", nil)
	}

	if request.LeaseTTL <= 0 {
		return newStateError(RedisErrorKindAmbiguousState, scriptBackendReserve, "reservation ttl required", nil)
	}

	return nil
}

// validateBackendReservationReleaseRequest checks reservation release input.
func validateBackendReservationReleaseRequest(request BackendReservationReleaseRequest) error {
	if strings.TrimSpace(request.BackendIdentifier) == "" {
		return newStateError(RedisErrorKindAmbiguousState, scriptBackendRelease, "backend id required", nil)
	}

	if strings.TrimSpace(request.ReservationID) == "" {
		return newStateError(RedisErrorKindAmbiguousState, scriptBackendRelease, "reservation id required", nil)
	}

	return nil
}

// validateBackendReservationReapRequest checks reservation repair input.
func validateBackendReservationReapRequest(request BackendReservationReapRequest) error {
	if strings.TrimSpace(request.BackendIdentifier) == "" {
		return newStateError(RedisErrorKindAmbiguousState, scriptBackendReap, "backend id required", nil)
	}

	if request.Limit <= 0 {
		return newStateError(RedisErrorKindAmbiguousState, scriptBackendReap, "limit must be greater than zero", nil)
	}

	return nil
}

// parseBackendReservationRecord converts backend reservation script output.
func parseBackendReservationRecord(value any) (BackendReservationRecord, error) {
	parsed, err := parseBackendScriptFields(value)
	if err != nil {
		return BackendReservationRecord{}, err
	}

	record := BackendReservationRecord{
		Status:            parsed.Status,
		BackendIdentifier: parsed.BackendIdentifier,
		ReservationID:     parsed.Fields[scriptFieldBackendReservation],
		ServerTime:        parsed.ServerTime,
	}

	record.BackendActiveCount, err = parseIntField(parsed.Fields, scriptFieldActiveSessionCount)
	if err != nil {
		return BackendReservationRecord{}, err
	}

	record.RepairedCount, err = parseOptionalIntField(parsed.Fields, "repaired_reservations")
	if err != nil {
		return BackendReservationRecord{}, err
	}

	record.LeaseExpiresAt, err = parseTimeField(parsed.Fields, scriptFieldLeaseExpiresAtMS)
	if err != nil {
		return BackendReservationRecord{}, err
	}

	return record, nil
}

// parseBackendReservationActiveCount validates one Redis count field.
func parseBackendReservationActiveCount(value string) (int, error) {
	count, err := strconv.Atoi(value)
	if err != nil || count < 0 {
		return 0, newStateError(RedisErrorKindAmbiguousState, "backend_reservation_count", "active session count invalid", err)
	}

	return count, nil
}

// parseOptionalIntField extracts an optional integer field from a script result.
func parseOptionalIntField(fields map[string]string, name string) (int, error) {
	value, ok := fields[name]
	if !ok || value == "" {
		return 0, nil
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, newStateError(RedisErrorKindAmbiguousState, "script_result", name+" invalid", err)
	}

	return parsed, nil
}
