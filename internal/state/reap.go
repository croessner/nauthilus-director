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

const scriptReap = "reap"

// ReapSessions repairs expired session leases, counts and listing indexes.
func (s *RedisSessionStore) ReapSessions(ctx context.Context, request ReapRequest) (ReapRecord, error) {
	if request.Limit <= 0 {
		return ReapRecord{}, newStateError(RedisErrorKindAmbiguousState, scriptReap, "limit must be greater than zero", nil)
	}

	remaining := request.Limit

	deadline := time.Time{}
	if request.MaxPassDuration > 0 {
		deadline = time.Now().Add(request.MaxPassDuration)
	}

	total := ReapRecord{Status: "reaped"}

	for shard := 0; shard < s.keys.sessionIndexShards && remaining > 0; shard++ {
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			break
		}

		sessionIndexKey, err := s.keys.SessionIndexShardKeyByNumber(shard)
		if err != nil {
			return ReapRecord{}, err
		}

		sessionDueIndexKey, err := s.keys.SessionDueIndexShardKeyByNumber(shard)
		if err != nil {
			return ReapRecord{}, err
		}

		value, err := s.runScript(ctx, scriptReap, []string{sessionIndexKey, sessionDueIndexKey}, remaining)
		if err != nil {
			return ReapRecord{}, err
		}

		record, err := parseReapRecord(value)
		if err != nil {
			return ReapRecord{}, err
		}

		total.ScannedSessions += record.ScannedSessions
		total.ExpiredSessions += record.ExpiredSessions
		total.StaleIndexEntries += record.StaleIndexEntries
		total.RepairedBackends += s.releaseReapedBackendReservations(ctx, record.releases)
		s.removeReapedSessionAggregates(ctx, record.aggregateRemovals)
		s.addReapedIdleAffinities(ctx, record.idleAffinities)
		total.ServerTime = record.ServerTime

		if total.ScannedSessions > 0 {
			total.Status = record.Status
		}

		remaining -= record.ScannedSessions
	}

	repairedReservations, err := s.reapIndexedBackendReservations(ctx, request.Limit)
	if err != nil {
		return ReapRecord{}, err
	}

	total.RepairedBackends += repairedReservations
	s.incrementAggregateRepairCount(ctx, aggregateFieldExpiredSessions, total.ExpiredSessions)
	s.incrementAggregateRepairCount(ctx, aggregateFieldStaleIndexEntries, total.StaleIndexEntries)

	return total, nil
}

// releaseReapedBackendReservations applies backend release deltas returned by session repair.
func (s *RedisSessionStore) releaseReapedBackendReservations(ctx context.Context, releases []BackendReservationReleaseRequest) int {
	repaired := 0

	for _, release := range releases {
		record, err := s.ReleaseBackendReservation(ctx, release)
		if err != nil {
			s.recordRedisOperation(redisContext(ctx), "reap_backend_reservation_release", time.Now(), err)

			continue
		}

		repaired += record.RepairedCount
	}

	s.incrementAggregateRepairCount(ctx, aggregateFieldBackendReservations, repaired)

	return repaired
}

// removeReapedSessionAggregates removes aggregate markers for expired sessions.
func (s *RedisSessionStore) removeReapedSessionAggregates(ctx context.Context, sessionIDs []string) {
	for _, sessionID := range sessionIDs {
		s.removeSessionAggregate(ctx, sessionID)
	}
}

// addReapedIdleAffinities records affinities that became idle during reaping.
func (s *RedisSessionStore) addReapedIdleAffinities(ctx context.Context, affinities []aggregateIdleAffinity) {
	for _, affinity := range affinities {
		s.addIdleAffinityAggregate(ctx, affinity)
	}
}

// parseReapRecord converts the expired-session repair payload.
func parseReapRecord(value any) (ReapRecord, error) {
	fields, err := parseScriptFields(value)
	if err != nil {
		return ReapRecord{}, err
	}

	record := ReapRecord{Status: fields["status"]}
	if record.Status == "" {
		return ReapRecord{}, newStateError(RedisErrorKindAmbiguousState, "script_result", "status required", nil)
	}

	record.ScannedSessions, err = parseIntField(fields, "scanned_sessions")
	if err != nil {
		return ReapRecord{}, err
	}

	record.ExpiredSessions, err = parseIntField(fields, "expired_sessions")
	if err != nil {
		return ReapRecord{}, err
	}

	record.RepairedBackends, err = parseIntField(fields, "repaired_backends")
	if err != nil {
		return ReapRecord{}, err
	}

	record.StaleIndexEntries, err = parseOptionalIntField(fields, "stale_index_entries")
	if err != nil {
		return ReapRecord{}, err
	}

	record.releases, err = parseBackendReservationReleases(fields["reservation_releases"])
	if err != nil {
		return ReapRecord{}, err
	}

	record.aggregateRemovals = parseAggregateRemovalSessions(fields["aggregate_removals"])

	record.idleAffinities, err = parseAggregateIdleAffinities(fields["idle_affinities"])
	if err != nil {
		return ReapRecord{}, err
	}

	record.ServerTime, err = parseTimeField(fields, "server_time_ms")
	if err != nil {
		return ReapRecord{}, err
	}

	return record, nil
}

// parseBackendReservationReleases converts a compact release-delta payload.
func parseBackendReservationReleases(value string) ([]BackendReservationReleaseRequest, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}

	lines := strings.Split(value, "\n")
	releases := make([]BackendReservationReleaseRequest, 0, len(lines))

	for _, line := range lines {
		parts := strings.Split(line, "\t")
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return nil, newStateError(RedisErrorKindAmbiguousState, "script_result", "reservation release invalid", nil)
		}

		releases = append(releases, BackendReservationReleaseRequest{
			BackendIdentifier: strings.TrimSpace(parts[0]),
			ReservationID:     strings.TrimSpace(parts[1]),
		})
	}

	return releases, nil
}

// parseAggregateRemovalSessions converts bounded reaper aggregate removal payloads.
func parseAggregateRemovalSessions(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}

	lines := strings.Split(value, "\n")

	sessionIDs := make([]string, 0, len(lines))
	for _, line := range lines {
		sessionID := strings.TrimSpace(line)
		if sessionID != "" {
			sessionIDs = append(sessionIDs, sessionID)
		}
	}

	return sessionIDs
}

// parseAggregateIdleAffinities converts bounded reaper idle-affinity payloads.
func parseAggregateIdleAffinities(value string) ([]aggregateIdleAffinity, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}

	lines := strings.Split(value, "\n")
	affinities := make([]aggregateIdleAffinity, 0, len(lines))

	for _, line := range lines {
		parts := strings.Split(line, "\t")
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
			return nil, newStateError(RedisErrorKindAmbiguousState, "script_result", "idle affinity invalid", nil)
		}

		expiresAtMS, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
		if err != nil || expiresAtMS <= 0 {
			return nil, newStateError(RedisErrorKindAmbiguousState, "script_result", "idle affinity expiry invalid", err)
		}

		affinities = append(affinities, aggregateIdleAffinity{
			AffinityHash: strings.TrimSpace(parts[0]),
			ExpiresAt:    time.UnixMilli(expiresAtMS).UTC(),
		})
	}

	return affinities, nil
}
