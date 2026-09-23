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
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	backendAtCapacityMessage           = "backend at capacity"
	backendReservationStatusAtCapacity = "at_capacity"
	redisScoreMin                      = "-inf"
)

const (
	backendReservationReapCount = "backend_reservation_reap_count"
	backendReservationScan      = "backend_reservation_scan"

	// backendReservationBucketMarker separates the caller identity from the owning bucket.
	backendReservationBucketMarker = "#rb"
	// legacyBackendReservationBucket marks a reservation stored in the pre-bucketing group.
	legacyBackendReservationBucket = -1
)

// backendReservationRef locates one stored reservation.
type backendReservationRef struct {
	ID     string
	Bucket int
}

// backendReservationGroupState is one bucket's advisory count and due-candidate read.
type backendReservationGroupState struct {
	Bucket int
	Keys   BackendReservationKeys
	Count  int
	Due    bool
	Holds  bool
}

// ReserveBackendCapacity reserves one backend capacity slot before affinity attach.
//
// A caller identifier without a bucket suffix admits a new reservation into
// the bucket selected by that identifier. Each bucket enforces an exact share
// of max_connections, and the shares add up to the configured limit, so the
// global limit holds without a shared hot key. A full bucket spills into
// buckets with free share. The returned identifier names the owning bucket;
// passing it again refreshes that reservation, and release requires it.
func (s *RedisSessionStore) ReserveBackendCapacity(
	ctx context.Context,
	request BackendReservationRequest,
) (BackendReservationRecord, error) {
	if err := validateBackendReservationRequest(request); err != nil {
		return BackendReservationRecord{}, err
	}

	request.BackendIdentifier = normalizedStateValue(request.BackendIdentifier)
	request.ReservationID = normalizedStateValue(request.ReservationID)

	quotas, err := s.backendReservationQuotas(ctx, request.BackendIdentifier, request.MaxConnections)
	if err != nil {
		return BackendReservationRecord{}, err
	}

	if ref := parseBackendReservationRef(request.ReservationID); ref.Bucket != legacyBackendReservationBucket {
		return s.reserveInBucket(ctx, request, ref, quotas[ref.Bucket])
	}

	return s.reserveNewBackendCapacity(ctx, request, quotas)
}

// refreshBackendReservation extends a stored reservation in the group that already owns it.
//
// Identifiers issued before bucketing stay in the legacy group, so a lease
// refresh never duplicates capacity across layouts.
func (s *RedisSessionStore) refreshBackendReservation(ctx context.Context, request BackendReservationRequest) (BackendReservationRecord, error) {
	if err := validateBackendReservationRequest(request); err != nil {
		return BackendReservationRecord{}, err
	}

	request.BackendIdentifier = normalizedStateValue(request.BackendIdentifier)
	request.ReservationID = normalizedStateValue(request.ReservationID)

	if parseBackendReservationRef(request.ReservationID).Bucket == legacyBackendReservationBucket {
		return s.reserveInLegacyGroup(ctx, request)
	}

	return s.ReserveBackendCapacity(ctx, request)
}

// ReleaseBackendReservation idempotently releases one reserved backend slot.
//
// The identifier must be the one returned at admission. Identifiers issued
// before bucketing release from the legacy group.
func (s *RedisSessionStore) ReleaseBackendReservation(
	ctx context.Context,
	request BackendReservationReleaseRequest,
) (BackendReservationRecord, error) {
	if err := validateBackendReservationReleaseRequest(request); err != nil {
		return BackendReservationRecord{}, err
	}

	ref := parseBackendReservationRef(normalizedStateValue(request.ReservationID))

	keys, err := s.keys.BackendReservationGroupKeys(request.BackendIdentifier, ref.ID)
	if err != nil {
		return BackendReservationRecord{}, err
	}

	value, err := s.runScript(ctx, scriptBackendRelease, []string{keys.State, keys.Due},
		normalizedStateValue(request.BackendIdentifier),
		ref.ID,
	)
	if err != nil {
		return BackendReservationRecord{}, err
	}

	record, err := parseBackendReservationRecord(value)
	if err != nil {
		return BackendReservationRecord{}, err
	}

	if ref.Bucket == legacyBackendReservationBucket {
		s.local.storeLegacyReservationCount(record.BackendIdentifier, record.BackendActiveCount)
	}

	s.local.adjustBackendReservationTotal(record.BackendIdentifier, -record.RepairedCount)

	return record, nil
}

// ReapBackendReservations repairs expired reservation leases across every bucket of one backend.
//
// Due candidates are read in one pipeline; only groups holding an expired
// candidate run the repair script, which rechecks each lease against Redis
// time. The returned active count is the backend-wide total.
func (s *RedisSessionStore) ReapBackendReservations(
	ctx context.Context,
	request BackendReservationReapRequest,
) (BackendReservationRecord, error) {
	if err := validateBackendReservationReapRequest(request); err != nil {
		return BackendReservationRecord{}, err
	}

	backendIdentifier := normalizedStateValue(request.BackendIdentifier)
	readStartedAt := s.local.currentTime()

	groups, err := s.readBackendReservationGroups(ctx, backendIdentifier, "", true)
	if err != nil {
		return BackendReservationRecord{}, err
	}

	total := BackendReservationRecord{Status: statusReaped, BackendIdentifier: backendIdentifier, ServerTime: time.Now().UTC()}
	remaining := request.Limit

	for index := range groups {
		group := &groups[index]
		if !group.Due || remaining <= 0 {
			continue
		}

		value, runErr := s.runScript(ctx, scriptBackendReap, []string{group.Keys.State, group.Keys.Due}, backendIdentifier, remaining)
		if runErr != nil {
			return BackendReservationRecord{}, runErr
		}

		record, parseErr := parseBackendReservationRecord(value)
		if parseErr != nil {
			return BackendReservationRecord{}, parseErr
		}

		group.Count = record.BackendActiveCount
		total.RepairedCount += record.RepairedCount
		total.ServerTime = record.ServerTime
		remaining -= record.RepairedCount
	}

	total.BackendActiveCount = sumBackendReservationGroups(groups)
	s.local.storeLegacyReservationCount(backendIdentifier, groups[len(groups)-1].Count)
	s.local.storeReadBackendReservationTotal(backendIdentifier, total.BackendActiveCount, readStartedAt)
	s.incrementAggregateRepairCount(ctx, aggregateFieldBackendReservations, total.RepairedCount)

	return total, nil
}

// reserveNewBackendCapacity admits a new reservation into its preferred or a spill bucket.
func (s *RedisSessionStore) reserveNewBackendCapacity(
	ctx context.Context,
	request BackendReservationRequest,
	quotas []int,
) (BackendReservationRecord, error) {
	preferred, err := s.keys.BackendReservationBucket(request.ReservationID, activeBackendReservationBuckets(quotas))
	if err != nil {
		return BackendReservationRecord{}, err
	}

	ref := backendReservationRef{ID: formatBackendReservationID(request.ReservationID, preferred), Bucket: preferred}

	record, err := s.reserveInBucket(ctx, request, ref, quotas[preferred])
	if err == nil || !isBackendAtCapacity(err) {
		return record, err
	}

	groups, err := s.readBackendReservationGroups(ctx, request.BackendIdentifier, request.ReservationID, true)
	if err != nil {
		return BackendReservationRecord{}, err
	}

	for _, group := range groups {
		if group.Holds {
			return s.reserveInBucket(ctx, request, backendReservationRef{
				ID:     formatBackendReservationID(request.ReservationID, group.Bucket),
				Bucket: group.Bucket,
			}, quotas[group.Bucket])
		}
	}

	for _, bucket := range spillBackendReservationBuckets(groups, quotas, preferred) {
		record, err = s.reserveInBucket(ctx, request, backendReservationRef{
			ID:     formatBackendReservationID(request.ReservationID, bucket),
			Bucket: bucket,
		}, quotas[bucket])
		if err == nil || !isBackendAtCapacity(err) {
			return record, err
		}
	}

	// Every share is used right now. Selection in this process should treat the
	// backend as saturated until fresher evidence arrives.
	s.local.storeBackendReservationTotal(request.BackendIdentifier, request.MaxConnections)

	return BackendReservationRecord{}, backendAtCapacityError()
}

// reserveInBucket admits or refreshes one reservation inside a single bucket slot.
func (s *RedisSessionStore) reserveInBucket(
	ctx context.Context,
	request BackendReservationRequest,
	ref backendReservationRef,
	quota int,
) (BackendReservationRecord, error) {
	keys, err := s.keys.BackendReservationBucketKeys(request.BackendIdentifier, ref.Bucket)
	if err != nil {
		return BackendReservationRecord{}, err
	}

	return s.runBackendReserveScript(ctx, request, keys, ref.ID, quota)
}

// reserveInLegacyGroup refreshes a reservation created before bucketing without moving it.
func (s *RedisSessionStore) reserveInLegacyGroup(ctx context.Context, request BackendReservationRequest) (BackendReservationRecord, error) {
	keys, err := s.keys.LegacyBackendReservationKeys(request.BackendIdentifier)
	if err != nil {
		return BackendReservationRecord{}, err
	}

	record, err := s.runBackendReserveScript(ctx, request, keys, request.ReservationID, request.MaxConnections)
	if err == nil {
		s.local.storeLegacyReservationCount(request.BackendIdentifier, record.BackendActiveCount)
	}

	return record, err
}

// runBackendReserveScript executes the reserve script and publishes repair side effects.
func (s *RedisSessionStore) runBackendReserveScript(
	ctx context.Context,
	request BackendReservationRequest,
	keys BackendReservationKeys,
	reservationID string,
	capacity int,
) (BackendReservationRecord, error) {
	value, err := s.runScript(ctx, scriptBackendReserve, []string{keys.State, keys.Due},
		request.BackendIdentifier,
		reservationID,
		capacity,
		durationMilliseconds(request.LeaseTTL),
	)
	if err != nil {
		return BackendReservationRecord{}, err
	}

	record, err := parseBackendReservationRecord(value)
	if err != nil {
		return BackendReservationRecord{}, err
	}

	s.incrementAggregateRepairCount(ctx, aggregateFieldBackendReservations, record.RepairedCount)
	s.local.adjustBackendReservationTotal(request.BackendIdentifier, record.created-record.RepairedCount)

	if record.Status == backendReservationStatusAtCapacity {
		return BackendReservationRecord{}, backendAtCapacityError()
	}

	s.ensureBackendIndexed(ctx, request.BackendIdentifier)

	return record, nil
}

// backendReservationQuotas returns each bucket's exact share of the remaining capacity.
func (s *RedisSessionStore) backendReservationQuotas(ctx context.Context, backendIdentifier string, maxConnections int) ([]int, error) {
	legacyCount, err := s.legacyBackendReservationCount(ctx, backendIdentifier)
	if err != nil {
		return nil, err
	}

	return backendReservationBucketQuotas(maxConnections-legacyCount, s.keys.BackendReservationBucketCount()), nil
}

// legacyBackendReservationCount returns the recently observed pre-bucketing reservation count.
func (s *RedisSessionStore) legacyBackendReservationCount(ctx context.Context, backendIdentifier string) (int, error) {
	if count, ok := s.local.legacyReservationCount(backendIdentifier); ok {
		return count, nil
	}

	keys, err := s.keys.LegacyBackendReservationKeys(backendIdentifier)
	if err != nil {
		return 0, err
	}

	redisCtx := redisContext(ctx)
	started := time.Now()

	value, err := s.client.HGet(redisCtx, keys.State, scriptFieldActiveSessionCount).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		classified := ClassifyRedisError("backend_reservation_legacy_count", err)
		s.recordRedisOperation(redisCtx, "backend_reservation_legacy_count", started, classified)

		return 0, classified
	}

	s.recordRedisOperation(redisCtx, "backend_reservation_legacy_count", started, nil)

	count := 0
	if err == nil {
		count, err = parseBackendReservationActiveCount(value)
		if err != nil {
			return 0, err
		}
	}

	s.local.storeLegacyReservationCount(backendIdentifier, count)

	return count, nil
}

// backendReservationActiveCount reads the exact backend-wide count across legacy and bucket groups.
func (s *RedisSessionStore) backendReservationActiveCount(ctx context.Context, backendIdentifier string) (int, error) {
	backendIdentifier = normalizedStateValue(backendIdentifier)
	readStartedAt := s.local.currentTime()

	groups, err := s.readBackendReservationGroups(ctx, backendIdentifier, "", false)
	if err != nil {
		return 0, err
	}

	total := sumBackendReservationGroups(groups)
	s.local.storeReadBackendReservationTotal(backendIdentifier, total, readStartedAt)

	return total, nil
}

// advisoryBackendReservationCount returns the backend-wide count for selection reads.
//
// A count observed within backendReservationTotalTTL is reused; otherwise all
// groups are read once and cached. Admission never relies on this value: the
// per-bucket reserve script remains the capacity authority.
func (s *RedisSessionStore) advisoryBackendReservationCount(ctx context.Context, backendIdentifier string) (int, error) {
	if total, ok := s.local.backendReservationTotal(normalizedStateValue(backendIdentifier)); ok {
		return total, nil
	}

	return s.backendReservationActiveCount(ctx, backendIdentifier)
}

// readBackendReservationGroups pipelines per-group counts and optional due or ownership probes.
//
// The legacy group is always included so reservations admitted by earlier
// releases keep counting against capacity until they are released or expire.
// Plain count reads reuse a legacy count observed within the last second, so
// the former single hot slot is not read on every login after the rollout.
func (s *RedisSessionStore) readBackendReservationGroups(
	ctx context.Context,
	backendIdentifier string,
	reservationID string,
	withDue bool,
) ([]backendReservationGroupState, error) {
	groups, err := s.backendReservationGroups(backendIdentifier)
	if err != nil {
		return nil, err
	}

	probe := backendReservationGroupProbe{reservationID: reservationID, withDue: withDue}
	if !withDue && reservationID == "" {
		probe.legacyCount, probe.legacyCached = s.local.legacyReservationCount(backendIdentifier)
	}

	commands := make([]backendReservationGroupCommands, len(groups))
	dueMax := strconv.FormatInt(time.Now().UnixMilli(), 10)
	redisCtx := redisContext(ctx)
	started := time.Now()

	_, err = s.client.Pipelined(redisCtx, func(pipe redis.Pipeliner) error {
		for index, group := range groups {
			commands[index] = probe.queue(redisCtx, pipe, group, dueMax)
		}

		return nil
	})
	if err != nil && !errors.Is(err, redis.Nil) {
		classified := ClassifyRedisError(backendReservationScan, err)
		s.recordRedisOperation(redisCtx, backendReservationScan, started, classified)

		return nil, classified
	}

	s.recordRedisOperation(redisCtx, backendReservationScan, started, nil)

	for index := range groups {
		if err := probe.apply(&groups[index], commands[index]); err != nil {
			return nil, err
		}
	}

	if !probe.legacyCached {
		s.local.storeLegacyReservationCount(backendIdentifier, groups[len(groups)-1].Count)
	}

	return groups, nil
}

// backendReservationGroups lists every bucket group followed by the legacy group of one backend.
func (s *RedisSessionStore) backendReservationGroups(backendIdentifier string) ([]backendReservationGroupState, error) {
	buckets := s.keys.BackendReservationBucketCount()
	groups := make([]backendReservationGroupState, 0, buckets+1)

	for bucket := range buckets {
		keys, err := s.keys.BackendReservationBucketKeys(backendIdentifier, bucket)
		if err != nil {
			return nil, err
		}

		groups = append(groups, backendReservationGroupState{Bucket: bucket, Keys: keys})
	}

	legacyKeys, err := s.keys.LegacyBackendReservationKeys(backendIdentifier)
	if err != nil {
		return nil, err
	}

	return append(groups, backendReservationGroupState{Bucket: legacyBackendReservationBucket, Keys: legacyKeys}), nil
}

// backendReservationGroupProbe selects the per-group reads one caller needs.
type backendReservationGroupProbe struct {
	reservationID string
	withDue       bool
	legacyCount   int
	legacyCached  bool
}

// backendReservationGroupCommands holds the pipelined reads of one group.
type backendReservationGroupCommands struct {
	count *redis.StringCmd
	due   *redis.StringSliceCmd
	holds *redis.BoolCmd
}

// queue adds the selected reads for one group to a pipeline.
func (p backendReservationGroupProbe) queue(
	ctx context.Context,
	pipe redis.Pipeliner,
	group backendReservationGroupState,
	dueMax string,
) backendReservationGroupCommands {
	legacy := group.Bucket == legacyBackendReservationBucket
	commands := backendReservationGroupCommands{}

	if !legacy || !p.legacyCached {
		commands.count = pipe.HGet(ctx, group.Keys.State, scriptFieldActiveSessionCount)
	}

	if p.withDue {
		commands.due = pipe.ZRangeByScore(ctx, group.Keys.Due, &redis.ZRangeBy{Min: redisScoreMin, Max: dueMax, Count: 1})
	}

	if p.reservationID != "" && !legacy {
		commands.holds = pipe.HExists(ctx, group.Keys.State, "reservation:"+formatBackendReservationID(p.reservationID, group.Bucket))
	}

	return commands
}

// apply stores the pipelined results of one group, reusing a fresh cached legacy count.
func (p backendReservationGroupProbe) apply(group *backendReservationGroupState, commands backendReservationGroupCommands) error {
	group.Count = p.legacyCount

	if commands.count != nil {
		count, err := pipelinedBackendReservationCount(commands.count)
		if err != nil {
			return err
		}

		group.Count = count
	}

	if commands.due != nil {
		due, err := commands.due.Result()
		if err != nil {
			return ClassifyRedisError(backendReservationScan, err)
		}

		group.Due = len(due) > 0
	}

	if commands.holds != nil {
		holds, err := commands.holds.Result()
		if err != nil {
			return ClassifyRedisError(backendReservationScan, err)
		}

		group.Holds = holds
	}

	return nil
}

// backendReservationGroupCount reads the active count of the group that owns one reservation.
func (s *RedisSessionStore) backendReservationGroupCount(ctx context.Context, backendIdentifier string, reservationID string) (int, error) {
	keys, err := s.keys.BackendReservationGroupKeys(backendIdentifier, reservationID)
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

// ensureBackendIndexed makes stale reservation repair discoverable without rewriting the member per login.
func (s *RedisSessionStore) ensureBackendIndexed(ctx context.Context, backendIdentifier string) {
	_ = s.ensureBackendIndexedRequired(ctx, "backend_reservation_index", backendIdentifier)
}

// ensureBackendIndexedRequired adds a backend to the add-only inventory and reports failures.
//
// Members are never removed by production code, so a recent successful add
// proves membership; the periodic rewrite restores an externally removed member.
func (s *RedisSessionStore) ensureBackendIndexedRequired(ctx context.Context, operation string, backendIdentifier string) error {
	backendIdentifier = strings.TrimSpace(backendIdentifier)
	if backendIdentifier == "" || s.local.backendIndexed(backendIdentifier) {
		return nil
	}

	err := s.runRequiredRepairableIndexCommand(ctx, operation, func(redisCtx context.Context) error {
		return s.client.SAdd(redisCtx, s.keys.BackendIndexKey(), backendIdentifier).Err()
	})
	if err == nil {
		s.local.markBackendIndexed(backendIdentifier)
	}

	return err
}

// backendReservationBucketQuotas splits capacity into exact per-bucket shares.
//
// Only the first min(buckets, capacity) buckets receive a share, so every
// active bucket can admit at least one reservation and the shares always add up
// to the capacity.
func backendReservationBucketQuotas(capacity int, buckets int) []int {
	quotas := make([]int, buckets)
	if capacity <= 0 || buckets <= 0 {
		return quotas
	}

	active := min(capacity, buckets)
	for bucket := range active {
		quotas[bucket] = capacity / active
		if bucket < capacity%active {
			quotas[bucket]++
		}
	}

	return quotas
}

// activeBackendReservationBuckets counts the buckets that currently hold a capacity share.
func activeBackendReservationBuckets(quotas []int) int {
	active := 0

	for _, quota := range quotas {
		if quota > 0 {
			active++
		}
	}

	return active
}

// spillBackendReservationBuckets orders spill candidates for a new reservation.
//
// Buckets with free share come first, most free first. Full buckets that hold
// an expired, not yet repaired lease follow: the reserve script repairs its
// own bucket before the capacity check, so a crashed writer's leases cannot
// cause a false "at capacity" while their share is still counted.
func spillBackendReservationBuckets(groups []backendReservationGroupState, quotas []int, skip int) []int {
	type candidate struct {
		bucket int
		free   int
	}

	free := make([]candidate, 0, len(quotas))
	repairable := make([]int, 0, len(quotas))

	for _, group := range groups {
		if group.Bucket == legacyBackendReservationBucket || group.Bucket == skip || quotas[group.Bucket] <= 0 {
			continue
		}

		if available := quotas[group.Bucket] - group.Count; available > 0 {
			free = append(free, candidate{bucket: group.Bucket, free: available})
		} else if group.Due {
			repairable = append(repairable, group.Bucket)
		}
	}

	sort.SliceStable(free, func(left int, right int) bool {
		return free[left].free > free[right].free
	})

	buckets := make([]int, 0, len(free)+len(repairable))
	for _, item := range free {
		buckets = append(buckets, item.bucket)
	}

	return append(buckets, repairable...)
}

// sumBackendReservationGroups returns the backend-wide reservation count.
func sumBackendReservationGroups(groups []backendReservationGroupState) int {
	total := 0

	for _, group := range groups {
		total += group.Count
	}

	return total
}

// pipelinedBackendReservationCount parses one pipelined count read, treating a missing group as empty.
func pipelinedBackendReservationCount(command *redis.StringCmd) (int, error) {
	value, err := command.Result()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}

	if err != nil {
		return 0, ClassifyRedisError("backend_reservation_count", err)
	}

	return parseBackendReservationActiveCount(value)
}

// parseBackendReservationRef decodes the owning bucket from a stored reservation identifier.
//
// Identifiers without a valid bucket suffix were issued before bucketing and
// resolve to the legacy group.
func parseBackendReservationRef(reservationID string) backendReservationRef {
	marker := strings.LastIndex(reservationID, backendReservationBucketMarker)
	if marker <= 0 {
		return backendReservationRef{ID: reservationID, Bucket: legacyBackendReservationBucket}
	}

	suffix := reservationID[marker+len(backendReservationBucketMarker):]
	if len(suffix) != 2 {
		return backendReservationRef{ID: reservationID, Bucket: legacyBackendReservationBucket}
	}

	bucket, err := strconv.Atoi(suffix)
	if err != nil || bucket < 0 || bucket >= backendReservationBuckets {
		return backendReservationRef{ID: reservationID, Bucket: legacyBackendReservationBucket}
	}

	return backendReservationRef{ID: reservationID, Bucket: bucket}
}

// formatBackendReservationID binds a caller identifier to its owning bucket.
func formatBackendReservationID(reservationID string, bucket int) string {
	return reservationID + backendReservationBucketMarker + twoDigit(bucket)
}

// isBackendAtCapacity reports whether a reserve attempt failed only because its bucket share is used.
//
// Current scripts report a full share as a status; the error text of earlier
// script versions is still recognized.
func isBackendAtCapacity(err error) bool {
	var stateErr *RedisStateError
	if !errors.As(err, &stateErr) || stateErr.Kind != RedisErrorKindAmbiguousState {
		return false
	}

	return stateErr.Message == backendAtCapacityMessage || strings.Contains(strings.ToLower(errorCauseText(stateErr)), "backend_at_capacity")
}

// errorCauseText returns the wrapped cause text of a classified state error.
func errorCauseText(err *RedisStateError) string {
	if err == nil || err.cause == nil {
		return ""
	}

	return err.cause.Error()
}

// backendAtCapacityError reports that no bucket had a free capacity share.
func backendAtCapacityError() error {
	return newStateError(RedisErrorKindAmbiguousState, scriptBackendReserve, backendAtCapacityMessage, nil)
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

	record.created, err = parseOptionalIntField(parsed.Fields, "reservation_created")
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
