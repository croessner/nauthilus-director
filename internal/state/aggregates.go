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

//nolint:funlen,gocyclo,wsl_v5 // Aggregate repair keeps bounded Redis cursor and counter convergence paths together.
package state

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	aggregateAccuracyCumulative         = "cumulative"
	aggregateAccuracyEventuallyRepaired = "eventually_repaired"
	aggregateDimensionBackend           = "backend"
	aggregateDimensionListener          = "listener"
	aggregateDimensionProtocol          = "protocol"
	aggregateDimensionService           = "service"
	aggregateDimensionShardTag          = "shard_tag"
	aggregateFieldBackendReservations   = "backend_reservations"
	aggregateFieldExpiredSessions       = "expired_sessions"
	aggregateFieldStaleIndexEntries     = "stale_index_entries"
	aggregateReconcileCursorFamily      = "aggregate_sessions"
	aggregateOperation                  = "runtime_aggregates"
	aggregateUnknownDimension           = "unknown"
	aggregateStatusPreview              = "preview"
	aggregateStatusReconciled           = "reconciled"

	// RuntimeAggregateReconcileScopeAll lets operators request every implemented aggregate repair family.
	RuntimeAggregateReconcileScopeAll = "all"
	// RuntimeAggregateReconcileScopeActiveSessions limits repair to active-session markers and counters.
	RuntimeAggregateReconcileScopeActiveSessions = "active_sessions"
)

// RuntimeAggregateReconcileRequest bounds a repair pass over runtime aggregates.
type RuntimeAggregateReconcileRequest struct {
	Limit           int
	MaxPassDuration time.Duration
	DryRun          bool
	Scope           string
	Cursor          string
}

// RuntimeAggregateReconcileRecord reports one bounded aggregate repair pass.
type RuntimeAggregateReconcileRecord struct {
	Status                 string
	Scope                  string
	ScannedMarkers         int
	StaleMarkersRemoved    int
	MarkersUpserted        int
	CounterFieldsChanged   int
	CounterFieldsRemoved   int
	AuthoritativeConflicts int
	Partial                bool
	NextCursor             string
	ServerTime             time.Time
}

// RuntimeAggregateSummary describes repairable operator totals without listing sessions.
type RuntimeAggregateSummary struct {
	GeneratedAt      time.Time
	RoutingAuthority bool
	ActiveSessions   RuntimeActiveSessionSummary
	IdleAffinities   RuntimeCountSummary
	BackendCapacity  []RuntimeBackendCapacitySummary
	Repairs          RuntimeRepairSummary
}

// RuntimeActiveSessionSummary groups active-session aggregates by bounded dimensions.
type RuntimeActiveSessionSummary struct {
	Total      RuntimeCountSummary
	ByProtocol []RuntimeDimensionCount
	ByListener []RuntimeDimensionCount
	ByService  []RuntimeDimensionCount
	ByShardTag []RuntimeDimensionCount
}

// RuntimeCountSummary carries one count and its operator-facing accuracy class.
type RuntimeCountSummary struct {
	Count    int
	Accuracy string
}

// RuntimeDimensionCount carries one dimension value and its repairable count.
type RuntimeDimensionCount struct {
	Value    string
	Count    int
	Accuracy string
}

// RuntimeBackendCapacitySummary carries backend-visible active and reserved capacity totals.
type RuntimeBackendCapacitySummary struct {
	BackendIdentifier string
	ActiveSessions    RuntimeCountSummary
	ReservedSessions  RuntimeCountSummary
	SummaryRepairable bool
	RoutingAuthority  bool
}

// RuntimeRepairSummary carries cumulative repair counters for aggregate drift clues.
type RuntimeRepairSummary struct {
	ExpiredSessions     RuntimeCountSummary
	StaleIndexEntries   RuntimeCountSummary
	BackendReservations RuntimeCountSummary
}

type aggregateSessionDimensions struct {
	SessionID         string `json:"-"`
	Protocol          string `json:"protocol"`
	ListenerName      string `json:"listener"`
	ServiceName       string `json:"service"`
	ShardTag          string `json:"shard_tag"`
	BackendIdentifier string `json:"backend,omitempty"`
}

type aggregateIdleAffinity struct {
	AffinityHash string
	ExpiresAt    time.Time
}

type aggregateCounter struct {
	Dimension string
	Field     string
}

type aggregateCounterSnapshot map[string]map[string]int

type aggregateReconcileMarkerResult struct {
	staleRemoved bool
	upserted     bool
	conflict     bool
	final        aggregateSessionDimensions
	countFinal   bool
}

// RuntimeAggregateSummary returns repairable operator totals without scanning runtime sessions.
func (s *RedisSessionStore) RuntimeAggregateSummary(ctx context.Context) (RuntimeAggregateSummary, error) {
	if s == nil || s.client == nil {
		return RuntimeAggregateSummary{}, newStateError(RedisErrorKindConfig, aggregateOperation, "session store required", nil)
	}

	redisCtx := redisContext(ctx)
	if err := s.pruneExpiredIdleAffinities(redisCtx); err != nil {
		return RuntimeAggregateSummary{}, err
	}

	activeSessions, err := s.aggregateActiveSessionSummary(redisCtx)
	if err != nil {
		return RuntimeAggregateSummary{}, err
	}

	idleCount, err := s.aggregateIdleAffinityCount(redisCtx)
	if err != nil {
		return RuntimeAggregateSummary{}, err
	}

	repairs, err := s.aggregateRepairSummary(redisCtx)
	if err != nil {
		return RuntimeAggregateSummary{}, err
	}

	backendCapacity, err := s.aggregateBackendCapacity(redisCtx)
	if err != nil {
		return RuntimeAggregateSummary{}, err
	}

	return RuntimeAggregateSummary{
		GeneratedAt:      time.Now().UTC(),
		RoutingAuthority: false,
		ActiveSessions:   activeSessions,
		IdleAffinities:   repairableCount(idleCount),
		BackendCapacity:  backendCapacity,
		Repairs:          repairs,
	}, nil
}

// ReconcileRuntimeAggregates repairs bounded active-session aggregate marker drift.
func (s *RedisSessionStore) ReconcileRuntimeAggregates(
	ctx context.Context,
	request RuntimeAggregateReconcileRequest,
) (RuntimeAggregateReconcileRecord, error) {
	if s == nil || s.client == nil {
		return RuntimeAggregateReconcileRecord{}, newStateError(RedisErrorKindConfig, aggregateOperation, "session store required", nil)
	}

	if err := validateRuntimeAggregateReconcileRequest(request); err != nil {
		return RuntimeAggregateReconcileRecord{}, err
	}

	scope := normalizeRuntimeAggregateReconcileScope(request.Scope)
	cursor, err := s.decodeRuntimeReadCursor(request.Cursor, aggregateReconcileCursorFamily, 1)
	if err != nil {
		return RuntimeAggregateReconcileRecord{}, err
	}

	status := aggregateStatusReconciled
	if request.DryRun {
		status = aggregateStatusPreview
	}

	record := RuntimeAggregateReconcileRecord{
		Status:     status,
		Scope:      scope,
		ServerTime: time.Now().UTC(),
	}
	expectedCounters := newAggregateCounterSnapshot()
	deadline := time.Now().Add(request.MaxPassDuration)
	redisCtx := redisContext(ctx)
	markerKey := s.keys.AggregateSessionMarkerKey()
	remaining := request.Limit
	scanCursor := cursor.RedisCursor
	entryOffset := cursor.Offset
	completeFromStart := strings.TrimSpace(request.Cursor) == ""

	for remaining > 0 {
		if !time.Now().Before(deadline) {
			record.Partial = true
			record.NextCursor = s.encodeRuntimeReadCursor(aggregateReconcileCursorFamily, 0, scanCursor, entryOffset)

			return record, nil
		}

		started := time.Now()
		entries, next, scanErr := s.client.HScan(redisCtx, markerKey, scanCursor, "*", int64(remaining)).Result()
		if scanErr != nil {
			classified := ClassifyRedisError(aggregateOperation, scanErr)
			s.recordRedisOperation(redisCtx, "aggregate_reconcile_marker_scan", started, classified)

			return RuntimeAggregateReconcileRecord{}, classified
		}

		s.recordRedisOperation(redisCtx, "aggregate_reconcile_marker_scan", started, nil)

		pairCount := len(entries) / 2
		if entryOffset > pairCount {
			entryOffset = pairCount
		}

		nextOffset := entryOffset
		for pairIndex := entryOffset; pairIndex < pairCount && remaining > 0; pairIndex++ {
			if !time.Now().Before(deadline) {
				record.Partial = true
				record.NextCursor = s.encodeRuntimeReadCursor(aggregateReconcileCursorFamily, 0, scanCursor, pairIndex)

				return record, nil
			}

			index := pairIndex * 2
			result, reconcileErr := s.reconcileRuntimeAggregateMarker(ctx, markerKey, entries[index], entries[index+1], request.DryRun)
			if reconcileErr != nil {
				return RuntimeAggregateReconcileRecord{}, reconcileErr
			}

			record.ScannedMarkers++
			remaining--
			nextOffset = pairIndex + 1

			if result.staleRemoved {
				record.StaleMarkersRemoved++
			}

			if result.upserted {
				record.MarkersUpserted++
			}

			if result.conflict {
				record.AuthoritativeConflicts++
			}

			if result.countFinal {
				expectedCounters.Add(result.final)
			}
		}

		if remaining == 0 {
			nextCursor := s.nextRuntimeHashReadCursor(aggregateReconcileCursorFamily, 0, 1, scanCursor, next, nextOffset, pairCount)
			if nextCursor != "" {
				record.Partial = true
				record.NextCursor = nextCursor
			}

			break
		}

		if next == 0 {
			break
		}

		scanCursor = next
		entryOffset = 0
	}

	if completeFromStart && !record.Partial {
		changed, removed, reconcileErr := s.reconcileAggregateCountersFromSnapshot(ctx, expectedCounters, request.DryRun)
		if reconcileErr != nil {
			return RuntimeAggregateReconcileRecord{}, reconcileErr
		}

		record.CounterFieldsChanged = changed
		record.CounterFieldsRemoved = removed
	}

	record.ServerTime = time.Now().UTC()

	return record, nil
}

// validateRuntimeAggregateReconcileRequest rejects unbounded aggregate repair.
func validateRuntimeAggregateReconcileRequest(request RuntimeAggregateReconcileRequest) error {
	if request.Limit <= 0 {
		return newStateError(RedisErrorKindAmbiguousState, aggregateOperation, "limit must be greater than zero", nil)
	}

	if request.MaxPassDuration <= 0 {
		return newStateError(RedisErrorKindAmbiguousState, aggregateOperation, "max pass duration required", nil)
	}

	if normalizeRuntimeAggregateReconcileScope(request.Scope) == "" {
		return newStateError(RedisErrorKindAmbiguousState, aggregateOperation, "scope invalid", nil)
	}

	return nil
}

// normalizeRuntimeAggregateReconcileScope maps accepted public scope names.
func normalizeRuntimeAggregateReconcileScope(scope string) string {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "", RuntimeAggregateReconcileScopeAll:
		return RuntimeAggregateReconcileScopeAll
	case RuntimeAggregateReconcileScopeActiveSessions, "active-sessions":
		return RuntimeAggregateReconcileScopeActiveSessions
	default:
		return ""
	}
}

// reconcileRuntimeAggregateMarker repairs one marker after authoritative reads.
func (s *RedisSessionStore) reconcileRuntimeAggregateMarker(
	ctx context.Context,
	markerKey string,
	sessionID string,
	encoded string,
	dryRun bool,
) (aggregateReconcileMarkerResult, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return aggregateReconcileMarkerResult{conflict: true}, nil
	}

	marker, markerOK := decodeAggregateSessionDimensions(encoded, sessionID)
	record, visible, present, err := s.readRuntimeSessionByID(ctx, sessionID)
	if err != nil {
		return aggregateReconcileMarkerResult{conflict: true}, nil
	}

	if !present {
		if dryRun {
			return aggregateReconcileMarkerResult{staleRemoved: true}, nil
		}

		removed, removeErr := s.removeRuntimeAggregateMarker(ctx, markerKey, sessionID)
		if removeErr != nil {
			return aggregateReconcileMarkerResult{}, removeErr
		}

		if markerOK && removed {
			s.decrementAggregateCounters(ctx, marker)
		}

		return aggregateReconcileMarkerResult{staleRemoved: removed}, nil
	}

	if !visible || !markerOK {
		return aggregateReconcileMarkerResult{conflict: true}, nil
	}

	expected := aggregateSessionDimensionsFromRecord(record)
	if marker.equal(expected) {
		return aggregateReconcileMarkerResult{final: expected, countFinal: true}, nil
	}

	if dryRun {
		return aggregateReconcileMarkerResult{upserted: true, final: expected, countFinal: true}, nil
	}

	encodedExpected, encodeErr := expected.encode()
	if encodeErr != nil {
		return aggregateReconcileMarkerResult{}, encodeErr
	}

	if err := s.replaceRuntimeAggregateMarker(ctx, markerKey, sessionID, encodedExpected); err != nil {
		return aggregateReconcileMarkerResult{}, err
	}

	s.decrementAggregateCounters(ctx, marker)
	s.incrementAggregateCounters(ctx, expected)

	return aggregateReconcileMarkerResult{upserted: true, final: expected, countFinal: true}, nil
}

// removeRuntimeAggregateMarker deletes one repairable marker without touching authoritative state.
func (s *RedisSessionStore) removeRuntimeAggregateMarker(ctx context.Context, markerKey string, sessionID string) (bool, error) {
	redisCtx := redisContext(ctx)
	started := time.Now()
	removed, err := s.client.HDel(redisCtx, markerKey, sessionID).Result()
	classified := ClassifyRedisError(aggregateOperation, err)
	s.recordRedisOperation(redisCtx, "aggregate_reconcile_marker_remove", started, classified)

	return removed > 0, classified
}

// replaceRuntimeAggregateMarker stores authoritative dimensions for an existing marker.
func (s *RedisSessionStore) replaceRuntimeAggregateMarker(ctx context.Context, markerKey string, sessionID string, encoded string) error {
	redisCtx := redisContext(ctx)
	started := time.Now()
	err := s.client.HSet(redisCtx, markerKey, sessionID, encoded).Err()
	classified := ClassifyRedisError(aggregateOperation, err)
	s.recordRedisOperation(redisCtx, "aggregate_reconcile_marker_upsert", started, classified)

	return classified
}

// reconcileAggregateCountersFromSnapshot converges dimension counters after a complete marker scan.
func (s *RedisSessionStore) reconcileAggregateCountersFromSnapshot(
	ctx context.Context,
	expected aggregateCounterSnapshot,
	dryRun bool,
) (int, int, error) {
	changed := 0
	removed := 0

	for _, dimension := range aggregateSessionCounterDimensions() {
		dimensionChanged, dimensionRemoved, err := s.reconcileAggregateDimensionCounter(ctx, dimension, expected[dimension], dryRun)
		if err != nil {
			return changed, removed, err
		}

		changed += dimensionChanged
		removed += dimensionRemoved
	}

	return changed, removed, nil
}

// reconcileAggregateDimensionCounter updates one bounded aggregate dimension hash.
func (s *RedisSessionStore) reconcileAggregateDimensionCounter(
	ctx context.Context,
	dimension string,
	expected map[string]int,
	dryRun bool,
) (int, int, error) {
	key := s.keys.AggregateActiveDimensionKey(dimension)
	values, err := s.aggregateHash(redisContext(ctx), key, "aggregate_reconcile_counter_read")
	if err != nil {
		return 0, 0, err
	}

	fields := make(map[string]struct{}, len(values)+len(expected))
	for field := range values {
		fields[field] = struct{}{}
	}

	for field := range expected {
		fields[field] = struct{}{}
	}

	ordered := make([]string, 0, len(fields))
	for field := range fields {
		if strings.TrimSpace(field) != "" {
			ordered = append(ordered, field)
		}
	}

	sort.Strings(ordered)

	changed := 0
	removed := 0
	for _, field := range ordered {
		want := expected[field]
		have := parseAggregateCount(values[field])
		if want <= 0 {
			if _, ok := values[field]; !ok {
				continue
			}

			removed++
			if !dryRun {
				if err := s.writeRuntimeAggregateCounter(ctx, key, field, 0); err != nil {
					return changed, removed, err
				}
			}

			continue
		}

		if have == want {
			continue
		}

		changed++
		if !dryRun {
			if err := s.writeRuntimeAggregateCounter(ctx, key, field, want); err != nil {
				return changed, removed, err
			}
		}
	}

	return changed, removed, nil
}

// writeRuntimeAggregateCounter sets or removes one repairable counter field.
func (s *RedisSessionStore) writeRuntimeAggregateCounter(ctx context.Context, key string, field string, count int) error {
	redisCtx := redisContext(ctx)
	started := time.Now()
	var err error
	if count <= 0 {
		err = s.client.HDel(redisCtx, key, field).Err()
	} else {
		err = s.client.HSet(redisCtx, key, field, count).Err()
	}

	classified := ClassifyRedisError(aggregateOperation, err)
	s.recordRedisOperation(redisCtx, "aggregate_reconcile_counter_write", started, classified)

	return classified
}

// newAggregateCounterSnapshot creates empty counter buckets for every active dimension.
func newAggregateCounterSnapshot() aggregateCounterSnapshot {
	snapshot := make(aggregateCounterSnapshot)
	for _, dimension := range aggregateSessionCounterDimensions() {
		snapshot[dimension] = make(map[string]int)
	}

	return snapshot
}

// Add records the final aggregate dimensions for one visible session marker.
func (s aggregateCounterSnapshot) Add(dimensions aggregateSessionDimensions) {
	for _, counter := range dimensions.counters() {
		if counter.Dimension == "" || counter.Field == "" {
			continue
		}

		if s[counter.Dimension] == nil {
			s[counter.Dimension] = make(map[string]int)
		}

		s[counter.Dimension][counter.Field]++
	}
}

// aggregateSessionCounterDimensions returns the bounded active-session dimensions.
func aggregateSessionCounterDimensions() []string {
	return []string{
		aggregateDimensionProtocol,
		aggregateDimensionListener,
		aggregateDimensionService,
		aggregateDimensionShardTag,
		aggregateDimensionBackend,
	}
}

// aggregateActiveSessionSummary reads active-session aggregates by bounded dimensions.
func (s *RedisSessionStore) aggregateActiveSessionSummary(ctx context.Context) (RuntimeActiveSessionSummary, error) {
	total, err := s.aggregateSessionTotal(ctx)
	if err != nil {
		return RuntimeActiveSessionSummary{}, err
	}

	protocols, err := s.aggregateDimensionCounts(ctx, aggregateDimensionProtocol)
	if err != nil {
		return RuntimeActiveSessionSummary{}, err
	}

	listeners, err := s.aggregateDimensionCounts(ctx, aggregateDimensionListener)
	if err != nil {
		return RuntimeActiveSessionSummary{}, err
	}

	services, err := s.aggregateDimensionCounts(ctx, aggregateDimensionService)
	if err != nil {
		return RuntimeActiveSessionSummary{}, err
	}

	shards, err := s.aggregateDimensionCounts(ctx, aggregateDimensionShardTag)
	if err != nil {
		return RuntimeActiveSessionSummary{}, err
	}

	return RuntimeActiveSessionSummary{
		Total:      repairableCount(total),
		ByProtocol: protocols,
		ByListener: listeners,
		ByService:  services,
		ByShardTag: shards,
	}, nil
}

// upsertSessionAggregate records an active session in repairable aggregate counters.
func (s *RedisSessionStore) upsertSessionAggregate(ctx context.Context, dimensions aggregateSessionDimensions) {
	dimensions = dimensions.normalize()
	if !dimensions.valid() {
		return
	}

	redisCtx := redisContext(ctx)
	started := time.Now()
	markerKey := s.keys.AggregateSessionMarkerKey()

	encoded, err := dimensions.encode()
	if err != nil {
		s.recordRedisOperation(redisCtx, "aggregate_session_encode", started, err)

		return
	}

	created, err := s.client.HSetNX(redisCtx, markerKey, dimensions.SessionID, encoded).Result()
	if err != nil {
		s.recordRedisOperation(redisCtx, "aggregate_session_upsert", started, ClassifyRedisError(aggregateOperation, err))

		return
	}

	if created {
		s.recordRedisOperation(redisCtx, "aggregate_session_upsert", started, nil)
		s.incrementAggregateCounters(ctx, dimensions)

		return
	}

	previousValue, err := s.client.HGet(redisCtx, markerKey, dimensions.SessionID).Result()
	if errors.Is(err, redis.Nil) {
		s.recordRedisOperation(redisCtx, "aggregate_session_read", started, nil)
		s.upsertSessionAggregate(ctx, dimensions)

		return
	}

	if err != nil {
		s.recordRedisOperation(redisCtx, "aggregate_session_read", started, ClassifyRedisError(aggregateOperation, err))

		return
	}

	previous, ok := decodeAggregateSessionDimensions(previousValue, dimensions.SessionID)
	if ok && previous.equal(dimensions) {
		s.recordRedisOperation(redisCtx, "aggregate_session_upsert", started, nil)

		return
	}

	s.replaceSessionAggregate(ctx, markerKey, encoded, previous, ok, dimensions, started)
}

// replaceSessionAggregate swaps one marker and adjusts old and new dimensions.
func (s *RedisSessionStore) replaceSessionAggregate(
	ctx context.Context,
	markerKey string,
	encoded string,
	previous aggregateSessionDimensions,
	hasPrevious bool,
	dimensions aggregateSessionDimensions,
	started time.Time,
) {
	redisCtx := redisContext(ctx)
	if err := s.client.HSet(redisCtx, markerKey, dimensions.SessionID, encoded).Err(); err != nil {
		s.recordRedisOperation(redisCtx, "aggregate_session_upsert", started, ClassifyRedisError(aggregateOperation, err))

		return
	}

	s.recordRedisOperation(redisCtx, "aggregate_session_upsert", started, nil)

	if hasPrevious {
		s.decrementAggregateCounters(ctx, previous)
	}

	s.incrementAggregateCounters(ctx, dimensions)
}

// removeSessionAggregate removes one active-session marker and decrements counters once.
func (s *RedisSessionStore) removeSessionAggregate(ctx context.Context, sessionID string) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return
	}

	redisCtx := redisContext(ctx)
	started := time.Now()
	markerKey := s.keys.AggregateSessionMarkerKey()

	previousValue, err := s.client.HGet(redisCtx, markerKey, sessionID).Result()
	if errors.Is(err, redis.Nil) {
		s.recordRedisOperation(redisCtx, "aggregate_session_remove", started, nil)

		return
	}

	if err != nil {
		s.recordRedisOperation(redisCtx, "aggregate_session_remove", started, ClassifyRedisError(aggregateOperation, err))

		return
	}

	removed, err := s.client.HDel(redisCtx, markerKey, sessionID).Result()
	if err != nil {
		s.recordRedisOperation(redisCtx, "aggregate_session_remove", started, ClassifyRedisError(aggregateOperation, err))

		return
	}

	s.recordRedisOperation(redisCtx, "aggregate_session_remove", started, nil)

	if removed == 0 {
		return
	}

	previous, ok := decodeAggregateSessionDimensions(previousValue, sessionID)
	if ok {
		s.decrementAggregateCounters(ctx, previous)
	}
}

// upsertSessionAggregateFromSession repairs aggregate state from an existing session hash.
func (s *RedisSessionStore) upsertSessionAggregateFromSession(ctx context.Context, sessionID string, sessionKey string) {
	record, visible, present, err := s.readRuntimeSession(ctx, sessionID, sessionKey)
	if err != nil {
		s.recordRedisOperation(redisContext(ctx), "aggregate_session_read", time.Now(), err)

		return
	}

	if !present || !visible {
		return
	}

	s.upsertSessionAggregate(ctx, aggregateSessionDimensionsFromRecord(record))
}

// updateIdleAffinityAggregate records whether an affinity is currently idle.
func (s *RedisSessionStore) updateIdleAffinityAggregate(ctx context.Context, result affinityMutationResult) {
	if result.Delta.AffinityHash == "" {
		return
	}

	if result.Record.Status == "idle" {
		s.addIdleAffinityAggregate(ctx, aggregateIdleAffinity{
			AffinityHash: result.Delta.AffinityHash,
			ExpiresAt:    result.Delta.IdleExpiresAt,
		})

		return
	}

	s.removeIdleAffinityAggregate(ctx, result.Delta.AffinityHash)
}

// addIdleAffinityAggregate adds or refreshes one idle affinity marker.
func (s *RedisSessionStore) addIdleAffinityAggregate(ctx context.Context, idle aggregateIdleAffinity) {
	idle.AffinityHash = strings.TrimSpace(idle.AffinityHash)
	if idle.AffinityHash == "" || idle.ExpiresAt.IsZero() {
		return
	}

	s.runRepairableIndexCommand(ctx, "aggregate_idle_affinity_add", func(redisCtx context.Context) error {
		return s.client.ZAdd(redisCtx, s.keys.AggregateIdleAffinityKey(), redisZ(idle.ExpiresAt, idle.AffinityHash)).Err()
	})
}

// removeIdleAffinityAggregate removes one affinity from the idle aggregate set.
func (s *RedisSessionStore) removeIdleAffinityAggregate(ctx context.Context, affinityHash string) {
	affinityHash = strings.TrimSpace(affinityHash)
	if affinityHash == "" {
		return
	}

	s.runRepairableIndexCommand(ctx, "aggregate_idle_affinity_remove", func(redisCtx context.Context) error {
		return s.client.ZRem(redisCtx, s.keys.AggregateIdleAffinityKey(), affinityHash).Err()
	})
}

// incrementAggregateRepairCount records cumulative repair work without raw identifiers.
func (s *RedisSessionStore) incrementAggregateRepairCount(ctx context.Context, field string, count int) {
	field = strings.TrimSpace(field)
	if field == "" || count <= 0 {
		return
	}

	s.runRepairableIndexCommand(ctx, "aggregate_repair_count", func(redisCtx context.Context) error {
		return s.client.HIncrBy(redisCtx, s.keys.AggregateRepairKey(), field, int64(count)).Err()
	})
}

// setBackendReservedAggregate publishes the current backend reservation count for summaries.
func (s *RedisSessionStore) setBackendReservedAggregate(ctx context.Context, backendIdentifier string, count int) {
	backendIdentifier = strings.TrimSpace(backendIdentifier)
	if backendIdentifier == "" {
		return
	}

	s.setAggregateCounter(ctx, s.keys.AggregateActiveDimensionKey("reserved_backend"), backendIdentifier, int64(count))
}

// incrementAggregateCounters applies one active-session aggregate increment.
func (s *RedisSessionStore) incrementAggregateCounters(ctx context.Context, dimensions aggregateSessionDimensions) {
	for _, counter := range dimensions.counters() {
		s.adjustAggregateCounter(ctx, counter, 1)
	}
}

// decrementAggregateCounters applies one active-session aggregate decrement without underflow.
func (s *RedisSessionStore) decrementAggregateCounters(ctx context.Context, dimensions aggregateSessionDimensions) {
	for _, counter := range dimensions.counters() {
		s.adjustAggregateCounter(ctx, counter, -1)
	}
}

// adjustAggregateCounter changes one aggregate counter and removes zero or negative fields.
func (s *RedisSessionStore) adjustAggregateCounter(ctx context.Context, counter aggregateCounter, delta int64) {
	if counter.Dimension == "" || counter.Field == "" || delta == 0 {
		return
	}

	key := s.keys.AggregateActiveDimensionKey(counter.Dimension)
	redisCtx := redisContext(ctx)
	started := time.Now()

	value, err := s.client.HIncrBy(redisCtx, key, counter.Field, delta).Result()
	if err != nil {
		s.recordRedisOperation(redisCtx, "aggregate_counter_adjust", started, ClassifyRedisError(aggregateOperation, err))

		return
	}

	if value <= 0 {
		err = s.client.HDel(redisCtx, key, counter.Field).Err()
	}

	s.recordRedisOperation(redisCtx, "aggregate_counter_adjust", started, ClassifyRedisError(aggregateOperation, err))
}

// setAggregateCounter stores an aggregate counter snapshot and removes non-positive fields.
func (s *RedisSessionStore) setAggregateCounter(ctx context.Context, key string, field string, count int64) {
	field = strings.TrimSpace(field)
	if field == "" {
		return
	}

	s.runRepairableIndexCommand(ctx, "aggregate_counter_set", func(redisCtx context.Context) error {
		if count <= 0 {
			return s.client.HDel(redisCtx, key, field).Err()
		}

		return s.client.HSet(redisCtx, key, field, count).Err()
	})
}

// pruneExpiredIdleAffinities removes idle markers whose grace windows expired.
func (s *RedisSessionStore) pruneExpiredIdleAffinities(ctx context.Context) error {
	started := time.Now()
	err := s.client.ZRemRangeByScore(ctx, s.keys.AggregateIdleAffinityKey(), "-inf", strconv.FormatInt(time.Now().UnixMilli(), 10)).Err()
	classified := ClassifyRedisError(aggregateOperation, err)
	s.recordRedisOperation(ctx, "aggregate_idle_affinity_prune", started, classified)

	return classified
}

// aggregateSessionTotal reads the active aggregate marker count without listing sessions.
func (s *RedisSessionStore) aggregateSessionTotal(ctx context.Context) (int, error) {
	return s.aggregateCardinality(ctx, "aggregate_session_total", func(redisCtx context.Context) (int64, error) {
		return s.client.HLen(redisCtx, s.keys.AggregateSessionMarkerKey()).Result()
	})
}

// aggregateIdleAffinityCount reads the current idle-affinity aggregate count.
func (s *RedisSessionStore) aggregateIdleAffinityCount(ctx context.Context) (int, error) {
	return s.aggregateCardinality(ctx, "aggregate_idle_affinity_count", func(redisCtx context.Context) (int64, error) {
		return s.client.ZCard(redisCtx, s.keys.AggregateIdleAffinityKey()).Result()
	})
}

// aggregateCardinality reads one aggregate cardinality without returning members.
func (s *RedisSessionStore) aggregateCardinality(
	ctx context.Context,
	operation string,
	command func(context.Context) (int64, error),
) (int, error) {
	started := time.Now()

	value, err := command(ctx)
	if err != nil {
		classified := ClassifyRedisError(aggregateOperation, err)
		s.recordRedisOperation(ctx, operation, started, classified)

		return 0, classified
	}

	s.recordRedisOperation(ctx, operation, started, nil)

	return int(value), nil
}

// aggregateDimensionCounts reads one bounded aggregate dimension hash.
func (s *RedisSessionStore) aggregateDimensionCounts(ctx context.Context, dimension string) ([]RuntimeDimensionCount, error) {
	values, err := s.aggregateHash(ctx, s.keys.AggregateActiveDimensionKey(dimension), "aggregate_dimension_read")
	if err != nil {
		return nil, err
	}

	counts := make([]RuntimeDimensionCount, 0, len(values))
	for value, raw := range values {
		count := parseAggregateCount(raw)
		if count <= 0 {
			continue
		}

		counts = append(counts, RuntimeDimensionCount{
			Value:    value,
			Count:    count,
			Accuracy: aggregateAccuracyEventuallyRepaired,
		})
	}

	sort.Slice(counts, func(left int, right int) bool {
		return counts[left].Value < counts[right].Value
	})

	return counts, nil
}

// aggregateRepairSummary reads cumulative repair counters.
func (s *RedisSessionStore) aggregateRepairSummary(ctx context.Context) (RuntimeRepairSummary, error) {
	values, err := s.aggregateHash(ctx, s.keys.AggregateRepairKey(), "aggregate_repairs_read")
	if err != nil {
		return RuntimeRepairSummary{}, err
	}

	return RuntimeRepairSummary{
		ExpiredSessions:     cumulativeCount(parseAggregateCount(values[aggregateFieldExpiredSessions])),
		StaleIndexEntries:   cumulativeCount(parseAggregateCount(values[aggregateFieldStaleIndexEntries])),
		BackendReservations: cumulativeCount(parseAggregateCount(values[aggregateFieldBackendReservations])),
	}, nil
}

// aggregateBackendCapacity merges active-session and reservation aggregate hashes.
func (s *RedisSessionStore) aggregateBackendCapacity(ctx context.Context) ([]RuntimeBackendCapacitySummary, error) {
	active, err := s.aggregateHash(ctx, s.keys.AggregateActiveDimensionKey(aggregateDimensionBackend), "aggregate_backend_active_read")
	if err != nil {
		return nil, err
	}

	reserved, err := s.aggregateHash(ctx, s.keys.AggregateActiveDimensionKey("reserved_backend"), "aggregate_backend_reserved_read")
	if err != nil {
		return nil, err
	}

	backendIDs := make(map[string]struct{}, len(active)+len(reserved))
	for backendID := range active {
		backendIDs[backendID] = struct{}{}
	}

	for backendID := range reserved {
		backendIDs[backendID] = struct{}{}
	}

	summaries := make([]RuntimeBackendCapacitySummary, 0, len(backendIDs))
	for backendID := range backendIDs {
		activeCount := parseAggregateCount(active[backendID])

		reservedCount := parseAggregateCount(reserved[backendID])
		if activeCount <= 0 && reservedCount <= 0 {
			continue
		}

		summaries = append(summaries, RuntimeBackendCapacitySummary{
			BackendIdentifier: backendID,
			ActiveSessions:    repairableCount(activeCount),
			ReservedSessions:  repairableCount(reservedCount),
			SummaryRepairable: true,
			RoutingAuthority:  false,
		})
	}

	sort.Slice(summaries, func(left int, right int) bool {
		return summaries[left].BackendIdentifier < summaries[right].BackendIdentifier
	})

	return summaries, nil
}

// aggregateHash reads one aggregate hash whose cardinality is bounded by dimensions.
func (s *RedisSessionStore) aggregateHash(ctx context.Context, key string, operation string) (map[string]string, error) {
	started := time.Now()

	values, err := s.client.HGetAll(ctx, key).Result()
	if err != nil {
		classified := ClassifyRedisError(aggregateOperation, err)
		s.recordRedisOperation(ctx, operation, started, classified)

		return nil, classified
	}

	s.recordRedisOperation(ctx, operation, started, nil)

	return values, nil
}

// aggregateSessionDimensionsFromDelta converts an affinity script delta into aggregate dimensions.
func aggregateSessionDimensionsFromDelta(delta sessionMutationDelta) (aggregateSessionDimensions, bool) {
	if normalizedHolderKind(delta.HolderKind) != HolderKindSession {
		return aggregateSessionDimensions{}, false
	}

	return aggregateSessionDimensions{
		SessionID:         delta.SessionID,
		Protocol:          delta.Protocol,
		ListenerName:      delta.ListenerName,
		ServiceName:       delta.ServiceName,
		ShardTag:          delta.ShardTag,
		BackendIdentifier: delta.BackendIdentifier,
	}.normalize(), true
}

// aggregateSessionDimensionsFromRecord converts a visible runtime session into aggregate dimensions.
func aggregateSessionDimensionsFromRecord(record RuntimeSessionRecord) aggregateSessionDimensions {
	return aggregateSessionDimensions{
		SessionID:         record.SessionID,
		Protocol:          record.Protocol,
		ListenerName:      record.ListenerName,
		ServiceName:       record.ServiceName,
		ShardTag:          record.ShardTag,
		BackendIdentifier: record.BackendIdentifier,
	}.normalize()
}

// normalize prepares dimensions for stable storage and reporting.
func (d aggregateSessionDimensions) normalize() aggregateSessionDimensions {
	d.SessionID = strings.TrimSpace(d.SessionID)
	d.Protocol = aggregateDimensionValue(d.Protocol)
	d.ListenerName = aggregateDimensionValue(d.ListenerName)
	d.ServiceName = aggregateDimensionValue(d.ServiceName)
	d.ShardTag = aggregateDimensionValue(d.ShardTag)
	d.BackendIdentifier = strings.TrimSpace(d.BackendIdentifier)

	return d
}

// valid reports whether required aggregate dimensions are present.
func (d aggregateSessionDimensions) valid() bool {
	return d.SessionID != "" &&
		d.Protocol != "" &&
		d.ListenerName != "" &&
		d.ServiceName != "" &&
		d.ShardTag != ""
}

// equal reports whether two aggregate dimension snapshots match.
func (d aggregateSessionDimensions) equal(other aggregateSessionDimensions) bool {
	return d.normalize() == other.normalize()
}

// counters returns the repairable aggregate counters touched by one session.
func (d aggregateSessionDimensions) counters() []aggregateCounter {
	d = d.normalize()
	counters := []aggregateCounter{
		{Dimension: aggregateDimensionProtocol, Field: d.Protocol},
		{Dimension: aggregateDimensionListener, Field: d.ListenerName},
		{Dimension: aggregateDimensionService, Field: d.ServiceName},
		{Dimension: aggregateDimensionShardTag, Field: d.ShardTag},
	}

	if d.BackendIdentifier != "" {
		counters = append(counters, aggregateCounter{Dimension: aggregateDimensionBackend, Field: d.BackendIdentifier})
	}

	return counters
}

// encode serializes aggregate dimensions without secret-bearing user material.
func (d aggregateSessionDimensions) encode() (string, error) {
	payload, err := json.Marshal(d.normalize())
	if err != nil {
		return "", err
	}

	return string(payload), nil
}

// decodeAggregateSessionDimensions parses a stored session aggregate marker.
func decodeAggregateSessionDimensions(value string, sessionID string) (aggregateSessionDimensions, bool) {
	var dimensions aggregateSessionDimensions
	if err := json.Unmarshal([]byte(value), &dimensions); err != nil {
		return aggregateSessionDimensions{}, false
	}

	dimensions.SessionID = strings.TrimSpace(sessionID)
	dimensions = dimensions.normalize()

	return dimensions, dimensions.valid()
}

// aggregateDimensionValue normalizes empty bounded dimensions into one bucket.
func aggregateDimensionValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return aggregateUnknownDimension
	}

	return value
}

// repairableCount creates an eventually repaired count value.
func repairableCount(count int) RuntimeCountSummary {
	if count < 0 {
		count = 0
	}

	return RuntimeCountSummary{Count: count, Accuracy: aggregateAccuracyEventuallyRepaired}
}

// cumulativeCount creates a cumulative repair count value.
func cumulativeCount(count int) RuntimeCountSummary {
	if count < 0 {
		count = 0
	}

	return RuntimeCountSummary{Count: count, Accuracy: aggregateAccuracyCumulative}
}

// parseAggregateCount converts a Redis aggregate field to a non-negative count.
func parseAggregateCount(value string) int {
	count, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || count < 0 {
		return 0
	}

	return count
}
