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
	scriptAggregateSessionUpsert        = "aggregate_session_upsert"
	scriptAggregateSessionRemove        = "aggregate_session_remove"

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

// aggregateGroupTotals carries the pipelined reads of one aggregate group.
type aggregateGroupTotals struct {
	markers    *redis.IntCmd
	idle       *redis.IntCmd
	dimensions map[string]*redis.MapStringStringCmd
}

type aggregateReconcileMarkerResult struct {
	staleRemoved bool
	upserted     bool
	conflict     bool
	final        aggregateSessionDimensions
	countFinal   bool
}

// RuntimeAggregateSummary returns repairable operator totals without scanning runtime sessions.
//
// Totals are summed over every bucketed group plus the legacy untagged group,
// so sessions opened by earlier releases stay visible during a rolling upgrade.
// Reserved capacity is read from the reservation groups themselves.
func (s *RedisSessionStore) RuntimeAggregateSummary(ctx context.Context) (RuntimeAggregateSummary, error) {
	if s == nil || s.client == nil {
		return RuntimeAggregateSummary{}, newStateError(RedisErrorKindConfig, aggregateOperation, "session store required", nil)
	}

	redisCtx := redisContext(ctx)

	totals, err := s.readAggregateGroupTotals(redisCtx)
	if err != nil {
		return RuntimeAggregateSummary{}, err
	}

	repairs, err := s.aggregateRepairSummary(redisCtx)
	if err != nil {
		return RuntimeAggregateSummary{}, err
	}

	backendCapacity, err := s.aggregateBackendCapacity(redisCtx, totals.dimensions[aggregateDimensionBackend])
	if err != nil {
		return RuntimeAggregateSummary{}, err
	}

	return RuntimeAggregateSummary{
		GeneratedAt:      time.Now().UTC(),
		RoutingAuthority: false,
		ActiveSessions: RuntimeActiveSessionSummary{
			Total:      repairableCount(totals.markers),
			ByProtocol: aggregateDimensionCountList(totals.dimensions[aggregateDimensionProtocol]),
			ByListener: aggregateDimensionCountList(totals.dimensions[aggregateDimensionListener]),
			ByService:  aggregateDimensionCountList(totals.dimensions[aggregateDimensionService]),
			ByShardTag: aggregateDimensionCountList(totals.dimensions[aggregateDimensionShardTag]),
		},
		IdleAffinities:  repairableCount(totals.idle),
		BackendCapacity: backendCapacity,
		Repairs:         repairs,
	}, nil
}

// aggregateSummedTotals carries aggregate totals summed across all groups.
type aggregateSummedTotals struct {
	markers    int
	idle       int
	dimensions map[string]map[string]int
}

// aggregateReadGroups returns every bucketed group followed by the legacy group.
func (s *RedisSessionStore) aggregateReadGroups() []AggregateKeys {
	return append(s.keys.AggregateKeyGroups(), s.keys.LegacyAggregateKeys())
}

// readAggregateGroupTotals prunes expired idle markers and sums every group in one pipeline.
func (s *RedisSessionStore) readAggregateGroupTotals(ctx context.Context) (aggregateSummedTotals, error) {
	groups := s.aggregateReadGroups()
	reads := make([]aggregateGroupTotals, len(groups))
	dimensions := aggregateSessionCounterDimensions()
	now := strconv.FormatInt(time.Now().UnixMilli(), 10)
	started := time.Now()

	_, err := s.client.Pipelined(ctx, func(pipe redis.Pipeliner) error {
		for index, group := range groups {
			pipe.ZRemRangeByScore(ctx, group.IdleAffinities, redisScoreMin, now)
			reads[index] = aggregateGroupTotals{
				markers:    pipe.HLen(ctx, group.Sessions),
				idle:       pipe.ZCard(ctx, group.IdleAffinities),
				dimensions: make(map[string]*redis.MapStringStringCmd, len(dimensions)),
			}

			for _, dimension := range dimensions {
				reads[index].dimensions[dimension] = pipe.HGetAll(ctx, group.Dimension(dimension))
			}
		}

		return nil
	})
	if err != nil {
		classified := ClassifyRedisError(aggregateOperation, err)
		s.recordRedisOperation(ctx, "aggregate_summary_read", started, classified)

		return aggregateSummedTotals{}, classified
	}

	s.recordRedisOperation(ctx, "aggregate_summary_read", started, nil)

	totals := aggregateSummedTotals{dimensions: make(map[string]map[string]int, len(dimensions))}
	for _, dimension := range dimensions {
		totals.dimensions[dimension] = make(map[string]int)
	}

	for _, read := range reads {
		totals.markers += int(read.markers.Val())
		totals.idle += int(read.idle.Val())

		for dimension, command := range read.dimensions {
			for field, raw := range command.Val() {
				if count := parseAggregateCount(raw); count > 0 {
					totals.dimensions[dimension][field] += count
				}
			}
		}
	}

	return totals, nil
}

// ReconcileRuntimeAggregates repairs bounded active-session aggregate marker drift.
//
// The pass walks every bucketed group and then the legacy group. The opaque
// cursor names the group and its hash cursor. Counters converge per group only
// after a complete pass that started without a cursor.
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

	groups := s.aggregateReadGroups()
	scope := normalizeRuntimeAggregateReconcileScope(request.Scope)

	cursor, err := s.decodeRuntimeReadCursor(request.Cursor, aggregateReconcileCursorFamily, len(groups))
	if err != nil {
		return RuntimeAggregateReconcileRecord{}, err
	}

	status := aggregateStatusReconciled
	if request.DryRun {
		status = aggregateStatusPreview
	}

	pass := aggregateReconcilePass{
		store:    s,
		request:  request,
		groups:   groups,
		deadline: time.Now().Add(request.MaxPassDuration),
		expected: make([]aggregateCounterSnapshot, len(groups)),
		record: RuntimeAggregateReconcileRecord{
			Status:     status,
			Scope:      scope,
			ServerTime: time.Now().UTC(),
		},
		remaining: request.Limit,
	}

	for index := range groups {
		pass.expected[index] = newAggregateCounterSnapshot()
	}

	if err := pass.run(ctx, cursor); err != nil {
		return RuntimeAggregateReconcileRecord{}, err
	}

	if strings.TrimSpace(request.Cursor) == "" && !pass.record.Partial {
		for index, group := range groups {
			changed, removed, reconcileErr := s.reconcileAggregateCountersFromSnapshot(ctx, group, pass.expected[index], request.DryRun)
			if reconcileErr != nil {
				return RuntimeAggregateReconcileRecord{}, reconcileErr
			}

			pass.record.CounterFieldsChanged += changed
			pass.record.CounterFieldsRemoved += removed
		}
	}

	pass.record.ServerTime = time.Now().UTC()

	return pass.record, nil
}

// aggregateReconcilePass walks aggregate groups within one bounded repair request.
type aggregateReconcilePass struct {
	store     *RedisSessionStore
	request   RuntimeAggregateReconcileRequest
	groups    []AggregateKeys
	deadline  time.Time
	expected  []aggregateCounterSnapshot
	record    RuntimeAggregateReconcileRecord
	remaining int
}

// run scans marker hashes from the decoded cursor until the limit, deadline or last group.
func (p *aggregateReconcilePass) run(ctx context.Context, cursor runtimeReadCursor) error {
	redisCtx := redisContext(ctx)
	groupIndex := cursor.Shard
	scanCursor := cursor.RedisCursor
	entryOffset := cursor.Offset

	for groupIndex < len(p.groups) && p.remaining > 0 {
		group := p.groups[groupIndex]

		if !time.Now().Before(p.deadline) {
			p.suspend(groupIndex, scanCursor, entryOffset)

			return nil
		}

		started := time.Now()

		entries, next, scanErr := p.store.client.HScan(redisCtx, group.Sessions, scanCursor, "*", int64(p.remaining)).Result()
		if scanErr != nil {
			classified := ClassifyRedisError(aggregateOperation, scanErr)
			p.store.recordRedisOperation(redisCtx, "aggregate_reconcile_marker_scan", started, classified)

			return classified
		}

		p.store.recordRedisOperation(redisCtx, "aggregate_reconcile_marker_scan", started, nil)

		pairCount := len(entries) / 2
		entryOffset = min(entryOffset, pairCount)
		nextOffset := entryOffset

		for pairIndex := entryOffset; pairIndex < pairCount && p.remaining > 0; pairIndex++ {
			if !time.Now().Before(p.deadline) {
				p.suspend(groupIndex, scanCursor, pairIndex)

				return nil
			}

			index := pairIndex * 2

			result, err := p.store.reconcileRuntimeAggregateMarker(ctx, group, entries[index], entries[index+1], p.request.DryRun)
			if err != nil {
				return err
			}

			p.observe(groupIndex, result)
			nextOffset = pairIndex + 1
		}

		if p.remaining == 0 {
			nextCursor := p.store.nextRuntimeHashReadCursor(aggregateReconcileCursorFamily, groupIndex, len(p.groups), scanCursor, next, nextOffset, pairCount)
			if nextCursor != "" {
				p.record.Partial = true
				p.record.NextCursor = nextCursor
			}

			return nil
		}

		if next != 0 {
			scanCursor = next
			entryOffset = 0

			continue
		}

		groupIndex++
		scanCursor = 0
		entryOffset = 0
	}

	return nil
}

// suspend records a resumable partial pass at the given group position.
func (p *aggregateReconcilePass) suspend(groupIndex int, scanCursor uint64, entryOffset int) {
	p.record.Partial = true
	p.record.NextCursor = p.store.encodeRuntimeReadCursor(aggregateReconcileCursorFamily, groupIndex, scanCursor, entryOffset)
}

// observe folds one marker result into the pass record and expected counters.
func (p *aggregateReconcilePass) observe(groupIndex int, result aggregateReconcileMarkerResult) {
	p.record.ScannedMarkers++
	p.remaining--

	if result.staleRemoved {
		p.record.StaleMarkersRemoved++
	}

	if result.upserted {
		p.record.MarkersUpserted++
	}

	if result.conflict {
		p.record.AuthoritativeConflicts++
	}

	if result.countFinal {
		p.expected[groupIndex].Add(result.final)
	}
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

// reconcileRuntimeAggregateMarker repairs one marker of a group after authoritative reads.
func (s *RedisSessionStore) reconcileRuntimeAggregateMarker(
	ctx context.Context,
	group AggregateKeys,
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

		removed, removeErr := s.removeAggregateMarker(ctx, group, sessionID)
		if removeErr != nil {
			return aggregateReconcileMarkerResult{}, removeErr
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

	if err := s.upsertAggregateMarker(ctx, group, expected); err != nil {
		return aggregateReconcileMarkerResult{}, err
	}

	return aggregateReconcileMarkerResult{upserted: true, final: expected, countFinal: true}, nil
}

// reconcileAggregateCountersFromSnapshot converges one group's dimension counters after a complete marker scan.
func (s *RedisSessionStore) reconcileAggregateCountersFromSnapshot(
	ctx context.Context,
	group AggregateKeys,
	expected aggregateCounterSnapshot,
	dryRun bool,
) (int, int, error) {
	changed := 0
	removed := 0

	for _, dimension := range aggregateSessionCounterDimensions() {
		dimensionChanged, dimensionRemoved, err := s.reconcileAggregateDimensionCounter(ctx, group.Dimension(dimension), expected[dimension], dryRun)
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
	key string,
	expected map[string]int,
	dryRun bool,
) (int, int, error) {
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

// upsertSessionAggregate records an active session in its bucketed aggregate group.
func (s *RedisSessionStore) upsertSessionAggregate(ctx context.Context, dimensions aggregateSessionDimensions) {
	dimensions = dimensions.normalize()
	if !dimensions.valid() {
		return
	}

	group, err := s.keys.AggregateSessionKeys(dimensions.SessionID)
	if err != nil {
		s.recordRedisOperation(redisContext(ctx), "aggregate_session_upsert", time.Now(), err)

		return
	}

	if err := s.upsertAggregateMarker(ctx, group, dimensions); err != nil {
		s.recordRedisOperation(redisContext(ctx), "aggregate_session_upsert", time.Now(), err)
	}
}

// upsertAggregateMarker stores one marker and adjusts only the counters whose dimension changed.
func (s *RedisSessionStore) upsertAggregateMarker(ctx context.Context, group AggregateKeys, dimensions aggregateSessionDimensions) error {
	dimensions = dimensions.normalize()

	encoded, err := dimensions.encode()
	if err != nil {
		return newStateError(RedisErrorKindAmbiguousState, aggregateOperation, "aggregate marker encode failed", err)
	}

	if group.Legacy() {
		return s.replaceLegacyAggregateMarker(ctx, group, dimensions, encoded)
	}

	_, err = s.runScript(ctx, scriptAggregateSessionUpsert, group.sessionScriptKeys(),
		dimensions.SessionID,
		encoded,
		dimensions.Protocol,
		dimensions.ListenerName,
		dimensions.ServiceName,
		dimensions.ShardTag,
		dimensions.BackendIdentifier,
	)

	return err
}

// removeSessionAggregate removes one active-session marker and decrements counters once.
//
// A marker missing from the bucketed group is looked up in the legacy group
// only while that group still exists, so sessions opened by earlier releases
// are removed exactly once without a permanent extra read per close.
func (s *RedisSessionStore) removeSessionAggregate(ctx context.Context, sessionID string) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return
	}

	group, err := s.keys.AggregateSessionKeys(sessionID)
	if err != nil {
		s.recordRedisOperation(redisContext(ctx), "aggregate_session_remove", time.Now(), err)

		return
	}

	removed, err := s.removeAggregateMarker(ctx, group, sessionID)
	if err != nil {
		s.recordRedisOperation(redisContext(ctx), "aggregate_session_remove", time.Now(), err)

		return
	}

	legacy := s.keys.LegacyAggregateKeys()
	if removed || !s.legacyKeyPresent(ctx, legacy.Sessions) {
		return
	}

	if _, err := s.removeAggregateMarker(ctx, legacy, sessionID); err != nil {
		s.recordRedisOperation(redisContext(ctx), "aggregate_session_remove", time.Now(), err)
	}
}

// removeAggregateMarker removes one marker from a group and decrements its counters once.
func (s *RedisSessionStore) removeAggregateMarker(ctx context.Context, group AggregateKeys, sessionID string) (bool, error) {
	if group.Legacy() {
		return s.removeLegacyAggregateMarker(ctx, group, sessionID)
	}

	value, err := s.runScript(ctx, scriptAggregateSessionRemove, group.sessionScriptKeys(), sessionID)
	if err != nil {
		return false, err
	}

	removed, ok := value.(int64)
	if !ok || (removed != 0 && removed != 1) {
		return false, newStateError(RedisErrorKindAmbiguousState, scriptAggregateSessionRemove, "invalid aggregate remove result", nil)
	}

	return removed == 1, nil
}

// removeLegacyAggregateMarker removes a marker from the untagged legacy keys.
//
// The legacy keys live in independent slots, so this path keeps the earlier
// read-delete-decrement sequence; HDEL's result still guarantees one decrement.
func (s *RedisSessionStore) removeLegacyAggregateMarker(ctx context.Context, group AggregateKeys, sessionID string) (bool, error) {
	redisCtx := redisContext(ctx)
	started := time.Now()

	previousValue, err := s.client.HGet(redisCtx, group.Sessions, sessionID).Result()
	if errors.Is(err, redis.Nil) {
		s.recordRedisOperation(redisCtx, "aggregate_legacy_session_remove", started, nil)

		return false, nil
	}

	if err != nil {
		classified := ClassifyRedisError(aggregateOperation, err)
		s.recordRedisOperation(redisCtx, "aggregate_legacy_session_remove", started, classified)

		return false, classified
	}

	removed, err := s.client.HDel(redisCtx, group.Sessions, sessionID).Result()
	if err != nil {
		classified := ClassifyRedisError(aggregateOperation, err)
		s.recordRedisOperation(redisCtx, "aggregate_legacy_session_remove", started, classified)

		return false, classified
	}

	s.recordRedisOperation(redisCtx, "aggregate_legacy_session_remove", started, nil)

	if removed == 0 {
		return false, nil
	}

	if previous, ok := decodeAggregateSessionDimensions(previousValue, sessionID); ok {
		s.adjustAggregateCounters(ctx, group, previous, -1)
	}

	return true, nil
}

// replaceLegacyAggregateMarker rewrites a legacy marker during repair and moves its counters.
func (s *RedisSessionStore) replaceLegacyAggregateMarker(
	ctx context.Context,
	group AggregateKeys,
	dimensions aggregateSessionDimensions,
	encoded string,
) error {
	redisCtx := redisContext(ctx)
	started := time.Now()

	previousValue, err := s.client.HGet(redisCtx, group.Sessions, dimensions.SessionID).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		classified := ClassifyRedisError(aggregateOperation, err)
		s.recordRedisOperation(redisCtx, "aggregate_legacy_session_upsert", started, classified)

		return classified
	}

	if err := s.client.HSet(redisCtx, group.Sessions, dimensions.SessionID, encoded).Err(); err != nil {
		classified := ClassifyRedisError(aggregateOperation, err)
		s.recordRedisOperation(redisCtx, "aggregate_legacy_session_upsert", started, classified)

		return classified
	}

	s.recordRedisOperation(redisCtx, "aggregate_legacy_session_upsert", started, nil)

	if previous, ok := decodeAggregateSessionDimensions(previousValue, dimensions.SessionID); ok {
		s.adjustAggregateCounters(ctx, group, previous, -1)
	}

	s.adjustAggregateCounters(ctx, group, dimensions, 1)

	return nil
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

// addIdleAffinityAggregate adds or refreshes one idle affinity marker in its bucket.
func (s *RedisSessionStore) addIdleAffinityAggregate(ctx context.Context, idle aggregateIdleAffinity) {
	idle.AffinityHash = strings.TrimSpace(idle.AffinityHash)
	if idle.AffinityHash == "" || idle.ExpiresAt.IsZero() {
		return
	}

	group, err := s.keys.AggregateIdleAffinityKeys(idle.AffinityHash)
	if err != nil {
		s.recordRedisOperation(redisContext(ctx), "aggregate_idle_affinity_add", time.Now(), err)

		return
	}

	s.runRepairableIndexCommand(ctx, "aggregate_idle_affinity_add", func(redisCtx context.Context) error {
		return s.client.ZAdd(redisCtx, group.IdleAffinities, redisZ(idle.ExpiresAt, idle.AffinityHash)).Err()
	})
}

// removeIdleAffinityAggregate removes one affinity from its idle bucket and, while present, the legacy set.
func (s *RedisSessionStore) removeIdleAffinityAggregate(ctx context.Context, affinityHash string) {
	affinityHash = strings.TrimSpace(affinityHash)
	if affinityHash == "" {
		return
	}

	group, err := s.keys.AggregateIdleAffinityKeys(affinityHash)
	if err != nil {
		s.recordRedisOperation(redisContext(ctx), "aggregate_idle_affinity_remove", time.Now(), err)

		return
	}

	s.runRepairableIndexCommand(ctx, "aggregate_idle_affinity_remove", func(redisCtx context.Context) error {
		return s.client.ZRem(redisCtx, group.IdleAffinities, affinityHash).Err()
	})

	legacy := s.keys.LegacyAggregateKeys()
	if !s.legacyKeyPresent(ctx, legacy.IdleAffinities) {
		return
	}

	s.runRepairableIndexCommand(ctx, "aggregate_idle_affinity_remove", func(redisCtx context.Context) error {
		return s.client.ZRem(redisCtx, legacy.IdleAffinities, affinityHash).Err()
	})
}

// legacyKeyPresent reports whether a key family written by earlier releases still exists.
//
// The observation is cached briefly; a transient read failure assumes presence
// so compatibility cleanup is not skipped.
func (s *RedisSessionStore) legacyKeyPresent(ctx context.Context, key string) bool {
	if present, known := s.local.legacyPresence(key); known {
		return present
	}

	redisCtx := redisContext(ctx)
	started := time.Now()

	count, err := s.client.Exists(redisCtx, key).Result()
	if err != nil {
		s.recordRedisOperation(redisCtx, "legacy_layout_probe", started, ClassifyRedisError(aggregateOperation, err))

		return true
	}

	s.recordRedisOperation(redisCtx, "legacy_layout_probe", started, nil)
	s.local.storeLegacyPresence(key, count > 0)

	return count > 0
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

// adjustAggregateCounters applies one signed change to every counter of a session in one group.
func (s *RedisSessionStore) adjustAggregateCounters(ctx context.Context, group AggregateKeys, dimensions aggregateSessionDimensions, delta int64) {
	for _, counter := range dimensions.counters() {
		s.adjustAggregateCounter(ctx, group.Dimension(counter.Dimension), counter.Field, delta)
	}
}

// adjustAggregateCounter changes one aggregate counter and removes zero or negative fields.
func (s *RedisSessionStore) adjustAggregateCounter(ctx context.Context, key string, field string, delta int64) {
	if key == "" || field == "" || delta == 0 {
		return
	}

	redisCtx := redisContext(ctx)
	started := time.Now()

	value, err := s.client.HIncrBy(redisCtx, key, field, delta).Result()
	if err != nil {
		s.recordRedisOperation(redisCtx, "aggregate_counter_adjust", started, ClassifyRedisError(aggregateOperation, err))

		return
	}

	if value <= 0 {
		err = s.client.HDel(redisCtx, key, field).Err()
	}

	s.recordRedisOperation(redisCtx, "aggregate_counter_adjust", started, ClassifyRedisError(aggregateOperation, err))
}

// aggregateDimensionCountList converts summed dimension totals into sorted operator counts.
func aggregateDimensionCountList(values map[string]int) []RuntimeDimensionCount {
	counts := make([]RuntimeDimensionCount, 0, len(values))

	for value, count := range values {
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

	return counts
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

// aggregateBackendCapacity merges active-session aggregates with reservation counts.
//
// Reserved capacity is summed from the reservation groups of every indexed
// backend and every backend with active sessions, so no per-login snapshot
// write is needed to keep it current.
func (s *RedisSessionStore) aggregateBackendCapacity(ctx context.Context, active map[string]int) ([]RuntimeBackendCapacitySummary, error) {
	indexed, err := s.backendIndexMembers(ctx)
	if err != nil {
		return nil, err
	}

	backendIDs := make(map[string]struct{}, len(active)+len(indexed))
	for backendID := range active {
		backendIDs[backendID] = struct{}{}
	}

	for _, backendID := range indexed {
		backendIDs[backendID] = struct{}{}
	}

	summaries := make([]RuntimeBackendCapacitySummary, 0, len(backendIDs))

	for backendID := range backendIDs {
		reservedCount, countErr := s.backendReservationActiveCount(ctx, backendID)
		if countErr != nil {
			return nil, countErr
		}

		activeCount := active[backendID]
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
