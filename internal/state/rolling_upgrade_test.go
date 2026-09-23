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

//nolint:funlen,goconst,gocyclo // Mixed-version scenarios keep each compatibility contract readable end to end.
package state

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/redis/go-redis/v9"
)

const rollingBackendMax = 4

// TestRedisRollingUpgradeReservations proves capacity stays exact and nothing is lost next to legacy writers.
func TestRedisRollingUpgradeReservations(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	backendID := testBackendIMAP + "-rolling"

	cleanupBackend(t, client, builder, backendID)
	exerciseRollingUpgradeReservations(t, store, client)
}

// TestRedisRollingUpgradeAggregates proves summaries and removals cover sessions of both layouts.
func TestRedisRollingUpgradeAggregates(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)

	cleanupRuntimeAggregateState(t, client, builder)
	exerciseRollingUpgradeAggregates(t, store, client)
}

// TestRedisRollingUpgradeHealth proves placement keeps reading fresh health while old owners publish.
func TestRedisRollingUpgradeHealth(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)

	cleanupHealth(t, client, builder, testBackendIMAP)
	exerciseRollingUpgradeHealth(t, store, client)
}

// TestRedisBackendReservationBucketsNeverExceedCapacity races several writers against one limit.
func TestRedisBackendReservationBucketsNeverExceedCapacity(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)

	cleanupBackend(t, client, builder, testBackendIMAP+"-race")
	exerciseReservationCapacityRace(t, store, client)
}

// TestRedisBackendReservationsSpillBeforeRejecting admits exactly max_connections despite hash collisions.
func TestRedisBackendReservationsSpillBeforeRejecting(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	backendID := testBackendIMAP + "-spill"

	cleanupBackend(t, client, builder, backendID)

	capacity := builder.BackendReservationBucketCount()
	for index := range capacity {
		reserveBackendForTest(t, store, backendID, fmt.Sprintf("spill-%02d", index), capacity)
	}

	assertBackendCapacityRejected(t, store, backendID, "spill-overflow", capacity)

	if count := redisBackendActiveCount(t, client, builder, backendID); count != capacity {
		t.Fatalf("backend active count = %d, want %d", count, capacity)
	}
}

// exerciseRollingUpgradeReservations runs the mixed-version reservation contract on any topology.
func exerciseRollingUpgradeReservations(t *testing.T, store *RedisSessionStore, client redis.Cmdable) {
	t.Helper()

	ctx := context.Background()
	backendID := testBackendIMAP + "-rolling"
	clock := newRollingClock(store)

	legacyWriterReserve(t, client, store.keys, backendID, "old-1", time.Minute)
	legacyWriterReserve(t, client, store.keys, backendID, "old-2", time.Minute)
	legacyWriterReserve(t, client, store.keys, backendID, "old-expired", 20*time.Millisecond)

	assertSnapshotActive(t, store, backendID, 3, "legacy reservations visible")

	fresh := reserveBackendForTest(t, store, backendID, "new-1", rollingBackendMax)
	if parseBackendReservationRef(fresh.ReservationID).Bucket == legacyBackendReservationBucket {
		t.Fatalf("new reservation %q was not bucket-bound", fresh.ReservationID)
	}

	assertBackendCapacityRejected(t, store, backendID, "new-2", rollingBackendMax)
	assertSnapshotActive(t, store, backendID, rollingBackendMax, "legacy plus bucketed reservations")

	time.Sleep(40 * time.Millisecond)

	reaped, err := store.ReapBackendReservations(ctx, BackendReservationReapRequest{BackendIdentifier: backendID, Limit: 10})
	if err != nil {
		t.Fatalf("ReapBackendReservations returned error: %v", err)
	}

	if reaped.RepairedCount != 1 || reaped.BackendActiveCount != 3 {
		t.Fatalf("reap = %+v, want one legacy repair and three active", reaped)
	}

	if _, err := store.refreshBackendReservation(ctx, BackendReservationRequest{
		BackendIdentifier: backendID,
		ReservationID:     "old-1",
		MaxConnections:    rollingBackendMax,
		LeaseTTL:          time.Minute,
	}); err != nil {
		t.Fatalf("legacy refresh returned error: %v", err)
	}

	assertSnapshotActive(t, store, backendID, 3, "legacy refresh stays in place")

	release(t, store, backendID, "old-1", 1)
	assertSnapshotActive(t, store, backendID, 2, "legacy release")

	legacyWriterRelease(t, store, backendID, fresh.ReservationID)
	assertSnapshotActive(t, store, backendID, 2, "legacy writer cannot release a bucket reservation")

	release(t, store, backendID, fresh.ReservationID, 1)
	assertSnapshotActive(t, store, backendID, 1, "bucket release")

	clock.advance(2 * legacyReservationCountTTL)

	for index := range rollingBackendMax - 1 {
		reserveBackendForTest(t, store, backendID, fmt.Sprintf("after-%d", index), rollingBackendMax)
	}

	assertBackendCapacityRejected(t, store, backendID, "after-overflow", rollingBackendMax)
	assertSnapshotActive(t, store, backendID, rollingBackendMax, "capacity after legacy drain")
}

// exerciseRollingUpgradeAggregates runs the mixed-version aggregate contract on any topology.
func exerciseRollingUpgradeAggregates(t *testing.T, store *RedisSessionStore, client redis.Cmdable) {
	t.Helper()

	ctx := context.Background()
	key := AffinityKey{Tenant: "rolling", AccountKey: "aggregate-new@example.test"}
	legacy := store.keys.LegacyAggregateKeys()

	cleanupRollingAffinity(t, store, key, "rolling-new-session")
	legacyWriterOpenAggregate(t, client, store.keys, "rolling-old-session")
	legacyWriterOpenAggregate(t, client, store.keys, "rolling-old-stale")

	if err := client.ZAdd(ctx, legacy.IdleAffinities, redis.Z{Score: float64(time.Now().Add(time.Minute).UnixMilli()), Member: "rolling-old-affinity"}).Err(); err != nil {
		t.Fatalf("seed legacy idle affinity: %v", err)
	}

	if _, err := store.OpenSession(ctx, testSessionRecord(key, "rolling-new-session")); err != nil {
		t.Fatalf("OpenSession returned error: %v", err)
	}

	summary := rollingSummary(t, store)
	if summary.ActiveSessions.Total.Count != 3 || runtimeDimensionCount(summary.ActiveSessions.ByProtocol, testProtocolIMAP) != 3 {
		t.Fatalf("mixed summary = %+v, want three active IMAP sessions", summary.ActiveSessions)
	}

	if summary.IdleAffinities.Count != 1 {
		t.Fatalf("mixed idle affinities = %d, want the legacy one", summary.IdleAffinities.Count)
	}

	store.removeSessionAggregate(ctx, "rolling-old-session")
	store.removeIdleAffinityAggregate(ctx, "rolling-old-affinity")

	if exists := client.HExists(ctx, legacy.Sessions, "rolling-old-session").Val(); exists {
		t.Fatal("legacy marker survived removal by the current writer")
	}

	record, err := store.ReconcileRuntimeAggregates(ctx, RuntimeAggregateReconcileRequest{Limit: 100, MaxPassDuration: 5 * time.Second})
	if err != nil {
		t.Fatalf("ReconcileRuntimeAggregates returned error: %v", err)
	}

	if record.StaleMarkersRemoved != 1 || record.Partial {
		t.Fatalf("reconcile = %+v, want the stale legacy marker removed", record)
	}

	summary = rollingSummary(t, store)
	if summary.ActiveSessions.Total.Count != 1 || runtimeDimensionCount(summary.ActiveSessions.ByProtocol, testProtocolIMAP) != 1 || summary.IdleAffinities.Count != 0 {
		t.Fatalf("drained summary = %+v idle=%d, want only the new session", summary.ActiveSessions, summary.IdleAffinities.Count)
	}

	if _, err := store.CloseSession(ctx, key, "rolling-new-session"); err != nil {
		t.Fatalf("CloseSession returned error: %v", err)
	}

	if total := rollingSummary(t, store).ActiveSessions.Total.Count; total != 0 {
		t.Fatalf("active total after close = %d, want 0", total)
	}
}

// exerciseRollingUpgradeHealth runs the mixed-version health contract on any topology.
func exerciseRollingUpgradeHealth(t *testing.T, store *RedisSessionStore, client redis.Cmdable) {
	t.Helper()

	ctx := context.Background()

	legacyWriterPublishHealth(t, client, store.keys, testBackendIMAP, backend.HealthStatusHealthy)

	state, err := store.ReadHealthState(ctx, testBackendIMAP)
	if err != nil || state.Status != backend.HealthStatusHealthy {
		t.Fatalf("fallback health = %+v, %v; want legacy healthy", state, err)
	}

	publishTestInstanceHeartbeat(t, store, "director-new")

	owner := acquireTestHealthOwner(t, store, "director-new", testBackendIMAP, time.Minute)
	if !owner.Owned {
		t.Fatalf("new owner blocked by legacy owner: %+v", owner)
	}

	if _, err := store.PublishHealthState(ctx, HealthPublishRequest{
		InstanceID:        "director-new",
		BackendIdentifier: testBackendIMAP,
		FencingToken:      owner.FencingToken,
		State:             backend.HealthState{Enabled: true, Status: backend.HealthStatusUnhealthy, ReasonClass: "connect"},
		TTL:               time.Minute,
	}); err != nil {
		t.Fatalf("PublishHealthState returned error: %v", err)
	}

	state, err = store.ReadHealthState(ctx, testBackendIMAP)
	if err != nil || state.Status != backend.HealthStatusUnhealthy {
		t.Fatalf("current health = %+v, %v; want the current owner's unhealthy result", state, err)
	}

	legacyKey, _ := store.keys.LegacyHealthStateKey(testBackendIMAP)
	if status := client.HGet(ctx, legacyKey, "status").Val(); status != string(backend.HealthStatusHealthy) {
		t.Fatalf("legacy health status = %q, want untouched for older readers", status)
	}

	other := &RedisSessionStore{client: store.client, keys: store.keys, registry: store.registry, recorder: store.recorder, local: newStoreLocalState()}
	if _, err := other.AcquireHealthOwner(ctx, HealthOwnershipRequest{InstanceID: "director-silent", BackendIdentifier: testBackendIMAP, LeaseTTL: time.Minute}); !IsRedisErrorKind(err, RedisErrorKindAmbiguousState) {
		t.Fatalf("acquire without own heartbeat error = %v, want ambiguous_state", err)
	}

	stateKey, _ := store.keys.HealthStateKey(testBackendIMAP)
	if err := client.HSet(ctx, stateKey, "expires_at_ms", strconv.FormatInt(time.Now().Add(-time.Second).UnixMilli(), 10)).Err(); err != nil {
		t.Fatalf("expire current health: %v", err)
	}

	state, err = store.ReadHealthState(ctx, testBackendIMAP)
	if err != nil || state.Status != backend.HealthStatusHealthy {
		t.Fatalf("health with stale current result = %+v, %v; want fresh legacy healthy", state, err)
	}

	legacyWriterPublishHealth(t, client, store.keys, testBackendIMAP, backend.HealthStatusHealthy)

	if err := client.HSet(ctx, legacyKey, "expires_at_ms", strconv.FormatInt(time.Now().Add(-time.Second).UnixMilli(), 10)).Err(); err != nil {
		t.Fatalf("expire legacy health: %v", err)
	}

	state, err = store.ReadHealthState(ctx, testBackendIMAP)
	if err != nil || state.Status != backend.HealthStatusStale || state.ReasonClass != "connect" {
		t.Fatalf("health with both results stale = %+v, %v; want the current stale result", state, err)
	}

	contender := &RedisSessionStore{client: store.client, keys: store.keys, registry: store.registry, recorder: store.recorder, local: newStoreLocalState()}
	publishTestInstanceHeartbeat(t, contender, "director-other")

	held := acquireTestHealthOwner(t, contender, "director-other", testBackendIMAP, time.Minute)
	if held.Owned || held.OwnerInstanceID != "director-new" || !held.ExpiresAt.After(held.ServerTime) {
		t.Fatalf("contender = %+v, want held by director-new with the real lease expiry", held)
	}
}

// exerciseReservationCapacityRace admits exactly max_connections under concurrent writers.
func exerciseReservationCapacityRace(t *testing.T, store *RedisSessionStore, client redis.Cmdable) {
	t.Helper()

	const (
		capacity = 20
		attempts = 60
		writers  = 3
	)

	backendID := testBackendIMAP + "-race"
	stores := make([]*RedisSessionStore, writers)

	for index := range stores {
		stores[index] = &RedisSessionStore{client: store.client, keys: store.keys, registry: store.registry, recorder: store.recorder, local: newStoreLocalState()}
	}

	var (
		wait      sync.WaitGroup
		mu        sync.Mutex
		successes int
		failures  []error
	)

	start := make(chan struct{})

	for attempt := range attempts {
		wait.Go(func() {
			<-start

			_, err := stores[attempt%writers].ReserveBackendCapacity(context.Background(), BackendReservationRequest{
				BackendIdentifier: backendID,
				ReservationID:     fmt.Sprintf("race-%03d", attempt),
				MaxConnections:    capacity,
				LeaseTTL:          time.Minute,
			})

			mu.Lock()
			defer mu.Unlock()

			if err == nil {
				successes++
			} else if !isBackendAtCapacity(err) {
				failures = append(failures, err)
			}
		})
	}

	close(start)
	wait.Wait()

	if len(failures) > 0 {
		t.Fatalf("unexpected reservation errors: %v", failures)
	}

	if successes != capacity {
		t.Fatalf("successful reservations = %d, want exactly %d", successes, capacity)
	}

	total, err := store.backendReservationActiveCount(context.Background(), backendID)
	if err != nil || total != capacity {
		t.Fatalf("backend active count = %d, %v; want %d", total, err, capacity)
	}

	_ = client
}

// legacyWriterReserve writes a reservation exactly as the single-slot layout stored it.
func legacyWriterReserve(t *testing.T, client redis.Cmdable, builder KeyBuilder, backendID string, reservationID string, ttl time.Duration) {
	t.Helper()

	ctx := context.Background()

	keys, err := builder.LegacyBackendReservationKeys(backendID)
	if err != nil {
		t.Fatalf("LegacyBackendReservationKeys returned error: %v", err)
	}

	expiresAt := time.Now().Add(ttl).UnixMilli()

	if err := client.HIncrBy(ctx, keys.State, scriptFieldActiveSessionCount, 1).Err(); err != nil {
		t.Fatalf("legacy reserve count: %v", err)
	}

	if err := client.HSet(ctx, keys.State, "backend_id", backendID, "reservation:"+reservationID, expiresAt, "updated_at_ms", time.Now().UnixMilli()).Err(); err != nil {
		t.Fatalf("legacy reserve field: %v", err)
	}

	if err := client.ZAdd(ctx, keys.Due, redis.Z{Score: float64(expiresAt), Member: reservationID}).Err(); err != nil {
		t.Fatalf("legacy reserve due: %v", err)
	}
}

// legacyWriterRelease replays an older reaper releasing an identifier in the single-slot group.
func legacyWriterRelease(t *testing.T, store *RedisSessionStore, backendID string, reservationID string) {
	t.Helper()

	keys, err := store.keys.LegacyBackendReservationKeys(backendID)
	if err != nil {
		t.Fatalf("LegacyBackendReservationKeys returned error: %v", err)
	}

	if _, err := store.runScript(context.Background(), scriptBackendRelease, []string{keys.State, keys.Due}, backendID, reservationID); err != nil {
		t.Fatalf("legacy release script returned error: %v", err)
	}
}

// legacyWriterOpenAggregate records a session the way the untagged aggregate layout did.
func legacyWriterOpenAggregate(t *testing.T, client redis.Cmdable, builder KeyBuilder, sessionID string) {
	t.Helper()

	ctx := context.Background()
	legacy := builder.LegacyAggregateKeys()
	dimensions := map[string]string{
		aggregateDimensionProtocol: testProtocolIMAP,
		aggregateDimensionListener: testListenerIMAPS,
		aggregateDimensionService:  testProtocolIMAP,
		aggregateDimensionShardTag: testShardA,
	}

	encoded, err := json.Marshal(dimensions)
	if err != nil {
		t.Fatalf("encode legacy marker: %v", err)
	}

	if err := client.HSetNX(ctx, legacy.Sessions, sessionID, string(encoded)).Err(); err != nil {
		t.Fatalf("legacy marker: %v", err)
	}

	for dimension, value := range dimensions {
		if err := client.HIncrBy(ctx, legacy.Dimension(dimension), value, 1).Err(); err != nil {
			t.Fatalf("legacy counter: %v", err)
		}
	}
}

// legacyWriterPublishHealth writes a health result into the shared legacy health slot.
func legacyWriterPublishHealth(t *testing.T, client redis.Cmdable, builder KeyBuilder, backendID string, status backend.HealthStatus) {
	t.Helper()

	key, err := builder.LegacyHealthStateKey(backendID)
	if err != nil {
		t.Fatalf("LegacyHealthStateKey returned error: %v", err)
	}

	now := time.Now()
	if err := client.HSet(context.Background(), key,
		"backend_id", backendID,
		"status", string(status),
		"reason_class", "",
		"capabilities", "",
		"capability_facts", "",
		"owner_instance_id", "director-old",
		"fencing_token", "7",
		"generation", "42",
		"checked_at_ms", strconv.FormatInt(now.UnixMilli(), 10),
		"expires_at_ms", strconv.FormatInt(now.Add(time.Minute).UnixMilli(), 10),
	).Err(); err != nil {
		t.Fatalf("legacy health publish: %v", err)
	}
}

// assertSnapshotActive verifies the exact backend-wide active count behind selection reads.
func assertSnapshotActive(t *testing.T, store *RedisSessionStore, backendID string, want int, label string) {
	t.Helper()

	active, err := store.backendReservationActiveCount(context.Background(), backendID)
	if err != nil {
		t.Fatalf("%s: backendReservationActiveCount returned error: %v", label, err)
	}

	if active != want {
		t.Fatalf("%s: active sessions = %d, want %d", label, active, want)
	}
}

// assertBackendCapacityRejected verifies a reservation fails closed at the backend-wide limit.
func assertBackendCapacityRejected(t *testing.T, store *RedisSessionStore, backendID string, reservationID string, capacity int) {
	t.Helper()

	_, err := store.ReserveBackendCapacity(context.Background(), BackendReservationRequest{
		BackendIdentifier: backendID,
		ReservationID:     reservationID,
		MaxConnections:    capacity,
		LeaseTTL:          time.Minute,
	})
	if !isBackendAtCapacity(err) {
		t.Fatalf("reservation %s error = %v, want backend at capacity", reservationID, err)
	}
}

// release releases one reservation and verifies the released count.
func release(t *testing.T, store *RedisSessionStore, backendID string, reservationID string, wantReleased int) {
	t.Helper()

	record, err := store.ReleaseBackendReservation(context.Background(), BackendReservationReleaseRequest{BackendIdentifier: backendID, ReservationID: reservationID})
	if err != nil {
		t.Fatalf("ReleaseBackendReservation %s returned error: %v", reservationID, err)
	}

	if record.RepairedCount != wantReleased {
		t.Fatalf("release %s = %+v, want %d released", reservationID, record, wantReleased)
	}
}

// rollingSummary reads the operator aggregate summary.
func rollingSummary(t *testing.T, store *RedisSessionStore) RuntimeAggregateSummary {
	t.Helper()

	summary, err := store.RuntimeAggregateSummary(context.Background())
	if err != nil {
		t.Fatalf("RuntimeAggregateSummary returned error: %v", err)
	}

	return summary
}

// cleanupRollingAffinity removes one affinity group through the topology-neutral client.
func cleanupRollingAffinity(t *testing.T, store *RedisSessionStore, key AffinityKey, sessionIDs ...string) {
	t.Helper()

	keys, err := store.keys.AffinityKeys(key.Tenant, key.AccountKey)
	if err != nil {
		t.Fatalf("AffinityKeys returned error: %v", err)
	}

	for _, redisKey := range []string{keys.State, keys.Sessions, keys.Override, keys.BackendPin, keys.Hold} {
		_ = store.client.Del(context.Background(), redisKey).Err()
	}

	for _, sessionID := range sessionIDs {
		sessionKey, _ := store.keys.SessionKey(key.Tenant, key.AccountKey, sessionID)
		_ = store.client.Del(context.Background(), sessionKey).Err()
	}
}

// rollingClock lets a test move the store's local cache clock forward.
type rollingClock struct {
	mu     sync.Mutex
	offset time.Duration
}

// newRollingClock installs an adjustable clock into the store's local accelerators.
func newRollingClock(store *RedisSessionStore) *rollingClock {
	clock := &rollingClock{}
	store.local.now = clock.now

	return clock
}

// now returns wall time shifted by the configured offset.
func (c *rollingClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return time.Now().Add(c.offset)
}

// advance moves the local cache clock forward.
func (c *rollingClock) advance(delta time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.offset += delta
}
