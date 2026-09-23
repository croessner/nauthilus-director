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

//nolint:goconst // Reservation fixtures repeat scoped identifiers intentionally.
package state

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// TestRedisBackendSnapshotReusesAdvisoryReservationTotal keeps selection off the bucket reads per login.
func TestRedisBackendSnapshotReusesAdvisoryReservationTotal(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	backendID := testBackendIMAP + "-advisory"
	clock := newRollingClock(store)

	other := &RedisSessionStore{client: store.client, keys: store.keys, registry: store.registry, recorder: store.recorder, local: newStoreLocalState()}

	cleanupBackend(t, client, builder, backendID)
	own := reserveBackendForTest(t, store, backendID, "advisory-1", 10)
	assertSnapshotCount(t, store, backendID, 1, "first read")

	reserveBackendForTest(t, store, backendID, "advisory-own", 10)
	assertSnapshotCount(t, store, backendID, 2, "own admission applied to cached read")

	release(t, store, backendID, own.ReservationID, 1)
	assertSnapshotCount(t, store, backendID, 1, "own release applied to cached read")

	reserveBackendForTest(t, other, backendID, "advisory-other", 10)
	assertSnapshotCount(t, store, backendID, 1, "other process visible only after expiry")

	clock.advance(backendReservationTotalTTL)
	assertSnapshotCount(t, store, backendID, 2, "read after expiry")

	reserveBackendForTest(t, other, backendID, "advisory-3", 10)

	if _, err := store.ReapBackendReservations(context.Background(), BackendReservationReapRequest{BackendIdentifier: backendID, Limit: 10}); err != nil {
		t.Fatalf("ReapBackendReservations returned error: %v", err)
	}

	assertSnapshotCount(t, store, backendID, 3, "read fed by repair")
}

// TestRedisBackendReservationSpillRepairsExpiredBuckets avoids false capacity rejections after a writer crash.
func TestRedisBackendReservationSpillRepairsExpiredBuckets(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	backendID := testBackendIMAP + "-spill-due"
	capacity := builder.BackendReservationBucketCount()

	cleanupBackend(t, client, builder, backendID)

	crashed := reservationIDInBucket(t, builder, "crashed", 0, capacity)
	if _, err := store.ReserveBackendCapacity(context.Background(), BackendReservationRequest{
		BackendIdentifier: backendID,
		ReservationID:     crashed,
		MaxConnections:    capacity,
		LeaseTTL:          20 * time.Millisecond,
	}); err != nil {
		t.Fatalf("reserve crashed writer lease: %v", err)
	}

	for bucket := 1; bucket < capacity; bucket++ {
		reserveBackendForTest(t, store, backendID, reservationIDInBucket(t, builder, "live", bucket, capacity), capacity)
	}

	time.Sleep(40 * time.Millisecond)

	incoming := reservationIDInBucket(t, builder, "incoming", 5, capacity)

	record, err := store.ReserveBackendCapacity(context.Background(), BackendReservationRequest{
		BackendIdentifier: backendID,
		ReservationID:     incoming,
		MaxConnections:    capacity,
		LeaseTTL:          time.Minute,
	})
	if err != nil {
		t.Fatalf("reservation next to an expired lease error = %v, want spill into the repaired bucket", err)
	}

	if ref := parseBackendReservationRef(record.ReservationID); ref.Bucket != 0 || record.RepairedCount != 1 {
		t.Fatalf("spill record = %+v, want bucket 0 with one inline repair", record)
	}

	if count := redisBackendActiveCount(t, client, builder, backendID); count != capacity {
		t.Fatalf("backend active count = %d, want %d", count, capacity)
	}
}

// TestRedisBucketReservationRefreshSurvivesShareShrink keeps existing leases when a bucket share drops to zero.
func TestRedisBucketReservationRefreshSurvivesShareShrink(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	backendID := testBackendIMAP + "-shrink"

	cleanupBackend(t, client, builder, backendID)

	reserved := reserveBackendForTest(t, store, backendID, reservationIDInBucket(t, builder, "shrink", 7, 12), 12)
	if parseBackendReservationRef(reserved.ReservationID).Bucket != 7 {
		t.Fatalf("reservation %q not in bucket 7", reserved.ReservationID)
	}

	refreshed := reserveBackendForTest(t, store, backendID, reserved.ReservationID, 1)
	if refreshed.ReservationID != reserved.ReservationID || refreshed.BackendActiveCount != 1 {
		t.Fatalf("refresh with zero share = %+v, want the same lease kept", refreshed)
	}

	release(t, store, backendID, reserved.ReservationID, 1)

	_, err := store.ReserveBackendCapacity(context.Background(), BackendReservationRequest{
		BackendIdentifier: backendID,
		ReservationID:     reserved.ReservationID,
		MaxConnections:    1,
		LeaseTTL:          time.Minute,
	})
	if !isBackendAtCapacity(err) {
		t.Fatalf("re-admission into a zero share error = %v, want backend at capacity", err)
	}
}

// TestRedisAttachRetryAdoptsNewBucketOfSameCaller replaces a retried reservation without a conflict.
func TestRedisAttachRetryAdoptsNewBucketOfSameCaller(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	backendID := testBackendIMAP + "-attach-retry"
	key := AffinityKey{Tenant: "blue", AccountKey: "attach-retry@example.test"}
	sessionID := "attach-retry-session"

	cleanupAffinity(t, client, builder, key, sessionID)
	cleanupBackend(t, client, builder, backendID)

	if _, err := store.OpenSession(context.Background(), testSessionRecord(key, sessionID)); err != nil {
		t.Fatalf("OpenSession returned error: %v", err)
	}

	first := reserveBackendForTest(t, store, backendID, sessionID, 12)
	attachForTest(t, store, key, sessionID, backendID, first.ReservationID)

	otherBucket := (parseBackendReservationRef(first.ReservationID).Bucket + 1) % 12
	retried := reserveBackendForTest(t, store, backendID, formatBackendReservationID(sessionID, otherBucket), 12)
	attachForTest(t, store, key, sessionID, backendID, retried.ReservationID)

	sessionKey, _ := builder.SessionKey(key.Tenant, key.AccountKey, sessionID)
	if got := client.HGet(context.Background(), sessionKey, scriptFieldBackendReservation).Val(); got != retried.ReservationID {
		t.Fatalf("session reservation = %q, want %q", got, retried.ReservationID)
	}

	if count := redisBackendActiveCount(t, client, builder, backendID); count != 1 {
		t.Fatalf("backend active count after retried attach = %d, want the replaced lease released", count)
	}

	outOfRange := reserveBackendForTest(t, store, backendID, sessionID+"#rb12", 12)

	for _, foreignID := range []string{reserveBackendForTest(t, store, backendID, "another-caller", 12).ReservationID, outOfRange.ReservationID} {
		if _, err := store.AttachSelectedBackend(context.Background(), SessionBackendAttachment{
			Key:               key,
			SessionID:         sessionID,
			BackendIdentifier: backendID,
			BackendNode:       testBackendNodeA,
			ReservationID:     foreignID,
			MaxConnections:    12,
		}); !IsRedisErrorKind(err, RedisErrorKindAmbiguousState) {
			t.Fatalf("attach with foreign reservation %q error = %v, want conflict", foreignID, err)
		}
	}
}

// TestSpreadHashTagRejectsInvalidFamilies fails loudly instead of emitting an unspread tag.
func TestSpreadHashTagRejectsInvalidFamilies(t *testing.T) {
	for _, item := range []struct {
		family  string
		bucket  int
		buckets int
	}{
		{"agg", -1, 12},
		{"agg", 12, 12},
		{"agg", 0, 0},
		{"agg", 0, redisClusterSlots + 1},
		{"a{g", 0, 12},
	} {
		if tag, err := spreadHashTag(item.family, item.bucket, item.buckets); err == nil {
			t.Fatalf("spreadHashTag(%+v) = %q, want error", item, tag)
		}
	}
}

// attachForTest attaches one reservation to an open session.
func attachForTest(t *testing.T, store *RedisSessionStore, key AffinityKey, sessionID string, backendID string, reservationID string) {
	t.Helper()

	if _, err := store.AttachSelectedBackend(context.Background(), SessionBackendAttachment{
		Key:               key,
		SessionID:         sessionID,
		BackendIdentifier: backendID,
		BackendNode:       testBackendNodeA,
		ReservationID:     reservationID,
		MaxConnections:    12,
	}); err != nil {
		t.Fatalf("AttachSelectedBackend(%s) returned error: %v", reservationID, err)
	}
}

// assertSnapshotCount verifies the advisory active count seen by selection.
func assertSnapshotCount(t *testing.T, store *RedisSessionStore, backendID string, want int, label string) {
	t.Helper()

	snapshot, err := store.BackendSnapshot(context.Background(), backendID)
	if err != nil {
		t.Fatalf("%s: BackendSnapshot returned error: %v", label, err)
	}

	if snapshot.ActiveSessions != want {
		t.Fatalf("%s: snapshot active sessions = %d, want %d", label, snapshot.ActiveSessions, want)
	}
}

// reservationIDInBucket finds a caller identifier whose preferred bucket is the requested one.
func reservationIDInBucket(t *testing.T, builder KeyBuilder, prefix string, bucket int, activeBuckets int) string {
	t.Helper()

	for index := range 10000 {
		candidate := fmt.Sprintf("%s-%d", prefix, index)

		preferred, err := builder.BackendReservationBucket(candidate, activeBuckets)
		if err != nil {
			t.Fatalf("BackendReservationBucket returned error: %v", err)
		}

		if preferred == bucket {
			return candidate
		}
	}

	t.Fatalf("no identifier found for bucket %d", bucket)

	return ""
}

// TestAdvisoryReservationTotalKeepsNewerLocalChanges rejects a read result that started before a local change.
func TestAdvisoryReservationTotalKeepsNewerLocalChanges(t *testing.T) {
	local := newStoreLocalState()
	now := time.Unix(1000, 0)
	local.now = func() time.Time { return now }

	local.storeReadBackendReservationTotal("b", 4, now)
	readStartedAt := now

	now = now.Add(time.Millisecond)

	local.adjustBackendReservationTotal("b", 1)

	now = now.Add(time.Millisecond)

	local.storeReadBackendReservationTotal("b", 4, readStartedAt)

	if count, ok := local.backendReservationTotal("b"); !ok || count != 5 {
		t.Fatalf("total after stale read = %d, %t; want the newer local 5", count, ok)
	}

	local.storeReadBackendReservationTotal("b", 7, now)

	if count, ok := local.backendReservationTotal("b"); !ok || count != 7 {
		t.Fatalf("total after newer read = %d, %t; want 7", count, ok)
	}
}

// TestRedisAdvisoryReservationTotalSurvivesConcurrentAdmission keeps an admission made during a sweep.
func TestRedisAdvisoryReservationTotalSurvivesConcurrentAdmission(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	backendID := testBackendIMAP + "-toctou"

	cleanupBackend(t, client, builder, backendID)
	reserveBackendForTest(t, store, backendID, "toctou-1", 10)
	assertSnapshotCount(t, store, backendID, 1, "primed")

	hooked := &admittingPipelineClient{RedisClient: store.client}
	store.client = hooked
	hooked.during = func() { reserveBackendForTest(t, store, backendID, "toctou-2", 10) }

	total, err := store.backendReservationActiveCount(context.Background(), backendID)
	if err != nil || total != 1 {
		t.Fatalf("sweep total = %d, %v; want the pre-admission 1", total, err)
	}

	assertSnapshotCount(t, store, backendID, 2, "admission during sweep kept")
}

// TestRedisFailedAdmissionMarksBackendFull stops the same process from selecting a saturated backend again.
func TestRedisFailedAdmissionMarksBackendFull(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	backendID := testBackendIMAP + "-full"
	other := &RedisSessionStore{client: store.client, keys: store.keys, registry: store.registry, recorder: store.recorder, local: newStoreLocalState()}

	cleanupBackend(t, client, builder, backendID)
	assertSnapshotCount(t, store, backendID, 0, "empty")

	reserveBackendForTest(t, other, backendID, "full-1", 2)
	reserveBackendForTest(t, other, backendID, "full-2", 2)
	assertSnapshotCount(t, store, backendID, 0, "other process not yet visible")
	assertBackendCapacityRejected(t, store, backendID, "full-3", 2)
	assertSnapshotCount(t, store, backendID, 2, "failed admission marks the backend full")
}

// TestRedisAtCapacityStatusAccountsInlineRepairs counts repaired leases even when admission fails.
func TestRedisAtCapacityStatusAccountsInlineRepairs(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	backendID := testBackendIMAP + "-capacity-status"

	cleanupBackend(t, client, builder, backendID)
	cleanupRuntimeAggregateState(t, client, builder)
	reserveBackendForTest(t, store, backendID, reservationIDInBucket(t, builder, "status-live", 0, 12), 24)

	if _, err := store.ReserveBackendCapacity(context.Background(), BackendReservationRequest{
		BackendIdentifier: backendID,
		ReservationID:     reservationIDInBucket(t, builder, "status-expired", 0, 12),
		MaxConnections:    24,
		LeaseTTL:          20 * time.Millisecond,
	}); err != nil {
		t.Fatalf("reserve expiring lease: %v", err)
	}

	time.Sleep(40 * time.Millisecond)
	assertBackendCapacityRejected(t, store, backendID, "status-new", 1)

	if got := aggregateHashField(t, store, builder.AggregateRepairKey(), aggregateFieldBackendReservations); got != "1" {
		t.Fatalf("repair counter = %q, want the inline repair of the rejected admission", got)
	}

	if count := redisBackendActiveCount(t, client, builder, backendID); count != 1 {
		t.Fatalf("backend active count = %d, want only the live lease", count)
	}
}

// admittingPipelineClient runs one callback after a pipeline read and before its caller stores the result.
type admittingPipelineClient struct {
	RedisClient
	during func()
}

// Pipelined forwards the pipeline and then runs the one-shot callback.
func (c *admittingPipelineClient) Pipelined(ctx context.Context, fn func(redis.Pipeliner) error) ([]redis.Cmder, error) {
	commands, err := c.RedisClient.Pipelined(ctx, fn)

	if during := c.during; during != nil {
		c.during = nil
		during()
	}

	return commands, err
}
