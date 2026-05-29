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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	seededRuntimeBackendID   = "scale-backend-imap"
	seededRuntimeLabelActive = "active"
	seededRuntimeRecordCount = 20000
	seededRuntimeSmallCount  = 3
	seededRuntimeTenant      = "scale"
)

// seededRuntimeRecord tracks exact keys so scale tests can clean up safely.
type seededRuntimeRecord struct {
	key          AffinityKey
	sessionID    string
	sessionKey   string
	affinityHash string
}

// TestRuntimeReadCursorRoundTripAndTamperRejection verifies cursor validation stays strict.
func TestRuntimeReadCursorRoundTripAndTamperRejection(t *testing.T) {
	store := &RedisSessionStore{keys: mustKeyBuilder(t)}
	encoded := store.encodeRuntimeReadCursor(runtimeReadFamilySessions, 7, 42, 3)

	decoded, err := store.decodeRuntimeReadCursor(encoded, runtimeReadFamilySessions, 8)
	if err != nil {
		t.Fatalf("decodeRuntimeReadCursor returned error: %v", err)
	}

	if decoded.Shard != 7 || decoded.RedisCursor != 42 || decoded.Offset != 3 {
		t.Fatalf("decoded cursor = %#v, want shard 7 cursor 42 offset 3", decoded)
	}

	assertRuntimeCursorRejected(t, store, "not-valid-base64", runtimeReadFamilySessions, 8)
	assertRuntimeCursorRejected(t, store, store.encodeRuntimeReadCursor(runtimeReadFamilyUsers, 0, 0), runtimeReadFamilySessions, 8)
	assertRuntimeCursorRejected(t, store, encodedRuntimeCursor(t, runtimeReadFamilySessions, 99, 0, 0), runtimeReadFamilySessions, 8)
	assertRuntimeCursorRejected(t, store, encodedRuntimeCursor(t, runtimeReadFamilySessions, 0, 0, -1), runtimeReadFamilySessions, 8)
}

// TestRedisRuntimeReadPagesEnforceLimitAcrossScanBatch proves HSCAN over-return remains bounded.
func TestRedisRuntimeReadPagesEnforceLimitAcrossScanBatch(t *testing.T) {
	store, client, builder := redisScaleIntegrationStore(t, KeyBuilderOptions{
		SessionIndexShards: 1,
		UserIndexShards:    1,
		BackendIndexShards: 1,
	}, WithRuntimeIndexPages(1, 1))
	records := seedRuntimeReadRecords(t, client, builder, seededRuntimeSmallCount, time.Hour)

	first := readSessionPage(t, store, RuntimeSessionPageRequest{Limit: 1})
	second := readSessionPage(t, store, RuntimeSessionPageRequest{Limit: 1, Cursor: first.NextCursor})
	third := readSessionPage(t, store, RuntimeSessionPageRequest{Limit: 1, Cursor: second.NextCursor})

	if len(first.Records) != 1 || len(second.Records) != 1 || len(third.Records) != 1 {
		t.Fatalf("page lengths = %d/%d/%d, want one record each", len(first.Records), len(second.Records), len(third.Records))
	}

	if first.NextCursor == "" || second.NextCursor == "" || third.NextCursor != "" {
		t.Fatalf("cursors = %q/%q/%q, want two continuations then end", first.NextCursor, second.NextCursor, third.NextCursor)
	}

	cleanupSeededRuntimeRecords(t, client, builder, records)
}

// TestRedisRuntimeReadPagesSeededLargeDataset proves large logical state remains paginated.
func TestRedisRuntimeReadPagesSeededLargeDataset(t *testing.T) {
	store, client, builder := redisScaleIntegrationStore(t, KeyBuilderOptions{
		SessionIndexShards: 1,
		UserIndexShards:    1,
		BackendIndexShards: 1,
	}, WithRuntimeIndexPages(17, 17))
	records := seedRuntimeReadRecords(t, client, builder, seededRuntimeRecordCount, time.Hour)

	sessionPage := readSessionPage(t, store, RuntimeSessionPageRequest{Limit: 17})
	if len(sessionPage.Records) != 17 || sessionPage.NextCursor == "" {
		t.Fatalf("session page len=%d cursor=%q, want bounded page with cursor", len(sessionPage.Records), sessionPage.NextCursor)
	}

	userPage, err := store.ListRuntimeUsersPage(context.Background(), RuntimeUserPageRequest{Limit: 17})
	if err != nil {
		t.Fatalf("ListRuntimeUsersPage returned error: %v", err)
	}

	if len(userPage.Records) != 17 || userPage.NextCursor == "" {
		t.Fatalf("user page len=%d cursor=%q, want bounded page with cursor", len(userPage.Records), userPage.NextCursor)
	}

	cleanupSeededRuntimeRecords(t, client, builder, records)
}

// TestRedisReaperSeededDueRecordsRemainBounded proves due-time repair ignores future leases.
func TestRedisReaperSeededDueRecordsRemainBounded(t *testing.T) {
	store, client, builder := redisScaleIntegrationStore(t, KeyBuilderOptions{
		SessionIndexShards: 1,
		UserIndexShards:    1,
		BackendIndexShards: 1,
	})
	expired := seedRuntimeReadRecords(t, client, builder, 5, -time.Hour)
	active := seedRuntimeReadRecords(t, client, builder, 5, time.Hour)

	reaped, err := store.ReapSessions(context.Background(), ReapRequest{Limit: 3, MaxPassDuration: time.Second})
	if err != nil {
		t.Fatalf("ReapSessions returned error: %v", err)
	}

	if reaped.ScannedSessions != 3 || reaped.ExpiredSessions != 3 {
		t.Fatalf("reap result = %#v, want bounded three expired records", reaped)
	}

	for _, record := range active {
		if _, ok, err := store.GetRuntimeSession(context.Background(), record.sessionID); err != nil || !ok {
			t.Fatalf("active session %s lookup ok=%t err=%v, want present", record.sessionID, ok, err)
		}
	}

	cleanupSeededRuntimeRecords(t, client, builder, append(expired, active...))
}

// assertRuntimeCursorRejected verifies malformed or cross-scope cursors fail closed.
func assertRuntimeCursorRejected(t *testing.T, store *RedisSessionStore, cursor string, family string, shardCount int) {
	t.Helper()

	if _, err := store.decodeRuntimeReadCursor(cursor, family, shardCount); !IsRedisErrorKind(err, RedisErrorKindAmbiguousState) {
		t.Fatalf("decodeRuntimeReadCursor(%q) error = %v, want ambiguous_state", cursor, err)
	}
}

// encodedRuntimeCursor returns a serialized internal cursor fixture.
func encodedRuntimeCursor(t *testing.T, family string, shard int, redisCursor uint64, offset int) string {
	t.Helper()

	payload, err := json.Marshal(runtimeReadCursor{
		Version:     runtimeReadCursorVersion,
		Family:      family,
		Shard:       shard,
		RedisCursor: redisCursor,
		Offset:      offset,
	})
	if err != nil {
		t.Fatalf("marshal cursor: %v", err)
	}

	return base64.RawURLEncoding.EncodeToString(payload)
}

// redisScaleIntegrationStore creates a Redis store with explicit scale key options.
func redisScaleIntegrationStore(
	t *testing.T,
	options KeyBuilderOptions,
	storeOptions ...RedisSessionStoreOption,
) (*RedisSessionStore, *redis.Client, KeyBuilder) {
	t.Helper()

	addr := scaleRedisAddress()
	if addr == "" {
		t.Skip("Redis integration skipped: set NAUTHILUS_DIRECTOR_REDIS_ADDR or REDIS_ADDR")
	}

	client := redis.NewClient(&redis.Options{Addr: addr, Protocol: 2})

	t.Cleanup(func() { _ = client.Close() })

	if err := client.Ping(context.Background()).Err(); err != nil {
		t.Skipf("Redis integration skipped: ping %s failed: %v", addr, err)
	}

	options.Prefix = "ndscale:" + strings.ReplaceAll(t.Name(), "/", "-")
	options.SchemaVersion = 1

	builder, err := NewKeyBuilder(options)
	if err != nil {
		t.Fatalf("NewKeyBuilder returned error: %v", err)
	}

	store, err := NewRedisSessionStore(client, builder, nil, storeOptions...)
	if err != nil {
		t.Fatalf("NewRedisSessionStore returned error: %v", err)
	}

	return store, client, builder
}

// scaleRedisAddress returns the package-scoped Redis-compatible test address.
func scaleRedisAddress() string {
	if addr := os.Getenv("NAUTHILUS_DIRECTOR_REDIS_ADDR"); addr != "" {
		return addr
	}

	if addr := os.Getenv("REDIS_ADDR"); addr != "" {
		return addr
	}

	return packageRedisAddr
}

// readSessionPage reads one session page and fails the current test on error.
func readSessionPage(t *testing.T, store *RedisSessionStore, request RuntimeSessionPageRequest) RuntimeSessionPage {
	t.Helper()

	page, err := store.ListRuntimeSessionsPage(context.Background(), request)
	if err != nil {
		t.Fatalf("ListRuntimeSessionsPage returned error: %v", err)
	}

	return page
}

// seedRuntimeReadRecords writes logical runtime records without opening sockets.
func seedRuntimeReadRecords(
	t *testing.T,
	client *redis.Client,
	builder KeyBuilder,
	count int,
	leaseOffset time.Duration,
) []seededRuntimeRecord {
	t.Helper()

	records := make([]seededRuntimeRecord, 0, count)
	now := time.Now().UTC()
	leaseExpiresAt := now.Add(leaseOffset)
	idleExpiresAt := now.Add(2 * time.Hour)
	pipe := client.Pipeline()

	for index := range count {
		record := seededRuntimeRecordForIndex(t, builder, seedRuntimeRecordLabel(leaseOffset), index, leaseExpiresAt)
		records = append(records, record)
		seedRuntimeReadRecord(t, pipe, builder, record, leaseExpiresAt, idleExpiresAt)

		if (index+1)%1000 == 0 {
			execRedisPipeline(t, pipe, "seed runtime read records")
			pipe = client.Pipeline()
		}
	}

	execRedisPipeline(t, pipe, "seed runtime read records")

	return records
}

// seedRuntimeRecordLabel keeps repeated seed groups distinct inside one test.
func seedRuntimeRecordLabel(leaseOffset time.Duration) string {
	if leaseOffset < 0 {
		return "expired"
	}

	return seededRuntimeLabelActive
}

// seededRuntimeRecordForIndex returns deterministic seed identity and key data.
func seededRuntimeRecordForIndex(
	t *testing.T,
	builder KeyBuilder,
	label string,
	index int,
	leaseExpiresAt time.Time,
) seededRuntimeRecord {
	t.Helper()

	key := AffinityKey{Tenant: seededRuntimeTenant, AccountKey: fmt.Sprintf("%s-user-%05d@example.test", label, index)}
	sessionID := fmt.Sprintf("seeded-%s-session-%05d", label, index)

	sessionKey, err := builder.SessionKey(key.Tenant, key.AccountKey, sessionID)
	if err != nil {
		t.Fatalf("SessionKey returned error: %v", err)
	}

	affinityHash, err := builder.AffinityHash(key.Tenant, key.AccountKey)
	if err != nil {
		t.Fatalf("AffinityHash returned error: %v", err)
	}

	if leaseExpiresAt.IsZero() {
		t.Fatal("seeded lease expiry must be set")
	}

	return seededRuntimeRecord{key: key, sessionID: sessionID, sessionKey: sessionKey, affinityHash: affinityHash}
}

// seedRuntimeReadRecord writes one runtime read fixture into repairable indexes.
func seedRuntimeReadRecord(
	t *testing.T,
	pipe redis.Pipeliner,
	builder KeyBuilder,
	record seededRuntimeRecord,
	leaseExpiresAt time.Time,
	idleExpiresAt time.Time,
) {
	t.Helper()

	keys, sessionIndexKey, dueIndexKey, userSessionIndexKey := runtimeRecordIndexKeys(t, builder, record)

	backendIndexKey, err := builder.BackendSessionIndexShardKey(seededRuntimeBackendID, record.sessionID)
	if err != nil {
		t.Fatalf("BackendSessionIndexShardKey returned error: %v", err)
	}

	pipe.HSet(context.Background(), keys.State, runtimeStateHash(record, idleExpiresAt))
	pipe.ZAdd(context.Background(), keys.Sessions, redis.Z{Score: float64(leaseExpiresAt.UnixMilli()), Member: record.sessionID})
	pipe.HSet(context.Background(), record.sessionKey, runtimeSessionHash(record, keys, sessionIndexKey, dueIndexKey, userSessionIndexKey, backendIndexKey, leaseExpiresAt))
	pipe.HSet(context.Background(), sessionIndexKey, record.sessionID, record.sessionKey)
	pipe.ZAdd(context.Background(), dueIndexKey, redis.Z{Score: float64(leaseExpiresAt.UnixMilli()), Member: record.sessionID})
	pipe.SAdd(context.Background(), userSessionIndexKey, record.sessionID)
	pipe.SAdd(context.Background(), backendIndexKey, record.sessionID)
	pipe.HSet(context.Background(), userIndexShardKey(t, builder, record), record.affinityHash, record.key.Tenant+"\t"+record.key.AccountKey)
}

// runtimeRecordIndexKeys returns the index keys touched by one fixture.
func runtimeRecordIndexKeys(
	t *testing.T,
	builder KeyBuilder,
	record seededRuntimeRecord,
) (AffinityKeys, string, string, string) {
	t.Helper()

	keys, err := builder.AffinityKeys(record.key.Tenant, record.key.AccountKey)
	if err != nil {
		t.Fatalf("AffinityKeys returned error: %v", err)
	}

	sessionIndexKey, err := builder.SessionIndexShardKey(record.sessionID)
	if err != nil {
		t.Fatalf("SessionIndexShardKey returned error: %v", err)
	}

	dueIndexKey, err := builder.SessionDueIndexShardKey(record.sessionID)
	if err != nil {
		t.Fatalf("SessionDueIndexShardKey returned error: %v", err)
	}

	userSessionIndexKey, err := builder.UserSessionIndexShardKey(record.key.Tenant, record.key.AccountKey, record.sessionID)
	if err != nil {
		t.Fatalf("UserSessionIndexShardKey returned error: %v", err)
	}

	return keys, sessionIndexKey, dueIndexKey, userSessionIndexKey
}

// runtimeStateHash returns a minimal active affinity state hash fixture.
func runtimeStateHash(record seededRuntimeRecord, idleExpiresAt time.Time) map[string]any {
	return map[string]any{
		aggregateDimensionShardTag:    testShardA,
		"generation":                  "1",
		scriptFieldControlGeneration:  "0",
		"control_action":              string(ControlActionNone),
		scriptFieldActiveSessionCount: "1",
		scriptFieldExpiresAtMS:        idleExpiresAt.UnixMilli(),
		"idle_grace_ms":               int64(time.Hour / time.Millisecond),
		scriptFieldAffinityHash:       record.affinityHash,
	}
}

// runtimeSessionHash returns a minimal visible session hash fixture.
func runtimeSessionHash(
	record seededRuntimeRecord,
	keys AffinityKeys,
	sessionIndexKey string,
	dueIndexKey string,
	userSessionIndexKey string,
	backendIndexKey string,
	leaseExpiresAt time.Time,
) map[string]any {
	return map[string]any{
		"session_id":                 record.sessionID,
		"tenant":                     record.key.Tenant,
		"account_key":                record.key.AccountKey,
		"affinity_hash":              record.affinityHash,
		scriptFieldHolderKind:        HolderKindSession,
		"protocol":                   testProtocolIMAP,
		"listener_name":              testListenerIMAPS,
		"service_name":               testProtocolIMAP,
		aggregateDimensionShardTag:   testShardA,
		"selected_backend_id":        seededRuntimeBackendID,
		"director_instance_id":       "scale-test-director",
		"backend_counted":            "0",
		scriptFieldControlGeneration: "0",
		scriptFieldStatus:            seededRuntimeLabelActive,
		"opened_at_ms":               leaseExpiresAt.Add(-time.Hour).UnixMilli(),
		scriptFieldLeaseExpiresAtMS:  leaseExpiresAt.UnixMilli(),
		"state_key":                  keys.State,
		"sessions_key":               keys.Sessions,
		"session_index_key":          sessionIndexKey,
		"session_due_index_key":      dueIndexKey,
		"user_sessions_key":          userSessionIndexKey,
		"backend_sessions_key":       backendIndexKey,
		"backend_reservation_id":     "",
	}
}

// userIndexShardKey returns the sharded user index key for one fixture.
func userIndexShardKey(t *testing.T, builder KeyBuilder, record seededRuntimeRecord) string {
	t.Helper()

	key, err := builder.UserIndexShardKey(record.affinityHash)
	if err != nil {
		t.Fatalf("UserIndexShardKey returned error: %v", err)
	}

	return key
}

// cleanupSeededRuntimeRecords removes only exact keys written by scale fixtures.
func cleanupSeededRuntimeRecords(t *testing.T, client *redis.Client, builder KeyBuilder, records []seededRuntimeRecord) {
	t.Helper()

	pipe := client.Pipeline()

	for index, record := range records {
		keys, sessionIndexKey, dueIndexKey, userSessionIndexKey := runtimeRecordIndexKeys(t, builder, record)

		backendIndexKey, err := builder.BackendSessionIndexShardKey(seededRuntimeBackendID, record.sessionID)
		if err != nil {
			t.Fatalf("BackendSessionIndexShardKey returned error: %v", err)
		}

		pipe.Del(context.Background(), keys.State, keys.Sessions, keys.Override, record.sessionKey)
		pipe.HDel(context.Background(), sessionIndexKey, record.sessionID)
		pipe.ZRem(context.Background(), dueIndexKey, record.sessionID)
		pipe.SRem(context.Background(), userSessionIndexKey, record.sessionID)
		pipe.SRem(context.Background(), backendIndexKey, record.sessionID)
		pipe.HDel(context.Background(), userIndexShardKey(t, builder, record), record.affinityHash)

		if (index+1)%1000 == 0 {
			execRedisPipeline(t, pipe, "cleanup seeded runtime records")
			pipe = client.Pipeline()
		}
	}

	execRedisPipeline(t, pipe, "cleanup seeded runtime records")
}

// execRedisPipeline runs a test fixture pipeline when it has queued commands.
func execRedisPipeline(t *testing.T, pipe redis.Pipeliner, operation string) {
	t.Helper()

	if len(pipe.Cmds()) == 0 {
		return
	}

	if _, err := pipe.Exec(context.Background()); err != nil {
		t.Fatalf("%s: %v", operation, err)
	}
}
