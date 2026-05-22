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
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	testProtocolIMAP = "imap"
	testShardA       = "mailstore-a"
)

// TestKeyBuilderCreatesClusterHashTaggedAffinityKeys verifies Cluster-safe affinity key shape.
func TestKeyBuilderCreatesClusterHashTaggedAffinityKeys(t *testing.T) {
	builder := mustKeyBuilder(t)

	keys, err := builder.AffinityKeys("default", "user@example.org")
	if err != nil {
		t.Fatalf("AffinityKeys returned error: %v", err)
	}

	for name, key := range map[string]string{
		"state":    keys.State,
		"sessions": keys.Sessions,
		"override": keys.Override,
	} {
		if !strings.Contains(key, keys.HashTag) {
			t.Fatalf("%s key %q does not contain hash tag %q", name, key, keys.HashTag)
		}

		if !strings.HasPrefix(key, "nd:v1:{aff:") {
			t.Fatalf("%s key %q has wrong prefix", name, key)
		}
	}

	sessionKey, err := builder.SessionKey("default", "user@example.org", "session-1")
	if err != nil {
		t.Fatalf("SessionKey returned error: %v", err)
	}

	if !strings.Contains(sessionKey, keys.HashTag) || !strings.HasSuffix(sessionKey, ":session:session-1") {
		t.Fatalf("session key = %q, hash tag = %q", sessionKey, keys.HashTag)
	}
}

// TestKeyBuilderDoesNotRequireRawUsernameInKeys protects Redis key privacy.
func TestKeyBuilderDoesNotRequireRawUsernameInKeys(t *testing.T) {
	rawAccount := "User.Name+Secret@example.org"
	builder := mustKeyBuilder(t)

	keys, err := builder.AffinityKeys("default", rawAccount)
	if err != nil {
		t.Fatalf("AffinityKeys returned error: %v", err)
	}

	for _, key := range []string{keys.State, keys.Sessions, keys.Override} {
		if strings.Contains(key, rawAccount) || strings.Contains(key, strings.ToLower(rawAccount)) {
			t.Fatalf("key %q leaked raw account %q", key, rawAccount)
		}
	}

	sessionKey, err := builder.SessionKey("default", rawAccount, "session-1")
	if err != nil {
		t.Fatalf("SessionKey returned error: %v", err)
	}

	if strings.Contains(sessionKey, rawAccount) || strings.Contains(sessionKey, strings.ToLower(rawAccount)) {
		t.Fatalf("session key %q leaked raw account %q", sessionKey, rawAccount)
	}
}

// TestBackendAndIndexKeysFollowRuntimeShape checks non-affinity runtime keys.
func TestBackendAndIndexKeysFollowRuntimeShape(t *testing.T) {
	builder := mustKeyBuilder(t)

	backendKey, err := builder.BackendRuntimeKey("mailstore-a-imap")
	if err != nil {
		t.Fatalf("BackendRuntimeKey returned error: %v", err)
	}

	if backendKey != "nd:v1:runtime:backend:mailstore-a-imap" {
		t.Fatalf("backend key = %q", backendKey)
	}

	if got := builder.SessionIndexKey(); got != "nd:v1:idx:sessions" {
		t.Fatalf("session index key = %q", got)
	}

	if got := builder.BackendIndexKey(); got != "nd:v1:idx:backends" {
		t.Fatalf("backend index key = %q", got)
	}
}

// TestScriptLoaderTracksSHAAndMissingScripts verifies script loading conventions.
func TestScriptLoaderTracksSHAAndMissingScripts(t *testing.T) {
	registry, err := LoadEmbeddedScripts()
	if err != nil {
		t.Fatalf("LoadEmbeddedScripts returned error: %v", err)
	}

	script, ok := registry.Get("server_time")
	if !ok {
		t.Fatalf("server_time script missing; scripts=%v", registry.Names())
	}

	if len(script.SHA) != 40 {
		t.Fatalf("script SHA length = %d, want 40", len(script.SHA))
	}

	err = missingScriptError("server_time")

	if !IsRedisErrorKind(err, RedisErrorKindScriptMissing) {
		t.Fatalf("missing script error = %v, want script_missing", err)
	}

	if !ShouldFallbackToEval(err) {
		t.Fatal("missing script should permit controlled EVAL fallback")
	}

	if !IsFailClosedRedisError(err) {
		t.Fatal("missing script must remain fail-closed")
	}

	for _, name := range []string{"open", "heartbeat", "close", "lookup"} {
		if _, ok := registry.Get(name); !ok {
			t.Fatalf("%s script missing; scripts=%v", name, registry.Names())
		}
	}
}

// TestRedisAmbiguousStateErrorsFailClosed checks missing required state handling.
func TestRedisAmbiguousStateErrorsFailClosed(t *testing.T) {
	err := ClassifyRedisError("lookup_affinity", redis.Nil)
	if !IsRedisErrorKind(err, RedisErrorKindAmbiguousState) {
		t.Fatalf("classified error = %v, want ambiguous_state", err)
	}

	if !IsFailClosedRedisError(err) {
		t.Fatal("ambiguous Redis state must fail closed")
	}

	if classified := ClassifyRedisError("lookup_affinity", nil); classified != nil {
		t.Fatalf("nil error classified as %v", classified)
	}

	if IsFailClosedRedisError(errors.New("plain")) {
		t.Fatal("plain errors should not be treated as classified state errors")
	}
}

// TestRedisSessionLifecycleScripts verifies affinity scripts against a Redis-compatible service.
func TestRedisSessionLifecycleScripts(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	key := AffinityKey{Tenant: "blue", AccountKey: "User.Name+Secret@example.test"}
	cleanupAffinity(t, client, builder, key, "session-1", "session-2")

	first := SessionRecord{
		ID:        "session-1",
		Key:       key,
		Protocol:  testProtocolIMAP,
		ShardTag:  testShardA,
		LeaseTTL:  2 * time.Second,
		IdleGrace: time.Second,
	}

	opened, err := store.OpenSession(context.Background(), first)
	if err != nil {
		t.Fatalf("OpenSession returned error: %v", err)
	}

	assertAffinityRecord(t, opened, "created", testShardA, 1)
	assertLookupAndHeartbeat(t, store, key, opened)

	second := first
	second.ID = "session-2"
	second.ShardTag = "mailstore-b"

	reused, err := store.OpenSession(context.Background(), second)
	if err != nil {
		t.Fatalf("second OpenSession returned error: %v", err)
	}

	assertAffinityRecord(t, reused, "reused", testShardA, 2)

	closedFirst, err := store.CloseSession(context.Background(), key, "session-1")
	if err != nil {
		t.Fatalf("first CloseSession returned error: %v", err)
	}

	assertAffinityRecord(t, closedFirst, "closed", testShardA, 1)

	closedSecond, err := store.CloseSession(context.Background(), key, "session-2")
	if err != nil {
		t.Fatalf("second CloseSession returned error: %v", err)
	}

	assertAffinityRecord(t, closedSecond, "idle", testShardA, 0)
}

// TestRedisCloseReleasesAffinityWithoutGrace verifies configured immediate release behavior.
func TestRedisCloseReleasesAffinityWithoutGrace(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	key := AffinityKey{Tenant: "green", AccountKey: "release@example.test"}
	cleanupAffinity(t, client, builder, key, "release-session")

	_, err := store.OpenSession(context.Background(), SessionRecord{
		ID:        "release-session",
		Key:       key,
		Protocol:  testProtocolIMAP,
		ShardTag:  testShardA,
		LeaseTTL:  time.Second,
		IdleGrace: 0,
	})
	if err != nil {
		t.Fatalf("OpenSession returned error: %v", err)
	}

	closed, err := store.CloseSession(context.Background(), key, "release-session")
	if err != nil {
		t.Fatalf("CloseSession returned error: %v", err)
	}

	assertAffinityRecord(t, closed, "released", testShardA, 0)

	lookup, err := store.LookupAffinity(context.Background(), key)
	if err != nil {
		t.Fatalf("LookupAffinity returned error: %v", err)
	}

	if lookup.Present || lookup.Status != "missing" {
		t.Fatalf("lookup after release = %#v, want missing", lookup)
	}
}

// TestRedisAmbiguousSessionStateFailsClosed verifies script-level ambiguity classification.
func TestRedisAmbiguousSessionStateFailsClosed(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	key := AffinityKey{Tenant: "red", AccountKey: "ambiguous@example.test"}
	cleanupAffinity(t, client, builder, key, "missing-session")

	_, err := store.HeartbeatSession(context.Background(), key, "missing-session", time.Second)
	if !IsRedisErrorKind(err, RedisErrorKindAmbiguousState) {
		t.Fatalf("HeartbeatSession error = %v, want ambiguous_state", err)
	}

	if !IsFailClosedRedisError(err) {
		t.Fatal("ambiguous heartbeat must fail closed")
	}
}

// mustKeyBuilder creates the standard Redis key builder fixture.
func mustKeyBuilder(t *testing.T) KeyBuilder {
	t.Helper()

	builder, err := NewKeyBuilder(KeyBuilderOptions{Prefix: "nd:", SchemaVersion: 1})
	if err != nil {
		t.Fatalf("NewKeyBuilder returned error: %v", err)
	}

	return builder
}

// assertLookupAndHeartbeat verifies read-only lookup and lease extension behavior.
func assertLookupAndHeartbeat(t *testing.T, store *RedisSessionStore, key AffinityKey, opened AffinityRecord) {
	t.Helper()

	lookedUp, err := store.LookupAffinity(context.Background(), key)
	if err != nil {
		t.Fatalf("LookupAffinity returned error: %v", err)
	}

	assertAffinityRecord(t, lookedUp, "found", testShardA, 1)

	if lookedUp.Generation != opened.Generation {
		t.Fatalf("lookup generation = %q, want unchanged %q", lookedUp.Generation, opened.Generation)
	}

	heartbeat, err := store.HeartbeatSession(context.Background(), key, "session-1", 3*time.Second)
	if err != nil {
		t.Fatalf("HeartbeatSession returned error: %v", err)
	}

	assertGenerationAdvanced(t, opened.Generation, heartbeat.Generation)

	if !heartbeat.LeaseExpiresAt.After(opened.LeaseExpiresAt) {
		t.Fatalf("heartbeat lease = %s, want after %s", heartbeat.LeaseExpiresAt, opened.LeaseExpiresAt)
	}
}

// redisIntegrationStore creates a store backed by an optional Redis-compatible test service.
func redisIntegrationStore(t *testing.T) (*RedisSessionStore, *redis.Client, KeyBuilder) {
	t.Helper()

	addr := os.Getenv("NAUTHILUS_DIRECTOR_REDIS_ADDR")
	if addr == "" {
		addr = os.Getenv("REDIS_ADDR")
	}

	if addr == "" {
		t.Skip("Redis integration skipped: set NAUTHILUS_DIRECTOR_REDIS_ADDR or REDIS_ADDR")
	}

	client := redis.NewClient(&redis.Options{Addr: addr, Protocol: 2})

	t.Cleanup(func() { _ = client.Close() })

	if err := client.Ping(context.Background()).Err(); err != nil {
		t.Skipf("Redis integration skipped: ping %s failed: %v", addr, err)
	}

	builder, err := NewKeyBuilder(KeyBuilderOptions{Prefix: "ndtest:" + strings.ReplaceAll(t.Name(), "/", "-"), SchemaVersion: 1})
	if err != nil {
		t.Fatalf("NewKeyBuilder returned error: %v", err)
	}

	store, err := NewRedisSessionStore(client, builder, nil)
	if err != nil {
		t.Fatalf("NewRedisSessionStore returned error: %v", err)
	}

	return store, client, builder
}

// cleanupAffinity deletes the known test keys for one affinity group.
func cleanupAffinity(t *testing.T, client *redis.Client, builder KeyBuilder, key AffinityKey, sessionIDs ...string) {
	t.Helper()

	keys, err := builder.AffinityKeys(key.Tenant, key.AccountKey)
	if err != nil {
		t.Fatalf("AffinityKeys returned error: %v", err)
	}

	redisKeys := []string{keys.State, keys.Sessions, keys.Override}

	for _, sessionID := range sessionIDs {
		sessionKey, err := builder.SessionKey(key.Tenant, key.AccountKey, sessionID)
		if err != nil {
			t.Fatalf("SessionKey returned error: %v", err)
		}

		redisKeys = append(redisKeys, sessionKey)
	}

	if err := client.Del(context.Background(), redisKeys...).Err(); err != nil {
		t.Fatalf("cleanup redis keys: %v", err)
	}
}

// assertAffinityRecord verifies the stable fields returned by affinity scripts.
func assertAffinityRecord(t *testing.T, record AffinityRecord, status string, shard string, activeCount int) {
	t.Helper()

	if !record.Present {
		t.Fatalf("record not present: %#v", record)
	}

	if record.Status != status {
		t.Fatalf("record status = %q, want %q", record.Status, status)
	}

	if record.ShardTag != shard {
		t.Fatalf("record shard = %q, want %q", record.ShardTag, shard)
	}

	if record.ActiveSessionCount != activeCount {
		t.Fatalf("active count = %d, want %d", record.ActiveSessionCount, activeCount)
	}

	if record.ServerTime.IsZero() || record.ExpiresAt.IsZero() {
		t.Fatalf("record times missing: %#v", record)
	}
}

// assertGenerationAdvanced checks that a mutation advanced the Redis generation counter.
func assertGenerationAdvanced(t *testing.T, before string, after string) {
	t.Helper()

	beforeInt, err := strconv.Atoi(before)
	if err != nil {
		t.Fatalf("before generation %q invalid: %v", before, err)
	}

	afterInt, err := strconv.Atoi(after)
	if err != nil {
		t.Fatalf("after generation %q invalid: %v", after, err)
	}

	if afterInt <= beforeInt {
		t.Fatalf("generation did not advance: before=%d after=%d", beforeInt, afterInt)
	}
}
