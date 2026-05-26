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
	testAttachSessionID  = "attach-session"
	testBackendIMAP      = "mailstore-a-imap"
	testKickSessionID    = "kick-session"
	testKillSessionID    = "kill-session"
	testOperatorClear    = "operator clear"
	testProtocolIMAP     = "imap"
	testRuntimeSessionID = "runtime-session"
	testShardA           = "mailstore-a"
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

	backendKey, err := builder.BackendRuntimeKey(testBackendIMAP)
	if err != nil {
		t.Fatalf("BackendRuntimeKey returned error: %v", err)
	}

	if backendKey != "nd:v1:runtime:backend:"+testBackendIMAP {
		t.Fatalf("backend key = %q", backendKey)
	}

	if got := builder.SessionIndexKey(); got != "nd:v1:idx:sessions" {
		t.Fatalf("session index key = %q", got)
	}

	if got := builder.BackendIndexKey(); got != "nd:v1:idx:backends" {
		t.Fatalf("backend index key = %q", got)
	}

	backendSessions, err := builder.BackendSessionIndexKey(testBackendIMAP)
	if err != nil {
		t.Fatalf("BackendSessionIndexKey returned error: %v", err)
	}

	if backendSessions != "nd:v1:idx:backend:"+testBackendIMAP+":sessions" {
		t.Fatalf("backend session index key = %q", backendSessions)
	}

	if got := builder.UserIndexKey(); got != "nd:v1:idx:users" {
		t.Fatalf("user index key = %q", got)
	}

	userSessions, err := builder.UserSessionIndexKey("default", "user@example.org")
	if err != nil {
		t.Fatalf("UserSessionIndexKey returned error: %v", err)
	}

	if strings.Contains(userSessions, "user@example.org") || !strings.HasPrefix(userSessions, "nd:v1:idx:user:") {
		t.Fatalf("user session index key = %q", userSessions)
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

	for _, name := range []string{
		scriptAttach,
		scriptBackendRuntimeClear,
		scriptBackendRuntimeSet,
		scriptClear,
		scriptClose,
		scriptHeartbeat,
		scriptKick,
		scriptLookup,
		scriptMove,
		scriptOpen,
		scriptReap,
		scriptSessionKill,
	} {
		if _, ok := registry.Get(name); !ok {
			t.Fatalf("%s script missing; scripts=%v", name, registry.Names())
		}
	}
}

// TestAmbiguousScriptPayloadFailsClosed verifies parser-level control-action validation.
func TestAmbiguousScriptPayloadFailsClosed(t *testing.T) {
	_, err := parseAffinityRecord(AffinityKey{Tenant: "default", AccountKey: "hash"}, []any{
		"status", scriptHeartbeat,
		"present", "1",
		"shard_tag", testShardA,
		"generation", "1",
		"control_generation", "1",
		"control_action", "unknown",
		"active_session_count", "1",
		"server_time_ms", "1000",
		"expires_at_ms", "2000",
		"lease_expires_at_ms", "1500",
	})
	if !IsRedisErrorKind(err, RedisErrorKindAmbiguousState) {
		t.Fatalf("parseAffinityRecord error = %v, want ambiguous_state", err)
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

// TestRedisBackendAttachAndCloseCountsExactlyOnce verifies selected-backend registration.
func TestRedisBackendAttachAndCloseCountsExactlyOnce(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	key := AffinityKey{Tenant: "blue", AccountKey: "attach@example.test"}
	backendID := testBackendIMAP
	sessionID := testAttachSessionID

	cleanupAffinity(t, client, builder, key, sessionID)
	cleanupBackend(t, client, builder, backendID)

	record := testSessionRecord(key, sessionID)
	if _, err := store.OpenSession(context.Background(), record); err != nil {
		t.Fatalf("OpenSession returned error: %v", err)
	}

	firstAttach, err := store.AttachSelectedBackend(context.Background(), SessionBackendAttachment{
		Key:               key,
		SessionID:         sessionID,
		BackendIdentifier: backendID,
		MaxConnections:    10,
	})
	if err != nil {
		t.Fatalf("AttachSelectedBackend returned error: %v", err)
	}

	if firstAttach.BackendActiveCount != 1 {
		t.Fatalf("backend active count after attach = %d, want 1", firstAttach.BackendActiveCount)
	}

	secondAttach, err := store.AttachSelectedBackend(context.Background(), SessionBackendAttachment{
		Key:               key,
		SessionID:         sessionID,
		BackendIdentifier: backendID,
		MaxConnections:    10,
	})
	if err != nil {
		t.Fatalf("second AttachSelectedBackend returned error: %v", err)
	}

	if secondAttach.BackendActiveCount != 1 {
		t.Fatalf("backend active count after idempotent attach = %d, want 1", secondAttach.BackendActiveCount)
	}

	if count := redisBackendActiveCount(t, client, builder, backendID); count != 1 {
		t.Fatalf("redis backend active count = %d, want 1", count)
	}

	if _, err := store.CloseSession(context.Background(), key, sessionID); err != nil {
		t.Fatalf("CloseSession returned error: %v", err)
	}

	if count := redisBackendActiveCount(t, client, builder, backendID); count != 0 {
		t.Fatalf("redis backend active count after close = %d, want 0", count)
	}
}

// TestRedisKickAndSessionKillAreObservedByHeartbeat verifies control generations.
func TestRedisKickAndSessionKillAreObservedByHeartbeat(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	key := AffinityKey{Tenant: "blue", AccountKey: "kick@example.test"}
	backendID := testBackendIMAP

	cleanupAffinity(t, client, builder, key, testKickSessionID, testKillSessionID)
	cleanupBackend(t, client, builder, backendID)

	for _, sessionID := range []string{testKickSessionID, testKillSessionID} {
		if _, err := store.OpenSession(context.Background(), testSessionRecord(key, sessionID)); err != nil {
			t.Fatalf("OpenSession %s returned error: %v", sessionID, err)
		}

		if _, err := store.AttachSelectedBackend(context.Background(), SessionBackendAttachment{
			Key:               key,
			SessionID:         sessionID,
			BackendIdentifier: backendID,
			MaxConnections:    10,
		}); err != nil {
			t.Fatalf("AttachSelectedBackend %s returned error: %v", sessionID, err)
		}
	}

	kicked, err := store.KickUser(context.Background(), UserKickRequest{Key: key, Reason: "operator requested reconnect"})
	if err != nil {
		t.Fatalf("KickUser returned error: %v", err)
	}

	if kicked.ControlAction != ControlActionKick {
		t.Fatalf("kick action = %q, want kick", kicked.ControlAction)
	}

	heartbeat, err := store.HeartbeatSession(context.Background(), key, testKickSessionID, time.Second)
	if err != nil {
		t.Fatalf("HeartbeatSession after kick returned error: %v", err)
	}

	if heartbeat.ControlAction != ControlActionKick {
		t.Fatalf("heartbeat control action = %q, want kick", heartbeat.ControlAction)
	}

	if _, err := store.KillSession(context.Background(), SessionKillRequest{
		SessionID: testKillSessionID,
		Reason:    "operator killed one session",
	}); err != nil {
		t.Fatalf("KillSession returned error: %v", err)
	}

	killHeartbeat, err := store.HeartbeatSession(context.Background(), key, testKillSessionID, time.Second)
	if err != nil {
		t.Fatalf("HeartbeatSession after session kill returned error: %v", err)
	}

	if killHeartbeat.ControlAction != ControlActionKick {
		t.Fatalf("heartbeat control action for session kill = %q, want kick", killHeartbeat.ControlAction)
	}
}

// TestRedisReapRepairsExpiredSessions verifies expired session repair updates backend counts.
func TestRedisReapRepairsExpiredSessions(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	key := AffinityKey{Tenant: "blue", AccountKey: "reap@example.test"}
	backendID := testBackendIMAP
	sessionID := "reap-session"

	cleanupAffinity(t, client, builder, key, sessionID)
	cleanupBackend(t, client, builder, backendID)

	record := testSessionRecord(key, sessionID)
	record.LeaseTTL = 25 * time.Millisecond
	record.IdleGrace = time.Second

	if _, err := store.OpenSession(context.Background(), record); err != nil {
		t.Fatalf("OpenSession returned error: %v", err)
	}

	if _, err := store.AttachSelectedBackend(context.Background(), SessionBackendAttachment{
		Key:               key,
		SessionID:         sessionID,
		BackendIdentifier: backendID,
		MaxConnections:    10,
	}); err != nil {
		t.Fatalf("AttachSelectedBackend returned error: %v", err)
	}

	time.Sleep(60 * time.Millisecond)

	reaped, err := store.ReapSessions(context.Background(), ReapRequest{Limit: 100})
	if err != nil {
		t.Fatalf("ReapSessions returned error: %v", err)
	}

	if reaped.ExpiredSessions != 1 || reaped.RepairedBackends != 1 {
		t.Fatalf("reap result = %#v, want one expired and one backend repair", reaped)
	}

	if count := redisBackendActiveCount(t, client, builder, backendID); count != 0 {
		t.Fatalf("redis backend active count after reap = %d, want 0", count)
	}
}

// TestRedisMoveAndClearScripts verifies user move and inactive affinity clear behavior.
func TestRedisMoveAndClearScripts(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	key := AffinityKey{Tenant: "blue", AccountKey: "runtime-move@example.test"}
	backendID := testBackendIMAP

	cleanupAffinity(t, client, builder, key, testRuntimeSessionID)
	cleanupBackend(t, client, builder, backendID)

	openAttachedSession(t, store, key, testRuntimeSessionID, backendID)

	moved, err := store.MoveUser(context.Background(), UserMoveRequest{
		Key:         key,
		TargetShard: "mailstore-b",
		Strategy:    moveStrategyKickExisting,
		Reason:      "operator move",
	})
	if err != nil {
		t.Fatalf("MoveUser returned error: %v", err)
	}

	if moved.ControlAction != ControlActionMoveGenerationChanged || moved.TargetShard != "mailstore-b" {
		t.Fatalf("move result = %#v", moved)
	}

	_, err = store.ClearUserAffinity(context.Background(), UserClearRequest{Key: key, Reason: testOperatorClear})
	if !IsRedisErrorKind(err, RedisErrorKindAmbiguousState) {
		t.Fatalf("ClearUserAffinity active error = %v, want ambiguous_state", err)
	}

	if _, err := store.CloseSession(context.Background(), key, testRuntimeSessionID); err != nil {
		t.Fatalf("CloseSession returned error: %v", err)
	}

	cleared, err := store.ClearUserAffinity(context.Background(), UserClearRequest{Key: key, Reason: testOperatorClear})
	if err != nil {
		t.Fatalf("ClearUserAffinity inactive returned error: %v", err)
	}

	if cleared.Status != "cleared" {
		t.Fatalf("clear result = %#v", cleared)
	}
}

// TestRedisBackendRuntimeScripts verifies backend runtime drain and clear behavior.
func TestRedisBackendRuntimeScripts(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	key := AffinityKey{Tenant: "blue", AccountKey: "runtime-backend@example.test"}
	backendID := testBackendIMAP

	cleanupAffinity(t, client, builder, key, testRuntimeSessionID)
	cleanupBackend(t, client, builder, backendID)

	openAttachedSession(t, store, key, testRuntimeSessionID, backendID)

	runtimeSet, err := store.SetBackendRuntime(context.Background(), BackendRuntimeMutation{
		BackendIdentifier: backendID,
		DrainEnabled:      true,
		DrainMode:         "hard",
		Reason:            "host drain",
	})
	if err != nil {
		t.Fatalf("SetBackendRuntime returned error: %v", err)
	}

	if runtimeSet.MarkedSessionCount != 1 {
		t.Fatalf("marked sessions = %d, want 1", runtimeSet.MarkedSessionCount)
	}

	drainHeartbeat, err := store.HeartbeatSession(context.Background(), key, testRuntimeSessionID, time.Second)
	if err != nil {
		t.Fatalf("HeartbeatSession after backend drain returned error: %v", err)
	}

	if drainHeartbeat.ControlAction != ControlActionDrain {
		t.Fatalf("heartbeat control action after backend drain = %q, want drain", drainHeartbeat.ControlAction)
	}

	runtimeClear, err := store.ClearBackendRuntime(context.Background(), BackendRuntimeClearRequest{
		BackendIdentifier: backendID,
		Reason:            "host drain finished",
	})
	if err != nil {
		t.Fatalf("ClearBackendRuntime returned error: %v", err)
	}

	if runtimeClear.ActiveSessionCount != 1 {
		t.Fatalf("active count after runtime clear = %d, want preserved count 1", runtimeClear.ActiveSessionCount)
	}

	if _, err := store.CloseSession(context.Background(), key, testRuntimeSessionID); err != nil {
		t.Fatalf("CloseSession returned error: %v", err)
	}
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

	userSessionIndex, err := builder.UserSessionIndexKey(key.Tenant, key.AccountKey)
	if err != nil {
		t.Fatalf("UserSessionIndexKey returned error: %v", err)
	}

	redisKeys = append(redisKeys, userSessionIndex)

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

	if len(sessionIDs) > 0 {
		if err := client.HDel(context.Background(), builder.SessionIndexKey(), sessionIDs...).Err(); err != nil {
			t.Fatalf("cleanup session index: %v", err)
		}
	}
}

// cleanupBackend deletes one backend runtime state and membership index.
func cleanupBackend(t *testing.T, client *redis.Client, builder KeyBuilder, backendID string) {
	t.Helper()

	backendKey, err := builder.BackendRuntimeKey(backendID)
	if err != nil {
		t.Fatalf("BackendRuntimeKey returned error: %v", err)
	}

	backendSessionsKey, err := builder.BackendSessionIndexKey(backendID)
	if err != nil {
		t.Fatalf("BackendSessionIndexKey returned error: %v", err)
	}

	if err := client.Del(context.Background(), backendKey, backendSessionsKey).Err(); err != nil {
		t.Fatalf("cleanup backend keys: %v", err)
	}

	if err := client.SRem(context.Background(), builder.BackendIndexKey(), backendID).Err(); err != nil {
		t.Fatalf("cleanup backend index: %v", err)
	}
}

// redisBackendActiveCount reads the Redis-coordinated active session count.
func redisBackendActiveCount(t *testing.T, client *redis.Client, builder KeyBuilder, backendID string) int {
	t.Helper()

	backendKey, err := builder.BackendRuntimeKey(backendID)
	if err != nil {
		t.Fatalf("BackendRuntimeKey returned error: %v", err)
	}

	count, err := client.HGet(context.Background(), backendKey, "active_session_count").Int()
	if err != nil && !errors.Is(err, redis.Nil) {
		t.Fatalf("read backend active count: %v", err)
	}

	return count
}

// openAttachedSession opens a lease and registers its selected backend.
func openAttachedSession(
	t *testing.T,
	store *RedisSessionStore,
	key AffinityKey,
	sessionID string,
	backendID string,
) {
	t.Helper()

	if _, err := store.OpenSession(context.Background(), testSessionRecord(key, sessionID)); err != nil {
		t.Fatalf("OpenSession returned error: %v", err)
	}

	if _, err := store.AttachSelectedBackend(context.Background(), SessionBackendAttachment{
		Key:               key,
		SessionID:         sessionID,
		BackendIdentifier: backendID,
		MaxConnections:    10,
	}); err != nil {
		t.Fatalf("AttachSelectedBackend returned error: %v", err)
	}
}

// testSessionRecord returns a complete session record fixture.
func testSessionRecord(key AffinityKey, sessionID string) SessionRecord {
	return SessionRecord{
		ID:                 sessionID,
		Key:                key,
		Protocol:           testProtocolIMAP,
		ListenerName:       "imaps",
		ServiceName:        "imap",
		ShardTag:           testShardA,
		DirectorInstanceID: "director-test",
		LeaseTTL:           2 * time.Second,
		IdleGrace:          time.Second,
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
