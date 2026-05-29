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
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/redis/go-redis/v9"
)

const (
	testAttachSessionID  = "attach-session"
	testBackendIMAP      = "mailstore-a-imap"
	testBackendLMTP      = "mailstore-a-lmtp"
	testKickSessionID    = "kick-session"
	testKillSessionID    = "kill-session"
	testOperatorClear    = "operator clear"
	testOperatorActor    = "test-operator"
	testProtocolIMAP     = "imap"
	testProtocolLMTP     = "lmtp"
	testProtocolPOP3     = "pop3"
	testRedisModeCluster = "cluster"
	testExpiredReserve   = "expired-reservation"
	testReservationOne   = "reservation-1"
	testReservationTwo   = "reservation-2"
	testReservationThree = "reservation-3"
	testRuntimeSessionID = "runtime-session"
	testSessionOne       = "session-1"
	testSessionTwo       = "session-2"
	testTenantDefault    = "default"
	testClearStatus      = "cleared"
	testListenerIMAPS    = "imaps"
	testShardA           = "mailstore-a"
	testShardB           = "mailstore-b"
	testShardC           = "mailstore-c"
	testStatusCreated    = "created"
	testUserExample      = "user@example.org"
)

var packageRedisAddr string

// TestMain starts a package-scoped Redis-compatible service when available.
func TestMain(m *testing.M) {
	code := runStateTests(m)
	os.Exit(code)
}

// runStateTests keeps package test setup outside the special TestMain entrypoint.
func runStateTests(m *testing.M) int {
	addr := os.Getenv("NAUTHILUS_DIRECTOR_REDIS_ADDR")
	if addr == "" {
		addr = os.Getenv("REDIS_ADDR")
	}

	if addr == "" {
		addr = packageRedisAddr
	}

	if addr != "" {
		packageRedisAddr = addr

		return m.Run()
	}

	startedAddr, cleanup, err := startPackageValkey()
	if err != nil {
		return m.Run()
	}

	packageRedisAddr = startedAddr

	defer cleanup()

	return m.Run()
}

// startPackageValkey starts a local Valkey server for Redis script integration tests.
func startPackageValkey() (string, func(), error) {
	path, err := exec.LookPath("valkey-server")
	if err != nil {
		return "", func() {}, err
	}

	addr, port, err := reservePackageRedisAddress()
	if err != nil {
		return "", func() {}, err
	}

	var output bytes.Buffer

	cmd := exec.Command(
		path,
		"--bind", "127.0.0.1",
		"--port", port,
		"--save", "",
		"--appendonly", "no",
		"--dir", os.TempDir(),
		"--loglevel", "warning",
	)
	cmd.Stdout = &output
	cmd.Stderr = &output

	if err := cmd.Start(); err != nil {
		return "", func() {}, err
	}

	client := redis.NewClient(&redis.Options{Addr: addr, Protocol: 2})
	cleanup := func() {
		_ = client.Close()

		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}

		_ = cmd.Wait()
	}

	if waitForPackageValkey(client) {
		return addr, cleanup, nil
	}

	cleanup()

	return "", func() {}, errors.New(output.String())
}

// reservePackageRedisAddress reserves a loopback port long enough to configure Valkey.
func reservePackageRedisAddress() (string, string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", "", err
	}

	addr := listener.Addr().String()
	_ = listener.Close()

	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", "", err
	}

	return addr, port, nil
}

// waitForPackageValkey waits until the package-scoped Redis-compatible server accepts commands.
func waitForPackageValkey(client *redis.Client) bool {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		err := client.Ping(ctx).Err()

		cancel()

		if err == nil {
			return true
		}

		time.Sleep(25 * time.Millisecond)
	}

	return false
}

// TestKeyBuilderCreatesClusterHashTaggedAffinityKeys verifies Cluster-safe affinity key shape.
func TestKeyBuilderCreatesClusterHashTaggedAffinityKeys(t *testing.T) {
	builder := mustKeyBuilder(t)

	keys, err := builder.AffinityKeys(testTenantDefault, testUserExample)
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

	sessionKey, err := builder.SessionKey(testTenantDefault, testUserExample, testSessionOne)
	if err != nil {
		t.Fatalf("SessionKey returned error: %v", err)
	}

	if !strings.Contains(sessionKey, keys.HashTag) || !strings.HasSuffix(sessionKey, ":session:"+testSessionOne) {
		t.Fatalf("session key = %q, hash tag = %q", sessionKey, keys.HashTag)
	}

	firstTag := redisHashTag(t, keys.State)
	for name, key := range map[string]string{
		"state":    keys.State,
		"sessions": keys.Sessions,
		"override": keys.Override,
		"session":  sessionKey,
	} {
		if got := redisHashTag(t, key); got != firstTag {
			t.Fatalf("%s key hash tag = %q, want %q", name, got, firstTag)
		}
	}
}

// TestPerAffinityScriptWrappersUseAffinityOwnedKeys protects Cluster-safe Lua dispatch.
func TestPerAffinityScriptWrappersUseAffinityOwnedKeys(t *testing.T) {
	builder := mustKeyBuilder(t)
	store := &RedisSessionStore{keys: builder}
	key := AffinityKey{Tenant: testTenantDefault, AccountKey: testUserExample}

	affinityKeys, err := builder.AffinityKeys(key.Tenant, key.AccountKey)
	if err != nil {
		t.Fatalf("AffinityKeys returned error: %v", err)
	}

	_, _, openKeys, err := store.openSessionScriptKeys(key, testSessionOne)
	if err != nil {
		t.Fatalf("openSessionScriptKeys returned error: %v", err)
	}

	_, _, heartbeatKeys, err := store.heartbeatSessionScriptKeys(key, testSessionOne)
	if err != nil {
		t.Fatalf("heartbeatSessionScriptKeys returned error: %v", err)
	}

	_, _, closeKeys, err := store.closeSessionScriptKeys(key, testSessionOne)
	if err != nil {
		t.Fatalf("closeSessionScriptKeys returned error: %v", err)
	}

	_, _, attachKeys, err := store.attachSelectedBackendScriptKeys(key, testSessionOne)
	if err != nil {
		t.Fatalf("attachSelectedBackendScriptKeys returned error: %v", err)
	}

	for _, item := range []struct {
		operation string
		keys      []string
	}{
		{operation: scriptOpen, keys: openKeys},
		{operation: scriptAttach, keys: attachKeys},
		{operation: scriptHeartbeat, keys: heartbeatKeys},
		{operation: scriptClose, keys: closeKeys},
		{operation: scriptLookup, keys: store.lookupAffinityScriptKeys(affinityKeys)},
		{operation: scriptMove, keys: store.moveUserScriptKeys(affinityKeys)},
		{operation: scriptKick, keys: store.kickUserScriptKeys(affinityKeys)},
		{operation: scriptClear, keys: store.clearUserAffinityScriptKeys(affinityKeys)},
	} {
		assertAffinityOwnedScriptKeys(t, store, item.operation, item.keys)
	}
}

// TestPerAffinityScriptValidationRejectsForeignKeys verifies local Cluster-mode guardrails.
func TestPerAffinityScriptValidationRejectsForeignKeys(t *testing.T) {
	builder := mustKeyBuilder(t)
	store := &RedisSessionStore{keys: builder}
	key := AffinityKey{Tenant: testTenantDefault, AccountKey: testUserExample}

	keys, err := builder.AffinityKeys(key.Tenant, key.AccountKey)
	if err != nil {
		t.Fatalf("AffinityKeys returned error: %v", err)
	}

	backendKey, err := builder.BackendRuntimeKey(testBackendIMAP)
	if err != nil {
		t.Fatalf("BackendRuntimeKey returned error: %v", err)
	}

	for _, foreignKey := range []string{builder.SessionIndexKey(), backendKey} {
		err := store.validateScriptKeys(scriptOpen, []string{keys.State, keys.Sessions, foreignKey})
		if !IsRedisErrorKind(err, RedisErrorKindConfig) {
			t.Fatalf("validateScriptKeys(%q) error = %v, want config", foreignKey, err)
		}
	}
}

// TestBackendReservationScriptWrappersUseBackendOwnedKeys protects backend-slot Lua dispatch.
func TestBackendReservationScriptWrappersUseBackendOwnedKeys(t *testing.T) {
	builder := mustKeyBuilder(t)
	store := &RedisSessionStore{keys: builder}

	keys, err := builder.BackendReservationKeys(testBackendIMAP)
	if err != nil {
		t.Fatalf("BackendReservationKeys returned error: %v", err)
	}

	for _, operation := range []string{scriptBackendReserve, scriptBackendRelease, scriptBackendReap} {
		if err := store.validateScriptKeys(operation, []string{keys.State, keys.Due}); err != nil {
			t.Fatalf("validateScriptKeys(%s) returned error: %v", operation, err)
		}
	}

	other, err := builder.BackendReservationKeys(testBackendLMTP)
	if err != nil {
		t.Fatalf("BackendReservationKeys other returned error: %v", err)
	}

	if err := store.validateScriptKeys(scriptBackendReserve, []string{keys.State, other.Due}); !IsRedisErrorKind(err, RedisErrorKindConfig) {
		t.Fatalf("mixed backend reservation keys error = %v, want config", err)
	}
}

// TestAffinityMutationDeltaRequiresRepairFields verifies authoritative script delta parsing.
func TestAffinityMutationDeltaRequiresRepairFields(t *testing.T) {
	key := AffinityKey{Tenant: testTenantDefault, AccountKey: testUserExample}
	fields := []any{
		scriptFieldStatus, testStatusCreated,
		scriptFieldPresent, "1",
		scriptFieldShardTag, testShardA,
		scriptFieldGeneration, "1",
		scriptFieldControlGeneration, "0",
		scriptFieldControlAction, "none",
		scriptFieldBackendID, "",
		scriptFieldBackendCounted, "0",
		scriptFieldSessionID, testSessionOne,
		scriptFieldAffinityHash, strings.Repeat("a", 64),
		scriptFieldTenant, key.Tenant,
		scriptFieldAccountKey, key.AccountKey,
		scriptFieldHolderKind, HolderKindSession,
		scriptFieldProtocol, testProtocolIMAP,
		scriptFieldListenerName, testListenerIMAPS,
		scriptFieldServiceName, testProtocolIMAP,
		scriptFieldActiveSessionCount, "1",
		scriptFieldServerTimeMS, "1000",
		scriptFieldExpiresAtMS, "3000",
		scriptFieldLeaseExpiresAtMS, "2000",
		scriptFieldIdleExpiresAtMS, "3000",
	}

	result, err := parseAffinityMutationResult(key, fields)
	if err != nil {
		t.Fatalf("parseAffinityMutationResult returned error: %v", err)
	}

	if result.Delta.SessionID != testSessionOne || result.Delta.AffinityHash == "" || result.Delta.LeaseExpiresAt.IsZero() || result.Delta.IdleExpiresAt.IsZero() {
		t.Fatalf("delta missing required fields: %#v", result.Delta)
	}

	withoutSessionID := replaceScriptField(t, fields, scriptFieldSessionID, "")
	if _, err := parseAffinityMutationResult(key, withoutSessionID); !IsRedisErrorKind(err, RedisErrorKindAmbiguousState) {
		t.Fatalf("missing session delta error = %v, want ambiguous_state", err)
	}
}

// TestKeyBuilderDoesNotRequireRawUsernameInKeys protects Redis key privacy.
func TestKeyBuilderDoesNotRequireRawUsernameInKeys(t *testing.T) {
	rawAccount := "User.Name+Secret@example.org"
	builder := mustKeyBuilder(t)

	keys, err := builder.AffinityKeys(testTenantDefault, rawAccount)
	if err != nil {
		t.Fatalf("AffinityKeys returned error: %v", err)
	}

	for _, key := range []string{keys.State, keys.Sessions, keys.Override} {
		if strings.Contains(key, rawAccount) || strings.Contains(key, strings.ToLower(rawAccount)) {
			t.Fatalf("key %q leaked raw account %q", key, rawAccount)
		}
	}

	sessionKey, err := builder.SessionKey(testTenantDefault, rawAccount, testSessionOne)
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

	instanceKey, err := builder.InstanceKey("director-a")
	if err != nil {
		t.Fatalf("InstanceKey returned error: %v", err)
	}

	if instanceKey != "nd:v1:runtime:instance:director-a" {
		t.Fatalf("instance key = %q", instanceKey)
	}

	ownerKey, err := builder.HealthOwnerKey(testBackendIMAP)
	if err != nil {
		t.Fatalf("HealthOwnerKey returned error: %v", err)
	}

	if ownerKey != "nd:v1:health:backend:"+testBackendIMAP+":owner" {
		t.Fatalf("health owner key = %q", ownerKey)
	}

	healthKey, err := builder.HealthStateKey(testBackendIMAP)
	if err != nil {
		t.Fatalf("HealthStateKey returned error: %v", err)
	}

	if healthKey != "nd:v1:health:backend:"+testBackendIMAP+":state" {
		t.Fatalf("health state key = %q", healthKey)
	}

	backendSessions, err := builder.BackendSessionIndexKey(testBackendIMAP)
	if err != nil {
		t.Fatalf("BackendSessionIndexKey returned error: %v", err)
	}

	if backendSessions != "nd:v1:idx:backend:"+testBackendIMAP+":sessions:00" {
		t.Fatalf("backend session index key = %q", backendSessions)
	}

	reservationKeys, err := builder.BackendReservationKeys(testBackendIMAP)
	if err != nil {
		t.Fatalf("BackendReservationKeys returned error: %v", err)
	}

	if !strings.HasPrefix(reservationKeys.State, "nd:v1:{backend:") || !strings.HasSuffix(reservationKeys.State, ":runtime:backend:"+testBackendIMAP+":reservations") {
		t.Fatalf("backend reservation key = %q", reservationKeys.State)
	}

	if got := redisHashTag(t, reservationKeys.Due); got != redisHashTag(t, reservationKeys.State) {
		t.Fatalf("backend reservation due hash tag = %q, want %q", got, redisHashTag(t, reservationKeys.State))
	}

	if got := builder.UserIndexKey(); got != "nd:v1:idx:users" {
		t.Fatalf("user index key = %q", got)
	}

	userSessions, err := builder.UserSessionIndexKey(testTenantDefault, testUserExample)
	if err != nil {
		t.Fatalf("UserSessionIndexKey returned error: %v", err)
	}

	if strings.Contains(userSessions, testUserExample) || !strings.HasPrefix(userSessions, "nd:v1:idx:user:") {
		t.Fatalf("user session index key = %q", userSessions)
	}

	sessionShardKey, err := builder.SessionIndexShardKey(testSessionOne)
	if err != nil {
		t.Fatalf("SessionIndexShardKey returned error: %v", err)
	}

	if sessionShardKey == builder.SessionIndexKey() || !strings.HasPrefix(sessionShardKey, "nd:v1:idx:sessions:") {
		t.Fatalf("session shard key = %q", sessionShardKey)
	}

	dueShardKey, err := builder.SessionDueIndexShardKey(testSessionOne)
	if err != nil {
		t.Fatalf("SessionDueIndexShardKey returned error: %v", err)
	}

	if !strings.HasPrefix(dueShardKey, "nd:v1:idx:sessions_due:") {
		t.Fatalf("session due shard key = %q", dueShardKey)
	}
}

// TestSessionLocatorIndexesAreShardedDeterministically verifies stable shard mapping.
func TestSessionLocatorIndexesAreShardedDeterministically(t *testing.T) {
	builder := mustKeyBuilder(t)

	first, err := builder.SessionIndexShard(testSessionOne)
	if err != nil {
		t.Fatalf("SessionIndexShard returned error: %v", err)
	}

	second, err := builder.SessionIndexShard(testSessionOne)
	if err != nil {
		t.Fatalf("SessionIndexShard second call returned error: %v", err)
	}

	if first != second {
		t.Fatalf("session shard changed from %d to %d", first, second)
	}

	key, err := builder.SessionIndexShardKey(testSessionOne)
	if err != nil {
		t.Fatalf("SessionIndexShardKey returned error: %v", err)
	}

	again, err := builder.SessionIndexShardKey(testSessionOne)
	if err != nil {
		t.Fatalf("SessionIndexShardKey second call returned error: %v", err)
	}

	if key != again {
		t.Fatalf("session shard key changed from %q to %q", key, again)
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
		scriptBackendReap,
		scriptBackendRelease,
		scriptBackendReserve,
		scriptBackendRuntimeClear,
		scriptBackendRuntimeSet,
		scriptClear,
		scriptClose,
		scriptHeartbeat,
		scriptHealthOwnerAcquire,
		scriptHealthOwnerRenew,
		scriptHealthStatePublish,
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

// TestRuntimeSessionPathsAvoidFullIndexReads rejects deployment-wide scans on session paths.
func TestRuntimeSessionPathsAvoidFullIndexReads(t *testing.T) {
	files := map[string][]string{
		"runtime_read.go": {
			"HGetAll(redisCtx, s.keys.SessionIndexKey()",
			"SMembers(redisCtx",
			".Keys(",
		},
		"scripts/reap.lua": {
			"HGETALL",
			"SMEMBERS",
			"redis.call(\"KEYS\"",
		},
	}

	for file, forbidden := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}

		source := string(data)
		for _, pattern := range forbidden {
			if strings.Contains(source, pattern) {
				t.Fatalf("%s contains forbidden runtime scan pattern %q", file, pattern)
			}
		}
	}
}

// TestAmbiguousScriptPayloadFailsClosed verifies parser-level control-action validation.
func TestAmbiguousScriptPayloadFailsClosed(t *testing.T) {
	_, err := parseAffinityRecord(AffinityKey{Tenant: testTenantDefault, AccountKey: "hash"}, []any{
		scriptFieldStatus, scriptHeartbeat,
		scriptFieldPresent, "1",
		scriptFieldShardTag, testShardA,
		scriptFieldGeneration, "1",
		scriptFieldControlGeneration, "1",
		scriptFieldControlAction, "unknown",
		scriptFieldActiveSessionCount, "1",
		scriptFieldServerTimeMS, "1000",
		scriptFieldExpiresAtMS, "2000",
		scriptFieldLeaseExpiresAtMS, "1500",
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

// TestRedisObservationClassifiesAmbiguousStateWithoutKeys verifies state telemetry stays bounded.
func TestRedisObservationClassifiesAmbiguousStateWithoutKeys(t *testing.T) {
	recorder := &recordingStateObservability{}
	store := &RedisSessionStore{recorder: recorder, redisMode: testRedisModeCluster}

	store.recordRedisOperation(
		context.Background(),
		scriptOpen,
		time.Now(),
		newStateError(RedisErrorKindAmbiguousState, scriptOpen, "ambiguous key {secret}:session", nil),
	)

	event, ok := recorder.last(observability.EventRedisOperation)
	if !ok {
		t.Fatalf("redis operation event missing: %#v", recorder.events)
	}

	if got := event.MetricLabels["reason_class"]; got != string(RedisErrorKindAmbiguousState) {
		t.Fatalf("reason_class = %q, want ambiguous_state", got)
	}

	if got := event.MetricLabels["redis_mode"]; got != testRedisModeCluster {
		t.Fatalf("redis_mode = %q, want cluster", got)
	}

	rendered := event.LogFields["redis_key"] + event.MetricLabels["redis_key"]
	if strings.Contains(rendered, "{secret}") {
		t.Fatalf("redis key leaked into observation: %#v", event)
	}
}

// TestRedisSessionLifecycleScripts verifies affinity scripts against a Redis-compatible service.
func TestRedisSessionLifecycleScripts(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	key := AffinityKey{Tenant: "blue", AccountKey: "User.Name+Secret@example.test"}
	cleanupAffinity(t, client, builder, key, testSessionOne, testSessionTwo)

	first := SessionRecord{
		ID:        testSessionOne,
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

	assertAffinityRecord(t, opened, testStatusCreated, testShardA, 1)
	assertLookupAndHeartbeat(t, store, key, opened)

	second := first
	second.ID = testSessionTwo
	second.ShardTag = testShardB

	reused, err := store.OpenSession(context.Background(), second)
	if err != nil {
		t.Fatalf("second OpenSession returned error: %v", err)
	}

	assertAffinityRecord(t, reused, "reused", testShardA, 2)

	closedFirst, err := store.CloseSession(context.Background(), key, testSessionOne)
	if err != nil {
		t.Fatalf("first CloseSession returned error: %v", err)
	}

	assertAffinityRecord(t, closedFirst, "closed", testShardA, 1)

	closedSecond, err := store.CloseSession(context.Background(), key, testSessionTwo)
	if err != nil {
		t.Fatalf("second CloseSession returned error: %v", err)
	}

	assertAffinityRecord(t, closedSecond, "idle", testShardA, 0)
}

// TestRuntimeAggregatesAreIdempotentAndUnderflowSafe verifies repairable counters do not drift on repeats.
func TestRuntimeAggregatesAreIdempotentAndUnderflowSafe(t *testing.T) {
	store, _, builder := redisIntegrationStore(t)
	key := AffinityKey{Tenant: "blue", AccountKey: "aggregate-idempotent@example.test"}
	sessionID := "aggregate-session"

	if _, err := store.OpenSession(context.Background(), testSessionRecord(key, sessionID)); err != nil {
		t.Fatalf("OpenSession returned error: %v", err)
	}

	if _, err := store.OpenSession(context.Background(), testSessionRecord(key, sessionID)); err != nil {
		t.Fatalf("second OpenSession returned error: %v", err)
	}

	summary, err := store.RuntimeAggregateSummary(context.Background())
	if err != nil {
		t.Fatalf("RuntimeAggregateSummary returned error: %v", err)
	}

	if summary.ActiveSessions.Total.Count != 1 {
		t.Fatalf("active total = %d, want 1", summary.ActiveSessions.Total.Count)
	}

	if got := runtimeDimensionCount(summary.ActiveSessions.ByProtocol, testProtocolIMAP); got != 1 {
		t.Fatalf("protocol aggregate = %d, want 1", got)
	}

	store.decrementAggregateCounters(context.Background(), aggregateSessionDimensions{
		SessionID:    "not-counted",
		Protocol:     testProtocolPOP3,
		ListenerName: testProtocolPOP3,
		ServiceName:  testProtocolPOP3,
		ShardTag:     testShardC,
	})

	if got := aggregateHashField(t, store, builder.AggregateActiveDimensionKey(aggregateDimensionProtocol), testProtocolPOP3); got != "" {
		t.Fatalf("underflow field = %q, want absent", got)
	}

	if _, err := store.CloseSession(context.Background(), key, sessionID); err != nil {
		t.Fatalf("CloseSession returned error: %v", err)
	}

	store.removeSessionAggregate(context.Background(), sessionID)

	summary, err = store.RuntimeAggregateSummary(context.Background())
	if err != nil {
		t.Fatalf("RuntimeAggregateSummary after close returned error: %v", err)
	}

	if summary.ActiveSessions.Total.Count != 0 {
		t.Fatalf("active total after close = %d, want 0", summary.ActiveSessions.Total.Count)
	}

	if got := runtimeDimensionCount(summary.ActiveSessions.ByProtocol, testProtocolIMAP); got != 0 {
		t.Fatalf("protocol aggregate after close = %d, want 0", got)
	}

	if summary.IdleAffinities.Count != 1 {
		t.Fatalf("idle affinities = %d, want 1", summary.IdleAffinities.Count)
	}
}

// TestReaperUpdatesRuntimeAggregateRepairCounters verifies reaping repairs aggregate views.
func TestReaperUpdatesRuntimeAggregateRepairCounters(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	key := AffinityKey{Tenant: "blue", AccountKey: "aggregate-reap@example.test"}
	sessionID := "aggregate-reap-session"
	reservationID := "aggregate-reap-reservation"

	cleanupAffinity(t, client, builder, key, sessionID)
	cleanupBackend(t, client, builder, testBackendIMAP)

	if _, err := store.ReserveBackendCapacity(context.Background(), BackendReservationRequest{
		BackendIdentifier: testBackendIMAP,
		ReservationID:     reservationID,
		MaxConnections:    10,
		LeaseTTL:          time.Second,
	}); err != nil {
		t.Fatalf("ReserveBackendCapacity returned error: %v", err)
	}

	record := testSessionRecord(key, sessionID)
	record.LeaseTTL = 20 * time.Millisecond

	record.IdleGrace = time.Second
	if _, err := store.OpenSession(context.Background(), record); err != nil {
		t.Fatalf("OpenSession returned error: %v", err)
	}

	if _, err := store.AttachSelectedBackend(context.Background(), SessionBackendAttachment{
		Key:               key,
		SessionID:         sessionID,
		BackendIdentifier: testBackendIMAP,
		ReservationID:     reservationID,
		MaxConnections:    10,
	}); err != nil {
		t.Fatalf("AttachSelectedBackend returned error: %v", err)
	}

	time.Sleep(40 * time.Millisecond)

	reaped, err := store.ReapSessions(context.Background(), ReapRequest{Limit: 10, MaxPassDuration: time.Second})
	if err != nil {
		t.Fatalf("ReapSessions returned error: %v", err)
	}

	if reaped.ExpiredSessions != 1 || reaped.RepairedBackends != 1 {
		t.Fatalf("reap result = %#v, want one expired session and backend repair", reaped)
	}

	summary, err := store.RuntimeAggregateSummary(context.Background())
	if err != nil {
		t.Fatalf("RuntimeAggregateSummary returned error: %v", err)
	}

	if summary.ActiveSessions.Total.Count != 0 || summary.IdleAffinities.Count != 1 {
		t.Fatalf("summary active=%d idle=%d, want active 0 idle 1", summary.ActiveSessions.Total.Count, summary.IdleAffinities.Count)
	}

	if summary.Repairs.ExpiredSessions.Count != 1 || summary.Repairs.BackendReservations.Count != 1 {
		t.Fatalf("repair summary = %#v, want expired and reservation repairs", summary.Repairs)
	}
}

// TestBackendReservationRepairUpdatesAggregateCounters verifies reservation repair totals converge.
func TestBackendReservationRepairUpdatesAggregateCounters(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	backendID := testBackendLMTP + "-aggregate"
	cleanupBackend(t, client, builder, backendID)

	if _, err := store.ReserveBackendCapacity(context.Background(), BackendReservationRequest{
		BackendIdentifier: backendID,
		ReservationID:     testExpiredReserve,
		MaxConnections:    10,
		LeaseTTL:          20 * time.Millisecond,
	}); err != nil {
		t.Fatalf("ReserveBackendCapacity returned error: %v", err)
	}

	time.Sleep(40 * time.Millisecond)

	record, err := store.ReapBackendReservations(context.Background(), BackendReservationReapRequest{
		BackendIdentifier: backendID,
		Limit:             10,
	})
	if err != nil {
		t.Fatalf("ReapBackendReservations returned error: %v", err)
	}

	if record.RepairedCount != 1 || record.BackendActiveCount != 0 {
		t.Fatalf("reservation reap = %#v, want one repair and zero active", record)
	}

	summary, err := store.RuntimeAggregateSummary(context.Background())
	if err != nil {
		t.Fatalf("RuntimeAggregateSummary returned error: %v", err)
	}

	if summary.Repairs.BackendReservations.Count != 1 {
		t.Fatalf("backend reservation repair count = %d, want 1", summary.Repairs.BackendReservations.Count)
	}

	if capacity := runtimeBackendCapacity(summary.BackendCapacity, backendID); capacity.ReservedSessions.Count != 0 {
		t.Fatalf("backend capacity = %#v, want zero reserved", capacity)
	}
}

// TestRedisLookupAffinityDoesNotDependOnSecondaryIndexes verifies routing state remains authoritative.
func TestRedisLookupAffinityDoesNotDependOnSecondaryIndexes(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	key := AffinityKey{Tenant: "blue", AccountKey: "missing-index@example.test"}
	cleanupAffinity(t, client, builder, key, "indexed-session", "reuse-session")

	if _, err := store.OpenSession(context.Background(), testSessionRecord(key, "indexed-session")); err != nil {
		t.Fatalf("OpenSession returned error: %v", err)
	}

	userSessionIndexKeys, err := builder.UserSessionIndexShardKeys(key.Tenant, key.AccountKey)
	if err != nil {
		t.Fatalf("UserSessionIndexShardKeys returned error: %v", err)
	}

	indexKeys := append([]string{}, userSessionIndexKeys...)

	affinityHash, err := builder.AffinityHash(key.Tenant, key.AccountKey)
	if err != nil {
		t.Fatalf("AffinityHash returned error: %v", err)
	}

	userIndexKey, err := builder.UserIndexShardKey(affinityHash)
	if err != nil {
		t.Fatalf("UserIndexShardKey returned error: %v", err)
	}

	indexKeys = append(indexKeys, userIndexKey)
	if err := client.Del(context.Background(), indexKeys...).Err(); err != nil {
		t.Fatalf("delete secondary indexes: %v", err)
	}

	for _, sessionID := range []string{"indexed-session"} {
		sessionIndexKey, err := builder.SessionIndexShardKey(sessionID)
		if err != nil {
			t.Fatalf("SessionIndexShardKey returned error: %v", err)
		}

		if err := client.HDel(context.Background(), sessionIndexKey, sessionID).Err(); err != nil {
			t.Fatalf("delete session index: %v", err)
		}
	}

	lookedUp, err := store.LookupAffinity(context.Background(), key)
	if err != nil {
		t.Fatalf("LookupAffinity returned error with missing indexes: %v", err)
	}

	assertAffinityRecord(t, lookedUp, "found", testShardA, 1)

	reused := testSessionRecord(key, "reuse-session")
	reused.ShardTag = testShardB

	opened, err := store.OpenSession(context.Background(), reused)
	if err != nil {
		t.Fatalf("OpenSession reuse returned error with missing indexes: %v", err)
	}

	assertAffinityRecord(t, opened, "reused", testShardA, 2)
}

// TestRedisRuntimeReadModelListsSessionsAndUsers verifies production control reads use Redis state.
func TestRedisRuntimeReadModelListsSessionsAndUsers(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	key := AffinityKey{Tenant: testTenantDefault, AccountKey: "reader@example.test"}
	cleanupAffinity(t, client, builder, key, "reader-session-1", "reader-session-2")
	cleanupBackend(t, client, builder, testBackendIMAP)

	openAttachedSession(t, store, key, "reader-session-1", testBackendIMAP)
	openAttachedSession(t, store, key, "reader-session-2", testBackendIMAP)

	assertRuntimeSessionList(t, store, key)
	assertRuntimeSessionLookup(t, store, key)
	assertRuntimeUserReads(t, store, key)
}

// TestRedisRuntimeReadPagesUseBoundedMembershipScans verifies cursor-readable indexes.
func TestRedisRuntimeReadPagesUseBoundedMembershipScans(t *testing.T) {
	store, client, builder := redisIntegrationStoreWithOptions(t, WithRuntimeIndexPages(1, 1))
	key := AffinityKey{Tenant: testTenantDefault, AccountKey: "reader-page@example.test"}
	cleanupAffinity(t, client, builder, key, "reader-page-1", "reader-page-2")
	cleanupBackend(t, client, builder, testBackendIMAP)

	openAttachedSession(t, store, key, "reader-page-1", testBackendIMAP)
	openAttachedSession(t, store, key, "reader-page-2", testBackendIMAP)

	userPage, err := store.ListRuntimeSessionsForUserPage(context.Background(), key, RuntimeSessionPageRequest{Limit: 1})
	if err != nil {
		t.Fatalf("ListRuntimeSessionsForUserPage returned error: %v", err)
	}

	if len(userPage.Records) == 0 {
		t.Fatal("user session page was empty")
	}

	backendPage, err := store.ListRuntimeSessionsForBackendPage(context.Background(), testBackendIMAP, RuntimeSessionPageRequest{Limit: 1})
	if err != nil {
		t.Fatalf("ListRuntimeSessionsForBackendPage returned error: %v", err)
	}

	if len(backendPage.Records) == 0 {
		t.Fatal("backend session page was empty")
	}

	globalPage, err := store.ListRuntimeSessionsPage(context.Background(), RuntimeSessionPageRequest{Limit: 1})
	if err != nil {
		t.Fatalf("ListRuntimeSessionsPage returned error: %v", err)
	}

	if len(globalPage.Records) == 0 {
		t.Fatal("global session page was empty")
	}
}

// TestRedisRuntimeReadRemovesStaleLocator verifies stale locator repair during paging.
func TestRedisRuntimeReadRemovesStaleLocator(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	sessionID := "stale-locator-session"

	sessionIndexKey, err := builder.SessionIndexShardKey(sessionID)
	if err != nil {
		t.Fatalf("SessionIndexShardKey returned error: %v", err)
	}

	if err := client.HSet(context.Background(), sessionIndexKey, sessionID, "missing-session-key").Err(); err != nil {
		t.Fatalf("seed stale session locator: %v", err)
	}

	page, err := store.ListRuntimeSessionsPage(context.Background(), RuntimeSessionPageRequest{Limit: 10})
	if err != nil {
		t.Fatalf("ListRuntimeSessionsPage returned error: %v", err)
	}

	for _, record := range page.Records {
		if record.SessionID == sessionID {
			t.Fatalf("stale session appeared in page: %#v", record)
		}
	}

	if exists := client.HExists(context.Background(), sessionIndexKey, sessionID).Val(); exists {
		t.Fatal("stale session locator still exists")
	}
}

// TestRedisDeliveryHoldPinsAffinityWithoutSessionListing verifies LMTP holds are not login sessions.
func TestRedisDeliveryHoldPinsAffinityWithoutSessionListing(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	key := AffinityKey{Tenant: "blue", AccountKey: "delivery@example.test"}
	deliveryID := "delivery-hold"
	imapID := "imap-during-delivery"
	cleanupAffinity(t, client, builder, key, deliveryID, imapID)
	cleanupBackend(t, client, builder, testBackendLMTP)
	cleanupBackend(t, client, builder, testBackendIMAP)

	openDeliveryHoldForTest(t, store, key, deliveryID)
	assertDeliveryAffinityPin(t, store, key)
	assertDeliveryHoldNotListed(t, store, deliveryID)
	assertIMAPReusesDeliveryHold(t, store, key, imapID)
	closeStateSession(t, store, key, imapID, "IMAP")
	closeStateSession(t, store, key, deliveryID, "delivery")
}

// openDeliveryHoldForTest opens and attaches one delivery-scoped lease.
func openDeliveryHoldForTest(t *testing.T, store *RedisSessionStore, key AffinityKey, deliveryID string) {
	t.Helper()

	delivery := testSessionRecord(key, deliveryID)
	delivery.HolderKind = HolderKindDelivery
	delivery.Protocol = testProtocolLMTP
	delivery.ServiceName = testProtocolLMTP
	delivery.ShardTag = testShardA

	if _, err := store.OpenSession(context.Background(), delivery); err != nil {
		t.Fatalf("OpenSession delivery returned error: %v", err)
	}

	reservation := reserveBackendForTest(t, store, testBackendLMTP, deliveryID, 10)

	if _, err := store.AttachSelectedBackend(context.Background(), SessionBackendAttachment{
		Key:               key,
		SessionID:         deliveryID,
		BackendIdentifier: testBackendLMTP,
		ReservationID:     reservation.ReservationID,
		MaxConnections:    10,
	}); err != nil {
		t.Fatalf("AttachSelectedBackend delivery returned error: %v", err)
	}

	if _, err := store.HeartbeatSession(context.Background(), key, deliveryID, time.Second); err != nil {
		t.Fatalf("HeartbeatSession delivery returned error: %v", err)
	}
}

// assertDeliveryAffinityPin verifies a delivery hold is visible to placement.
func assertDeliveryAffinityPin(t *testing.T, store *RedisSessionStore, key AffinityKey) {
	t.Helper()

	affinity, err := store.LookupAffinity(context.Background(), key)
	if err != nil {
		t.Fatalf("LookupAffinity returned error: %v", err)
	}

	if !affinity.Present || affinity.ActiveSessionCount != 1 || affinity.ShardTag != testShardA {
		t.Fatalf("delivery affinity = %#v, want active shard pin", affinity)
	}
}

// assertDeliveryHoldNotListed verifies delivery holds are hidden from session reads.
func assertDeliveryHoldNotListed(t *testing.T, store *RedisSessionStore, deliveryID string) {
	t.Helper()

	lmtpSessions, err := store.ListRuntimeSessions(context.Background(), testProtocolLMTP)
	if err != nil {
		t.Fatalf("ListRuntimeSessions returned error: %v", err)
	}

	if len(lmtpSessions) != 0 {
		t.Fatalf("delivery holds appeared as runtime sessions: %#v", lmtpSessions)
	}

	if _, ok, err := store.GetRuntimeSession(context.Background(), deliveryID); err != nil || ok {
		t.Fatalf("GetRuntimeSession delivery returned ok=%t err=%v", ok, err)
	}
}

// assertIMAPReusesDeliveryHold verifies a new IMAP lease observes the active shard.
func assertIMAPReusesDeliveryHold(t *testing.T, store *RedisSessionStore, key AffinityKey, imapID string) {
	t.Helper()

	imap := testSessionRecord(key, imapID)
	imap.ShardTag = testShardB

	reused, err := store.OpenSession(context.Background(), imap)
	if err != nil {
		t.Fatalf("OpenSession IMAP during delivery returned error: %v", err)
	}

	if reused.ShardTag != testShardA || reused.Status != "reused" {
		t.Fatalf("IMAP placement during delivery = %#v, want reused delivery shard", reused)
	}
}

// closeStateSession closes a Redis session fixture with contextual error text.
func closeStateSession(t *testing.T, store *RedisSessionStore, key AffinityKey, sessionID string, name string) {
	t.Helper()

	if _, err := store.CloseSession(context.Background(), key, sessionID); err != nil {
		t.Fatalf("CloseSession %s returned error: %v", name, err)
	}
}

// TestRedisReapRepairsExpiredDeliveryHold verifies expired delivery holds repair backend counts.
func TestRedisReapRepairsExpiredDeliveryHold(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	key := AffinityKey{Tenant: "blue", AccountKey: "delivery-reap@example.test"}
	deliveryID := "delivery-reap"
	cleanupAffinity(t, client, builder, key, deliveryID)
	cleanupBackend(t, client, builder, testBackendLMTP)

	delivery := testSessionRecord(key, deliveryID)
	delivery.HolderKind = HolderKindDelivery
	delivery.Protocol = testProtocolLMTP
	delivery.ServiceName = testProtocolLMTP
	delivery.ShardTag = testShardA

	delivery.LeaseTTL = 25 * time.Millisecond
	if _, err := store.OpenSession(context.Background(), delivery); err != nil {
		t.Fatalf("OpenSession delivery returned error: %v", err)
	}

	reservation := reserveBackendForTest(t, store, testBackendLMTP, deliveryID, 10)

	if _, err := store.AttachSelectedBackend(context.Background(), SessionBackendAttachment{
		Key:               key,
		SessionID:         deliveryID,
		BackendIdentifier: testBackendLMTP,
		ReservationID:     reservation.ReservationID,
		MaxConnections:    10,
	}); err != nil {
		t.Fatalf("AttachSelectedBackend delivery returned error: %v", err)
	}

	time.Sleep(60 * time.Millisecond)

	reaped, err := store.ReapSessions(context.Background(), ReapRequest{Limit: 100})
	if err != nil {
		t.Fatalf("ReapSessions returned error: %v", err)
	}

	if reaped.ExpiredSessions != 1 || reaped.RepairedBackends != 1 {
		t.Fatalf("reap result = %#v, want expired delivery hold and backend repair", reaped)
	}

	if count := redisBackendActiveCount(t, client, builder, testBackendLMTP); count != 0 {
		t.Fatalf("redis backend active count after reap = %d, want 0", count)
	}
}

// assertRuntimeSessionList verifies indexed runtime session listing.
func assertRuntimeSessionList(t *testing.T, store *RedisSessionStore, key AffinityKey) {
	t.Helper()

	sessions, err := store.ListRuntimeSessions(context.Background(), testProtocolIMAP)
	if err != nil {
		t.Fatalf("ListRuntimeSessions returned error: %v", err)
	}

	if len(sessions) != 2 {
		t.Fatalf("ListRuntimeSessions returned %d sessions, want 2: %#v", len(sessions), sessions)
	}

	for _, session := range sessions {
		if session.Key != key || session.BackendIdentifier != testBackendIMAP || session.ShardTag != testShardA {
			t.Fatalf("runtime session mismatch: %#v", session)
		}
	}
}

// assertRuntimeSessionLookup verifies individual and user-scoped session reads.
func assertRuntimeSessionLookup(t *testing.T, store *RedisSessionStore, key AffinityKey) {
	t.Helper()

	session, ok, err := store.GetRuntimeSession(context.Background(), "reader-session-1")
	if err != nil {
		t.Fatalf("GetRuntimeSession returned error: %v", err)
	}

	if !ok || session.SessionID != "reader-session-1" || session.Key.AccountKey != key.AccountKey {
		t.Fatalf("GetRuntimeSession returned ok=%t session=%#v", ok, session)
	}

	userSessions, err := store.ListRuntimeSessionsForUser(context.Background(), key)
	if err != nil {
		t.Fatalf("ListRuntimeSessionsForUser returned error: %v", err)
	}

	if len(userSessions) != 2 {
		t.Fatalf("ListRuntimeSessionsForUser returned %d sessions, want 2", len(userSessions))
	}
}

// assertRuntimeUserReads verifies Redis-derived user runtime views.
func assertRuntimeUserReads(t *testing.T, store *RedisSessionStore, key AffinityKey) {
	t.Helper()

	users, err := store.ListRuntimeUsers(context.Background())
	if err != nil {
		t.Fatalf("ListRuntimeUsers returned error: %v", err)
	}

	if len(users) != 1 || users[0].Key != key || users[0].ActiveSessionCount != 2 {
		t.Fatalf("ListRuntimeUsers returned %#v", users)
	}

	user, ok, err := store.GetRuntimeUser(context.Background(), key)
	if err != nil {
		t.Fatalf("GetRuntimeUser returned error: %v", err)
	}

	if !ok || user.Key != key || user.ShardTag != testShardA || user.ActiveSessionCount != 2 {
		t.Fatalf("GetRuntimeUser returned ok=%t user=%#v", ok, user)
	}
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

	reservation := reserveBackendForTest(t, store, backendID, sessionID, 10)

	firstAttach, err := store.AttachSelectedBackend(context.Background(), SessionBackendAttachment{
		Key:               key,
		SessionID:         sessionID,
		BackendIdentifier: backendID,
		ReservationID:     reservation.ReservationID,
		MaxConnections:    10,
	})
	if err != nil {
		t.Fatalf("AttachSelectedBackend returned error: %v", err)
	}

	if firstAttach.BackendActiveCount != 1 {
		t.Fatalf("backend active count after attach = %d, want 1", firstAttach.BackendActiveCount)
	}

	sessionKey, err := builder.SessionKey(key.Tenant, key.AccountKey, sessionID)
	if err != nil {
		t.Fatalf("SessionKey returned error: %v", err)
	}

	if got := client.HGet(context.Background(), sessionKey, scriptFieldBackendReservation).Val(); got != reservation.ReservationID {
		t.Fatalf("attached reservation id = %q, want %q", got, reservation.ReservationID)
	}

	secondAttach, err := store.AttachSelectedBackend(context.Background(), SessionBackendAttachment{
		Key:               key,
		SessionID:         sessionID,
		BackendIdentifier: backendID,
		ReservationID:     reservation.ReservationID,
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

	reservationKeys, err := builder.BackendReservationKeys(backendID)
	if err != nil {
		t.Fatalf("BackendReservationKeys returned error: %v", err)
	}

	beforeHeartbeat := client.ZScore(context.Background(), reservationKeys.Due, reservation.ReservationID).Val()

	time.Sleep(time.Millisecond)

	if _, err := store.HeartbeatSession(context.Background(), key, sessionID, 2*time.Second); err != nil {
		t.Fatalf("HeartbeatSession returned error: %v", err)
	}

	afterHeartbeat := client.ZScore(context.Background(), reservationKeys.Due, reservation.ReservationID).Val()
	if afterHeartbeat <= beforeHeartbeat {
		t.Fatalf("reservation expiry did not advance: before=%f after=%f", beforeHeartbeat, afterHeartbeat)
	}

	if _, err := store.CloseSession(context.Background(), key, sessionID); err != nil {
		t.Fatalf("CloseSession returned error: %v", err)
	}

	if count := redisBackendActiveCount(t, client, builder, backendID); count != 0 {
		t.Fatalf("redis backend active count after close = %d, want 0", count)
	}
}

// TestRedisBackendReservationsEnforceCapacity verifies backend-local capacity gates.
func TestRedisBackendReservationsEnforceCapacity(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	backendID := testBackendIMAP

	cleanupBackend(t, client, builder, backendID)

	assertBackendReservationCount(t, reserveBackendForTest(t, store, backendID, testReservationOne, 2), 1, "first reservation")
	assertBackendReservationCount(t, reserveBackendForTest(t, store, backendID, testReservationOne, 2), 1, "idempotent reservation")
	assertBackendReservationCount(t, reserveBackendForTest(t, store, backendID, testReservationTwo, 2), 2, "second reservation")
	assertBackendReservationCapacityFull(t, store, backendID, testReservationThree)
	assertBackendReservationRelease(t, store, backendID, testReservationOne, 1, 1, "release")
	assertBackendReservationRelease(t, store, backendID, testReservationOne, 1, 0, "repeated release")

	if _, err := store.ReleaseBackendReservation(context.Background(), BackendReservationReleaseRequest{
		BackendIdentifier: backendID,
		ReservationID:     testReservationTwo,
	}); err != nil {
		t.Fatalf("release second reservation returned error: %v", err)
	}

	if count := redisBackendActiveCount(t, client, builder, backendID); count != 0 {
		t.Fatalf("backend active count after releases = %d, want 0", count)
	}
}

// TestRedisBackendReservationReapRepairsExpiredReservations verifies stale slots converge.
func TestRedisBackendReservationReapRepairsExpiredReservations(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	backendID := testBackendIMAP

	cleanupBackend(t, client, builder, backendID)

	if _, err := store.ReserveBackendCapacity(context.Background(), BackendReservationRequest{
		BackendIdentifier: backendID,
		ReservationID:     testExpiredReserve,
		MaxConnections:    1,
		LeaseTTL:          25 * time.Millisecond,
	}); err != nil {
		t.Fatalf("ReserveBackendCapacity returned error: %v", err)
	}

	time.Sleep(60 * time.Millisecond)

	reaped, err := store.ReapBackendReservations(context.Background(), BackendReservationReapRequest{
		BackendIdentifier: backendID,
		Limit:             10,
	})
	if err != nil {
		t.Fatalf("ReapBackendReservations returned error: %v", err)
	}

	if reaped.RepairedCount != 1 || reaped.BackendActiveCount != 0 {
		t.Fatalf("backend reservation reap = %#v, want one repair and count 0", reaped)
	}

	if _, err := store.ReleaseBackendReservation(context.Background(), BackendReservationReleaseRequest{
		BackendIdentifier: backendID,
		ReservationID:     testExpiredReserve,
	}); err != nil {
		t.Fatalf("release after reap returned error: %v", err)
	}

	if count := redisBackendActiveCount(t, client, builder, backendID); count != 0 {
		t.Fatalf("backend active count after repeated repair = %d, want 0", count)
	}
}

// TestRedisConcurrentReservationsCannotExceedMaxConnections verifies cross-store safety.
func TestRedisConcurrentReservationsCannotExceedMaxConnections(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	backendID := testBackendIMAP

	cleanupBackend(t, client, builder, backendID)

	secondStore, err := NewRedisSessionStore(client, builder, nil)
	if err != nil {
		t.Fatalf("NewRedisSessionStore returned error: %v", err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)

	for _, item := range []struct {
		store         *RedisSessionStore
		reservationID string
	}{
		{store: store, reservationID: "concurrent-a"},
		{store: secondStore, reservationID: "concurrent-b"},
	} {
		go func(item struct {
			store         *RedisSessionStore
			reservationID string
		}) {
			<-start

			_, reserveErr := item.store.ReserveBackendCapacity(context.Background(), BackendReservationRequest{
				BackendIdentifier: backendID,
				ReservationID:     item.reservationID,
				MaxConnections:    1,
				LeaseTTL:          time.Second,
			})
			results <- reserveErr
		}(item)
	}

	close(start)

	successes := 0

	for range 2 {
		if err := <-results; err == nil {
			successes++
		} else if !IsRedisErrorKind(err, RedisErrorKindAmbiguousState) {
			t.Fatalf("concurrent reservation error = %v, want nil or ambiguous_state", err)
		}
	}

	if successes != 1 {
		t.Fatalf("successful concurrent reservations = %d, want 1", successes)
	}

	if count := redisBackendActiveCount(t, client, builder, backendID); count != 1 {
		t.Fatalf("backend active count after concurrent reserve = %d, want 1", count)
	}
}

// TestRedisBackendSnapshotReadsReservationCapacity verifies route lookup sees reservations only as reads.
func TestRedisBackendSnapshotReadsReservationCapacity(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	backendID := testBackendIMAP

	cleanupBackend(t, client, builder, backendID)
	reserveBackendForTest(t, store, backendID, "snapshot-reservation", 10)

	snapshot, err := store.BackendSnapshot(context.Background(), backendID)
	if err != nil {
		t.Fatalf("BackendSnapshot returned error: %v", err)
	}

	if snapshot.ActiveSessions != 1 {
		t.Fatalf("snapshot active sessions = %d, want reservation-backed count 1", snapshot.ActiveSessions)
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

		reservation := reserveBackendForTest(t, store, backendID, sessionID, 10)

		if _, err := store.AttachSelectedBackend(context.Background(), SessionBackendAttachment{
			Key:               key,
			SessionID:         sessionID,
			BackendIdentifier: backendID,
			ReservationID:     reservation.ReservationID,
			MaxConnections:    10,
		}); err != nil {
			t.Fatalf("AttachSelectedBackend %s returned error: %v", sessionID, err)
		}
	}

	if _, err := store.KillSession(context.Background(), SessionKillRequest{
		SessionID: testKillSessionID,
		Reason:    "operator killed one session",
	}); err != nil {
		t.Fatalf("KillSession returned error: %v", err)
	}

	otherHeartbeat, err := store.HeartbeatSession(context.Background(), key, testKickSessionID, time.Second)
	if err != nil {
		t.Fatalf("HeartbeatSession for non-killed session returned error: %v", err)
	}

	if otherHeartbeat.ControlAction != ControlActionNone {
		t.Fatalf("heartbeat action for non-killed session = %q, want none", otherHeartbeat.ControlAction)
	}

	killHeartbeat, err := store.HeartbeatSession(context.Background(), key, testKillSessionID, time.Second)
	if err != nil {
		t.Fatalf("HeartbeatSession after session kill returned error: %v", err)
	}

	if killHeartbeat.ControlAction != ControlActionKick {
		t.Fatalf("heartbeat control action for session kill = %q, want kick", killHeartbeat.ControlAction)
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

	reservation := reserveBackendForTest(t, store, backendID, sessionID, 10)

	if _, err := store.AttachSelectedBackend(context.Background(), SessionBackendAttachment{
		Key:               key,
		SessionID:         sessionID,
		BackendIdentifier: backendID,
		ReservationID:     reservation.ReservationID,
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

	cleared, err := store.ClearUserAffinity(context.Background(), UserClearRequest{
		Key:    key,
		Reason: "operator clear after reap",
	})
	if err != nil {
		t.Fatalf("ClearUserAffinity after reap returned error: %v", err)
	}

	if cleared.Status != testClearStatus {
		t.Fatalf("clear after reap = %#v, want %q", cleared, testClearStatus)
	}
}

// TestRedisReapReadsOnlyDueSessions verifies future leases are not inspected or expired.
func TestRedisReapReadsOnlyDueSessions(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	key := AffinityKey{Tenant: "blue", AccountKey: "reap-due@example.test"}
	backendID := testBackendIMAP
	expiredID := "reap-due-expired"
	activeID := "reap-due-active"

	cleanupAffinity(t, client, builder, key, expiredID, activeID)
	cleanupBackend(t, client, builder, backendID)

	expired := testSessionRecord(key, expiredID)
	expired.LeaseTTL = 25 * time.Millisecond

	expired.IdleGrace = time.Second
	if _, err := store.OpenSession(context.Background(), expired); err != nil {
		t.Fatalf("OpenSession expired returned error: %v", err)
	}

	expiredReservation := reserveBackendForTest(t, store, backendID, expiredID, 10)

	if _, err := store.AttachSelectedBackend(context.Background(), SessionBackendAttachment{
		Key:               key,
		SessionID:         expiredID,
		BackendIdentifier: backendID,
		ReservationID:     expiredReservation.ReservationID,
		MaxConnections:    10,
	}); err != nil {
		t.Fatalf("AttachSelectedBackend expired returned error: %v", err)
	}

	active := testSessionRecord(key, activeID)
	active.LeaseTTL = 5 * time.Second

	active.IdleGrace = time.Second
	if _, err := store.OpenSession(context.Background(), active); err != nil {
		t.Fatalf("OpenSession active returned error: %v", err)
	}

	activeReservation := reserveBackendForTest(t, store, backendID, activeID, 10)

	if _, err := store.AttachSelectedBackend(context.Background(), SessionBackendAttachment{
		Key:               key,
		SessionID:         activeID,
		BackendIdentifier: backendID,
		ReservationID:     activeReservation.ReservationID,
		MaxConnections:    10,
	}); err != nil {
		t.Fatalf("AttachSelectedBackend active returned error: %v", err)
	}

	time.Sleep(60 * time.Millisecond)

	reaped, err := store.ReapSessions(context.Background(), ReapRequest{Limit: 100, MaxPassDuration: time.Second})
	if err != nil {
		t.Fatalf("ReapSessions returned error: %v", err)
	}

	if reaped.ScannedSessions != 1 || reaped.ExpiredSessions != 1 {
		t.Fatalf("reap result = %#v, want only due session scanned and expired", reaped)
	}

	if _, ok, err := store.GetRuntimeSession(context.Background(), activeID); err != nil || !ok {
		t.Fatalf("active session lookup ok=%t err=%v, want present", ok, err)
	}
}

// TestRedisReapRespectsBatchSize verifies each pass stops at the requested due bound.
func TestRedisReapRespectsBatchSize(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	key := AffinityKey{Tenant: "blue", AccountKey: "reap-batch@example.test"}
	backendID := testBackendIMAP
	sessionIDs := []string{"reap-batch-1", "reap-batch-2", "reap-batch-3"}

	cleanupAffinity(t, client, builder, key, sessionIDs...)
	cleanupBackend(t, client, builder, backendID)

	for _, sessionID := range sessionIDs {
		record := testSessionRecord(key, sessionID)
		record.LeaseTTL = 25 * time.Millisecond

		record.IdleGrace = time.Second
		if _, err := store.OpenSession(context.Background(), record); err != nil {
			t.Fatalf("OpenSession %s returned error: %v", sessionID, err)
		}

		reservation := reserveBackendForTest(t, store, backendID, sessionID, 10)

		if _, err := store.AttachSelectedBackend(context.Background(), SessionBackendAttachment{
			Key:               key,
			SessionID:         sessionID,
			BackendIdentifier: backendID,
			ReservationID:     reservation.ReservationID,
			MaxConnections:    10,
		}); err != nil {
			t.Fatalf("AttachSelectedBackend %s returned error: %v", sessionID, err)
		}
	}

	time.Sleep(60 * time.Millisecond)

	first, err := store.ReapSessions(context.Background(), ReapRequest{Limit: 2, MaxPassDuration: time.Second})
	if err != nil {
		t.Fatalf("first ReapSessions returned error: %v", err)
	}

	if first.ScannedSessions != 2 || first.ExpiredSessions != 2 {
		t.Fatalf("first reap = %#v, want batch of two", first)
	}

	second, err := store.ReapSessions(context.Background(), ReapRequest{Limit: 2, MaxPassDuration: time.Second})
	if err != nil {
		t.Fatalf("second ReapSessions returned error: %v", err)
	}

	if second.ExpiredSessions != 1 {
		t.Fatalf("second reap = %#v, want remaining expired session", second)
	}
}

// TestRedisReapIsIdempotentForAlreadyRepairedDueSession verifies duplicate workers are harmless.
func TestRedisReapIsIdempotentForAlreadyRepairedDueSession(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	key := AffinityKey{Tenant: "blue", AccountKey: "reap-idempotent@example.test"}
	backendID := testBackendIMAP
	sessionID := "reap-idempotent"

	cleanupAffinity(t, client, builder, key, sessionID)
	cleanupBackend(t, client, builder, backendID)

	record := testSessionRecord(key, sessionID)
	record.LeaseTTL = 25 * time.Millisecond

	record.IdleGrace = time.Second
	if _, err := store.OpenSession(context.Background(), record); err != nil {
		t.Fatalf("OpenSession returned error: %v", err)
	}

	reservation := reserveBackendForTest(t, store, backendID, sessionID, 10)

	if _, err := store.AttachSelectedBackend(context.Background(), SessionBackendAttachment{
		Key:               key,
		SessionID:         sessionID,
		BackendIdentifier: backendID,
		ReservationID:     reservation.ReservationID,
		MaxConnections:    10,
	}); err != nil {
		t.Fatalf("AttachSelectedBackend returned error: %v", err)
	}

	time.Sleep(60 * time.Millisecond)

	first, err := store.ReapSessions(context.Background(), ReapRequest{Limit: 10, MaxPassDuration: time.Second})
	if err != nil {
		t.Fatalf("first ReapSessions returned error: %v", err)
	}

	second, err := store.ReapSessions(context.Background(), ReapRequest{Limit: 10, MaxPassDuration: time.Second})
	if err != nil {
		t.Fatalf("second ReapSessions returned error: %v", err)
	}

	if first.ExpiredSessions != 1 || second.ExpiredSessions != 0 {
		t.Fatalf("reap results first=%#v second=%#v, want idempotent repair", first, second)
	}

	if count := redisBackendActiveCount(t, client, builder, backendID); count != 0 {
		t.Fatalf("backend count after duplicate reap = %d, want 0", count)
	}
}

// TestRedisMoveAndClearScripts verifies user move and inactive affinity clear behavior.
func TestRedisMoveAndClearScripts(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	key := AffinityKey{Tenant: "blue", AccountKey: "runtime-move@example.test"}
	backendID := testBackendIMAP

	cleanupAffinity(t, client, builder, key, testRuntimeSessionID, "second-session", "third-session")
	cleanupBackend(t, client, builder, backendID)

	openAttachedSession(t, store, key, testRuntimeSessionID, backendID)

	pendingMove, err := store.MoveUser(context.Background(), UserMoveRequest{
		Key:         key,
		TargetShard: testShardB,
		Strategy:    moveStrategyNewSessionsOnly,
		Reason:      "operator pending move",
		Actor:       testOperatorActor,
	})
	if err != nil {
		t.Fatalf("MoveUser new_sessions_only returned error: %v", err)
	}

	if pendingMove.ControlAction != ControlActionNone || pendingMove.ActiveSessionCount != 1 {
		t.Fatalf("pending move result = %#v, want no control action and one active session", pendingMove)
	}

	second := testSessionRecord(key, "second-session")
	second.ShardTag = testShardB

	secondAffinity, err := store.OpenSession(context.Background(), second)
	if err != nil {
		t.Fatalf("OpenSession during new_sessions_only returned error: %v", err)
	}

	if secondAffinity.ShardTag != testShardA {
		t.Fatalf("new session during active pending move shard = %q, want old shard %q", secondAffinity.ShardTag, testShardA)
	}

	if _, err := store.CloseSession(context.Background(), key, testRuntimeSessionID); err != nil {
		t.Fatalf("CloseSession first returned error: %v", err)
	}

	if _, err := store.CloseSession(context.Background(), key, "second-session"); err != nil {
		t.Fatalf("CloseSession second returned error: %v", err)
	}

	third := testSessionRecord(key, "third-session")
	third.ShardTag = testShardB

	movedAfterIdle, err := store.OpenSession(context.Background(), third)
	if err != nil {
		t.Fatalf("OpenSession after pending move returned error: %v", err)
	}

	if movedAfterIdle.ShardTag != testShardB {
		t.Fatalf("new session after active count reached zero shard = %q, want %q", movedAfterIdle.ShardTag, testShardB)
	}

	if _, err := store.CloseSession(context.Background(), key, "third-session"); err != nil {
		t.Fatalf("CloseSession third returned error: %v", err)
	}

	openAttachedSession(t, store, key, testRuntimeSessionID, backendID)

	moved, err := store.MoveUser(context.Background(), UserMoveRequest{
		Key:         key,
		TargetShard: testShardC,
		Strategy:    moveStrategyKickExisting,
		Reason:      "operator move",
	})
	if err != nil {
		t.Fatalf("MoveUser returned error: %v", err)
	}

	if moved.ControlAction != ControlActionMoveGenerationChanged || moved.TargetShard != testShardC {
		t.Fatalf("move result = %#v", moved)
	}

	moveHeartbeat, err := store.HeartbeatSession(context.Background(), key, testRuntimeSessionID, time.Second)
	if err != nil {
		t.Fatalf("HeartbeatSession after kick_existing returned error: %v", err)
	}

	if moveHeartbeat.ControlAction != ControlActionMoveGenerationChanged {
		t.Fatalf("kick_existing heartbeat action = %q, want move_generation_changed", moveHeartbeat.ControlAction)
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

	if cleared.Status != testClearStatus {
		t.Fatalf("clear result = %#v, want %q", cleared, testClearStatus)
	}
}

// TestRedisBackendRuntimeScripts verifies backend runtime drain and clear behavior.
func TestRedisBackendRuntimeScripts(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	key := AffinityKey{Tenant: "blue", AccountKey: "runtime-backend@example.test"}
	secondKey := AffinityKey{Tenant: "blue", AccountKey: "runtime-backend-second@example.test"}
	backendID := testBackendIMAP

	cleanupAffinity(t, client, builder, key, testRuntimeSessionID)
	cleanupAffinity(t, client, builder, secondKey, "runtime-session-2")
	cleanupBackend(t, client, builder, backendID)

	openAttachedSession(t, store, key, testRuntimeSessionID, backendID)
	openAttachedSession(t, store, secondKey, "runtime-session-2", backendID)

	runtimeSet, err := store.SetBackendRuntime(context.Background(), BackendRuntimeMutation{
		BackendIdentifier: backendID,
		DrainEnabled:      true,
		DrainMode:         "hard",
		Reason:            "host drain",
	})
	if err != nil {
		t.Fatalf("SetBackendRuntime returned error: %v", err)
	}

	if runtimeSet.MarkedSessionCount != 2 {
		t.Fatalf("marked sessions = %d, want 2", runtimeSet.MarkedSessionCount)
	}

	drainHeartbeat, err := store.HeartbeatSession(context.Background(), key, testRuntimeSessionID, time.Second)
	if err != nil {
		t.Fatalf("HeartbeatSession after backend drain returned error: %v", err)
	}

	if drainHeartbeat.ControlAction != ControlActionDrain {
		t.Fatalf("heartbeat control action after backend drain = %q, want drain", drainHeartbeat.ControlAction)
	}

	secondDrainHeartbeat, err := store.HeartbeatSession(context.Background(), secondKey, "runtime-session-2", time.Second)
	if err != nil {
		t.Fatalf("second HeartbeatSession after backend drain returned error: %v", err)
	}

	if secondDrainHeartbeat.ControlAction != ControlActionDrain {
		t.Fatalf("second heartbeat control action after backend drain = %q, want drain", secondDrainHeartbeat.ControlAction)
	}

	runtimeClear, err := store.ClearBackendRuntime(context.Background(), BackendRuntimeClearRequest{
		BackendIdentifier: backendID,
		Reason:            "host drain finished",
	})
	if err != nil {
		t.Fatalf("ClearBackendRuntime returned error: %v", err)
	}

	if runtimeClear.ActiveSessionCount != 2 {
		t.Fatalf("active count after runtime clear = %d, want preserved count 2", runtimeClear.ActiveSessionCount)
	}

	if _, err := store.CloseSession(context.Background(), key, testRuntimeSessionID); err != nil {
		t.Fatalf("CloseSession returned error: %v", err)
	}

	if _, err := store.CloseSession(context.Background(), secondKey, "runtime-session-2"); err != nil {
		t.Fatalf("second CloseSession returned error: %v", err)
	}
}

// TestRedisDrainExistingMoveAllowsAuditedSplit verifies explicit drain split semantics.
func TestRedisDrainExistingMoveAllowsAuditedSplit(t *testing.T) {
	const (
		oldSessionID = "old-session"
		newSessionID = "new-session"
	)

	store, client, builder := redisIntegrationStore(t)
	key := AffinityKey{Tenant: "blue", AccountKey: "runtime-drain-move@example.test"}
	backendID := testBackendIMAP

	cleanupAffinity(t, client, builder, key, oldSessionID, newSessionID)
	cleanupBackend(t, client, builder, backendID)

	openAttachedSession(t, store, key, oldSessionID, backendID)

	moved, err := store.MoveUser(context.Background(), UserMoveRequest{
		Key:         key,
		TargetShard: testShardB,
		Strategy:    moveStrategyDrainExisting,
		Reason:      "operator drain move",
		Actor:       testOperatorActor,
	})
	if err != nil {
		t.Fatalf("MoveUser drain_existing returned error: %v", err)
	}

	if moved.ControlAction != ControlActionNone || moved.TargetShard != testShardB {
		t.Fatalf("drain move result = %#v", moved)
	}

	assertDrainExistingOverride(t, client, builder, key)
	assertHeartbeatAction(t, store, key, oldSessionID, ControlActionNone)
	assertOpenDrainSessionShard(t, store, key, newSessionID)

	if _, err := store.CloseSession(context.Background(), key, oldSessionID); err != nil {
		t.Fatalf("CloseSession old returned error: %v", err)
	}

	if _, err := store.CloseSession(context.Background(), key, newSessionID); err != nil {
		t.Fatalf("CloseSession new returned error: %v", err)
	}
}

// assertDrainExistingOverride verifies the audited override fields for a drain split.
func assertDrainExistingOverride(t *testing.T, client *redis.Client, builder KeyBuilder, key AffinityKey) {
	t.Helper()

	keys, err := builder.AffinityKeys(key.Tenant, key.AccountKey)
	if err != nil {
		t.Fatalf("AffinityKeys returned error: %v", err)
	}

	override := client.HGetAll(context.Background(), keys.Override).Val()
	if override["strategy"] != moveStrategyDrainExisting || override["target_shard"] != testShardB {
		t.Fatalf("override = %#v, want drain_existing target", override)
	}
}

// assertHeartbeatAction verifies one session heartbeat control decision.
func assertHeartbeatAction(
	t *testing.T,
	store *RedisSessionStore,
	key AffinityKey,
	sessionID string,
	want ControlAction,
) {
	t.Helper()

	heartbeat, err := store.HeartbeatSession(context.Background(), key, sessionID, time.Second)
	if err != nil {
		t.Fatalf("HeartbeatSession returned error: %v", err)
	}

	if heartbeat.ControlAction != want {
		t.Fatalf("heartbeat action = %q, want %q", heartbeat.ControlAction, want)
	}
}

// assertOpenDrainSessionShard verifies a new drain-split session uses the target shard.
func assertOpenDrainSessionShard(t *testing.T, store *RedisSessionStore, key AffinityKey, sessionID string) {
	t.Helper()

	newRecord := testSessionRecord(key, sessionID)
	newRecord.ShardTag = testShardB

	newAffinity, err := store.OpenSession(context.Background(), newRecord)
	if err != nil {
		t.Fatalf("OpenSession during drain_existing returned error: %v", err)
	}

	if newAffinity.ShardTag != testShardB {
		t.Fatalf("new drain session shard = %q, want %q", newAffinity.ShardTag, testShardB)
	}
}

// TestRedisHardMaintenanceMarksBackendSessions verifies hard maintenance bulk control.
func TestRedisHardMaintenanceMarksBackendSessions(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	firstKey := AffinityKey{Tenant: "blue", AccountKey: "hard-maintenance-a@example.test"}
	secondKey := AffinityKey{Tenant: "blue", AccountKey: "hard-maintenance-b@example.test"}
	backendID := testBackendIMAP

	cleanupAffinity(t, client, builder, firstKey, "hard-session-a")
	cleanupAffinity(t, client, builder, secondKey, "hard-session-b")
	cleanupBackend(t, client, builder, backendID)

	openAttachedSession(t, store, firstKey, "hard-session-a", backendID)
	openAttachedSession(t, store, secondKey, "hard-session-b", backendID)

	runtimeSet, err := store.SetBackendRuntime(context.Background(), BackendRuntimeMutation{
		BackendIdentifier: backendID,
		MaintenanceMode:   "hard",
		Reason:            "hard maintenance",
	})
	if err != nil {
		t.Fatalf("SetBackendRuntime hard maintenance returned error: %v", err)
	}

	if runtimeSet.MarkedSessionCount != 2 {
		t.Fatalf("marked sessions = %d, want 2", runtimeSet.MarkedSessionCount)
	}

	for _, item := range []struct {
		key       AffinityKey
		sessionID string
	}{
		{key: firstKey, sessionID: "hard-session-a"},
		{key: secondKey, sessionID: "hard-session-b"},
	} {
		heartbeat, err := store.HeartbeatSession(context.Background(), item.key, item.sessionID, time.Second)
		if err != nil {
			t.Fatalf("HeartbeatSession %s returned error: %v", item.sessionID, err)
		}

		if heartbeat.ControlAction != ControlActionDrain {
			t.Fatalf("heartbeat action %s = %q, want drain", item.sessionID, heartbeat.ControlAction)
		}
	}
}

// TestRedisHealthOwnershipAndFencing verifies owner lease renewal and stale write rejection.
func TestRedisHealthOwnershipAndFencing(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	backendID := testBackendIMAP
	instanceA := "director-health-a"
	instanceB := "director-health-b"

	cleanupHealth(t, client, builder, backendID, instanceA, instanceB)
	publishTestInstanceHeartbeat(t, store, instanceA)

	ownerA := acquireTestHealthOwner(t, store, instanceA, backendID, 75*time.Millisecond)
	if !ownerA.Owned || ownerA.FencingToken <= 0 {
		t.Fatalf("owner A = %#v, want owned with token", ownerA)
	}

	renewed := renewTestHealthOwner(t, store, instanceA, backendID, ownerA.FencingToken, 75*time.Millisecond)
	if renewed.FencingToken != ownerA.FencingToken {
		t.Fatalf("renew token = %d, want %d", renewed.FencingToken, ownerA.FencingToken)
	}

	publishTestInstanceHeartbeat(t, store, instanceB)
	time.Sleep(120 * time.Millisecond)

	ownerB := acquireTestHealthOwner(t, store, instanceB, backendID, time.Second)
	if !ownerB.Owned || ownerB.FencingToken <= ownerA.FencingToken {
		t.Fatalf("owner B = %#v, want newer fencing token after takeover", ownerB)
	}

	assertStaleHealthPublishRejected(t, store, instanceA, backendID, ownerA.FencingToken)

	published := publishTestHealthState(t, store, instanceB, backendID, ownerB.FencingToken)
	if published.Status != backend.HealthStatusHealthy || published.Generation == "" || !published.Capabilities.Has("CHUNKING") {
		t.Fatalf("published health = %#v", published)
	}
}

// publishTestInstanceHeartbeat records an integration-test instance heartbeat.
func publishTestInstanceHeartbeat(t *testing.T, store *RedisSessionStore, instanceID string) {
	t.Helper()

	if err := store.PublishInstanceHeartbeat(context.Background(), instanceID, time.Second); err != nil {
		t.Fatalf("PublishInstanceHeartbeat %s returned error: %v", instanceID, err)
	}
}

// acquireTestHealthOwner acquires a health-owner lease for integration tests.
func acquireTestHealthOwner(t *testing.T, store *RedisSessionStore, instanceID string, backendID string, ttl time.Duration) HealthOwnershipRecord {
	t.Helper()

	owner, err := store.AcquireHealthOwner(context.Background(), HealthOwnershipRequest{
		InstanceID:        instanceID,
		BackendIdentifier: backendID,
		LeaseTTL:          ttl,
	})
	if err != nil {
		t.Fatalf("AcquireHealthOwner %s returned error: %v", instanceID, err)
	}

	return owner
}

// renewTestHealthOwner renews a health-owner lease for integration tests.
func renewTestHealthOwner(t *testing.T, store *RedisSessionStore, instanceID string, backendID string, token int64, ttl time.Duration) HealthOwnershipRecord {
	t.Helper()

	owner, err := store.RenewHealthOwner(context.Background(), HealthOwnershipRequest{
		InstanceID:        instanceID,
		BackendIdentifier: backendID,
		LeaseTTL:          ttl,
		FencingToken:      token,
	})
	if err != nil {
		t.Fatalf("RenewHealthOwner %s returned error: %v", instanceID, err)
	}

	return owner
}

// assertStaleHealthPublishRejected verifies fenced stale health writes fail closed.
func assertStaleHealthPublishRejected(t *testing.T, store *RedisSessionStore, instanceID string, backendID string, token int64) {
	t.Helper()

	_, err := store.PublishHealthState(context.Background(), HealthPublishRequest{
		InstanceID:        instanceID,
		BackendIdentifier: backendID,
		FencingToken:      token,
		State: backend.HealthState{
			Enabled:      true,
			Status:       backend.HealthStatusHealthy,
			Capabilities: backend.NewCapabilitySet("CHUNKING"),
		},
		TTL: time.Second,
	})
	if !IsRedisErrorKind(err, RedisErrorKindAmbiguousState) {
		t.Fatalf("stale PublishHealthState error = %v, want ambiguous_state", err)
	}
}

// publishTestHealthState publishes a healthy integration-test health record.
func publishTestHealthState(t *testing.T, store *RedisSessionStore, instanceID string, backendID string, token int64) backend.HealthState {
	t.Helper()

	published, err := store.PublishHealthState(context.Background(), HealthPublishRequest{
		InstanceID:        instanceID,
		BackendIdentifier: backendID,
		FencingToken:      token,
		State: backend.HealthState{
			Enabled:      true,
			Status:       backend.HealthStatusHealthy,
			Capabilities: backend.NewCapabilitySet("CHUNKING"),
		},
		TTL: time.Second,
	})
	if err != nil {
		t.Fatalf("PublishHealthState %s returned error: %v", instanceID, err)
	}

	return published
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

// redisHashTag extracts a Redis Cluster hash tag from a key fixture.
func redisHashTag(t *testing.T, key string) string {
	t.Helper()

	start := strings.Index(key, "{")

	end := strings.Index(key, "}")
	if start < 0 || end <= start {
		t.Fatalf("key %q has no hash tag", key)
	}

	return key[start : end+1]
}

// assertAffinityOwnedScriptKeys verifies a wrapper key list stays in one affinity slot.
func assertAffinityOwnedScriptKeys(t *testing.T, store *RedisSessionStore, operation string, keys []string) {
	t.Helper()

	if err := store.validateScriptKeys(operation, keys); err != nil {
		t.Fatalf("validateScriptKeys(%s, %#v) returned error: %v", operation, keys, err)
	}

	hashTag := ""

	for _, key := range keys {
		if strings.Contains(key, ":idx:") || strings.Contains(key, ":runtime:backend:") {
			t.Fatalf("%s key list includes secondary or backend key: %#v", operation, keys)
		}

		current := redisHashTag(t, key)
		if hashTag == "" {
			hashTag = current

			continue
		}

		if current != hashTag {
			t.Fatalf("%s key %q hash tag = %q, want %q", operation, key, current, hashTag)
		}
	}
}

// replaceScriptField clones a flat script response with one field changed.
func replaceScriptField(t *testing.T, fields []any, name string, value any) []any {
	t.Helper()

	replaced := append([]any{}, fields...)
	for index := 0; index < len(replaced)-1; index += 2 {
		if replaced[index] == name {
			replaced[index+1] = value

			return replaced
		}
	}

	t.Fatalf("script field %q not found in %#v", name, fields)

	return nil
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

	heartbeat, err := store.HeartbeatSession(context.Background(), key, testSessionOne, 3*time.Second)
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
	return redisIntegrationStoreWithOptions(t)
}

// redisIntegrationStoreWithOptions creates a store with caller-provided options.
func redisIntegrationStoreWithOptions(t *testing.T, options ...RedisSessionStoreOption) (*RedisSessionStore, *redis.Client, KeyBuilder) {
	t.Helper()

	addr := os.Getenv("NAUTHILUS_DIRECTOR_REDIS_ADDR")
	if addr == "" {
		addr = os.Getenv("REDIS_ADDR")
	}

	if addr == "" {
		addr = packageRedisAddr
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

	store, err := NewRedisSessionStore(client, builder, nil, options...)
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

	userSessionIndexes, err := builder.UserSessionIndexShardKeys(key.Tenant, key.AccountKey)
	if err != nil {
		t.Fatalf("UserSessionIndexShardKeys returned error: %v", err)
	}

	redisKeys = append(redisKeys, userSessionIndexes...)

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
		for _, sessionID := range sessionIDs {
			sessionIndexKey, err := builder.SessionIndexShardKey(sessionID)
			if err != nil {
				t.Fatalf("SessionIndexShardKey returned error: %v", err)
			}

			if err := client.HDel(context.Background(), sessionIndexKey, sessionID).Err(); err != nil {
				t.Fatalf("cleanup session index: %v", err)
			}

			sessionDueIndexKey, err := builder.SessionDueIndexShardKey(sessionID)
			if err != nil {
				t.Fatalf("SessionDueIndexShardKey returned error: %v", err)
			}

			if err := client.ZRem(context.Background(), sessionDueIndexKey, sessionID).Err(); err != nil {
				t.Fatalf("cleanup session due index: %v", err)
			}
		}
	}

	affinityHash, err := builder.AffinityHash(key.Tenant, key.AccountKey)
	if err != nil {
		t.Fatalf("AffinityHash returned error: %v", err)
	}

	userIndexKey, err := builder.UserIndexShardKey(affinityHash)
	if err != nil {
		t.Fatalf("UserIndexShardKey returned error: %v", err)
	}

	if err := client.HDel(context.Background(), userIndexKey, affinityHash).Err(); err != nil {
		t.Fatalf("cleanup user index: %v", err)
	}
}

// cleanupBackend deletes one backend runtime state and membership index.
func cleanupBackend(t *testing.T, client *redis.Client, builder KeyBuilder, backendID string) {
	t.Helper()

	backendKey, err := builder.BackendRuntimeKey(backendID)
	if err != nil {
		t.Fatalf("BackendRuntimeKey returned error: %v", err)
	}

	backendSessionsKeys, err := builder.BackendSessionIndexShardKeys(backendID)
	if err != nil {
		t.Fatalf("BackendSessionIndexShardKeys returned error: %v", err)
	}

	reservationKeys, err := builder.BackendReservationKeys(backendID)
	if err != nil {
		t.Fatalf("BackendReservationKeys returned error: %v", err)
	}

	redisKeys := append([]string{backendKey, reservationKeys.State, reservationKeys.Due}, backendSessionsKeys...)
	if err := client.Del(context.Background(), redisKeys...).Err(); err != nil {
		t.Fatalf("cleanup backend keys: %v", err)
	}

	if err := client.SRem(context.Background(), builder.BackendIndexKey(), backendID).Err(); err != nil {
		t.Fatalf("cleanup backend index: %v", err)
	}
}

// runtimeDimensionCount returns one aggregate dimension count from a summary list.
func runtimeDimensionCount(counts []RuntimeDimensionCount, value string) int {
	for _, count := range counts {
		if count.Value == value {
			return count.Count
		}
	}

	return 0
}

// runtimeBackendCapacity returns one backend capacity summary or a zero value.
func runtimeBackendCapacity(summaries []RuntimeBackendCapacitySummary, backendID string) RuntimeBackendCapacitySummary {
	for _, summary := range summaries {
		if summary.BackendIdentifier == backendID {
			return summary
		}
	}

	return RuntimeBackendCapacitySummary{}
}

// aggregateHashField reads one raw aggregate hash field for underflow assertions.
func aggregateHashField(t *testing.T, store *RedisSessionStore, key string, field string) string {
	t.Helper()

	value, err := store.client.HGet(context.Background(), key, field).Result()
	if errors.Is(err, redis.Nil) {
		return ""
	}

	if err != nil {
		t.Fatalf("read aggregate field: %v", err)
	}

	return value
}

// cleanupHealth deletes one backend health state and instance heartbeat keys.
func cleanupHealth(t *testing.T, client *redis.Client, builder KeyBuilder, backendID string, instanceIDs ...string) {
	t.Helper()

	ownerKey, err := builder.HealthOwnerKey(backendID)
	if err != nil {
		t.Fatalf("HealthOwnerKey returned error: %v", err)
	}

	stateKey, err := builder.HealthStateKey(backendID)
	if err != nil {
		t.Fatalf("HealthStateKey returned error: %v", err)
	}

	keys := []string{ownerKey, stateKey}

	for _, instanceID := range instanceIDs {
		instanceKey, err := builder.InstanceKey(instanceID)
		if err != nil {
			t.Fatalf("InstanceKey returned error: %v", err)
		}

		keys = append(keys, instanceKey)
	}

	if err := client.Del(context.Background(), keys...).Err(); err != nil {
		t.Fatalf("cleanup health keys: %v", err)
	}
}

// redisBackendActiveCount reads the Redis-coordinated active session count.
func redisBackendActiveCount(t *testing.T, client *redis.Client, builder KeyBuilder, backendID string) int {
	t.Helper()

	reservationKeys, err := builder.BackendReservationKeys(backendID)
	if err != nil {
		t.Fatalf("BackendReservationKeys returned error: %v", err)
	}

	count, err := client.HGet(context.Background(), reservationKeys.State, scriptFieldActiveSessionCount).Int()
	if err != nil && !errors.Is(err, redis.Nil) {
		t.Fatalf("read backend active count: %v", err)
	}

	return count
}

// reserveBackendForTest reserves one backend capacity slot for an integration fixture.
func reserveBackendForTest(t *testing.T, store *RedisSessionStore, backendID string, reservationID string, maxConnections int) BackendReservationRecord {
	t.Helper()

	record, err := store.ReserveBackendCapacity(context.Background(), BackendReservationRequest{
		BackendIdentifier: backendID,
		ReservationID:     reservationID,
		MaxConnections:    maxConnections,
		LeaseTTL:          time.Second,
	})
	if err != nil {
		t.Fatalf("ReserveBackendCapacity returned error: %v", err)
	}

	return record
}

// assertBackendReservationCount verifies the active count on a reservation result.
func assertBackendReservationCount(t *testing.T, record BackendReservationRecord, want int, label string) {
	t.Helper()

	if record.BackendActiveCount != want {
		t.Fatalf("%s count = %d, want %d", label, record.BackendActiveCount, want)
	}
}

// assertBackendReservationCapacityFull verifies a backend slot fails closed at capacity.
func assertBackendReservationCapacityFull(t *testing.T, store *RedisSessionStore, backendID string, reservationID string) {
	t.Helper()

	_, err := store.ReserveBackendCapacity(context.Background(), BackendReservationRequest{
		BackendIdentifier: backendID,
		ReservationID:     reservationID,
		MaxConnections:    2,
		LeaseTTL:          time.Second,
	})
	if !IsRedisErrorKind(err, RedisErrorKindAmbiguousState) {
		t.Fatalf("reservation at capacity error = %v, want ambiguous_state", err)
	}
}

// assertBackendReservationRelease verifies release count and idempotency semantics.
func assertBackendReservationRelease(
	t *testing.T,
	store *RedisSessionStore,
	backendID string,
	reservationID string,
	wantActive int,
	wantRepaired int,
	label string,
) {
	t.Helper()

	released, err := store.ReleaseBackendReservation(context.Background(), BackendReservationReleaseRequest{
		BackendIdentifier: backendID,
		ReservationID:     reservationID,
	})
	if err != nil {
		t.Fatalf("%s ReleaseBackendReservation returned error: %v", label, err)
	}

	if released.BackendActiveCount != wantActive || released.RepairedCount != wantRepaired {
		t.Fatalf("%s release result = %#v, want count %d and repaired %d", label, released, wantActive, wantRepaired)
	}
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

	reservation := reserveBackendForTest(t, store, backendID, sessionID, 10)

	if _, err := store.AttachSelectedBackend(context.Background(), SessionBackendAttachment{
		Key:               key,
		SessionID:         sessionID,
		BackendIdentifier: backendID,
		ReservationID:     reservation.ReservationID,
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
		ListenerName:       testListenerIMAPS,
		ServiceName:        testProtocolIMAP,
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

type recordingStateObservability struct {
	events []observability.Event
}

// Record stores one Redis state observation for assertions.
func (r *recordingStateObservability) Record(_ context.Context, event observability.Event) {
	r.events = append(r.events, event)
}

// last returns the latest state observation with the supplied event name.
func (r *recordingStateObservability) last(name string) (observability.Event, bool) {
	for index := len(r.events) - 1; index >= 0; index-- {
		if r.events[index].Name == name {
			return r.events[index], true
		}
	}

	return observability.Event{}, false
}
