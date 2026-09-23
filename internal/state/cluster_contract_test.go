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

//nolint:funlen,goconst,gocyclo,wsl_v5 // Redis script fixtures repeat scoped payload values intentionally.
package state

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// TestRedisClusterStateOperations exercises authority mutations without a namespace-wide hash tag.
func TestRedisClusterStateOperations(t *testing.T) {
	for _, name := range []string{"health ownership", "backend override", "session kill", "session reap"} {
		t.Run(name, func(t *testing.T) {
			store := clusterContractStore(t)
			ctx := t.Context()
			switch name {
			case "health ownership":
				if err := store.PublishInstanceHeartbeat(ctx, "test-instance", time.Minute); err != nil {
					t.Fatal(err)
				}
				record, err := store.AcquireHealthOwner(ctx, HealthOwnershipRequest{InstanceID: "test-instance", BackendIdentifier: testBackendIMAP, LeaseTTL: time.Minute})
				if err != nil {
					t.Fatal(err)
				}
				if !record.Owned {
					t.Fatal("health ownership was not acquired")
				}
			case "backend override":
				enabled := true
				_, err := store.SetBackendRuntime(ctx, BackendRuntimeMutation{BackendIdentifier: testBackendIMAP, InService: &enabled, Reason: "cluster contract"})
				if err != nil {
					t.Fatal(err)
				}
			default:
				key := AffinityKey{Tenant: "cluster-test", AccountKey: "fixture@example.test"}
				record := testSessionRecord(key, "cluster-session")
				record.LeaseTTL = time.Minute
				if name == "session reap" {
					record.LeaseTTL = 20 * time.Millisecond
				}
				if _, err := store.OpenSession(ctx, record); err != nil {
					t.Fatal(err)
				}
				if name == "session kill" {
					killed, err := store.KillSession(ctx, SessionKillRequest{SessionID: "cluster-session", Reason: "cluster contract"})
					if err != nil {
						t.Fatal(err)
					}
					if killed.Status != SessionKillStatusMarked {
						t.Fatalf("kill status = %s", killed.Status)
					}
				} else {
					time.Sleep(50 * time.Millisecond)
					reaped, err := store.ReapSessions(ctx, ReapRequest{Limit: 100, MaxPassDuration: time.Second})
					if err != nil {
						t.Fatal(err)
					}
					if reaped.ExpiredSessions != 1 {
						t.Fatalf("expired sessions = %d", reaped.ExpiredSessions)
					}
				}
			}
		})
	}
}

// clusterContractStore restricts destructive test cleanup to an explicitly configured loopback cluster.
func clusterContractStore(t *testing.T) *RedisSessionStore {
	t.Helper()
	raw := os.Getenv("NAUTHILUS_DIRECTOR_TEST_CLUSTER_ADDRS")
	if raw == "" {
		t.Skip("set NAUTHILUS_DIRECTOR_TEST_CLUSTER_ADDRS to a disposable loopback Redis Cluster")
	}
	addresses := strings.Split(raw, ",")
	for _, address := range addresses {
		host, _, err := net.SplitHostPort(address)
		if err != nil || !net.ParseIP(host).IsLoopback() {
			t.Fatal("cluster contract tests require numeric loopback addresses")
		}
	}
	client := redis.NewClusterClient(&redis.ClusterOptions{Addrs: addresses})
	prefix := fmt.Sprintf("nd-cluster-test:%d", time.Now().UnixNano())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := client.ForEachMaster(ctx, func(ctx context.Context, node *redis.Client) error {
			iterator := node.Scan(ctx, 0, prefix+":*", 100).Iterator()
			for iterator.Next(ctx) {
				if err := client.Del(ctx, iterator.Val()).Err(); err != nil {
					return err
				}
			}
			return iterator.Err()
		})
		if err != nil {
			t.Errorf("cluster fixture cleanup: %v", err)
		}
		_ = client.Close()
	})
	builder, err := NewKeyBuilder(KeyBuilderOptions{Prefix: prefix, SchemaVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewRedisSessionStore(client, builder, nil)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// TestKeyBuilderRejectsNamespaceHashTags protects per-affinity distribution from prefix shadowing.
func TestKeyBuilderRejectsNamespaceHashTags(t *testing.T) {
	for _, prefix := range []string{"{nauthilus-director}", "nd:{global}", "nd:{}", "nd:{unfinished"} {
		t.Run(prefix, func(t *testing.T) {
			if _, err := NewKeyBuilder(KeyBuilderOptions{Prefix: prefix, SchemaVersion: 1}); err == nil {
				t.Fatal("namespace braces must not override authority hash tags")
			}
		})
	}
}

// TestRedisClusterReaperRechecksLease protects sessions renewed after index candidate selection.
func TestRedisClusterReaperRechecksLease(t *testing.T) {
	store := clusterContractStore(t)
	key := AffinityKey{Tenant: "cluster-test", AccountKey: "renewed@example.test"}
	sessionID := "renewed-session"
	session := testSessionRecord(key, sessionID)
	session.LeaseTTL = time.Minute
	if _, err := store.OpenSession(t.Context(), session); err != nil {
		t.Fatal(err)
	}
	index, _ := store.keys.SessionIndexShardKey(sessionID)
	due, _ := store.keys.SessionDueIndexShardKey(sessionID)
	reaped, err := store.reapIndexedSession(t.Context(), index, due, sessionID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if reaped.ExpiredSessions != 0 || reaped.nextDue <= 0 {
		t.Fatalf("live lease was not preserved: %+v", reaped)
	}
	affinity, err := store.LookupAffinity(t.Context(), key)
	if err != nil || !affinity.Present {
		t.Fatalf("live affinity lost: %+v, %v", affinity, err)
	}
}

// TestRedisClusterEmptyReaperAvoidsScripts verifies empty index shards cause no authority script calls.
func TestRedisClusterEmptyReaperAvoidsScripts(t *testing.T) {
	store := clusterContractStore(t)
	counted := &scriptCountingClient{RedisClient: store.client}
	store.client = counted
	if _, err := store.ReapSessions(t.Context(), ReapRequest{Limit: 100}); err != nil {
		t.Fatal(err)
	}
	if counted.calls != 0 {
		t.Fatalf("empty reaper executed %d scripts", counted.calls)
	}
}

// scriptCountingClient counts synchronous script dispatches without changing Redis behavior.
type scriptCountingClient struct {
	RedisClient
	calls int
}

// Eval counts uncached script execution before forwarding it to the test cluster.
func (c *scriptCountingClient) Eval(ctx context.Context, script string, keys []string, args ...any) *redis.Cmd {
	c.calls++
	return c.RedisClient.Eval(ctx, script, keys, args...)
}

// EvalSha counts cached script execution before forwarding it to the test cluster.
func (c *scriptCountingClient) EvalSha(ctx context.Context, sha string, keys []string, args ...any) *redis.Cmd {
	c.calls++
	return c.RedisClient.EvalSha(ctx, sha, keys, args...)
}

// TestRedisClusterDistributesAffinityState verifies real session authority lands on every test master.
func TestRedisClusterDistributesAffinityState(t *testing.T) {
	store := clusterContractStore(t)
	const affinityCount = 60
	for i := range affinityCount {
		key := AffinityKey{Tenant: "cluster-test", AccountKey: fmt.Sprintf("account-%d@example.test", i)}
		record := testSessionRecord(key, fmt.Sprintf("session-%d", i))
		if _, err := store.OpenSession(t.Context(), record); err != nil {
			t.Fatal(err)
		}
	}
	client := store.client.(*redis.ClusterClient)
	var mu sync.Mutex
	counts := make(map[string]int)
	err := client.ForEachMaster(t.Context(), func(ctx context.Context, node *redis.Client) error {
		count := 0
		iterator := node.Scan(ctx, 0, store.keys.namespaceBase()+":{aff:*}:state", 100).Iterator()
		for iterator.Next(ctx) {
			count++
		}
		if err := iterator.Err(); err != nil {
			return err
		}
		mu.Lock()
		counts[node.Options().Addr] = count
		mu.Unlock()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for address, count := range counts {
		if count == 0 {
			t.Fatalf("master %s received no affinity state", address)
		}
		total += count
	}
	if len(counts) != 3 || total != affinityCount {
		t.Fatalf("affinity distribution = %v", counts)
	}
	t.Logf("affinity distribution across three masters: %v", counts)
}

// TestRedisClusterReaperPreservesReplacedLocator protects a newer registration during delayed index cleanup.
func TestRedisClusterReaperPreservesReplacedLocator(t *testing.T) {
	store := clusterContractStore(t)
	sessionID := "replaced-session"
	index, _ := store.keys.SessionIndexShardKey(sessionID)
	due, _ := store.keys.SessionDueIndexShardKey(sessionID)
	oldKey, _ := store.keys.SessionKey("cluster-test", "old@example.test", sessionID)
	newKey, _ := store.keys.SessionKey("cluster-test", "new@example.test", sessionID)
	if err := store.client.HSet(t.Context(), index, sessionID, newKey).Err(); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Minute).UnixMilli()
	if err := store.client.ZAdd(t.Context(), due, redis.Z{Score: float64(future), Member: sessionID}).Err(); err != nil {
		t.Fatal(err)
	}
	old := ReapRecord{ExpiredSessions: 1, ServerTime: time.Now(), sessionKey: oldKey}
	if err := store.removeReapedIndexes(t.Context(), index, due, sessionID, old); err != nil {
		t.Fatal(err)
	}
	if got := store.client.HGet(t.Context(), index, sessionID).Val(); got != newKey {
		t.Fatal("delayed cleanup removed a newer locator")
	}
	if got := store.client.ZScore(t.Context(), due, sessionID).Val(); got != float64(future) {
		t.Fatal("delayed cleanup removed a newer due entry")
	}
}

// TestRedisClusterSlotFunctionMatchesServer proves the local slot function equals CLUSTER KEYSLOT.
func TestRedisClusterSlotFunctionMatchesServer(t *testing.T) {
	store := clusterContractStore(t)
	keys := []string{store.keys.BackendIndexKey(), store.keys.AggregateRepairKey()}
	for _, backendID := range []string{testBackendIMAP, testBackendLMTP, "sink-imap"} {
		for bucket := range store.keys.BackendReservationBucketCount() {
			group, _ := store.keys.BackendReservationBucketKeys(backendID, bucket)
			keys = append(keys, group.State, group.Due)
		}
		legacy, _ := store.keys.LegacyBackendReservationKeys(backendID)
		owner, _ := store.keys.HealthOwnerKey(backendID)
		health, _ := store.keys.HealthStateKey(backendID)
		legacyHealth, _ := store.keys.LegacyHealthStateKey(backendID)
		keys = append(keys, legacy.State, owner, health, legacyHealth)
	}
	for _, group := range append(store.keys.AggregateKeyGroups(), store.keys.LegacyAggregateKeys()) {
		keys = append(keys, append(group.sessionScriptKeys(), group.IdleAffinities)...)
	}
	for _, key := range keys {
		want, err := store.client.ClusterKeySlot(t.Context(), key).Result()
		if err != nil {
			t.Fatal(err)
		}
		if got := redisClusterSlot(key); int64(got) != want {
			t.Fatalf("slot(%q) = %d, server = %d", key, got, want)
		}
	}
}

// TestRedisClusterBucketedStateOperations runs every bucketed and mixed-version contract through real Cluster routing.
func TestRedisClusterBucketedStateOperations(t *testing.T) {
	for name, exercise := range map[string]func(*testing.T, *RedisSessionStore, redis.Cmdable){
		"rolling reservations": exerciseRollingUpgradeReservations,
		"rolling aggregates":   exerciseRollingUpgradeAggregates,
		"rolling health":       exerciseRollingUpgradeHealth,
		"capacity race":        exerciseReservationCapacityRace,
	} {
		t.Run(name, func(t *testing.T) {
			store := clusterContractStore(t)
			exercise(t, store, store.client)
		})
	}
}

// TestRedisClusterDistributesBucketedState verifies one busy backend's state reaches every master evenly.
func TestRedisClusterDistributesBucketedState(t *testing.T) {
	store := clusterContractStore(t)
	const sessions = 120
	for i := range sessions {
		key := AffinityKey{Tenant: "cluster-test", AccountKey: fmt.Sprintf("bucket-%d@example.test", i)}
		sessionID := fmt.Sprintf("bucket-session-%03d", i)
		if _, err := store.OpenSession(t.Context(), testSessionRecord(key, sessionID)); err != nil {
			t.Fatal(err)
		}
		reservation, err := store.ReserveBackendCapacity(t.Context(), BackendReservationRequest{BackendIdentifier: "sink-imap", ReservationID: sessionID, MaxConnections: 1000, LeaseTTL: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.AttachSelectedBackend(t.Context(), SessionBackendAttachment{Key: key, SessionID: sessionID, BackendIdentifier: "sink-imap", BackendNode: testBackendNodeA, ReservationID: reservation.ReservationID, MaxConnections: 1000}); err != nil {
			t.Fatal(err)
		}
	}
	client := store.client.(*redis.ClusterClient)
	var mu sync.Mutex
	counts := make(map[string][2]int)
	err := client.ForEachMaster(t.Context(), func(ctx context.Context, node *redis.Client) error {
		var found [2]int
		for index, pattern := range []string{":{backend:*}:runtime:backend:sink-imap:reservations", ":{agg:*}:runtime:aggregates:sessions"} {
			iterator := node.Scan(ctx, 0, store.keys.namespaceBase()+pattern, 100).Iterator()
			for iterator.Next(ctx) {
				found[index]++
			}
			if err := iterator.Err(); err != nil {
				return err
			}
		}
		mu.Lock()
		counts[node.Options().Addr] = found
		mu.Unlock()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(counts) != 3 {
		t.Fatalf("masters = %v", counts)
	}
	for address, found := range counts {
		if found[0] != store.keys.BackendReservationBucketCount()/3 || found[1] != store.keys.AggregateBucketCount()/3 {
			t.Fatalf("master %s holds %d reservation buckets and %d aggregate groups, want an equal third: %v", address, found[0], found[1], counts)
		}
	}
	total, err := store.backendReservationActiveCount(t.Context(), "sink-imap")
	if err != nil || total != sessions {
		t.Fatalf("backend-wide reservations = %d, %v; want %d", total, err, sessions)
	}
	t.Logf("reservation buckets / aggregate groups per master: %v", counts)
}
