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

package app

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/redis/go-redis/v9"
)

const (
	redisTestClusterAddress  = "redis-cluster.example.test:6379"
	redisTestFailoverAddress = "FailoverClient"
)

// TestNewRedisClientCreatesClusterClientForSingleSeed verifies cluster mode does not fall back to standalone.
func TestNewRedisClientCreatesClusterClientForSingleSeed(t *testing.T) {
	cfg := redisClientTestConfig(t)
	cfg.Mode = redisModeCluster
	cfg.Cluster.Addresses = []string{redisTestClusterAddress}
	cfg.Cluster.MaxRedirects = 13

	client, err := newRedisClient(cfg)
	if err != nil {
		t.Fatalf("newRedisClient returned error: %v", err)
	}
	defer closeRedisClient(t, client)

	clusterClient, ok := client.(*redis.ClusterClient)
	if !ok {
		t.Fatalf("client type = %T, want *redis.ClusterClient", client)
	}

	options := clusterClient.Options()
	if !slices.Equal(options.Addrs, cfg.Cluster.Addresses) {
		t.Fatalf("cluster addrs = %v, want %v", options.Addrs, cfg.Cluster.Addresses)
	}

	if options.MaxRedirects != cfg.Cluster.MaxRedirects {
		t.Fatalf("cluster max redirects = %d, want %d", options.MaxRedirects, cfg.Cluster.MaxRedirects)
	}
}

// TestNewRedisClientPropagatesClusterReplicaReadOptions verifies read-only routing reaches go-redis cluster options.
func TestNewRedisClientPropagatesClusterReplicaReadOptions(t *testing.T) {
	cfg := redisClientTestConfig(t)
	cfg.Mode = redisModeCluster
	cfg.Cluster.RouteReadsToReplicas = true
	cfg.Cluster.RouteByLatency = true

	client, err := newRedisClient(cfg)
	if err != nil {
		t.Fatalf("newRedisClient returned error: %v", err)
	}
	defer closeRedisClient(t, client)

	clusterClient, ok := client.(*redis.ClusterClient)
	if !ok {
		t.Fatalf("client type = %T, want *redis.ClusterClient", client)
	}

	options := clusterClient.Options()
	if !options.ReadOnly || !options.RouteByLatency {
		t.Fatalf("cluster replica-read flags = route_reads_to_replicas:%t route_by_latency:%t, want both true", options.ReadOnly, options.RouteByLatency)
	}
}

// TestNewRedisClientCreatesStandaloneClientFromStandaloneMode verifies inactive cluster seeds do not select cluster topology.
func TestNewRedisClientCreatesStandaloneClientFromStandaloneMode(t *testing.T) {
	cfg := redisClientTestConfig(t)
	cfg.Mode = redisModeStandalone
	cfg.Cluster.Addresses = []string{"redis-cluster-a.example.test:6379", "redis-cluster-b.example.test:6379"}
	cfg.Cluster.RouteRandomly = true

	client, err := newRedisClient(cfg)
	if err != nil {
		t.Fatalf("newRedisClient returned error: %v", err)
	}
	defer closeRedisClient(t, client)

	standaloneClient, ok := client.(*redis.Client)
	if !ok {
		t.Fatalf("client type = %T, want *redis.Client", client)
	}

	if standaloneClient.Options().Addr != cfg.Standalone.Address {
		t.Fatalf("standalone addr = %q, want %q", standaloneClient.Options().Addr, cfg.Standalone.Address)
	}
}

// TestNewRedisClientCreatesFailoverClientWithoutClusterRouteFlags verifies sentinel mode ignores inactive cluster routing.
func TestNewRedisClientCreatesFailoverClientWithoutClusterRouteFlags(t *testing.T) {
	cfg := redisClientTestConfig(t)
	cfg.Mode = redisModeSentinel
	cfg.Cluster.RouteReadsToReplicas = true
	cfg.Cluster.RouteByLatency = true
	cfg.Cluster.RouteRandomly = true

	client, err := newRedisClient(cfg)
	if err != nil {
		t.Fatalf("newRedisClient returned error: %v", err)
	}
	defer closeRedisClient(t, client)

	if _, ok := client.(*redis.ClusterClient); ok {
		t.Fatalf("client type = %T, want sentinel failover client", client)
	}

	failoverClient, ok := client.(*redis.Client)
	if !ok {
		t.Fatalf("client type = %T, want *redis.Client", client)
	}

	if failoverClient.Options().Addr != redisTestFailoverAddress {
		t.Fatalf("sentinel client addr = %q, want failover marker", failoverClient.Options().Addr)
	}
}

// TestNewRedisClientReadsPasswordFiles verifies file-backed Redis secrets reach go-redis options.
func TestNewRedisClientReadsPasswordFiles(t *testing.T) {
	cfg := redisClientTestConfig(t)
	cfg.Mode = redisModeSentinel

	common, err := newRedisCommonOptions(cfg)
	if err != nil {
		t.Fatalf("newRedisCommonOptions returned error: %v", err)
	}

	if common.password != "redis-password" {
		t.Fatalf("redis password = %q, want file content", common.password)
	}

	if common.password == cfg.Auth.PasswordFile.Value() {
		t.Fatal("redis password used the password_file path string")
	}

	options := common.failoverOptions(cfg)
	if options.SentinelPassword != "sentinel-password" {
		t.Fatalf("sentinel password = %q, want file content", options.SentinelPassword)
	}

	if options.SentinelPassword == cfg.Sentinel.PasswordFile.Value() {
		t.Fatal("sentinel password used the password_file path string")
	}
}

// TestNewRedisClientFailsClosedOnMissingPasswordFile rejects broken secret refs.
func TestNewRedisClientFailsClosedOnMissingPasswordFile(t *testing.T) {
	cfg := redisClientTestConfig(t)
	cfg.Auth.PasswordFile = config.Secret(filepath.Join(t.TempDir(), "missing"))

	_, err := newRedisClient(cfg)
	if err == nil {
		t.Fatal("newRedisClient accepted missing redis password_file")
	}
}

// redisClientTestConfig returns a Redis config that can build clients without opening sockets.
func redisClientTestConfig(t *testing.T) config.RedisConfig {
	t.Helper()

	cfg := config.DefaultConfig().Storage.Redis
	cfg.TLS.Enabled = false
	cfg.PoolSize = 1
	cfg.MinIdleConnections = 0
	cfg.Standalone.Address = "redis-standalone.example.test:6379"
	cfg.Cluster.Addresses = []string{redisTestClusterAddress}
	cfg.Sentinel.MasterName = "mailstore"
	cfg.Sentinel.Addresses = []string{"redis-sentinel.example.test:26379"}
	cfg.Auth.PasswordFile = config.Secret(writeRedisSecretFile(t, "redis-password\n"))
	cfg.Sentinel.PasswordFile = config.Secret(writeRedisSecretFile(t, "sentinel-password\n"))

	return cfg
}

// writeRedisSecretFile writes one Redis secret test file.
func writeRedisSecretFile(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write Redis secret file: %v", err)
	}

	return path
}

// closeRedisClient closes a constructed Redis client and fails the test on cleanup errors.
func closeRedisClient(t *testing.T, client redis.UniversalClient) {
	t.Helper()

	if err := client.Close(); err != nil {
		t.Fatalf("close Redis client: %v", err)
	}
}
