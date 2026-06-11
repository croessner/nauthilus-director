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
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/state"
	"github.com/redis/go-redis/v9"
)

const (
	redisModeStandalone = "standalone"
	redisModeCluster    = "cluster"
	redisModeSentinel   = "sentinel"
)

// newRedisClient creates the configured Redis topology client.
func newRedisClient(cfg config.RedisConfig) (redis.UniversalClient, error) {
	common, err := newRedisCommonOptions(cfg)
	if err != nil {
		return nil, err
	}

	switch redisMode(cfg.Mode) {
	case redisModeStandalone:
		return redis.NewClient(common.standaloneOptions(cfg)), nil
	case redisModeCluster:
		return redis.NewClusterClient(common.clusterOptions(cfg)), nil
	case redisModeSentinel:
		return redis.NewFailoverClient(common.failoverOptions(cfg)), nil
	default:
		return nil, fmt.Errorf("unsupported Redis mode %q", cfg.Mode)
	}
}

// redisCommonOptions carries mode-independent Redis client settings.
type redisCommonOptions struct {
	databaseNumber     int
	protocol           int
	username           string
	password           string
	maxRetries         int
	minRetryBackoff    config.Duration
	maxRetryBackoff    config.Duration
	dialTimeout        config.Duration
	readTimeout        config.Duration
	writeTimeout       config.Duration
	poolSize           int
	poolTimeout        config.Duration
	minIdleConnections int
	tlsConfig          *tls.Config
}

// newRedisCommonOptions creates mode-independent Redis client settings.
func newRedisCommonOptions(cfg config.RedisConfig) (redisCommonOptions, error) {
	options := redisCommonOptions{
		databaseNumber:     cfg.DatabaseNumber,
		protocol:           cfg.Protocol,
		username:           cfg.Auth.Username,
		password:           cfg.Auth.PasswordFile.Value(),
		maxRetries:         cfg.Retries.MaxAttempts,
		minRetryBackoff:    cfg.Retries.MinBackoff,
		maxRetryBackoff:    cfg.Retries.MaxBackoff,
		dialTimeout:        cfg.DialTimeout,
		readTimeout:        cfg.ReadTimeout,
		writeTimeout:       cfg.WriteTimeout,
		poolSize:           cfg.PoolSize,
		poolTimeout:        cfg.PoolTimeout,
		minIdleConnections: cfg.MinIdleConnections,
	}

	if cfg.TLS.Enabled {
		tlsConfig, err := redisTLSConfig(cfg.TLS)
		if err != nil {
			return redisCommonOptions{}, err
		}

		options.tlsConfig = tlsConfig
	}

	return options, nil
}

// standaloneOptions returns the go-redis options for a standalone Redis server.
func (o redisCommonOptions) standaloneOptions(cfg config.RedisConfig) *redis.Options {
	return &redis.Options{
		Addr:            cfg.Standalone.Address,
		DB:              o.databaseNumber,
		Protocol:        o.protocol,
		Username:        o.username,
		Password:        o.password,
		MaxRetries:      o.maxRetries,
		MinRetryBackoff: o.minRetryBackoff.Std(),
		MaxRetryBackoff: o.maxRetryBackoff.Std(),
		DialTimeout:     o.dialTimeout.Std(),
		ReadTimeout:     o.readTimeout.Std(),
		WriteTimeout:    o.writeTimeout.Std(),
		PoolSize:        o.poolSize,
		PoolTimeout:     o.poolTimeout.Std(),
		MinIdleConns:    o.minIdleConnections,
		TLSConfig:       o.tlsConfig,
	}
}

// clusterOptions returns the go-redis options for Redis Cluster.
func (o redisCommonOptions) clusterOptions(cfg config.RedisConfig) *redis.ClusterOptions {
	return &redis.ClusterOptions{
		Addrs:           redisAddresses(cfg),
		Protocol:        o.protocol,
		Username:        o.username,
		Password:        o.password,
		MaxRetries:      o.maxRetries,
		MinRetryBackoff: o.minRetryBackoff.Std(),
		MaxRetryBackoff: o.maxRetryBackoff.Std(),
		DialTimeout:     o.dialTimeout.Std(),
		ReadTimeout:     o.readTimeout.Std(),
		WriteTimeout:    o.writeTimeout.Std(),
		PoolSize:        o.poolSize,
		PoolTimeout:     o.poolTimeout.Std(),
		MinIdleConns:    o.minIdleConnections,
		TLSConfig:       o.tlsConfig,
		MaxRedirects:    cfg.Cluster.MaxRedirects,
		ReadOnly:        cfg.Cluster.RouteReadsToReplicas,
		RouteByLatency:  cfg.Cluster.RouteByLatency,
		RouteRandomly:   cfg.Cluster.RouteRandomly,
	}
}

// failoverOptions returns the go-redis options for Redis Sentinel failover.
func (o redisCommonOptions) failoverOptions(cfg config.RedisConfig) *redis.FailoverOptions {
	return &redis.FailoverOptions{
		MasterName:       cfg.Sentinel.MasterName,
		SentinelAddrs:    redisAddresses(cfg),
		DB:               o.databaseNumber,
		Protocol:         o.protocol,
		Username:         o.username,
		Password:         o.password,
		SentinelUsername: cfg.Sentinel.Username,
		SentinelPassword: cfg.Sentinel.PasswordFile.Value(),
		MaxRetries:       o.maxRetries,
		MinRetryBackoff:  o.minRetryBackoff.Std(),
		MaxRetryBackoff:  o.maxRetryBackoff.Std(),
		DialTimeout:      o.dialTimeout.Std(),
		ReadTimeout:      o.readTimeout.Std(),
		WriteTimeout:     o.writeTimeout.Std(),
		PoolSize:         o.poolSize,
		PoolTimeout:      o.poolTimeout.Std(),
		MinIdleConns:     o.minIdleConnections,
		TLSConfig:        o.tlsConfig,
	}
}

// newRedisStore creates the Redis-backed session and runtime store.
func newRedisStore(client redis.UniversalClient, cfg config.Config, recorder observability.Recorder) (*state.RedisSessionStore, error) {
	keys, err := state.NewKeyBuilder(state.KeyBuilderOptions{
		Prefix:             cfg.Storage.Redis.KeyPrefix,
		SchemaVersion:      cfg.Storage.Redis.SchemaVersion,
		SessionIndexShards: cfg.Runtime.State.Indexes.SessionShards,
		UserIndexShards:    cfg.Runtime.State.Indexes.UserShards,
		BackendIndexShards: cfg.Runtime.State.Indexes.BackendShards,
	})
	if err != nil {
		return nil, err
	}

	return state.NewRedisSessionStore(
		client,
		keys,
		nil,
		state.WithObservabilityRecorder(recorder),
		state.WithRedisMode(cfg.Storage.Redis.Mode),
		state.WithRuntimeIndexPages(cfg.Runtime.State.Indexes.PageDefault, cfg.Runtime.State.Indexes.PageMax),
	)
}

// pingRedis verifies that the central runtime state backend is reachable.
func pingRedis(ctx context.Context, client redis.UniversalClient, cfg config.RedisConfig) error {
	if client == nil {
		return fmt.Errorf("redis client is required")
	}

	pingCtx, cancel := context.WithTimeout(ctx, cfg.Health.Timeout.Std())
	defer cancel()

	if err := client.Ping(pingCtx).Err(); err != nil {
		return fmt.Errorf("redis ping failed: %w", err)
	}

	return nil
}

// redisAddresses selects the configured Redis seed addresses for the active topology.
func redisAddresses(cfg config.RedisConfig) []string {
	switch redisMode(cfg.Mode) {
	case redisModeCluster:
		return append([]string(nil), cfg.Cluster.Addresses...)
	case redisModeSentinel:
		return append([]string(nil), cfg.Sentinel.Addresses...)
	default:
		return []string{cfg.Standalone.Address}
	}
}

// redisMode returns the canonical Redis topology mode name.
func redisMode(mode string) string {
	return strings.ToLower(strings.TrimSpace(mode))
}

// redisTLSConfig builds Redis TLS settings from typed config.
func redisTLSConfig(cfg config.RedisTLSConfig) (*tls.Config, error) {
	minVersion, err := redisTLSMinVersion(cfg.MinTLSVersion)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		MinVersion:         minVersion,
		ServerName:         strings.TrimSpace(cfg.ServerName),
	}

	if strings.TrimSpace(cfg.CAFile) != "" {
		pemBytes, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("load Redis CA: %w", err)
		}

		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("redis CA did not contain PEM certificates")
		}

		tlsConfig.RootCAs = pool
	}

	if strings.TrimSpace(cfg.Cert) != "" || !cfg.Key.IsZero() {
		certificate, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key.Value())
		if err != nil {
			return nil, fmt.Errorf("load Redis TLS certificate: %w", err)
		}

		tlsConfig.Certificates = []tls.Certificate{certificate}
	}

	return tlsConfig, nil
}

// redisTLSMinVersion converts Redis TLS config into Go constants.
func redisTLSMinVersion(version string) (uint16, error) {
	switch strings.ToUpper(strings.TrimSpace(version)) {
	case "", tlsVersion12Name, tlsVersion12Compact, tlsVersion12Symbol:
		return tls.VersionTLS12, nil
	case tlsVersion13Name, tlsVersion13Compact, tlsVersion13Symbol:
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported Redis TLS minimum version %q", version)
	}
}
