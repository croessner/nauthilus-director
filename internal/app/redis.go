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

// newRedisClient creates the configured Redis topology client.
func newRedisClient(cfg config.RedisConfig) (redis.UniversalClient, error) {
	options := &redis.UniversalOptions{
		Addrs:            redisAddresses(cfg),
		DB:               cfg.DatabaseNumber,
		Protocol:         cfg.Protocol,
		Username:         cfg.Auth.Username,
		Password:         cfg.Auth.PasswordFile.Value(),
		SentinelUsername: cfg.Sentinel.Username,
		SentinelPassword: cfg.Sentinel.PasswordFile.Value(),
		MaxRetries:       cfg.Retries.MaxAttempts,
		MinRetryBackoff:  cfg.Retries.MinBackoff.Std(),
		MaxRetryBackoff:  cfg.Retries.MaxBackoff.Std(),
		DialTimeout:      cfg.DialTimeout.Std(),
		ReadTimeout:      cfg.ReadTimeout.Std(),
		WriteTimeout:     cfg.WriteTimeout.Std(),
		PoolSize:         cfg.PoolSize,
		PoolTimeout:      cfg.PoolTimeout.Std(),
		MinIdleConns:     cfg.MinIdleConnections,
		MaxRedirects:     cfg.Cluster.MaxRedirects,
		ReadOnly:         cfg.Cluster.ReadOnly,
		RouteByLatency:   cfg.Cluster.RouteByLatency,
		RouteRandomly:    cfg.Cluster.RouteRandomly,
		MasterName:       cfg.Sentinel.MasterName,
	}

	if cfg.TLS.Enabled {
		tlsConfig, err := redisTLSConfig(cfg.TLS)
		if err != nil {
			return nil, err
		}

		options.TLSConfig = tlsConfig
	}

	return redis.NewUniversalClient(options), nil
}

// newRedisStore creates the Redis-backed session and runtime store.
func newRedisStore(client redis.UniversalClient, cfg config.RedisConfig, recorder observability.Recorder) (*state.RedisSessionStore, error) {
	keys, err := state.NewKeyBuilder(state.KeyBuilderOptions{
		Prefix:        cfg.KeyPrefix,
		SchemaVersion: cfg.SchemaVersion,
	})
	if err != nil {
		return nil, err
	}

	return state.NewRedisSessionStore(
		client,
		keys,
		nil,
		state.WithObservabilityRecorder(recorder),
		state.WithRedisMode(cfg.Mode),
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
	switch strings.ToLower(strings.TrimSpace(cfg.Mode)) {
	case "cluster":
		return append([]string(nil), cfg.Cluster.Addresses...)
	case "sentinel":
		return append([]string(nil), cfg.Sentinel.Addresses...)
	default:
		return []string{cfg.Standalone.Address}
	}
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
