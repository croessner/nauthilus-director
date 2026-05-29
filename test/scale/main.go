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

// Package main provides an optional runtime-state Redis scale harness.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/state"
	"github.com/redis/go-redis/v9"
)

const (
	defaultBackendID       = "scale-backend-imap"
	defaultKeyPrefixFormat = "nauthilus-director-scale-%d-%d"
	defaultProtocolIMAP    = "imap"
	defaultTenant          = "scale"
	exitUsage              = 2
	redisClusterSlots      = 16384
)

// scaleConfig contains explicit operator inputs for one stress run.
type scaleConfig struct {
	RedisAddr             string
	RedisClusterAddrs     string
	RedisUsername         string
	RedisPasswordFile     string
	TLSEnabled            bool
	TLSServerName         string
	TLSInsecureSkipVerify bool
	KeyPrefix             string
	Sessions              int
	HeartbeatSample       int
	CloseSample           int
	ReapExpired           int
	MaxConnections        int
	LeaseTTL              time.Duration
	Timeout               time.Duration
	Cleanup               bool
	AllowProductionTarget bool
}

// scaleResult captures the bounded output fields operators need for sizing.
type scaleResult struct {
	ActiveCount      int
	MemoryEstimate   int64
	SlotSummary      slotSummary
	OpenStats        operationStats
	HeartbeatStats   operationStats
	CloseStats       operationStats
	ReaperStats      operationStats
	ReaperDueRecords int
}

// stressSession identifies one synthetic runtime session.
type stressSession struct {
	Key           state.AffinityKey
	SessionID     string
	ReservationID string
}

// operationStats records latency and classified errors for one operation family.
type operationStats struct {
	Durations []time.Duration
	Errors    map[string]int
}

// slotSummary reports how evenly synthetic keys spread across Redis Cluster slots.
type slotSummary struct {
	Unique int
	Min    int
	Max    int
}

// redisHandle owns the selected standalone or Cluster Redis client.
type redisHandle struct {
	Client state.RedisClient
	Close  func() error
}

// main runs the optional Redis runtime-state scale harness.
func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)

		os.Exit(exitUsage)
	}
}

// run parses input, executes the harness and writes a bounded report.
func run(args []string, writer io.Writer) error {
	config, err := parseConfig(args)
	if err != nil {
		return err
	}

	if err := validateConfig(config); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()

	result, err := runScaleHarness(ctx, config)
	if err != nil {
		return err
	}

	writeScaleResult(writer, result)

	return nil
}

// parseConfig converts CLI flags into a typed scale configuration.
func parseConfig(args []string) (scaleConfig, error) {
	config := scaleConfig{KeyPrefix: defaultScaleKeyPrefix(), Sessions: 10000, HeartbeatSample: 1000, CloseSample: 1000, ReapExpired: 1000, LeaseTTL: 5 * time.Minute, Timeout: time.Minute, Cleanup: true}
	flags := flag.NewFlagSet("runtime-state-scale", flag.ContinueOnError)
	flags.StringVar(&config.RedisAddr, "redis-addr", "", "standalone Redis address")
	flags.StringVar(&config.RedisClusterAddrs, "redis-cluster-addrs", "", "comma-separated Redis Cluster addresses")
	flags.StringVar(&config.RedisUsername, "redis-username", "", "Redis ACL username")
	flags.StringVar(&config.RedisPasswordFile, "redis-password-file", "", "file containing the Redis password")
	flags.BoolVar(&config.TLSEnabled, "tls", false, "enable TLS for Redis connections")
	flags.StringVar(&config.TLSServerName, "tls-server-name", "", "Redis TLS server name")
	flags.BoolVar(&config.TLSInsecureSkipVerify, "tls-insecure-skip-verify", false, "skip Redis TLS verification")
	flags.StringVar(&config.KeyPrefix, "key-prefix", config.KeyPrefix, "temporary Redis key prefix")
	flags.IntVar(&config.Sessions, "sessions", config.Sessions, "active sessions to open")
	flags.IntVar(&config.HeartbeatSample, "heartbeat-sample", config.HeartbeatSample, "sessions to heartbeat")
	flags.IntVar(&config.CloseSample, "close-sample", config.CloseSample, "sessions to close")
	flags.IntVar(&config.ReapExpired, "reap-expired", config.ReapExpired, "expired sessions to seed and reap")
	flags.IntVar(&config.MaxConnections, "max-connections", 0, "backend max connection budget")
	flags.DurationVar(&config.LeaseTTL, "lease-ttl", config.LeaseTTL, "session and reservation lease TTL")
	flags.DurationVar(&config.Timeout, "timeout", config.Timeout, "overall harness timeout")
	flags.BoolVar(&config.Cleanup, "cleanup", config.Cleanup, "close synthetic sessions before exit")
	flags.BoolVar(&config.AllowProductionTarget, "allow-production-target", false, "allow non-loopback targets or production-looking prefixes")

	if err := flags.Parse(args); err != nil {
		return scaleConfig{}, err
	}

	return config, nil
}

// validateConfig rejects implicit, unsafe or contradictory stress inputs.
func validateConfig(config scaleConfig) error {
	if err := validateRedisTarget(config); err != nil {
		return err
	}

	if err := validateScaleBounds(config); err != nil {
		return err
	}

	if strings.TrimSpace(config.KeyPrefix) == "" {
		return errors.New("key prefix is required")
	}

	if !config.AllowProductionTarget && productionLooking(config) {
		return errors.New("refusing production-looking Redis target or key prefix without --allow-production-target")
	}

	return nil
}

// validateRedisTarget requires one explicit Redis target type.
func validateRedisTarget(config scaleConfig) error {
	switch {
	case strings.TrimSpace(config.RedisAddr) == "" && strings.TrimSpace(config.RedisClusterAddrs) == "":
		return errors.New("explicit --redis-addr or --redis-cluster-addrs is required")
	case strings.TrimSpace(config.RedisAddr) != "" && strings.TrimSpace(config.RedisClusterAddrs) != "":
		return errors.New("choose only one of --redis-addr or --redis-cluster-addrs")
	default:
		return nil
	}
}

// validateScaleBounds rejects negative samples and unusable timing.
func validateScaleBounds(config scaleConfig) error {
	if config.Sessions < 0 || config.HeartbeatSample < 0 || config.CloseSample < 0 || config.ReapExpired < 0 {
		return errors.New("session and sample counts must not be negative")
	}

	if config.LeaseTTL <= 0 || config.Timeout <= 0 {
		return errors.New("lease TTL and timeout must be greater than zero")
	}

	return nil
}

// runScaleHarness executes bounded synthetic runtime-state operations.
func runScaleHarness(ctx context.Context, config scaleConfig) (scaleResult, error) {
	handle, err := newRedisHandle(config)
	if err != nil {
		return scaleResult{}, err
	}
	defer func() { _ = handle.Close() }()

	if err := handle.Client.Ping(ctx).Err(); err != nil {
		return scaleResult{}, fmt.Errorf("redis ping failed: %w", err)
	}

	builder, err := state.NewKeyBuilder(state.KeyBuilderOptions{Prefix: config.KeyPrefix, SchemaVersion: 1})
	if err != nil {
		return scaleResult{}, err
	}

	store, err := state.NewRedisSessionStore(handle.Client, builder, nil)
	if err != nil {
		return scaleResult{}, err
	}

	beforeMemory := usedMemory(ctx, handle.Client)
	result, sessions := exerciseRuntimeState(ctx, store, builder, config)
	result.MemoryEstimate = memoryDelta(beforeMemory, usedMemory(ctx, handle.Client))
	result.SlotSummary = summarizeSlots(builder, sessions)
	result.ActiveCount = activeCount(ctx, store)

	if config.Cleanup {
		cleanupStressSessions(ctx, store, sessions, config)
	}

	return result, nil
}

// exerciseRuntimeState opens, heartbeats, closes and reaps synthetic sessions.
func exerciseRuntimeState(
	ctx context.Context,
	store *state.RedisSessionStore,
	builder state.KeyBuilder,
	config scaleConfig,
) (scaleResult, []stressSession) {
	result := scaleResult{}
	sessions := openStressSessions(ctx, store, config, &result.OpenStats)
	heartbeatStressSessions(ctx, store, sessions, sampleLimit(config.HeartbeatSample, len(sessions)), config.LeaseTTL, &result.HeartbeatStats)
	closeStressSessions(ctx, store, sessions, sampleLimit(config.CloseSample, len(sessions)), &result.CloseStats)
	expired := openExpiredStressSessions(ctx, store, config, &result.OpenStats)
	result.ReaperDueRecords = reapStressSessions(ctx, store, sampleLimit(config.ReapExpired, len(expired)), &result.ReaperStats)
	sessions = append(sessions, expired...)
	result.SlotSummary = summarizeSlots(builder, sessions)

	return result, sessions
}

// openStressSessions opens active sessions through production state APIs.
func openStressSessions(ctx context.Context, store *state.RedisSessionStore, config scaleConfig, stats *operationStats) []stressSession {
	sessions := make([]stressSession, 0, config.Sessions)
	for index := range config.Sessions {
		item := stressSessionForIndex(index)
		started := time.Now()
		err := openOneStressSession(ctx, store, item, config.LeaseTTL, maxConnections(config))
		stats.Observe(time.Since(started), err)

		if err == nil {
			sessions = append(sessions, item)
		}
	}

	return sessions
}

// openExpiredStressSessions opens short-lived sessions for reaper sizing.
func openExpiredStressSessions(ctx context.Context, store *state.RedisSessionStore, config scaleConfig, stats *operationStats) []stressSession {
	sessions := make([]stressSession, 0, config.ReapExpired)
	for index := range config.ReapExpired {
		item := stressSessionForIndex(config.Sessions + index)
		started := time.Now()
		err := openOneStressSession(ctx, store, item, 20*time.Millisecond, maxConnections(config)+config.ReapExpired)
		stats.Observe(time.Since(started), err)

		if err == nil {
			sessions = append(sessions, item)
		}
	}

	time.Sleep(30 * time.Millisecond)

	return sessions
}

// openOneStressSession reserves backend capacity, opens a lease and attaches the backend.
func openOneStressSession(
	ctx context.Context,
	store *state.RedisSessionStore,
	item stressSession,
	leaseTTL time.Duration,
	maxConnections int,
) error {
	if _, err := store.ReserveBackendCapacity(ctx, state.BackendReservationRequest{BackendIdentifier: defaultBackendID, ReservationID: item.ReservationID, MaxConnections: maxConnections, LeaseTTL: leaseTTL}); err != nil {
		return err
	}

	if _, err := store.OpenSession(ctx, state.SessionRecord{ID: item.SessionID, Key: item.Key, Protocol: defaultProtocolIMAP, ListenerName: defaultProtocolIMAP, ServiceName: defaultProtocolIMAP, ShardTag: "scale-shard-a", DirectorInstanceID: "scale-harness", LeaseTTL: leaseTTL, IdleGrace: time.Minute}); err != nil {
		_, _ = store.ReleaseBackendReservation(ctx, state.BackendReservationReleaseRequest{BackendIdentifier: defaultBackendID, ReservationID: item.ReservationID})

		return err
	}

	if _, err := store.AttachSelectedBackend(ctx, state.SessionBackendAttachment{Key: item.Key, SessionID: item.SessionID, BackendIdentifier: defaultBackendID, ReservationID: item.ReservationID, MaxConnections: maxConnections}); err != nil {
		_, _ = store.ReleaseBackendReservation(ctx, state.BackendReservationReleaseRequest{BackendIdentifier: defaultBackendID, ReservationID: item.ReservationID})
		_, _ = store.CloseSession(ctx, item.Key, item.SessionID)

		return err
	}

	return nil
}

// heartbeatStressSessions refreshes a bounded sample of active sessions.
func heartbeatStressSessions(ctx context.Context, store *state.RedisSessionStore, sessions []stressSession, limit int, ttl time.Duration, stats *operationStats) {
	for _, item := range sessions[:limit] {
		started := time.Now()
		_, err := store.HeartbeatSession(ctx, item.Key, item.SessionID, ttl)
		stats.Observe(time.Since(started), err)
	}
}

// closeStressSessions closes a bounded sample of active sessions.
func closeStressSessions(ctx context.Context, store *state.RedisSessionStore, sessions []stressSession, limit int, stats *operationStats) {
	for _, item := range sessions[:limit] {
		started := time.Now()
		_, err := store.CloseSession(ctx, item.Key, item.SessionID)
		stats.Observe(time.Since(started), err)
	}
}

// reapStressSessions runs one bounded due-time reaper pass.
func reapStressSessions(ctx context.Context, store *state.RedisSessionStore, limit int, stats *operationStats) int {
	if limit == 0 {
		return 0
	}

	started := time.Now()
	record, err := store.ReapSessions(ctx, state.ReapRequest{Limit: limit, MaxPassDuration: 30 * time.Second})
	stats.Observe(time.Since(started), err)

	if err != nil {
		return 0
	}

	return record.ExpiredSessions
}

// cleanupStressSessions closes any synthetic sessions still present.
func cleanupStressSessions(ctx context.Context, store *state.RedisSessionStore, sessions []stressSession, config scaleConfig) {
	for _, item := range sessions {
		_, _ = store.CloseSession(ctx, item.Key, item.SessionID)
		_, _ = store.ReleaseBackendReservation(ctx, state.BackendReservationReleaseRequest{BackendIdentifier: defaultBackendID, ReservationID: item.ReservationID})
	}

	_, _ = store.ReapSessions(ctx, state.ReapRequest{Limit: maxConnections(config) + config.ReapExpired, MaxPassDuration: 30 * time.Second})
}

// Observe records one operation duration and a bounded error class.
func (s *operationStats) Observe(duration time.Duration, err error) {
	s.Durations = append(s.Durations, duration)

	if err == nil {
		return
	}

	if s.Errors == nil {
		s.Errors = make(map[string]int)
	}

	s.Errors[errorClass(err)]++
}

// Count returns the number of observed operations.
func (s operationStats) Count() int {
	return len(s.Durations)
}

// Duration returns the total observed duration.
func (s operationStats) Duration() time.Duration {
	total := time.Duration(0)
	for _, duration := range s.Durations {
		total += duration
	}

	return total
}

// Percentile returns a nearest-rank latency percentile.
func (s operationStats) Percentile(percentile float64) time.Duration {
	if len(s.Durations) == 0 {
		return 0
	}

	values := append([]time.Duration{}, s.Durations...)
	slices.Sort(values)
	index := int(float64(len(values)-1) * percentile)

	return values[index]
}

// Rate returns operations per second over the observed operation wall time.
func (s operationStats) Rate() float64 {
	duration := s.Duration().Seconds()
	if duration == 0 {
		return 0
	}

	return float64(s.Count()) / duration
}

// writeScaleResult renders the stress output without high-cardinality identifiers.
func writeScaleResult(writer io.Writer, result scaleResult) {
	_, _ = fmt.Fprintf(writer, "active_count=%d memory_estimate_bytes=%d reaper_due_records=%d\n", result.ActiveCount, result.MemoryEstimate, result.ReaperDueRecords)
	_, _ = fmt.Fprintf(writer, "cluster_slot_distribution unique=%d min=%d max=%d\n", result.SlotSummary.Unique, result.SlotSummary.Min, result.SlotSummary.Max)
	writeOperationStats(writer, "open", result.OpenStats)
	writeOperationStats(writer, "heartbeat", result.HeartbeatStats)
	writeOperationStats(writer, "close", result.CloseStats)
	writeOperationStats(writer, "reaper", result.ReaperStats)
}

// writeOperationStats renders one operation family summary.
func writeOperationStats(writer io.Writer, name string, stats operationStats) {
	_, _ = fmt.Fprintf(writer, "%s_rate_per_sec=%.2f %s_count=%d %s_p50_ms=%.3f %s_p95_ms=%.3f %s_p99_ms=%.3f\n",
		name, stats.Rate(), name, stats.Count(),
		name, durationMillis(stats.Percentile(0.50)),
		name, durationMillis(stats.Percentile(0.95)),
		name, durationMillis(stats.Percentile(0.99)))
	for class, count := range stats.Errors {
		_, _ = fmt.Fprintf(writer, "error_class operation=%s class=%s count=%d\n", name, class, count)
	}
}

// newRedisHandle creates the requested Redis client type.
func newRedisHandle(config scaleConfig) (redisHandle, error) {
	password, err := redisPassword(config.RedisPasswordFile)
	if err != nil {
		return redisHandle{}, err
	}

	tlsConfig := redisTLSConfig(config)

	if strings.TrimSpace(config.RedisClusterAddrs) != "" {
		client := redis.NewClusterClient(&redis.ClusterOptions{Addrs: splitCSV(config.RedisClusterAddrs), Username: config.RedisUsername, Password: password, TLSConfig: tlsConfig})
		return redisHandle{Client: client, Close: client.Close}, nil
	}

	client := redis.NewClient(&redis.Options{Addr: strings.TrimSpace(config.RedisAddr), Username: config.RedisUsername, Password: password, Protocol: 2, TLSConfig: tlsConfig})

	return redisHandle{Client: client, Close: client.Close}, nil
}

// redisTLSConfig returns nil unless TLS is explicitly requested.
func redisTLSConfig(config scaleConfig) *tls.Config {
	if !config.TLSEnabled {
		return nil
	}

	return &tls.Config{MinVersion: tls.VersionTLS12, ServerName: config.TLSServerName, InsecureSkipVerify: config.TLSInsecureSkipVerify} //nolint:gosec // Explicit operator flag for isolated stress targets.
}

// redisPassword reads a password from a file so secrets stay out of argv.
func redisPassword(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read redis password file: %w", err)
	}

	return strings.TrimRight(string(data), "\r\n"), nil
}

// productionLooking reports whether a target needs an explicit safety override.
func productionLooking(config scaleConfig) bool {
	if productionLookingPrefix(config.KeyPrefix) {
		return true
	}

	for _, addr := range redisTargets(config) {
		if !loopbackTarget(addr) {
			return true
		}
	}

	return false
}

// productionLookingPrefix catches obvious attempts to reuse production state keys.
func productionLookingPrefix(prefix string) bool {
	normalized := strings.ToLower(strings.TrimSpace(prefix))

	return normalized == "nauthilus-director" || strings.Contains(normalized, "prod")
}

// redisTargets returns every configured Redis address.
func redisTargets(config scaleConfig) []string {
	if strings.TrimSpace(config.RedisAddr) != "" {
		return []string{strings.TrimSpace(config.RedisAddr)}
	}

	return splitCSV(config.RedisClusterAddrs)
}

// loopbackTarget reports whether an address clearly points at the local machine.
func loopbackTarget(addr string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		host = strings.TrimSpace(addr)
	}

	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}

	parsed := net.ParseIP(host)

	return parsed != nil && parsed.IsLoopback()
}

// stressSessionForIndex returns stable synthetic identity without exposing it in output.
func stressSessionForIndex(index int) stressSession {
	sessionID := fmt.Sprintf("scale-session-%08d", index)

	return stressSession{
		Key:           state.AffinityKey{Tenant: defaultTenant, AccountKey: fmt.Sprintf("scale-user-%08d@example.invalid", index)},
		SessionID:     sessionID,
		ReservationID: "scale-reservation-" + sessionID,
	}
}

// summarizeSlots computes a Redis Cluster slot spread over synthetic key groups.
func summarizeSlots(builder state.KeyBuilder, sessions []stressSession) slotSummary {
	counts := make(map[int]int)
	reservationKeys, reservationErr := builder.BackendReservationKeys(defaultBackendID)

	for _, item := range sessions {
		sessionKey, err := builder.SessionKey(item.Key.Tenant, item.Key.AccountKey, item.SessionID)
		if err == nil {
			counts[redisSlot(sessionKey)]++
		}

		if reservationErr == nil {
			counts[redisSlot(reservationKeys.State)]++
		}
	}

	return slotSummaryFromCounts(counts)
}

// slotSummaryFromCounts reduces slot counts to a compact distribution.
func slotSummaryFromCounts(counts map[int]int) slotSummary {
	summary := slotSummary{Unique: len(counts)}
	for _, count := range counts {
		if summary.Min == 0 || count < summary.Min {
			summary.Min = count
		}

		if count > summary.Max {
			summary.Max = count
		}
	}

	return summary
}

// redisSlot calculates the Redis Cluster slot for a key.
func redisSlot(key string) int {
	key = redisHashInput(key)

	crc := uint16(0)
	for _, char := range []byte(key) {
		crc ^= uint16(char) << 8
		for range 8 {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}

	return int(crc % redisClusterSlots)
}

// redisHashInput extracts a hash tag when a key contains one.
func redisHashInput(key string) string {
	start := strings.Index(key, "{")

	end := strings.Index(key, "}")
	if start >= 0 && end > start+1 {
		return key[start+1 : end]
	}

	return key
}

// usedMemory reads Redis memory usage when INFO is available.
func usedMemory(ctx context.Context, client state.RedisClient) int64 {
	info, err := client.Info(ctx, "memory").Result()
	if err != nil {
		return 0
	}

	for line := range strings.SplitSeq(info, "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), "used_memory:"); ok {
			var parsed int64

			_, _ = fmt.Sscanf(value, "%d", &parsed)

			return parsed
		}
	}

	return 0
}

// memoryDelta returns a non-negative memory estimate.
func memoryDelta(before int64, after int64) int64 {
	if before == 0 || after < before {
		return 0
	}

	return after - before
}

// activeCount reads aggregate active sessions without listing sessions.
func activeCount(ctx context.Context, store *state.RedisSessionStore) int {
	summary, err := store.RuntimeAggregateSummary(ctx)
	if err != nil {
		return 0
	}

	return summary.ActiveSessions.Total.Count
}

// maxConnections returns a fail-closed backend capacity budget.
func maxConnections(config scaleConfig) int {
	if config.MaxConnections > 0 {
		return config.MaxConnections
	}

	return config.Sessions + config.ReapExpired + 1
}

// sampleLimit clamps a requested sample to the available session count.
func sampleLimit(requested int, available int) int {
	if requested > available {
		return available
	}

	return requested
}

// durationMillis converts a duration to milliseconds.
func durationMillis(duration time.Duration) float64 {
	return float64(duration) / float64(time.Millisecond)
}

// splitCSV trims a comma-separated list and drops empty values.
func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))

	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}

	return result
}

// errorClass maps errors into bounded, secret-safe classes.
func errorClass(err error) string {
	switch {
	case state.IsRedisErrorKind(err, state.RedisErrorKindAmbiguousState):
		return "ambiguous_state"
	case state.IsRedisErrorKind(err, state.RedisErrorKindConfig):
		return "config"
	case state.IsRedisErrorKind(err, state.RedisErrorKindScriptMissing):
		return "script_missing"
	case state.IsRedisErrorKind(err, state.RedisErrorKindTransport):
		return "transport"
	default:
		return "error"
	}
}

// defaultScaleKeyPrefix creates a non-production temporary namespace.
func defaultScaleKeyPrefix() string {
	return fmt.Sprintf(defaultKeyPrefixFormat, os.Getpid(), time.Now().UnixNano())
}
