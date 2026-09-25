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

package observability

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/config"
)

// staticRedisPoolStats returns one fixed pool snapshot.
type staticRedisPoolStats struct {
	stats RedisPoolStats
}

// RedisPoolStats returns the fixed snapshot.
func (s staticRedisPoolStats) RedisPoolStats() RedisPoolStats {
	return s.stats
}

// TestRedisPoolStatsAreExportedAtScrapeTime verifies that pool waits become visible next to operation durations.
func TestRedisPoolStatsAreExportedAtScrapeTime(t *testing.T) {
	cfg := config.DefaultConfig().Observability
	cfg.Tracing.Enabled = false

	runtime, err := NewRuntime(cfg, WithLogWriter(io.Discard))
	if err != nil {
		t.Fatalf("NewRuntime returned error: %v", err)
	}

	source := staticRedisPoolStats{stats: RedisPoolStats{
		Hits: 90, Misses: 10, Timeouts: 1, Waits: 7, WaitDuration: 1500 * time.Millisecond,
		TotalConnections: 20, IdleConnections: 3, PendingRequests: 5,
	}}
	if err := runtime.RegisterRedisPool(source); err != nil {
		t.Fatalf("RegisterRedisPool returned error: %v", err)
	}

	metrics, err := runtime.MetricsProvider().Metrics(context.Background())
	if err != nil {
		t.Fatalf("Metrics returned error: %v", err)
	}

	for _, want := range []string{
		metricNameRedisPoolHits + " 90",
		metricNameRedisPoolMisses + " 10",
		metricNameRedisPoolTimeouts + " 1",
		metricNameRedisPoolWaits + " 7",
		metricNameRedisPoolWaitSeconds + " 1.5",
		metricNameRedisPoolConnections + " 20",
		metricNameRedisPoolIdle + " 3",
		metricNameRedisPoolPendingWaits + " 5",
	} {
		if !strings.Contains(metrics, want) {
			t.Fatalf("metrics are missing %q:\n%s", want, metrics)
		}
	}
}

// TestRedisPoolStatsStayOffWithDisabledMetrics verifies that disabled metrics register nothing.
func TestRedisPoolStatsStayOffWithDisabledMetrics(t *testing.T) {
	cfg := config.DefaultConfig().Observability
	cfg.Metrics.Enabled = false
	cfg.Tracing.Enabled = false

	runtime, err := NewRuntime(cfg, WithLogWriter(io.Discard))
	if err != nil {
		t.Fatalf("NewRuntime returned error: %v", err)
	}

	if err := runtime.RegisterRedisPool(staticRedisPoolStats{}); err != nil {
		t.Fatalf("RegisterRedisPool returned error: %v", err)
	}

	metrics, err := runtime.MetricsProvider().Metrics(context.Background())
	if err != nil {
		t.Fatalf("Metrics returned error: %v", err)
	}

	if strings.Contains(metrics, "redis_pool") {
		t.Fatalf("disabled metrics exported Redis pool statistics:\n%s", metrics)
	}
}
