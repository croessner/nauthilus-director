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
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/redis/go-redis/v9"
)

// fixedPoolStatsClient reports one fixed go-redis pool snapshot.
type fixedPoolStatsClient struct {
	redis.UniversalClient

	stats *redis.PoolStats
}

// PoolStats returns the fixed snapshot.
func (c fixedPoolStatsClient) PoolStats() *redis.PoolStats {
	return c.stats
}

// TestRedisPoolStatsSourceMapsGoRedisFields verifies the adapter keeps every counter and gauge.
func TestRedisPoolStatsSourceMapsGoRedisFields(t *testing.T) {
	source := redisPoolStatsSource{client: fixedPoolStatsClient{stats: &redis.PoolStats{
		Hits: 1, Misses: 2, Timeouts: 3, WaitCount: 4, WaitDurationNs: int64(5 * time.Millisecond),
		TotalConns: 6, IdleConns: 7, PendingRequests: 8,
	}}}

	want := observability.RedisPoolStats{
		Hits: 1, Misses: 2, Timeouts: 3, Waits: 4, WaitDuration: 5 * time.Millisecond,
		TotalConnections: 6, IdleConnections: 7, PendingRequests: 8,
	}
	if got := source.RedisPoolStats(); got != want {
		t.Fatalf("RedisPoolStats() = %+v, want %+v", got, want)
	}

	if got := (redisPoolStatsSource{client: fixedPoolStatsClient{}}).RedisPoolStats(); got != (observability.RedisPoolStats{}) {
		t.Fatalf("RedisPoolStats() without pool statistics = %+v, want zero", got)
	}
}
