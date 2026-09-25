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
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	metricNameRedisPoolHits         = "nauthilus_director_redis_pool_hits_total"
	metricNameRedisPoolMisses       = "nauthilus_director_redis_pool_misses_total"
	metricNameRedisPoolTimeouts     = "nauthilus_director_redis_pool_timeouts_total"
	metricNameRedisPoolWaits        = "nauthilus_director_redis_pool_waits_total"
	metricNameRedisPoolWaitSeconds  = "nauthilus_director_redis_pool_wait_duration_seconds_total"
	metricNameRedisPoolConnections  = "nauthilus_director_redis_pool_connections"
	metricNameRedisPoolIdle         = "nauthilus_director_redis_pool_idle_connections"
	metricNameRedisPoolPendingWaits = "nauthilus_director_redis_pool_pending_requests"
)

// RedisPoolStats is one snapshot of the Redis client connection pools, summed over every node of the topology.
type RedisPoolStats struct {
	Hits             uint64
	Misses           uint64
	Timeouts         uint64
	Waits            uint64
	WaitDuration     time.Duration
	TotalConnections uint64
	IdleConnections  uint64
	PendingRequests  uint64
}

// RedisPoolStatsSource reads the current pool statistics; it is called on every metrics scrape.
type RedisPoolStatsSource interface {
	RedisPoolStats() RedisPoolStats
}

// redisPoolCollector exports Redis pool statistics at scrape time, so the request path pays nothing for them. The
// statistics separate time spent waiting for a pooled connection from the Redis operation durations, which
// include that wait.
type redisPoolCollector struct {
	source       RedisPoolStatsSource
	hits         *prometheus.Desc
	misses       *prometheus.Desc
	timeouts     *prometheus.Desc
	waits        *prometheus.Desc
	waitSeconds  *prometheus.Desc
	connections  *prometheus.Desc
	idle         *prometheus.Desc
	pendingWaits *prometheus.Desc
}

// newRedisPoolCollector builds label-free descriptors for one process-wide Redis client.
func newRedisPoolCollector(source RedisPoolStatsSource) *redisPoolCollector {
	return &redisPoolCollector{
		source:       source,
		hits:         prometheus.NewDesc(metricNameRedisPoolHits, "Redis pool requests served by an idle connection.", nil, nil),
		misses:       prometheus.NewDesc(metricNameRedisPoolMisses, "Redis pool requests that found no idle connection.", nil, nil),
		timeouts:     prometheus.NewDesc(metricNameRedisPoolTimeouts, "Redis pool requests that timed out waiting for a connection.", nil, nil),
		waits:        prometheus.NewDesc(metricNameRedisPoolWaits, "Redis pool requests that had to wait for a connection.", nil, nil),
		waitSeconds:  prometheus.NewDesc(metricNameRedisPoolWaitSeconds, "Total time Redis pool requests waited for a connection.", nil, nil),
		connections:  prometheus.NewDesc(metricNameRedisPoolConnections, "Open Redis pool connections.", nil, nil),
		idle:         prometheus.NewDesc(metricNameRedisPoolIdle, "Idle Redis pool connections.", nil, nil),
		pendingWaits: prometheus.NewDesc(metricNameRedisPoolPendingWaits, "Redis pool requests currently waiting for a connection.", nil, nil),
	}
}

// Describe sends the fixed descriptor set.
func (c *redisPoolCollector) Describe(descriptors chan<- *prometheus.Desc) {
	for _, descriptor := range []*prometheus.Desc{
		c.hits, c.misses, c.timeouts, c.waits, c.waitSeconds, c.connections, c.idle, c.pendingWaits,
	} {
		descriptors <- descriptor
	}
}

// Collect reads one pool snapshot and emits it as constant metrics.
func (c *redisPoolCollector) Collect(metrics chan<- prometheus.Metric) {
	stats := c.source.RedisPoolStats()

	for _, metric := range []struct {
		descriptor *prometheus.Desc
		valueType  prometheus.ValueType
		value      float64
	}{
		{descriptor: c.hits, valueType: prometheus.CounterValue, value: float64(stats.Hits)},
		{descriptor: c.misses, valueType: prometheus.CounterValue, value: float64(stats.Misses)},
		{descriptor: c.timeouts, valueType: prometheus.CounterValue, value: float64(stats.Timeouts)},
		{descriptor: c.waits, valueType: prometheus.CounterValue, value: float64(stats.Waits)},
		{descriptor: c.waitSeconds, valueType: prometheus.CounterValue, value: stats.WaitDuration.Seconds()},
		{descriptor: c.connections, valueType: prometheus.GaugeValue, value: float64(stats.TotalConnections)},
		{descriptor: c.idle, valueType: prometheus.GaugeValue, value: float64(stats.IdleConnections)},
		{descriptor: c.pendingWaits, valueType: prometheus.GaugeValue, value: float64(stats.PendingRequests)},
	} {
		metrics <- prometheus.MustNewConstMetric(metric.descriptor, metric.valueType, metric.value)
	}
}

// RegisterRedisPool exports the pool statistics of the process Redis client when metrics are enabled.
func (r *Runtime) RegisterRedisPool(source RedisPoolStatsSource) error {
	if r == nil || source == nil || !r.MetricsEnabled() {
		return nil
	}

	return registerCollector(r.metrics.registry, newRedisPoolCollector(source))
}
