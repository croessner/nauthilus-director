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
	"net"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/redis/go-redis/v9"
)

// roundTripRecorder counts the Redis round-trips of a client: one per single command and one per pipeline.
type roundTripRecorder struct {
	mu            sync.Mutex
	singles       int
	pipelineSizes []int
}

// DialHook passes connection setup through unchanged.
func (r *roundTripRecorder) DialHook(next redis.DialHook) redis.DialHook {
	return func(ctx context.Context, network string, addr string) (net.Conn, error) {
		return next(ctx, network, addr)
	}
}

// ProcessHook counts one round-trip per single command.
func (r *roundTripRecorder) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		r.mu.Lock()
		r.singles++
		r.mu.Unlock()

		return next(ctx, cmd)
	}
}

// ProcessPipelineHook counts one round-trip per pipeline and remembers its size.
func (r *roundTripRecorder) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		r.mu.Lock()
		r.pipelineSizes = append(r.pipelineSizes, len(cmds))
		r.mu.Unlock()

		return next(ctx, cmds)
	}
}

// reset forgets every counted round-trip.
func (r *roundTripRecorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.singles = 0
	r.pipelineSizes = nil
}

// roundTrips returns the counted single commands and pipeline sizes.
func (r *roundTripRecorder) roundTrips() (int, []int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.singles, slices.Clone(r.pipelineSizes)
}

// TestRedisBackendSnapshotsMatchSingleReadsInFewerRoundTrips verifies the batch read against per-backend reads.
func TestRedisBackendSnapshotsMatchSingleReadsInFewerRoundTrips(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	backends := []string{testBackendIMAP, testBackendLMTP, testBackendCanaryIMAP}
	prepareBatchSnapshotBackends(t, store, client, builder, backends)

	recorder := &roundTripRecorder{}
	client.AddHook(recorder)

	single := make([]backend.RuntimeSnapshot, 0, len(backends))
	for _, backendID := range backends {
		snapshot, err := store.BackendSnapshot(context.Background(), backendID)
		if err != nil {
			t.Fatalf("BackendSnapshot(%s) returned error: %v", backendID, err)
		}

		single = append(single, snapshot)
	}

	// Both passes run with warm local caches, so only the runtime and health reads differ.
	recorder.reset()

	for _, backendID := range backends {
		if _, err := store.BackendSnapshot(context.Background(), backendID); err != nil {
			t.Fatalf("BackendSnapshot(%s) returned error: %v", backendID, err)
		}
	}

	singleCommands, singlePipelines := recorder.roundTrips()
	recorder.reset()

	batch, err := store.BackendSnapshots(context.Background(), backends)
	if err != nil {
		t.Fatalf("BackendSnapshots returned error: %v", err)
	}

	batchCommands, batchPipelines := recorder.roundTrips()

	for index, snapshot := range batch {
		if !reflect.DeepEqual(snapshot, single[index]) {
			t.Fatalf("batch snapshot %s = %+v, want %+v", backends[index], snapshot, single[index])
		}
	}

	if batchCommands+len(batchPipelines) >= singleCommands+len(singlePipelines) {
		t.Fatalf("batch round-trips = %d commands + %v pipelines, single reads = %d commands + %v pipelines",
			batchCommands, batchPipelines, singleCommands, singlePipelines)
	}
}

// prepareBatchSnapshotBackends gives the backends a drain override, a published health state and a reservation.
func prepareBatchSnapshotBackends(
	t *testing.T,
	store *RedisSessionStore,
	client *redis.Client,
	builder KeyBuilder,
	backends []string,
) {
	t.Helper()

	for _, backendID := range backends {
		cleanupBackend(t, client, builder, backendID)
	}

	if _, err := store.SetBackendRuntime(context.Background(), BackendRuntimeMutation{
		BackendIdentifier: testBackendIMAP,
		DrainEnabled:      true,
		DrainMode:         "soft",
		Reason:            "batch snapshot drain",
	}); err != nil {
		t.Fatalf("SetBackendRuntime returned error: %v", err)
	}

	cleanupHealth(t, client, builder, testBackendLMTP, "batch-snapshot-owner")
	publishTestInstanceHeartbeat(t, store, "batch-snapshot-owner")

	owner := acquireTestHealthOwner(t, store, "batch-snapshot-owner", testBackendLMTP, time.Minute)
	publishTestHealthState(t, store, "batch-snapshot-owner", testBackendLMTP, owner.FencingToken)
	reserveBackendForTest(t, store, testBackendCanaryIMAP, "batch-snapshot-reservation", 10)
}

// TestRedisSessionIndexWritesShareOnePipelinePerStep verifies open, attach and close index writes are batched.
func TestRedisSessionIndexWritesShareOnePipelinePerStep(t *testing.T) {
	store, client, builder := redisIntegrationStore(t)
	key := AffinityKey{Tenant: testTenantDefault, AccountKey: "pipelined-indexes@example.test"}
	sessionID := "pipelined-index-session"

	cleanupAffinity(t, client, builder, key, sessionID)
	cleanupBackend(t, client, builder, testBackendIMAP)

	recorder := &roundTripRecorder{}
	client.AddHook(recorder)

	openAttachedSession(t, store, key, sessionID, testBackendIMAP)

	_, pipelines := recorder.roundTrips()
	if count := countPipelinesOfSize(pipelines, 5); count < 2 {
		t.Fatalf("open and attach pipelines = %v, want the five open and five attach index writes batched", pipelines)
	}

	recorder.reset()

	if _, err := store.CloseSession(context.Background(), key, sessionID); err != nil {
		t.Fatalf("CloseSession returned error: %v", err)
	}

	_, pipelines = recorder.roundTrips()
	if countPipelinesOfSize(pipelines, 4) != 1 {
		t.Fatalf("close pipelines = %v, want the four close index writes batched", pipelines)
	}
}

// countPipelinesOfSize counts pipelines with exactly size commands.
func countPipelinesOfSize(sizes []int, size int) int {
	count := 0

	for _, candidate := range sizes {
		if candidate == size {
			count++
		}
	}

	return count
}
