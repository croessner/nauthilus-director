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

package backend

import (
	"context"
	"errors"
	"testing"
)

// batchSnapshots serves candidate snapshots through the batch reader and fails single reads.
type batchSnapshots struct {
	snapshots fakeSnapshots
	batches   *[][]string
}

// errSingleSnapshotRead reports a per-candidate read where the selector must use the batch read.
var errSingleSnapshotRead = errors.New("single snapshot read instead of the batch read")

// BackendSnapshot fails because the selector must use the batch read for several candidates.
func (s batchSnapshots) BackendSnapshot(context.Context, string) (RuntimeSnapshot, error) {
	return RuntimeSnapshot{}, errSingleSnapshotRead
}

// BackendSnapshots returns the fixtures in identifier order and records the requested identifiers.
func (s batchSnapshots) BackendSnapshots(_ context.Context, identifiers []string) ([]RuntimeSnapshot, error) {
	*s.batches = append(*s.batches, append([]string(nil), identifiers...))

	result := make([]RuntimeSnapshot, len(identifiers))
	for index, identifier := range identifiers {
		result[index] = s.snapshots[identifier]
	}

	return result, nil
}

// TestRuntimeSelectorReadsSeveralCandidatesInOneBatch verifies batch readers replace per-candidate reads.
func TestRuntimeSelectorReadsSeveralCandidatesInOneBatch(t *testing.T) {
	var batches [][]string

	selector := mustRuntimeSelector(t, sameShardBackendsConfig(), batchSnapshots{
		snapshots: fakeSnapshots{
			testBackendID: {RuntimeOverride: RuntimeOverride{Drain: &DrainState{Enabled: true, Mode: DrainModeSoft}}},
		},
		batches: &batches,
	}, runtimeSelectionPolicy(true))

	result, err := selector.Select(context.Background(), defaultSelectionRequest(testAccountKey))
	if err != nil {
		t.Fatalf("Select returned error: %v", err)
	}

	if result.Backend.Identifier != testBackendIDB {
		t.Fatalf("selected backend = %s, want %s while %s drains", result.Backend.Identifier, testBackendIDB, testBackendID)
	}

	if len(batches) != 1 || len(batches[0]) != 2 {
		t.Fatalf("snapshot batches = %v, want one batch with both same-shard candidates", batches)
	}
}
