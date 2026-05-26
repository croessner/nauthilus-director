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

package config

import "testing"

const fallbackShardTag = "fallback-shard"

// TestBackendWithoutShardTagUsesEffectiveDefaultShard verifies loader normalization semantics.
func TestBackendWithoutShardTagUsesEffectiveDefaultShard(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Director.Routing.DefaultShard = fallbackShardTag
	backend := cfg.Director.Backends["mailstore-a-imap"]
	backend.ShardTag = ""
	cfg.Director.Backends["mailstore-a-imap"] = backend

	normalized := cfg.Normalize()
	if got := normalized.Director.Backends["mailstore-a-imap"].ShardTag; got != fallbackShardTag {
		t.Fatalf("normalized shard = %q, want %s", got, fallbackShardTag)
	}

	if err := NewLoader().Validate(cfg); err != nil {
		t.Fatalf("Validate rejected config with omitted shard tag: %v", err)
	}
}

// TestBackendWithoutDefaultShardFallsBackToDefault verifies the hard-coded safe fallback.
func TestBackendWithoutDefaultShardFallsBackToDefault(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Director.Routing.DefaultShard = ""
	backend := cfg.Director.Backends["mailstore-a-imap"]
	backend.ShardTag = ""
	cfg.Director.Backends["mailstore-a-imap"] = backend

	normalized := cfg.Normalize()
	if got := normalized.Director.Backends["mailstore-a-imap"].ShardTag; got != fallbackDefaultShard {
		t.Fatalf("normalized shard = %q, want %s", got, fallbackDefaultShard)
	}
}
