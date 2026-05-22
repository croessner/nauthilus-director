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

package routing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

const routingHashGenerationPrefix = "sha256-rendezvous-v1:"

// HashResolverConfig configures deterministic hash fallback routing.
type HashResolverConfig struct {
	ShardTags []string
	Sticky    bool
	TTL       time.Duration
}

// HashResolver chooses a logical shard through deterministic rendezvous hashing.
type HashResolver struct {
	shardTags  []string
	generation string
	sticky     bool
	ttl        time.Duration
}

// NewHashResolver creates a deterministic hash resolver.
func NewHashResolver(config HashResolverConfig) (*HashResolver, error) {
	shards := normalizeShardSet(config.ShardTags)
	if len(shards) == 0 {
		return nil, configError(SourceHash, "at least one shard tag required")
	}

	return &HashResolver{
		shardTags:  shards,
		generation: shardGeneration(shards),
		sticky:     config.Sticky,
		ttl:        config.TTL,
	}, nil
}

// Resolve maps the normalized account and tenant to a logical shard tag.
func (r *HashResolver) Resolve(_ context.Context, request RoutingRequest) (RoutingResult, error) {
	accountKey := trimValue(request.NormalizedAccount)
	if accountKey == "" {
		return RoutingResult{}, invalidRequestError(SourceHash, "normalized_account")
	}

	tenant := trimValue(request.Tenant)
	if tenant == "" {
		return RoutingResult{}, invalidRequestError(SourceHash, "tenant")
	}

	return RoutingResult{
		AccountKey:        accountKey,
		Tenant:            tenant,
		ShardTag:          r.selectShard(tenant, accountKey),
		RoutingSource:     SourceHash,
		RoutingGeneration: r.generation,
		Sticky:            r.sticky,
		TTL:               r.ttl,
		Attributes:        safeAttributes(request.AuthAttributes),
	}, nil
}

// ShardTags returns the configured logical shard set.
func (r *HashResolver) ShardTags() []string {
	return append([]string(nil), r.shardTags...)
}

// selectShard performs rendezvous hashing over the configured shard set.
func (r *HashResolver) selectShard(tenant string, accountKey string) string {
	var (
		bestShard string
		bestScore [sha256.Size]byte
	)

	for index, shard := range r.shardTags {
		score := sha256.Sum256([]byte(tenant + "\x00" + accountKey + "\x00" + shard))
		if index == 0 || bytes.Compare(score[:], bestScore[:]) > 0 {
			bestScore = score
			bestShard = shard
		}
	}

	return bestShard
}

// normalizeShardSet trims, deduplicates and sorts shard tags.
func normalizeShardSet(shards []string) []string {
	seen := make(map[string]struct{}, len(shards))
	normalized := make([]string, 0, len(shards))

	for _, shard := range shards {
		shard = trimValue(shard)
		if shard == "" {
			continue
		}

		if _, ok := seen[shard]; ok {
			continue
		}

		seen[shard] = struct{}{}
		normalized = append(normalized, shard)
	}

	sort.Strings(normalized)

	return normalized
}

// shardGeneration fingerprints the logical shard set without exposing accounts.
func shardGeneration(shards []string) string {
	sum := sha256.Sum256([]byte(strings.Join(shards, "\x00")))

	return routingHashGenerationPrefix + hex.EncodeToString(sum[:8])
}
