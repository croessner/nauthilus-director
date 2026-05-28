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
	"strings"
	"time"
)

const capabilitySeparator = ","

// CapabilitySet stores backend protocol capabilities in a case-insensitive set.
type CapabilitySet struct {
	values []string
	set    map[string]struct{}
}

// NewCapabilitySet creates a normalized capability set from wire tokens.
func NewCapabilitySet(values ...string) CapabilitySet {
	var set CapabilitySet
	for _, value := range values {
		set.Add(value)
	}

	return set
}

// CapabilitySetFromString restores a capability set from Redis state.
func CapabilitySetFromString(value string) CapabilitySet {
	if strings.TrimSpace(value) == "" {
		return CapabilitySet{}
	}

	return NewCapabilitySet(strings.Split(value, capabilitySeparator)...)
}

// Add inserts a normalized token while preserving first-seen order.
func (s *CapabilitySet) Add(value string) {
	normalized := normalizeCapabilityToken(value)
	if normalized == "" {
		return
	}

	if s.set == nil {
		s.set = make(map[string]struct{})
	}

	if _, exists := s.set[normalized]; exists {
		return
	}

	s.set[normalized] = struct{}{}
	s.values = append(s.values, normalized)
}

// Has reports whether a normalized capability token is present.
func (s CapabilitySet) Has(value string) bool {
	normalized := normalizeCapabilityToken(value)
	if normalized == "" {
		return false
	}

	_, ok := s.set[normalized]

	return ok
}

// List returns a detached capability list in first-seen order.
func (s CapabilitySet) List() []string {
	return append([]string(nil), s.values...)
}

// Empty reports whether the set contains no usable capability tokens.
func (s CapabilitySet) Empty() bool {
	return len(s.values) == 0
}

// String serializes the set into a stable Redis-safe field value.
func (s CapabilitySet) String() string {
	return strings.Join(s.values, capabilitySeparator)
}

// Normalize returns a detached set with canonical token spelling.
func (s CapabilitySet) Normalize() CapabilitySet {
	return NewCapabilitySet(s.values...)
}

// PoolSupportsCapability verifies every backend in a pool has fresh capability proof.
func PoolSupportsCapability(
	ctx context.Context,
	registry Registry,
	snapshots RuntimeSnapshotReader,
	backendPool string,
	capability string,
	now time.Time,
) (bool, error) {
	if registry == nil || snapshots == nil {
		return false, nil
	}

	if now.IsZero() {
		now = time.Now().UTC()
	}

	pool, err := registry.Pool(ctx, backendPool)
	if err != nil {
		return false, err
	}

	if len(pool.Backends) == 0 {
		return false, nil
	}

	for _, identifier := range pool.Backends {
		allowed, err := backendHasFreshCapability(ctx, registry, snapshots, pool, identifier, capability, now)
		if err != nil {
			return false, err
		}

		if !allowed {
			return false, nil
		}
	}

	return true, nil
}

// PoolSupportsCapability checks dynamic capability proof through the selector runtime view.
func (s *RuntimeSelector) PoolSupportsCapability(ctx context.Context, backendPool string, capability string) (bool, error) {
	if s == nil {
		return false, nil
	}

	return PoolSupportsCapability(ctx, s.registry, s.snapshots, backendPool, capability, s.currentTime())
}

// backendHasFreshCapability checks one backend's fresh health-published capabilities.
func backendHasFreshCapability(
	ctx context.Context,
	registry Registry,
	snapshots RuntimeSnapshotReader,
	pool Pool,
	identifier string,
	capability string,
	now time.Time,
) (bool, error) {
	entry, err := registry.Lookup(ctx, identifier)
	if err != nil {
		return false, err
	}

	if entry.Protocol != pool.Protocol {
		return false, newBackendError(ErrorKindAmbiguous, "capability_policy", "pool and backend protocol mismatch", nil)
	}

	snapshot, err := snapshots.BackendSnapshot(ctx, entry.Identifier)
	if err != nil {
		return false, err
	}

	health, err := snapshot.Health.Normalize(now)
	if err != nil {
		return false, err
	}

	return health.Enabled && health.Status == HealthStatusHealthy && health.Capabilities.Has(capability), nil
}

// normalizeCapabilityToken canonicalizes a protocol capability token for comparisons.
func normalizeCapabilityToken(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" || strings.Contains(value, capabilitySeparator) {
		return ""
	}

	return value
}
