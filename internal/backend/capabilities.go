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
	"strconv"
	"strings"
	"time"
)

const capabilitySeparator = ","
const sizeCapabilityName = "SIZE"

// CapabilitySet stores backend protocol capabilities in a case-insensitive set.
type CapabilitySet struct {
	values []string
	set    map[string]struct{}
}

// CapabilityFacts stores structured backend capability facts that carry parameters.
type CapabilityFacts struct {
	size SizeCapabilityFact
}

// SizeCapabilityFact stores a backend SIZE extension advertisement and optional limit.
type SizeCapabilityFact struct {
	Supported    bool
	HasMaximum   bool
	MaximumBytes uint64
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

// CapabilityFactsFromString restores structured capability facts from Redis state.
func CapabilityFactsFromString(value string) (CapabilityFacts, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return CapabilityFacts{}, nil
	}

	var facts CapabilityFacts

	for rawFact := range strings.SplitSeq(value, capabilitySeparator) {
		fact := strings.TrimSpace(rawFact)
		if fact == "" {
			continue
		}

		if facts.Size().Supported {
			return CapabilityFacts{}, newBackendError(ErrorKindAmbiguous, "capability_facts", "duplicate size capability fact", nil)
		}

		size, ok := parseSerializedSizeCapabilityFact(fact)
		if !ok {
			return CapabilityFacts{}, newBackendError(ErrorKindAmbiguous, "capability_facts", "invalid size capability fact", nil)
		}

		facts.SetSize(size)
	}

	return facts.Normalize()
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

// Empty reports whether the fact set contains no structured facts.
func (f CapabilityFacts) Empty() bool {
	return !f.size.Supported
}

// Normalize canonicalizes structured facts for deterministic state.
func (f CapabilityFacts) Normalize() (CapabilityFacts, error) {
	if !f.size.Supported {
		return CapabilityFacts{}, nil
	}

	f.size = f.size.Normalize()

	return f, nil
}

// SetSize stores a normalized SIZE capability fact.
func (f *CapabilityFacts) SetSize(size SizeCapabilityFact) {
	if f == nil {
		return
	}

	f.size = size.Normalize()
}

// Size returns the structured backend SIZE capability fact.
func (f CapabilityFacts) Size() SizeCapabilityFact {
	return f.size.Normalize()
}

// String serializes structured facts into a stable Redis-safe field value.
func (f CapabilityFacts) String() string {
	size := f.Size()
	if !size.Supported {
		return ""
	}

	if maximum, ok := size.Maximum(); ok {
		return sizeCapabilityName + "=" + strconv.FormatUint(maximum, 10)
	}

	return sizeCapabilityName
}

// Normalize canonicalizes the SIZE fact and treats SIZE 0 as no fixed maximum.
func (f SizeCapabilityFact) Normalize() SizeCapabilityFact {
	if !f.Supported {
		return SizeCapabilityFact{}
	}

	if f.HasMaximum && f.MaximumBytes == 0 {
		f.HasMaximum = false
	}

	return f
}

// Maximum returns the positive backend-declared maximum when one exists.
func (f SizeCapabilityFact) Maximum() (uint64, bool) {
	f = f.Normalize()
	if !f.Supported || !f.HasMaximum {
		return 0, false
	}

	return f.MaximumBytes, true
}

// ParseSizeCapabilityFact parses the parameter tail from a SIZE LHLO line.
func ParseSizeCapabilityFact(parameters []string) (SizeCapabilityFact, bool) {
	switch len(parameters) {
	case 0:
		return SizeCapabilityFact{Supported: true}, true
	case 1:
		return parseSizeCapabilityMaximum(parameters[0])
	default:
		return SizeCapabilityFact{}, false
	}
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

// PoolSizeProof reports fresh pool-wide SIZE support and the lowest fixed maximum.
type PoolSizeProof struct {
	Supported    bool
	HasMaximum   bool
	MaximumBytes uint64
}

// PoolSupportsSize verifies every backend in a pool has fresh structured SIZE proof.
func PoolSupportsSize(
	ctx context.Context,
	registry Registry,
	snapshots RuntimeSnapshotReader,
	backendPool string,
	now time.Time,
) (PoolSizeProof, error) {
	if registry == nil || snapshots == nil {
		return PoolSizeProof{}, nil
	}

	if now.IsZero() {
		now = time.Now().UTC()
	}

	pool, err := registry.Pool(ctx, backendPool)
	if err != nil {
		return PoolSizeProof{}, err
	}

	if len(pool.Backends) == 0 {
		return PoolSizeProof{}, nil
	}

	proof := PoolSizeProof{Supported: true}

	for _, identifier := range pool.Backends {
		size, ok, err := backendHasFreshSizeCapability(ctx, registry, snapshots, pool, identifier, now)
		if err != nil {
			return PoolSizeProof{}, err
		}

		if !ok {
			return PoolSizeProof{}, nil
		}

		if maximum, hasMaximum := size.Maximum(); hasMaximum && (!proof.HasMaximum || maximum < proof.MaximumBytes) {
			proof.HasMaximum = true
			proof.MaximumBytes = maximum
		}
	}

	return proof, nil
}

// PoolSupportsSize checks dynamic SIZE proof through the selector runtime view.
func (s *RuntimeSelector) PoolSupportsSize(ctx context.Context, backendPool string) (PoolSizeProof, error) {
	if s == nil {
		return PoolSizeProof{}, nil
	}

	return PoolSupportsSize(ctx, s.registry, s.snapshots, backendPool, s.currentTime())
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

// backendHasFreshSizeCapability checks one backend's fresh structured SIZE proof.
func backendHasFreshSizeCapability(
	ctx context.Context,
	registry Registry,
	snapshots RuntimeSnapshotReader,
	pool Pool,
	identifier string,
	now time.Time,
) (SizeCapabilityFact, bool, error) {
	entry, err := registry.Lookup(ctx, identifier)
	if err != nil {
		return SizeCapabilityFact{}, false, err
	}

	if entry.Protocol != pool.Protocol {
		return SizeCapabilityFact{}, false, newBackendError(ErrorKindAmbiguous, "capability_policy", "pool and backend protocol mismatch", nil)
	}

	snapshot, err := snapshots.BackendSnapshot(ctx, entry.Identifier)
	if err != nil {
		return SizeCapabilityFact{}, false, err
	}

	health, err := snapshot.Health.Normalize(now)
	if err != nil {
		return SizeCapabilityFact{}, false, err
	}

	if !health.Enabled || health.Status != HealthStatusHealthy {
		return SizeCapabilityFact{}, false, nil
	}

	size := health.CapabilityFacts.Size()

	return size, size.Supported, nil
}

// parseSerializedSizeCapabilityFact parses one deterministic Redis SIZE fact.
func parseSerializedSizeCapabilityFact(value string) (SizeCapabilityFact, bool) {
	name, rawMaximum, hasMaximum := strings.Cut(value, "=")
	if normalizeCapabilityToken(name) != sizeCapabilityName {
		return SizeCapabilityFact{}, false
	}

	if !hasMaximum {
		return SizeCapabilityFact{Supported: true}, true
	}

	return parseSizeCapabilityMaximum(rawMaximum)
}

// parseSizeCapabilityMaximum parses a non-negative decimal SIZE maximum.
func parseSizeCapabilityMaximum(value string) (SizeCapabilityFact, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return SizeCapabilityFact{}, false
	}

	for index := 0; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return SizeCapabilityFact{}, false
		}
	}

	maximum, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return SizeCapabilityFact{}, false
	}

	if maximum == 0 {
		return SizeCapabilityFact{Supported: true}, true
	}

	return SizeCapabilityFact{Supported: true, HasMaximum: true, MaximumBytes: maximum}, true
}

// normalizeCapabilityToken canonicalizes a protocol capability token for comparisons.
func normalizeCapabilityToken(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" || strings.Contains(value, capabilitySeparator) {
		return ""
	}

	return value
}
