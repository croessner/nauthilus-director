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

//nolint:goconst // Redis Cluster reference vectors repeat literal keys intentionally.
package state

import (
	"fmt"
	"strings"
	"testing"
)

const (
	distributionBackends  = 10
	distributionInstances = 3
	distributionSessions  = 10000
	distributionMasters   = 3
)

// TestRedisCRC16MatchesClusterReference pins the slot function to Redis Cluster reference values.
func TestRedisCRC16MatchesClusterReference(t *testing.T) {
	if got := redisCRC16("123456789"); got != 0x31C3 {
		t.Fatalf("CRC16(123456789) = %#x, want 0x31c3", got)
	}

	for key, want := range map[string]int{
		"foo":     12182,
		"bar":     5061,
		"hello":   866,
		"somekey": 11058,
	} {
		if got := redisClusterSlot(key); got != want {
			t.Fatalf("slot(%q) = %d, want %d", key, got, want)
		}
	}

	for _, pair := range [][2]string{
		{"{user1000}.following", "{user1000}.followers"},
		{"foo{bar}{zap}", "bar"},
		{"foo{{bar}}zap", "{bar"},
		{"foo{}{bar}", "foo{}{bar}"},
		{"foo{bar", "foo{bar"},
	} {
		if left, right := redisClusterSlot(pair[0]), redisClusterSlot(pair[1]); left != right {
			t.Fatalf("slot(%q)=%d, slot(%q)=%d, want equal", pair[0], left, pair[1], right)
		}
	}
}

// TestSpreadHashTagsCoverEqualSlotRanges proves bucket tags land in their own slot interval.
func TestSpreadHashTagsCoverEqualSlotRanges(t *testing.T) {
	builder := mustKeyBuilder(t)

	families := map[string][]string{"aggregates": aggregateGroupSlotKeys(builder)}

	for index := range distributionBackends {
		backendID := fmt.Sprintf("mailstore-%02d-imap", index)
		families["reservations "+backendID] = reservationBucketSlotKeys(t, builder, backendID)
	}

	families["reservations sink-imap"] = reservationBucketSlotKeys(t, builder, "sink-imap")

	for name, keys := range families {
		for bucket, key := range keys {
			slot := redisClusterSlot(key)

			low := (bucket*redisClusterSlots + len(keys) - 1) / len(keys)
			high := ((bucket + 1) * redisClusterSlots) / len(keys)

			if slot < low || slot >= high {
				t.Fatalf("%s bucket %d slot %d outside [%d,%d)", name, bucket, slot, low, high)
			}
		}

		for _, masters := range []int{2, 3, 4, 6} {
			counts := masterRangeCounts(keys, masters)
			for master, count := range counts {
				if count != len(keys)/masters {
					t.Fatalf("%s over %d masters: master %d has %d buckets, want %d (%v)", name, masters, master, count, len(keys)/masters, counts)
				}
			}
		}
	}
}

// TestSpreadHashTagIsStable pins the persisted tag contract for one family.
func TestSpreadHashTagIsStable(t *testing.T) {
	builder := mustKeyBuilder(t)

	group, err := builder.AggregateKeys(0)
	if err != nil {
		t.Fatalf("AggregateKeys returned error: %v", err)
	}

	again, err := mustKeyBuilder(t).AggregateKeys(0)
	if err != nil {
		t.Fatalf("AggregateKeys returned error: %v", err)
	}

	if group.HashTag != again.HashTag || !strings.HasPrefix(group.HashTag, "{agg:00.") {
		t.Fatalf("aggregate tag = %q / %q, want stable {agg:00.<nonce>}", group.HashTag, again.HashTag)
	}

	if want, err := spreadHashTag(aggregateHashTagFamily, 0, aggregateBuckets); err != nil || group.HashTag != want {
		t.Fatalf("aggregate tag %q is not the documented spread tag", group.HashTag)
	}
}

// TestBucketedKeyGroupsShareOneSlot verifies every atomic key group stays inside one hash tag.
func TestBucketedKeyGroupsShareOneSlot(t *testing.T) {
	builder := mustKeyBuilder(t)

	for bucket := range builder.BackendReservationBucketCount() {
		keys, err := builder.BackendReservationBucketKeys(testBackendIMAP, bucket)
		if err != nil {
			t.Fatalf("BackendReservationBucketKeys returned error: %v", err)
		}

		assertSameSlot(t, "reservation bucket", keys.State, keys.Due)
	}

	for _, group := range builder.AggregateKeyGroups() {
		assertSameSlot(t, "aggregate group", append(group.sessionScriptKeys(), group.IdleAffinities)...)

		if err := validateSameSlotScriptKeys(scriptAggregateSessionUpsert, group.sessionScriptKeys()); err != nil {
			t.Fatalf("aggregate script keys rejected: %v", err)
		}
	}

	owner, err := builder.HealthOwnerKey(testBackendIMAP)
	if err != nil {
		t.Fatalf("HealthOwnerKey returned error: %v", err)
	}

	stateKey, err := builder.HealthStateKey(testBackendIMAP)
	if err != nil {
		t.Fatalf("HealthStateKey returned error: %v", err)
	}

	assertSameSlot(t, "health", owner, stateKey)

	if err := validateSameSlotScriptKeys(scriptHealthOwnerAcquire, []string{owner, stateKey}); err != nil {
		t.Fatalf("health acquire keys rejected: %v", err)
	}
}

// TestBucketedKeyGroupsUseDistinctSlots verifies independent groups do not collapse into one slot.
func TestBucketedKeyGroupsUseDistinctSlots(t *testing.T) {
	builder := mustKeyBuilder(t)

	assertDistinctSlots(t, "aggregate groups", aggregateGroupSlotKeys(builder))
	assertDistinctSlots(t, "reservation buckets", reservationBucketSlotKeys(t, builder, testBackendIMAP))

	healthKeys := make([]string, 0, distributionBackends)
	legacyHealthKeys := make([]string, 0, distributionBackends)

	for index := range distributionBackends {
		backendID := fmt.Sprintf("mailstore-%02d-imap", index)

		key, err := builder.HealthStateKey(backendID)
		if err != nil {
			t.Fatalf("HealthStateKey returned error: %v", err)
		}

		legacy, err := builder.LegacyHealthStateKey(backendID)
		if err != nil {
			t.Fatalf("LegacyHealthStateKey returned error: %v", err)
		}

		healthKeys = append(healthKeys, key)
		legacyHealthKeys = append(legacyHealthKeys, legacy)
	}

	assertDistinctSlots(t, "health groups", healthKeys)

	if slots := uniqueSlots(legacyHealthKeys); slots != 1 {
		t.Fatalf("legacy health keys use %d slots, want the single shared slot", slots)
	}

	legacyReservation, err := builder.LegacyBackendReservationKeys(testBackendIMAP)
	if err != nil {
		t.Fatalf("LegacyBackendReservationKeys returned error: %v", err)
	}

	for _, key := range reservationBucketSlotKeys(t, builder, testBackendIMAP) {
		if redisClusterSlot(key) == redisClusterSlot(legacyReservation.State) {
			t.Fatalf("reservation bucket %q shares the legacy slot", key)
		}
	}
}

// TestSameSlotScriptValidationRejectsCrossSlotKeys protects every multi-key script from CROSSSLOT.
func TestSameSlotScriptValidationRejectsCrossSlotKeys(t *testing.T) {
	builder := mustKeyBuilder(t)
	first, _ := builder.AggregateKeys(0)
	second, _ := builder.AggregateKeys(1)
	legacy := builder.LegacyAggregateKeys()

	for name, keys := range map[string][]string{
		"different buckets": {first.Sessions, second.Protocol},
		"legacy untagged":   legacy.sessionScriptKeys(),
		"tagged and legacy": {first.Sessions, legacy.Protocol},
	} {
		if err := validateSameSlotScriptKeys("test", keys); !IsRedisErrorKind(err, RedisErrorKindConfig) {
			t.Fatalf("%s: validateSameSlotScriptKeys error = %v, want config", name, err)
		}
	}

	if err := validateSameSlotScriptKeys("test", []string{legacy.Sessions}); err != nil {
		t.Fatalf("single untagged key rejected: %v", err)
	}
}

// TestBackendReservationQuotasAddUpToCapacity verifies bucket shares never exceed max_connections.
func TestBackendReservationQuotasAddUpToCapacity(t *testing.T) {
	for _, capacity := range []int{-3, 0, 1, 2, 5, 11, 12, 13, 100, 1000, 1001} {
		quotas := backendReservationBucketQuotas(capacity, backendReservationBuckets)
		total := 0

		for bucket, quota := range quotas {
			if quota < 0 {
				t.Fatalf("capacity %d bucket %d quota %d", capacity, bucket, quota)
			}

			total += quota
		}

		want := max(capacity, 0)
		if total != want {
			t.Fatalf("capacity %d quotas %v sum %d", capacity, quotas, total)
		}

		if active := activeBackendReservationBuckets(quotas); active != min(want, backendReservationBuckets) {
			t.Fatalf("capacity %d active buckets = %d", capacity, active)
		}
	}
}

// TestBackendReservationRefRoundTrip verifies bucket-bound identifiers and legacy fallback parsing.
func TestBackendReservationRefRoundTrip(t *testing.T) {
	for bucket := range backendReservationBuckets {
		id := formatBackendReservationID("0123abcd", bucket)
		if ref := parseBackendReservationRef(id); ref.Bucket != bucket || ref.ID != id {
			t.Fatalf("parse(%q) = %+v, want bucket %d", id, ref, bucket)
		}
	}

	for _, legacy := range []string{"0123abcd", "reservation-1", "#rb01", "x#rb1", "x#rb12", "x#rbxx", "x#rb001"} {
		if ref := parseBackendReservationRef(legacy); ref.Bucket != legacyBackendReservationBucket || ref.ID != legacy {
			t.Fatalf("parse(%q) = %+v, want legacy", legacy, ref)
		}
	}
}

// TestClusterKeyDistributionReport reports how realistic traffic spreads over three equal masters.
//
// It models 10 backends, 3 director instances and 10,000 sessions, maps every
// per-session key family to its master range and compares the new layout with
// the single-slot layout it replaces. Run with -v to print the report.
func TestClusterKeyDistributionReport(t *testing.T) {
	builder := mustKeyBuilder(t)
	report := newDistributionReport(distributionMasters)

	for index := range distributionSessions {
		sessionID := fmt.Sprintf("%032x", index+1)
		backendID := fmt.Sprintf("mailstore-%02d-imap", index%distributionBackends)
		affinityHash, _ := builder.AffinityHash("default", fmt.Sprintf("user%05d@example.test", index))

		bucket, err := builder.BackendReservationBucket(sessionID, builder.BackendReservationBucketCount())
		if err != nil {
			t.Fatalf("BackendReservationBucket returned error: %v", err)
		}

		reservation, _ := builder.BackendReservationBucketKeys(backendID, bucket)
		singleBackendReservation, _ := builder.BackendReservationBucketKeys("sink-imap", bucket)
		legacyReservation, _ := builder.LegacyBackendReservationKeys(backendID)
		legacySingleReservation, _ := builder.LegacyBackendReservationKeys("sink-imap")
		aggregates, _ := builder.AggregateSessionKeys(sessionID)
		idle, _ := builder.AggregateIdleAffinityKeys(affinityHash)
		legacyAggregates := builder.LegacyAggregateKeys()

		report.add("reservations, 10 backends", reservation.State, legacyReservation.State)
		report.add("reservations, one backend", singleBackendReservation.State, legacySingleReservation.State)
		report.add("aggregate markers+counters", aggregates.Sessions, legacyAggregates.Sessions)
		report.add("idle affinities", idle.IdleAffinities, legacyAggregates.IdleAffinities)
	}

	for index := range distributionBackends {
		backendID := fmt.Sprintf("mailstore-%02d-imap", index)
		stateKey, _ := builder.HealthStateKey(backendID)
		legacyKey, _ := builder.LegacyHealthStateKey(backendID)

		for range distributionInstances {
			report.add("health owner/state per backend", stateKey, legacyKey)
		}
	}

	for index := range distributionInstances {
		instanceKey, _ := builder.InstanceKey(fmt.Sprintf("director-%d", index))
		report.add("instance heartbeats", instanceKey, builder.namespaceBase()+":{health}:runtime:instance:director")
	}

	t.Log("\n" + report.String())

	for _, family := range []string{"reservations, 10 backends", "reservations, one backend", "aggregate markers+counters", "idle affinities"} {
		if share := report.maxShare(family); share > 0.36 {
			t.Fatalf("%s: busiest master receives %.1f%%, want at most 36%%", family, share*100)
		}
	}
}

// distributionReport accumulates per-family master-range counts for new and legacy keys.
type distributionReport struct {
	masters int
	order   []string
	current map[string][]int
	legacy  map[string][]int
}

// newDistributionReport creates an empty report over equally sized master ranges.
func newDistributionReport(masters int) *distributionReport {
	return &distributionReport{masters: masters, current: make(map[string][]int), legacy: make(map[string][]int)}
}

// add records one operation on the new key and on the key it replaces.
func (r *distributionReport) add(family string, current string, legacy string) {
	if _, ok := r.current[family]; !ok {
		r.order = append(r.order, family)
		r.current[family] = make([]int, r.masters)
		r.legacy[family] = make([]int, r.masters)
	}

	r.current[family][masterRange(redisClusterSlot(current), r.masters)]++
	r.legacy[family][masterRange(redisClusterSlot(legacy), r.masters)]++
}

// maxShare returns the busiest master's share of one family under the new layout.
func (r *distributionReport) maxShare(family string) float64 {
	total, busiest := 0, 0

	for _, count := range r.current[family] {
		total += count
		busiest = max(busiest, count)
	}

	if total == 0 {
		return 0
	}

	return float64(busiest) / float64(total)
}

// String renders the report as a fixed-width table.
func (r *distributionReport) String() string {
	var builder strings.Builder

	fmt.Fprintf(&builder, "%-32s %-22s   %-22s\n", "family (master slot ranges)", "new 0-5460|-10922|-16383", "replaced single-slot layout")

	for _, family := range r.order {
		fmt.Fprintf(&builder, "%-32s %-22s   %-22s\n", family, shareRow(r.current[family]), shareRow(r.legacy[family]))
	}

	return builder.String()
}

// shareRow formats per-master counts as percentages.
func shareRow(counts []int) string {
	total := 0
	for _, count := range counts {
		total += count
	}

	parts := make([]string, 0, len(counts))
	for _, count := range counts {
		parts = append(parts, fmt.Sprintf("%5.1f%%", float64(count)*100/float64(max(total, 1))))
	}

	return strings.Join(parts, " ")
}

// masterRange maps a slot to one of n contiguous, equally sized master ranges.
func masterRange(slot int, masters int) int {
	return min(slot*masters/redisClusterSlots, masters-1)
}

// masterRangeCounts counts keys per contiguous master range.
func masterRangeCounts(keys []string, masters int) []int {
	counts := make([]int, masters)
	for _, key := range keys {
		counts[masterRange(redisClusterSlot(key), masters)]++
	}

	return counts
}

// aggregateGroupSlotKeys returns one representative key per aggregate group.
func aggregateGroupSlotKeys(builder KeyBuilder) []string {
	keys := make([]string, 0, aggregateBuckets)
	for _, group := range builder.AggregateKeyGroups() {
		keys = append(keys, group.Sessions)
	}

	return keys
}

// reservationBucketSlotKeys returns one representative key per reservation bucket.
func reservationBucketSlotKeys(t *testing.T, builder KeyBuilder, backendID string) []string {
	t.Helper()

	keys := make([]string, 0, backendReservationBuckets)

	for bucket := range backendReservationBuckets {
		group, err := builder.BackendReservationBucketKeys(backendID, bucket)
		if err != nil {
			t.Fatalf("BackendReservationBucketKeys returned error: %v", err)
		}

		keys = append(keys, group.State)
	}

	return keys
}

// assertSameSlot fails unless every key hashes to the first key's slot.
func assertSameSlot(t *testing.T, label string, keys ...string) {
	t.Helper()

	for _, key := range keys[1:] {
		if redisClusterSlot(key) != redisClusterSlot(keys[0]) {
			t.Fatalf("%s: %q and %q use different slots", label, keys[0], key)
		}
	}
}

// assertDistinctSlots fails when two keys of independent groups share a slot.
func assertDistinctSlots(t *testing.T, label string, keys []string) {
	t.Helper()

	if slots := uniqueSlots(keys); slots != len(keys) {
		t.Fatalf("%s: %d keys use only %d slots", label, len(keys), slots)
	}
}

// uniqueSlots counts the distinct slots used by keys.
func uniqueSlots(keys []string) int {
	slots := make(map[int]struct{}, len(keys))
	for _, key := range keys {
		slots[redisClusterSlot(key)] = struct{}{}
	}

	return len(slots)
}
