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
	"sync"
	"time"
)

const (
	// legacyReservationCountTTL bounds how long a legacy capacity share may be reused.
	legacyReservationCountTTL = time.Second
	// backendIndexRefreshInterval bounds how often an add-only inventory member is rewritten.
	backendIndexRefreshInterval = time.Minute
	// legacyLayoutProbeTTL bounds how long the presence of a legacy key family is reused.
	legacyLayoutProbeTTL = 10 * time.Second
	// backendReservationTotalTTL bounds how long selection may reuse a backend-wide
	// reservation count. Selection only uses it to skip saturated backends; the
	// per-bucket reserve script still enforces max_connections exactly. Half a
	// second keeps a saturated backend visible quickly while one process reads
	// the twelve buckets of a backend at most about twice per second instead of
	// on every login and candidate.
	backendReservationTotalTTL = 500 * time.Millisecond
)

// storeLocalState keeps process-local accelerators for Redis state.
//
// Nothing here is authoritative. Each entry either suppresses an idempotent
// write that Redis already holds, or reuses a short-lived read that only
// narrows compatibility work for key families written by earlier releases.
// All methods are safe on a nil receiver, which then disables caching.
type storeLocalState struct {
	mu                 sync.Mutex
	now                func() time.Time
	legacyReservations map[string]localCountEntry
	reservationTotals  map[string]localCountEntry
	indexedBackends    map[string]time.Time
	legacyProbes       map[string]localPresenceEntry
	instanceLiveUntil  map[string]time.Time
}

// localCountEntry stores one cached count with its expiry and last local change.
type localCountEntry struct {
	count     int
	expiresAt time.Time
	updatedAt time.Time
}

// localPresenceEntry stores one cached key-presence observation with its expiry.
type localPresenceEntry struct {
	present   bool
	expiresAt time.Time
}

// newStoreLocalState creates empty process-local accelerators.
func newStoreLocalState() *storeLocalState {
	return &storeLocalState{
		now:                time.Now,
		legacyReservations: make(map[string]localCountEntry),
		reservationTotals:  make(map[string]localCountEntry),
		indexedBackends:    make(map[string]time.Time),
		legacyProbes:       make(map[string]localPresenceEntry),
		instanceLiveUntil:  make(map[string]time.Time),
	}
}

// currentTime returns the local clock used for cache expiry.
func (l *storeLocalState) currentTime() time.Time {
	if l == nil || l.now == nil {
		return time.Now()
	}

	return l.now()
}

// legacyReservationCount returns a fresh cached legacy capacity count.
func (l *storeLocalState) legacyReservationCount(backendIdentifier string) (int, bool) {
	if l == nil {
		return 0, false
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	entry, ok := l.legacyReservations[backendIdentifier]
	if !ok || !l.currentTime().Before(entry.expiresAt) {
		return 0, false
	}

	return entry.count, true
}

// storeLegacyReservationCount caches one legacy capacity count for a short interval.
func (l *storeLocalState) storeLegacyReservationCount(backendIdentifier string, count int) {
	if l == nil {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.legacyReservations[backendIdentifier] = localCountEntry{
		count:     count,
		expiresAt: l.currentTime().Add(legacyReservationCountTTL),
	}
}

// backendReservationTotal returns a fresh advisory backend-wide reservation count.
func (l *storeLocalState) backendReservationTotal(backendIdentifier string) (int, bool) {
	if l == nil {
		return 0, false
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	entry, ok := l.reservationTotals[backendIdentifier]
	if !ok || !l.currentTime().Before(entry.expiresAt) {
		return 0, false
	}

	return entry.count, true
}

// storeBackendReservationTotal caches a count this process knows first-hand, such as a full backend.
func (l *storeLocalState) storeBackendReservationTotal(backendIdentifier string, count int) {
	if l == nil {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.currentTime()
	l.reservationTotals[backendIdentifier] = localCountEntry{
		count:     count,
		expiresAt: now.Add(backendReservationTotalTTL),
		updatedAt: now,
	}
}

// storeReadBackendReservationTotal caches an exact count read from Redis that started at readStartedAt.
//
// A local admission or release applied after the read began is newer than the
// read result, so the read must not overwrite it.
func (l *storeLocalState) storeReadBackendReservationTotal(backendIdentifier string, count int, readStartedAt time.Time) {
	if l == nil {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if entry, ok := l.reservationTotals[backendIdentifier]; ok && entry.updatedAt.After(readStartedAt) {
		return
	}

	now := l.currentTime()
	l.reservationTotals[backendIdentifier] = localCountEntry{
		count:     count,
		expiresAt: now.Add(backendReservationTotalTTL),
		updatedAt: now,
	}
}

// adjustBackendReservationTotal applies this process' own admission or release to a fresh cached total.
//
// The expiry is kept, so other processes' changes still become visible within
// backendReservationTotalTTL while this process never lags behind itself.
func (l *storeLocalState) adjustBackendReservationTotal(backendIdentifier string, delta int) {
	if l == nil || delta == 0 {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	entry, ok := l.reservationTotals[backendIdentifier]
	if !ok || !l.currentTime().Before(entry.expiresAt) {
		return
	}

	entry.count = max(entry.count+delta, 0)
	entry.updatedAt = l.currentTime()
	l.reservationTotals[backendIdentifier] = entry
}

// backendIndexed reports whether the add-only inventory member was written recently.
func (l *storeLocalState) backendIndexed(backendIdentifier string) bool {
	if l == nil {
		return false
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	refreshAt, ok := l.indexedBackends[backendIdentifier]

	return ok && l.currentTime().Before(refreshAt)
}

// markBackendIndexed records a successful inventory write.
func (l *storeLocalState) markBackendIndexed(backendIdentifier string) {
	if l == nil {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.indexedBackends[backendIdentifier] = l.currentTime().Add(backendIndexRefreshInterval)
}

// legacyPresence returns a fresh cached presence observation for one legacy key.
func (l *storeLocalState) legacyPresence(key string) (bool, bool) {
	if l == nil {
		return false, false
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	entry, ok := l.legacyProbes[key]
	if !ok || !l.currentTime().Before(entry.expiresAt) {
		return false, false
	}

	return entry.present, true
}

// storeLegacyPresence caches one legacy key presence observation.
func (l *storeLocalState) storeLegacyPresence(key string, present bool) {
	if l == nil {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.legacyProbes[key] = localPresenceEntry{present: present, expiresAt: l.currentTime().Add(legacyLayoutProbeTTL)}
}

// markInstanceLive records how long this process' own instance heartbeat stays valid.
func (l *storeLocalState) markInstanceLive(instanceID string, liveUntil time.Time) {
	if l == nil {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.instanceLiveUntil[instanceID] = liveUntil
}

// instanceLive reports whether this process published a still-valid heartbeat for an instance.
func (l *storeLocalState) instanceLive(instanceID string) bool {
	if l == nil {
		return false
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	liveUntil, ok := l.instanceLiveUntil[instanceID]

	return ok && l.currentTime().Before(liveUntil)
}
