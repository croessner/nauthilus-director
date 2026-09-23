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

package placement

import (
	"strings"
	"sync"
	"time"
)

// reservationRepairInterval bounds how often one process repairs a candidate's
// expired capacity leases before selection. Admission itself repairs the
// affected reservation bucket atomically, so this pass only keeps saturation
// reads from lagging behind crashed writers.
const reservationRepairInterval = time.Second

// reservationRepairSchedule rate-limits pre-selection lease repair per backend.
type reservationRepairSchedule struct {
	mu       sync.Mutex
	interval time.Duration
	now      func() time.Time
	next     map[string]time.Time
}

// newReservationRepairSchedule creates a per-backend repair limiter.
func newReservationRepairSchedule(interval time.Duration) *reservationRepairSchedule {
	return &reservationRepairSchedule{
		interval: interval,
		now:      time.Now,
		next:     make(map[string]time.Time),
	}
}

// claim reports whether this caller should repair the backend now and reserves the slot.
func (s *reservationRepairSchedule) claim(backendIdentifier string) bool {
	if s == nil || s.interval <= 0 {
		return true
	}

	backendIdentifier = strings.TrimSpace(backendIdentifier)
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	if next, ok := s.next[backendIdentifier]; ok && now.Before(next) {
		return false
	}

	s.next[backendIdentifier] = now.Add(s.interval)

	return true
}

// release allows an immediate retry after a failed repair attempt.
func (s *reservationRepairSchedule) release(backendIdentifier string) {
	if s == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.next, strings.TrimSpace(backendIdentifier))
}
