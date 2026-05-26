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
	"strings"
	"time"
)

// HealthStatus describes the published backend health result.
type HealthStatus string

const (
	// HealthStatusHealthy permits placement when health enforcement is active.
	HealthStatusHealthy HealthStatus = "healthy"
	// HealthStatusStale excludes placement because the result is no longer fresh.
	HealthStatusStale HealthStatus = "stale"
	// HealthStatusUnknown excludes placement when health is required but absent.
	HealthStatusUnknown HealthStatus = "unknown"
	// HealthStatusUnhealthy excludes placement because checks failed.
	HealthStatusUnhealthy HealthStatus = "unhealthy"
)

// HealthState carries one secret-safe backend health observation.
type HealthState struct {
	Enabled     bool
	Status      HealthStatus
	ReasonClass string
	CheckedAt   time.Time
	ExpiresAt   time.Time
	Generation  string
}

// Normalize validates health state and marks expired results stale.
func (s HealthState) Normalize(now time.Time) (HealthState, error) {
	status := HealthStatus(strings.ToLower(strings.TrimSpace(string(s.Status))))
	if status == "" {
		status = HealthStatusUnknown
	}

	switch status {
	case HealthStatusHealthy, HealthStatusUnhealthy, HealthStatusUnknown, HealthStatusStale:
		s.Status = status
	default:
		return HealthState{}, newBackendError(ErrorKindAmbiguous, "effective_state", "unsupported health status", nil)
	}

	if now.IsZero() {
		now = time.Now().UTC()
	}

	if s.Enabled && !s.ExpiresAt.IsZero() && now.After(s.ExpiresAt) {
		s.Status = HealthStatusStale
	}

	s.ReasonClass = strings.TrimSpace(s.ReasonClass)
	s.Generation = strings.TrimSpace(s.Generation)

	return s, nil
}

// AllowsNewPlacement reports whether health permits a new backend placement.
func (s HealthState) AllowsNewPlacement(enforce bool) bool {
	if !enforce || !s.Enabled {
		return true
	}

	return s.Status == HealthStatusHealthy
}
