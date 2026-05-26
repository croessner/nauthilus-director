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

// MaintenanceMode describes runtime backend placement eligibility.
type MaintenanceMode string

const (
	// MaintenanceModeDisabled permits normal placement.
	MaintenanceModeDisabled MaintenanceMode = "disabled"
	// MaintenanceModeHard rejects new sessions and may terminate active sessions.
	MaintenanceModeHard MaintenanceMode = "hard"
	// MaintenanceModeSoft excludes new initial placements but preserves pins.
	MaintenanceModeSoft MaintenanceMode = "soft"
)

// MaintenanceState describes static or runtime maintenance with audit context.
type MaintenanceState struct {
	Mode        MaintenanceMode
	ReasonClass string
	Since       time.Time
	Generation  string
}

// DrainMode describes how an administrative drain treats active sessions.
type DrainMode string

const (
	// DrainModeDisabled means no runtime drain is active.
	DrainModeDisabled DrainMode = "disabled"
	// DrainModeHard excludes new sessions and does not preserve active pins.
	DrainModeHard DrainMode = "hard"
	// DrainModeSoft excludes new initial placement while preserving active pins.
	DrainModeSoft DrainMode = "soft"
)

// DrainState describes an auditable runtime drain overlay.
type DrainState struct {
	Enabled     bool
	Mode        DrainMode
	ReasonClass string
	StartedAt   time.Time
	Deadline    time.Time
	Generation  string
}

// NormalizeMaintenanceMode applies a default mode and validates the result.
func NormalizeMaintenanceMode(value MaintenanceMode, defaultMode MaintenanceMode) (MaintenanceMode, error) {
	mode := MaintenanceMode(strings.ToLower(strings.TrimSpace(string(value))))
	if mode == "" {
		mode = MaintenanceMode(strings.ToLower(strings.TrimSpace(string(defaultMode))))
	}

	if mode == "" {
		mode = MaintenanceModeDisabled
	}

	switch mode {
	case MaintenanceModeDisabled, MaintenanceModeSoft, MaintenanceModeHard:
		return mode, nil
	default:
		return "", newBackendError(ErrorKindAmbiguous, "effective_state", "unsupported maintenance mode", nil)
	}
}

// Normalize returns a validated maintenance state with a concrete mode.
func (s MaintenanceState) Normalize(defaultMode MaintenanceMode) (MaintenanceState, error) {
	mode, err := NormalizeMaintenanceMode(s.Mode, defaultMode)
	if err != nil {
		return MaintenanceState{}, err
	}

	s.Mode = mode
	s.ReasonClass = strings.TrimSpace(s.ReasonClass)
	s.Generation = strings.TrimSpace(s.Generation)

	return s, nil
}

// StrongestMaintenanceMode keeps the most restrictive static/runtime mode.
func StrongestMaintenanceMode(left MaintenanceMode, right MaintenanceMode) MaintenanceMode {
	if maintenanceRank(right) > maintenanceRank(left) {
		return right
	}

	return left
}

// Normalize returns a validated drain state with disabled represented as zero effect.
func (s DrainState) Normalize() (DrainState, error) {
	if !s.Enabled {
		return DrainState{Mode: DrainModeDisabled}, nil
	}

	mode := DrainMode(strings.ToLower(strings.TrimSpace(string(s.Mode))))
	if mode == "" {
		mode = DrainModeSoft
	}

	switch mode {
	case DrainModeSoft, DrainModeHard:
		s.Mode = mode
	default:
		return DrainState{}, newBackendError(ErrorKindAmbiguous, "effective_state", "unsupported drain mode", nil)
	}

	s.ReasonClass = strings.TrimSpace(s.ReasonClass)
	s.Generation = strings.TrimSpace(s.Generation)

	return s, nil
}

// PreservesActivePins reports whether the drain allows existing pins to continue.
func (s DrainState) PreservesActivePins() bool {
	return !s.Enabled || s.Mode != DrainModeHard
}

// maintenanceRank orders maintenance modes by placement restrictiveness.
func maintenanceRank(mode MaintenanceMode) int {
	switch mode {
	case MaintenanceModeHard:
		return 2
	case MaintenanceModeSoft:
		return 1
	default:
		return 0
	}
}
