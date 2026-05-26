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

// ConnectionLimitState overlays configured limits with Redis-backed active counts.
type ConnectionLimitState struct {
	MaxConnections int
	ActiveSessions int
}

// Normalize validates the count fields before selector policy consumes them.
func (s ConnectionLimitState) Normalize() (ConnectionLimitState, error) {
	if s.MaxConnections <= 0 {
		return ConnectionLimitState{}, newBackendError(ErrorKindAmbiguous, "effective_state", "max connections required", nil)
	}

	if s.ActiveSessions < 0 {
		return ConnectionLimitState{}, newBackendError(ErrorKindAmbiguous, "effective_state", "active sessions must not be negative", nil)
	}

	return s, nil
}

// AtCapacity reports whether a new session would exceed the configured limit.
func (s ConnectionLimitState) AtCapacity() bool {
	return s.MaxConnections > 0 && s.ActiveSessions >= s.MaxConnections
}
