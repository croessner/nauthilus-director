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

package proxy

import "errors"

// ControlActionError marks heartbeat-observed control actions as deliberate proxy shutdowns.
type ControlActionError struct {
	Action string
}

// Error returns a low-cardinality control action failure description.
func (e *ControlActionError) Error() string {
	if e == nil || e.Action == "" {
		return "proxy: control action requested shutdown"
	}

	return "proxy: control action requested shutdown: " + e.Action
}

// NewControlActionError creates a proxy control-action shutdown error.
func NewControlActionError(action string) error {
	if action == "" {
		action = "unknown"
	}

	return &ControlActionError{Action: action}
}

// IsControlActionError reports whether an error represents a heartbeat control action.
func IsControlActionError(err error) bool {
	var controlErr *ControlActionError

	return errors.As(err, &controlErr)
}
