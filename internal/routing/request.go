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

import "strings"

// RoutingRequest carries authenticated identity and listener context into routing.
//
//nolint:revive // The M0 spec intentionally names this public boundary RoutingRequest.
type RoutingRequest struct {
	Tenant            string
	Protocol          string
	ListenerName      string
	ServiceName       string
	BackendPool       string
	LoginName         string
	NormalizedAccount string
	AuthAttributes    map[string][]string
	ClientIP          string
}

// cloneAttributes returns a detached copy of attribute values.
func cloneAttributes(attributes map[string][]string) map[string][]string {
	if attributes == nil {
		return nil
	}

	cloned := make(map[string][]string, len(attributes))
	for key, values := range attributes {
		cloned[key] = append([]string(nil), values...)
	}

	return cloned
}

// trimValue removes insignificant whitespace from singular routing facts.
func trimValue(value string) string {
	return strings.TrimSpace(value)
}
