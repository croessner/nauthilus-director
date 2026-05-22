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

import "time"

const (
	// SourceAuthAttribute identifies routing facts read from auth attributes.
	SourceAuthAttribute = "auth_attribute"
	// SourceHash identifies deterministic hash fallback routing facts.
	SourceHash = "hash"
)

// RoutingResult contains logical routing facts only.
//
//nolint:revive // The public API intentionally names this boundary RoutingResult.
type RoutingResult struct {
	AccountKey        string
	Tenant            string
	ShardTag          string
	RoutingSource     string
	RoutingGeneration string
	Sticky            bool
	TTL               time.Duration
	Attributes        map[string][]string
}

// Complete reports whether all mandatory logical routing facts are present.
func (r RoutingResult) Complete() bool {
	return trimValue(r.AccountKey) != "" && trimValue(r.Tenant) != "" && trimValue(r.ShardTag) != ""
}

// Clone returns a detached routing result.
func (r RoutingResult) Clone() RoutingResult {
	r.Attributes = cloneAttributes(r.Attributes)

	return r
}
