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

import "context"

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

// Backend describes one protocol-specific backend entry.
type Backend struct {
	Identifier      string
	Protocol        string
	BackendPool     string
	ShardTag        string
	MaintenanceMode MaintenanceMode
	Weight          int
}

// Registry exposes backend entries without owning selection policy.
type Registry interface {
	BackendsForShard(ctx context.Context, request RegistryRequest) ([]Backend, error)
	Lookup(ctx context.Context, identifier string) (Backend, error)
}

// RegistryRequest identifies the logical shard-to-backend lookup.
type RegistryRequest struct {
	Protocol    string
	BackendPool string
	ShardTag    string
}
