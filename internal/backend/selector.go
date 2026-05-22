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

// SelectionRequest joins logical routing facts with protocol backend context.
type SelectionRequest struct {
	AccountKey  string
	Tenant      string
	ShardTag    string
	Protocol    string
	BackendPool string
}

// SelectionResult contains the concrete backend chosen after policy checks.
type SelectionResult struct {
	Backend        Backend
	Reason         string
	Generation     string
	ActiveAffinity bool
}

// Selector selects concrete backends after routing facts are known.
type Selector interface {
	Select(ctx context.Context, request SelectionRequest) (SelectionResult, error)
}
