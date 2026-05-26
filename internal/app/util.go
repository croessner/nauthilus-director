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

package app

import "sort"

const (
	tlsVersion12Compact = "TLS12"
	tlsVersion12Name    = "TLS1.2"
	tlsVersion12Symbol  = "TLS1_2"
	tlsVersion13Compact = "TLS13"
	tlsVersion13Name    = "TLS1.3"
	tlsVersion13Symbol  = "TLS1_3"
)

// sortedStrings returns a deterministic copy of the supplied values.
func sortedStrings(values []string) []string {
	copied := append([]string(nil), values...)
	sort.Strings(copied)

	return copied
}
