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

package nauthilus

import "strings"

// responseAccount resolves the authenticated account from the Nauthilus account-field attribute.
func responseAccount(operation authOperation, accountField string, attributes map[string][]string) (string, error) {
	field := strings.TrimSpace(accountField)
	if field == "" {
		return "", malformedResponseError(operation, "missing account field", nil)
	}

	values, exists := attributes[field]
	if !exists {
		return "", malformedResponseError(operation, "missing account attribute", nil)
	}

	accounts := make([]string, 0, len(values))
	for _, value := range values {
		account := strings.TrimSpace(value)
		if account != "" {
			accounts = append(accounts, account)
		}
	}

	if len(accounts) == 0 {
		return "", malformedResponseError(operation, "empty account attribute", nil)
	}

	if len(accounts) > 1 {
		return "", malformedResponseError(operation, "ambiguous account attribute", nil)
	}

	return accounts[0], nil
}
