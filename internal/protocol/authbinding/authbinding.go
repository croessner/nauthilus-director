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

// Package authbinding enforces authority-principal binding for protocol handoff.
package authbinding

import (
	"errors"
	"strings"
)

// ErrMissingAccount reports an authenticated authority result without a usable principal.
var ErrMissingAccount = errors.New("authenticated account unavailable")

// CanonicalAccount returns the normalized authority account used for backend handoff and affinity.
func CanonicalAccount(value string) (string, error) {
	account := strings.ToLower(strings.TrimSpace(value))
	if account == "" {
		return "", ErrMissingAccount
	}

	return account, nil
}
