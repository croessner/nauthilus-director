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

//nolint:goconst // The repeated values are deliberate secret-safety fixtures.
package nauthilus

import (
	"errors"
	"testing"
)

// TestSecretSafeRequestAndErrorFields verifies diagnostics omit secret material.
func TestSecretSafeRequestAndErrorFields(t *testing.T) {
	request := AuthRequest{
		Context: RequestContext{
			Username:          "alice@example.test",
			ClientIP:          "203.0.113.10",
			ExternalSessionID: "external-session-secret",
			Protocol:          "imap",
			Method:            "plain",
			OIDCCID:           "oidc-client",
		},
		Credential: NewSecret("secret-password"),
	}

	fields := request.LogFields()
	for key, value := range fields {
		assertDoesNotContainSecret(t, key, "secret-password")
		assertDoesNotContainSecret(t, value, "secret-password")
		assertDoesNotContainSecret(t, value, "external-session-secret")
	}

	err := transportError(operationAuthenticate, errors.New("secret-password"))
	assertDoesNotContainSecret(t, err.Error(), "secret-password")

	for key, value := range err.SafeFields() {
		assertDoesNotContainSecret(t, key, "secret-password")
		assertDoesNotContainSecret(t, value, "secret-password")
	}
}
