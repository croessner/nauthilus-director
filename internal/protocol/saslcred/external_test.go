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

package saslcred

import (
	"encoding/base64"
	"testing"
)

// TestParseExternalAuthorizationIdentity proves empty and explicit authzid payloads.
func TestParseExternalAuthorizationIdentity(t *testing.T) {
	mechanism, err := NewMechanism("EXTERNAL")
	if err != nil {
		t.Fatalf("NewMechanism returned error: %v", err)
	}

	tests := []struct {
		name    string
		encoded string
		want    string
	}{
		{name: "explicit empty", encoded: "=", want: ""},
		{name: "authorization identity", encoded: base64.StdEncoding.EncodeToString([]byte("alias@example.test")), want: "alias@example.test"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			credentials, parseErr := Parse(mechanism, test.encoded, 1024, 0)
			if parseErr != nil {
				t.Fatalf("Parse returned error: %v", parseErr)
			}

			if credentials.Kind != KindExternal {
				t.Fatalf("kind = %q, want %q", credentials.Kind, KindExternal)
			}

			if credentials.AuthorizationID != test.want {
				t.Fatalf("authorization id = %q, want %q", credentials.AuthorizationID, test.want)
			}

			if credentials.Secret != nil {
				t.Fatal("external credentials unexpectedly contain a secret")
			}
		})
	}
}
