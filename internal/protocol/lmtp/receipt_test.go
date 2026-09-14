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

package lmtp

import (
	"strings"
	"testing"
)

// TestBackendDeliveryReceipt accepts only bounded native successful session receipts.
func TestBackendDeliveryReceipt(t *testing.T) {
	const session = "aakmHZ8hqGpxPgkAdY0skA:1"
	for _, tc := range []struct {
		name  string
		code  string
		lines []string
		want  string
	}{
		{"native", "250", []string{"2.0.0 " + session + " Saved"}, session + " Saved"},
		{"recipient prefix", "250", []string{"2.0.0 <user@example.test> " + session + " Saved"}, session + " Saved"},
		{"error", "451", []string{"2.0.0 " + session + " Saved"}, ""},
		{"different success", "251", []string{"2.0.0 " + session + " Saved"}, ""},
		{"enhanced status", "250", []string{"2.1.5 " + session + " Saved"}, ""},
		{"generic success", "250", []string{"2.0.0 Message accepted"}, ""},
		{"short session", "250", []string{"2.0.0 short Saved"}, ""},
		{"long session", "250", []string{"2.0.0 " + strings.Repeat("a", 129) + " Saved"}, ""},
		{"injection", "250", []string{"2.0.0 " + session + "\r\n250 Saved"}, ""},
		{"multiline", "250", []string{"2.0.0 " + session + " Saved", "2.0.0 more"}, ""},
		{"malformed prefix", "250", []string{"2.0.0 <user@example.test " + session + " Saved"}, ""},
		{"unicode", "250", []string{"2.0.0 " + session + "ä Saved"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := backendStatusResponse{code: tc.code, lines: tc.lines}
			if got := response.deliveryReceipt(); got != tc.want {
				t.Fatalf("receipt = %q, want %q", got, tc.want)
			}
		})
	}
}
