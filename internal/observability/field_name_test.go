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

package observability

import (
	"strings"
	"testing"
)

// TestNormalizeFieldNameMatchesTheReplacerChain compares the fast path with the full normalization.
func TestNormalizeFieldNameMatchesTheReplacerChain(t *testing.T) {
	reference := func(name string) string {
		return strings.ToLower(strings.TrimSpace(strings.NewReplacer("-", "_", ".", "_", " ", "_").Replace(name)))
	}

	for _, name := range []string{
		"", "reason_class", "backend_pool", "Reason_Class", "shard-tag", "trace.id", " result ", "\tresult\n",
		"user name", "ÄNDERUNG", "straße", "password", "X-Company-Domain", "a b", "status_code_2",
	} {
		if got, want := normalizeFieldName(name), reference(name); got != want {
			t.Fatalf("normalizeFieldName(%q) = %q, want %q", name, got, want)
		}
	}

	if allocs := testing.AllocsPerRun(100, func() { _ = normalizeFieldName("reason_class") }); allocs != 0 {
		t.Fatalf("normalizeFieldName allocations for a canonical name = %.0f, want 0", allocs)
	}
}
