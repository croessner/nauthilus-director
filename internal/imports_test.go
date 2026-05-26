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

package internal_test

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

// TestProductionPackagesDoNotImportArchivedPrototype keeps historical code out of root packages.
func TestProductionPackagesDoNotImportArchivedPrototype(t *testing.T) {
	for _, line := range packageImportLines(t) {
		fields := strings.Fields(line)
		importPath := fields[0]

		if strings.Contains(importPath, "/poc") {
			t.Fatalf("production module includes archived package %q", importPath)
		}

		for _, imported := range fields[1:] {
			if strings.Contains(imported, "/poc") {
				t.Fatalf("production package %q imports archived package %q", importPath, imported)
			}
		}
	}
}

// TestDomainPackagesDoNotImportGeneratedDTOs keeps generated REST DTOs at the REST edge.
func TestDomainPackagesDoNotImportGeneratedDTOs(t *testing.T) {
	for _, line := range packageImportLines(t) {
		fields := strings.Fields(line)

		importPath := fields[0]
		if !strings.Contains(importPath, "/internal/") ||
			strings.Contains(importPath, "/internal/rest") ||
			strings.Contains(importPath, "/internal/client") {
			continue
		}

		for _, imported := range fields[1:] {
			if strings.Contains(imported, "/internal/rest/generated") ||
				strings.Contains(imported, "/internal/client/generated") {
				t.Fatalf("domain package %q imports generated DTO package %q", importPath, imported)
			}
		}
	}
}

// TestRuntimePackageDoesNotImportNauthilus keeps diagnostics from authenticating.
func TestRuntimePackageDoesNotImportNauthilus(t *testing.T) {
	for _, line := range packageImportLines(t) {
		fields := strings.Fields(line)
		if len(fields) == 0 || !strings.HasSuffix(fields[0], "/internal/runtime") {
			continue
		}

		for _, imported := range fields[1:] {
			if strings.Contains(imported, "/internal/nauthilus") {
				t.Fatalf("runtime package imports Nauthilus auth boundary %q", imported)
			}
		}
	}
}

// packageImportLines returns import summaries for every package in the module.
func packageImportLines(t *testing.T) []string {
	t.Helper()

	command := exec.Command("go", "list", "-mod=vendor", "-f", "{{.ImportPath}} {{join .Imports \" \"}}", "./...")
	command.Dir = ".."

	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)

	command.Stdout = &stdout
	command.Stderr = &stderr

	if err := command.Run(); err != nil {
		t.Fatalf("go list failed: %v\n%s", err, stderr.String())
	}

	var lines []string
	for line := range strings.SplitSeq(strings.TrimSpace(stdout.String()), "\n") {
		if line != "" {
			lines = append(lines, line)
		}
	}

	return lines
}
