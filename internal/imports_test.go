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

func TestProductionPackagesDoNotImportPOC(t *testing.T) {
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

	for line := range strings.SplitSeq(strings.TrimSpace(stdout.String()), "\n") {
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		importPath := fields[0]

		if strings.Contains(importPath, "/poc") {
			t.Fatalf("production module includes POC package %q", importPath)
		}

		for _, imported := range fields[1:] {
			if strings.Contains(imported, "/poc") {
				t.Fatalf("production package %q imports POC package %q", importPath, imported)
			}
		}
	}
}
