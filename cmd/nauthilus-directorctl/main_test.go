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

package main

import (
	"bytes"
	"strings"
	"testing"

	"net/http/httptest"

	"github.com/croessner/nauthilus-director/internal/rest"
)

// TestVersionOutput keeps the client version flag stable for operators.
func TestVersionOutput(t *testing.T) {
	previousVersion := version
	version = "test-version"

	t.Cleanup(func() {
		version = previousVersion
	})

	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)

	code := run([]string{"--version"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run returned exit code %d, want 0; stderr=%q", code, stderr.String())
	}

	const want = "nauthilus-directorctl test-version\n"
	if stdout.String() != want {
		t.Fatalf("version output = %q, want %q", stdout.String(), want)
	}
}

// TestStatusCommandUsesGeneratedClient verifies the read-only SDK transport path.
func TestStatusCommandUsesGeneratedClient(t *testing.T) {
	server := httptest.NewServer(rest.NewServer(rest.Options{Version: "test-version"}).Handler())
	t.Cleanup(server.Close)

	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)

	code := run([]string{"--address", server.URL, "status"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run returned exit code %d, want 0; stderr=%q", code, stderr.String())
	}

	output := stdout.String()
	for _, want := range []string{"health=ok", "ready=ok", "version=test-version", "api_version=v1"} {
		if !strings.Contains(output, want) {
			t.Fatalf("status output = %q, want to contain %q", output, want)
		}
	}
}
