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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCheckDetectsStaleGeneratedDocs verifies reference output drift fails the gate.
func TestCheckDetectsStaleGeneratedDocs(t *testing.T) {
	options := tempOptions(t, validMetadataPath())
	if err := generate(options); err != nil {
		t.Fatalf("generate: %v", err)
	}

	if err := os.WriteFile(options.defaultsPath, []byte("stale\n"), 0o644); err != nil {
		t.Fatalf("write stale defaults: %v", err)
	}

	err := check(options)
	if err == nil {
		t.Fatal("check returned nil error for stale generated docs")
	}

	if !strings.Contains(err.Error(), "stale generated config documentation") {
		t.Fatalf("error = %q, want stale output", err.Error())
	}
}

// TestMetadataRejectsMissingStableCoverage verifies every generated path needs metadata.
func TestMetadataRejectsMissingStableCoverage(t *testing.T) {
	path := writeMetadata(t, `paths:
  runtime.**:
    stability: stable
    description: Runtime settings.
`)

	_, _, err := renderArtifacts(path)
	if err == nil {
		t.Fatal("renderArtifacts returned nil error for missing metadata")
	}

	if !strings.Contains(err.Error(), "missing metadata") {
		t.Fatalf("error = %q, want missing metadata", err.Error())
	}
}

// TestMetadataRejectsTODODescriptions verifies stable paths cannot keep placeholders.
func TestMetadataRejectsTODODescriptions(t *testing.T) {
	path := writeMetadata(t, `paths:
  "**":
    stability: stable
    description: TODO describe this path.
`)

	_, _, err := renderArtifacts(path)
	if err == nil {
		t.Fatal("renderArtifacts returned nil error for TODO metadata")
	}

	if !strings.Contains(err.Error(), "contains TODO") {
		t.Fatalf("error = %q, want TODO metadata", err.Error())
	}
}

// TestMetadataRejectsUnknownPaths verifies metadata cannot name removed paths.
func TestMetadataRejectsUnknownPaths(t *testing.T) {
	path := writeMetadata(t, `paths:
  "**":
    stability: stable
    description: Covered stable configuration path.
  removed.path.**:
    stability: stable
    description: Removed path.
`)

	_, _, err := renderArtifacts(path)
	if err == nil {
		t.Fatal("renderArtifacts returned nil error for unknown metadata")
	}

	if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("error = %q, want unknown metadata", err.Error())
	}
}

// tempOptions returns isolated configdoc output paths for tests.
func tempOptions(t *testing.T, metadata string) cliOptions {
	t.Helper()

	root := t.TempDir()

	return cliOptions{
		metadataPath: metadata,
		defaultsPath: filepath.Join(root, "config-defaults.yaml"),
		pathsPath:    filepath.Join(root, "config-paths.md"),
	}
}

// validMetadataPath returns the repository metadata fixture.
func validMetadataPath() string {
	return filepath.Join("..", "..", "docs", "config", "metadata.yml")
}

// writeMetadata creates a temporary metadata file.
func writeMetadata(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "metadata.yml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write metadata: %v", err)
	}

	return path
}
