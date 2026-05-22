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

//nolint:goconst,wsl_v5 // Repeated CLI flag literals keep command assertions readable.
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVersionOutput keeps the binary version flag stable for operators.
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

	const want = "nauthilus-director test-version\n"
	if stdout.String() != want {
		t.Fatalf("version output = %q, want %q", stdout.String(), want)
	}
}

// TestConfigDumpDefaultsCommand verifies the CLI default dump stays redacted.
func TestConfigDumpDefaultsCommand(t *testing.T) {
	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)

	code := run([]string{"config", "dump", "-d", "--format", "yaml"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run returned exit code %d, want 0; stderr=%q", code, stderr.String())
	}
	output := stdout.String()
	if !strings.Contains(output, "runtime:") || !strings.Contains(output, "storage:") {
		t.Fatalf("default dump missing expected roots:\n%s", output)
	}
	if strings.Contains(output, "/etc/nauthilus-director/redis-password") {
		t.Fatalf("default dump leaked protected redis password path:\n%s", output)
	}
	if !strings.Contains(output, "<redacted>") {
		t.Fatalf("default dump missing redaction marker:\n%s", output)
	}
}

// TestConfigDumpNonDefaultCommandRedactionAndProtectedOutput checks -n and -n -P behavior.
func TestConfigDumpNonDefaultCommandRedactionAndProtectedOutput(t *testing.T) {
	t.Setenv("DIRECTOR_CLI_SECRET", "/run/secrets/from-cli-test")
	configPath := writeMainConfig(t, `runtime:
  instance_name: cli-test
storage:
  redis:
    auth:
      password_file: "${DIRECTOR_CLI_SECRET}"
`)

	var redactedOut, redactedErr bytes.Buffer
	code := run([]string{"config", "dump", "-n", "--config", configPath, "--format", "yaml"}, &redactedOut, &redactedErr)
	if code != 0 {
		t.Fatalf("redacted dump exit code %d, want 0; stderr=%q", code, redactedErr.String())
	}
	if strings.Contains(redactedOut.String(), "/run/secrets/from-cli-test") {
		t.Fatalf("redacted dump leaked secret:\n%s", redactedOut.String())
	}
	if !strings.Contains(redactedOut.String(), "<redacted>") {
		t.Fatalf("redacted dump missing marker:\n%s", redactedOut.String())
	}

	var protectedOut, protectedErr bytes.Buffer
	code = run([]string{"config", "dump", "-n", "-P", "--config", configPath, "--format", "yaml"}, &protectedOut, &protectedErr)
	if code != 0 {
		t.Fatalf("protected dump exit code %d, want 0; stderr=%q", code, protectedErr.String())
	}
	if !strings.Contains(protectedOut.String(), "/run/secrets/from-cli-test") {
		t.Fatalf("protected dump missing secret:\n%s", protectedOut.String())
	}
}

// TestConfigDumpMissingPlaceholderExitsNonZeroSafely prevents placeholder errors from leaking values.
func TestConfigDumpMissingPlaceholderExitsNonZeroSafely(t *testing.T) {
	t.Setenv("DIRECTOR_PRESENT", "do-not-leak")
	configPath := writeMainConfig(t, `runtime:
  instance_name: "prefix-${DIRECTOR_PRESENT}-${DIRECTOR_MISSING}"
`)

	var stdout, stderr bytes.Buffer
	code := run([]string{"config", "dump", "-n", "--config", configPath, "--format", "yaml"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("config dump returned success for missing placeholder")
	}
	errText := stderr.String()
	if !strings.Contains(errText, "runtime.instance_name") || !strings.Contains(errText, "DIRECTOR_MISSING") {
		t.Fatalf("stderr = %q, want path and missing variable name", errText)
	}
	if strings.Contains(errText, "do-not-leak") || strings.Contains(errText, "prefix-") {
		t.Fatalf("stderr leaked raw or expanded value: %q", errText)
	}
}

// writeMainConfig creates a temporary CLI fixture config.
func writeMainConfig(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "nauthilus-director.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	return path
}
