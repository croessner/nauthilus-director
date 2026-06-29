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

//nolint:goconst // Table names intentionally mirror secret-file states.
package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReadSecretFileLoadsContent verifies file-backed fields resolve to file contents.
func TestReadSecretFileLoadsContent(t *testing.T) {
	path := writeSecretFile(t, "redis-password\n")

	secret, err := ReadSecretFile(SecretFileOptions{
		Field:    "storage.redis.auth.password_file",
		Path:     Secret(path),
		MaxBytes: 1024,
	})
	if err != nil {
		t.Fatalf("ReadSecretFile returned error: %v", err)
	}

	if secret != "redis-password" {
		t.Fatalf("secret = %q, want file content without trailing newline", secret)
	}

	if secret == path {
		t.Fatal("secret resolver used the path string itself")
	}
}

// TestReadSecretFileFailsClosed verifies unsafe file references are rejected.
func TestReadSecretFileFailsClosed(t *testing.T) {
	dir := t.TempDir()
	missingPath := filepath.Join(dir, "missing")
	emptyPath := writeSecretFile(t, "")
	directoryPath := t.TempDir()
	unreadablePath := writeSecretFile(t, "hidden-file-content")

	if err := os.Chmod(unreadablePath, 0o000); err != nil {
		t.Fatalf("chmod unreadable secret: %v", err)
	}

	t.Cleanup(func() {
		_ = os.Chmod(unreadablePath, 0o600)
	})

	tests := map[string]struct {
		path    string
		content string
	}{
		"missing":    {path: missingPath},
		"empty":      {path: emptyPath},
		"directory":  {path: directoryPath},
		"unreadable": {path: unreadablePath, content: "hidden-file-content"},
	}
	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ReadSecretFile(SecretFileOptions{
				Field:    "auth.authorities.default.grpc.caller_auth.basic.password_file",
				Path:     Secret(testCase.path),
				MaxBytes: 1024,
			})
			if err == nil {
				t.Fatal("ReadSecretFile returned nil error")
			}

			assertSecretFileErrorSafe(t, err, testCase.path, testCase.content)
		})
	}
}

// TestReadSecretFileRejectsOversizedSecrets checks the caller-supplied bound.
func TestReadSecretFileRejectsOversizedSecrets(t *testing.T) {
	path := writeSecretFile(t, "abcdef")

	_, err := ReadSecretFile(SecretFileOptions{
		Field:    "director.backends.mailstore.auth.oauthbearer.token_file",
		Path:     Secret(path),
		MaxBytes: 5,
	})
	if err == nil {
		t.Fatal("ReadSecretFile accepted oversized content")
	}

	assertSecretFileErrorSafe(t, err, path, "abcdef")
}

// TestReadSecretFileRequiresPath keeps omitted file-backed secrets fail closed.
func TestReadSecretFileRequiresPath(t *testing.T) {
	_, err := ReadSecretFile(SecretFileOptions{
		Field:    "runtime.servers.control.auth.bearer.token_file",
		Path:     Secret(""),
		MaxBytes: 1024,
	})
	if err == nil {
		t.Fatal("ReadSecretFile accepted an empty path")
	}

	assertSecretFileErrorSafe(t, err, "", "")
}

// writeSecretFile writes one temporary secret fixture with private permissions.
func writeSecretFile(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write secret file: %v", err)
	}

	return path
}

// assertSecretFileErrorSafe verifies diagnostics do not expose paths or content.
func assertSecretFileErrorSafe(t *testing.T, err error, path string, content string) {
	t.Helper()

	if !errors.Is(err, ErrSecretFile) {
		t.Fatalf("error = %v, want ErrSecretFile", err)
	}

	errText := err.Error()
	if path != "" && strings.Contains(errText, path) {
		t.Fatalf("error leaked secret file path: %q", errText)
	}

	if content != "" && strings.Contains(errText, content) {
		t.Fatalf("error leaked secret file content: %q", errText)
	}
}
