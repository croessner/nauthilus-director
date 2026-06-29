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

package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
)

const (
	redactedSecret = "<redacted>"
	// MaxSecretFileBytes bounds one-line file-backed passwords and tokens.
	MaxSecretFileBytes = 64 << 10
)

// ErrSecretFile classifies fail-closed file-backed secret resolution errors.
var ErrSecretFile = errors.New("secret file error")

// SecretString is an explicitly protected scalar config value.
type SecretString struct {
	value string
}

// SecretFileOptions describes one bounded file-backed secret read.
type SecretFileOptions struct {
	Field    string
	Path     SecretString
	MaxBytes int64
}

// Secret creates a protected scalar value.
func Secret(value string) SecretString {
	return SecretString{value: value}
}

// Value returns the protected value for code paths that explicitly need it.
func (s SecretString) Value() string {
	return s.value
}

// IsZero reports whether the protected value is empty.
func (s SecretString) IsZero() bool {
	return s.value == ""
}

// String deliberately returns the redacted representation.
func (s SecretString) String() string {
	if s.value == "" {
		return ""
	}

	return redactedSecret
}

// GoString deliberately returns only the redacted representation in diagnostics.
func (s SecretString) GoString() string {
	return s.String()
}

// MarshalYAML keeps direct YAML marshaling redaction-safe by default.
func (s SecretString) MarshalYAML() (any, error) {
	return s.String(), nil
}

// ReadSecretFile reads one configured secret file without exposing path or content in errors.
func ReadSecretFile(options SecretFileOptions) (string, error) {
	field := strings.TrimSpace(options.Field)
	if field == "" {
		field = "secret_file"
	}

	if options.MaxBytes <= 0 {
		return "", secretFileError(field, "has invalid size bound")
	}

	path := strings.TrimSpace(options.Path.Value())
	if path == "" {
		return "", secretFileError(field, "is required")
	}

	fileInfo, err := os.Stat(path)
	if err != nil {
		return "", secretFileError(field, "is unreadable")
	}

	if !fileInfo.Mode().IsRegular() {
		return "", secretFileError(field, "must reference a regular file")
	}

	file, err := os.Open(path)
	if err != nil {
		return "", secretFileError(field, "is unreadable")
	}
	defer func() {
		_ = file.Close()
	}()

	content, err := io.ReadAll(io.LimitReader(file, options.MaxBytes+1))
	if err != nil {
		return "", secretFileError(field, "is unreadable")
	}

	if int64(len(content)) > options.MaxBytes {
		return "", secretFileError(field, "is too large")
	}

	secret := strings.TrimRight(string(content), "\r\n")
	if secret == "" {
		return "", secretFileError(field, "is empty")
	}

	return secret, nil
}

// ReadSecretFileValue resolves one file-backed secret into protected secret metadata.
func ReadSecretFileValue(options SecretFileOptions) (SecretString, error) {
	secret, err := ReadSecretFile(options)
	if err != nil {
		return SecretString{}, err
	}

	return Secret(secret), nil
}

// ReadOptionalSecretFile resolves a configured secret file and preserves empty optional fields.
func ReadOptionalSecretFile(options SecretFileOptions) (string, error) {
	if options.Path.IsZero() {
		return "", nil
	}

	return ReadSecretFile(options)
}

// ReadOptionalSecretFileValue resolves an optional file-backed secret into protected metadata.
func ReadOptionalSecretFileValue(options SecretFileOptions) (SecretString, error) {
	secret, err := ReadOptionalSecretFile(options)
	if err != nil {
		return SecretString{}, err
	}

	return Secret(secret), nil
}

// secretFileError wraps secret-file failures without adding path or content details.
func secretFileError(field string, reason string) error {
	message := strings.TrimSpace(field) + " " + strings.TrimSpace(reason)
	return fmt.Errorf("%w: %s", ErrSecretFile, message)
}

// secretDecodeHook preserves explicit secret metadata during typed decode.
func secretDecodeHook(_ reflect.Type, to reflect.Type, value any) (any, error) {
	if to != reflect.TypeFor[SecretString]() {
		return value, nil
	}

	switch typed := value.(type) {
	case SecretString:
		return typed, nil
	case string:
		return Secret(typed), nil
	default:
		return nil, fmt.Errorf("cannot decode %T as protected string", value)
	}
}
