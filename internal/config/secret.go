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
	"fmt"
	"reflect"
)

const redactedSecret = "<redacted>"

// SecretString is an explicitly protected scalar config value.
type SecretString struct {
	value string
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
