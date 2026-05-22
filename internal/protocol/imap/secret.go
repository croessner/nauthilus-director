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

package imap

const redactedCredential = "<redacted>"

// credentialSecret keeps credential material out of normal formatting paths.
type credentialSecret struct {
	value []byte
}

// newCredentialSecret copies a credential value into a redaction-aware wrapper.
func newCredentialSecret(value string) *credentialSecret {
	return &credentialSecret{value: []byte(value)}
}

// Value returns the wrapped credential for the short-lived authority call path.
func (s *credentialSecret) Value() string {
	if s == nil {
		return ""
	}

	return string(s.value)
}

// Len reports the byte length of the wrapped credential.
func (s *credentialSecret) Len() int {
	if s == nil {
		return 0
	}

	return len(s.value)
}

// IsZero reports whether the wrapper contains no credential material.
func (s *credentialSecret) IsZero() bool {
	return s == nil || len(s.value) == 0
}

// Clear overwrites the local copy and releases the wrapped credential bytes.
func (s *credentialSecret) Clear() {
	if s == nil {
		return
	}

	for index := range s.value {
		s.value[index] = 0
	}

	s.value = nil
}

// String returns only a redaction marker for non-empty credentials.
func (s *credentialSecret) String() string {
	if s.IsZero() {
		return ""
	}

	return redactedCredential
}

// GoString returns only a redaction marker for Go-syntax formatting.
func (s *credentialSecret) GoString() string {
	return s.String()
}
