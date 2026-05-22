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

const (
	// RedactedValue is the only value emitted for secret-bearing log fields.
	RedactedValue = "<redacted>"

	logBoolFalse          = "false"
	logBoolTrue           = "true"
	logFieldPresentSuffix = "_present"
)

// LogFields contains structured log fields after safety normalization.
type LogFields map[string]string

// SanitizeLogFields redacts secrets and collapses high-cardinality fields.
func SanitizeLogFields(fields map[string]string) LogFields {
	safe := make(LogFields, len(fields))
	for name, value := range fields {
		switch {
		case IsSecretFieldName(name):
			safe[name] = RedactedValue
		case IsHighCardinalityFieldName(name):
			safe[name+logFieldPresentSuffix] = boolString(value != "")
		default:
			safe[name] = value
		}
	}

	return safe
}

// SecretLogField returns a field value that is always redacted.
func SecretLogField(name string) LogFields {
	return LogFields{name: RedactedValue}
}

// boolString renders booleans without importing a logger-specific type.
func boolString(value bool) string {
	if value {
		return logBoolTrue
	}

	return logBoolFalse
}
