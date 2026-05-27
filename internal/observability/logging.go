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

import "strings"

const (
	// RedactedValue is the only value emitted for secret-bearing log fields.
	RedactedValue = "<redacted>"

	defaultLogValueMaxRunes = 512
	logBoolFalse            = "false"
	logBoolTrue             = "true"
	logFieldPresentSuffix   = "_present"
)

// LogFields contains structured log fields after safety normalization.
type LogFields map[string]string

// LogPolicy controls structured-log field normalization independently from metrics.
type LogPolicy struct {
	maxValueRunes int
}

// NewLogPolicy creates the runtime log policy from typed logging config.
func NewLogPolicy(redactSecrets bool) LogPolicy {
	maxValueRunes := defaultLogValueMaxRunes
	if !redactSecrets {
		maxValueRunes *= 2
	}

	return LogPolicy{maxValueRunes: maxValueRunes}
}

// DefaultLogPolicy returns the secret-safe policy used before runtime config exists.
func DefaultLogPolicy() LogPolicy {
	return NewLogPolicy(true)
}

// SanitizeLogFields redacts secrets and collapses high-cardinality fields.
func SanitizeLogFields(fields map[string]string) LogFields {
	return DefaultLogPolicy().Sanitize(fields)
}

// Sanitize redacts secrets and collapses high-cardinality fields for logs.
func (p LogPolicy) Sanitize(fields map[string]string) LogFields {
	safe := make(LogFields, len(fields))
	for name, value := range fields {
		p.addField(safe, name, value)
	}

	return safe
}

// addField applies the log-field policy to one raw field.
func (p LogPolicy) addField(safe LogFields, name string, value string) {
	normalized := normalizeFieldName(name)
	if normalized == "" {
		return
	}

	switch {
	case IsSecretFieldName(normalized):
		safe[normalized] = p.secretValue()
	case normalized == metricLabelReasonClass:
		safe[normalized] = NormalizeReasonClass(value)
	case normalized == metricLabelResult:
		safe[normalized] = normalizeLogToken(value, reasonClassOther)
	case IsDiagnosticLogFieldAllowed(normalized):
		safe[normalized] = p.boundedValue(value)
	case IsCollapsedLogFieldName(normalized):
		safe[normalized+logFieldPresentSuffix] = boolString(strings.TrimSpace(value) != "")
	default:
		safe[normalized] = p.boundedValue(value)
	}
}

// secretValue keeps protected values redacted even when future diagnostics expand.
func (LogPolicy) secretValue() string {
	return RedactedValue
}

// boundedValue keeps log diagnostics finite under the configured policy.
func (p LogPolicy) boundedValue(value string) string {
	limit := p.maxValueRunes
	if limit <= 0 {
		limit = defaultLogValueMaxRunes
	}

	return boundedLogFieldValue(value, limit)
}

// SecretLogField returns a field value that is always redacted.
func SecretLogField(name string) LogFields {
	return LogFields{normalizeFieldName(name): RedactedValue}
}

// boolString renders booleans without importing a logger-specific type.
func boolString(value bool) string {
	if value {
		return logBoolTrue
	}

	return logBoolFalse
}

// normalizeLogToken keeps operational tokens bounded without accepting raw text.
func normalizeLogToken(value string, fallback string) string {
	normalized, ok := normalizedReasonToken(strings.ToLower(strings.TrimSpace(value)))
	if !ok || normalized == "" || IsSecretFieldName(normalized) || IsHighCardinalityFieldName(normalized) {
		return fallback
	}

	return normalized
}

// boundedLogFieldValue keeps log diagnostics finite and line-oriented.
func boundedLogFieldValue(value string, maxRunes int) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}

	var builder strings.Builder
	builder.Grow(len(trimmed))

	count := 0
	for _, token := range trimmed {
		if count >= maxRunes {
			break
		}

		if token < ' ' {
			builder.WriteByte(' ')
		} else {
			builder.WriteRune(token)
		}

		count++
	}

	return strings.TrimSpace(builder.String())
}
