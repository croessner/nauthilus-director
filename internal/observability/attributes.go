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

import (
	"maps"
	"sort"
	"strings"
	"unicode/utf8"

	"go.opentelemetry.io/otel/attribute"
)

const (
	maxTraceAttributeValueRunes = 256
	traceAttributeUnknown       = "unknown"
)

var traceDiagnosticFields = map[string]struct{}{
	fieldBackendIdentifier: {},
	fieldSpanID:            {},
	fieldTraceID:           {},
}

// TraceAttributesForEvent converts an event into policy-checked span attributes.
func TraceAttributesForEvent(event Event) []attribute.KeyValue {
	fields := map[string]string{
		otelAttributeEventName: event.Name,
	}

	maps.Copy(fields, event.MetricLabels)

	maps.Copy(fields, event.LogFields)

	return NewTraceAttributes(fields)
}

// NewTraceAttributes returns sanitized OpenTelemetry attributes for raw fields.
func NewTraceAttributes(fields map[string]string) []attribute.KeyValue {
	safe := SanitizeTraceFields(fields)

	names := make([]string, 0, len(safe))
	for name := range safe {
		names = append(names, name)
	}

	sort.Strings(names)

	attrs := make([]attribute.KeyValue, 0, len(names))
	for _, name := range names {
		attrs = append(attrs, attribute.String(name, safe[name]))
	}

	return attrs
}

// SanitizeTraceFields applies trace-specific redaction and cardinality policy.
func SanitizeTraceFields(fields map[string]string) map[string]string {
	safe := make(map[string]string, len(fields))
	for name, value := range fields {
		normalized := normalizeFieldName(name)
		if normalized == "" {
			continue
		}

		traceName, traceValue := safeTraceField(normalized, value)
		if traceName == "" {
			continue
		}

		safe[traceName] = traceValue
	}

	return safe
}

// IsTraceDiagnosticField reports whether traces may carry a diagnostic value.
func IsTraceDiagnosticField(name string) bool {
	_, ok := traceDiagnosticFields[normalizeFieldName(name)]

	return ok
}

// IsTraceRawFieldForbidden reports whether traces must not carry a raw value.
func IsTraceRawFieldForbidden(name string) bool {
	normalized := normalizeFieldName(name)
	if normalized == "" {
		return true
	}

	if strings.HasSuffix(normalized, logFieldPresentSuffix) {
		return false
	}

	if IsSecretFieldName(normalized) {
		return true
	}

	if IsTraceDiagnosticField(normalized) {
		return false
	}

	return IsCollapsedLogFieldName(normalized)
}

// safeTraceField returns the exported attribute name and value for one field.
func safeTraceField(name string, value string) (string, string) {
	switch {
	case name == otelAttributeEventName:
		return name, boundedTraceAttributeValue(value)
	case IsSecretFieldName(name):
		return name, RedactedValue
	case strings.HasSuffix(name, logFieldPresentSuffix):
		return name, boolString(strings.TrimSpace(value) != "" && strings.TrimSpace(value) != logBoolFalse)
	case IsTraceRawFieldForbidden(name):
		return name + logFieldPresentSuffix, boolString(strings.TrimSpace(value) != "")
	case name == metricLabelResult:
		return name, normalizeTraceResult(value)
	case name == metricLabelReasonClass:
		return name, NormalizeReasonClass(value)
	default:
		return name, boundedTraceAttributeValue(value)
	}
}

// normalizeTraceResult keeps result attributes tokenized and non-secret.
func normalizeTraceResult(value string) string {
	normalized, ok := normalizedReasonToken(strings.ToLower(strings.TrimSpace(value)))
	if !ok || normalized == "" || IsSecretFieldName(normalized) || IsHighCardinalityFieldName(normalized) {
		return reasonClassOther
	}

	return normalized
}

// boundedTraceAttributeValue keeps trace attributes useful but finite.
func boundedTraceAttributeValue(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return traceAttributeUnknown
	}

	var builder strings.Builder
	builder.Grow(len(trimmed))

	count := 0
	for len(trimmed) > 0 && count < maxTraceAttributeValueRunes {
		r, size := utf8.DecodeRuneInString(trimmed)
		if r == utf8.RuneError && size == 0 {
			break
		}

		if r < ' ' {
			builder.WriteByte(' ')
		} else {
			builder.WriteRune(r)
		}

		trimmed = trimmed[size:]
		count++
	}

	return strings.TrimSpace(builder.String())
}
