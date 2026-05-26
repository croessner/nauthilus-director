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

import "testing"

const testOperationAuthenticate = "authenticate"

const (
	testReasonClassOther                  = "other"
	testReasonClassRuntimeHardMaintenance = "runtime_hard_maintenance"
	testReasonClassRuntimeOut             = "runtime_out"
)

// TestMetricLabelAllowlistAcceptsDocumentedLabels verifies approved labels.
func TestMetricLabelAllowlistAcceptsDocumentedLabels(t *testing.T) {
	labels := map[string]string{
		metricLabelBackendPool: "imap-default",
		metricLabelOperation:   "resolve",
		metricLabelProtocol:    "imap",
		metricLabelResult:      "ok",
		metricLabelShardTag:    "mailstore-a",
	}

	if _, err := NewMetricLabels(labels); err != nil {
		t.Fatalf("NewMetricLabels returned error: %v", err)
	}
}

// TestMetricLabelAllowlistRejectsForbiddenLabels verifies hard forbidden names.
func TestMetricLabelAllowlistRejectsForbiddenLabels(t *testing.T) {
	for _, label := range ForbiddenMetricLabels() {
		if err := ValidateMetricLabels(label); err == nil {
			t.Fatalf("ValidateMetricLabels(%q) returned nil error", label)
		}
	}

	if err := ValidateMetricLabels("custom_label"); err == nil {
		t.Fatal("custom_label was accepted without allowlist entry")
	}
}

// TestSanitizeLogFieldsRedactsSecretsAndCollapsesIdentityValues checks log safety.
func TestSanitizeLogFieldsRedactsSecretsAndCollapsesIdentityValues(t *testing.T) {
	fields := SanitizeLogFields(map[string]string{
		fieldClientIP:        "192.0.2.10",
		metricLabelOperation: testOperationAuthenticate,
		fieldPassword:        "secret",
		fieldSessionID:       "session-1",
		fieldUsername:        "user@example.org",
	})

	if fields[fieldPassword] != RedactedValue {
		t.Fatalf("password field = %q, want redacted", fields[fieldPassword])
	}

	if fields["username_present"] != logBoolTrue {
		t.Fatalf("username_present = %q, want true", fields["username_present"])
	}

	if fields["client_ip_present"] != logBoolTrue {
		t.Fatalf("client_ip_present = %q, want true", fields["client_ip_present"])
	}

	if fields["session_id_present"] != logBoolTrue {
		t.Fatalf("session_id_present = %q, want true", fields["session_id_present"])
	}

	if _, ok := fields[fieldUsername]; ok {
		t.Fatal("raw username remained in log fields")
	}

	if fields[metricLabelOperation] != testOperationAuthenticate {
		t.Fatalf("operation = %q, want authenticate", fields[metricLabelOperation])
	}
}

// TestTraceSpanNamesPrepared verifies named trace boundaries.
func TestTraceSpanNamesPrepared(t *testing.T) {
	routingName, ok := SpanName(TraceBoundaryRoutingResolve)
	if !ok {
		t.Fatal("routing span name missing")
	}

	if routingName != traceSpanRoutingResolve {
		t.Fatalf("routing span = %q", routingName)
	}

	authName, ok := SpanName(TraceBoundaryNauthilusAuth)
	if !ok {
		t.Fatal("auth span name missing")
	}

	if authName != traceSpanNauthilusAuth {
		t.Fatalf("auth span = %q", authName)
	}

	if len(PreparedSpanNames()) == 0 {
		t.Fatal("prepared span name list is empty")
	}
}

// TestIMAPSessionSpanNamesPrepared verifies the IMAP session span boundaries.
func TestIMAPSessionSpanNamesPrepared(t *testing.T) {
	required := map[TraceBoundary]string{
		TraceBoundaryBackendConnect: traceSpanBackendConnect,
		TraceBoundaryBackendSelect:  traceSpanBackendSelect,
		TraceBoundaryIMAPPreAuth:    traceSpanIMAPPreAuth,
		TraceBoundaryNauthilusAuth:  traceSpanNauthilusAuth,
		TraceBoundaryProxyPipe:      traceSpanProxyPipe,
		TraceBoundaryRoutingResolve: traceSpanRoutingResolve,
		TraceBoundarySession:        traceSpanSession,
	}

	for boundary, want := range required {
		got, ok := SpanName(boundary)
		if !ok {
			t.Fatalf("span name for %q is missing", boundary)
		}

		if got != want {
			t.Fatalf("span name for %q = %q, want %q", boundary, got, want)
		}
	}
}

// TestEventNormalizationAppliesLogAndMetricPolicies verifies runtime hooks cannot bypass policy helpers.
func TestEventNormalizationAppliesLogAndMetricPolicies(t *testing.T) {
	event, err := NewEvent(EventNauthilusAuth, TraceBoundaryNauthilusAuth, map[string]string{
		fieldPassword:     "secret-password",
		fieldSessionID:    "session-1",
		metricLabelResult: "ok",
	}, map[string]string{
		metricLabelMechanism: "plain",
		metricLabelOperation: "authenticate",
		metricLabelProtocol:  "imap",
		metricLabelResult:    "ok",
	})
	if err != nil {
		t.Fatalf("NewEvent returned error: %v", err)
	}

	if event.SpanName != traceSpanNauthilusAuth {
		t.Fatalf("span name = %q, want %q", event.SpanName, traceSpanNauthilusAuth)
	}

	if event.LogFields[fieldPassword] != RedactedValue {
		t.Fatalf("password field = %q, want redacted", event.LogFields[fieldPassword])
	}

	if _, ok := event.LogFields[fieldSessionID]; ok {
		t.Fatal("raw session ID remained in event log fields")
	}

	if event.LogFields["session_id_present"] != logBoolTrue {
		t.Fatalf("session_id_present = %q, want true", event.LogFields["session_id_present"])
	}

	if err := event.MetricLabels.Validate(); err != nil {
		t.Fatalf("event metric labels failed validation: %v", err)
	}
}

// TestEventNormalizationRejectsForbiddenMetricLabels keeps raw errors out of result labels.
func TestEventNormalizationRejectsForbiddenMetricLabels(t *testing.T) {
	_, err := NewEvent(EventProxyPipe, TraceBoundaryProxyPipe, nil, map[string]string{
		fieldRawError: "dial tcp failed with raw details",
	})
	if err == nil {
		t.Fatal("NewEvent accepted raw_error as a metric label")
	}
}

// TestRuntimeEventVocabularyCoversControlSurface verifies runtime hooks are named explicitly.
func TestRuntimeEventVocabularyCoversControlSurface(t *testing.T) {
	required := map[string]bool{
		EventBackendHealthTransition:     false,
		EventBackendEffectiveState:       false,
		EventBackendRuntimeOperation:     false,
		EventBackendMaintenanceOperation: false,
		EventBackendDrain:                false,
		EventSelectorExclusion:           false,
		EventSessionAttach:               false,
		EventSessionClose:                false,
		EventSessionReap:                 false,
		EventSessionKill:                 false,
		EventUserMove:                    false,
		EventUserKick:                    false,
		EventAffinityClear:               false,
		EventRouteLookup:                 false,
		EventReload:                      false,
	}

	for _, name := range RuntimeEventNames() {
		if required[name] {
			t.Fatalf("runtime event %q is listed more than once", name)
		}

		if _, ok := required[name]; ok {
			required[name] = true
		}
	}

	if len(RuntimeEventNames()) != len(required) {
		t.Fatalf("RuntimeEventNames returned %d events, want %d", len(RuntimeEventNames()), len(required))
	}

	for name, seen := range required {
		if !seen {
			t.Fatalf("runtime event %q is missing from RuntimeEventNames", name)
		}
	}
}

// TestReasonClassNormalizationKeepsMetricValuesBounded verifies raw errors become generic classes.
func TestReasonClassNormalizationKeepsMetricValuesBounded(t *testing.T) {
	tests := map[string]string{
		testReasonClassRuntimeOut:                  testReasonClassRuntimeOut,
		"Runtime Hard Maintenance":                 testReasonClassRuntimeHardMaintenance,
		"dial tcp 127.0.0.1:143: secret token":     testReasonClassOther,
		"session_id":                               testReasonClassOther,
		"custom per-user backend error alice@test": testReasonClassOther,
	}

	for input, want := range tests {
		if got := NormalizeReasonClass(input); got != want {
			t.Fatalf("NormalizeReasonClass(%q) = %q, want %q", input, got, want)
		}
	}
}
