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

const (
	testDiagnosticAccount     = "alice@example.org"
	testDiagnosticBackendID   = "mailstore-a-imap"
	testOperationAuthenticate = "authenticate"
)

const (
	testReasonClassOther                  = "other"
	testReasonClassRuntimeHardMaintenance = "runtime_hard_maintenance"
	testReasonClassRuntimeOut             = "runtime_out"
	testReasonClassUserHoldActive         = "user_hold_active"
	testReasonClassUserHoldWaiterLimit    = "user_hold_waiter_limit_exceeded"
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

	expected := []string{
		"nauthilus_director.backend.connect",
		"nauthilus_director.backend.select",
		"nauthilus_director.imap.pre_auth",
		"nauthilus_director.lmtp.transaction",
		"nauthilus_director.nauthilus.auth",
		"nauthilus_director.pop3.pre_auth",
		"nauthilus_director.proxy.pipe",
		"nauthilus_director.rest.request",
		"nauthilus_director.routing.resolve",
		"nauthilus_director.session",
		"nauthilus_director.sieve.pre_auth",
	}

	names := PreparedSpanNames()
	if len(names) != len(expected) {
		t.Fatalf("prepared span names = %d, want %d", len(names), len(expected))
	}

	for index, want := range expected {
		if names[index] != want {
			t.Fatalf("prepared span name[%d] = %q, want %q", index, names[index], want)
		}
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

// TestTraceAttributesApplyDiagnosticPolicy verifies traces have their own safe attribute policy.
func TestTraceAttributesApplyDiagnosticPolicy(t *testing.T) {
	fields := SanitizeTraceFields(map[string]string{
		fieldBackendIdentifier: testDiagnosticBackendID,
		fieldClientIP:          "192.0.2.10",
		fieldPassword:          "secret",
		fieldRawError:          "dial tcp 192.0.2.10:143: secret",
		fieldRecipient:         testDiagnosticAccount,
		fieldRedisKey:          "{alice}:session",
		fieldUsername:          testDiagnosticAccount,
		metricLabelOperation:   testOperationAuthenticate,
	})

	if fields[fieldPassword] != RedactedValue {
		t.Fatalf("password trace attribute = %q, want redacted", fields[fieldPassword])
	}

	if fields[fieldBackendIdentifier] != testDiagnosticBackendID {
		t.Fatalf("backend identifier trace attribute = %q", fields[fieldBackendIdentifier])
	}

	for _, name := range []string{fieldClientIP, fieldRawError, fieldRecipient, fieldRedisKey, fieldUsername} {
		if _, ok := fields[name]; ok {
			t.Fatalf("raw trace attribute %q remained", name)
		}

		if fields[name+logFieldPresentSuffix] != logBoolTrue {
			t.Fatalf("%s presence = %q, want true", name, fields[name+logFieldPresentSuffix])
		}
	}
}

// TestMailContentFieldsCollapseBeforeLogsAndTraces verifies message-specific values never pass through raw.
func TestMailContentFieldsCollapseBeforeLogsAndTraces(t *testing.T) {
	rawValues := map[string]string{
		fieldAuthorizationHeader: "Bearer raw-token",
		fieldEnvelopeSender:      "sender@example.test",
		fieldMessageBody:         "Subject: private\r\n\r\nsecret body",
		fieldMessageContent:      "DATA private text",
		fieldMessageID:           "<private-message@example.test>",
		fieldRecipient:           testDiagnosticAccount,
		fieldSubject:             "private subject",
	}

	logFields := SanitizeLogFields(rawValues)
	traceFields := SanitizeTraceFields(rawValues)

	for name, value := range rawValues {
		if _, ok := logFields[name]; ok {
			t.Fatalf("raw log field %q remained", name)
		}

		if _, ok := traceFields[name]; ok {
			t.Fatalf("raw trace field %q remained", name)
		}

		if logFields[name+logFieldPresentSuffix] != logBoolTrue {
			t.Fatalf("log presence for %q = %q, want true", name, logFields[name+logFieldPresentSuffix])
		}

		if traceFields[name+logFieldPresentSuffix] != logBoolTrue {
			t.Fatalf("trace presence for %q = %q, want true", name, traceFields[name+logFieldPresentSuffix])
		}

		assertNoSanitizedValue(t, logFields, value)
		assertNoSanitizedValue(t, traceFields, value)
	}

	if _, err := NewEvent(EventLMTPRecipientRoute, TraceBoundaryLMTPTransaction, nil, map[string]string{fieldRecipient: testDiagnosticAccount}); err == nil {
		t.Fatal("NewEvent accepted recipient as a metric label")
	}

	if _, err := NewEvent(EventLMTPDataStream, TraceBoundaryLMTPTransaction, nil, map[string]string{fieldMessageBody: "private body"}); err == nil {
		t.Fatal("NewEvent accepted message_body as a metric label")
	}
}

// TestBackendIdentifierPolicyDiffersBySink keeps logs/traces separate from metrics.
func TestBackendIdentifierPolicyDiffersBySink(t *testing.T) {
	if err := ValidateMetricLabels(fieldBackendIdentifier); err == nil {
		t.Fatal("backend_identifier was accepted as a metric label")
	}

	logFields := SanitizeLogFields(map[string]string{fieldBackendIdentifier: testDiagnosticBackendID})
	if logFields[fieldBackendIdentifier] != testDiagnosticBackendID {
		t.Fatalf("backend identifier log field = %q", logFields[fieldBackendIdentifier])
	}

	traceFields := SanitizeTraceFields(map[string]string{fieldBackendIdentifier: testDiagnosticBackendID})
	if traceFields[fieldBackendIdentifier] != testDiagnosticBackendID {
		t.Fatalf("backend identifier trace field = %q", traceFields[fieldBackendIdentifier])
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
		EventListenerInventory:           false,
		EventListenerDrain:               false,
		EventListenerResume:              false,
		EventListenerOperationFailure:    false,
		EventSelectorExclusion:           false,
		EventSessionAttach:               false,
		EventSessionClose:                false,
		EventSessionReap:                 false,
		EventSessionKill:                 false,
		EventUserMove:                    false,
		EventUserKick:                    false,
		EventUserBackendPin:              false,
		EventUserHold:                    false,
		EventAffinityClear:               false,
		EventRouteLookup:                 false,
		EventReload:                      false,
		EventRedisOperation:              false,
		EventRuntimePagination:           false,
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
		reasonClassBackendPinApplied:               reasonClassBackendPinApplied,
		"backend pin mismatch":                     reasonClassBackendPinMismatch,
		reasonClassOperatorBackendPin:              reasonClassOperatorBackendPin,
		reasonClassAuth:                            reasonClassAuth,
		reasonClassBackendStatus:                   reasonClassBackendStatus,
		reasonClassBDAT:                            reasonClassBDAT,
		reasonClassData:                            reasonClassData,
		reasonClassParser:                          reasonClassParser,
		reasonClassRouting:                         reasonClassRouting,
		"Runtime Hard Maintenance":                 testReasonClassRuntimeHardMaintenance,
		reasonClassSameBackend:                     reasonClassSameBackend,
		"user hold active":                         testReasonClassUserHoldActive,
		testReasonClassUserHoldWaiterLimit:         testReasonClassUserHoldWaiterLimit,
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

// assertNoSanitizedValue verifies sanitized fields do not contain one raw value.
func assertNoSanitizedValue(t *testing.T, fields map[string]string, value string) {
	t.Helper()

	for name, current := range fields {
		if current == value {
			t.Fatalf("sanitized field %q leaked %q", name, value)
		}
	}
}
