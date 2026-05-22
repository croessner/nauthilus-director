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

// TestTraceSpanNamesPrepared verifies named M0 trace boundaries.
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
