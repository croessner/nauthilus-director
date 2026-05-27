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
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/croessner/nauthilus-director/internal/config"
)

const (
	testClientIP           = "192.0.2.44"
	testDebugSecret        = "debug-secret"
	testLogBackendID       = "mailstore-a-imap"
	testLogOperationLookup = "lookup"
	testPrivateKey         = "-----BEGIN PRIVATE KEY-----secret"
	testProtectedValue     = "/run/secrets/username-hash-salt"
	testRawError           = "dial tcp alice@example.org password=debug-secret"
	testSASLBlob           = "AHVzZXIAc2VjcmV0"
	testSessionID          = "session-raw-123"
	testToken              = "debug-token"
	testUser               = "alice@example.org"
)

// TestJSONLoggingEmitsParseableStructuredRecord verifies JSON logs stay machine-readable.
func TestJSONLoggingEmitsParseableStructuredRecord(t *testing.T) {
	runtime, output := newLoggingTestRuntime(t, func(cfg *config.ObservabilityConfig) {
		cfg.Log.JSON = true
	})

	event := newLoggingTestEvent(t)
	runtime.Recorder().Record(context.Background(), event)

	record := decodeSingleJSONLog(t, output)
	if record[logFieldEventName] != EventRouteLookup {
		t.Fatalf("event_name = %v, want %s", record[logFieldEventName], EventRouteLookup)
	}

	if record[logFieldComponent] != "route" {
		t.Fatalf("component = %v, want route", record[logFieldComponent])
	}

	if record[metricLabelOperation] != testLogOperationLookup {
		t.Fatalf("operation = %v, want %s", record[metricLabelOperation], testLogOperationLookup)
	}
}

// TestTextLoggingEmitsStableKeyValueRecord verifies text logs keep stable fields.
func TestTextLoggingEmitsStableKeyValueRecord(t *testing.T) {
	runtime, output := newLoggingTestRuntime(t, func(cfg *config.ObservabilityConfig) {
		cfg.Log.JSON = false
	})

	runtime.Recorder().Record(context.Background(), newLoggingTestEvent(t))

	body := output.String()
	for _, want := range []string{
		"event_name=route.lookup",
		"component=route",
		"operation=lookup",
		"reason_class=ok",
		"result=ok",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("text log missing %q:\n%s", want, body)
		}
	}
}

// TestLogLevelFilteringDropsDebugAtInfo verifies debug records are suppressed by level.
func TestLogLevelFilteringDropsDebugAtInfo(t *testing.T) {
	runtime, output := newLoggingTestRuntime(t, func(cfg *config.ObservabilityConfig) {
		cfg.Log.Level = logLevelInfo
	})

	runtime.Recorder().Record(context.Background(), Event{
		Name: EventRESTRequest,
		LogFields: LogFields{
			telemetryFieldLevel:    logLevelDebug,
			metricLabelOperation:   testRESTOperationGetVersion,
			metricLabelReasonClass: reasonClassOK,
			metricLabelResult:      reasonClassOK,
		},
	})

	if output.Len() != 0 {
		t.Fatalf("debug record was emitted at info level:\n%s", output.String())
	}
}

// TestDebugLoggingKeepsHighRiskValuesOut verifies debug level does not weaken redaction.
func TestDebugLoggingKeepsHighRiskValuesOut(t *testing.T) {
	runtime, output := newLoggingTestRuntime(t, func(cfg *config.ObservabilityConfig) {
		cfg.Log.Level = logLevelDebug
		cfg.Log.JSON = false
	})

	runtime.Recorder().Record(context.Background(), highRiskLogEvent())

	assertLogDoesNotContainHighRiskValues(t, output.String())
	assertLogContainsPresenceMarkers(t, output.String())
}

// TestRedactSecretsFalseStillProtectsCredentials documents the narrow opt-out semantics.
func TestRedactSecretsFalseStillProtectsCredentials(t *testing.T) {
	runtime, output := newLoggingTestRuntime(t, func(cfg *config.ObservabilityConfig) {
		cfg.Log.Level = logLevelDebug
		cfg.Log.RedactSecrets = false
	})

	runtime.Recorder().Record(context.Background(), highRiskLogEvent())

	assertLogDoesNotContainHighRiskValues(t, output.String())

	if !strings.Contains(output.String(), RedactedValue) {
		t.Fatalf("log did not include redacted marker:\n%s", output.String())
	}
}

// TestBackendAndTraceDiagnosticsRemainLogOnly verifies diagnostic policy is not the metric policy.
func TestBackendAndTraceDiagnosticsRemainLogOnly(t *testing.T) {
	if err := ValidateMetricLabels(fieldBackendIdentifier); err == nil {
		t.Fatal("backend_identifier was accepted as a metric label")
	}

	if err := ValidateMetricLabels(fieldTraceID); err == nil {
		t.Fatal("trace_id was accepted as a metric label")
	}

	if err := ValidateMetricLabels(fieldSpanID); err == nil {
		t.Fatal("span_id was accepted as a metric label")
	}

	fields := SanitizeLogFields(map[string]string{
		fieldBackendIdentifier: testLogBackendID,
		fieldTraceID:           "0123456789abcdef0123456789abcdef",
		fieldSpanID:            "0123456789abcdef",
	})
	if fields[fieldBackendIdentifier] != testLogBackendID {
		t.Fatalf("backend identifier log field = %q", fields[fieldBackendIdentifier])
	}

	if fields[fieldTraceID] == "" || fields[fieldSpanID] == "" {
		t.Fatalf("trace/span log diagnostics missing: %#v", fields)
	}
}

// newLoggingTestRuntime creates a runtime with only structured logging enabled.
func newLoggingTestRuntime(t *testing.T, mutate func(*config.ObservabilityConfig)) (*Runtime, *bytes.Buffer) {
	t.Helper()

	cfg := config.DefaultConfig().Observability
	cfg.Metrics.Enabled = false

	cfg.Tracing.Enabled = false

	if mutate != nil {
		mutate(&cfg)
	}

	var output bytes.Buffer

	runtime, err := NewRuntime(cfg, WithLogWriter(&output))
	if err != nil {
		t.Fatalf("NewRuntime returned error: %v", err)
	}

	return runtime, &output
}

// newLoggingTestEvent creates a representative route lookup observation.
func newLoggingTestEvent(t *testing.T) Event {
	t.Helper()

	event, err := NewEvent(EventRouteLookup, TraceBoundaryRESTRequest, map[string]string{
		metricLabelOperation:   testLogOperationLookup,
		metricLabelReasonClass: reasonClassOK,
		metricLabelResult:      reasonClassOK,
		metricLabelRoute:       "/api/v1/route/lookup",
	}, map[string]string{
		metricLabelOperation:   testLogOperationLookup,
		metricLabelReasonClass: reasonClassOK,
		metricLabelResult:      reasonClassOK,
	})
	if err != nil {
		t.Fatalf("NewEvent returned error: %v", err)
	}

	return event
}

// highRiskLogEvent returns an intentionally raw event to prove sink-level safety.
func highRiskLogEvent() Event {
	return Event{
		Name: EventNauthilusAuth,
		LogFields: LogFields{
			fieldClientIP:          testClientIP,
			fieldPassword:          testDebugSecret,
			fieldPrivateKey:        testPrivateKey,
			fieldProtected:         testProtectedValue,
			fieldRawError:          testRawError,
			fieldRecipient:         testUser,
			fieldSASLBlob:          testSASLBlob,
			fieldSessionID:         testSessionID,
			fieldToken:             testToken,
			fieldUsername:          testUser,
			telemetryFieldLevel:    logLevelDebug,
			metricLabelOperation:   testOperationAuthenticate,
			metricLabelReasonClass: "password=" + testDebugSecret,
			metricLabelResult:      telemetryResultFailed,
		},
	}
}

// decodeSingleJSONLog decodes the first structured JSON log record.
func decodeSingleJSONLog(t *testing.T, output *bytes.Buffer) map[string]any {
	t.Helper()

	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("decode JSON log: %v\n%s", err, output.String())
	}

	return record
}

// assertLogDoesNotContainHighRiskValues checks raw protected values are absent.
func assertLogDoesNotContainHighRiskValues(t *testing.T, body string) {
	t.Helper()

	for _, forbidden := range []string{
		testDebugSecret,
		testClientIP,
		testPrivateKey,
		testProtectedValue,
		testRawError,
		testSASLBlob,
		testSessionID,
		testToken,
		testUser,
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("log leaked %q:\n%s", forbidden, body)
		}
	}
}

// assertLogContainsPresenceMarkers verifies high-risk identity fields collapse.
func assertLogContainsPresenceMarkers(t *testing.T, body string) {
	t.Helper()

	for _, want := range []string{
		"client_ip_present=true",
		"raw_error_present=true",
		"recipient_present=true",
		"session_id_present=true",
		"username_present=true",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("log missing %q:\n%s", want, body)
		}
	}
}
