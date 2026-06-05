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

//nolint:goconst,wsl_v5 // Observability tests repeat secret and mailbox sentinels intentionally.
package pop3

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/protocol/saslcred"
	"github.com/croessner/nauthilus-director/internal/proxy"
	runtimectl "github.com/croessner/nauthilus-director/internal/runtime"
	"go.opentelemetry.io/otel/attribute"
)

const (
	testPOP3ForbiddenBearerToken    = "pop3-observability-bearer-token"
	testPOP3ForbiddenMessageContent = "Subject: pop3-observability-message-content"
	testPOP3ForbiddenMessageNumber  = "4242"
	testPOP3ForbiddenMessageSize    = "987654"
	testPOP3ForbiddenSASLBlob       = "AHBvcDMAdGVzdA=="
	testPOP3ForbiddenUIDL           = "pop3-observability-uidl"
	testPOP3ForbiddenUsername       = "pop3-user@example.test"
)

// TestPOP3MetricRegistrationUsesOnlyAllowedLabels verifies POP3 observations stay in policy.
func TestPOP3MetricRegistrationUsesOnlyAllowedLabels(t *testing.T) {
	session, cleanup := newPOP3ObservationSession(t)
	defer cleanup()

	events := []observability.Event{
		session.newObservation(observability.EventPOP3PreAuth, observability.TraceBoundaryPOP3PreAuth, pop3ObservationOperationAuthenticate, pop3ObservationResultRejected, pop3ReasonCredentialInput, map[string]string{
			pop3ObsFieldMechanism: authMethodUserPass,
		}),
		session.newObservation(observability.EventNauthilusAuth, observability.TraceBoundaryNauthilusAuth, pop3ObservationOperationAuthenticate, pop3ObservationResultOK, pop3ReasonOK, map[string]string{
			pop3ObsFieldMechanism: saslcred.MechanismXOAUTH2,
			pop3ObsFieldTransport: "http",
		}),
		session.newObservation(observability.EventRoutingResolve, observability.TraceBoundaryRoutingResolve, pop3ObservationOperationRouting, pop3ObservationResultOK, pop3ReasonOK, map[string]string{
			pop3ObsFieldShardTag: "mailstore-a",
		}),
		session.newObservation(observability.EventUserHold, observability.TraceBoundaryBackendSelect, pop3ObservationOperationHoldWait, pop3ObservationResultWaitReleased, pop3ReasonUserHoldWaitReleased, nil),
		session.newObservation(observability.EventBackendSelect, observability.TraceBoundaryBackendSelect, pop3ObservationOperationBackendSelect, pop3ObservationResultOK, "operator_backend_pin", map[string]string{
			pop3ObsFieldBackendIdentifier: "mailstore-a-pop3",
			pop3ObsFieldBackendNode:       "node-a",
			pop3ObsFieldShardTag:          "mailstore-a",
		}),
		session.newObservation(observability.EventBackendConnect, observability.TraceBoundaryBackendConnect, pop3ObservationOperationBackendConn, pop3ObservationResultFailure, pop3ReasonBackendProxyWrite, nil),
		session.newObservation(observability.EventBackendAuth, observability.TraceBoundaryBackendConnect, pop3ObservationOperationBackendAuth, pop3ObservationResultOK, pop3ReasonOK, map[string]string{
			pop3ObsFieldMechanism: authMethodUserPass,
		}),
	}

	for _, event := range events {
		if event.Name == "" {
			t.Fatal("POP3 observation was dropped before label validation")
		}

		for label := range event.MetricLabels {
			if !observability.IsMetricLabelAllowed(label) {
				t.Fatalf("POP3 metric label %q is not allowlisted", label)
			}
		}

		for _, forbidden := range observability.ForbiddenMetricLabels() {
			if _, ok := event.MetricLabels[forbidden]; ok {
				t.Fatalf("POP3 metric label %q is forbidden", forbidden)
			}
		}
	}
}

// TestPOP3SpanAttributesHideUnsafeMaterial verifies traces receive presence markers only.
func TestPOP3SpanAttributesHideUnsafeMaterial(t *testing.T) {
	event, err := observability.NewEvent(
		observability.EventPOP3PreAuth,
		observability.TraceBoundaryPOP3PreAuth,
		map[string]string{
			"bearer_token":           testPOP3ForbiddenBearerToken,
			"client_ip":              "203.0.113.10",
			"message_content":        testPOP3ForbiddenMessageContent,
			"message_number":         testPOP3ForbiddenMessageNumber,
			"message_size":           testPOP3ForbiddenMessageSize,
			"post_auth_command_body": "RETR " + testPOP3ForbiddenMessageNumber,
			"sasl_blob":              testPOP3ForbiddenSASLBlob,
			"session_id":             "pop3-session-id",
			"uidl":                   testPOP3ForbiddenUIDL,
			"username":               testPOP3ForbiddenUsername,
			pop3ObsFieldOperation:    pop3ObservationOperationAuthenticate,
			pop3ObsFieldReasonClass:  pop3ReasonCredentialInput,
			pop3ObsFieldResult:       pop3ObservationResultRejected,
		},
		map[string]string{
			pop3ObsFieldBackendPool: "pop3-default",
			pop3ObsFieldListener:    "pop3",
			pop3ObsFieldOperation:   pop3ObservationOperationAuthenticate,
			pop3ObsFieldProtocol:    ProtocolPOP3,
			pop3ObsFieldReasonClass: pop3ReasonCredentialInput,
			pop3ObsFieldResult:      pop3ObservationResultRejected,
			pop3ObsFieldService:     "pop3",
			pop3ObsFieldTLSMode:     TLSModeImplicit,
		},
	)
	if err != nil {
		t.Fatalf("NewEvent returned error: %v", err)
	}

	if event.SpanName != "nauthilus_director.pop3.pre_auth" {
		t.Fatalf("POP3 span name = %q", event.SpanName)
	}

	rendered := renderPOP3TraceAttributes(observability.TraceAttributesForEvent(event))
	for _, forbidden := range []string{
		testPOP3ForbiddenBearerToken,
		testPOP3ForbiddenMessageContent,
		testPOP3ForbiddenMessageNumber,
		testPOP3ForbiddenMessageSize,
		testPOP3ForbiddenSASLBlob,
		testPOP3ForbiddenUIDL,
		testPOP3ForbiddenUsername,
		"203.0.113.10",
		"pop3-session-id",
	} {
		if strings.Contains(rendered, forbidden) {
			t.Fatal("POP3 trace attributes retained unsafe raw material")
		}
	}
}

// TestPOP3MailboxSentinelsAreSanitizedByObservationPolicy keeps POP3 mailbox data out of events.
func TestPOP3MailboxSentinelsAreSanitizedByObservationPolicy(t *testing.T) {
	session, cleanup := newPOP3ObservationSession(t)
	defer cleanup()

	event := session.newObservation(
		observability.EventPOP3PreAuth,
		observability.TraceBoundaryPOP3PreAuth,
		pop3ObservationOperationPreAuth,
		pop3ObservationResultRejected,
		pop3ReasonUnsupported,
		map[string]string{
			"message_content":        testPOP3ForbiddenMessageContent,
			"message_number":         testPOP3ForbiddenMessageNumber,
			"message_size":           testPOP3ForbiddenMessageSize,
			"post_auth_command_body": "UIDL " + testPOP3ForbiddenMessageNumber,
			"uidl":                   testPOP3ForbiddenUIDL,
		},
	)
	if event.Name == "" {
		t.Fatal("POP3 mailbox-sentinel observation was dropped")
	}

	for _, forbidden := range []string{
		testPOP3ForbiddenMessageContent,
		testPOP3ForbiddenMessageNumber,
		testPOP3ForbiddenMessageSize,
		testPOP3ForbiddenUIDL,
	} {
		if pop3EventContains(event.LogFields, forbidden) || pop3EventContains(event.MetricLabels, forbidden) {
			t.Fatalf("POP3 observation retained mailbox sentinel %q", forbidden)
		}
	}

	for _, label := range []string{"message_number", "message_size", "uidl", "message_content"} {
		if _, err := observability.NewEvent(observability.EventPOP3PreAuth, observability.TraceBoundaryPOP3PreAuth, nil, map[string]string{
			label: "unsafe-pop3-mailbox-value",
		}); err == nil {
			t.Fatalf("POP3 event accepted %q as a metric label", label)
		}
	}
}

// TestPOP3ReasonClassesAreBounded verifies parser, auth, hold, backend and proxy classes.
func TestPOP3ReasonClassesAreBounded(t *testing.T) {
	holdResult, holdReason := pop3HoldGateObservation(
		runtimectl.PlacementGateResult{},
		&runtimectl.Error{Kind: runtimectl.ErrorKindUnavailable, Operation: "user_hold_check", Message: "user hold wait timeout"},
	)
	if holdResult != pop3ObservationResultFailure || holdReason != pop3ReasonUserHoldWaitTimeout {
		t.Fatal("POP3 hold timeout did not map to the bounded wait-timeout class")
	}

	reasons := []string{
		pop3ReasonClass(ErrMalformedCommand),
		pop3ReasonClass(saslcred.ErrRejected),
		pop3ReasonRouting,
		holdReason,
		pop3ReasonClass(ErrBackendConnect),
		pop3ReasonClass(ErrBackendAuth),
		pop3ReasonClass(&backend.TransportError{Reason: backend.TransportReasonWriteFailed}),
		pop3ReasonClass(proxy.NewControlActionError("kick")),
		pop3ReasonClass(ErrBackendReadinessUnavailable),
	}

	for _, reason := range reasons {
		if got := observability.NormalizeReasonClass(reason); got != reason {
			t.Fatalf("POP3 reason class %q normalized to %q", reason, got)
		}
	}

	if got := observability.NormalizeReasonClass("raw backend text with ! secret"); got != "other" {
		t.Fatalf("raw reason normalized to %q, want other", got)
	}

	if got := pop3ReasonClass(errors.New("mailbox uidl " + testPOP3ForbiddenUIDL)); got != pop3ReasonProtocol {
		t.Fatalf("unknown POP3 error classified as %q, want protocol", got)
	}
}

// newPOP3ObservationSession creates a session suitable for direct observability tests.
func newPOP3ObservationSession(t *testing.T) (*Session, func()) {
	t.Helper()

	client, server := net.Pipe()
	session := newTestSession(t, testPOP3Config(TLSModeImplicit, nil), server)
	session.placed = true
	session.placement = Placement{
		Backend: backend.SelectionResult{Backend: backend.Backend{
			Identifier:  "mailstore-a-pop3",
			Protocol:    ProtocolPOP3,
			BackendPool: "pop3-default",
			ShardTag:    "mailstore-a",
			BackendNode: "node-a",
		}},
		SelectedShardTag: "mailstore-a",
	}

	cleanup := func() {
		_ = client.Close()
		_ = server.Close()
	}

	return session, cleanup
}

// renderPOP3TraceAttributes returns a compact string for forbidden-value checks.
func renderPOP3TraceAttributes(attributes []attribute.KeyValue) string {
	var builder strings.Builder
	for _, attr := range attributes {
		builder.WriteString(string(attr.Key))
		builder.WriteByte('=')
		builder.WriteString(attr.Value.AsString())
		builder.WriteByte('\n')
	}

	return builder.String()
}

// pop3EventContains reports whether any event field retains a forbidden value.
func pop3EventContains(values map[string]string, forbidden string) bool {
	for key, value := range values {
		if strings.Contains(key, forbidden) || strings.Contains(value, forbidden) {
			return true
		}
	}

	return false
}
