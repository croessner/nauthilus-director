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

//nolint:goconst,wsl_v5 // Observability tests repeat safe label and redaction sentinels intentionally.
package sieve

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
	testSieveForbiddenScriptName    = "sieve-observability-script-name"
	testSieveForbiddenScriptContent = "require [\"fileinto\"]; # sieve-observability-script-content"
	testSieveForbiddenSASLBlob      = "AHVzZXIAc2VjcmV0"
	testSieveForbiddenToken         = "sieve-observability-token"
	testSieveForbiddenUsername      = "unsafe-user@example.test"
)

// TestSieveMetricRegistrationUsesOnlyAllowedLabels verifies Sieve observations stay in policy.
func TestSieveMetricRegistrationUsesOnlyAllowedLabels(t *testing.T) {
	session, cleanup := newSieveObservationSession(t)
	defer cleanup()

	events := []observability.Event{
		session.newObservation(observability.EventSievePreAuth, observability.TraceBoundarySievePreAuth, sieveObservationOperationAuthenticate, sieveObservationResultRejected, sieveReasonCredentialInput, map[string]string{
			sieveObsFieldMechanism: mechanismPlain,
		}),
		session.newObservation(observability.EventNauthilusAuth, observability.TraceBoundaryNauthilusAuth, sieveObservationOperationAuthenticate, sieveObservationResultOK, sieveReasonOK, map[string]string{
			sieveObsFieldMechanism: mechanismPlain,
			sieveObsFieldTransport: "http",
		}),
		session.newObservation(observability.EventRoutingResolve, observability.TraceBoundaryRoutingResolve, sieveObservationOperationRouting, sieveObservationResultOK, sieveReasonOK, map[string]string{
			sieveObsFieldShardTag: "mailstore-a",
		}),
		session.newObservation(observability.EventUserHold, observability.TraceBoundaryBackendSelect, sieveObservationOperationHoldWait, sieveObservationResultWaitReleased, sieveReasonUserHoldWaitReleased, nil),
		session.newObservation(observability.EventBackendSelect, observability.TraceBoundaryBackendSelect, sieveObservationOperationBackendSelect, sieveObservationResultOK, "operator_backend_pin", map[string]string{
			sieveObsFieldBackendIdentifier: "mailstore-a-sieve",
			sieveObsFieldBackendNode:       "node-a",
			sieveObsFieldShardTag:          "mailstore-a",
		}),
		session.newObservation(observability.EventBackendConnect, observability.TraceBoundaryBackendConnect, sieveObservationOperationBackendConn, sieveObservationResultFailure, sieveReasonBackendProxyWrite, nil),
		session.newObservation(observability.EventBackendAuth, observability.TraceBoundaryBackendConnect, sieveObservationOperationBackendAuth, sieveObservationResultOK, sieveReasonOK, map[string]string{
			sieveObsFieldMechanism: mechanismPlain,
		}),
	}

	for _, event := range events {
		if event.Name == "" {
			t.Fatal("Sieve observation was dropped before label validation")
		}

		for label := range event.MetricLabels {
			if !observability.IsMetricLabelAllowed(label) {
				t.Fatalf("Sieve metric label %q is not allowlisted", label)
			}
		}

		for _, forbidden := range observability.ForbiddenMetricLabels() {
			if _, ok := event.MetricLabels[forbidden]; ok {
				t.Fatalf("Sieve metric label %q is forbidden", forbidden)
			}
		}
	}
}

// TestSieveSpanAttributesHideUnsafeMaterial verifies traces receive presence markers only.
func TestSieveSpanAttributesHideUnsafeMaterial(t *testing.T) {
	event, err := observability.NewEvent(
		observability.EventSievePreAuth,
		observability.TraceBoundarySievePreAuth,
		map[string]string{
			"bearer_token":           testSieveForbiddenToken,
			"client_ip":              "203.0.113.10",
			"post_auth_command_body": "PUTSCRIPT body",
			"sasl_blob":              testSieveForbiddenSASLBlob,
			"script_content":         testSieveForbiddenScriptContent,
			"script_name":            testSieveForbiddenScriptName,
			"session_id":             "sieve-session-id",
			"username":               testSieveForbiddenUsername,
			sieveObsFieldOperation:   sieveObservationOperationAuthenticate,
			sieveObsFieldReasonClass: sieveReasonCredentialInput,
			sieveObsFieldResult:      sieveObservationResultRejected,
		},
		map[string]string{
			sieveObsFieldBackendPool: "sieve-default",
			sieveObsFieldListener:    "sieve",
			sieveObsFieldOperation:   sieveObservationOperationAuthenticate,
			sieveObsFieldProtocol:    protocolSieve,
			sieveObsFieldReasonClass: sieveReasonCredentialInput,
			sieveObsFieldResult:      sieveObservationResultRejected,
			sieveObsFieldService:     "sieve",
			sieveObsFieldTLSMode:     TLSModeImplicit,
		},
	)
	if err != nil {
		t.Fatalf("NewEvent returned error: %v", err)
	}

	if event.SpanName != "nauthilus_director.sieve.pre_auth" {
		t.Fatalf("Sieve span name = %q", event.SpanName)
	}

	attributes := observability.TraceAttributesForEvent(event)
	rendered := renderTraceAttributes(attributes)
	for _, forbidden := range []string{
		testSieveForbiddenScriptName,
		testSieveForbiddenScriptContent,
		testSieveForbiddenSASLBlob,
		testSieveForbiddenToken,
		testSieveForbiddenUsername,
		"203.0.113.10",
		"PUTSCRIPT body",
		"sieve-session-id",
	} {
		if strings.Contains(rendered, forbidden) {
			t.Fatal("Sieve trace attributes retained unsafe raw material")
		}
	}
}

// TestSieveScriptSentinelsAreSanitizedByObservationPolicy keeps script bytes out of events.
func TestSieveScriptSentinelsAreSanitizedByObservationPolicy(t *testing.T) {
	session, cleanup := newSieveObservationSession(t)
	defer cleanup()

	event := session.newObservation(
		observability.EventSievePreAuth,
		observability.TraceBoundarySievePreAuth,
		sieveObservationOperationPreAuth,
		sieveObservationResultRejected,
		sieveReasonUnsupported,
		map[string]string{
			"post_auth_command_body": "PUTSCRIPT body",
			"script_content":         testSieveForbiddenScriptContent,
			"script_name":            testSieveForbiddenScriptName,
		},
	)
	if event.Name == "" {
		t.Fatal("Sieve script-sentinel observation was dropped")
	}

	if eventContains(event.LogFields, testSieveForbiddenScriptName) ||
		eventContains(event.LogFields, testSieveForbiddenScriptContent) ||
		eventContains(event.MetricLabels, testSieveForbiddenScriptName) ||
		eventContains(event.MetricLabels, testSieveForbiddenScriptContent) {
		t.Fatal("Sieve observation retained script sentinel material")
	}

	if _, err := observability.NewEvent(observability.EventSievePreAuth, observability.TraceBoundarySievePreAuth, nil, map[string]string{
		"script_name": testSieveForbiddenScriptName,
	}); err == nil {
		t.Fatal("Sieve event accepted script_name as a metric label")
	}
}

// TestSieveReasonClassesAreBounded verifies parser, auth, hold, backend and proxy classes.
func TestSieveReasonClassesAreBounded(t *testing.T) {
	holdResult, holdReason := holdGateObservation(
		runtimectl.PlacementGateResult{},
		&runtimectl.Error{Kind: runtimectl.ErrorKindUnavailable, Operation: "user_hold_check", Message: "user hold wait timeout"},
	)
	if holdResult != sieveObservationResultFailure || holdReason != sieveReasonUserHoldWaitTimeout {
		t.Fatal("Sieve hold timeout did not map to the bounded wait-timeout class")
	}

	reasons := []string{
		sieveReasonClass(ErrMalformedCommand),
		sieveReasonClass(saslcred.ErrRejected),
		sieveReasonClass(errors.New("routing backend secret")),
		sieveReasonRouting,
		holdReason,
		sieveReasonClass(ErrBackendConnect),
		sieveReasonClass(ErrBackendAuth),
		sieveReasonClass(&backend.TransportError{Reason: backend.TransportReasonWriteFailed}),
		sieveReasonClass(proxy.NewControlActionError("kick")),
	}

	for _, reason := range reasons {
		if got := observability.NormalizeReasonClass(reason); got != reason {
			t.Fatalf("Sieve reason class %q normalized to %q", reason, got)
		}
	}
}

// newSieveObservationSession creates a session suitable for direct observability tests.
func newSieveObservationSession(t *testing.T) (*Session, func()) {
	t.Helper()

	client, server := net.Pipe()
	session, err := NewSession(testPlacementSessionConfig(TLSModeImplicit, nil, nil, nil), server)
	if err != nil {
		t.Fatalf("NewSession returned error: %v", err)
	}

	session.placed = true
	session.placement = Placement{
		Backend: backend.SelectionResult{Backend: backend.Backend{
			Identifier:  "mailstore-a-sieve",
			Protocol:    protocolSieve,
			BackendPool: "sieve-default",
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

// renderTraceAttributes returns a compact string for forbidden-value checks.
func renderTraceAttributes(attributes []attribute.KeyValue) string {
	var builder strings.Builder
	for _, attribute := range attributes {
		builder.WriteString(string(attribute.Key))
		builder.WriteByte('=')
		builder.WriteString(attribute.Value.AsString())
		builder.WriteByte('\n')
	}

	return builder.String()
}
