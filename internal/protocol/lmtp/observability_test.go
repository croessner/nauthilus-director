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

package lmtp

import (
	"bytes"
	"context"
	"net"
	"strings"
	"sync"
	"testing"

	directorconfig "github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/observability"
)

const (
	testObservationBody      = "Subject: private-subject\r\n\r\nsuper-secret-body\r\n"
	testObservationSender    = "sender-secret@example.test"
	testObservationSubmitter = "submitter.example"
)

// TestLMTPObservabilityKeepsRecipientsCredentialsAndContentOut proves a real flow is secret-safe.
func TestLMTPObservabilityKeepsRecipientsCredentialsAndContentOut(t *testing.T) {
	runtime, output, recorder := newLMTPObservationRuntime(t)
	sink := &recordingMessageSink{}
	config := placementSessionConfig(
		identityLookuperForRecipients(map[string]string{testRecipientLookup: testPlacementShardA}),
		&recordingRoutingResolver{},
		&recordingDeliveryStore{},
		&recordingBackendSelector{},
	)
	config.MessageSink = sink
	config.Observability = runtime.Recorder()

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO "+testObservationSubmitter+"\r\n")
	harness.drainLHLO(t)
	harness.write(t, "MAIL FROM:<"+testObservationSender+">\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<Local@EXAMPLE.com>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "DATA\r\n")
	harness.expectLine(t, "354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	harness.write(t, testObservationBody+".\r\n")
	harness.expectLine(t, "250 2.0.0 Message accepted\r\n")

	assertLMTPObservationLogs(t, output.String())
	assertLMTPObservationMetrics(t, runtime)
	assertLMTPObservationEvents(t, recorder.snapshot())
}

// TestLMTPDATAObservationRecordsBackendBodyTransport verifies bounded DATA transport diagnostics.
func TestLMTPDATAObservationRecordsBackendBodyTransport(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	recorder := &recordingLMTPObservation{}
	session := &Session{
		conn:          server,
		observability: recorder,
	}

	session.recordDATAStream(context.Background(), lmtpObservationResultOK, lmtpReasonOK, lmtpStatusClass2xx, 0, backendBodyTransportDATA)
	session.recordDATAStream(context.Background(), lmtpObservationResultOK, lmtpReasonOK, lmtpStatusClass2xx, 0, backendBodyTransportBDAT)
	session.recordDATAStream(context.Background(), lmtpObservationResultOK, lmtpReasonOK, lmtpStatusClass2xx, 0, backendBodyTransport("recipient@example.test"))

	events := recorder.snapshot()
	if len(events) != 3 {
		t.Fatalf("DATA stream events = %d, want 3", len(events))
	}

	assertDATAStreamTransportObservation(t, events[0], string(backendBodyTransportDATA))
	assertDATAStreamTransportObservation(t, events[1], string(backendBodyTransportBDAT))

	if got := events[2].LogFields[lmtpObsFieldBackendBody]; got != "" {
		t.Fatalf("invalid backend body transport was recorded as %q", got)
	}
}

// newLMTPObservationRuntime creates an enabled log and metrics runtime for LMTP tests.
func newLMTPObservationRuntime(t *testing.T) (*observability.Runtime, *bytes.Buffer, *recordingLMTPObservation) {
	t.Helper()

	cfg := directorconfig.DefaultConfig().Observability
	cfg.Log.JSON = false
	cfg.Log.Level = "debug"
	cfg.Metrics.RuntimeMetrics = false
	cfg.Tracing.Enabled = false

	output := &bytes.Buffer{}
	recorder := &recordingLMTPObservation{}

	runtime, err := observability.NewRuntime(
		cfg,
		observability.WithLogWriter(output),
		observability.WithAdditionalRecorder(recorder),
	)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}

	return runtime, output, recorder
}

// assertLMTPObservationLogs checks useful bounded fields and absence of unsafe values.
func assertLMTPObservationLogs(t *testing.T, body string) {
	t.Helper()

	for _, want := range []string{
		"event_name=lmtp.recipient_route",
		"operation=recipient_route",
		"result=accepted",
		"reason_class=ok",
		"event_name=lmtp.data_stream",
		"status_class=2xx",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("LMTP log missing %q:\n%s", want, body)
		}
	}

	assertLMTPObservationTextSafe(t, body)
}

// assertLMTPObservationMetrics checks LMTP metrics appeared through the public provider.
func assertLMTPObservationMetrics(t *testing.T, runtime *observability.Runtime) {
	t.Helper()

	body, err := runtime.MetricsProvider().Metrics(context.Background())
	if err != nil {
		t.Fatalf("Metrics: %v", err)
	}

	for _, want := range []string{
		"nauthilus_director_lmtp_transactions_total",
		"nauthilus_director_lmtp_recipient_routes_total",
		"nauthilus_director_lmtp_data_streams_total",
		"nauthilus_director_lmtp_recipient_status_total",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("LMTP metric missing %q:\n%s", want, body)
		}
	}

	assertLMTPObservationTextSafe(t, body)
}

// assertLMTPObservationEvents checks span attributes built from LMTP events stay safe.
func assertLMTPObservationEvents(t *testing.T, events []observability.Event) {
	t.Helper()

	if len(events) == 0 {
		t.Fatal("no LMTP observability events captured")
	}

	for _, event := range events {
		attributes := observability.TraceAttributesForEvent(event)
		for _, attr := range attributes {
			assertLMTPObservationTextSafe(t, attr.Value.AsString())
		}
	}
}

// assertDATAStreamTransportObservation verifies transport is log/trace-only and bounded.
func assertDATAStreamTransportObservation(t *testing.T, event observability.Event, want string) {
	t.Helper()

	if event.Name != observability.EventLMTPDataStream {
		t.Fatalf("event name = %q, want DATA stream", event.Name)
	}

	if got := event.LogFields[lmtpObsFieldBackendBody]; got != want {
		t.Fatalf("backend body transport = %q, want %q", got, want)
	}

	if got := event.MetricLabels[lmtpObsFieldBackendBody]; got != "" {
		t.Fatalf("backend body transport was added to metric labels as %q", got)
	}

	attributes := observability.TraceAttributesForEvent(event)
	found := false

	for _, attr := range attributes {
		if string(attr.Key) == lmtpObsFieldBackendBody && attr.Value.AsString() == want {
			found = true
		}
	}

	if !found {
		t.Fatalf("trace attributes missing backend body transport %q: %#v", want, attributes)
	}
}

// assertLMTPObservationTextSafe rejects raw recipient, sender, credential and content values.
func assertLMTPObservationTextSafe(t *testing.T, body string) {
	t.Helper()

	for _, forbidden := range []string{
		"Local@EXAMPLE.com",
		testObservationBody,
		testObservationSender,
		testObservationSubmitter,
		testPeerPassword,
		testPeerToken,
		testRecipientLookup,
		"private-subject",
		"super-secret-body",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("LMTP observability leaked %q:\n%s", forbidden, body)
		}
	}
}

// recordingLMTPObservation captures events from the real recorder fanout.
type recordingLMTPObservation struct {
	mu     sync.Mutex
	events []observability.Event
}

// Record stores one normalized LMTP event for policy assertions.
func (r *recordingLMTPObservation) Record(_ context.Context, event observability.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.events = append(r.events, event)
}

// snapshot returns captured events without exposing internal mutable state.
func (r *recordingLMTPObservation) snapshot() []observability.Event {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]observability.Event(nil), r.events...)
}
