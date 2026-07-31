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

package backend

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/observability"
)

const (
	testProxyBackendAddress  = "10.0.0.10:143"
	testProxyBackendNode     = "mailstore-password-node"
	testProxyBackendSecret   = "alice@example.test"
	testProxyDestinationIPv4 = "198.51.100.20"
	testProxyLocalIPv4       = "10.0.0.1"
	testProxyRemoteIPv4      = "10.0.0.2"
	testProxySourceIPv4      = "203.0.113.10"
	testProxyUnixNetwork     = "unix"
	testProxyUnixSocket      = "/run/mailstore.sock"
	testProxyHeaderV4        = "PROXY TCP4 " + testProxySourceIPv4 + " " + testProxyDestinationIPv4 + " 42500 143\r\n"
	testProxyHeaderV6        = "PROXY TCP6 2001:db8::10 2001:db8::20 42501 993\r\n"
	testProxyLaterBackendMsg = "* OK backend ready\r\n"
)

// TestBackendTransportDisabledWritesNoBytes verifies disabled backends preserve current wire behavior.
func TestBackendTransportDisabledWritesNoBytes(t *testing.T) {
	conn := newProxyRecordingTransportConn()

	result, err := NewTransport().WriteProxyProtocolPreface(context.Background(), conn, ConnectRequest{
		Target:  Backend{},
		Purpose: ConnectPurposeSession,
	})
	if err != nil {
		t.Fatalf("WriteProxyProtocolPreface returned error: %v", err)
	}

	if result.Written || result.Reason != TransportReasonDisabled {
		t.Fatalf("result = %#v, want disabled no-op", result)
	}

	if got := conn.String(); got != "" {
		t.Fatalf("disabled backend wrote bytes %q", got)
	}

	if conn.closed {
		t.Fatal("disabled backend closed the connection")
	}
}

// TestSetHealthCheckDeadlinePreservesSessionStreamsAndBoundsHealthIO verifies purpose scoping.
func TestSetHealthCheckDeadlinePreservesSessionStreamsAndBoundsHealthIO(t *testing.T) {
	deadline := time.Now().Add(time.Minute).Round(time.Millisecond)

	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	sessionConn := newRecordingTransportConn(nil, nil)
	if err := SetHealthCheckDeadline(ctx, sessionConn, ConnectRequest{
		Purpose: ConnectPurposeSession,
		Timeout: time.Second,
	}); err != nil {
		t.Fatalf("SetHealthCheckDeadline session returned error: %v", err)
	}

	if !sessionConn.deadline.IsZero() {
		t.Fatalf("session deadline = %s, want unchanged", sessionConn.deadline)
	}

	healthConn := newRecordingTransportConn(nil, nil)
	if err := SetHealthCheckDeadline(ctx, healthConn, ConnectRequest{
		Purpose: ConnectPurposeHealth,
		Timeout: time.Second,
	}); err != nil {
		t.Fatalf("SetHealthCheckDeadline health returned error: %v", err)
	}

	if !healthConn.deadline.Equal(deadline) {
		t.Fatalf("health deadline = %s, want %s", healthConn.deadline, deadline)
	}
}

// TestBackendTransportSessionWritesProxyHeaderBeforeBackendBytes verifies first-byte ordering.
func TestBackendTransportSessionWritesProxyHeaderBeforeBackendBytes(t *testing.T) {
	conn := newProxyRecordingTransportConn()
	request := ConnectRequest{
		Target:         proxyTransportTarget(true),
		Purpose:        ConnectPurposeSession,
		ProxyAddresses: testProxySessionAddresses(),
	}

	result, err := NewTransport().WriteProxyProtocolPreface(context.Background(), conn, request)
	if err != nil {
		t.Fatalf("WriteProxyProtocolPreface returned error: %v", err)
	}

	if !result.Written || result.Reason != TransportReasonOK {
		t.Fatalf("result = %#v, want written ok", result)
	}

	if !conn.flushed {
		t.Fatal("PROXY header was not flushed")
	}

	if _, err := conn.Write([]byte(testProxyLaterBackendMsg)); err != nil {
		t.Fatalf("write later backend bytes: %v", err)
	}

	want := testProxyHeaderV4 + testProxyLaterBackendMsg
	if got := conn.String(); got != want {
		t.Fatalf("wire bytes = %q, want %q", got, want)
	}

	if strings.Count(conn.String(), "PROXY ") != 1 {
		t.Fatalf("wire bytes contain multiple PROXY headers: %q", conn.String())
	}
}

// TestBackendTransportRendersTCPAddressFamilies verifies IPv4 and IPv6 tuples preserve ports.
func TestBackendTransportRendersTCPAddressFamilies(t *testing.T) {
	tests := []struct {
		name        string
		source      net.Addr
		destination net.Addr
		want        string
	}{
		{
			name:        "ipv4",
			source:      tcpAddr(testProxySourceIPv4, 42500),
			destination: tcpAddr(testProxyDestinationIPv4, 143),
			want:        testProxyHeaderV4,
		},
		{
			name:        "ipv6",
			source:      tcpAddr("2001:db8::10", 42501),
			destination: tcpAddr("2001:db8::20", 993),
			want:        testProxyHeaderV6,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			conn := newProxyRecordingTransportConn()
			request := ConnectRequest{
				Target:  proxyTransportTarget(true),
				Purpose: ConnectPurposeSession,
				ProxyAddresses: &ProxyAddresses{
					Source:      testCase.source,
					Destination: testCase.destination,
				},
			}

			if _, err := NewTransport().WriteProxyProtocolPreface(context.Background(), conn, request); err != nil {
				t.Fatalf("WriteProxyProtocolPreface returned error: %v", err)
			}

			if got := conn.String(); got != testCase.want {
				t.Fatalf("wire bytes = %q, want %q", got, testCase.want)
			}
		})
	}
}

// TestBackendTransportRejectsUnsafeSessionAddresses verifies enabled backends fail closed.
func TestBackendTransportRejectsUnsafeSessionAddresses(t *testing.T) {
	for _, testCase := range unsafeSessionAddressCases() {
		t.Run(testCase.name, func(t *testing.T) {
			conn := newProxyRecordingTransportConn()
			request := ConnectRequest{
				Target:  proxyTransportTarget(true),
				Purpose: ConnectPurposeSession,
				ProxyAddresses: &ProxyAddresses{
					Source:      testCase.source,
					Destination: testCase.destination,
				},
			}

			result, err := NewTransport().WriteProxyProtocolPreface(context.Background(), conn, request)
			assertTransportReason(t, err, testCase.reason)

			if result.Reason != testCase.reason {
				t.Fatalf("result reason = %q, want %q", result.Reason, testCase.reason)
			}

			if !conn.closed {
				t.Fatal("unsafe PROXY address did not close backend connection")
			}

			if got := conn.String(); got != "" {
				t.Fatalf("unsafe PROXY address wrote bytes %q", got)
			}
		})
	}
}

// TestBackendTransportSessionRequiresFrontendAddresses verifies sessions never use socket tuples implicitly.
func TestBackendTransportSessionRequiresFrontendAddresses(t *testing.T) {
	conn := newProxyRecordingTransportConn()
	request := ConnectRequest{
		Target:  proxyTransportTarget(true),
		Purpose: ConnectPurposeSession,
	}

	_, err := NewTransport().WriteProxyProtocolPreface(context.Background(), conn, request)
	assertTransportReason(t, err, TransportReasonMissingAddress)

	if !conn.closed {
		t.Fatal("missing session frontend addresses did not close backend connection")
	}
}

// TestBackendTransportHealthUsesSocketAddresses verifies health checks derive a safe synthetic tuple.
func TestBackendTransportHealthUsesSocketAddresses(t *testing.T) {
	conn := newRecordingTransportConn(tcpAddr("10.10.0.1", 50143), tcpAddr("10.10.0.2", 143))
	request := ConnectRequest{
		Target:         proxyTransportTarget(true),
		Purpose:        ConnectPurposeHealth,
		ProxyAddresses: testProxySessionAddresses(),
	}

	if _, err := NewTransport().WriteProxyProtocolPreface(context.Background(), conn, request); err != nil {
		t.Fatalf("WriteProxyProtocolPreface returned error: %v", err)
	}

	want := "PROXY TCP4 10.10.0.1 10.10.0.2 50143 143\r\n"
	if got := conn.String(); got != want {
		t.Fatalf("health wire bytes = %q, want %q", got, want)
	}
}

// TestBackendTransportRejectsUnsafeHealthSocketAddresses verifies health fails closed on unusable socket data.
func TestBackendTransportRejectsUnsafeHealthSocketAddresses(t *testing.T) {
	tests := []struct {
		name   string
		local  net.Addr
		remote net.Addr
		reason TransportReason
	}{
		{
			name:   "missing local",
			remote: tcpAddr("10.10.0.2", 143),
			reason: TransportReasonMissingAddress,
		},
		{
			name:   "missing remote",
			local:  tcpAddr("10.10.0.1", 50143),
			reason: TransportReasonMissingAddress,
		},
		{
			name:   "non tcp local",
			local:  testStringAddr("pipe"),
			remote: tcpAddr("10.10.0.2", 143),
			reason: TransportReasonUnsupportedFamily,
		},
		{
			name:   "non tcp remote",
			local:  tcpAddr("10.10.0.1", 50143),
			remote: &net.UnixAddr{Name: testProxyUnixSocket, Net: testProxyUnixNetwork},
			reason: TransportReasonUnsupportedFamily,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			conn := newRecordingTransportConn(testCase.local, testCase.remote)
			request := ConnectRequest{
				Target:  proxyTransportTarget(true),
				Purpose: ConnectPurposeHealth,
			}

			result, err := NewTransport().WriteProxyProtocolPreface(context.Background(), conn, request)
			assertTransportReason(t, err, testCase.reason)

			if result.Reason != testCase.reason {
				t.Fatalf("result reason = %q, want %q", result.Reason, testCase.reason)
			}

			if !conn.closed {
				t.Fatal("unsafe health socket data did not close backend connection")
			}

			if got := conn.String(); got != "" {
				t.Fatalf("unsafe health socket data wrote bytes %q", got)
			}
		})
	}
}

// TestBackendTransportWriteFailureClosesConnection verifies failed prefaces cannot continue to auth.
func TestBackendTransportWriteFailureClosesConnection(t *testing.T) {
	writeErr := errors.New("write failed for " + testProxyBackendSecret + " at " + testProxyBackendAddress)
	conn := newProxyRecordingTransportConn()
	conn.writeErr = writeErr
	request := ConnectRequest{
		Target:         proxyTransportTarget(true),
		Purpose:        ConnectPurposeSession,
		ProxyAddresses: testProxySessionAddresses(),
	}

	result, err := NewTransport().WriteProxyProtocolPreface(context.Background(), conn, request)
	assertTransportReason(t, err, TransportReasonWriteFailed)
	assertTransportErrorSecretSafe(t, err)

	if result.Reason != TransportReasonWriteFailed {
		t.Fatalf("result reason = %q, want write_failed", result.Reason)
	}

	if !conn.closed {
		t.Fatal("write failure did not close backend connection")
	}
}

// TestBackendTransportFlushFailureIsWriteFailure verifies buffered writer failures are bounded.
func TestBackendTransportFlushFailureIsWriteFailure(t *testing.T) {
	conn := newProxyRecordingTransportConn()
	conn.flushErr = errors.New("flush failed for " + testProxyBackendSecret)
	request := ConnectRequest{
		Target:         proxyTransportTarget(true),
		Purpose:        ConnectPurposeSession,
		ProxyAddresses: testProxySessionAddresses(),
	}

	_, err := NewTransport().WriteProxyProtocolPreface(context.Background(), conn, request)
	assertTransportReason(t, err, TransportReasonWriteFailed)
	assertTransportErrorSecretSafe(t, err)

	if !conn.closed {
		t.Fatal("flush failure did not close backend connection")
	}
}

// TestBackendTransportObservabilityUsesBoundedProxyFields verifies outbound PROXY events stay safe.
func TestBackendTransportObservabilityUsesBoundedProxyFields(t *testing.T) {
	recorder := &recordingBackendProxyRecorder{}
	request := testProxySessionRequest(recorder)

	if _, err := NewTransport().WriteProxyProtocolPreface(context.Background(), newProxyRecordingTransportConn(), request); err != nil {
		t.Fatalf("WriteProxyProtocolPreface returned error: %v", err)
	}

	okEvent := recorder.singleEvent(t)
	assertBackendProxyOKEvent(t, okEvent, request)
	assertBackendProxyMetricLabelsSafe(t, okEvent, request)

	recorder.events = nil
	failing := newProxyRecordingTransportConn()
	failing.writeErr = errors.New("write failed for " + testProxyRemoteIPv4 + " secret backend")
	_, err := NewTransport().WriteProxyProtocolPreface(context.Background(), failing, request)
	assertTransportReason(t, err, TransportReasonWriteFailed)

	assertBackendProxyFailureEvent(t, recorder.singleEvent(t))
}

// assertBackendProxyOKEvent verifies the bounded success event fields.
func assertBackendProxyOKEvent(t *testing.T, event observability.Event, request ConnectRequest) {
	t.Helper()

	if event.Name != observability.EventBackendProxyProtocol {
		t.Fatalf("event name = %q, want backend proxy protocol", event.Name)
	}

	if got := event.LogFields[backendProxyObservationFieldOperation]; got != backendProxyObservationOperation {
		t.Fatalf("operation field = %q, want %q", got, backendProxyObservationOperation)
	}

	if got := event.LogFields[backendProxyObservationFieldPurpose]; got != string(ConnectPurposeSession) {
		t.Fatalf("purpose field = %q, want session", got)
	}

	if got := event.LogFields[backendProxyObservationFieldReasonClass]; got != string(TransportReasonOK) {
		t.Fatalf("reason field = %q, want ok", got)
	}

	if got := event.LogFields[backendProxyObservationFieldBackendNode]; got != request.Target.BackendNode {
		t.Fatalf("backend node log field = %q, want diagnostic value", got)
	}
}

// assertBackendProxyMetricLabelsSafe verifies that metrics omit raw backend diagnostics.
func assertBackendProxyMetricLabelsSafe(t *testing.T, event observability.Event, request ConnectRequest) {
	t.Helper()

	for _, forbiddenLabel := range []string{"backend_identifier", "backend_node", "remote_addr", "raw_error"} {
		if _, ok := event.MetricLabels[forbiddenLabel]; ok {
			t.Fatalf("metric labels included forbidden %q: %#v", forbiddenLabel, event.MetricLabels)
		}
	}

	forbiddenValues := []string{request.Target.Identifier, testProxySourceIPv4, testProxyDestinationIPv4, testProxyLocalIPv4, testProxyRemoteIPv4}
	for _, value := range forbiddenValues {
		for labelName, labelValue := range event.MetricLabels {
			if strings.Contains(labelValue, value) {
				t.Fatalf("metric label %s leaked %q in %#v", labelName, value, event.MetricLabels)
			}
		}
	}
}

// assertBackendProxyFailureEvent verifies the bounded failure event fields.
func assertBackendProxyFailureEvent(t *testing.T, event observability.Event) {
	t.Helper()

	if got := event.LogFields[backendProxyObservationFieldResult]; got != backendProxyObservationResultFailure {
		t.Fatalf("failure result = %q, want failure", got)
	}

	if got := event.LogFields[backendProxyObservationFieldReasonClass]; got != string(TransportReasonWriteFailed) {
		t.Fatalf("failure reason = %q, want write_failed", got)
	}
}

// assertTransportReason verifies typed transport classification.
func assertTransportReason(t *testing.T, err error, reason TransportReason) {
	t.Helper()

	if err == nil {
		t.Fatalf("error = nil, want %s", reason)
	}

	if !IsTransportReason(err, reason) {
		t.Fatalf("error = %v, want reason %s", err, reason)
	}
}

// assertTransportErrorSecretSafe checks that error strings expose only bounded classes.
func assertTransportErrorSecretSafe(t *testing.T, err error) {
	t.Helper()

	message := err.Error()
	for _, forbidden := range []string{
		testProxyBackendSecret,
		testProxyBackendAddress,
		testProxySourceIPv4,
		testProxyDestinationIPv4,
		testProxyBackendNode,
	} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("transport error leaked %q in %q", forbidden, message)
		}
	}
}

// proxyTransportTarget returns a minimal backend with outbound PROXY policy.
func proxyTransportTarget(enabled bool) Backend {
	return Backend{
		Identifier:  testProxyBackendSecret,
		Protocol:    "imap",
		BackendPool: "imap-default",
		BackendNode: testProxyBackendNode,
		Address:     testProxyBackendAddress,
		HAProxy: HAProxyConfig{
			Enabled: enabled,
		},
	}
}

// newProxyRecordingTransportConn creates the common IPv4 test connection tuple.
func newProxyRecordingTransportConn() *recordingTransportConn {
	return newRecordingTransportConn(tcpAddr(testProxyLocalIPv4, 50000), tcpAddr(testProxyRemoteIPv4, 143))
}

// testProxySessionAddresses returns a stable client-to-listener tuple.
func testProxySessionAddresses() *ProxyAddresses {
	return &ProxyAddresses{
		Source:      tcpAddr(testProxySourceIPv4, 42500),
		Destination: tcpAddr(testProxyDestinationIPv4, 143),
	}
}

// testProxySessionRequest creates a complete session request for observability tests.
func testProxySessionRequest(recorder observability.Recorder) ConnectRequest {
	return ConnectRequest{
		Target:         proxyTransportTarget(true),
		Purpose:        ConnectPurposeSession,
		Observability:  recorder,
		ProxyAddresses: testProxySessionAddresses(),
	}
}

// unsafeSessionAddressCase describes one fail-closed frontend tuple.
type unsafeSessionAddressCase struct {
	name        string
	source      net.Addr
	destination net.Addr
	reason      TransportReason
}

// unsafeSessionAddressCases returns the documented unsafe session address cases.
func unsafeSessionAddressCases() []unsafeSessionAddressCase {
	return []unsafeSessionAddressCase{
		{
			name:        "nil source",
			source:      nil,
			destination: tcpAddr(testProxyDestinationIPv4, 143),
			reason:      TransportReasonMissingAddress,
		},
		{
			name:        "nil destination",
			source:      tcpAddr(testProxySourceIPv4, 42500),
			destination: nil,
			reason:      TransportReasonMissingAddress,
		},
		{
			name:        "unix source",
			source:      &net.UnixAddr{Name: testProxyUnixSocket, Net: testProxyUnixNetwork},
			destination: tcpAddr(testProxyDestinationIPv4, 143),
			reason:      TransportReasonUnsupportedFamily,
		},
		{
			name:        "unresolved tcp source",
			source:      &net.TCPAddr{Port: 42500},
			destination: tcpAddr(testProxyDestinationIPv4, 143),
			reason:      TransportReasonMissingAddress,
		},
		{
			name:        "non tcp source",
			source:      testStringAddr(testProxySourceIPv4 + ":42500"),
			destination: tcpAddr(testProxyDestinationIPv4, 143),
			reason:      TransportReasonUnsupportedFamily,
		},
		{
			name:        "mixed families",
			source:      tcpAddr(testProxySourceIPv4, 42500),
			destination: tcpAddr("2001:db8::20", 143),
			reason:      TransportReasonUnsupportedFamily,
		},
	}
}

// tcpAddr parses a literal test TCP address and preserves the supplied port.
func tcpAddr(ip string, port int) *net.TCPAddr {
	return &net.TCPAddr{IP: net.ParseIP(ip), Port: port}
}

// testStringAddr is a non-TCP net.Addr fixture.
type testStringAddr string

// Network returns a fake network name for unsupported address tests.
func (a testStringAddr) Network() string {
	return "string"
}

// String returns a fake endpoint string for unsupported address tests.
func (a testStringAddr) String() string {
	return string(a)
}

// recordingTransportConn captures backend transport writes without network I/O.
type recordingTransportConn struct {
	buffer   bytes.Buffer
	local    net.Addr
	remote   net.Addr
	writeErr error
	flushErr error
	deadline time.Time
	closed   bool
	flushed  bool
}

// newRecordingTransportConn creates a test connection with stable socket addresses.
func newRecordingTransportConn(local net.Addr, remote net.Addr) *recordingTransportConn {
	return &recordingTransportConn{local: local, remote: remote}
}

// Read is unused by transport tests and behaves like a closed backend reader.
func (c *recordingTransportConn) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

// Write records bytes or returns the configured write failure.
func (c *recordingTransportConn) Write(payload []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}

	return c.buffer.Write(payload)
}

// Close marks the fake backend connection closed.
func (c *recordingTransportConn) Close() error {
	c.closed = true

	return nil
}

// LocalAddr returns the Director-side socket address.
func (c *recordingTransportConn) LocalAddr() net.Addr {
	return c.local
}

// RemoteAddr returns the backend-side socket address.
func (c *recordingTransportConn) RemoteAddr() net.Addr {
	return c.remote
}

// SetDeadline records deadline changes for the net.Conn contract.
func (c *recordingTransportConn) SetDeadline(deadline time.Time) error {
	c.deadline = deadline

	return nil
}

// SetReadDeadline accepts read deadline changes for the net.Conn contract.
func (c *recordingTransportConn) SetReadDeadline(_ time.Time) error {
	return nil
}

// SetWriteDeadline accepts write deadline changes for the net.Conn contract.
func (c *recordingTransportConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

// Flush records flush ordering or returns the configured flush failure.
func (c *recordingTransportConn) Flush() error {
	if c.flushErr != nil {
		return c.flushErr
	}

	c.flushed = true

	return nil
}

// String returns the captured backend wire bytes.
func (c *recordingTransportConn) String() string {
	return c.buffer.String()
}

// recordingBackendProxyRecorder captures transport observations.
type recordingBackendProxyRecorder struct {
	events []observability.Event
}

// Record stores one event for later assertions.
func (r *recordingBackendProxyRecorder) Record(_ context.Context, event observability.Event) {
	r.events = append(r.events, event)
}

// singleEvent returns the only captured event.
func (r *recordingBackendProxyRecorder) singleEvent(t *testing.T) observability.Event {
	t.Helper()

	if len(r.events) != 1 {
		t.Fatalf("events = %d, want 1: %#v", len(r.events), r.events)
	}

	return r.events[0]
}
