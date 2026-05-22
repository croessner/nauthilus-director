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

//nolint:funlen,goconst,wsl_v5 // IMAP wire tests keep transcripts inline for clarity.
package imap

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

const (
	testCapabilityCleartext = "* CAPABILITY IMAP4rev1 ID SASL-IR STARTTLS AUTH=PLAIN AUTH=XOAUTH2 AUTH=OAUTHBEARER\r\n"
	testCapabilityTLS       = "* CAPABILITY IMAP4rev1 ID SASL-IR AUTH=PLAIN AUTH=XOAUTH2 AUTH=OAUTHBEARER\r\n"
)

// TestGreetingAndTaggedResponseFormatting verifies greeting and tagged NOOP output.
func TestGreetingAndTaggedResponseFormatting(t *testing.T) {
	harness := startTestSession(t, testPreauthConfig(TLSModeStartTLS, false))

	harness.expectLine(t, greetingLine)
	harness.write(t, "A001 NOOP\r\n")
	harness.expectLine(t, "A001 OK NOOP completed\r\n")
}

// TestCommandDispatchIsCaseInsensitive verifies command names are normalized.
func TestCommandDispatchIsCaseInsensitive(t *testing.T) {
	harness := startTestSession(t, testPreauthConfig(TLSModeStartTLS, false))

	harness.expectLine(t, greetingLine)
	harness.write(t, "a001 nOoP\r\n")
	harness.expectLine(t, "a001 OK NOOP completed\r\n")
}

// TestUnsupportedCommandGetsTaggedBad verifies invalid command responses keep the client tag.
func TestUnsupportedCommandGetsTaggedBad(t *testing.T) {
	harness := startTestSession(t, testPreauthConfig(TLSModeStartTLS, false))

	harness.expectLine(t, greetingLine)
	harness.write(t, "A001 ENABLE CONDSTORE\r\n")
	harness.expectLine(t, "A001 BAD Unsupported command before authentication\r\n")
}

// TestCapabilityCleartextPostStartTLSAndImplicitTLS verifies truthful dynamic capability output.
func TestCapabilityCleartextPostStartTLSAndImplicitTLS(t *testing.T) {
	cleartext := startTestSession(t, testPreauthConfig(TLSModeStartTLS, false))
	cleartext.expectLine(t, greetingLine)
	cleartext.write(t, "A001 CAPABILITY\r\n")
	cleartext.expectLine(t, testCapabilityCleartext)
	cleartext.expectLine(t, "A001 OK CAPABILITY completed\r\n")

	postStartTLS := startTestSession(t, testPreauthConfig(TLSModeStartTLS, false))
	postStartTLS.expectLine(t, greetingLine)
	postStartTLS.write(t, "A001 STARTTLS\r\nA002 CAPABILITY\r\n")
	postStartTLS.expectLine(t, "A001 OK Begin TLS negotiation now\r\n")
	postStartTLS.expectLine(t, testCapabilityTLS)
	postStartTLS.expectLine(t, "A002 OK CAPABILITY completed\r\n")
	if !postStartTLS.session.TLSActive() {
		t.Fatal("STARTTLS did not mark the session TLS-active")
	}

	implicit := startTestSession(t, testPreauthConfig(TLSModeImplicit, false))
	implicit.expectLine(t, greetingLine)
	implicit.write(t, "A001 CAPABILITY\r\n")
	implicit.expectLine(t, testCapabilityTLS)
	implicit.expectLine(t, "A001 OK CAPABILITY completed\r\n")
}

// TestCapabilityDoesNotAdvertiseEnable verifies unsupported ENABLE never appears.
func TestCapabilityDoesNotAdvertiseEnable(t *testing.T) {
	harness := startTestSession(t, testPreauthConfig(TLSModeStartTLS, false))

	harness.expectLine(t, greetingLine)
	harness.write(t, "A001 CAPABILITY\r\n")
	line := harness.readLine(t)
	if strings.Contains(line, "ENABLE") {
		t.Fatalf("capability response advertised ENABLE: %q", line)
	}

	harness.expectLine(t, "A001 OK CAPABILITY completed\r\n")
}

// TestIDNilAndClientIDMapping verifies ID parsing and selection order.
func TestIDNilAndClientIDMapping(t *testing.T) {
	harness := startTestSession(t, testPreauthConfig(TLSModeStartTLS, false))
	harness.expectLine(t, greetingLine)

	harness.write(t, "A001 ID NIL\r\n")
	harness.expectLine(t, "* ID NIL\r\n")
	harness.expectLine(t, "A001 OK ID completed\r\n")
	if got := harness.session.ClientID(); got != "" {
		t.Fatalf("client ID after ID NIL = %q, want empty", got)
	}

	harness.write(t, `A002 ID ("name" "Mail Client" "client-id" "cid-hyphen" "client_id" "cid_underscore")`+"\r\n")
	harness.expectLine(t, "* ID NIL\r\n")
	harness.expectLine(t, "A002 OK ID completed\r\n")
	if got := harness.session.ClientID(); got != "cid_underscore" {
		t.Fatalf("client ID = %q, want cid_underscore", got)
	}
}

// TestIDDoesNotPopulateUserAgent verifies IMAP ID maps only to Nauthilus client_id.
func TestIDDoesNotPopulateUserAgent(t *testing.T) {
	harness := startTestSession(t, testPreauthConfig(TLSModeStartTLS, false))
	harness.expectLine(t, greetingLine)
	harness.write(t, `A001 ID ("name" "Desktop Mail")`+"\r\n")
	harness.expectLine(t, "* ID NIL\r\n")
	harness.expectLine(t, "A001 OK ID completed\r\n")

	context := harness.session.NauthilusRequestContext("plain")
	if context.ClientID != "Desktop Mail" {
		t.Fatalf("client ID = %q, want Desktop Mail", context.ClientID)
	}
	if context.UserAgent != "" {
		t.Fatalf("user agent = %q, want empty", context.UserAgent)
	}
}

// TestMissingIDPermissiveByDefault verifies auth shape is allowed to reach the later auth boundary.
func TestMissingIDPermissiveByDefault(t *testing.T) {
	harness := startTestSession(t, testPreauthConfig(TLSModeStartTLS, false))
	harness.expectLine(t, greetingLine)
	harness.write(t, `A001 LOGIN "alice" "secret"`+"\r\n")
	harness.expectLine(t, "A001 NO [UNAVAILABLE] Authentication service temporarily unavailable\r\n")
}

// TestAuthenticateMechanismShapes verifies supported SASL mechanisms and initial responses parse.
func TestAuthenticateMechanismShapes(t *testing.T) {
	harness := startTestSession(t, testPreauthConfig(TLSModeStartTLS, false))
	harness.expectLine(t, greetingLine)
	harness.write(t, "A001 AUTHENTICATE PLAIN "+plainPayload("plain-user@example.test", "plain-passphrase")+"\r\n"+
		"A002 AUTHENTICATE XOAUTH2 "+xoauth2Payload("xoauth2-user@example.test", "xoauth2-token")+"\r\n"+
		"A003 AUTHENTICATE OAUTHBEARER "+oauthBearerPayload("oauth-user@example.test", "oauth-token")+"\r\n")

	harness.expectLine(t, "A001 NO [UNAVAILABLE] Authentication service temporarily unavailable\r\n")
	harness.expectLine(t, "A002 NO [UNAVAILABLE] Authentication service temporarily unavailable\r\n")
	harness.expectLine(t, "A003 NO [UNAVAILABLE] Authentication service temporarily unavailable\r\n")
}

// TestAuthenticateRejectsMalformedInitialResponse verifies SASL-IR shape validation.
func TestAuthenticateRejectsMalformedInitialResponse(t *testing.T) {
	harness := startTestSession(t, testPreauthConfig(TLSModeStartTLS, false))
	harness.expectLine(t, greetingLine)
	harness.write(t, "A001 AUTHENTICATE PLAIN !!!\r\n")
	harness.expectLine(t, "A001 BAD Invalid AUTHENTICATE response\r\n")
}

// TestMissingIDCanBeRequiredBeforeAuth verifies listener policy blocks auth generically.
func TestMissingIDCanBeRequiredBeforeAuth(t *testing.T) {
	harness := startTestSession(t, testPreauthConfig(TLSModeStartTLS, true))
	harness.expectLine(t, greetingLine)
	harness.write(t, "A001 AUTHENTICATE PLAIN AHVzZXIAcGFzcw==\r\n")
	harness.expectLine(t, "A001 NO Authentication failed\r\n")
}

// TestMalformedAndOversizedIDRejectWithoutRawLeakage verifies invalid ID responses are generic.
func TestMalformedAndOversizedIDRejectWithoutRawLeakage(t *testing.T) {
	rawValue := strings.Repeat("x", maxIDValueBytes+1)
	harness := startTestSession(t, testPreauthConfig(TLSModeStartTLS, false))
	harness.expectLine(t, greetingLine)
	harness.write(t, `A001 ID ("name" "`+rawValue+`")`+"\r\n")

	response := harness.readLine(t)
	if response != "A001 BAD Invalid ID command\r\n" {
		t.Fatalf("ID response = %q, want generic BAD", response)
	}
	if strings.Contains(response, rawValue) {
		t.Fatalf("ID response leaked raw value: %q", response)
	}
}

// TestUnsupportedLiteralMarkerIsTaggedAndStops verifies literals never trigger continuations.
func TestUnsupportedLiteralMarkerIsTaggedAndStops(t *testing.T) {
	harness := startTestSession(t, testPreauthConfig(TLSModeStartTLS, false))
	harness.expectLine(t, greetingLine)
	harness.write(t, "A001 LOGIN alice {5}\r\n")
	harness.expectLine(t, "A001 BAD Unsupported IMAP literal before authentication\r\n")

	err := harness.wait(t)
	if !strings.Contains(err.Error(), ErrPreauthLiteralUnsupported.Error()) {
		t.Fatalf("session error = %v, want literal unsupported", err)
	}
}

// TestPreauthPipelinedCommandsProcessInWireOrder verifies responses preserve command order.
func TestPreauthPipelinedCommandsProcessInWireOrder(t *testing.T) {
	harness := startTestSession(t, testPreauthConfig(TLSModeStartTLS, false))
	harness.expectLine(t, greetingLine)
	harness.write(t, "A001 NOOP\r\nA002 CAPABILITY\r\nA003 LOGOUT\r\n")

	harness.expectLine(t, "A001 OK NOOP completed\r\n")
	harness.expectLine(t, testCapabilityCleartext)
	harness.expectLine(t, "A002 OK CAPABILITY completed\r\n")
	harness.expectLine(t, "* BYE Logging out\r\n")
	harness.expectLine(t, "A003 OK LOGOUT completed\r\n")
}

// TestBufferedProxyHandoffPreservesAlreadyReadBytes verifies post-auth bytes survive parser read-ahead.
func TestBufferedProxyHandoffPreservesAlreadyReadBytes(t *testing.T) {
	conn := newScriptedConn("A001 NOOP\r\nA002 SELECT INBOX\r\n")
	session, err := NewSession(testPreauthConfig(TLSModeStartTLS, false), conn)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	line, err := session.readPreauthLine()
	if err != nil {
		t.Fatalf("readPreauthLine: %v", err)
	}
	if string(line) != "A001 NOOP\r\n" {
		t.Fatalf("first line = %q", string(line))
	}

	handoff := session.BufferedProxyHandoff()
	if got := string(handoff.Buffered()); got != "A002 SELECT INBOX\r\n" {
		t.Fatalf("buffered handoff = %q, want post-auth command", got)
	}

	replayed, err := io.ReadAll(handoff.Reader())
	if err != nil {
		t.Fatalf("read handoff stream: %v", err)
	}
	if string(replayed) != "A002 SELECT INBOX\r\n" {
		t.Fatalf("handoff stream = %q, want buffered bytes first", string(replayed))
	}
}

type sessionHarness struct {
	session *Session
	client  net.Conn
	reader  *bufio.Reader
	done    chan error
}

// startTestSession starts one in-memory frontend session.
func startTestSession(t *testing.T, cfg SessionConfig) *sessionHarness {
	t.Helper()

	client, server := net.Pipe()
	session, err := NewSession(cfg, server)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	harness := &sessionHarness{
		session: session,
		client:  client,
		reader:  bufio.NewReader(client),
		done:    make(chan error, 1),
	}

	go func() {
		defer func() { _ = server.Close() }()

		harness.done <- session.Serve(context.Background())
	}()

	t.Cleanup(func() {
		_ = client.Close()
		if harness.done == nil {
			return
		}
		select {
		case <-harness.done:
		case <-time.After(time.Second):
			t.Fatal("session did not stop during cleanup")
		}
	})

	return harness
}

// write sends raw IMAP bytes to the session frontend.
func (h *sessionHarness) write(t *testing.T, input string) {
	t.Helper()

	if _, err := io.WriteString(h.client, input); err != nil {
		t.Fatalf("write input: %v", err)
	}
}

// readLine reads exactly one server response line.
func (h *sessionHarness) readLine(t *testing.T) string {
	t.Helper()

	if err := h.client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}

	line, err := h.reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read line: %v", err)
	}

	return line
}

// expectLine reads one response line and compares it to the expected transcript.
func (h *sessionHarness) expectLine(t *testing.T, want string) {
	t.Helper()

	if got := h.readLine(t); got != want {
		t.Fatalf("line = %q, want %q", got, want)
	}
}

// wait waits for the session to stop after a fatal protocol error.
func (h *sessionHarness) wait(t *testing.T) error {
	t.Helper()

	select {
	case err := <-h.done:
		h.done = nil

		return err
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for session")
	}

	return nil
}

// testPreauthConfig returns a fully bounded IMAP test session config.
func testPreauthConfig(tlsMode string, requireID bool) SessionConfig {
	return SessionConfig{
		ListenerName:           testIMAPService,
		ServiceName:            testIMAPService,
		Network:                testNetworkTCP,
		TLSMode:                tlsMode,
		AuthMechanisms:         []string{"plain", "xoauth2", "oauthbearer"},
		MaxBearerTokenBytes:    64,
		RequireIDBeforeAuth:    requireID,
		PreauthTimeout:         time.Second,
		MaxPreauthLineBytes:    8192,
		MaxPreauthLiteralBytes: 16,
	}
}

type scriptedConn struct {
	reader *bytes.Reader
	writer bytes.Buffer
}

// newScriptedConn creates a deterministic net.Conn backed by in-memory input.
func newScriptedConn(input string) *scriptedConn {
	return &scriptedConn{reader: bytes.NewReader([]byte(input))}
}

// Read consumes scripted bytes.
func (c *scriptedConn) Read(payload []byte) (int, error) {
	return c.reader.Read(payload)
}

// Write records output bytes.
func (c *scriptedConn) Write(payload []byte) (int, error) {
	return c.writer.Write(payload)
}

// Close marks the scripted connection closed.
func (c *scriptedConn) Close() error {
	return nil
}

// LocalAddr returns a stable local test address.
func (c *scriptedConn) LocalAddr() net.Addr {
	return testAddr("127.0.0.1:10143")
}

// RemoteAddr returns a stable remote test address.
func (c *scriptedConn) RemoteAddr() net.Addr {
	return testAddr("127.0.0.1:12345")
}

// SetDeadline accepts deadline calls from the session.
func (c *scriptedConn) SetDeadline(time.Time) error {
	return nil
}

// SetReadDeadline accepts read deadline calls from the session.
func (c *scriptedConn) SetReadDeadline(time.Time) error {
	return nil
}

// SetWriteDeadline accepts write deadline calls from the session.
func (c *scriptedConn) SetWriteDeadline(time.Time) error {
	return nil
}

type testAddr string

// Network returns the test network name.
func (a testAddr) Network() string {
	return "tcp"
}

// String returns the test address text.
func (a testAddr) String() string {
	return string(a)
}
