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
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/nauthilus"
)

const (
	testAllAuthCapability = "AUTH PLAIN LOGIN XOAUTH2 OAUTHBEARER"
	testDataBody          = "line-one\r\n.line-two\r\n"
	testMTLSPeerIdentity  = "technical-peer"
	testPeerPassword      = "submitter-secret"
	testPeerToken         = "submitter-token"
	testSubmitterIdentity = "technical-submit@example.test"
)

// TestGreetingAndLHLOCapabilitiesAreDeterministic verifies safe capability filtering before and after STARTTLS.
func TestGreetingAndLHLOCapabilitiesAreDeterministic(t *testing.T) {
	harness := startLMTPHarness(t, testSessionConfig())
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")

	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250-SMTPUTF8\r\n")
	harness.expectLine(t, "250 STARTTLS\r\n")

	harness.write(t, "STARTTLS\r\n")
	harness.expectLine(t, "220 2.0.0 Ready to start TLS\r\n")

	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250-SMTPUTF8\r\n")
	harness.expectLine(t, "250 AUTH PLAIN LOGIN XOAUTH2 OAUTHBEARER\r\n")
}

// TestCommandsBeforeLHLOFailWithStableBadSequence verifies transaction commands do not run before LHLO.
func TestCommandsBeforeLHLOFailWithStableBadSequence(t *testing.T) {
	harness := startLMTPHarness(t, testSessionConfig())
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")

	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "503 5.5.1 Send LHLO first\r\n")
}

// TestSTARTTLSSequencingAndStateReset verifies STARTTLS only runs before auth and transaction state.
func TestSTARTTLSSequencingAndStateReset(t *testing.T) {
	harness := startLMTPHarness(t, testSessionConfig())
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")

	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250-SMTPUTF8\r\n")
	harness.expectLine(t, "250 STARTTLS\r\n")

	harness.write(t, "STARTTLS\r\n")
	harness.expectLine(t, "220 2.0.0 Ready to start TLS\r\n")

	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "503 5.5.1 Send LHLO first\r\n")

	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250-SMTPUTF8\r\n")
	harness.expectLine(t, "250 AUTH PLAIN LOGIN XOAUTH2 OAUTHBEARER\r\n")

	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "STARTTLS\r\n")
	harness.expectLine(t, "503 5.5.1 STARTTLS is not available\r\n")
}

// TestRequiredPeerAuthBlocksTransactionCommands verifies submitter auth gates envelope and body commands.
func TestRequiredPeerAuthBlocksTransactionCommands(t *testing.T) {
	for _, command := range []string{
		"MAIL FROM:<sender@example.test>\r\n",
		"RCPT TO:<recipient@example.test>\r\n",
		"DATA\r\n",
		"BDAT 0 LAST\r\n",
	} {
		t.Run(strings.Fields(command)[0], func(t *testing.T) {
			config := testSessionConfig()
			config.TLSMode = TLSModeImplicit
			config.RequirePeerAuth = true
			config.BackendChunkingAllowed = true
			config.Capabilities = []string{testAllAuthCapability, capabilityCHUNKING}

			harness := startLMTPHarness(t, config)
			harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
			harness.write(t, "LHLO submitter.example\r\n")
			harness.drainLHLO(t)
			harness.write(t, command)
			harness.expectLine(t, "530 5.7.0 Authentication required\r\n")
		})
	}
}

// TestSASLPeerAuthUsesSubmitterIdentity verifies recipient values never become credential-auth usernames.
func TestSASLPeerAuthUsesSubmitterIdentity(t *testing.T) {
	authenticator := &recordingAuthenticator{}
	config := testSessionConfig()
	config.TLSMode = TLSModeImplicit
	config.RequirePeerAuth = true
	config.Authenticator = authenticator
	config.Capabilities = []string{testAllAuthCapability}

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 AUTH PLAIN LOGIN XOAUTH2 OAUTHBEARER\r\n")
	harness.write(t, "AUTH PLAIN "+plainPayload(testSubmitterIdentity, testPeerPassword)+"\r\n")
	harness.expectLine(t, "235 2.7.0 Authentication successful\r\n")
	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<mailbox-user@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")

	request := authenticator.singleRequest(t)
	if request.Context.Protocol != protocolLMTP {
		t.Fatalf("protocol = %q, want lmtp", request.Context.Protocol)
	}

	if request.Context.Method != mechanismPlain {
		t.Fatalf("method = %q, want plain", request.Context.Method)
	}

	if request.Context.Username != testSubmitterIdentity {
		t.Fatalf("username = %q, want submitter identity", request.Context.Username)
	}

	if request.Context.Username == "mailbox-user@example.test" {
		t.Fatal("recipient identity was used as peer-auth username")
	}
}

// TestHTTPSASLPeerAuthDoesNotUseNoAuth verifies HTTP credential auth stays separate from lookup mode.
func TestHTTPSASLPeerAuthDoesNotUseNoAuth(t *testing.T) {
	var seenMode string

	var seenUsername string

	authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenMode = r.URL.Query().Get("mode")

		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}

		seenUsername, _ = body["username"].(string)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"account_field":"` + testSubmitterIdentity + `"}`))
	}))
	defer authority.Close()

	client, err := nauthilus.NewHTTPClient(nauthilus.HTTPClientConfig{
		Endpoint: authority.URL,
		Client:   authority.Client(),
	})
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}

	config := testSessionConfig()
	config.TLSMode = TLSModeImplicit
	config.RequirePeerAuth = true
	config.Authenticator = client
	config.Capabilities = []string{"AUTH PLAIN"}
	config.PeerAuthMechanisms = []string{mechanismPlain}

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 AUTH PLAIN\r\n")
	harness.write(t, "AUTH PLAIN "+plainPayload(testSubmitterIdentity, testPeerPassword)+"\r\n")
	harness.expectLine(t, "235 2.7.0 Authentication successful\r\n")

	if seenMode == "no-auth" {
		t.Fatal("HTTP SASL peer auth used mode=no-auth")
	}

	if seenUsername != testSubmitterIdentity {
		t.Fatalf("HTTP username = %q, want submitter identity", seenUsername)
	}
}

// TestVerifiedClientCertRequiresExplicitMTLSPolicy verifies transport certificates are not implicit auth.
func TestVerifiedClientCertRequiresExplicitMTLSPolicy(t *testing.T) {
	config := testMTLSConfig(false)
	harness := startLMTPHarnessWithState(t, config, verifiedTLSState(testMTLSPeerIdentity))
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.drainLHLO(t)
	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "530 5.7.0 Authentication required\r\n")
}

// TestVerifiedClientCertSatisfiesExplicitMTLSPeerAuth verifies verified mTLS can satisfy required peer auth.
func TestVerifiedClientCertSatisfiesExplicitMTLSPeerAuth(t *testing.T) {
	config := testMTLSConfig(true)
	harness := startLMTPHarnessWithState(t, config, verifiedTLSState(testMTLSPeerIdentity))
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.drainLHLO(t)
	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")

	if !harness.session.PeerAuthenticated() {
		t.Fatal("verified explicit mTLS did not satisfy peer auth")
	}

	if harness.session.PeerIdentity() != testMTLSPeerIdentity {
		t.Fatalf("peer identity = %q, want bounded certificate identity", harness.session.PeerIdentity())
	}
}

// TestMTLSPeerIdentityIsBounded verifies certificate-derived identities stay safe and bounded.
func TestMTLSPeerIdentityIsBounded(t *testing.T) {
	rawIdentity := strings.Repeat("a", maxSafePeerIdentityBytes+32) + "\r\nsecret"
	config := testMTLSConfig(true)
	harness := startLMTPHarnessWithState(t, config, verifiedTLSState(rawIdentity))
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")

	identity := harness.session.PeerIdentity()
	if len(identity) > maxSafePeerIdentityBytes {
		t.Fatalf("identity length = %d, want <= %d", len(identity), maxSafePeerIdentityBytes)
	}

	if strings.ContainsAny(identity, "\r\n") {
		t.Fatalf("identity contains controls: %q", identity)
	}
}

// TestAUTHRejectsMalformedOrOversizedInputsWithoutLeakingSecrets verifies parser failures stay secret-safe.
func TestAUTHRejectsMalformedOrOversizedInputsWithoutLeakingSecrets(t *testing.T) {
	mechanism, err := newMechanismIdentity(mechanismXOAUTH2)
	if err != nil {
		t.Fatalf("newMechanismIdentity: %v", err)
	}

	_, err = parseSASLCredentials(mechanism, xoauth2Payload(testSubmitterIdentity, testPeerToken), 256, 8)
	if !errors.Is(err, ErrCredentialTooLarge) {
		t.Fatalf("error = %v, want credential too large", err)
	}

	assertNoSecretLeak(t, err.Error(), testPeerToken)

	_, err = parseSASLCredentials(mechanism, "not-base64!", 256, 8)
	if !errors.Is(err, ErrCredentialRejected) {
		t.Fatalf("error = %v, want credential rejected", err)
	}

	assertNoSecretLeak(t, err.Error(), "not-base64!")
}

// TestBDATRejectsInvalidStateAndMalformedSizes verifies BDAT fails closed before streaming.
func TestBDATRejectsInvalidStateAndMalformedSizes(t *testing.T) {
	t.Run("not advertised", func(t *testing.T) {
		harness := startLMTPHarness(t, testSessionConfig())
		harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
		harness.write(t, "LHLO submitter.example\r\n")
		harness.drainLHLO(t)
		harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
		harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
		harness.write(t, "RCPT TO:<recipient@example.test>\r\n")
		harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
		harness.write(t, "BDAT 0 LAST\r\n")
		harness.expectLine(t, "502 5.5.1 BDAT is not available\r\n")
	})

	t.Run("missing recipient", func(t *testing.T) {
		config := testChunkingConfig()
		harness := startLMTPHarness(t, config)
		harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
		harness.write(t, "LHLO submitter.example\r\n")
		harness.expectLine(t, "250-nauthilus-director\r\n")
		harness.expectLine(t, "250 CHUNKING\r\n")
		harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
		harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
		harness.write(t, "BDAT 0 LAST\r\n")
		harness.expectLine(t, "503 5.5.1 Need recipient before message body\r\n")
	})

	t.Run("malformed size", func(t *testing.T) {
		config := testChunkingConfig()
		harness := startLMTPHarness(t, config)
		harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
		harness.write(t, "LHLO submitter.example\r\n")
		harness.expectLine(t, "250-nauthilus-director\r\n")
		harness.expectLine(t, "250 CHUNKING\r\n")
		harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
		harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
		harness.write(t, "RCPT TO:<recipient@example.test>\r\n")
		harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
		harness.write(t, "BDAT nope LAST\r\n")
		harness.expectLine(t, "501 5.5.4 Invalid BDAT command\r\n")
	})
}

// TestBDATStreamsExactChunkSizesAndHonorsLAST verifies byte-counted chunks are not parsed as commands.
func TestBDATStreamsExactChunkSizesAndHonorsLAST(t *testing.T) {
	sink := &recordingMessageSink{}
	config := testChunkingConfig()
	config.MessageSink = sink

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 CHUNKING\r\n")
	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<recipient@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "BDAT 5\r\nhelloNOOP\r\n")
	harness.expectLine(t, "250 2.0.0 BDAT chunk accepted\r\n")
	harness.expectLine(t, "250 2.0.0 OK\r\n")
	harness.write(t, "BDAT 0 LAST\r\n")
	harness.expectLine(t, "250 2.0.0 Message accepted\r\n")

	if got := sink.bodyString(); got != "hello" {
		t.Fatalf("BDAT body = %q, want exact chunk", got)
	}

	if sink.finishCount() != 1 {
		t.Fatalf("finish count = %d, want 1", sink.finishCount())
	}
}

// TestDATATerminatorStreamsIncrementally verifies DATA handling avoids whole-message buffering.
func TestDATATerminatorStreamsIncrementally(t *testing.T) {
	sink := &recordingMessageSink{}
	config := testSessionConfig()
	config.MessageSink = sink

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.drainLHLO(t)
	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<recipient@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "DATA\r\n")
	harness.expectLine(t, "354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	harness.write(t, "line-one\r\n..line-two\r\n.\r\n")
	harness.expectLine(t, "250 2.0.0 Message accepted\r\n")

	if got := sink.bodyString(); got != testDataBody {
		t.Fatalf("DATA body = %q, want dot-unescaped lines", got)
	}

	if sink.maxWriteBytes() >= len(testDataBody) {
		t.Fatalf("max write size = %d, DATA appears whole-buffered", sink.maxWriteBytes())
	}
}

// testSessionConfig returns a minimal LMTP session configuration.
func testSessionConfig() SessionConfig {
	return SessionConfig{
		ListenerName:        protocolLMTP,
		AuthorityName:       "default",
		AuthorityTransport:  "http",
		ServiceName:         protocolLMTP,
		Network:             "tcp",
		BackendPool:         "lmtp-default",
		TLSMode:             TLSModeStartTLS,
		Capabilities:        []string{"SMTPUTF8", "STARTTLS", testAllAuthCapability},
		PreauthTimeout:      time.Second,
		AuthTimeout:         time.Second,
		MaxLineBytes:        8192,
		MaxBearerTokenBytes: 64,
		PeerAuthMechanisms:  []string{mechanismPlain, mechanismLogin, mechanismXOAUTH2, mechanismOAuthBearer},
	}
}

// testChunkingConfig returns a session config where CHUNKING is safe to advertise for tests.
func testChunkingConfig() SessionConfig {
	config := testSessionConfig()
	config.TLSMode = TLSModeImplicit
	config.Capabilities = []string{"CHUNKING"}
	config.BackendChunkingAllowed = true

	return config
}

// testMTLSConfig returns a required-peer-auth config for certificate-auth tests.
func testMTLSConfig(satisfiesRequired bool) SessionConfig {
	config := testSessionConfig()
	config.TLSMode = TLSModeImplicit
	config.RequirePeerAuth = true
	config.RequireTLSClientCert = true
	config.MTLSPeerAuth = MTLSPeerAuthConfig{
		SatisfiesRequired: satisfiesRequired,
		IdentitySource:    identitySourceSubjectCommonName,
	}

	return config
}

type lmtpHarness struct {
	session *Session
	client  net.Conn
	reader  *bufio.Reader
	cancel  context.CancelFunc
	done    chan error
}

// startLMTPHarness starts a session over an in-memory connection.
func startLMTPHarness(t *testing.T, config SessionConfig) *lmtpHarness {
	t.Helper()

	return startLMTPHarnessWithServerConn(t, config, nil)
}

// startLMTPHarnessWithState starts a session over a connection exposing TLS state.
func startLMTPHarnessWithState(t *testing.T, config SessionConfig, state tls.ConnectionState) *lmtpHarness {
	t.Helper()

	return startLMTPHarnessWithServerConn(t, config, func(conn net.Conn) net.Conn {
		return stateConn{Conn: conn, state: state}
	})
}

// startLMTPHarnessWithServerConn starts a session with an optional server-side connection wrapper.
func startLMTPHarnessWithServerConn(
	t *testing.T,
	config SessionConfig,
	wrap func(net.Conn) net.Conn,
) *lmtpHarness {
	t.Helper()

	server, client := net.Pipe()
	if wrap != nil {
		server = wrap(server)
	}

	session, err := NewSession(config, server)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)

	go func() {
		done <- session.Serve(ctx)
	}()

	harness := &lmtpHarness{
		session: session,
		client:  client,
		reader:  bufio.NewReader(client),
		cancel:  cancel,
		done:    done,
	}

	t.Cleanup(func() {
		cancel()

		_ = client.Close()

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("LMTP session did not exit")
		}
	})

	return harness
}

// write sends raw frontend bytes to the session.
func (h *lmtpHarness) write(t *testing.T, value string) {
	t.Helper()

	if _, err := h.client.Write([]byte(value)); err != nil {
		t.Fatalf("write %q: %v", value, err)
	}
}

// expectLine reads one response line and compares it exactly.
func (h *lmtpHarness) expectLine(t *testing.T, expected string) {
	t.Helper()

	line, err := h.reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	if line != expected {
		t.Fatalf("line = %q, want %q", line, expected)
	}
}

// drainLHLO reads a complete LHLO response with one or more lines.
func (h *lmtpHarness) drainLHLO(t *testing.T) {
	t.Helper()

	for {
		line, err := h.reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read LHLO line: %v", err)
		}

		if len(line) >= 4 && line[3] == ' ' {
			return
		}
	}
}

type stateConn struct {
	net.Conn
	state tls.ConnectionState
}

// ConnectionState returns fixed TLS metadata for mTLS unit tests.
func (c stateConn) ConnectionState() tls.ConnectionState {
	return c.state
}

// verifiedTLSState returns a verified TLS state carrying one peer certificate.
func verifiedTLSState(commonName string) tls.ConnectionState {
	cert := &x509.Certificate{
		Subject: pkix.Name{CommonName: commonName},
	}

	return tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   [][]*x509.Certificate{{cert}},
	}
}

type recordingAuthenticator struct {
	mu       sync.Mutex
	requests []nauthilus.AuthRequest
	result   nauthilus.AuthResult
	err      error
}

// Authenticate records the request and returns a deterministic success by default.
func (a *recordingAuthenticator) Authenticate(_ context.Context, request nauthilus.AuthRequest) (nauthilus.AuthResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.requests = append(a.requests, request)
	if a.err != nil {
		return nauthilus.AuthResult{Decision: nauthilus.DecisionTemporaryFailure}, a.err
	}

	if a.result.Decision != "" {
		return a.result, nil
	}

	return nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: request.Context.Username}, nil
}

// singleRequest returns the only recorded auth request.
func (a *recordingAuthenticator) singleRequest(t *testing.T) nauthilus.AuthRequest {
	t.Helper()

	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.requests) != 1 {
		t.Fatalf("recorded requests = %d, want 1", len(a.requests))
	}

	return a.requests[0]
}

type recordingMessageSink struct {
	mu     sync.Mutex
	body   strings.Builder
	max    int
	finish int
}

// OpenMessage returns the sink itself as the streaming body.
func (s *recordingMessageSink) OpenMessage(context.Context, TransactionSnapshot) (MessageBody, error) {
	return s, nil
}

// Write records one streamed body chunk and tracks the largest write size.
func (s *recordingMessageSink) Write(payload []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(payload) > s.max {
		s.max = len(payload)
	}

	s.body.Write(payload)

	return len(payload), nil
}

// Finish records message completion.
func (s *recordingMessageSink) Finish(context.Context) (MessageResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.finish++

	return MessageResult{Status: responseStatusOK, Text: dataQueuedText}, nil
}

// Abort records no payload and allows the session to close cleanly.
func (s *recordingMessageSink) Abort(context.Context, string) error {
	return nil
}

// bodyString returns all streamed bytes for assertions.
func (s *recordingMessageSink) bodyString() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.body.String()
}

// maxWriteBytes returns the largest chunk passed to Write.
func (s *recordingMessageSink) maxWriteBytes() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.max
}

// finishCount returns the number of completed messages.
func (s *recordingMessageSink) finishCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.finish
}

// plainPayload builds a base64 SASL PLAIN initial response.
func plainPayload(username string, password string) string {
	return base64.StdEncoding.EncodeToString([]byte("\x00" + username + "\x00" + password))
}

// xoauth2Payload builds a base64 XOAUTH2 envelope.
func xoauth2Payload(username string, token string) string {
	payload := "user=" + username + "\x01auth=Bearer " + token + "\x01\x01"

	return base64.StdEncoding.EncodeToString([]byte(payload))
}

// assertNoSecretLeak fails if an error string contains raw secret material.
func assertNoSecretLeak(t *testing.T, value string, secret string) {
	t.Helper()

	if strings.Contains(value, secret) {
		t.Fatalf("value %q leaked secret %q", value, secret)
	}
}
