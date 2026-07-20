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

//nolint:dupl,goconst,wsl_v5 // POP3 session tests repeat public wire values for readability.
package pop3

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/protocol/greeting"
	"github.com/croessner/nauthilus-director/internal/protocol/saslcred"
)

// TestExternalCapabilityRequiresVerifiedClientCertificate proves POP3 advertises EXTERNAL truthfully.
func TestExternalCapabilityRequiresVerifiedClientCertificate(t *testing.T) {
	config := testPOP3Config(TLSModeImplicit, nil)
	config.AuthMechanisms = append(config.AuthMechanisms, saslcred.MechanismExternal)
	leaf := &x509.Certificate{EmailAddresses: []string{"cert@example.test"}}
	session := newTestSession(t, config, stateConn{Conn: nopConn{}, state: tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf}},
	}})

	if !slices.Contains(session.effectiveSASLMechanisms(), "EXTERNAL") {
		t.Fatalf("SASL mechanisms = %v, want EXTERNAL", session.effectiveSASLMechanisms())
	}

	session.conn = stateConn{Conn: nopConn{}, state: tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}}
	if slices.Contains(session.effectiveSASLMechanisms(), "EXTERNAL") {
		t.Fatalf("SASL mechanisms = %v, EXTERNAL must require verification", session.effectiveSASLMechanisms())
	}
}

// TestGreetingRendersSafeOK verifies the POP3 greeting has no deployment-specific secret material.
func TestGreetingRendersSafeOK(t *testing.T) {
	authenticator := &recordingAuthenticator{}
	harness := startPOP3Harness(t, testPOP3Config(TLSModeImplicit, authenticator))

	line := harness.readLine(t)
	if line != "+OK nauthilus-director POP3 ready\r\n" {
		t.Fatalf("greeting = %q, want compatible default", line)
	}

	if strings.Contains(line, "director-instance-secret") {
		t.Fatal("greeting leaked director instance identity")
	}
}

// TestGreetingPolicyControlsPOP3Greeting verifies policy rendering without changing the response class.
func TestGreetingPolicyControlsPOP3Greeting(t *testing.T) {
	tests := []struct {
		name           string
		displayName    string
		processVersion string
		disclosure     greeting.SoftwareVersionDisclosure
		want           string
	}{
		{
			name:           "custom display name",
			displayName:    "Norbert",
			processVersion: "v1.2.3",
			disclosure:     greeting.DisclosureDefault,
			want:           "+OK Norbert POP3 ready\r\n",
		},
		{
			name:           "include version",
			displayName:    "Norbert",
			processVersion: " v1.2.3\nbuild\t7 ",
			disclosure:     greeting.DisclosureInclude,
			want:           "+OK Norbert v1.2.3 build 7 POP3 ready\r\n",
		},
		{
			name:           "suppress default version",
			displayName:    "nauthilus-director",
			processVersion: "v1.2.3",
			disclosure:     greeting.DisclosureSuppress,
			want:           "+OK nauthilus-director POP3 ready\r\n",
		},
		{
			name:           "suppress custom version",
			displayName:    "Norbert",
			processVersion: "v1.2.3",
			disclosure:     greeting.DisclosureSuppress,
			want:           "+OK Norbert POP3 ready\r\n",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			config := testPOP3Config(TLSModeImplicit, &recordingAuthenticator{})
			config.GreetingPolicy = testGreetingPolicy(t, testCase.displayName, testCase.processVersion, testCase.disclosure)

			harness := startPOP3Harness(t, config)
			harness.expectLine(t, testCase.want)
		})
	}
}

// TestCAPARendersEffectiveCapabilities verifies CAPA follows configured methods and TLS state.
func TestCAPARendersEffectiveCapabilities(t *testing.T) {
	harness := startPOP3Harness(t, testPOP3Config(TLSModeStartTLS, &recordingAuthenticator{}))
	harness.expectOK(t)

	harness.write(t, "CAPA\r\n")
	harness.expectLines(t,
		"+OK Capability list follows\r\n",
		"STLS\r\n",
		"PIPELINING\r\n",
		".\r\n",
	)

	harness.session.provisionalUser = "discard-before-tls"
	harness.write(t, "STLS\r\n")
	harness.expectLine(t, "+OK Begin TLS negotiation now\r\n")
	if !harness.session.TLSActive() {
		t.Fatal("TLSActive = false after STLS")
	}

	if got := harness.session.ProvisionalUser(); got != "" {
		t.Fatalf("provisional user after STLS = %q, want empty", got)
	}

	for range 2 {
		harness.write(t, "CAPA\r\n")
		harness.expectLines(t,
			"+OK Capability list follows\r\n",
			"USER\r\n",
			"SASL XOAUTH2 OAUTHBEARER\r\n",
			"PIPELINING\r\n",
			".\r\n",
		)
	}
}

// TestSTLSAcceptsOnlyAdvertisedAndRejectsInjection verifies STARTTLS-like POP3 safety gates.
func TestSTLSAcceptsOnlyAdvertisedAndRejectsInjection(t *testing.T) {
	t.Run("implicit rejects unadvertised STLS", func(t *testing.T) {
		harness := startPOP3Harness(t, testPOP3Config(TLSModeImplicit, &recordingAuthenticator{}))
		harness.expectOK(t)

		harness.write(t, "STLS\r\n")
		harness.expectERR(t)
	})

	t.Run("pipelined plaintext closes", func(t *testing.T) {
		harness := startPOP3Harness(t, testPOP3Config(TLSModeStartTLS, &recordingAuthenticator{}))
		harness.expectOK(t)

		harness.write(t, "STLS\r\nCAPA\r\n")
		harness.expectERR(t)
		harness.expectDone(t)
	})
}

// TestUSERStoresOnlyProvisionalInput verifies USER does not call authority or placement paths.
func TestUSERStoresOnlyProvisionalInput(t *testing.T) {
	authenticator := &recordingAuthenticator{}
	harness := startPOP3Harness(t, testPOP3Config(TLSModeImplicit, authenticator))
	harness.expectOK(t)

	harness.write(t, "USER alice@example.test\r\n")
	harness.expectLine(t, "+OK User accepted\r\n")

	if got := harness.session.ProvisionalUser(); got != "alice@example.test" {
		t.Fatalf("provisional user = %q, want supplied protocol input", got)
	}

	if calls := authenticator.CallCount(); calls != 0 {
		t.Fatalf("auth calls = %d, want 0", calls)
	}
}

// TestPASSWithoutUSERFailsBeforeNauthilus verifies PASS has a fail-closed USER dependency.
func TestPASSWithoutUSERFailsBeforeNauthilus(t *testing.T) {
	authenticator := &recordingAuthenticator{}
	harness := startPOP3Harness(t, testPOP3Config(TLSModeImplicit, authenticator))
	harness.expectOK(t)

	harness.write(t, "PASS secret\r\n")
	harness.expectERR(t)

	if calls := authenticator.CallCount(); calls != 0 {
		t.Fatalf("auth calls = %d, want 0", calls)
	}
}

// TestPlaintextCredentialsFailBeforeNauthilus verifies credential-bearing methods require TLS first.
func TestPlaintextCredentialsFailBeforeNauthilus(t *testing.T) {
	authenticator := &recordingAuthenticator{}
	introspector := &recordingBearerIntrospector{}
	config := testPOP3Config(TLSModeStartTLS, authenticator)
	config.BearerIntrospector = introspector
	harness := startPOP3Harness(t, config)
	harness.expectOK(t)

	harness.session.provisionalUser = "alice@example.test"
	harness.write(t, "PASS secret\r\n")
	harness.expectERR(t)

	harness.write(t, "AUTH XOAUTH2 "+xoauth2Payload("alice@example.test", "token-before-tls")+"\r\n")
	harness.expectERR(t)

	if calls := authenticator.CallCount(); calls != 0 {
		t.Fatalf("auth calls = %d, want 0", calls)
	}
	if calls := introspector.CallCount(); calls != 0 {
		t.Fatalf("introspection calls = %d, want 0", calls)
	}
}

// TestUSERPASSParsesCredentialsAndDelaysSuccess verifies password auth reaches Nauthilus without POP3 success.
func TestUSERPASSParsesCredentialsAndDelaysSuccess(t *testing.T) {
	authenticator := &recordingAuthenticator{
		result: nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: "alice@example.test"},
	}
	introspector := &recordingBearerIntrospector{}
	config := testPOP3Config(TLSModeImplicit, authenticator)
	config.BearerIntrospector = introspector
	harness := startPOP3Harness(t, config)
	harness.expectOK(t)

	harness.write(t, "USER alice@example.test\r\n")
	harness.expectOK(t)
	harness.write(t, "PASS correct-password\r\n")
	harness.expectERR(t)

	request := authenticator.LastRequest(t)
	if request.Context.Protocol != ProtocolPOP3 {
		t.Fatalf("protocol = %q, want pop3", request.Context.Protocol)
	}

	if request.Context.Method != authMethodUserPass {
		t.Fatalf("method = %q, want userpass", request.Context.Method)
	}

	if request.Context.Username != "alice@example.test" {
		t.Fatalf("username = %q, want provisional USER value", request.Context.Username)
	}

	if request.Credential.Value() != "correct-password" {
		t.Fatal("password credential was not forwarded to Nauthilus")
	}
	if calls := introspector.CallCount(); calls != 0 {
		t.Fatalf("introspection calls = %d, want 0", calls)
	}

	assertNoServiceField(t, request)
}

// TestOversizedUSERPASSInputFailsSafely verifies bounded command lines reject credential input early.
func TestOversizedUSERPASSInputFailsSafely(t *testing.T) {
	authenticator := &recordingAuthenticator{}
	config := testPOP3Config(TLSModeImplicit, authenticator)
	config.MaxPreauthLineBytes = 24
	harness := startPOP3Harness(t, config)
	harness.expectOK(t)

	harness.write(t, "USER alice@example.test\r\n")
	harness.expectERR(t)
	harness.expectDone(t)

	if calls := authenticator.CallCount(); calls != 0 {
		t.Fatalf("auth calls = %d, want 0", calls)
	}
}

// TestAUTHBearerInitialAndContinuation verifies both supported bearer response forms.
func TestAUTHBearerInitialAndContinuation(t *testing.T) {
	t.Run("xoauth2 initial response", func(t *testing.T) {
		authenticator := authenticatedRecorder()
		introspector := &recordingBearerIntrospector{
			result: nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: "alice@example.test"},
		}
		config := testPOP3Config(TLSModeImplicit, authenticator)
		config.BearerIntrospector = introspector
		harness := startPOP3Harness(t, config)
		harness.expectOK(t)

		harness.write(t, "AUTH XOAUTH2 "+xoauth2Payload("alice@example.test", "xoauth-token")+"\r\n")
		harness.expectERR(t)

		if calls := authenticator.CallCount(); calls != 0 {
			t.Fatalf("password auth calls = %d, want 0", calls)
		}

		request := introspector.LastRequest(t)
		if request.Context.Method != "xoauth2" || request.Context.Username != "alice@example.test" {
			t.Fatalf("auth context = method %q username %q, want XOAUTH2 identity", request.Context.Method, request.Context.Username)
		}

		if request.BearerToken.Value() != "xoauth-token" {
			t.Fatal("XOAUTH2 bearer token was not sent to introspection")
		}
	})

	t.Run("oauthbearer continuation", func(t *testing.T) {
		authenticator := authenticatedRecorder()
		introspector := &recordingBearerIntrospector{
			result: nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: "alice@example.test"},
		}
		config := testPOP3Config(TLSModeImplicit, authenticator)
		config.BearerIntrospector = introspector
		harness := startPOP3Harness(t, config)
		harness.expectOK(t)

		harness.write(t, "AUTH OAUTHBEARER\r\n")
		harness.expectLine(t, "+ \r\n")
		harness.write(t, oauthBearerPayload("alice@example.test", "oauth-token")+"\r\n")
		harness.expectERR(t)

		if calls := authenticator.CallCount(); calls != 0 {
			t.Fatalf("password auth calls = %d, want 0", calls)
		}

		request := introspector.LastRequest(t)
		if request.Context.Method != "oauthbearer" || request.Context.Username != "alice@example.test" {
			t.Fatalf("auth context = method %q username %q, want OAUTHBEARER identity", request.Context.Method, request.Context.Username)
		}

		if request.BearerToken.Value() != "oauth-token" {
			t.Fatal("OAUTHBEARER token was not sent to introspection")
		}
	})
}

// TestAUTHBearerTemporaryFailureMapsToERR verifies introspection transport failures are temporary.
func TestAUTHBearerTemporaryFailureMapsToERR(t *testing.T) {
	config := testPOP3Config(TLSModeImplicit, &recordingAuthenticator{})
	config.BearerIntrospector = &recordingBearerIntrospector{err: errors.New("temporary introspection failure")}
	harness := startPOP3Harness(t, config)
	harness.expectOK(t)

	harness.write(t, "AUTH XOAUTH2 "+xoauth2Payload("alice@example.test", "xoauth-token")+"\r\n")
	harness.expectLine(t, "-ERR Authentication service temporarily unavailable\r\n")
}

// TestAUTHBearerRejectionMapsToERR verifies inactive tokens reject authentication.
func TestAUTHBearerRejectionMapsToERR(t *testing.T) {
	config := testPOP3Config(TLSModeImplicit, &recordingAuthenticator{})
	config.BearerIntrospector = &recordingBearerIntrospector{
		result: nauthilus.AuthResult{Decision: nauthilus.DecisionRejected},
	}
	harness := startPOP3Harness(t, config)
	harness.expectOK(t)

	harness.write(t, "AUTH OAUTHBEARER "+oauthBearerPayload("alice@example.test", "oauth-token")+"\r\n")
	harness.expectLine(t, "-ERR Authentication failed\r\n")
}

// TestAUTHMalformedOversizedAndUnsupportedInputsFailSafely verifies bad SASL never reaches Nauthilus.
func TestAUTHMalformedOversizedAndUnsupportedInputsFailSafely(t *testing.T) {
	t.Run("malformed initial response", func(t *testing.T) {
		authenticator := authenticatedRecorder()
		harness := startPOP3Harness(t, testPOP3Config(TLSModeImplicit, authenticator))
		harness.expectOK(t)

		harness.write(t, "AUTH XOAUTH2 !!!not-base64!!!\r\n")
		line := harness.expectERR(t)
		if strings.Contains(line, "not-base64") {
			t.Fatal("response leaked malformed SASL payload")
		}

		if calls := authenticator.CallCount(); calls != 0 {
			t.Fatalf("auth calls = %d, want 0", calls)
		}
	})

	t.Run("oversized bearer token", func(t *testing.T) {
		authenticator := authenticatedRecorder()
		config := testPOP3Config(TLSModeImplicit, authenticator)
		config.MaxBearerTokenBytes = 4
		harness := startPOP3Harness(t, config)
		harness.expectOK(t)

		harness.write(t, "AUTH XOAUTH2 "+xoauth2Payload("alice@example.test", "oversized-token")+"\r\n")
		line := harness.expectERR(t)
		if strings.Contains(line, "oversized-token") {
			t.Fatal("response leaked oversized bearer token")
		}

		if calls := authenticator.CallCount(); calls != 0 {
			t.Fatalf("auth calls = %d, want 0", calls)
		}
	})

	t.Run("unsupported mechanism", func(t *testing.T) {
		authenticator := authenticatedRecorder()
		harness := startPOP3Harness(t, testPOP3Config(TLSModeImplicit, authenticator))
		harness.expectOK(t)

		harness.write(t, "AUTH PLAIN AHVzZXIAc2VjcmV0\r\n")
		harness.expectERR(t)

		if calls := authenticator.CallCount(); calls != 0 {
			t.Fatalf("auth calls = %d, want 0", calls)
		}
	})
}

// TestSASLCancellationReturnsSafeERR verifies cancellation is handled without payload disclosure.
func TestSASLCancellationReturnsSafeERR(t *testing.T) {
	authenticator := authenticatedRecorder()
	harness := startPOP3Harness(t, testPOP3Config(TLSModeImplicit, authenticator))
	harness.expectOK(t)

	harness.write(t, "AUTH XOAUTH2\r\n")
	harness.expectLine(t, "+ \r\n")
	harness.write(t, "*\r\n")
	harness.expectERR(t)

	if calls := authenticator.CallCount(); calls != 0 {
		t.Fatalf("auth calls = %d, want 0", calls)
	}
}

// TestUnsupportedPreauthCommandsFailSafely verifies transaction-state commands do not reach auth paths.
func TestUnsupportedPreauthCommandsFailSafely(t *testing.T) {
	authenticator := authenticatedRecorder()
	harness := startPOP3Harness(t, testPOP3Config(TLSModeImplicit, authenticator))
	harness.expectOK(t)

	for _, command := range []string{"STAT", "LIST", "UIDL", "RETR"} {
		harness.write(t, command+"\r\n")
		harness.expectERR(t)
	}

	if calls := authenticator.CallCount(); calls != 0 {
		t.Fatalf("auth calls = %d, want 0", calls)
	}
}

// TestNauthilusSSLContextFields verifies plaintext, STLS and implicit TLS facts are truthful.
func TestNauthilusSSLContextFields(t *testing.T) {
	plain := newTestSession(t, testPOP3Config(TLSModeStartTLS, nil), nopConn{})
	plainContext := plain.NauthilusRequestContext("xoauth2")
	if plainContext.TLS != "false" {
		t.Fatalf("plaintext TLS = %q, want false", plainContext.TLS)
	}

	stls := newTestSession(t, testPOP3Config(TLSModeStartTLS, nil), nopConn{})
	stls.resetAfterSTLS()
	stlsContext := stls.NauthilusRequestContext("xoauth2")
	if stlsContext.TLS != "true" || stlsContext.TLSClientVerify != "NONE" {
		t.Fatalf("STLS context = TLS %q verify %q, want active synthetic TLS", stlsContext.TLS, stlsContext.TLSClientVerify)
	}

	implicitState := tls.ConnectionState{Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256}
	implicit := newTestSession(t, testPOP3Config(TLSModeImplicit, nil), stateConn{Conn: nopConn{}, state: implicitState})
	implicitContext := implicit.NauthilusRequestContext("oauthbearer")
	if implicitContext.TLS != "true" || implicitContext.TLSProtocol != "TLS1.3" || implicitContext.TLSCipher == "" {
		t.Fatalf("implicit context = TLS %q protocol %q cipher %q, want active TLS metadata", implicitContext.TLS, implicitContext.TLSProtocol, implicitContext.TLSCipher)
	}
}

// TestQUITClosesSession verifies the safe pre-auth close command remains available.
func TestQUITClosesSession(t *testing.T) {
	harness := startPOP3Harness(t, testPOP3Config(TLSModeImplicit, &recordingAuthenticator{}))
	harness.expectOK(t)

	harness.write(t, "NOOP\r\n")
	harness.expectOK(t)
	harness.write(t, "QUIT\r\n")
	harness.expectOK(t)
	harness.expectDone(t)
}

// authenticatedRecorder returns a fake Nauthilus authenticator that accepts credentials.
func authenticatedRecorder() *recordingAuthenticator {
	return &recordingAuthenticator{
		result: nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: "alice@example.test"},
	}
}

// testPOP3Config returns a bounded listener config for POP3 unit tests.
func testPOP3Config(tlsMode string, authenticator nauthilus.Authenticator) SessionConfig {
	capabilities := []string{capabilitySTLS, capabilityUser, capabilitySASL, capabilityPipelining}
	if tlsMode == TLSModeImplicit {
		capabilities = []string{capabilityUser, capabilitySASL, capabilityPipelining}
	}

	return SessionConfig{
		ListenerName:           "pop3",
		AuthorityName:          "default",
		AuthorityTransport:     "http",
		ServiceName:            "pop3",
		Network:                "tcp",
		BackendPool:            "pop3-default",
		DirectorInstanceID:     "director-instance-secret",
		DefaultTenant:          "default",
		DefaultShard:           "mailstore-a",
		TLSMode:                tlsMode,
		AuthMechanisms:         []string{authMethodUserPass, "xoauth2", "oauthbearer"},
		Capabilities:           capabilities,
		AuthTimeout:            time.Second,
		MaxPreauthLineBytes:    8192,
		MaxPreauthLiteralBytes: 8192,
		MaxBearerTokenBytes:    8192,
		Authenticator:          authenticator,
	}
}

// testGreetingPolicy builds a shared greeting policy for POP3 wire tests.
func testGreetingPolicy(
	t *testing.T,
	displayNameValue string,
	processVersion string,
	disclosure greeting.SoftwareVersionDisclosure,
) greeting.Policy {
	t.Helper()

	displayName, err := greeting.NewDisplayName(displayNameValue)
	if err != nil {
		t.Fatalf("NewDisplayName(%q): %v", displayNameValue, err)
	}

	policy, err := greeting.NewPolicy(displayName, processVersion, disclosure)
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}

	return policy
}

type pop3Harness struct {
	client  net.Conn
	server  net.Conn
	reader  *bufio.Reader
	session *Session
	done    chan error
}

// startPOP3Harness starts one POP3 session over net.Pipe.
func startPOP3Harness(t *testing.T, config SessionConfig) *pop3Harness {
	t.Helper()

	client, server := net.Pipe()

	return startPOP3HarnessOnConn(t, config, client, server)
}

// startPOP3HarnessWithState starts one POP3 session with synthetic TLS state.
func startPOP3HarnessWithState(t *testing.T, config SessionConfig, state tls.ConnectionState) *pop3Harness {
	t.Helper()

	client, server := net.Pipe()

	return startPOP3HarnessOnConn(t, config, client, stateConn{Conn: server, state: state})
}

// startPOP3HarnessOnConn starts one POP3 session over the provided connection pair.
func startPOP3HarnessOnConn(t *testing.T, config SessionConfig, client net.Conn, server net.Conn) *pop3Harness {
	t.Helper()

	session := newTestSession(t, config, server)
	harness := &pop3Harness{
		client:  client,
		server:  server,
		reader:  bufio.NewReader(client),
		session: session,
		done:    make(chan error, 1),
	}
	go func() {
		harness.done <- session.Serve(context.Background())
	}()

	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()

		if harness.done == nil {
			return
		}

		select {
		case err := <-harness.done:
			if err != nil && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("Serve returned error: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("Serve did not stop")
		}
	})

	return harness
}

// newTestSession builds one POP3 session for tests.
func newTestSession(t *testing.T, config SessionConfig, conn net.Conn) *Session {
	t.Helper()

	session, err := NewSession(config, conn)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	return session
}

// expectOK consumes one successful POP3 response line.
func (h *pop3Harness) expectOK(t *testing.T) string {
	t.Helper()

	line := h.readLine(t)
	if !strings.HasPrefix(line, "+OK") {
		t.Fatalf("line = %q, want +OK", line)
	}

	return line
}

// expectERR consumes one failed POP3 response line.
func (h *pop3Harness) expectERR(t *testing.T) string {
	t.Helper()

	line := h.readLine(t)
	if !strings.HasPrefix(line, "-ERR") {
		t.Fatalf("line = %q, want -ERR", line)
	}

	return line
}

// expectLines consumes expected response lines in order.
func (h *pop3Harness) expectLines(t *testing.T, lines ...string) {
	t.Helper()

	for _, line := range lines {
		h.expectLine(t, line)
	}
}

// expectLine consumes one exact response line.
func (h *pop3Harness) expectLine(t *testing.T, want string) {
	t.Helper()

	got := h.readLine(t)
	if got != want {
		t.Fatalf("line = %q, want %q", got, want)
	}
}

// readLine reads one response line with a test deadline.
func (h *pop3Harness) readLine(t *testing.T) string {
	t.Helper()

	_ = h.client.SetReadDeadline(time.Now().Add(time.Second))
	line, err := h.reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read line: %v", err)
	}

	_ = h.client.SetReadDeadline(time.Time{})

	return line
}

// write sends raw client bytes with a test deadline.
func (h *pop3Harness) write(t *testing.T, value string) {
	t.Helper()

	_ = h.client.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := io.WriteString(h.client, value); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	_ = h.client.SetWriteDeadline(time.Time{})
}

// expectDone verifies the session finished after a close decision.
func (h *pop3Harness) expectDone(t *testing.T) {
	t.Helper()

	select {
	case err := <-h.done:
		if err != nil {
			t.Fatalf("Serve returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not stop")
	}

	h.done = nil
}

type recordingAuthenticator struct {
	mu       sync.Mutex
	requests []nauthilus.AuthRequest
	result   nauthilus.AuthResult
	err      error
}

// Authenticate records one Nauthilus request and returns the configured result.
func (a *recordingAuthenticator) Authenticate(_ context.Context, request nauthilus.AuthRequest) (nauthilus.AuthResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.requests = append(a.requests, request)
	if a.err != nil {
		return nauthilus.AuthResult{Decision: nauthilus.DecisionTemporaryFailure}, a.err
	}

	if a.result.Decision == "" {
		return nauthilus.AuthResult{Decision: nauthilus.DecisionRejected}, nil
	}

	return a.result, nil
}

// CallCount returns how often Authenticate was invoked.
func (a *recordingAuthenticator) CallCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()

	return len(a.requests)
}

// LastRequest returns the most recent recorded auth request.
func (a *recordingAuthenticator) LastRequest(t *testing.T) nauthilus.AuthRequest {
	t.Helper()

	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.requests) == 0 {
		t.Fatal("missing auth request")
	}

	return a.requests[len(a.requests)-1]
}

type recordingBearerIntrospector struct {
	mu       sync.Mutex
	requests []nauthilus.BearerIntrospectionRequest
	result   nauthilus.AuthResult
	err      error
}

// Introspect records one bearer request and returns the configured result.
func (i *recordingBearerIntrospector) Introspect(_ context.Context, request nauthilus.BearerIntrospectionRequest) (nauthilus.AuthResult, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	i.requests = append(i.requests, request)
	if i.err != nil {
		return nauthilus.AuthResult{Decision: nauthilus.DecisionTemporaryFailure}, i.err
	}

	if i.result.Decision == "" {
		return nauthilus.AuthResult{Decision: nauthilus.DecisionRejected}, nil
	}

	return i.result, nil
}

// CallCount returns how often Introspect was invoked.
func (i *recordingBearerIntrospector) CallCount() int {
	i.mu.Lock()
	defer i.mu.Unlock()

	return len(i.requests)
}

// LastRequest returns the most recent recorded introspection request.
func (i *recordingBearerIntrospector) LastRequest(t *testing.T) nauthilus.BearerIntrospectionRequest {
	t.Helper()

	i.mu.Lock()
	defer i.mu.Unlock()

	if len(i.requests) == 0 {
		t.Fatal("missing introspection request")
	}

	return i.requests[len(i.requests)-1]
}

// xoauth2Payload builds a test XOAUTH2 envelope.
func xoauth2Payload(username string, token string) string {
	return base64.StdEncoding.EncodeToString([]byte("user=" + username + "\x01auth=Bearer " + token + "\x01\x01"))
}

// oauthBearerPayload builds a test OAUTHBEARER envelope.
func oauthBearerPayload(username string, token string) string {
	return base64.StdEncoding.EncodeToString([]byte("n,a=" + username + ",\x01auth=Bearer " + token + "\x01\x01"))
}

// assertNoServiceField verifies POP3 did not synthesize the forbidden service body field.
func assertNoServiceField(t *testing.T, request nauthilus.AuthRequest) {
	t.Helper()

	if _, ok := reflect.TypeFor[nauthilus.AuthRequest]().FieldByName("Service"); ok {
		t.Fatal("AuthRequest unexpectedly contains Service field")
	}

	body, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal auth request: %v", err)
	}

	if strings.Contains(strings.ToLower(string(body)), "service") {
		t.Fatal("auth request JSON contained forbidden service field")
	}
}

type nopConn struct{}

// Read implements net.Conn for synthetic request-context tests.
func (nopConn) Read([]byte) (int, error) {
	return 0, io.EOF
}

// Write implements net.Conn for synthetic request-context tests.
func (nopConn) Write(p []byte) (int, error) {
	return len(p), nil
}

// Close implements net.Conn for synthetic request-context tests.
func (nopConn) Close() error {
	return nil
}

// LocalAddr implements net.Conn for synthetic request-context tests.
func (nopConn) LocalAddr() net.Addr {
	return testAddr("127.0.0.1:110")
}

// RemoteAddr implements net.Conn for synthetic request-context tests.
func (nopConn) RemoteAddr() net.Addr {
	return testAddr("192.0.2.10:49152")
}

// SetDeadline implements net.Conn for synthetic request-context tests.
func (nopConn) SetDeadline(time.Time) error {
	return nil
}

// SetReadDeadline implements net.Conn for synthetic request-context tests.
func (nopConn) SetReadDeadline(time.Time) error {
	return nil
}

// SetWriteDeadline implements net.Conn for synthetic request-context tests.
func (nopConn) SetWriteDeadline(time.Time) error {
	return nil
}

type stateConn struct {
	net.Conn
	state tls.ConnectionState
}

// ConnectionState returns fixed TLS metadata for auth-context tests.
func (c stateConn) ConnectionState() tls.ConnectionState {
	return c.state
}

type testAddr string

// Network returns the synthetic address network.
func (a testAddr) Network() string {
	return "tcp"
}

// String returns the synthetic address value.
func (a testAddr) String() string {
	return string(a)
}
