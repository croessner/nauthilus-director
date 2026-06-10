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

//nolint:funlen,goconst,wsl_v5 // Scripted backend tests keep POP3 wire order visible.
package pop3

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/placement"
	"github.com/croessner/nauthilus-director/internal/protocol/saslcred"
)

const (
	testPOP3BackendAddress       = "localhost:110"
	testPOP3BackendHealthPass    = "health-secret"
	testPOP3BackendHealthProxyV4 = "PROXY TCP4 10.10.0.1 10.10.0.2 50110 110"
	testPOP3BackendHealthUser    = "healthcheck@example.test"
	testPOP3BackendMasterPass    = "master-secret"
	testPOP3BackendMasterUser    = "director-master"
	testPOP3BackendProxyV4       = "PROXY TCP4 203.0.113.10 198.51.100.20 42500 110"
	testPOP3BackendServerName    = "localhost"
	testPOP3FrontendPassword     = "frontend-secret"
)

// TestBackendConnectorHandlesPlaintext verifies cleartext greeting and CAPA discovery.
func TestBackendConnectorHandlesPlaintext(t *testing.T) {
	dialer := scriptedPOP3BackendDialer(t, func(_ *testing.T, conn net.Conn) {
		reader := bufio.NewReader(conn)
		writePOP3BackendLine(t, conn, "+OK ready")
		expectPOP3BackendLine(t, reader, "CAPA")
		writePOP3BackendCapabilities(t, conn, false)
	})

	connection, err := NewTCPBackendConnector(dialer).Connect(
		context.Background(),
		testPOP3BackendConnectRequest(testPOP3BackendTarget(backendTLSNone)),
	)
	if err != nil {
		t.Fatalf("Connect returned error: %v", err)
	}
	defer func() { _ = connection.Conn().Close() }()

	if connection.TLSActive() || connection.TLSVerified() {
		t.Fatalf("TLS state active=%v verified=%v, want plaintext", connection.TLSActive(), connection.TLSVerified())
	}

	if !connection.CapabilitySet().Has(capabilityUser) || !connection.CapabilitySet().Has(capabilitySASL+"=XOAUTH2") {
		t.Fatalf("capabilities = %v, want USER and bearer SASL", connection.Capabilities())
	}

	dialer.Wait(t)
}

// TestBackendConnectorWritesProxyBeforePlaintextGreeting verifies PROXY precedes all POP3 bytes.
func TestBackendConnectorWritesProxyBeforePlaintextGreeting(t *testing.T) {
	dialer := scriptedPOP3BackendDialer(t, func(_ *testing.T, conn net.Conn) {
		reader := bufio.NewReader(conn)
		expectPOP3BackendLine(t, reader, testPOP3BackendProxyV4)
		writePOP3BackendLine(t, conn, "+OK ready")
		expectPOP3BackendLine(t, reader, "CAPA")
		writePOP3BackendCapabilities(t, conn, false)
	})

	connection, err := NewTCPBackendConnector(dialer).Connect(
		context.Background(),
		testProxyPOP3BackendConnectRequest(testPOP3BackendTarget(backendTLSNone)),
	)
	if err != nil {
		t.Fatalf("Connect returned error: %v", err)
	}
	defer func() { _ = connection.Conn().Close() }()

	dialer.Wait(t)
}

// TestBackendConnectorHandlesStartTLS verifies STLS advertisement and TLS upgrade order.
func TestBackendConnectorHandlesStartTLS(t *testing.T) {
	certPath, certificate := writePOP3BackendTestCertificate(t)
	dialer := scriptedPOP3BackendDialer(t, func(_ *testing.T, conn net.Conn) {
		reader := bufio.NewReader(conn)
		writePOP3BackendLine(t, conn, "+OK ready")
		expectPOP3BackendLine(t, reader, "CAPA")
		writePOP3BackendCapabilities(t, conn, true)
		expectPOP3BackendLine(t, reader, "STLS")
		writePOP3BackendLine(t, conn, "+OK begin tls")

		tlsConn := tls.Server(conn, pop3BackendTestTLSConfig(certificate))
		if err := tlsConn.Handshake(); err != nil {
			t.Errorf("server handshake: %v", err)
			return
		}

		tlsReader := bufio.NewReader(tlsConn)
		expectPOP3BackendLine(t, tlsReader, "CAPA")
		writePOP3BackendCapabilities(t, tlsConn, false)
	})

	connection, err := NewTCPBackendConnector(dialer).Connect(
		context.Background(),
		testPOP3BackendConnectRequest(testPOP3BackendTargetWithCA(backendTLSStartTLS, certPath)),
	)
	if err != nil {
		t.Fatalf("Connect returned error: %v", err)
	}
	defer func() { _ = connection.Conn().Close() }()

	if !connection.TLSActive() || !connection.TLSVerified() {
		t.Fatalf("TLS state active=%v verified=%v", connection.TLSActive(), connection.TLSVerified())
	}

	dialer.Wait(t)
}

// TestBackendStartTLSRequiresAdvertisement verifies STLS fails closed without CAPA proof.
func TestBackendStartTLSRequiresAdvertisement(t *testing.T) {
	dialer := scriptedPOP3BackendDialer(t, func(_ *testing.T, conn net.Conn) {
		reader := bufio.NewReader(conn)
		writePOP3BackendLine(t, conn, "+OK ready")
		expectPOP3BackendLine(t, reader, "CAPA")
		writePOP3BackendCapabilities(t, conn, false)
	})

	_, err := NewTCPBackendConnector(dialer).Connect(
		context.Background(),
		testPOP3BackendConnectRequest(testPOP3BackendTarget(backendTLSStartTLS)),
	)
	if !errors.Is(err, ErrBackendTLS) {
		t.Fatalf("Connect error = %v, want backend TLS rejection", err)
	}

	dialer.Wait(t)
}

// TestBackendConnectorHandlesImplicitTLS verifies TLS wraps before greeting and CAPA.
func TestBackendConnectorHandlesImplicitTLS(t *testing.T) {
	certPath, certificate := writePOP3BackendTestCertificate(t)
	dialer := scriptedPOP3BackendDialer(t, func(t *testing.T, conn net.Conn) {
		tlsConn := tls.Server(conn, pop3BackendTestTLSConfig(certificate))
		if err := tlsConn.Handshake(); err != nil {
			t.Errorf("server handshake: %v", err)
			return
		}

		reader := bufio.NewReader(tlsConn)
		writePOP3BackendLine(t, tlsConn, "+OK ready")
		expectPOP3BackendLine(t, reader, "CAPA")
		writePOP3BackendCapabilities(t, tlsConn, false)
	})

	connection, err := NewTCPBackendConnector(dialer).Connect(
		context.Background(),
		testPOP3BackendConnectRequest(testPOP3BackendTargetWithCA(backendTLSImplicit, certPath)),
	)
	if err != nil {
		t.Fatalf("Connect returned error: %v", err)
	}
	defer func() { _ = connection.Conn().Close() }()

	if !connection.TLSActive() || !connection.TLSVerified() {
		t.Fatalf("TLS state active=%v verified=%v", connection.TLSActive(), connection.TLSVerified())
	}

	dialer.Wait(t)
}

// TestBackendCertificateVerificationIsDefault verifies self-signed TLS fails without a trusted CA.
func TestBackendCertificateVerificationIsDefault(t *testing.T) {
	_, certificate := writePOP3BackendTestCertificate(t)
	dialer := scriptedPOP3BackendDialer(t, func(_ *testing.T, conn net.Conn) {
		tlsConn := tls.Server(conn, pop3BackendTestTLSConfig(certificate))
		_ = tlsConn.Handshake()
	})

	_, err := NewTCPBackendConnector(dialer).Connect(
		context.Background(),
		testPOP3BackendConnectRequest(testPOP3BackendTarget(backendTLSImplicit)),
	)
	if !errors.Is(err, ErrBackendTLS) {
		t.Fatalf("Connect error = %v, want verification failure", err)
	}

	dialer.Wait(t)
}

// TestMasterUserAuthFormatsSelectedUser verifies master-user USER/PASS is formatted safely.
func TestMasterUserAuthFormatsSelectedUser(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = server.Close() }()

		reader := bufio.NewReader(server)
		expectPOP3BackendLine(t, reader, "USER canonical@example.test*director-master")
		writePOP3BackendLine(t, server, "+OK user accepted")
		expectPOP3BackendLine(t, reader, "PASS "+testPOP3BackendMasterPass)
		writePOP3BackendLine(t, server, "+OK pass accepted")
	}()

	connection := newBackendConnection(client)
	connection.capabilities = backend.NewCapabilitySet(capabilityUser)
	target := testPOP3BackendTarget(backendTLSNone)
	target.Auth = backend.AuthConfig{
		Mode: backendAuthModeMasterUser,
		MasterUser: backend.MasterUserConfig{
			Username:   testPOP3BackendMasterUser,
			Password:   config.Secret(testPOP3BackendMasterPass),
			UserFormat: "{user}*{master_user}",
			Mechanism:  "plain",
		},
	}

	credentials := newPasswordCredentials("frontend@example.test", testPOP3FrontendPassword)
	defer credentials.Clear()

	if err := AuthenticateBackend(connection, target, credentials, "canonical@example.test"); err != nil {
		t.Fatalf("AuthenticateBackend returned error: %v", err)
	}

	waitPOP3BackendDone(t, done)
}

// TestMasterUserModeBearerUsesCredentialReplay verifies bearer sessions never become USER/PASS master logins.
func TestMasterUserModeBearerUsesCredentialReplay(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	done := make(chan error, 1)
	go func() {
		defer close(done)
		defer func() { _ = server.Close() }()

		reader := bufio.NewReader(server)
		rawLine, err := reader.ReadString('\n')
		if err != nil {
			done <- fmt.Errorf("read backend line: %w", err)

			return
		}
		line := strings.TrimRight(rawLine, "\r\n")
		if strings.HasPrefix(strings.ToUpper(line), "USER ") {
			done <- fmt.Errorf("bearer backend auth used USER/PASS master-user command %q", line)

			return
		}
		if !strings.HasPrefix(line, "AUTH XOAUTH2 ") {
			done <- fmt.Errorf("backend auth line = %q, want AUTH XOAUTH2", line)

			return
		}

		payloadBytes, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "AUTH XOAUTH2 "))
		if err != nil {
			done <- fmt.Errorf("decode POP3 SASL payload: %w", err)

			return
		}
		payload := string(payloadBytes)
		if payload != "user=alice@example.test\x01auth=Bearer "+testPOP3FrontendPassword+"\x01\x01" {
			done <- fmt.Errorf("XOAUTH2 payload mismatch: got %d bytes, want bearer replay payload", len(payload))

			return
		}
		for _, forbidden := range []string{testPOP3BackendMasterUser, testPOP3BackendMasterPass, "*director-master"} {
			if strings.Contains(payload, forbidden) {
				done <- fmt.Errorf("bearer replay payload used master-user material %q", forbidden)

				return
			}
		}

		if _, err := io.WriteString(server, "+OK bearer accepted\r\n"); err != nil {
			done <- fmt.Errorf("write backend line: %w", err)
		}
	}()

	connection := newBackendConnection(client)
	connection.capabilities = backend.NewCapabilitySet(capabilityUser, capabilitySASL+"=XOAUTH2")
	connection.tlsActive = true
	connection.tlsVerified = true

	credentials := pop3XOAUTH2CredentialsForBackendTest(t)
	defer credentials.Clear()

	if err := AuthenticateBackend(connection, testPOP3MasterUserBackend(), credentials, "canonical@example.test"); err != nil {
		t.Fatalf("AuthenticateBackend returned error: %v", err)
	}

	waitPOP3BackendResult(t, done)
}

// TestMasterUserBearerReplayFailsClosedBeforePOP3Commands verifies unsafe policy sends no bytes.
func TestMasterUserBearerReplayFailsClosedBeforePOP3Commands(t *testing.T) {
	testCases := map[string]struct {
		target       backend.Backend
		capabilities backend.CapabilitySet
		tlsVerified  bool
	}{
		"missing allowlist": {
			target: func() backend.Backend {
				target := testPOP3MasterUserBackend()
				target.Auth.CredentialReplay.AllowedMechanisms = []string{saslcred.MechanismOAuthBearer}

				return target
			}(),
			capabilities: backend.NewCapabilitySet(capabilityUser, capabilitySASL+"=XOAUTH2"),
			tlsVerified:  true,
		},
		"missing capability": {
			target:       testPOP3MasterUserBackend(),
			capabilities: backend.NewCapabilitySet(capabilityUser),
			tlsVerified:  true,
		},
		"tls required": {
			target:       testPOP3MasterUserBackend(),
			capabilities: backend.NewCapabilitySet(capabilityUser, capabilitySASL+"=XOAUTH2"),
			tlsVerified:  false,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			credentials := pop3XOAUTH2CredentialsForBackendTest(t)
			defer credentials.Clear()

			assertPOP3AuthenticateWritesNothing(t, testCase.target, testCase.capabilities, testCase.tlsVerified, credentials)
		})
	}
}

// TestCredentialReplayPolicy verifies allowlists and verified TLS enforcement.
func TestCredentialReplayPolicy(t *testing.T) {
	credentials := newPasswordCredentials("alice@example.test", testPOP3FrontendPassword)
	defer credentials.Clear()

	connection := &BackendConnection{
		capabilities: backend.NewCapabilitySet(capabilityUser),
		tlsActive:    true,
		tlsVerified:  false,
	}
	replay := backend.CredentialReplayConfig{
		RequireBackendTLS: true,
		AllowedMechanisms: []string{authMethodUserPass},
	}
	if _, err := selectReplayMechanism(replay, connection.CapabilitySet(), credentials); err != nil {
		t.Fatalf("selectReplayMechanism without TLS returned error before TLS policy: %v", err)
	}

	target := testPOP3BackendTarget(backendTLSNone)
	target.Auth = backend.AuthConfig{Mode: backendAuthModeCredentialReplay, CredentialReplay: replay}
	if err := AuthenticateBackend(connection, target, credentials, "alice@example.test"); !errors.Is(err, ErrBackendAuthPolicy) {
		t.Fatalf("AuthenticateBackend without verified TLS error = %v, want policy", err)
	}

	replay.RequireBackendTLS = false
	replay.AllowedMechanisms = []string{saslcred.MechanismXOAUTH2}
	if _, err := selectReplayMechanism(replay, connection.CapabilitySet(), credentials); !errors.Is(err, ErrBackendAuthPolicy) {
		t.Fatalf("password replay without userpass allowlist error = %v, want policy", err)
	}
}

// TestCredentialReplayBearerRequiresCAPA verifies bearer replay needs method allowlist and CAPA proof.
func TestCredentialReplayBearerRequiresCAPA(t *testing.T) {
	mechanism, err := saslcred.NewMechanism(saslcred.MechanismXOAUTH2)
	if err != nil {
		t.Fatalf("new mechanism: %v", err)
	}

	credentials, err := parseSASLCredentials(mechanism, xoauth2Payload("alice@example.test", testPOP3FrontendPassword), 256, 128)
	if err != nil {
		t.Fatalf("parse credentials: %v", err)
	}
	defer credentials.Clear()

	replay := backend.CredentialReplayConfig{
		AllowedMechanisms: []string{saslcred.MechanismXOAUTH2},
	}
	if _, err := selectReplayMechanism(replay, backend.NewCapabilitySet(capabilityUser), credentials); !errors.Is(err, ErrBackendAuthPolicy) {
		t.Fatalf("bearer replay without CAPA error = %v, want policy", err)
	}

	mechanismName, err := selectReplayMechanism(replay, backend.NewCapabilitySet(capabilitySASL+"=XOAUTH2"), credentials)
	if err != nil {
		t.Fatalf("selectReplayMechanism returned error: %v", err)
	}
	if mechanismName != saslcred.MechanismXOAUTH2 {
		t.Fatalf("mechanism = %q, want XOAUTH2", mechanismName)
	}
}

// TestLightHealthWritesProxyBeforeGreeting verifies health uses purpose health and socket tuple.
func TestLightHealthWritesProxyBeforeGreeting(t *testing.T) {
	dialer := scriptedPOP3BackendDialerWithAddrs(
		t,
		pop3TCPAddr("10.10.0.1", 50110),
		pop3TCPAddr("10.10.0.2", 110),
		func(_ *testing.T, conn net.Conn) {
			reader := bufio.NewReader(conn)
			expectPOP3BackendLine(t, reader, testPOP3BackendHealthProxyV4)
			writePOP3BackendLine(t, conn, "+OK ready")
			expectPOP3BackendLine(t, reader, "CAPA")
			writePOP3BackendCapabilities(t, conn, false)
			expectPOP3BackendLine(t, reader, "QUIT")
			writePOP3BackendLine(t, conn, "+OK bye")
		},
	)
	target := testPOP3BackendTarget(backendTLSNone)
	target.HAProxy.Enabled = true

	result := NewHealthChecker(NewTCPBackendConnector(dialer)).CheckBackend(context.Background(), target, backend.HealthCheckRequest{
		Timeout: time.Second,
	})
	if !result.Healthy {
		t.Fatalf("health result = %#v, want healthy", result)
	}

	dialer.Wait(t)
}

// TestDeepHealthUsesOnlyNonMutatingCommands verifies health never inspects mailbox state.
func TestDeepHealthUsesOnlyNonMutatingCommands(t *testing.T) {
	commands := make(chan string, 8)
	dialer := scriptedPOP3BackendDialer(t, func(_ *testing.T, conn net.Conn) {
		reader := bufio.NewReader(conn)
		writePOP3BackendLine(t, conn, "+OK ready")
		recordAndExpectPOP3BackendLine(t, reader, commands, "CAPA")
		writePOP3BackendCapabilities(t, conn, false)
		recordAndExpectPOP3BackendLine(t, reader, commands, "USER "+testPOP3BackendHealthUser)
		writePOP3BackendLine(t, conn, "+OK user accepted")
		recordAndExpectPOP3BackendLine(t, reader, commands, "PASS "+testPOP3BackendHealthPass)
		writePOP3BackendLine(t, conn, "+OK pass accepted")
		recordAndExpectPOP3BackendLine(t, reader, commands, "NOOP")
		writePOP3BackendLine(t, conn, "+OK noop")
		recordAndExpectPOP3BackendLine(t, reader, commands, "QUIT")
		writePOP3BackendLine(t, conn, "+OK bye")
	})
	target := testPOP3BackendTarget(backendTLSNone)
	target.Health = backend.HealthConfig{
		Enabled:   true,
		DeepCheck: true,
		Username:  testPOP3BackendHealthUser,
		Password:  config.Secret(testPOP3BackendHealthPass),
	}

	result := NewHealthChecker(NewTCPBackendConnector(dialer)).CheckBackend(context.Background(), target, backend.HealthCheckRequest{
		Deep:    true,
		Timeout: time.Second,
	})
	if !result.Healthy {
		t.Fatalf("health result = %#v, want healthy", result)
	}

	dialer.Wait(t)
	close(commands)
	for command := range commands {
		assertPOP3HealthCommandIsSafe(t, command)
	}
}

// TestBackendHealthReasonClassesPreserveSharedTransportVocabulary verifies bounded mappings.
func TestBackendHealthReasonClassesPreserveSharedTransportVocabulary(t *testing.T) {
	cases := map[error]string{
		ErrBackendConnect:        healthReasonConnect,
		ErrBackendTLS:            healthReasonTLS,
		ErrBackendProtocol:       healthReasonProtocol,
		ErrBackendAuth:           healthReasonAuth,
		context.DeadlineExceeded: healthReasonTimeout,
		&backend.TransportError{Reason: backend.TransportReasonWriteFailed, Purpose: backend.ConnectPurposeHealth}:       healthReasonProxyWrite,
		&backend.TransportError{Reason: backend.TransportReasonMissingAddress, Purpose: backend.ConnectPurposeHealth}:    healthReasonProxyMissingAddress,
		&backend.TransportError{Reason: backend.TransportReasonUnsupportedFamily, Purpose: backend.ConnectPurposeHealth}: healthReasonProxyUnsupportedFamily,
		&backend.TransportError{Reason: backend.TransportReasonConfig, Purpose: backend.ConnectPurposeHealth}:            healthReasonProxyConfig,
		errors.New(testPOP3BackendHealthPass): healthReasonUnknown,
	}

	for err, want := range cases {
		if got := backendHealthReason(err); got != want {
			t.Fatalf("backendHealthReason(%T) = %q, want %q", err, got, want)
		}
	}
}

// TestAuthenticatedPOP3ConnectsSelectedBackendBeforeFrontendSuccess verifies backend readiness ordering.
func TestAuthenticatedPOP3ConnectsSelectedBackendBeforeFrontendSuccess(t *testing.T) {
	authenticator := &recordingAuthenticator{
		result: nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: "canonical@example.test"},
	}
	placer := &recordingSessionPlacer{}
	lease := newRecordingPlacementLease(placement.SessionRequest{
		BackendPool: "pop3-default",
		ShardTag:    "mailstore-a",
	})
	lease.backend.Backend.TLS = backend.TLSConfig{Mode: backendTLSNone}
	lease.backend.Backend.Auth = backend.AuthConfig{
		Mode: backendAuthModeMasterUser,
		MasterUser: backend.MasterUserConfig{
			Username:   testPOP3BackendMasterUser,
			Password:   config.Secret(testPOP3BackendMasterPass),
			UserFormat: "{user}*{master_user}",
			Mechanism:  "plain",
		},
	}
	placer.lease = lease

	connector := &recordingPOP3BackendConnector{}
	config := testPlacementPOP3Config(TLSModeImplicit, authenticator, nil, placer)
	config.BackendConnector = connector
	harness := startPOP3Harness(t, config)
	harness.expectOK(t)

	harness.write(t, "USER frontend@example.test\r\n")
	harness.expectOK(t)
	harness.write(t, "PASS "+testPOP3FrontendPassword+"\r\n")
	line := harness.expectOK(t)
	if strings.Contains(line, testPOP3BackendMasterPass) || strings.Contains(line, testPOP3FrontendPassword) {
		t.Fatalf("frontend success leaked secret material: %q", line)
	}
	harness.expectDone(t)

	request := connector.singleRequest(t)
	if request.Purpose != backend.ConnectPurposeSession {
		t.Fatalf("connect purpose = %q, want session", request.Purpose)
	}
	if request.Target.Identifier != "mailstore-a-pop3" {
		t.Fatalf("connect target = %q, want selected backend", request.Target.Identifier)
	}
	if request.ProxyAddresses == nil {
		t.Fatal("connect request missing frontend tuple")
	}
	if got := request.ProxyAddresses.Source.String(); got != "pipe" {
		t.Fatalf("proxy source = %q, want effective frontend remote tuple", got)
	}
	if !connector.sawCommandPrefix("USER canonical@example.test*director-master") {
		t.Fatal("backend did not receive formatted master-user USER before frontend success")
	}
}

// TestBackendAuthFailureMapsToTemporaryFrontendFailure verifies backend status text stays hidden.
func TestBackendAuthFailureMapsToTemporaryFrontendFailure(t *testing.T) {
	authenticator := &recordingAuthenticator{
		result: nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: "canonical@example.test"},
	}
	placer := &recordingSessionPlacer{}
	lease := newRecordingPlacementLease(placement.SessionRequest{
		BackendPool: "pop3-default",
		ShardTag:    "mailstore-a",
	})
	lease.backend.Backend.TLS = backend.TLSConfig{Mode: backendTLSNone}
	lease.backend.Backend.Auth = backend.AuthConfig{
		Mode: backendAuthModeMasterUser,
		MasterUser: backend.MasterUserConfig{
			Username:   testPOP3BackendMasterUser,
			Password:   config.Secret(testPOP3BackendMasterPass),
			UserFormat: "{user}*{master_user}",
			Mechanism:  "plain",
		},
	}
	placer.lease = lease

	config := testPlacementPOP3Config(TLSModeImplicit, authenticator, nil, placer)
	config.BackendConnector = &recordingPOP3BackendConnector{authResponse: "-ERR backend-secret says no"}
	harness := startPOP3Harness(t, config)
	harness.expectOK(t)

	harness.write(t, "USER frontend@example.test\r\n")
	harness.expectOK(t)
	harness.write(t, "PASS "+testPOP3FrontendPassword+"\r\n")
	line := harness.expectERR(t)
	if !strings.Contains(line, "Mailbox temporarily unavailable") {
		t.Fatalf("backend auth failure response = %q, want safe temporary failure", line)
	}
	if strings.Contains(line, "backend-secret") || strings.Contains(line, testPOP3FrontendPassword) {
		t.Fatalf("backend auth failure leaked secret material: %q", line)
	}
}

// scriptedPOP3BackendDialer creates a net.Pipe dialer with one scripted backend.
func scriptedPOP3BackendDialer(t *testing.T, script func(*testing.T, net.Conn)) *pop3BackendScriptedDialer {
	t.Helper()

	return scriptedPOP3BackendDialerWithAddrs(t, nil, nil, script)
}

// scriptedPOP3BackendDialerWithAddrs creates a dialer with fixed backend socket addresses.
func scriptedPOP3BackendDialerWithAddrs(
	t *testing.T,
	local net.Addr,
	remote net.Addr,
	script func(*testing.T, net.Conn),
) *pop3BackendScriptedDialer {
	t.Helper()

	return &pop3BackendScriptedDialer{
		t:      t,
		local:  local,
		remote: remote,
		script: script,
		done:   make(chan struct{}),
	}
}

type pop3BackendScriptedDialer struct {
	t      *testing.T
	local  net.Addr
	remote net.Addr
	script func(*testing.T, net.Conn)
	done   chan struct{}
}

// DialContext returns one side of a net.Pipe and runs the fake backend on the other.
func (d *pop3BackendScriptedDialer) DialContext(_ context.Context, _ string, _ string) (net.Conn, error) {
	client, server := net.Pipe()
	clientConn := client

	if d.local != nil || d.remote != nil {
		clientConn = pop3BackendAddressConn{Conn: client, local: d.local, remote: d.remote}
	}

	go func() {
		defer close(d.done)
		defer func() { _ = server.Close() }()

		d.script(d.t, server)
	}()

	return clientConn, nil
}

// Wait asserts that the fake backend script finished.
func (d *pop3BackendScriptedDialer) Wait(t *testing.T) {
	t.Helper()

	waitPOP3BackendDone(t, d.done)
}

// waitPOP3BackendDone waits for a scripted backend goroutine.
func waitPOP3BackendDone(t *testing.T, done <-chan struct{}) {
	t.Helper()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for scripted backend")
	}
}

// waitPOP3BackendResult waits for a scripted backend goroutine and reports its error.
func waitPOP3BackendResult(t *testing.T, done <-chan error) {
	t.Helper()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for scripted backend")
	}
}

// testPOP3BackendConnectRequest creates a disabled-PROXY request with stable metadata.
func testPOP3BackendConnectRequest(target backend.Backend) backend.ConnectRequest {
	return backend.ConnectRequest{
		Target:  target,
		Timeout: time.Second,
		Purpose: backend.ConnectPurposeSession,
		ProxyAddresses: &backend.ProxyAddresses{
			Source:      pop3TCPAddr("203.0.113.10", 42500),
			Destination: pop3TCPAddr("198.51.100.20", 110),
		},
	}
}

// testProxyPOP3BackendConnectRequest enables outbound PROXY for connector tests.
func testProxyPOP3BackendConnectRequest(target backend.Backend) backend.ConnectRequest {
	request := testPOP3BackendConnectRequest(target)
	request.Target.HAProxy.Enabled = true

	return request
}

// testPOP3BackendTarget returns a minimal backend target for connector tests.
func testPOP3BackendTarget(mode string) backend.Backend {
	return backend.Backend{
		Identifier:  "mailstore-a-pop3",
		Protocol:    ProtocolPOP3,
		BackendPool: "pop3-default",
		Address:     testPOP3BackendAddress,
		TLS: backend.TLSConfig{
			Mode:          mode,
			ServerName:    testPOP3BackendServerName,
			MinTLSVersion: backendTLSMinDefault,
		},
	}
}

// testPOP3BackendTargetWithCA returns a backend target using the generated test CA.
func testPOP3BackendTargetWithCA(mode string, caFile string) backend.Backend {
	target := testPOP3BackendTarget(mode)
	target.TLS.CAFile = caFile

	return target
}

// testPOP3MasterUserBackend returns a hybrid master-user backend fixture.
func testPOP3MasterUserBackend() backend.Backend {
	target := testPOP3BackendTarget(backendTLSStartTLS)
	target.Auth = backend.AuthConfig{
		Mode: backendAuthModeMasterUser,
		MasterUser: backend.MasterUserConfig{
			Username:   testPOP3BackendMasterUser,
			Password:   config.Secret(testPOP3BackendMasterPass),
			UserFormat: "{user}*{master_user}",
			Mechanism:  "plain",
		},
		CredentialReplay: backend.CredentialReplayConfig{
			RequireBackendTLS: true,
			PreserveMechanism: true,
			AllowedMechanisms: []string{authMethodUserPass, saslcred.MechanismXOAUTH2, saslcred.MechanismOAuthBearer},
		},
	}

	return target
}

// pop3XOAUTH2CredentialsForBackendTest creates bearer credentials for backend auth tests.
func pop3XOAUTH2CredentialsForBackendTest(t *testing.T) *frontendCredentials {
	t.Helper()

	mechanism, err := saslcred.NewMechanism(saslcred.MechanismXOAUTH2)
	if err != nil {
		t.Fatalf("new mechanism: %v", err)
	}

	credentials, err := parseSASLCredentials(mechanism, xoauth2Payload("alice@example.test", testPOP3FrontendPassword), 256, 128)
	if err != nil {
		t.Fatalf("parse XOAUTH2 credentials: %v", err)
	}

	return credentials
}

// assertPOP3AuthenticateWritesNothing proves policy rejection happens before backend auth bytes.
func assertPOP3AuthenticateWritesNothing(
	t *testing.T,
	target backend.Backend,
	capabilities backend.CapabilitySet,
	tlsVerified bool,
	credentials *frontendCredentials,
) {
	t.Helper()

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	connection := newBackendConnection(client)
	connection.capabilities = capabilities
	connection.tlsActive = tlsVerified
	connection.tlsVerified = tlsVerified

	done := make(chan error, 1)
	go func() {
		done <- AuthenticateBackend(connection, target, credentials, "canonical@example.test")
	}()

	select {
	case err := <-done:
		if !errors.Is(err, ErrBackendAuthPolicy) {
			t.Fatalf("AuthenticateBackend error = %v, want policy rejection", err)
		}
	case <-time.After(100 * time.Millisecond):
		if err := server.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
			t.Fatalf("set read deadline: %v", err)
		}

		buffer := make([]byte, 256)
		n, _ := server.Read(buffer)
		if n > 0 {
			t.Fatalf("AuthenticateBackend wrote %q before policy rejection", string(buffer[:n]))
		}

		t.Fatal("AuthenticateBackend did not return policy rejection")
	}

	if err := server.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}

	buffer := make([]byte, 1)
	n, err := server.Read(buffer)
	if err == nil || n > 0 {
		t.Fatalf("AuthenticateBackend wrote %q before policy rejection", string(buffer[:n]))
	}
}

// writePOP3BackendCapabilities writes a bounded CAPA response for tests.
func writePOP3BackendCapabilities(t *testing.T, writer io.Writer, startTLS bool) {
	t.Helper()

	writePOP3BackendLine(t, writer, "+OK Capability list follows")
	writePOP3BackendLine(t, writer, capabilityUser)
	if startTLS {
		writePOP3BackendLine(t, writer, capabilitySTLS)
	}
	writePOP3BackendLine(t, writer, capabilitySASL+" XOAUTH2 OAUTHBEARER")
	writePOP3BackendLine(t, writer, ".")
}

// writePOP3BackendLine writes one CRLF-terminated POP3 backend line.
func writePOP3BackendLine(t *testing.T, writer io.Writer, line string) {
	t.Helper()

	if _, err := io.WriteString(writer, line+"\r\n"); err != nil {
		t.Fatalf("write backend line: %v", err)
	}
}

// expectPOP3BackendLine reads and compares one CRLF-terminated backend command.
func expectPOP3BackendLine(t *testing.T, reader *bufio.Reader, want string) {
	t.Helper()

	line := readPOP3BackendLine(t, reader)
	if line != want {
		t.Fatalf("backend line mismatch: got %d bytes, want %d bytes", len(line), len(want))
	}
}

// recordAndExpectPOP3BackendLine records a command before comparing it.
func recordAndExpectPOP3BackendLine(t *testing.T, reader *bufio.Reader, commands chan<- string, want string) {
	t.Helper()

	line := readPOP3BackendLine(t, reader)
	commands <- line

	if line != want {
		t.Fatalf("backend line mismatch: got %d bytes, want %d bytes", len(line), len(want))
	}
}

// readPOP3BackendLine reads one command line from the scripted fake backend.
func readPOP3BackendLine(t *testing.T, reader *bufio.Reader) string {
	t.Helper()

	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read backend line: %v", err)
	}

	return strings.TrimRight(line, "\r\n")
}

// assertPOP3HealthCommandIsSafe rejects mailbox-inspecting or mutating health commands.
func assertPOP3HealthCommandIsSafe(t *testing.T, command string) {
	t.Helper()

	name := strings.ToUpper(strings.Fields(command)[0])
	switch name {
	case "STAT", "LIST", "RETR", "DELE", "RSET", "TOP", "UIDL":
		t.Fatalf("health sent mailbox command %q", name)
	}
}

// pop3TCPAddr creates a TCP address fixture for outbound PROXY metadata.
func pop3TCPAddr(ip string, port int) *net.TCPAddr {
	return &net.TCPAddr{IP: net.ParseIP(ip), Port: port}
}

type pop3BackendAddressConn struct {
	net.Conn
	local  net.Addr
	remote net.Addr
}

// LocalAddr returns the configured Director-side backend socket address.
func (c pop3BackendAddressConn) LocalAddr() net.Addr {
	return c.local
}

// RemoteAddr returns the configured backend-side socket address.
func (c pop3BackendAddressConn) RemoteAddr() net.Addr {
	return c.remote
}

// pop3BackendTestTLSConfig creates a server-side TLS config for backend tests.
func pop3BackendTestTLSConfig(certificate tls.Certificate) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
}

// writePOP3BackendTestCertificate writes a localhost server certificate and returns its PEM path.
func writePOP3BackendTestCertificate(t *testing.T) (string, tls.Certificate) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: testPOP3BackendServerName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{testPOP3BackendServerName},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	certPath := writePOP3BackendTempFile(t, "backend-*.crt", certPEM)
	keyPath := writePOP3BackendTempFile(t, "backend-*.key", keyPEM)

	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}

	return certPath, certificate
}

// writePOP3BackendTempFile writes bytes to a temporary file for TLS tests.
func writePOP3BackendTempFile(t *testing.T, pattern string, contents []byte) string {
	t.Helper()

	file, err := os.CreateTemp(t.TempDir(), pattern)
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer func() { _ = file.Close() }()

	if _, err := file.Write(contents); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	return file.Name()
}

type recordingPOP3BackendConnector struct {
	mu           sync.Mutex
	requests     []backend.ConnectRequest
	commands     []string
	err          error
	authResponse string
}

// Connect records backend connect facts and returns a prepared auth-capable stream.
func (c *recordingPOP3BackendConnector) Connect(_ context.Context, request backend.ConnectRequest) (*BackendConnection, error) {
	c.mu.Lock()
	c.requests = append(c.requests, request)
	c.mu.Unlock()

	if c.err != nil {
		return nil, c.err
	}

	client, server := net.Pipe()
	go c.serveAuth(server)

	connection := newBackendConnection(client)
	connection.capabilities = backend.NewCapabilitySet(capabilityUser, capabilitySASL+"=XOAUTH2", capabilitySASL+"=OAUTHBEARER")
	connection.tlsActive = true
	connection.tlsVerified = true

	return connection, nil
}

// serveAuth accepts one POP3 backend auth exchange and records command names safely.
func (c *recordingPOP3BackendConnector) serveAuth(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}

		line = strings.TrimRight(line, "\r\n")
		c.mu.Lock()
		c.commands = append(c.commands, line)
		c.mu.Unlock()

		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "USER "):
			_, _ = io.WriteString(conn, "+OK user accepted\r\n")
		case strings.HasPrefix(upper, "PASS "), strings.HasPrefix(upper, "AUTH "):
			response := c.authResponse
			if response == "" {
				response = "+OK backend auth completed"
			}
			_, _ = io.WriteString(conn, response+"\r\n")

			return
		default:
			_, _ = io.WriteString(conn, "-ERR unsupported\r\n")

			return
		}
	}
}

// singleRequest returns the only recorded backend connect request.
func (c *recordingPOP3BackendConnector) singleRequest(t *testing.T) backend.ConnectRequest {
	t.Helper()

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.requests) != 1 {
		t.Fatalf("backend connect requests = %d, want 1", len(c.requests))
	}

	return c.requests[0]
}

// sawCommandPrefix reports whether the fake backend observed a matching command prefix.
func (c *recordingPOP3BackendConnector) sawCommandPrefix(prefix string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, command := range c.commands {
		if strings.HasPrefix(command, prefix) {
			return true
		}
	}

	return false
}
