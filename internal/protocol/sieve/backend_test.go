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

//nolint:funlen,goconst,wsl_v5 // Scripted backend tests keep wire order visible.
package sieve

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
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/protocol/saslcred"
)

const (
	testSieveBackendAddress       = "localhost:4190"
	testSieveBackendHealthPass    = "health-secret"
	testSieveBackendHealthProxyV4 = "PROXY TCP4 10.10.0.1 10.10.0.2 50190 4190"
	testSieveBackendHealthUser    = "healthcheck@example.test"
	testSieveBackendMasterPass    = "master-secret"
	testSieveBackendMasterUser    = "director-master"
	testSieveBackendProxyV4       = "PROXY TCP4 203.0.113.10 198.51.100.20 42500 4190"
	testSieveBackendServerName    = "localhost"
	testSieveFrontendPassword     = "frontend-secret"
)

// TestBackendConnectorHandlesPlaintext verifies cleartext capability discovery.
func TestBackendConnectorHandlesPlaintext(t *testing.T) {
	dialer := scriptedSieveBackendDialer(t, func(_ *testing.T, conn net.Conn) {
		reader := bufio.NewReader(conn)
		writeSieveBackendGreeting(t, conn, false)
		expectSieveBackendLine(t, reader, commandCapability)
		writeSieveBackendCapabilities(t, conn)
	})

	connection, err := NewTCPBackendConnector(dialer).Connect(
		context.Background(),
		testSieveBackendConnectRequest(testSieveBackendTarget(backendTLSPlaintext)),
	)
	if err != nil {
		t.Fatalf("Connect returned error: %v", err)
	}
	defer func() { _ = connection.Conn().Close() }()

	if connection.TLSActive() || connection.TLSVerified() {
		t.Fatalf("TLS state active=%v verified=%v, want plaintext", connection.TLSActive(), connection.TLSVerified())
	}

	if !connection.CapabilitySet().Has("SASL=PLAIN") {
		t.Fatalf("capabilities = %v, want SASL=PLAIN", connection.Capabilities())
	}

	dialer.Wait(t)
}

// TestBackendConnectorWritesProxyBeforePlaintextGreeting verifies PROXY precedes greeting reads.
func TestBackendConnectorWritesProxyBeforePlaintextGreeting(t *testing.T) {
	dialer := scriptedSieveBackendDialer(t, func(_ *testing.T, conn net.Conn) {
		reader := bufio.NewReader(conn)
		expectSieveBackendLine(t, reader, testSieveBackendProxyV4)
		writeSieveBackendGreeting(t, conn, false)
		expectSieveBackendLine(t, reader, commandCapability)
		writeSieveBackendCapabilities(t, conn)
	})

	connection, err := NewTCPBackendConnector(dialer).Connect(
		context.Background(),
		testProxySieveBackendConnectRequest(testSieveBackendTarget(backendTLSPlaintext)),
	)
	if err != nil {
		t.Fatalf("Connect returned error: %v", err)
	}
	defer func() { _ = connection.Conn().Close() }()

	dialer.Wait(t)
}

// TestBackendConnectorHandlesStartTLS verifies STARTTLS upgrades before final capabilities.
func TestBackendConnectorHandlesStartTLS(t *testing.T) {
	certPath, certificate := writeSieveBackendTestCertificate(t)
	dialer := scriptedSieveBackendDialer(t, func(_ *testing.T, conn net.Conn) {
		reader := bufio.NewReader(conn)
		writeSieveBackendGreeting(t, conn, true)
		expectSieveBackendLine(t, reader, commandStartTLS)
		writeSieveBackendLine(t, conn, "OK \"begin tls\"")

		tlsConn := tls.Server(conn, sieveBackendTestTLSConfig(certificate))
		if err := tlsConn.Handshake(); err != nil {
			t.Errorf("server handshake: %v", err)
			return
		}

		tlsReader := bufio.NewReader(tlsConn)
		expectSieveBackendLine(t, tlsReader, commandCapability)
		writeSieveBackendCapabilities(t, tlsConn)
	})

	connection, err := NewTCPBackendConnector(dialer).Connect(
		context.Background(),
		testSieveBackendConnectRequest(testSieveBackendTargetWithCA(backendTLSStartTLS, certPath)),
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

// TestBackendStartTLSRequiresAdvertisement verifies STARTTLS fails closed without capability proof.
func TestBackendStartTLSRequiresAdvertisement(t *testing.T) {
	dialer := scriptedSieveBackendDialer(t, func(t *testing.T, conn net.Conn) {
		writeSieveBackendGreeting(t, conn, false)
	})

	_, err := NewTCPBackendConnector(dialer).Connect(
		context.Background(),
		testSieveBackendConnectRequest(testSieveBackendTarget(backendTLSStartTLS)),
	)
	if !errors.Is(err, ErrBackendTLS) {
		t.Fatalf("Connect error = %v, want backend TLS rejection", err)
	}

	dialer.Wait(t)
}

// TestBackendConnectorHandlesImplicitTLS verifies TLS wraps before backend greeting.
func TestBackendConnectorHandlesImplicitTLS(t *testing.T) {
	certPath, certificate := writeSieveBackendTestCertificate(t)
	dialer := scriptedSieveBackendDialer(t, func(t *testing.T, conn net.Conn) {
		tlsConn := tls.Server(conn, sieveBackendTestTLSConfig(certificate))
		if err := tlsConn.Handshake(); err != nil {
			t.Errorf("server handshake: %v", err)
			return
		}

		reader := bufio.NewReader(tlsConn)
		writeSieveBackendGreeting(t, tlsConn, false)
		expectSieveBackendLine(t, reader, commandCapability)
		writeSieveBackendCapabilities(t, tlsConn)
	})

	connection, err := NewTCPBackendConnector(dialer).Connect(
		context.Background(),
		testSieveBackendConnectRequest(testSieveBackendTargetWithCA(backendTLSImplicit, certPath)),
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
	_, certificate := writeSieveBackendTestCertificate(t)
	dialer := scriptedSieveBackendDialer(t, func(_ *testing.T, conn net.Conn) {
		tlsConn := tls.Server(conn, sieveBackendTestTLSConfig(certificate))
		_ = tlsConn.Handshake()
	})

	_, err := NewTCPBackendConnector(dialer).Connect(
		context.Background(),
		testSieveBackendConnectRequest(testSieveBackendTarget(backendTLSImplicit)),
	)
	if !errors.Is(err, ErrBackendTLS) {
		t.Fatalf("Connect error = %v, want verification failure", err)
	}

	dialer.Wait(t)
}

// TestMasterUserAuthCommandGeneration verifies configured user formatting and safe failures.
func TestMasterUserAuthCommandGeneration(t *testing.T) {
	credentials := sievePlainCredentialsForBackendTest(t)
	defer credentials.Clear()

	command, err := masterUserAuthCommand(testSieveMasterUserConfig(), backend.NewCapabilitySet("SASL=PLAIN"), credentials)
	if err != nil {
		t.Fatalf("masterUserAuthCommand returned error: %v", err)
	}

	payload := decodeSieveInitialResponse(t, command, mechanismPlain)
	if payload != "\x00alice@example.test*director-master\x00master-secret" {
		t.Fatalf("PLAIN payload mismatch: got %d bytes, want formatted master-user payload", len(payload))
	}

	_, err = masterUserAuthCommand(testSieveMasterUserConfig(), backend.NewCapabilitySet("SASL=XOAUTH2"), credentials)
	if !errors.Is(err, ErrBackendAuthPolicy) {
		t.Fatalf("masterUserAuthCommand error = %v, want policy rejection", err)
	}
	if strings.Contains(err.Error(), testSieveBackendMasterPass) || strings.Contains(err.Error(), "alice@example.test") {
		t.Fatal("policy error leaked sensitive material")
	}
}

// TestCredentialReplayPolicy verifies allowlists and verified TLS enforcement.
func TestCredentialReplayPolicy(t *testing.T) {
	credentials := sievePlainCredentialsForBackendTest(t)
	defer credentials.Clear()

	connection := &BackendConnection{
		capabilities: backend.NewCapabilitySet("SASL=PLAIN"),
		tlsActive:    true,
		tlsVerified:  false,
	}
	replay := backend.CredentialReplayConfig{
		RequireBackendTLS: true,
		AllowedMechanisms: []string{mechanismPlain},
	}

	_, err := credentialReplayCommand(replay, connection, credentials)
	if !errors.Is(err, ErrBackendAuthPolicy) {
		t.Fatalf("credentialReplayCommand error = %v, want TLS policy rejection", err)
	}

	connection.tlsVerified = true
	command, err := credentialReplayCommand(replay, connection, credentials)
	if err != nil {
		t.Fatalf("credentialReplayCommand returned error: %v", err)
	}

	payload := decodeSieveInitialResponse(t, command, mechanismPlain)
	if payload != "\x00alice@example.test\x00"+testSieveFrontendPassword {
		t.Fatalf("replay payload mismatch: got %d bytes, want frontend credential replay", len(payload))
	}

	replay.AllowedMechanisms = []string{mechanismXOAUTH2}
	_, err = credentialReplayCommand(replay, connection, credentials)
	if !errors.Is(err, ErrBackendAuthPolicy) {
		t.Fatalf("credentialReplayCommand allowlist error = %v, want policy rejection", err)
	}
}

// TestLightHealthWritesProxyBeforeGreeting verifies health uses the backend socket tuple.
func TestLightHealthWritesProxyBeforeGreeting(t *testing.T) {
	dialer := scriptedSieveBackendDialerWithAddrs(
		t,
		sieveTCPAddr("10.10.0.1", 50190),
		sieveTCPAddr("10.10.0.2", 4190),
		func(t *testing.T, conn net.Conn) {
			reader := bufio.NewReader(conn)
			expectSieveBackendLine(t, reader, testSieveBackendHealthProxyV4)
			writeSieveBackendGreeting(t, conn, false)
			expectSieveBackendLine(t, reader, commandCapability)
			writeSieveBackendCapabilities(t, conn)
			expectSieveBackendLine(t, reader, commandLogout)
			writeSieveBackendLine(t, conn, "OK \"bye\"")
		},
	)
	target := testSieveBackendTarget(backendTLSPlaintext)
	target.HAProxy.Enabled = true

	result := NewHealthChecker(NewTCPBackendConnector(dialer)).CheckBackend(context.Background(), target, backend.HealthCheckRequest{
		Timeout: time.Second,
	})
	if !result.Healthy || !result.Capabilities.Has("SASL=PLAIN") {
		t.Fatalf("health result = %#v, want healthy with capabilities", result)
	}

	dialer.Wait(t)
}

// TestDeepHealthUsesSafeCommandSequence verifies health avoids script-management commands.
func TestDeepHealthUsesSafeCommandSequence(t *testing.T) {
	commands := make(chan string, 8)
	dialer := scriptedSieveBackendDialerWithAddrs(
		t,
		sieveTCPAddr("10.10.0.1", 50190),
		sieveTCPAddr("10.10.0.2", 4190),
		func(t *testing.T, conn net.Conn) {
			reader := bufio.NewReader(conn)
			expectSieveBackendLine(t, reader, testSieveBackendHealthProxyV4)
			writeSieveBackendGreeting(t, conn, false)
			recordAndExpectSieveBackendLine(t, reader, commands, commandCapability)
			writeSieveBackendCapabilities(t, conn)
			recordAndExpectSieveBackendLine(t, reader, commands, expectedSieveHealthAuthCommand())
			writeSieveBackendLine(t, conn, "OK \"health auth\"")
			recordAndExpectSieveBackendLine(t, reader, commands, commandNoop)
			writeSieveBackendLine(t, conn, "OK \"noop\"")
			recordAndExpectSieveBackendLine(t, reader, commands, commandLogout)
			writeSieveBackendLine(t, conn, "OK \"bye\"")
		},
	)

	target := testSieveBackendTarget(backendTLSPlaintext)
	target.HAProxy.Enabled = true
	target.Health = backend.HealthConfig{
		Username: testSieveBackendHealthUser,
		Password: config.Secret(testSieveBackendHealthPass),
	}

	result := NewHealthChecker(NewTCPBackendConnector(dialer)).CheckBackend(context.Background(), target, backend.HealthCheckRequest{
		Deep:    true,
		Timeout: time.Second,
	})
	if !result.Healthy || !result.Capabilities.Has("SASL=PLAIN") {
		t.Fatalf("health result = %#v, want healthy with capabilities", result)
	}

	dialer.Wait(t)
	close(commands)

	for command := range commands {
		upper := strings.ToUpper(command)
		for _, forbidden := range []string{"HAVESPACE", "PUTSCRIPT", "SETACTIVE", "CHECKSCRIPT", "GETSCRIPT", "LISTSCRIPTS"} {
			if strings.HasPrefix(upper, forbidden) {
				t.Fatalf("deep health sent forbidden command %q", command)
			}
		}
	}
}

// TestBackendHealthReasonClassesAreBounded verifies secret-safe classification.
func TestBackendHealthReasonClassesAreBounded(t *testing.T) {
	for _, reason := range []string{
		backendHealthReason(ErrBackendConnect),
		backendHealthReason(ErrBackendTLS),
		backendHealthReason(ErrBackendProtocol),
		backendHealthReason(ErrBackendAuth),
		backendHealthReason(context.DeadlineExceeded),
		backendHealthReason(&backend.TransportError{Reason: backend.TransportReasonWriteFailed, Purpose: backend.ConnectPurposeHealth}),
		backendHealthReason(&backend.TransportError{Reason: backend.TransportReasonMissingAddress, Purpose: backend.ConnectPurposeHealth}),
		backendHealthReason(&backend.TransportError{Reason: backend.TransportReasonUnsupportedFamily, Purpose: backend.ConnectPurposeHealth}),
		backendHealthReason(errors.New(testSieveBackendHealthPass)),
	} {
		switch reason {
		case healthReasonConnect, healthReasonTLS, healthReasonProtocol, healthReasonAuth, healthReasonProxyConfig,
			healthReasonProxyMissingAddress, healthReasonProxyUnsupportedFamily, healthReasonProxyWrite,
			healthReasonTimeout, healthReasonUnknown:
		default:
			t.Fatalf("reason class %q is not bounded", reason)
		}

		if strings.Contains(reason, testSieveBackendHealthPass) {
			t.Fatalf("reason class leaked secret: %q", reason)
		}
	}
}

// scriptedSieveBackendDialer creates a dialer backed by net.Pipe and one script.
func scriptedSieveBackendDialer(t *testing.T, script func(*testing.T, net.Conn)) *sieveBackendScriptedDialer {
	t.Helper()

	return &sieveBackendScriptedDialer{t: t, script: script, done: make(chan struct{})}
}

// scriptedSieveBackendDialerWithAddrs creates a dialer with fixed socket addresses.
func scriptedSieveBackendDialerWithAddrs(
	t *testing.T,
	local net.Addr,
	remote net.Addr,
	script func(*testing.T, net.Conn),
) *sieveBackendScriptedDialer {
	t.Helper()

	return &sieveBackendScriptedDialer{
		t:      t,
		local:  local,
		remote: remote,
		script: script,
		done:   make(chan struct{}),
	}
}

type sieveBackendScriptedDialer struct {
	t      *testing.T
	local  net.Addr
	remote net.Addr
	script func(*testing.T, net.Conn)
	done   chan struct{}
}

// DialContext returns one side of a net.Pipe and runs the fake backend on the other.
func (d *sieveBackendScriptedDialer) DialContext(_ context.Context, _ string, _ string) (net.Conn, error) {
	client, server := net.Pipe()
	clientConn := client

	if d.local != nil || d.remote != nil {
		clientConn = sieveBackendAddressConn{Conn: client, local: d.local, remote: d.remote}
	}

	go func() {
		defer close(d.done)
		defer func() { _ = server.Close() }()

		d.script(d.t, server)
	}()

	return clientConn, nil
}

// Wait asserts that the fake backend script finished.
func (d *sieveBackendScriptedDialer) Wait(t *testing.T) {
	t.Helper()

	select {
	case <-d.done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for scripted backend")
	}
}

// testSieveBackendConnectRequest creates a disabled-PROXY request with stable metadata.
func testSieveBackendConnectRequest(target backend.Backend) backend.ConnectRequest {
	return backend.ConnectRequest{
		Target:  target,
		Timeout: time.Second,
		Purpose: backend.ConnectPurposeSession,
		ProxyAddresses: &backend.ProxyAddresses{
			Source:      sieveTCPAddr("203.0.113.10", 42500),
			Destination: sieveTCPAddr("198.51.100.20", 4190),
		},
	}
}

// testProxySieveBackendConnectRequest enables outbound PROXY for connector tests.
func testProxySieveBackendConnectRequest(target backend.Backend) backend.ConnectRequest {
	request := testSieveBackendConnectRequest(target)
	request.Target.HAProxy.Enabled = true

	return request
}

// testSieveBackendTarget returns a minimal backend target for connector tests.
func testSieveBackendTarget(mode string) backend.Backend {
	return backend.Backend{
		Protocol: backendProtocol,
		Address:  testSieveBackendAddress,
		TLS: backend.TLSConfig{
			Mode:          mode,
			ServerName:    testSieveBackendServerName,
			MinTLSVersion: backendTLSMinDefault,
		},
	}
}

// testSieveBackendTargetWithCA returns a backend target using the generated test CA.
func testSieveBackendTargetWithCA(mode string, caFile string) backend.Backend {
	target := testSieveBackendTarget(mode)
	target.TLS.CAFile = caFile

	return target
}

// testSieveMasterUserConfig returns an explicit master-user fixture.
func testSieveMasterUserConfig() backend.MasterUserConfig {
	return backend.MasterUserConfig{
		Username:   testSieveBackendMasterUser,
		Password:   config.Secret(testSieveBackendMasterPass),
		UserFormat: "{user}*{master_user}",
		Mechanism:  mechanismPlain,
	}
}

// sievePlainCredentialsForBackendTest creates PLAIN credentials for backend auth tests.
func sievePlainCredentialsForBackendTest(t *testing.T) *frontendCredentials {
	t.Helper()

	mechanism, err := saslcred.NewMechanism("PLAIN")
	if err != nil {
		t.Fatalf("new mechanism: %v", err)
	}

	credentials, err := parseSASLCredentials(mechanism, plainPayload("alice@example.test", testSieveFrontendPassword), 256, 64)
	if err != nil {
		t.Fatalf("parse PLAIN credentials: %v", err)
	}

	return credentials
}

// decodeSieveInitialResponse decodes the initial response from a backend auth command.
func decodeSieveInitialResponse(t *testing.T, command string, mechanism string) string {
	t.Helper()

	tokens, err := tokenizeArguments(command, backendLineLimitBytes)
	if err != nil {
		t.Fatalf("tokenize backend auth command: %v", err)
	}

	if len(tokens) != 3 {
		t.Fatalf("auth command tokens = %d, want 3", len(tokens))
	}

	gotMechanism, _ := tokenStringValue(tokens[1])
	if !strings.EqualFold(gotMechanism, mechanism) {
		t.Fatalf("auth mechanism = %q, want %q", gotMechanism, mechanism)
	}

	encoded, _ := tokenStringValue(tokens[2])
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode initial response: %v", err)
	}

	return string(raw)
}

// writeSieveBackendGreeting writes one RFC 5804-shaped backend greeting.
func writeSieveBackendGreeting(t *testing.T, writer io.Writer, startTLS bool) {
	t.Helper()

	writeSieveBackendLine(t, writer, "\"IMPLEMENTATION\" \"backend\"")
	writeSieveBackendLine(t, writer, "\"SASL\" \"PLAIN XOAUTH2 OAUTHBEARER\"")
	if startTLS {
		writeSieveBackendLine(t, writer, "\"STARTTLS\"")
	}
	writeSieveBackendLine(t, writer, "OK \"ready\"")
}

// writeSieveBackendCapabilities writes safe backend capability proof.
func writeSieveBackendCapabilities(t *testing.T, writer io.Writer) {
	t.Helper()

	writeSieveBackendLine(t, writer, "\"IMPLEMENTATION\" \"backend\"")
	writeSieveBackendLine(t, writer, "\"SASL\" \"PLAIN XOAUTH2 OAUTHBEARER\"")
	writeSieveBackendLine(t, writer, "\"SIEVE\" \"fileinto reject\"")
	writeSieveBackendLine(t, writer, "OK \"capability completed\"")
}

// writeSieveBackendLine writes one CRLF-terminated ManageSieve backend line.
func writeSieveBackendLine(t *testing.T, writer io.Writer, line string) {
	t.Helper()

	if _, err := io.WriteString(writer, line+"\r\n"); err != nil {
		t.Fatalf("write backend line: %v", err)
	}
}

// expectSieveBackendLine reads and compares one CRLF-terminated backend command.
func expectSieveBackendLine(t *testing.T, reader *bufio.Reader, want string) {
	t.Helper()

	line := readSieveBackendLine(t, reader)
	if line != want {
		t.Fatalf("backend line mismatch: got %d bytes, want %d bytes", len(line), len(want))
	}
}

// recordAndExpectSieveBackendLine records a command before comparing it.
func recordAndExpectSieveBackendLine(t *testing.T, reader *bufio.Reader, commands chan<- string, want string) {
	t.Helper()

	line := readSieveBackendLine(t, reader)
	commands <- line

	if line != want {
		t.Fatalf("backend line mismatch: got %d bytes, want %d bytes", len(line), len(want))
	}
}

// readSieveBackendLine reads one command line from the scripted fake backend.
func readSieveBackendLine(t *testing.T, reader *bufio.Reader) string {
	t.Helper()

	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read backend line: %v", err)
	}

	return strings.TrimRight(line, "\r\n")
}

// expectedSieveHealthAuthCommand returns the deep-health AUTHENTICATE command.
func expectedSieveHealthAuthCommand() string {
	return authenticateCommand(mechanismPlain, backendPlainPayload("", testSieveBackendHealthUser, testSieveBackendHealthPass))
}

// sieveTCPAddr creates a TCP address fixture for outbound PROXY metadata.
func sieveTCPAddr(ip string, port int) *net.TCPAddr {
	return &net.TCPAddr{IP: net.ParseIP(ip), Port: port}
}

type sieveBackendAddressConn struct {
	net.Conn
	local  net.Addr
	remote net.Addr
}

// LocalAddr returns the configured Director-side backend socket address.
func (c sieveBackendAddressConn) LocalAddr() net.Addr {
	return c.local
}

// RemoteAddr returns the configured backend-side socket address.
func (c sieveBackendAddressConn) RemoteAddr() net.Addr {
	return c.remote
}

// sieveBackendTestTLSConfig creates a server-side TLS config for backend tests.
func sieveBackendTestTLSConfig(certificate tls.Certificate) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
}

// writeSieveBackendTestCertificate writes a localhost server certificate and returns its PEM path.
func writeSieveBackendTestCertificate(t *testing.T) (string, tls.Certificate) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: testSieveBackendServerName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{testSieveBackendServerName},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	certPath := writeSieveBackendTempFile(t, "backend-*.crt", certPEM)
	keyPath := writeSieveBackendTempFile(t, "backend-*.key", keyPEM)

	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}

	return certPath, certificate
}

// writeSieveBackendTempFile writes bytes to a temporary file for TLS tests.
func writeSieveBackendTempFile(t *testing.T, pattern string, contents []byte) string {
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
