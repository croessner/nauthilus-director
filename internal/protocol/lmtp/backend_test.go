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

//nolint:funlen // Scripted protocol tests keep the wire transcript visible.
package lmtp

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
)

const (
	testBackendAddress       = "127.0.0.1:2424"
	testBackendPassword      = "backend-secret"
	testBackendServerName    = "mailstore.example.test"
	testBackendServiceUser   = "director-lmtp"
	testBackendTLSHost       = "localhost"
	testBackendTLSHostTarget = "localhost:2424"
	testBackendToken         = "backend-token"
)

// TestBackendConnectorHandlesPlaintext verifies cleartext LMTP capability discovery.
func TestBackendConnectorHandlesPlaintext(t *testing.T) {
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := bufio.NewReader(conn)
		writeLMTPBackendLine(t, conn, "220 backend ready")
		expectLMTPBackendLine(t, reader, "LHLO "+backendLHLOName)
		writeLMTPBackendLine(t, conn, "250-mailstore")
		writeLMTPBackendLine(t, conn, "250 "+capabilityCHUNKING)
	})

	connection, err := NewTCPBackendConnector(dialer).Connect(context.Background(), testLMTPBackendTarget(backendTLSPlaintext), time.Second)
	if err != nil {
		t.Fatalf("Connect returned error: %v", err)
	}
	defer func() { _ = connection.Conn().Close() }()

	if connection.TLSActive() || connection.TLSVerified() {
		t.Fatalf("TLS state active=%v verified=%v, want plaintext", connection.TLSActive(), connection.TLSVerified())
	}

	if !connection.CapabilitySet().Has(capabilityCHUNKING) {
		t.Fatalf("capabilities = %v, want CHUNKING", connection.Capabilities())
	}

	dialer.Wait(t)
}

// TestBackendConnectorHandlesStartTLS verifies STARTTLS before final LHLO state.
func TestBackendConnectorHandlesStartTLS(t *testing.T) {
	certPath, certificate := writeLMTPBackendTestCertificate(t)
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := bufio.NewReader(conn)
		writeLMTPBackendLine(t, conn, "220 backend ready")
		expectLMTPBackendLine(t, reader, "LHLO "+backendLHLOName)
		writeLMTPBackendLine(t, conn, "250-mailstore")
		writeLMTPBackendLine(t, conn, "250 STARTTLS")
		expectLMTPBackendLine(t, reader, "STARTTLS")
		writeLMTPBackendLine(t, conn, "220 ready for tls")

		tlsConn := tls.Server(conn, lmtpBackendTestTLSConfig(t, certificate))
		if err := tlsConn.Handshake(); err != nil {
			t.Errorf("server handshake: %v", err)
			return
		}

		tlsReader := bufio.NewReader(tlsConn)
		expectLMTPBackendLine(t, tlsReader, "LHLO "+backendLHLOName)
		writeLMTPBackendLine(t, tlsConn, "250-mailstore")
		writeLMTPBackendLine(t, tlsConn, "250-"+capabilityCHUNKING)
		writeLMTPBackendLine(t, tlsConn, "250 AUTH PLAIN")
	})

	connection, err := NewTCPBackendConnector(dialer).Connect(context.Background(), testLMTPBackendTargetWithCA(backendTLSStartTLS, certPath), time.Second)
	if err != nil {
		t.Fatalf("Connect returned error: %v", err)
	}
	defer func() { _ = connection.Conn().Close() }()

	if !connection.TLSActive() || !connection.TLSVerified() {
		t.Fatalf("TLS state active=%v verified=%v", connection.TLSActive(), connection.TLSVerified())
	}

	if !connection.CapabilitySet().Has(capabilityAUTH + "=" + strings.ToUpper(mechanismPlain)) {
		t.Fatalf("capabilities = %v, want AUTH PLAIN", connection.Capabilities())
	}

	dialer.Wait(t)
}

// TestBackendConnectorHandlesImplicitTLS verifies TLS wraps before the greeting.
func TestBackendConnectorHandlesImplicitTLS(t *testing.T) {
	certPath, certificate := writeLMTPBackendTestCertificate(t)
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		tlsConn := tls.Server(conn, lmtpBackendTestTLSConfig(t, certificate))
		if err := tlsConn.Handshake(); err != nil {
			t.Errorf("server handshake: %v", err)
			return
		}

		reader := bufio.NewReader(tlsConn)
		writeLMTPBackendLine(t, tlsConn, "220 backend ready")
		expectLMTPBackendLine(t, reader, "LHLO "+backendLHLOName)
		writeLMTPBackendLine(t, tlsConn, "250-mailstore")
		writeLMTPBackendLine(t, tlsConn, "250 "+capabilityCHUNKING)
	})

	connection, err := NewTCPBackendConnector(dialer).Connect(context.Background(), testLMTPBackendTargetWithCA(backendTLSImplicit, certPath), time.Second)
	if err != nil {
		t.Fatalf("Connect returned error: %v", err)
	}
	defer func() { _ = connection.Conn().Close() }()

	if !connection.TLSActive() || !connection.TLSVerified() {
		t.Fatalf("TLS state active=%v verified=%v", connection.TLSActive(), connection.TLSVerified())
	}

	dialer.Wait(t)
}

// TestBackendTLSRequiresServerNameForIPAddress verifies verified TLS fails closed without SNI.
func TestBackendTLSRequiresServerNameForIPAddress(t *testing.T) {
	target := testLMTPBackendTarget(backendTLSImplicit)
	target.Address = "127.0.0.1:2424"
	target.TLS.ServerName = ""

	_, _, _, err := backendTLSConfig(target)
	if !errors.Is(err, ErrBackendTLS) {
		t.Fatalf("backendTLSConfig error = %v, want TLS server_name rejection", err)
	}

	target.Address = testBackendServerName + ":2424"

	tlsConfig, verified, _, err := backendTLSConfig(target)
	if err != nil {
		t.Fatalf("backendTLSConfig returned error for hostname address: %v", err)
	}

	if tlsConfig.ServerName != testBackendServerName || !verified {
		t.Fatalf("TLS config server name = %q verified=%v", tlsConfig.ServerName, verified)
	}
}

// TestLHLOCapabilitiesAreParsedWithoutBannerText verifies prose does not create CHUNKING proof.
func TestLHLOCapabilitiesAreParsedWithoutBannerText(t *testing.T) {
	response := backendStatusResponse{
		code: responseStatusOK,
		lines: []string{
			"mailstore says CHUNKING is a word in prose",
			"AUTH PLAIN LOGIN",
			capabilityCHUNKING,
		},
	}

	capabilities := lmtpCapabilitiesFromLHLO(response)
	if !capabilities.Has(capabilityCHUNKING) || !capabilities.Has(capabilityAUTH+"=PLAIN") || !capabilities.Has(capabilityAUTH+"=LOGIN") {
		t.Fatalf("capabilities = %v, want CHUNKING and AUTH mechanisms", capabilities.List())
	}

	bannerOnly := lmtpCapabilitiesFromLHLO(backendStatusResponse{
		code:  responseStatusOK,
		lines: []string{"mailstore says CHUNKING"},
	})
	if bannerOnly.Has(capabilityCHUNKING) {
		t.Fatalf("banner-only capabilities = %v, want no CHUNKING", bannerOnly.List())
	}
}

// TestSASLBackendAuthRequiresCredentialsAndVerifiedTLS checks fail-closed SASL policy.
func TestSASLBackendAuthRequiresCredentialsAndVerifiedTLS(t *testing.T) {
	connection := &BackendConnection{capabilities: backend.NewCapabilitySet(capabilityAUTH + "=PLAIN")}
	target := testLMTPBackendTarget(backendTLSPlaintext)
	target.Auth = backend.AuthConfig{
		Mode: backendAuthModeSASL,
		SASL: backend.SASLConfig{
			Mechanism:  mechanismPlain,
			Username:   testBackendServiceUser,
			Password:   config.Secret(testBackendPassword),
			RequireTLS: true,
		},
	}

	if err := AuthenticateBackend(connection, target); !errors.Is(err, ErrBackendAuthPolicy) {
		t.Fatalf("AuthenticateBackend without verified TLS error = %v, want policy", err)
	}

	connection.tlsActive = true
	connection.tlsVerified = true
	target.Auth.SASL.Password = config.Secret("")

	if err := AuthenticateBackend(connection, target); !errors.Is(err, ErrBackendAuthPolicy) {
		t.Fatalf("AuthenticateBackend without credentials error = %v, want policy", err)
	}
}

// TestOAuthBearerBackendAuthRequiresTokenAndVerifiedTLS checks fail-closed bearer policy.
func TestOAuthBearerBackendAuthRequiresTokenAndVerifiedTLS(t *testing.T) {
	connection := &BackendConnection{capabilities: backend.NewCapabilitySet(capabilityAUTH + "=OAUTHBEARER")}
	target := testLMTPBackendTarget(backendTLSPlaintext)
	target.Auth = backend.AuthConfig{
		Mode: backendAuthModeOAuthBearer,
		OAuthBearer: backend.OAuthBearerConfig{
			Token:      config.Secret(testBackendToken),
			RequireTLS: true,
		},
	}

	if err := AuthenticateBackend(connection, target); !errors.Is(err, ErrBackendAuthPolicy) {
		t.Fatalf("AuthenticateBackend without verified TLS error = %v, want policy", err)
	}

	connection.tlsActive = true
	connection.tlsVerified = true
	target.Auth.OAuthBearer.Token = config.Secret("")

	if err := AuthenticateBackend(connection, target); !errors.Is(err, ErrBackendAuthPolicy) {
		t.Fatalf("AuthenticateBackend without token error = %v, want policy", err)
	}
}

// TestBackendMTLSAuthDoesNotSendSASL verifies certificate auth never emits AUTH commands.
func TestBackendMTLSAuthDoesNotSendSASL(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	connection := newBackendConnection(client)
	connection.tlsActive = true
	connection.tlsVerified = true
	connection.clientCertificateConfigured = true

	target := testLMTPBackendTarget(backendTLSImplicit)
	target.Auth.Mode = backendAuthModeMTLS
	target.TLS.Cert = "/configured/client.crt"
	target.TLS.Key = config.Secret("/configured/client.key")

	if err := AuthenticateBackend(connection, target); err != nil {
		t.Fatalf("AuthenticateBackend returned error: %v", err)
	}

	_ = server.SetReadDeadline(time.Now().Add(25 * time.Millisecond))

	line, err := bufio.NewReader(server).ReadString('\n')
	if err == nil {
		t.Fatalf("mtls backend auth wrote unexpected command %q", line)
	}
}

// TestDeepHealthUsesSafeCommandSequence verifies health stops before envelope state.
func TestDeepHealthUsesSafeCommandSequence(t *testing.T) {
	commands := make(chan string, 8)
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := bufio.NewReader(conn)
		writeLMTPBackendLine(t, conn, "220 backend ready")
		recordAndExpectLMTPBackendLine(t, reader, commands, "LHLO "+backendLHLOName)
		writeLMTPBackendLine(t, conn, "250-mailstore")
		writeLMTPBackendLine(t, conn, "250-AUTH PLAIN")
		writeLMTPBackendLine(t, conn, "250 CHUNKING")
		recordAndExpectLMTPBackendLine(t, reader, commands, expectedPlainAuthCommand())
		writeLMTPBackendLine(t, conn, "235 2.7.0 ok")
		recordAndExpectLMTPBackendLine(t, reader, commands, "NOOP")
		writeLMTPBackendLine(t, conn, "250 2.0.0 ok")
		recordAndExpectLMTPBackendLine(t, reader, commands, "RSET")
		writeLMTPBackendLine(t, conn, "250 2.0.0 ok")
		recordAndExpectLMTPBackendLine(t, reader, commands, "QUIT")
		writeLMTPBackendLine(t, conn, "221 2.0.0 bye")
	})

	target := testLMTPBackendTarget(backendTLSPlaintext)
	target.Auth = backend.AuthConfig{
		Mode: backendAuthModeSASL,
		SASL: backend.SASLConfig{
			Mechanism: mechanismPlain,
			Username:  testBackendServiceUser,
			Password:  config.Secret(testBackendPassword),
		},
	}

	result := NewHealthChecker(NewTCPBackendConnector(dialer)).CheckBackend(context.Background(), target, backend.HealthCheckRequest{
		Deep:    true,
		Timeout: time.Second,
	})
	if !result.Healthy || !result.Capabilities.Has(capabilityCHUNKING) {
		t.Fatalf("health result = %#v, want healthy with CHUNKING", result)
	}

	dialer.Wait(t)
	close(commands)

	for command := range commands {
		upper := strings.ToUpper(command)
		for _, forbidden := range []string{"MAIL FROM", "RCPT TO", "DATA", "BDAT"} {
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
		backendHealthReason(errors.New(testBackendPassword)),
	} {
		switch reason {
		case healthReasonConnect, healthReasonTLS, healthReasonProtocol, healthReasonAuth, healthReasonTimeout, healthReasonUnknown:
		default:
			t.Fatalf("reason class %q is not bounded", reason)
		}

		if strings.Contains(reason, testBackendPassword) {
			t.Fatalf("reason class leaked secret: %q", reason)
		}
	}
}

// scriptedLMTPBackendDialer creates a dialer backed by net.Pipe and one scripted server.
func scriptedLMTPBackendDialer(t *testing.T, script func(*testing.T, net.Conn)) *lmtpBackendScriptedDialer {
	t.Helper()

	return &lmtpBackendScriptedDialer{t: t, script: script, done: make(chan struct{})}
}

type lmtpBackendScriptedDialer struct {
	t      *testing.T
	script func(*testing.T, net.Conn)
	done   chan struct{}
}

// DialContext returns one side of a net.Pipe and runs the fake backend on the other.
func (d *lmtpBackendScriptedDialer) DialContext(_ context.Context, _ string, _ string) (net.Conn, error) {
	client, server := net.Pipe()

	go func() {
		defer close(d.done)
		defer func() { _ = server.Close() }()

		d.script(d.t, server)
	}()

	return client, nil
}

// Wait asserts that the fake backend script finished.
func (d *lmtpBackendScriptedDialer) Wait(t *testing.T) {
	t.Helper()

	select {
	case <-d.done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for scripted backend")
	}
}

// testLMTPBackendTarget returns a minimal backend target for connector tests.
func testLMTPBackendTarget(mode string) backend.Backend {
	return backend.Backend{
		Protocol: protocolLMTP,
		Address:  testBackendTLSHostTarget,
		TLS: backend.TLSConfig{
			Mode:          mode,
			ServerName:    testBackendTLSHost,
			MinTLSVersion: backendTLSMinDefault,
		},
		Auth: backend.AuthConfig{Mode: backendAuthModeNone},
	}
}

// testLMTPBackendTargetWithCA returns a backend target using the generated test CA.
func testLMTPBackendTargetWithCA(mode string, caFile string) backend.Backend {
	target := testLMTPBackendTarget(mode)
	target.TLS.CAFile = caFile

	return target
}

// lmtpBackendTestTLSConfig creates a server-side TLS config for backend tests.
func lmtpBackendTestTLSConfig(t *testing.T, certificate tls.Certificate) *tls.Config {
	t.Helper()

	return &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
}

// writeLMTPBackendTestCertificate writes a localhost server certificate and returns its PEM path.
func writeLMTPBackendTestCertificate(t *testing.T) (string, tls.Certificate) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: testBackendTLSHost},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{testBackendTLSHost},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	certPath := writeLMTPBackendTempFile(t, "backend-*.crt", certPEM)
	keyPath := writeLMTPBackendTempFile(t, "backend-*.key", keyPEM)

	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}

	return certPath, certificate
}

// writeLMTPBackendTempFile writes bytes to a temporary file for TLS tests.
func writeLMTPBackendTempFile(t *testing.T, pattern string, contents []byte) string {
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

// writeLMTPBackendLine writes one CRLF-terminated LMTP backend line.
func writeLMTPBackendLine(t *testing.T, writer io.Writer, line string) {
	t.Helper()

	if _, err := io.WriteString(writer, line+"\r\n"); err != nil {
		t.Fatalf("write backend line %q: %v", line, err)
	}
}

// expectLMTPBackendLine reads and compares one CRLF-terminated backend command.
func expectLMTPBackendLine(t *testing.T, reader *bufio.Reader, want string) {
	t.Helper()

	line := readLMTPBackendLine(t, reader)
	if line != want {
		t.Fatalf("backend line = %q, want %q", line, want)
	}
}

// recordAndExpectLMTPBackendLine records a command before comparing it.
func recordAndExpectLMTPBackendLine(t *testing.T, reader *bufio.Reader, commands chan<- string, want string) {
	t.Helper()

	line := readLMTPBackendLine(t, reader)
	commands <- line

	if line != want {
		t.Fatalf("backend line = %q, want %q", line, want)
	}
}

// readLMTPBackendLine reads one command line from the scripted fake backend.
func readLMTPBackendLine(t *testing.T, reader *bufio.Reader) string {
	t.Helper()

	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read backend line: %v", err)
	}

	return strings.TrimRight(line, "\r\n")
}

// expectedPlainAuthCommand returns the service-credential AUTH PLAIN command.
func expectedPlainAuthCommand() string {
	payload := "\x00" + testBackendServiceUser + "\x00" + testBackendPassword

	return "AUTH PLAIN " + base64.StdEncoding.EncodeToString([]byte(payload))
}
