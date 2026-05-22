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

//nolint:funlen // TLS test fixtures stay local so transport behavior is visible.
package imap

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
)

const (
	testBackendAddress       = "127.0.0.1:1143"
	testBackendServerName    = "mailstore.example.test"
	testBackendTLSHost       = "localhost"
	testBackendTLSHostTarget = "localhost:1143"
)

// TestBackendTargetValidationIsTCPOnly rejects Unix sockets and malformed backend addresses.
func TestBackendTargetValidationIsTCPOnly(t *testing.T) {
	valid := backend.Backend{Protocol: backendProtocol, Address: testBackendAddress}
	if err := validateBackendTarget(valid); err != nil {
		t.Fatalf("validateBackendTarget returned error for TCP address: %v", err)
	}

	for _, address := range []string{"/run/imap.sock", "unix:/run/imap.sock", "127.0.0.1"} {
		t.Run(address, func(t *testing.T) {
			err := validateBackendTarget(backend.Backend{Protocol: backendProtocol, Address: address})
			if !errors.Is(err, ErrBackendConnect) {
				t.Fatalf("validateBackendTarget error = %v, want backend connect error", err)
			}
		})
	}
}

// TestBackendTLSRequiresSNIForIPAddress verifies verified TLS fails closed without server_name.
func TestBackendTLSRequiresSNIForIPAddress(t *testing.T) {
	target := testBackendTarget(backendTLSImplicit)
	target.Address = "127.0.0.1:993"
	target.TLS.ServerName = ""

	_, _, err := backendTLSConfig(target)
	if !errors.Is(err, ErrBackendTLS) {
		t.Fatalf("backendTLSConfig error = %v, want TLS server_name rejection", err)
	}

	target.Address = testBackendServerName + ":993"

	tlsConfig, verified, err := backendTLSConfig(target)
	if err != nil {
		t.Fatalf("backendTLSConfig returned error for hostname address: %v", err)
	}

	if tlsConfig.ServerName != testBackendServerName || !verified {
		t.Fatalf("TLS config server name = %q verified=%v", tlsConfig.ServerName, verified)
	}
}

// TestBackendConnectorNegotiatesStartTLS verifies STARTTLS upgrades before capability discovery.
func TestBackendConnectorNegotiatesStartTLS(t *testing.T) {
	certPath, certificate := writeBackendTestCertificate(t)
	dialer := scriptedBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := bufio.NewReader(conn)
		writeBackendLine(t, conn, "* OK ready")
		expectBackendLine(t, reader, "D0001 STARTTLS")
		writeBackendLine(t, conn, "D0001 OK begin TLS")

		tlsConn := tls.Server(conn, backendTestTLSConfig(t, certificate))
		if err := tlsConn.Handshake(); err != nil {
			t.Errorf("server handshake: %v", err)
			return
		}

		tlsReader := bufio.NewReader(tlsConn)
		expectBackendLine(t, tlsReader, "D0002 CAPABILITY")
		writeBackendLine(t, tlsConn, "* CAPABILITY IMAP4rev1 AUTH=PLAIN")
		writeBackendLine(t, tlsConn, "D0002 OK capability completed")
	})

	connection, err := NewTCPBackendConnector(dialer).Connect(context.Background(), testBackendTargetWithCA(backendTLSStartTLS, certPath), time.Second)
	if err != nil {
		t.Fatalf("Connect returned error: %v", err)
	}
	defer func() { _ = connection.Conn().Close() }()

	if !connection.TLSActive() || !connection.TLSVerified() {
		t.Fatalf("TLS state active=%v verified=%v", connection.TLSActive(), connection.TLSVerified())
	}

	if !connection.capabilities.SupportsMechanism(mechanismPlain) {
		t.Fatalf("capabilities = %v, want AUTH=PLAIN", connection.Capabilities())
	}

	dialer.Wait(t)
}

// TestBackendConnectorNegotiatesImplicitTLS verifies TLS wraps the stream before the IMAP greeting.
func TestBackendConnectorNegotiatesImplicitTLS(t *testing.T) {
	certPath, certificate := writeBackendTestCertificate(t)
	dialer := scriptedBackendDialer(t, func(t *testing.T, conn net.Conn) {
		tlsConn := tls.Server(conn, backendTestTLSConfig(t, certificate))
		if err := tlsConn.Handshake(); err != nil {
			t.Errorf("server handshake: %v", err)
			return
		}

		reader := bufio.NewReader(tlsConn)
		writeBackendLine(t, tlsConn, "* OK ready")
		expectBackendLine(t, reader, "D0001 CAPABILITY")
		writeBackendLine(t, tlsConn, "* CAPABILITY IMAP4rev1 AUTH=PLAIN")
		writeBackendLine(t, tlsConn, "D0001 OK capability completed")
	})

	connection, err := NewTCPBackendConnector(dialer).Connect(context.Background(), testBackendTargetWithCA(backendTLSImplicit, certPath), time.Second)
	if err != nil {
		t.Fatalf("Connect returned error: %v", err)
	}
	defer func() { _ = connection.Conn().Close() }()

	if !connection.TLSActive() || !connection.TLSVerified() {
		t.Fatalf("TLS state active=%v verified=%v", connection.TLSActive(), connection.TLSVerified())
	}

	dialer.Wait(t)
}

// scriptedBackendDialer creates a dialer backed by net.Pipe and one scripted server.
func scriptedBackendDialer(t *testing.T, script func(*testing.T, net.Conn)) *backendScriptedDialer {
	t.Helper()

	return &backendScriptedDialer{t: t, script: script, done: make(chan struct{})}
}

// backendScriptedDialer runs a fake backend script for each dial.
type backendScriptedDialer struct {
	t      *testing.T
	script func(*testing.T, net.Conn)
	done   chan struct{}
}

// DialContext returns one side of a net.Pipe and runs the fake backend on the other.
func (d *backendScriptedDialer) DialContext(_ context.Context, _ string, _ string) (net.Conn, error) {
	client, server := net.Pipe()

	go func() {
		defer close(d.done)
		defer func() { _ = server.Close() }()

		d.script(d.t, server)
	}()

	return client, nil
}

// Wait asserts that the fake backend script finished.
func (d *backendScriptedDialer) Wait(t *testing.T) {
	t.Helper()

	select {
	case <-d.done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for scripted backend")
	}
}

// testBackendTarget returns a minimal backend target for connector tests.
func testBackendTarget(mode string) backend.Backend {
	return backend.Backend{
		Protocol: backendProtocol,
		Address:  testBackendTLSHostTarget,
		TLS: backend.TLSConfig{
			Mode:          mode,
			ServerName:    testBackendTLSHost,
			MinTLSVersion: backendTLSMinDefault,
		},
	}
}

// testBackendTargetWithCA returns a backend target using the generated test CA.
func testBackendTargetWithCA(mode string, caFile string) backend.Backend {
	target := testBackendTarget(mode)
	target.TLS.CAFile = caFile

	return target
}

// backendTestTLSConfig creates a server-side TLS config for backend tests.
func backendTestTLSConfig(t *testing.T, certificate tls.Certificate) *tls.Config {
	t.Helper()

	return &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
}

// writeBackendTestCertificate writes a localhost server certificate and returns its PEM path.
func writeBackendTestCertificate(t *testing.T) (string, tls.Certificate) {
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

	certPath := writeBackendTempFile(t, "backend-*.crt", certPEM)
	keyPath := writeBackendTempFile(t, "backend-*.key", keyPEM)

	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}

	return certPath, certificate
}

// writeBackendTempFile writes bytes to a temporary file for TLS tests.
func writeBackendTempFile(t *testing.T, pattern string, contents []byte) string {
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

// writeBackendLine writes one CRLF-terminated IMAP backend line.
func writeBackendLine(t *testing.T, writer io.Writer, line string) {
	t.Helper()

	if _, err := io.WriteString(writer, line+"\r\n"); err != nil {
		t.Fatalf("write backend line %q: %v", line, err)
	}
}

// expectBackendLine reads and compares one CRLF-terminated backend command.
func expectBackendLine(t *testing.T, reader *bufio.Reader, want string) {
	t.Helper()

	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read backend line: %v", err)
	}

	line = strings.TrimRight(line, "\r\n")
	if line != want {
		t.Fatalf("backend line = %q, want %q", line, want)
	}
}
