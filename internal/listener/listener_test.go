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

//nolint:funlen // Listener tests keep socket fixtures local to show the transport contract.
package listener

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/config"
	proxyproto "github.com/pires/go-proxyproto"
)

const (
	testGreeting         = "* OK test listener ready\r\n"
	testIMAPListener     = "imap"
	testIMAPSListener    = "imaps"
	trustedLocalhostCIDR = "127.0.0.1/32"
)

// TestManagerSelectsOnlyIMAPListeners verifies that M1 starts only protocol=imap entries.
func TestManagerSelectsOnlyIMAPListeners(t *testing.T) {
	cfg := config.DefaultConfig()

	manager, err := NewManagerWithConfig(cfg)
	if err != nil {
		t.Fatalf("NewManagerWithConfig returned error: %v", err)
	}

	got := manager.ListenerNames()
	want := []string{testIMAPListener, testIMAPSListener}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("listener names = %v, want %v", got, want)
	}
}

// TestStartTLSListenerStartsWithoutImplicitTLS verifies cleartext IMAP listener setup.
func TestStartTLSListenerStartsWithoutImplicitTLS(t *testing.T) {
	cfg := singleListenerConfig(testIMAPListener, tlsModeStartTLS)

	manager, address := startManager(t, cfg, testIMAPListener)

	snapshots := manager.Snapshots()
	if len(snapshots) != 1 {
		t.Fatalf("snapshots = %d, want 1", len(snapshots))
	}

	if snapshots[0].ImplicitTLS {
		t.Fatal("STARTTLS listener was marked as implicit TLS")
	}

	conn, err := net.Dial(networkTCP, address)
	if err != nil {
		t.Fatalf("dial listener: %v", err)
	}
	defer func() { _ = conn.Close() }()

	line := readLine(t, conn)
	if !strings.HasPrefix(line, "* OK ") {
		t.Fatalf("greeting = %q, want IMAP OK greeting", line)
	}
}

// TestIMAPSListenerWrapsAcceptedConnectionsInTLS verifies implicit TLS before IMAP greeting.
func TestIMAPSListenerWrapsAcceptedConnectionsInTLS(t *testing.T) {
	certPath, keyPath := writeTestCertificate(t)
	cfg := singleListenerConfig(testIMAPSListener, tlsModeImplicit)
	entry := cfg.Director.Listeners[testIMAPSListener]
	entry.TLS.Cert = certPath
	entry.TLS.Key = config.Secret(keyPath)
	cfg.Director.Listeners[testIMAPSListener] = entry

	_, address := startManager(t, cfg, testIMAPSListener)

	dialer := &net.Dialer{Timeout: time.Second}
	tlsConfig := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}

	conn, err := tls.DialWithDialer(dialer, networkTCP, address, tlsConfig)
	if err != nil {
		t.Fatalf("dial TLS listener: %v", err)
	}

	defer func() { _ = conn.Close() }()

	line := readLine(t, conn)
	if !strings.HasPrefix(line, "* OK ") {
		t.Fatalf("TLS greeting = %q, want IMAP OK greeting", line)
	}
}

// TestGracefulListenerShutdownClosesActiveSessions verifies deadline-enforced shutdown.
func TestGracefulListenerShutdownClosesActiveSessions(t *testing.T) {
	cfg := singleListenerConfig(testIMAPListener, tlsModeStartTLS)
	cfg.Runtime.Process.ShutdownTimeout = config.NewDuration(20 * time.Millisecond)

	manager, address := startManager(t, cfg, testIMAPListener)

	conn, err := net.Dial(networkTCP, address)
	if err != nil {
		t.Fatalf("dial listener: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_ = readLine(t, conn)

	stopCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	if err := manager.Stop(stopCtx); err != nil {
		t.Fatalf("Stop returned error: %v", err)
	}

	buffer := make([]byte, 1)

	_, err = conn.Read(buffer)
	if err == nil {
		t.Fatal("active connection remained readable after shutdown")
	}
}

// TestProxyProtocolRejectsEmptyTrustedCIDRs verifies fail-closed proxy config validation.
func TestProxyProtocolRejectsEmptyTrustedCIDRs(t *testing.T) {
	cfg := singleListenerConfig(testIMAPListener, tlsModeStartTLS)
	entry := cfg.Director.Listeners[testIMAPListener]
	entry.ProxyProtocol.Enabled = true
	entry.ProxyProtocol.TrustedCIDRs = nil
	cfg.Director.Listeners[testIMAPListener] = entry

	if _, err := NewManagerWithConfig(cfg); err == nil {
		t.Fatal("NewManagerWithConfig accepted proxy_protocol without trusted CIDRs")
	}

	if err := config.NewLoader().Validate(cfg); err == nil {
		t.Fatal("config validation accepted proxy_protocol without trusted CIDRs")
	}
}

// TestProxyProtocolV1AcceptedFromTrustedPeer verifies trusted v1 headers become session context.
func TestProxyProtocolV1AcceptedFromTrustedPeer(t *testing.T) {
	recorder := newRecordingHandler()
	cfg := proxyListenerConfig([]string{trustedLocalhostCIDR})
	_, address := startManager(t, cfg, testIMAPListener, WithSessionHandlerFactory(recorder.factory))

	conn, err := net.Dial(networkTCP, address)
	if err != nil {
		t.Fatalf("dial listener: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := io.WriteString(conn, "PROXY TCP4 198.51.100.10 203.0.113.10 12345 143\r\n"); err != nil {
		t.Fatalf("write proxy v1 header: %v", err)
	}

	if line := readLine(t, conn); line != testGreeting {
		t.Fatalf("greeting = %q, want %q", line, testGreeting)
	}

	recorder.expectRemote(t, "198.51.100.10:12345")
}

// TestProxyProtocolV2AcceptedFromTrustedPeer verifies trusted v2 headers become session context.
func TestProxyProtocolV2AcceptedFromTrustedPeer(t *testing.T) {
	recorder := newRecordingHandler()
	cfg := proxyListenerConfig([]string{trustedLocalhostCIDR})
	_, address := startManager(t, cfg, testIMAPListener, WithSessionHandlerFactory(recorder.factory))

	conn, err := net.Dial(networkTCP, address)
	if err != nil {
		t.Fatalf("dial listener: %v", err)
	}
	defer func() { _ = conn.Close() }()

	header := proxyproto.HeaderProxyFromAddrs(
		2,
		&net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 23456},
		&net.TCPAddr{IP: net.ParseIP("203.0.113.20"), Port: 143},
	)
	if _, err := header.WriteTo(conn); err != nil {
		t.Fatalf("write proxy v2 header: %v", err)
	}

	if line := readLine(t, conn); line != testGreeting {
		t.Fatalf("greeting = %q, want %q", line, testGreeting)
	}

	recorder.expectRemote(t, "198.51.100.20:23456")
}

// TestProxyProtocolRejectsUntrustedPeer verifies direct clients cannot supply source addresses.
func TestProxyProtocolRejectsUntrustedPeer(t *testing.T) {
	cfg := proxyListenerConfig([]string{"192.0.2.0/24"})

	expectProxyRejection(t, cfg, func(t *testing.T, conn net.Conn) {
		t.Helper()

		_, _ = io.WriteString(conn, "PROXY TCP4 198.51.100.30 203.0.113.30 34567 143\r\n")
	})
}

// TestProxyProtocolRejectsMissingHeader verifies enabled listeners require a PROXY preface.
func TestProxyProtocolRejectsMissingHeader(t *testing.T) {
	cfg := proxyListenerConfig([]string{trustedLocalhostCIDR})

	expectProxyRejection(t, cfg, func(t *testing.T, conn net.Conn) {
		t.Helper()

		_, _ = io.WriteString(conn, "A001 NOOP\r\n")
	})
}

// TestProxyProtocolRejectsMalformedHeader verifies malformed PROXY input fails closed.
func TestProxyProtocolRejectsMalformedHeader(t *testing.T) {
	cfg := proxyListenerConfig([]string{trustedLocalhostCIDR})

	expectProxyRejection(t, cfg, func(t *testing.T, conn net.Conn) {
		t.Helper()

		_, _ = io.WriteString(conn, "PROXY TCP4 broken\r\n")
	})
}

// TestProxyProtocolRejectsUnsupportedFamily verifies only stream TCP families are accepted.
func TestProxyProtocolRejectsUnsupportedFamily(t *testing.T) {
	cfg := proxyListenerConfig([]string{trustedLocalhostCIDR})

	header := &proxyproto.Header{
		Version:           2,
		Command:           proxyproto.PROXY,
		TransportProtocol: proxyproto.UDPv4,
		SourceAddr:        &net.UDPAddr{IP: net.ParseIP("198.51.100.40"), Port: 44444},
		DestinationAddr:   &net.UDPAddr{IP: net.ParseIP("203.0.113.40"), Port: 143},
	}

	expectProxyRejection(t, cfg, func(t *testing.T, conn net.Conn) {
		t.Helper()

		if _, err := header.WriteTo(conn); err != nil {
			t.Fatalf("write unsupported proxy header: %v", err)
		}
	})
}

// TestProxyProtocolRejectsLocalCommand verifies v2 LOCAL commands never reach IMAP.
func TestProxyProtocolRejectsLocalCommand(t *testing.T) {
	cfg := proxyListenerConfig([]string{trustedLocalhostCIDR})

	expectProxyRejection(t, cfg, func(t *testing.T, conn net.Conn) {
		t.Helper()

		if _, err := conn.Write(proxyLocalHeader()); err != nil {
			t.Fatalf("write proxy LOCAL header: %v", err)
		}
	})
}

// recordingHandler captures the effective remote address seen by the protocol boundary.
type recordingHandler struct {
	remote chan string
}

// newRecordingHandler creates a buffered recorder for one listener test.
func newRecordingHandler() *recordingHandler {
	return &recordingHandler{remote: make(chan string, 1)}
}

// factory returns the recorder itself as the configured session handler.
func (h *recordingHandler) factory(SessionOptions) SessionHandler {
	return h
}

// Serve records the effective remote address and writes a small IMAP greeting.
func (h *recordingHandler) Serve(_ context.Context, conn net.Conn) error {
	h.remote <- conn.RemoteAddr().String()

	if _, err := io.WriteString(conn, testGreeting); err != nil {
		return err
	}

	_, _ = io.Copy(io.Discard, conn)

	return nil
}

// expectRemote asserts that the handler observed the expected remote address.
func (h *recordingHandler) expectRemote(t *testing.T, want string) {
	t.Helper()

	select {
	case got := <-h.remote:
		if got != want {
			t.Fatalf("effective remote = %q, want %q", got, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for remote address %q", want)
	}
}

// expectNoSession asserts that rejected transport setup never reached the handler.
func (h *recordingHandler) expectNoSession(t *testing.T) {
	t.Helper()

	select {
	case got := <-h.remote:
		t.Fatalf("handler was invoked for rejected connection with remote %q", got)
	case <-time.After(50 * time.Millisecond):
	}
}

// expectProxyRejection starts a PROXY listener and verifies setup fails before IMAP.
func expectProxyRejection(t *testing.T, cfg config.Config, writeInput func(*testing.T, net.Conn)) {
	t.Helper()

	recorder := newRecordingHandler()
	_, address := startManager(t, cfg, testIMAPListener, WithSessionHandlerFactory(recorder.factory))

	conn, err := net.Dial(networkTCP, address)
	if err != nil {
		t.Fatalf("dial listener: %v", err)
	}
	defer func() { _ = conn.Close() }()

	writeInput(t, conn)
	expectNoGreeting(t, conn)
	recorder.expectNoSession(t)
}

// singleListenerConfig returns a default config narrowed to one IMAP-family listener.
func singleListenerConfig(name string, tlsMode string) config.Config {
	cfg := config.DefaultConfig()
	entry := cfg.Director.Listeners[name]
	entry.Address = "127.0.0.1:0"
	entry.TLS.Mode = tlsMode
	entry.ProxyProtocol.Enabled = false
	entry.ProxyProtocol.TrustedCIDRs = nil
	cfg.Director.Listeners = map[string]config.ListenerConfig{name: entry}

	return cfg
}

// proxyListenerConfig returns one STARTTLS listener that requires trusted PROXY headers.
func proxyListenerConfig(trustedCIDRs []string) config.Config {
	cfg := singleListenerConfig(testIMAPListener, tlsModeStartTLS)
	cfg.Runtime.Timeouts.Preauth = config.NewDuration(200 * time.Millisecond)
	entry := cfg.Director.Listeners[testIMAPListener]
	entry.ProxyProtocol.Enabled = true
	entry.ProxyProtocol.TrustedCIDRs = trustedCIDRs
	cfg.Director.Listeners[testIMAPListener] = entry

	return cfg
}

// startManager starts a listener manager and registers a cleanup stop hook.
func startManager(t *testing.T, cfg config.Config, listenerName string, opts ...ManagerOption) (*Manager, string) {
	t.Helper()

	manager, err := NewManagerWithConfig(cfg, opts...)
	if err != nil {
		t.Fatalf("NewManagerWithConfig: %v", err)
	}

	startCtx, cancelStart := context.WithTimeout(context.Background(), time.Second)
	defer cancelStart()

	if err := manager.Start(startCtx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	t.Cleanup(func() {
		stopCtx, cancelStop := context.WithTimeout(context.Background(), time.Second)
		defer cancelStop()

		_ = manager.Stop(stopCtx)
	})

	address, ok := manager.BoundAddress(listenerName)
	if !ok {
		t.Fatalf("listener %q did not expose a bound address", listenerName)
	}

	return manager, address
}

// readLine reads one CRLF-terminated line from a frontend connection.
func readLine(t *testing.T, conn net.Conn) string {
	t.Helper()

	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}

	buffer := make([]byte, 256)

	n, err := conn.Read(buffer)
	if err != nil {
		t.Fatalf("read line: %v", err)
	}

	return string(buffer[:n])
}

// expectNoGreeting verifies a rejected connection closes before any IMAP greeting.
func expectNoGreeting(t *testing.T, conn net.Conn) {
	t.Helper()

	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}

	buffer := make([]byte, 128)

	n, err := conn.Read(buffer)
	if err == nil || n > 0 {
		t.Fatalf("read %d bytes %q from rejected connection, want no greeting and an error", n, string(buffer[:n]))
	}
}

// writeTestCertificate writes a temporary self-signed TLS certificate pair.
func writeTestCertificate(t *testing.T) (string, string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	certPath := writeTempFile(t, "listener-*.crt", certPEM)
	keyPath := writeTempFile(t, "listener-*.key", keyPEM)

	return certPath, keyPath
}

// writeTempFile writes bytes to a temporary file and returns its path.
func writeTempFile(t *testing.T, pattern string, contents []byte) string {
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

// proxyLocalHeader returns a minimal PROXY protocol v2 LOCAL preface.
func proxyLocalHeader() []byte {
	return []byte{
		0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
		0x20,
		0x00,
		0x00, 0x00,
	}
}
