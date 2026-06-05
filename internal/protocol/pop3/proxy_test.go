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

//nolint:funlen,goconst,gocyclo,wsl_v5 // Proxy tests keep wire-order cases compact and explicit.
package pop3

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/placement"
	runtimectl "github.com/croessner/nauthilus-director/internal/runtime"
)

// TestPOP3ProxyForwardsBufferedClientBytesExactlyOnce proves authorization read-ahead is preserved.
func TestPOP3ProxyForwardsBufferedClientBytesExactlyOnce(t *testing.T) {
	postAuth := "STAT\r\nUIDL 7\r\n"
	connector := newProxyPOP3BackendConnector(len(postAuth))
	placer, lease := newPOP3ProxyPlacement()
	harness := startPOP3Harness(t, testPOP3ProxyConfig(connector, placer, nil, nil))
	harness.expectOK(t)

	harness.write(t, "USER frontend@example.test\r\n")
	harness.expectOK(t)
	harness.write(t, "PASS "+testPOP3FrontendPassword+"\r\n"+postAuth)
	harness.expectOK(t)

	if got := string(connector.proxiedBytes(t)); got != postAuth {
		t.Fatalf("proxied bytes = %q, want %q", got, postAuth)
	}

	harness.expectDone(t)
	connector.waitClosed(t)

	if lease.closeCount() != 1 {
		t.Fatalf("lease close count = %d, want 1", lease.closeCount())
	}
}

// TestPOP3ProxyRelaysBackendBufferedBytes verifies backend read-ahead reaches the client after success.
func TestPOP3ProxyRelaysBackendBufferedBytes(t *testing.T) {
	backendBuffered := "+OK backend post-auth notice\r\n"
	connector := newProxyPOP3BackendConnector(0)
	connector.backendBuffered = []byte(backendBuffered)
	placer, _ := newPOP3ProxyPlacement()
	harness := startPOP3Harness(t, testPOP3ProxyConfig(connector, placer, nil, nil))
	harness.expectOK(t)

	harness.write(t, "USER frontend@example.test\r\n")
	harness.expectOK(t)
	harness.write(t, "PASS "+testPOP3FrontendPassword+"\r\n")
	harness.expectOK(t)

	if got := readRawPOP3ClientBytes(t, harness, len(backendBuffered)); got != backendBuffered {
		t.Fatalf("backend buffered bytes = %q, want %q", got, backendBuffered)
	}

	harness.expectDone(t)
	connector.waitClosed(t)
}

// TestPOP3FrontendSuccessFailureRollsBackBackendAndLease verifies rollback after backend auth success.
func TestPOP3FrontendSuccessFailureRollsBackBackendAndLease(t *testing.T) {
	connector := newProxyPOP3BackendConnector(0)
	connector.readUntilClose = true
	placer, lease := newPOP3ProxyPlacement()
	session := newTestSession(t, testPOP3ProxyConfig(connector, placer, nil, nil), newFailingWriteConn(
		"USER frontend@example.test\r\nPASS "+testPOP3FrontendPassword+"\r\n",
		3,
	))

	err := session.Serve(context.Background())
	if err == nil {
		t.Fatal("Serve returned nil, want frontend success write failure")
	}

	connector.waitClosed(t)

	if lease.closeCount() != 1 {
		t.Fatalf("lease close count = %d, want rollback once", lease.closeCount())
	}

	if _, ok := session.Placement(); ok {
		t.Fatal("session still exposes placement after frontend success failure")
	}
}

// TestPOP3ProxyCloseReleasesPlacementOnce verifies proxy-owned cleanup is idempotent.
func TestPOP3ProxyCloseReleasesPlacementOnce(t *testing.T) {
	connector := newProxyPOP3BackendConnector(0)
	placer, lease := newPOP3ProxyPlacement()
	harness := startPOP3Harness(t, testPOP3ProxyConfig(connector, placer, nil, nil))
	harness.expectOK(t)

	harness.write(t, "USER frontend@example.test\r\n")
	harness.expectOK(t)
	harness.write(t, "PASS "+testPOP3FrontendPassword+"\r\n")
	harness.expectOK(t)
	harness.expectDone(t)
	connector.waitClosed(t)

	if lease.closeCount() != 1 {
		t.Fatalf("lease close count = %d, want 1", lease.closeCount())
	}

	if _, ok := harness.session.Placement(); ok {
		t.Fatal("session still exposes placement after proxy close")
	}
}

// TestPOP3ProxyHeartbeatsLeaseUntilClose verifies proxy mode refreshes and then stops refreshing leases.
func TestPOP3ProxyHeartbeatsLeaseUntilClose(t *testing.T) {
	connector := newProxyPOP3BackendConnector(0)
	connector.readUntilClose = true
	placer, lease := newPOP3ProxyPlacement()
	config := testPOP3ProxyConfig(connector, placer, nil, nil)
	config.SessionLeaseTTL = 20 * time.Millisecond
	config.ProxyIdleTimeout = time.Second
	harness := startPOP3Harness(t, config)
	harness.expectOK(t)

	harness.write(t, "USER frontend@example.test\r\n")
	harness.expectOK(t)
	harness.write(t, "PASS "+testPOP3FrontendPassword+"\r\n")
	harness.expectOK(t)

	waitForPOP3ProxyCondition(t, func() bool {
		return lease.heartbeatCount() > 0
	})

	_ = harness.client.Close()
	harness.expectDone(t)
	connector.waitClosed(t)

	afterClose := lease.heartbeatCount()
	time.Sleep(30 * time.Millisecond)
	if lease.heartbeatCount() != afterClose {
		t.Fatalf("heartbeat count after close = %d, want stopped at %d", lease.heartbeatCount(), afterClose)
	}

	if lease.closeCount() != 1 {
		t.Fatalf("lease close count = %d, want 1", lease.closeCount())
	}
}

// TestPOP3ProxyObservabilityDoesNotRecordMailboxMaterial verifies proxy telemetry is byte-oriented only.
func TestPOP3ProxyObservabilityDoesNotRecordMailboxMaterial(t *testing.T) {
	postAuth := "UIDL 4242\r\nRETR 4242\r\n"
	backendBuffered := "+OK unique-uidl-sentinel-4242\r\nSubject: sentinel mailbox material\r\n.\r\n"
	recorder := &recordingPOP3Observability{}
	connector := newProxyPOP3BackendConnector(len(postAuth))
	connector.backendBuffered = []byte(backendBuffered)
	placer, _ := newPOP3ProxyPlacement()
	harness := startPOP3Harness(t, testPOP3ProxyConfig(connector, placer, nil, recorder))
	harness.expectOK(t)

	harness.write(t, "USER frontend@example.test\r\n")
	harness.expectOK(t)
	harness.write(t, "PASS "+testPOP3FrontendPassword+"\r\n"+postAuth)
	harness.expectOK(t)
	_ = readRawPOP3ClientBytes(t, harness, len(backendBuffered))
	_ = connector.proxiedBytes(t)
	harness.expectDone(t)

	events := fmt.Sprintf("%#v", recorder.snapshot())
	for _, sentinel := range []string{"4242", "unique-uidl-sentinel-4242", "sentinel mailbox material"} {
		if strings.Contains(events, sentinel) {
			t.Fatalf("observability events leaked proxied material %q: %s", sentinel, events)
		}
	}
}

// TestPOP3ProxyDoesNotParsePostAuthCommands verifies transaction/update commands stay backend-owned.
func TestPOP3ProxyDoesNotParsePostAuthCommands(t *testing.T) {
	postAuth := "STAT\r\nLIST 1\r\nDELE 1\r\nRSET\r\nTOP 1 2\r\nNOOP\r\nQUIT\r\nX-OPAQUE mailbox words\r\n"
	authenticator := authenticatedRecorder()
	connector := newProxyPOP3BackendConnector(len(postAuth))
	placer, _ := newPOP3ProxyPlacement()
	harness := startPOP3Harness(t, testPOP3ProxyConfig(connector, placer, authenticator, nil))
	harness.expectOK(t)

	harness.write(t, "USER frontend@example.test\r\n")
	harness.expectOK(t)
	harness.write(t, "PASS "+testPOP3FrontendPassword+"\r\n")
	harness.expectOK(t)
	harness.write(t, postAuth)

	if got := string(connector.proxiedBytes(t)); got != postAuth {
		t.Fatalf("post-auth bytes = %q, want %q", got, postAuth)
	}

	harness.expectDone(t)
	if authenticator.CallCount() != 1 {
		t.Fatalf("auth calls = %d, want exactly initial login", authenticator.CallCount())
	}
}

// TestPOP3ProxyRegistersLocalSessionForGracefulDrain verifies runtime drain can close proxied POP3 streams.
func TestPOP3ProxyRegistersLocalSessionForGracefulDrain(t *testing.T) {
	registry := runtimectl.NewLocalSessionRegistry()
	connector := newProxyPOP3BackendConnector(0)
	connector.readUntilClose = true
	placer, lease := newPOP3ProxyPlacement()
	config := testPOP3ProxyConfig(connector, placer, nil, nil)
	config.LocalSessions = registry
	harness := startPOP3Harness(t, config)
	harness.expectOK(t)

	harness.write(t, "USER frontend@example.test\r\n")
	harness.expectOK(t)
	harness.write(t, "PASS "+testPOP3FrontendPassword+"\r\n")
	harness.expectOK(t)

	var closed int
	waitForPOP3ProxyCondition(t, func() bool {
		var err error
		closed, err = registry.CloseListener(context.Background(), "pop3", runtimectl.LocalSessionControl{
			Action: "test_graceful_drain",
			Reason: "pop3 proxy test",
		})

		return err == nil && closed == 1
	})

	harness.expectDone(t)
	connector.waitClosed(t)

	if closed != 1 || lease.closeCount() != 1 {
		t.Fatalf("closed local sessions = %d lease closes = %d, want 1/1", closed, lease.closeCount())
	}
}

// testPOP3ProxyConfig creates one authenticated POP3 proxy fixture.
func testPOP3ProxyConfig(
	connector BackendConnector,
	placer placement.SessionPlacer,
	authenticator nauthilus.Authenticator,
	recorder observability.Recorder,
) SessionConfig {
	if authenticator == nil {
		authenticator = authenticatedRecorder()
	}

	config := testPlacementPOP3Config(TLSModeImplicit, authenticator, nil, placer)
	config.BackendConnector = connector
	config.ProxyIdleTimeout = time.Second
	config.Observability = recorder

	return config
}

// newPOP3ProxyPlacement creates a placement fixture with master-user POP3 backend auth.
func newPOP3ProxyPlacement() (*recordingSessionPlacer, *recordingPlacementLease) {
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

	return &recordingSessionPlacer{lease: lease}, lease
}

// readRawPOP3ClientBytes reads opaque backend-to-client proxy bytes without line parsing.
func readRawPOP3ClientBytes(t *testing.T, harness *pop3Harness, length int) string {
	t.Helper()

	buffer := make([]byte, length)
	_ = harness.client.SetReadDeadline(time.Now().Add(time.Second))
	_, err := io.ReadFull(harness.reader, buffer)
	_ = harness.client.SetReadDeadline(time.Time{})
	if err != nil {
		t.Fatalf("read raw POP3 client bytes: %v", err)
	}

	return string(buffer)
}

// waitForPOP3ProxyCondition waits until a proxy-side asynchronous condition is true.
func waitForPOP3ProxyCondition(t *testing.T, condition func() bool) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}

		time.Sleep(5 * time.Millisecond)
	}

	t.Fatal("timed out waiting for POP3 proxy condition")
}

// proxyPOP3BackendConnector performs backend auth and then treats all later bytes as opaque.
type proxyPOP3BackendConnector struct {
	mu              sync.Mutex
	requests        []backend.ConnectRequest
	backendBuffered []byte
	expectedClient  int
	proxied         chan []byte
	closed          chan struct{}
	errs            chan error
	authResponse    string
	readUntilClose  bool
}

// newProxyPOP3BackendConnector creates a backend fixture that observes raw proxy bytes.
func newProxyPOP3BackendConnector(expectedClient int) *proxyPOP3BackendConnector {
	return &proxyPOP3BackendConnector{
		expectedClient: expectedClient,
		proxied:        make(chan []byte, 1),
		closed:         make(chan struct{}),
		errs:           make(chan error, 1),
	}
}

// Connect records the session request and returns an auth-capable backend stream.
func (c *proxyPOP3BackendConnector) Connect(_ context.Context, request backend.ConnectRequest) (*BackendConnection, error) {
	c.mu.Lock()
	c.requests = append(c.requests, request)
	c.mu.Unlock()

	client, server := net.Pipe()
	go c.serve(server)

	connection := newBackendConnection(client)
	connection.capabilities = backend.NewCapabilitySet(capabilityUser, capabilitySASL+"=XOAUTH2", capabilitySASL+"=OAUTHBEARER")
	connection.tlsActive = true
	connection.tlsVerified = true

	return connection, nil
}

// serve accepts backend auth and then captures optional raw proxy bytes.
func (c *proxyPOP3BackendConnector) serve(conn net.Conn) {
	defer close(c.closed)
	defer func() { _ = conn.Close() }()

	reader := bufio.NewReader(conn)
	if err := c.readAuthCommand(reader, "USER "); err != nil {
		c.recordError(err)

		return
	}

	if _, err := io.WriteString(conn, "+OK user accepted\r\n"); err != nil {
		c.recordError(err)

		return
	}

	if err := c.readAuthCommand(reader, "PASS "); err != nil {
		c.recordError(err)

		return
	}

	response := c.authResponse
	if response == "" {
		response = "+OK pass accepted"
	}

	authAndBuffered := append([]byte(response+"\r\n"), c.backendBuffered...)
	if _, err := conn.Write(authAndBuffered); err != nil {
		c.recordError(err)

		return
	}

	if c.expectedClient > 0 {
		buffer := make([]byte, c.expectedClient)
		if _, err := io.ReadFull(reader, buffer); err != nil {
			c.recordError(err)

			return
		}

		c.proxied <- buffer
	}

	if c.readUntilClose {
		_, _ = io.Copy(io.Discard, reader)
	}
}

// readAuthCommand consumes only backend-auth envelope lines.
func (c *proxyPOP3BackendConnector) readAuthCommand(reader *bufio.Reader, prefix string) error {
	line, err := reader.ReadString('\n')
	if err != nil {
		return err
	}

	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(strings.ToUpper(line), strings.ToUpper(prefix)) {
		return fmt.Errorf("backend auth command prefix mismatch: got %d bytes", len(line))
	}

	return nil
}

// recordError stores the first backend fixture error for the test goroutine.
func (c *proxyPOP3BackendConnector) recordError(err error) {
	if err == nil {
		return
	}

	select {
	case c.errs <- err:
	default:
	}
}

// proxiedBytes returns the raw bytes observed after backend auth completed.
func (c *proxyPOP3BackendConnector) proxiedBytes(t *testing.T) []byte {
	t.Helper()

	select {
	case payload := <-c.proxied:
		return payload
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for proxied POP3 bytes")
	}

	return nil
}

// waitClosed waits for the fake backend stream to close and reports fixture errors.
func (c *proxyPOP3BackendConnector) waitClosed(t *testing.T) {
	t.Helper()

	select {
	case <-c.closed:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for fake POP3 backend close")
	}

	select {
	case err := <-c.errs:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !strings.Contains(err.Error(), "closed pipe") {
			t.Fatalf("fake POP3 backend error: %v", err)
		}
	default:
	}
}

// recordingPOP3Observability stores normalized events for leak assertions.
type recordingPOP3Observability struct {
	mu     sync.Mutex
	events []observability.Event
}

// Record stores one observability event.
func (r *recordingPOP3Observability) Record(_ context.Context, event observability.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.events = append(r.events, event)
}

// snapshot returns a detached event slice.
func (r *recordingPOP3Observability) snapshot() []observability.Event {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]observability.Event(nil), r.events...)
}

// failingWriteConn fails on the configured Write call after serving scripted input.
type failingWriteConn struct {
	input      *bytes.Reader
	output     bytes.Buffer
	failAt     int
	writeCount int
}

// newFailingWriteConn creates a frontend stream that fails during a later response flush.
func newFailingWriteConn(input string, failAt int) *failingWriteConn {
	return &failingWriteConn{input: bytes.NewReader([]byte(input)), failAt: failAt}
}

// Read returns scripted frontend command bytes.
func (c *failingWriteConn) Read(p []byte) (int, error) {
	return c.input.Read(p)
}

// Write records frontend responses until the configured failure point.
func (c *failingWriteConn) Write(p []byte) (int, error) {
	c.writeCount++
	if c.failAt > 0 && c.writeCount >= c.failAt {
		return 0, errPOP3TestFrontendWrite
	}

	return c.output.Write(p)
}

// Close marks the synthetic connection as closed.
func (c *failingWriteConn) Close() error {
	return nil
}

// LocalAddr returns a stable local POP3 address.
func (c *failingWriteConn) LocalAddr() net.Addr {
	return testAddr("127.0.0.1:110")
}

// RemoteAddr returns a stable remote POP3 address.
func (c *failingWriteConn) RemoteAddr() net.Addr {
	return testAddr("192.0.2.50:50110")
}

// SetDeadline accepts deadline changes for proxy/session code.
func (c *failingWriteConn) SetDeadline(time.Time) error {
	return nil
}

// SetReadDeadline accepts read deadline changes for proxy/session code.
func (c *failingWriteConn) SetReadDeadline(time.Time) error {
	return nil
}

// SetWriteDeadline accepts write deadline changes for proxy/session code.
func (c *failingWriteConn) SetWriteDeadline(time.Time) error {
	return nil
}

var errPOP3TestFrontendWrite = errors.New("pop3 test frontend write failed")
