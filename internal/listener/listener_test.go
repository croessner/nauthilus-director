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
	"sync"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/observability"
	proxyproto "github.com/pires/go-proxyproto"
)

const (
	testGreeting         = "* OK test listener ready\r\n"
	testGRPCTransport    = "grpc"
	testGRPCAuthority    = "grpc-authority"
	testIMAPListener     = "imap"
	testIMAPSListener    = "imaps"
	testLMTPListener     = "lmtp"
	testLMTPSListener    = "lmtps"
	testLoopbackAny      = "127.0.0.1:0"
	trustedLocalhostCIDR = "127.0.0.1/32"
)

// TestManagerSelectsSupportedProtocolListeners verifies that startup plans include IMAP and LMTP listeners.
func TestManagerSelectsSupportedProtocolListeners(t *testing.T) {
	cfg := config.DefaultConfig()

	manager, err := NewManagerWithConfig(cfg)
	if err != nil {
		t.Fatalf("NewManagerWithConfig returned error: %v", err)
	}

	got := manager.ListenerNames()
	want := []string{testIMAPListener, testIMAPSListener, testLMTPListener, testLMTPSListener}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("listener names = %v, want %v", got, want)
	}
}

// TestManagerRejectsUnsupportedProtocolBeforeBind verifies unknown protocols fail during planning.
func TestManagerRejectsUnsupportedProtocolBeforeBind(t *testing.T) {
	cfg := singleListenerConfig(testIMAPListener, tlsModeStartTLS)
	entry := cfg.Director.Listeners[testIMAPListener]
	entry.Protocol = "pop3"
	cfg.Director.Listeners[testIMAPListener] = entry

	_, err := NewManagerWithConfig(cfg)
	if err == nil {
		t.Fatal("NewManagerWithConfig accepted an unsupported protocol")
	}

	if !strings.Contains(err.Error(), "unsupported protocol pop3") {
		t.Fatalf("error = %q, want unsupported protocol rejection", err.Error())
	}
}

// TestSessionOptionsIncludeAuthorityBearerTokenLimit verifies IMAP sessions inherit authority bearer limits.
func TestSessionOptionsIncludeAuthorityBearerTokenLimit(t *testing.T) {
	cfg := singleListenerConfig(testIMAPListener, tlsModeStartTLS)
	authority := cfg.Auth.Authorities["default"]
	authority.Mechanisms.Bearer.TokenMaxBytes = 42
	cfg.Auth.Authorities["default"] = authority

	captured := make(chan SessionOptions, 1)

	_, err := NewManagerWithConfig(cfg, WithSessionHandlerFactory(func(options SessionOptions) SessionHandler {
		captured <- options

		return newRecordingHandler()
	}))
	if err != nil {
		t.Fatalf("NewManagerWithConfig returned error: %v", err)
	}

	select {
	case options := <-captured:
		if options.BearerTokenMaxBytes != 42 {
			t.Fatalf("bearer token limit = %d, want 42", options.BearerTokenMaxBytes)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for session options")
	}
}

// TestManagerSelectsConfiguredListenerAuthorityTransport verifies listener authority selection.
func TestManagerSelectsConfiguredListenerAuthorityTransport(t *testing.T) {
	cfg := singleListenerConfig(testIMAPListener, tlsModeStartTLS)
	authority := cfg.Auth.Authorities["default"]
	authority.Transport = testGRPCTransport
	cfg.Auth.Authorities[testGRPCAuthority] = authority

	entry := cfg.Director.Listeners[testIMAPListener]
	entry.Authority = testGRPCAuthority
	cfg.Director.Listeners[testIMAPListener] = entry

	captured := make(chan config.AuthorityConfig, 1)
	optionsSeen := make(chan SessionOptions, 1)

	_, err := NewManagerWithConfig(
		cfg,
		WithNauthilusClientFactory(func(authority config.AuthorityConfig) (nauthilus.Authenticator, error) {
			captured <- authority

			return noopAuthenticator{}, nil
		}),
		WithSessionHandlerFactory(func(options SessionOptions) SessionHandler {
			optionsSeen <- options

			return newRecordingHandler()
		}),
	)
	if err != nil {
		t.Fatalf("NewManagerWithConfig returned error: %v", err)
	}

	select {
	case authority := <-captured:
		if authority.Transport != testGRPCTransport {
			t.Fatalf("authority transport = %q, want grpc", authority.Transport)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for selected authority")
	}

	select {
	case options := <-optionsSeen:
		if options.Config.Authority != testGRPCAuthority {
			t.Fatalf("listener authority = %q, want grpc-authority", options.Config.Authority)
		}

		if options.Authenticator == nil {
			t.Fatal("session options did not receive authenticator")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for session options")
	}
}

// TestStartTLSListenerStartsWithoutImplicitTLS verifies cleartext IMAP listener setup.
func TestStartTLSListenerStartsWithoutImplicitTLS(t *testing.T) {
	cfg := singleListenerConfig(testIMAPListener, tlsModeStartTLS)
	handler := newRecordingHandler()

	manager, address := startManager(t, cfg, testIMAPListener, WithSessionHandlerFactory(handler.factory))

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

// TestIMAPAndLMTPListenersStartThroughProtocolFactory verifies shared transport startup is protocol-generic.
func TestIMAPAndLMTPListenersStartThroughProtocolFactory(t *testing.T) {
	cfg := config.DefaultConfig()

	imapEntry := cfg.Director.Listeners[testIMAPListener]
	imapEntry.Address = testLoopbackAny
	cfg.Director.Listeners[testIMAPListener] = imapEntry

	lmtpEntry := cfg.Director.Listeners[testLMTPListener]
	lmtpEntry.Address = testLoopbackAny
	lmtpEntry.TLS.Mode = tlsModeStartTLS
	cfg.Director.Listeners[testLMTPListener] = lmtpEntry

	cfg.Director.Listeners = map[string]config.ListenerConfig{
		testIMAPListener: imapEntry,
		testLMTPListener: lmtpEntry,
	}

	protocols := make(chan string, 2)

	manager, err := NewManagerWithConfig(
		cfg,
		WithSessionHandlerFactory(func(options SessionOptions) SessionHandler {
			protocols <- options.Config.Protocol

			return newRecordingHandler()
		}),
	)
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

	if _, ok := manager.BoundAddress(testIMAPListener); !ok {
		t.Fatal("IMAP listener did not bind")
	}

	if _, ok := manager.BoundAddress(testLMTPListener); !ok {
		t.Fatal("LMTP listener did not bind")
	}

	if got := manager.ListenerNames(); !reflect.DeepEqual(got, []string{testIMAPListener, testLMTPListener}) {
		t.Fatalf("listener names = %v, want IMAP and LMTP", got)
	}

	if len(protocols) != 2 {
		t.Fatalf("handler factory calls = %d, want 2", len(protocols))
	}
}

// TestReloadAddsLMTPAndDrainsRemovedListener verifies live listener add/remove behavior.
func TestReloadAddsLMTPAndDrainsRemovedListener(t *testing.T) {
	current := singleListenerConfig(testIMAPListener, tlsModeStartTLS)
	next := current
	imapEntry := current.Director.Listeners[testIMAPListener]
	lmtpEntry := config.DefaultConfig().Director.Listeners[testLMTPListener]
	lmtpEntry.Address = testLoopbackAny
	lmtpEntry.TLS.Mode = tlsModeStartTLS
	lmtpEntry.ProxyProtocol.Enabled = false
	next.Director.Listeners = map[string]config.ListenerConfig{
		testIMAPListener: imapEntry,
		testLMTPListener: lmtpEntry,
	}

	manager, err := NewManagerWithConfig(current, WithSessionHandlerFactory(func(SessionOptions) SessionHandler {
		return newRecordingHandler()
	}))
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

	reloadCtx, cancelReload := context.WithTimeout(context.Background(), time.Second)
	defer cancelReload()

	if err := manager.Reload(reloadCtx, next); err != nil {
		t.Fatalf("Reload add LMTP: %v", err)
	}

	lmtpAddress, ok := manager.BoundAddress(testLMTPListener)
	if !ok {
		t.Fatal("LMTP listener did not bind after reload")
	}

	conn, err := net.Dial(networkTCP, lmtpAddress)
	if err != nil {
		t.Fatalf("dial reloaded LMTP listener: %v", err)
	}

	_ = conn.Close()

	if err := manager.Reload(reloadCtx, current); err != nil {
		t.Fatalf("Reload remove LMTP: %v", err)
	}

	if _, ok := manager.BoundAddress(testLMTPListener); ok {
		t.Fatal("removed LMTP listener still exposes a bound address")
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
	handler := newRecordingHandler()

	_, address := startManager(t, cfg, testIMAPSListener, WithSessionHandlerFactory(handler.factory))

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
	handler := newRecordingHandler()

	manager, address := startManager(t, cfg, testIMAPListener, WithSessionHandlerFactory(handler.factory))

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

// TestListenerObservabilityClassifiesLifecycleEvents verifies listener reasons stay bounded.
func TestListenerObservabilityClassifiesLifecycleEvents(t *testing.T) {
	cfg := singleListenerConfig(testIMAPListener, tlsModeStartTLS)
	entry := cfg.Director.Listeners[testIMAPListener]
	entry.Address = "127.0.0.1:not-a-port"
	cfg.Director.Listeners[testIMAPListener] = entry

	recorder := &recordingListenerObservability{}

	manager, err := NewManagerWithConfig(cfg, WithObservabilityRecorder(recorder))
	if err != nil {
		t.Fatalf("NewManagerWithConfig: %v", err)
	}

	if err := manager.Start(context.Background()); err == nil {
		t.Fatal("Start accepted an invalid bind address")
	}

	event, ok := recorder.last(observability.EventListenerStart)
	if !ok {
		t.Fatalf("listener start event missing: %#v", recorder.snapshot())
	}

	if got := event.MetricLabels["reason_class"]; got != "bind_failed" {
		t.Fatalf("bind reason_class = %q, want bind_failed", got)
	}
}

// TestListenerObservabilityRecordsAcceptLoopStop verifies accept-loop exit is explicit.
func TestListenerObservabilityRecordsAcceptLoopStop(t *testing.T) {
	cfg := singleListenerConfig(testIMAPListener, tlsModeStartTLS)
	recorder := &recordingListenerObservability{}
	manager, _ := startManager(t, cfg, testIMAPListener, WithObservabilityRecorder(recorder))

	stopCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := manager.Stop(stopCtx); err != nil {
		t.Fatalf("Stop returned error: %v", err)
	}

	event, ok := recorder.lastWithOperation(observability.EventListenerStop, "accept_loop")
	if !ok {
		t.Fatalf("accept loop stop event missing: %#v", recorder.snapshot())
	}

	if got := event.MetricLabels["reason_class"]; got != "closed" {
		t.Fatalf("accept loop reason_class = %q, want closed", got)
	}
}

// TestProxyProtocolObservabilityClassifiesAcceptAndReject verifies PROXY results are bounded.
func TestProxyProtocolObservabilityClassifiesAcceptAndReject(t *testing.T) {
	recorder := &recordingListenerObservability{}
	handler := newRecordingHandler()
	cfg := proxyListenerConfig([]string{trustedLocalhostCIDR})
	_, address := startManager(
		t,
		cfg,
		testIMAPListener,
		WithObservabilityRecorder(recorder),
		WithSessionHandlerFactory(handler.factory),
	)

	rejected, err := net.Dial(networkTCP, address)
	if err != nil {
		t.Fatalf("dial rejected proxy listener: %v", err)
	}

	_, _ = io.WriteString(rejected, "PROXY TCP4 broken\r\n")
	expectNoGreeting(t, rejected)
	_ = rejected.Close()

	rejectedEvent, ok := recorder.lastWithResult(observability.EventProxyProtocol, "rejected")
	if !ok {
		t.Fatalf("proxy rejection event missing: %#v", recorder.snapshot())
	}

	if got := rejectedEvent.MetricLabels["reason_class"]; got != listenerReasonMalformed {
		t.Fatalf("proxy reject reason_class = %q, want malformed", got)
	}

	accepted, err := net.Dial(networkTCP, address)
	if err != nil {
		t.Fatalf("dial accepted proxy listener: %v", err)
	}
	defer func() { _ = accepted.Close() }()

	if _, err := io.WriteString(accepted, "PROXY TCP4 198.51.100.10 203.0.113.10 12345 143\r\n"); err != nil {
		t.Fatalf("write proxy v1 header: %v", err)
	}

	if line := readLine(t, accepted); line != testGreeting {
		t.Fatalf("greeting = %q, want %q", line, testGreeting)
	}

	acceptedEvent, ok := recorder.lastWithResult(observability.EventProxyProtocol, "accepted")
	if !ok {
		t.Fatalf("proxy accept event missing: %#v", recorder.snapshot())
	}

	if got := acceptedEvent.MetricLabels["reason_class"]; got != listenerResultOK {
		t.Fatalf("proxy accept reason_class = %q, want ok", got)
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

type recordingListenerObservability struct {
	mu     sync.Mutex
	events []observability.Event
}

type noopAuthenticator struct{}

// Record stores one listener event for assertions.
func (r *recordingListenerObservability) Record(_ context.Context, event observability.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.events = append(r.events, event)
}

// last returns the most recent event with a matching name.
func (r *recordingListenerObservability) last(name string) (observability.Event, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for index := len(r.events) - 1; index >= 0; index-- {
		if r.events[index].Name == name {
			return r.events[index], true
		}
	}

	return observability.Event{}, false
}

// lastWithOperation returns the latest matching event for one operation label.
func (r *recordingListenerObservability) lastWithOperation(name string, operation string) (observability.Event, bool) {
	return r.lastMatching(name, "operation", operation)
}

// lastWithResult returns the latest matching event for one result label.
func (r *recordingListenerObservability) lastWithResult(name string, result string) (observability.Event, bool) {
	return r.lastMatching(name, "result", result)
}

// lastMatching returns the latest event whose metric label equals the expected value.
func (r *recordingListenerObservability) lastMatching(name string, label string, value string) (observability.Event, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for index := len(r.events) - 1; index >= 0; index-- {
		event := r.events[index]
		if event.Name == name && event.MetricLabels[label] == value {
			return event, true
		}
	}

	return observability.Event{}, false
}

// snapshot returns a detached copy of recorded listener events.
func (r *recordingListenerObservability) snapshot() []observability.Event {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]observability.Event(nil), r.events...)
}

// Authenticate returns a temporary failure without contacting an authority.
func (noopAuthenticator) Authenticate(context.Context, nauthilus.AuthRequest) (nauthilus.AuthResult, error) {
	return nauthilus.AuthResult{Decision: nauthilus.DecisionTemporaryFailure}, nil
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

// singleListenerConfig returns a default config narrowed to one listener.
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
