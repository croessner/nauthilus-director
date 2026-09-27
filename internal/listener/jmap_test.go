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

//nolint:funlen,goconst,gocyclo,wsl_v5 // Listener fixtures keep the JMAP lifecycle assertions in order.
package listener

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
)

const testJMAPListener = "jmap"

// acceptStateHandler records accept-state notifications and serves nothing.
type acceptStateHandler struct {
	mu     sync.Mutex
	states []bool
	closed int
}

// Close records one release of the handler's background resources.
func (h *acceptStateHandler) Close(context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.closed++

	return nil
}

// closeCount returns how often the listener released the handler.
func (h *acceptStateHandler) closeCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.closed
}

// Serve closes every stream immediately.
func (h *acceptStateHandler) Serve(context.Context, net.Conn) error { return nil }

// AcceptStateChanged records one notification.
func (h *acceptStateHandler) AcceptStateChanged(accepting bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.states = append(h.states, accepting)
}

// snapshot returns the recorded notifications.
func (h *acceptStateHandler) snapshot() []bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	return append([]bool(nil), h.states...)
}

// jmapListenerConfig returns a config with one implicit-TLS JMAP listener using bearer auth.
func jmapListenerConfig(t *testing.T) config.Config {
	t.Helper()

	cfg := config.DefaultConfig()
	entry := withTestListenerCertificate(t, config.ListenerConfig{
		Protocol:    protocolJMAP,
		ServiceName: testJMAPListener,
		Network:     networkTCP,
		Address:     "127.0.0.1:0",
		Authority:   "default",
		BackendPool: "jmap-default",
		TLS:         config.ListenerTLSConfig{Mode: tlsModeImplicit, MinTLSVersion: defaultTLSMinName},
		JMAP: &config.JMAPListenerConfig{
			Auth: config.JMAPAuthConfig{Bearer: config.JMAPBearerAuthConfig{
				Enabled:          true,
				RequiredResource: "https://mail.example.org/",
				RequiredScope:    "mail:jmap",
				AccountClaim:     "mail_account",
			}},
		},
	})
	cfg.Director.Listeners = map[string]config.ListenerConfig{testJMAPListener: entry}

	return cfg
}

// TestJMAPListenerUsesListenerBearerPolicyAndHTTP11 keeps JMAP token binding and ALPN listener-owned.
func TestJMAPListenerUsesListenerBearerPolicyAndHTTP11(t *testing.T) {
	cfg := jmapListenerConfig(t)
	captured := make(chan config.BearerIntrospectionConfig, 1)
	handler := &acceptStateHandler{}

	manager, err := NewManagerWithConfig(cfg,
		WithBearerIntrospectorFactory(func(_ context.Context, authority config.AuthorityConfig) (nauthilus.BearerIntrospector, error) {
			captured <- authority.Mechanisms.Bearer.Introspection

			return noopBearerIntrospector{}, nil
		}),
		WithSessionHandlerFactory(func(SessionOptions) SessionHandler { return handler }),
	)
	if err != nil {
		t.Fatalf("NewManagerWithConfig returned error: %v", err)
	}

	policy := <-captured
	if policy.RequiredResource != "https://mail.example.org/" || policy.RequiredAudience != "" ||
		policy.RequiredScope != "mail:jmap" || policy.AccountClaim != "mail_account" {
		t.Fatalf("introspection policy = %+v, want the JMAP listener binding only", policy)
	}

	if policy.Issuer != cfg.Auth.Authorities["default"].Mechanisms.Bearer.Introspection.Issuer {
		t.Fatal("introspection policy lost the authority endpoint")
	}

	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}

	pemBytes, err := os.ReadFile(cfg.Director.Listeners[testJMAPListener].TLS.Cert)
	if err != nil {
		t.Fatalf("read certificate: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pemBytes)

	address, _ := manager.BoundAddress(testJMAPListener)
	conn, err := tls.Dial("tcp", address, &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}

	if got := conn.ConnectionState().NegotiatedProtocol; got != httpProtocolHTTP11 {
		t.Fatalf("negotiated protocol = %q, want http/1.1", got)
	}

	_ = conn.Close()

	if _, err := manager.Drain(context.Background(), DrainRequest{Name: testJMAPListener, Mode: DrainModeSoft}); err != nil {
		t.Fatalf("Drain returned error: %v", err)
	}

	if _, err := manager.Resume(context.Background(), testJMAPListener); err != nil {
		t.Fatalf("Resume returned error: %v", err)
	}

	if err := manager.Stop(context.Background()); err != nil {
		t.Fatalf("Stop returned error: %v", err)
	}

	if handler.closeCount() != 1 {
		t.Fatalf("handler closed %d times on stop, want 1", handler.closeCount())
	}

	if got := handler.snapshot(); len(got) != 4 || !got[0] || got[1] || !got[2] || got[3] {
		t.Fatalf("accept state notifications = %v, want start, drain, resume, stop", got)
	}
}

// TestJMAPListenerBoundsTLSHandshake closes clients that never finish the TLS handshake.
func TestJMAPListenerBoundsTLSHandshake(t *testing.T) {
	cfg := jmapListenerConfig(t)
	entry := cfg.Director.Listeners[testJMAPListener]
	jmap := *entry.JMAP
	jmap.Timeouts.ReadHeader = config.NewDuration(100 * time.Millisecond)
	entry.JMAP = &jmap
	cfg.Director.Listeners[testJMAPListener] = entry

	manager, err := newTestManagerWithConfig(cfg, WithSessionHandlerFactory(func(SessionOptions) SessionHandler { return &acceptStateHandler{} }))
	if err != nil {
		t.Fatalf("NewManagerWithConfig returned error: %v", err)
	}

	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	defer func() { _ = manager.Stop(context.Background()) }()

	address, _ := manager.BoundAddress(testJMAPListener)

	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("silent client was not disconnected")
	} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatal("listener kept the silent TLS client open past the handshake bound")
	}
}

// TestReloadRemovingJMAPListenerClosesHandler proves reload releases the removed listener's server.
func TestReloadRemovingJMAPListenerClosesHandler(t *testing.T) {
	cfg := jmapListenerConfig(t)
	imap := singleListenerConfig(t, testIMAPListener, tlsModeStartTLS).Director.Listeners[testIMAPListener]
	cfg.Director.Listeners[testIMAPListener] = imap
	handler := &acceptStateHandler{}

	manager, err := newTestManagerWithConfig(cfg, WithSessionHandlerFactory(func(options SessionOptions) SessionHandler {
		if options.ListenerName == testJMAPListener {
			return handler
		}

		return newRecordingHandler()
	}))
	if err != nil {
		t.Fatalf("NewManagerWithConfig returned error: %v", err)
	}

	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	defer func() { _ = manager.Stop(context.Background()) }()

	next := cfg
	next.Director.Listeners = map[string]config.ListenerConfig{testIMAPListener: imap}

	if err := manager.Reload(context.Background(), next); err != nil {
		t.Fatalf("Reload returned error: %v", err)
	}

	if handler.closeCount() != 1 {
		t.Fatalf("removed JMAP handler closed %d times, want 1", handler.closeCount())
	}
}

// TestJMAPListenerUsesDedicatedIntrospectionClient keeps IMAP on the authority client.
func TestJMAPListenerUsesDedicatedIntrospectionClient(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "jmap-introspection-secret")
	if err := os.WriteFile(secretFile, []byte("jmap-secret\n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	cfg := jmapListenerConfig(t)
	entry := cfg.Director.Listeners[testJMAPListener]
	jmap := *entry.JMAP
	jmap.Auth.Bearer.IntrospectionClient = config.JMAPIntrospectionClientConfig{ClientID: "jmap-introspection", ClientSecretFile: config.Secret(secretFile)}
	entry.JMAP = &jmap
	cfg.Director.Listeners[testJMAPListener] = entry
	cfg.Director.Listeners[testIMAPListener] = singleListenerConfig(t, testIMAPListener, tlsModeStartTLS).Director.Listeners[testIMAPListener]

	var (
		mu      sync.Mutex
		clients = map[string]string{}
	)

	_, err := NewManagerWithConfig(cfg,
		WithBearerIntrospectorFactory(func(_ context.Context, authority config.AuthorityConfig) (nauthilus.BearerIntrospector, error) {
			introspection := authority.Mechanisms.Bearer.Introspection
			mu.Lock()
			clients[introspection.RequiredScope] = introspection.ClientID + "|" + introspection.ClientSecretFile.Value()
			mu.Unlock()

			return noopBearerIntrospector{}, nil
		}),
		WithSessionHandlerFactory(func(SessionOptions) SessionHandler { return &acceptStateHandler{} }),
	)
	if err != nil {
		t.Fatalf("NewManagerWithConfig returned error: %v", err)
	}

	authority := cfg.Auth.Authorities["default"].Mechanisms.Bearer.Introspection
	if got := clients["mail:jmap"]; got != "jmap-introspection|"+secretFile {
		t.Fatalf("JMAP introspection client = %q, want the dedicated client", got)
	}

	if got := clients[authority.RequiredScope]; got != authority.ClientID+"|"+authority.ClientSecretFile.Value() {
		t.Fatalf("IMAP introspection client = %q, want the authority client", got)
	}
}

// TestJMAPListenerRejectsUnreadableIntrospectionSecret fails startup without printing the path.
func TestJMAPListenerRejectsUnreadableIntrospectionSecret(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing-secret")
	cfg := jmapListenerConfig(t)
	entry := cfg.Director.Listeners[testJMAPListener]
	jmap := *entry.JMAP
	jmap.Auth.Bearer.IntrospectionClient = config.JMAPIntrospectionClientConfig{ClientID: "jmap-introspection", ClientSecretFile: config.Secret(missing)}
	entry.JMAP = &jmap
	cfg.Director.Listeners[testJMAPListener] = entry

	_, err := newTestManagerWithConfig(cfg, WithSessionHandlerFactory(func(SessionOptions) SessionHandler { return &acceptStateHandler{} }))
	if err == nil || strings.Contains(err.Error(), missing) {
		t.Fatalf("error = %v, want a path-free startup failure", err)
	}
}
