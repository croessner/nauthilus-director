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

//nolint:funlen,goconst,wsl_v5 // Test fixtures keep the JMAP proxy harness in one reviewable place.
package jmap

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/placement"
	"github.com/croessner/nauthilus-director/internal/routing"
	runtimectl "github.com/croessner/nauthilus-director/internal/runtime"
	"github.com/croessner/nauthilus-director/internal/state"
	jmapbackend "github.com/croessner/nauthilus-director/test/e2e/fakes/jmap_backend"
)

const (
	testAccount        = "alice@example.test"
	testPassword       = "jmap-password-sentinel"
	testToken          = "jmap-bearer-token-sentinel"
	testShardA         = "mailstore-a"
	testShardB         = "mailstore-b"
	testTenant         = "default"
	testListener       = "jmap"
	testPool           = "jmap-default"
	testPublicBaseURL  = "https://mail.example.test"
	testShardAttribute = "mailShard"
)

// testCertificate is one self-signed certificate valid for localhost and 127.0.0.1.
type testCertificate struct {
	certificate tls.Certificate
	pool        *x509.CertPool
	caFile      string
}

// newTestCertificate creates a short-lived loopback certificate and its trust pool.
func newTestCertificate(t *testing.T) testCertificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load key pair: %v", err)
	}

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)

	return testCertificate{certificate: certificate, pool: pool, caFile: caFile}
}

// fakeAuthority implements the Nauthilus password and identity-lookup boundaries.
type fakeAuthority struct {
	mu         sync.Mutex
	attributes map[string][]string
	tempfail   bool
	// lookupAccount overrides the canonical account the identity lookup returns.
	lookupAccount string
	// lookupTempfail makes the identity lookup fail temporarily.
	lookupTempfail bool
	// lookupReject makes the identity lookup report an unknown account.
	lookupReject bool
	authCalls    int
	lookupCalls  int
	lastRequests []nauthilus.RequestContext
}

// Authenticate accepts only the fixture password for the fixture account.
func (f *fakeAuthority) Authenticate(_ context.Context, request nauthilus.AuthRequest) (nauthilus.AuthResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.authCalls++
	f.lastRequests = append(f.lastRequests, request.Context)

	if f.tempfail {
		return nauthilus.AuthResult{Decision: nauthilus.DecisionTemporaryFailure}, errors.New("authority down")
	}

	if request.Context.Username != testAccount || request.Credential.Value() != testPassword {
		return nauthilus.AuthResult{Decision: nauthilus.DecisionRejected}, nil
	}

	return nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: strings.ToUpper(testAccount), Attributes: f.attributes}, nil
}

// LookupIdentity resolves the fixture account without a credential.
func (f *fakeAuthority) LookupIdentity(_ context.Context, request nauthilus.IdentityLookupRequest) (nauthilus.AuthResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.lookupCalls++
	f.lastRequests = append(f.lastRequests, request.Context)

	if f.lookupTempfail {
		return nauthilus.AuthResult{Decision: nauthilus.DecisionTemporaryFailure}, errors.New("authority down")
	}

	if f.lookupReject || request.Context.Username != testAccount {
		return nauthilus.AuthResult{Decision: nauthilus.DecisionRejected}, nil
	}

	account := testAccount
	if f.lookupAccount != "" {
		account = f.lookupAccount
	}

	return nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: account, Attributes: f.attributes}, nil
}

// calls returns authentication and lookup counts.
func (f *fakeAuthority) calls() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.authCalls, f.lookupCalls
}

// fakeIntrospector accepts only the fixture token.
type fakeIntrospector struct {
	calls atomic.Int64
}

// Introspect maps the fixture token to the fixture account without routing attributes.
func (f *fakeIntrospector) Introspect(_ context.Context, request nauthilus.BearerIntrospectionRequest) (nauthilus.AuthResult, error) {
	f.calls.Add(1)

	if request.BearerToken.Value() != testToken || request.Protocol != Protocol {
		return nauthilus.AuthResult{Decision: nauthilus.DecisionRejected}, nil
	}

	return nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: testAccount}, nil
}

// fakePlacer implements the placement boundary over fixed backends per shard.
type fakePlacer struct {
	mu            sync.Mutex
	backends      map[string]backend.Backend
	controlAction atomic.Value
	requestHolds  int
	sessions      int
	open          int
	heartbeats    atomic.Int64
	keys          []state.AffinityKey
}

// PlaceSession opens a counted fake session lease for event streams.
func (p *fakePlacer) PlaceSession(_ context.Context, request placement.Request) (placement.LeaseHandle, error) {
	return p.place(request, true)
}

// PlaceRequestHold opens a fake request hold.
func (p *fakePlacer) PlaceRequestHold(_ context.Context, request placement.Request) (placement.LeaseHandle, error) {
	return p.place(request, false)
}

// place selects the backend of the requested shard.
func (p *fakePlacer) place(request placement.Request, session bool) (placement.LeaseHandle, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	selected, ok := p.backends[request.ShardTag]
	if !ok {
		return nil, &placement.Error{Kind: placement.ErrorKindNoBackend}
	}

	if session {
		p.sessions++
	} else {
		p.requestHolds++
	}

	p.open++
	p.keys = append(p.keys, request.Key)

	return &fakeLease{placer: p, request: request, selected: selected}, nil
}

// openLeases returns the number of leases not yet closed.
func (p *fakePlacer) openLeases() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.open
}

// counts returns request-hold and session-lease counts.
func (p *fakePlacer) counts() (int, int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.requestHolds, p.sessions
}

// fakeLease is one fake placement lease.
type fakeLease struct {
	placer   *fakePlacer
	request  placement.Request
	selected backend.Backend
	once     sync.Once
}

// Affinity returns the affinity key of the lease.
func (l *fakeLease) Affinity() state.AffinityRecord {
	return state.AffinityRecord{Key: l.request.Key, ShardTag: l.request.ShardTag}
}

// AttachBackend is a no-op for the fake.
func (l *fakeLease) AttachBackend(context.Context) error { return nil }

// Backend returns the selected fake backend.
func (l *fakeLease) Backend() backend.SelectionResult {
	return backend.SelectionResult{Backend: l.selected}
}

// Binding returns an empty binding.
func (l *fakeLease) Binding() placement.BackendBinding { return placement.BackendBinding{} }

// Close releases the lease once.
func (l *fakeLease) Close(context.Context) error {
	l.once.Do(func() {
		l.placer.mu.Lock()
		l.placer.open--
		l.placer.mu.Unlock()
	})

	return nil
}

// Heartbeat reports the configured control action.
func (l *fakeLease) Heartbeat(context.Context, time.Duration) (state.AffinityRecord, error) {
	l.placer.heartbeats.Add(1)

	action, _ := l.placer.controlAction.Load().(state.ControlAction)

	return state.AffinityRecord{Key: l.request.Key, ControlAction: action}, nil
}

// SessionID returns the holder identifier.
func (l *fakeLease) SessionID() string { return l.request.SessionID }

// eventCollector records observability events for redaction assertions.
type eventCollector struct {
	mu     sync.Mutex
	events []observability.Event
}

// Record stores one event.
func (c *eventCollector) Record(_ context.Context, event observability.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.events = append(c.events, event)
}

// snapshot returns recorded events.
func (c *eventCollector) snapshot() []observability.Event {
	c.mu.Lock()
	defer c.mu.Unlock()

	return append([]observability.Event(nil), c.events...)
}

// harness is one running JMAP handler with fake authority, placement and backends.
type harness struct {
	t            *testing.T
	handler      *Handler
	address      string
	certificate  testCertificate
	authority    *fakeAuthority
	introspector *fakeIntrospector
	placer       *fakePlacer
	sessions     *runtimectl.LocalSessionRegistry
	events       *eventCollector
	backendA     *jmapbackend.Server
	backendB     *jmapbackend.Server
}

// harnessOptions adjusts the listener settings and authority attributes of one harness.
type harnessOptions struct {
	settings   func(*config.JMAPListenerConfig)
	attributes map[string][]string
	apiDelay   time.Duration
}

// startHarness starts two fake backends and a JMAP handler behind a loopback TLS listener.
func startHarness(t *testing.T, options harnessOptions) *harness {
	t.Helper()

	certificate := newTestCertificate(t)
	backendTLS := &tls.Config{Certificates: []tls.Certificate{certificate.certificate}, MinVersion: tls.VersionTLS12}
	backendA := jmapbackend.Start(t, jmapbackend.Options{Name: "a", TLSConfig: backendTLS, RequireProxyProtocol: true, PublicBaseURL: testPublicBaseURL, APIDelay: options.apiDelay})
	backendB := jmapbackend.Start(t, jmapbackend.Options{Name: "b", TLSConfig: backendTLS, RequireProxyProtocol: true, PublicBaseURL: "https://other.example.test"})

	attributes := options.attributes
	if attributes == nil {
		attributes = map[string][]string{testShardAttribute: {testShardA}}
	}

	settings := config.JMAPListenerConfig{
		PublicBaseURL: testPublicBaseURL,
		HealthPath:    "/director/healthz",
		Auth: config.JMAPAuthConfig{
			Bearer: config.JMAPBearerAuthConfig{Enabled: true, RequiredResource: testPublicBaseURL + "/", RequiredScope: "mail"},
		},
		EventSource: config.JMAPEventSourceConfig{HeartbeatInterval: config.NewDuration(50 * time.Millisecond)},
	}
	if options.settings != nil {
		options.settings(&settings)
	}

	h := &harness{
		t:            t,
		certificate:  certificate,
		authority:    &fakeAuthority{attributes: attributes},
		introspector: &fakeIntrospector{},
		sessions:     runtimectl.NewLocalSessionRegistry(),
		events:       &eventCollector{},
		backendA:     backendA,
		backendB:     backendB,
		placer: &fakePlacer{backends: map[string]backend.Backend{
			testShardA: harnessBackend("mailstore-a-jmap", testShardA, backendA.Address(), certificate.caFile),
			testShardB: harnessBackend("mailstore-b-jmap", testShardB, backendB.Address(), certificate.caFile),
		}},
	}
	h.placer.controlAction.Store(state.ControlActionNone)

	handler, err := NewHandler(Config{
		ListenerName:          testListener,
		AuthorityName:         "default",
		ServiceName:           testListener,
		BackendPool:           testPool,
		DirectorInstanceID:    "director-test",
		DefaultTenant:         testTenant,
		Settings:              settings,
		AuthTimeout:           time.Second,
		BackendConnectTimeout: time.Second,
		SessionLeaseTTL:       time.Minute,
		Authenticator:         h.authority,
		IdentityLookuper:      h.authority,
		BearerIntrospector:    h.introspector,
		RoutingResolver:       mustResolver(t),
		PlacementService:      h.placer,
		LocalSessions:         h.sessions,
		Observability:         h.events,
	})
	if err != nil {
		t.Fatalf("NewHandler returned error: %v", err)
	}

	h.handler = handler
	h.address = h.serveFrontend(certificate)

	return h
}

// harnessBackend describes one fake JMAP backend as a director backend entry.
func harnessBackend(identifier string, shard string, address string, caFile string) backend.Backend {
	return backend.Backend{
		Identifier:  identifier,
		Protocol:    Protocol,
		BackendPool: testPool,
		ShardTag:    shard,
		BackendNode: shard + "-node",
		Address:     address,
		HAProxy:     backend.HAProxyConfig{Enabled: true},
		TLS:         backend.TLSConfig{Mode: "implicit", CAFile: caFile, ServerName: "localhost", MinTLSVersion: "TLS1.2"},
	}
}

// mustResolver builds the production resolver chain with hash fallback.
func mustResolver(t *testing.T) routing.RoutingResolver {
	t.Helper()

	attributes, err := routing.NewAuthAttributeResolver(routing.AuthAttributeResolverConfig{
		TenantAttribute:   "tenant",
		ShardTagAttribute: testShardAttribute,
	})
	if err != nil {
		t.Fatalf("auth attribute resolver: %v", err)
	}

	hash, err := routing.NewHashResolver(routing.HashResolverConfig{ShardTags: []string{testShardA, testShardB}})
	if err != nil {
		t.Fatalf("hash resolver: %v", err)
	}

	chain, err := routing.NewChainResolver(attributes, hash)
	if err != nil {
		t.Fatalf("chain resolver: %v", err)
	}

	return chain
}

// serveFrontend accepts TLS connections and hands each to the handler like the listener does.
func (h *harness) serveFrontend(certificate testCertificate) string {
	h.t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		h.t.Fatalf("listen frontend: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	frontendTLS := &tls.Config{Certificates: []tls.Certificate{certificate.certificate}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}

	var wg sync.WaitGroup

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}

			wg.Go(func() {
				defer func() { _ = conn.Close() }()

				tlsConn := tls.Server(conn, frontendTLS)
				if err := tlsConn.Handshake(); err != nil {
					return
				}

				_ = h.handler.Serve(ctx, tlsConn)
			})
		}
	}()

	h.t.Cleanup(func() {
		_ = ln.Close()
		cancel()
		wg.Wait()
	})

	return ln.Addr().String()
}

// client returns an HTTP client with its own connection pool and records its local addresses.
func (h *harness) client() (*http.Client, *[]string) {
	var (
		mu     sync.Mutex
		locals []string
	)

	dialer := &net.Dialer{}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: h.certificate.pool, ServerName: "localhost", MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, address)
			if err == nil {
				mu.Lock()
				locals = append(locals, conn.LocalAddr().String())
				mu.Unlock()
			}

			return conn, err
		},
		MaxIdleConnsPerHost: 1,
	}
	h.t.Cleanup(transport.CloseIdleConnections)

	return &http.Client{Transport: transport, Timeout: 10 * time.Second}, &locals
}

// url returns the frontend URL for a path.
func (h *harness) url(path string) string {
	return "https://" + h.address + path
}

// assertEventsRedacted fails when any recorded event carries a credential sentinel.
func (h *harness) assertEventsRedacted() {
	h.t.Helper()

	for _, event := range h.events.snapshot() {
		for _, values := range []map[string]string{event.LogFields, event.MetricLabels} {
			for name, value := range values {
				for _, secret := range []string{testPassword, testToken, "Basic ", "Bearer ", testAccount} {
					if strings.Contains(value, secret) || strings.Contains(name, secret) {
						h.t.Fatalf("event %s field %s leaked a credential or account", event.Name, name)
					}
				}
			}
		}
	}
}
