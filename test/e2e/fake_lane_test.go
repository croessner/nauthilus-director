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

//nolint:funlen,goconst,wsl_v5 // E2E fixtures keep the public socket transcript visible.
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/listener"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/protocol/imap"
	"github.com/croessner/nauthilus-director/internal/proxy"
	"github.com/croessner/nauthilus-director/internal/routing"
	"github.com/croessner/nauthilus-director/internal/state"
	"github.com/redis/go-redis/v9"
)

const (
	e2eAccount       = "alice@example.test"
	e2eBackendPool   = "imap-default"
	e2eListenerName  = "imap"
	e2ePassword      = "e2e-secret-password"
	e2eProtocol      = "imap"
	e2eService       = "imap"
	e2eShardTag      = "mailstore-a"
	e2eTenant        = "default"
	e2eToken         = "e2e-bearer-token"
	fakeBackendReady = "* OK fake IMAP backend ready\r\n"
)

// TestFakeHTTPAuthorityPublicIMAPFlow proves the guardrail lane uses public sockets.
func TestFakeHTTPAuthorityPublicIMAPFlow(t *testing.T) {
	recorder := newCapturedRecorder()
	authority := startFakeHTTPAuthority(t, map[string][]string{
		"account":   {e2eAccount},
		"tenant":    {e2eTenant},
		"mailShard": {e2eShardTag},
	})
	fakeBackend := startFakeIMAPBackend(t, fakeBackendOptions{})
	authenticator := newHTTPAuthenticator(t, authority.URL())

	director := startDirector(t, directorOptions{
		Authenticator:  authenticator,
		BackendAuth:    masterUserBackendAuth(),
		BackendAddress: fakeBackend.Address(),
		Recorder:       recorder,
		TLSMode:        imap.TLSModeStartTLS,
	})
	defer director.Stop(t)

	client := dialPlain(t, director.Address())
	defer func() { _ = client.Close() }()

	reader := bufio.NewReader(client)
	expectLine(t, reader, "* OK nauthilus-director IMAP session ready\r\n")
	writeLine(t, client, `A001 ID ("client_id" "e2e-client")`)
	expectLine(t, reader, "* ID NIL\r\n")
	expectLine(t, reader, "A001 OK ID completed\r\n")
	writeLine(t, client, `A002 LOGIN "`+e2eAccount+`" "`+e2ePassword+`"`)
	expectLine(t, reader, "A002 OK Authentication completed\r\n")
	writeLine(t, client, "A003 NOOP")
	expectLine(t, reader, "A003 OK backend noop\r\n")

	authority.ExpectRequest(t, "imap", "login", "e2e-client")
	fakeBackend.ExpectProxyLine(t, "A003 NOOP")
	recorder.AssertSafe(t)
	recorder.ExpectEvents(t,
		observability.EventSessionStart,
		observability.EventNauthilusAuth,
		observability.EventRoutingResolve,
		observability.EventAffinityOpen,
		observability.EventBackendSelect,
		observability.EventBackendConnect,
		observability.EventBackendAuth,
		observability.EventProxyPipe,
		observability.EventSessionEnd,
	)
}

// TestFakeHTTPAuthorityUsesRedisLeaseStore proves active affinity through Redis-compatible state.
func TestFakeHTTPAuthorityUsesRedisLeaseStore(t *testing.T) {
	fixture := startValkeySessionStore(t)
	authority := startFakeHTTPAuthority(t, map[string][]string{
		"account":   {e2eAccount},
		"tenant":    {e2eTenant},
		"mailShard": {e2eShardTag},
	})
	fakeBackend := startFakeIMAPBackend(t, fakeBackendOptions{})

	director := startDirector(t, directorOptions{
		Authenticator:  newHTTPAuthenticator(t, authority.URL()),
		BackendAuth:    masterUserBackendAuth(),
		BackendAddress: fakeBackend.Address(),
		Recorder:       newCapturedRecorder(),
		SessionStore:   fixture.store,
		TLSMode:        imap.TLSModeStartTLS,
	})
	defer director.Stop(t)

	client := dialPlain(t, director.Address())
	defer func() { _ = client.Close() }()

	reader := bufio.NewReader(client)
	expectLine(t, reader, "* OK nauthilus-director IMAP session ready\r\n")
	writeLine(t, client, `A001 LOGIN "`+e2eAccount+`" "`+e2ePassword+`"`)
	expectLine(t, reader, "A001 OK Authentication completed\r\n")

	key := state.AffinityKey{Tenant: e2eTenant, AccountKey: e2eAccount}
	expectAffinityPresent(t, fixture.store, key, 1)

	writeLine(t, client, "A002 NOOP")
	expectLine(t, reader, "A002 OK backend noop\r\n")
	fakeBackend.ExpectProxyLine(t, "A002 NOOP")
	_ = client.Close()

	expectAffinityReleased(t, fixture.store, key)
}

// TestFakeGRPCAuthorityPublicIMAPFlow covers the scaffolded gRPC authority path.
func TestFakeGRPCAuthorityPublicIMAPFlow(t *testing.T) {
	service := &fakeGRPCService{}
	authenticator, err := nauthilus.NewGRPCClient(service)
	if err != nil {
		t.Fatalf("NewGRPCClient: %v", err)
	}

	fakeBackend := startFakeIMAPBackend(t, fakeBackendOptions{})
	director := startDirector(t, directorOptions{
		Authenticator:  authenticator,
		BackendAuth:    credentialReplayBackendAuth(false),
		BackendAddress: fakeBackend.Address(),
		Recorder:       newCapturedRecorder(),
		TLSMode:        imap.TLSModeStartTLS,
	})
	defer director.Stop(t)

	client := dialPlain(t, director.Address())
	defer func() { _ = client.Close() }()

	reader := bufio.NewReader(client)
	expectLine(t, reader, "* OK nauthilus-director IMAP session ready\r\n")
	writeLine(t, client, `A001 LOGIN "`+e2eAccount+`" "`+e2ePassword+`"`)
	expectLine(t, reader, "A001 OK Authentication completed\r\n")
	writeLine(t, client, "A002 NOOP")
	expectLine(t, reader, "A002 OK backend noop\r\n")

	if service.AuthCalls() != 1 {
		t.Fatalf("gRPC auth calls = %d, want 1", service.AuthCalls())
	}
	fakeBackend.ExpectProxyLine(t, "A002 NOOP")
}

// TestPublicSTARTTLSAndImplicitTLSSockets verifies frontend TLS handshakes with test certificates.
func TestPublicSTARTTLSAndImplicitTLSSockets(t *testing.T) {
	certPath, keyPath, certificate := writeTestCertificate(t)

	starttlsDirector := startDirector(t, directorOptions{
		Authenticator:      unavailableAuthenticator{},
		BackendAuth:        masterUserBackendAuth(),
		BackendAddress:     "127.0.0.1:1",
		FrontendTLSConfig:  &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12},
		ListenerCertPath:   certPath,
		ListenerKeyPath:    keyPath,
		Recorder:           newCapturedRecorder(),
		TLSMode:            imap.TLSModeStartTLS,
		UsePlacementStubs:  true,
		UseProxyRunnerStub: true,
	})
	defer starttlsDirector.Stop(t)

	plain := dialPlain(t, starttlsDirector.Address())
	defer func() { _ = plain.Close() }()
	plainReader := bufio.NewReader(plain)
	expectLine(t, plainReader, "* OK nauthilus-director IMAP session ready\r\n")
	writeLine(t, plain, "A001 STARTTLS")
	expectLine(t, plainReader, "A001 OK Begin TLS negotiation now\r\n")

	tlsClient := tls.Client(plain, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("STARTTLS client handshake: %v", err)
	}
	tlsReader := bufio.NewReader(tlsClient)
	writeLine(t, tlsClient, "A002 CAPABILITY")
	line := readLine(t, tlsReader)
	if strings.Contains(line, "STARTTLS") {
		t.Fatalf("post-STARTTLS capabilities still advertise STARTTLS: %q", line)
	}
	expectLine(t, tlsReader, "A002 OK CAPABILITY completed\r\n")

	implicitDirector := startDirector(t, directorOptions{
		Authenticator:     unavailableAuthenticator{},
		BackendAuth:       masterUserBackendAuth(),
		BackendAddress:    "127.0.0.1:1",
		ListenerCertPath:  certPath,
		ListenerKeyPath:   keyPath,
		Recorder:          newCapturedRecorder(),
		TLSMode:           imap.TLSModeImplicit,
		UsePlacementStubs: true,
	})
	defer implicitDirector.Stop(t)

	implicit := dialTLS(t, implicitDirector.Address())
	defer func() { _ = implicit.Close() }()
	expectLine(t, bufio.NewReader(implicit), "* OK nauthilus-director IMAP session ready\r\n")
}

type directorOptions struct {
	Authenticator      nauthilus.Authenticator
	BackendAuth        backend.AuthConfig
	BackendAddress     string
	BackendTLS         config.BackendTLSConfig
	FrontendTLSConfig  *tls.Config
	ListenerCertPath   string
	ListenerKeyPath    string
	Recorder           observability.Recorder
	SessionStore       state.SessionStore
	TLSMode            string
	UsePlacementStubs  bool
	UseProxyRunnerStub bool
}

type directorInstance struct {
	address string
	manager *listener.Manager
}

// Address returns the public listener address for clients.
func (d directorInstance) Address() string {
	return d.address
}

// Stop shuts down the public listener.
func (d directorInstance) Stop(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := d.manager.Stop(ctx); err != nil {
		t.Fatalf("stop director: %v", err)
	}
}

// startDirector starts the production listener/session stack on public sockets.
func startDirector(t *testing.T, options directorOptions) directorInstance {
	t.Helper()

	cfg := e2eConfig(options)
	store := options.SessionStore
	if store == nil {
		store = newMemorySessionStore()
	}
	resolver := mustRoutingResolver(t)
	selector := mustBackendSelector(t, cfg)
	proxyRunner := proxy.Runner(proxy.NewPipe())
	if options.UseProxyRunnerStub {
		proxyRunner = stubProxyRunner{}
	}

	manager, err := listener.NewManagerWithConfig(
		cfg,
		listener.WithNauthilusClientFactory(func(config.AuthorityConfig) (nauthilus.Authenticator, error) {
			return options.Authenticator, nil
		}),
		listener.WithObservabilityRecorder(options.Recorder),
		listener.WithSessionHandlerFactory(func(listenerOptions listener.SessionOptions) listener.SessionHandler {
			sessionConfig := imap.SessionConfig{
				ListenerName:           listenerOptions.ListenerName,
				AuthorityName:          listenerOptions.Config.Authority,
				ServiceName:            listenerOptions.Config.ServiceName,
				Network:                listenerOptions.Config.Network,
				BackendPool:            listenerOptions.Config.BackendPool,
				DirectorInstanceID:     listenerOptions.DirectorInstanceID,
				DefaultTenant:          e2eTenant,
				TLSMode:                listenerOptions.Config.TLS.Mode,
				Capabilities:           listenerOptions.Config.IMAP.Capabilities,
				AuthMechanisms:         listenerOptions.Config.IMAP.AuthMechanisms,
				MaxBearerTokenBytes:    listenerOptions.BearerTokenMaxBytes,
				SessionLeaseTTL:        time.Second,
				SessionIdleGrace:       0,
				PreauthTimeout:         time.Second,
				AuthTimeout:            time.Second,
				BackendConnectTimeout:  time.Second,
				ProxyIdleTimeout:       time.Second,
				MaxPreauthLineBytes:    8192,
				MaxPreauthLiteralBytes: 16,
				FrontendTLSConfig:      options.FrontendTLSConfig,
				Authenticator:          listenerOptions.Authenticator,
				RoutingResolver:        resolver,
				SessionStore:           store,
				BackendSelector:        selector,
				BackendConnector:       imap.NewTCPBackendConnector(nil),
				ProxyRunner:            proxyRunner,
				Observability:          options.Recorder,
			}
			if options.UsePlacementStubs {
				sessionConfig.RoutingResolver = nil
				sessionConfig.SessionStore = nil
				sessionConfig.BackendSelector = nil
			}

			return imap.NewHandler(sessionConfig)
		}),
	)
	if err != nil {
		t.Fatalf("NewManagerWithConfig: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := manager.Start(ctx); err != nil {
		t.Fatalf("start director: %v", err)
	}

	address, ok := manager.BoundAddress(e2eListenerName)
	if !ok {
		t.Fatal("director did not expose bound IMAP address")
	}

	return directorInstance{address: address, manager: manager}
}

// e2eConfig builds a narrow typed config for one public IMAP listener and backend.
func e2eConfig(options directorOptions) config.Config {
	cfg := config.DefaultConfig()
	listenerConfig := cfg.Director.Listeners[e2eListenerName]
	listenerConfig.Address = "127.0.0.1:0"
	listenerConfig.TLS.Mode = options.TLSMode
	listenerConfig.TLS.Cert = options.ListenerCertPath
	listenerConfig.TLS.Key = config.Secret(options.ListenerKeyPath)
	listenerConfig.IMAP.Capabilities = []string{"IMAP4rev1", "ID", "SASL-IR", "STARTTLS", "AUTH=PLAIN", "AUTH=XOAUTH2", "AUTH=OAUTHBEARER"}
	listenerConfig.IMAP.AuthMechanisms = []string{"plain", "xoauth2", "oauthbearer"}
	cfg.Director.Listeners = map[string]config.ListenerConfig{e2eListenerName: listenerConfig}

	cfg.Director.BackendPools = map[string]config.BackendPoolConfig{
		e2eBackendPool: {
			Protocol: "imap",
			Selector: "rendezvous_hash",
			Backends: []string{"mailstore-a-imap"},
		},
	}
	backendTLS := options.BackendTLS
	if strings.TrimSpace(backendTLS.Mode) == "" {
		backendTLS = config.BackendTLSConfig{
			Mode:          "plaintext",
			MinTLSVersion: "TLS1.2",
		}
	}
	cfg.Director.Backends = map[string]config.BackendConfig{
		"mailstore-a-imap": {
			Protocol:       "imap",
			ShardTag:       e2eShardTag,
			Address:        options.BackendAddress,
			Weight:         100,
			MaxConnections: 100,
			Maintenance:    "disabled",
			TLS:            backendTLS,
			Auth:           backendAuthConfig(options.BackendAuth),
			HealthCheck: config.BackendHealthConfig{
				Enabled: false,
			},
		},
	}

	return cfg
}

// backendAuthConfig maps backend-domain auth settings back into typed config.
func backendAuthConfig(auth backend.AuthConfig) config.BackendAuthConfig {
	return config.BackendAuthConfig{
		Mode: auth.Mode,
		MasterUser: config.BackendMasterUserConfig{
			Username:     auth.MasterUser.Username,
			PasswordFile: auth.MasterUser.Password,
			UserFormat:   auth.MasterUser.UserFormat,
			Mechanism:    auth.MasterUser.Mechanism,
		},
		CredentialReplay: config.BackendCredentialReplayConfig{
			RequireBackendTLS: auth.CredentialReplay.RequireBackendTLS,
			PreserveMechanism: auth.CredentialReplay.PreserveMechanism,
			AllowedMechanisms: auth.CredentialReplay.AllowedMechanisms,
		},
	}
}

// masterUserBackendAuth returns the safe default backend auth mode.
func masterUserBackendAuth() backend.AuthConfig {
	return backend.AuthConfig{
		Mode: "master_user",
		MasterUser: backend.MasterUserConfig{
			Username:   "director-master",
			Password:   config.Secret("backend-master-secret"),
			UserFormat: "{user}*{master_user}",
			Mechanism:  "plain",
		},
	}
}

// credentialReplayBackendAuth returns an explicit test replay backend mode.
func credentialReplayBackendAuth(requireTLS bool) backend.AuthConfig {
	return backend.AuthConfig{
		Mode: "credential_replay",
		CredentialReplay: backend.CredentialReplayConfig{
			RequireBackendTLS: requireTLS,
			PreserveMechanism: true,
			AllowedMechanisms: []string{"plain", "login", "xoauth2", "oauthbearer"},
		},
	}
}

// mustBackendSelector creates the production static backend selector for E2E.
func mustBackendSelector(t *testing.T, cfg config.Config) backend.Selector {
	t.Helper()

	registry, err := backend.NewStaticRegistry(cfg.Director)
	if err != nil {
		t.Fatalf("NewStaticRegistry: %v", err)
	}
	selector, err := backend.NewStaticSelector(registry, backend.SelectionPolicy{SoftAllowsActivePins: true})
	if err != nil {
		t.Fatalf("NewStaticSelector: %v", err)
	}

	return selector
}

// mustRoutingResolver creates the production routing chain used by the fake lane.
func mustRoutingResolver(t *testing.T) routing.RoutingResolver {
	t.Helper()

	authResolver, err := routing.NewAuthAttributeResolver(routing.AuthAttributeResolverConfig{
		AccountKeyAttribute: "account",
		TenantAttribute:     "tenant",
		ShardTagAttribute:   "mailShard",
		Sticky:              true,
	})
	if err != nil {
		t.Fatalf("NewAuthAttributeResolver: %v", err)
	}
	hashResolver, err := routing.NewHashResolver(routing.HashResolverConfig{
		ShardTags: []string{e2eShardTag},
		Sticky:    true,
	})
	if err != nil {
		t.Fatalf("NewHashResolver: %v", err)
	}
	chain, err := routing.NewChainResolver(authResolver, hashResolver)
	if err != nil {
		t.Fatalf("NewChainResolver: %v", err)
	}

	return chain
}

type redisSessionFixture struct {
	store *state.RedisSessionStore
}

// startValkeySessionStore starts a Redis-compatible server for public-socket E2E state.
func startValkeySessionStore(t *testing.T) redisSessionFixture {
	t.Helper()

	path, err := exec.LookPath("valkey-server")
	if err != nil {
		t.Skip("valkey-server is required for Redis-compatible e2e affinity")
	}

	port := reserveLoopbackPort(t)
	var output bytes.Buffer
	cmd := exec.Command(
		path,
		"--bind", "127.0.0.1",
		"--port", strconv.Itoa(port),
		"--save", "",
		"--appendonly", "no",
		"--dir", t.TempDir(),
		"--loglevel", "warning",
	)
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start valkey-server: %v", err)
	}

	client := redis.NewClient(&redis.Options{Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), Protocol: 2})
	t.Cleanup(func() {
		_ = client.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	})

	waitForRedis(t, client, &output)

	builder, err := state.NewKeyBuilder(state.KeyBuilderOptions{Prefix: "nauthilus-director-e2e", SchemaVersion: 1})
	if err != nil {
		t.Fatalf("NewKeyBuilder: %v", err)
	}
	store, err := state.NewRedisSessionStore(client, builder, nil)
	if err != nil {
		t.Fatalf("NewRedisSessionStore: %v", err)
	}

	return redisSessionFixture{store: store}
}

// reserveLoopbackPort reserves and releases one local TCP port for a child server.
func reserveLoopbackPort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve valkey port: %v", err)
	}
	defer func() { _ = listener.Close() }()

	return listener.Addr().(*net.TCPAddr).Port
}

// waitForRedis waits until the Redis-compatible test service accepts commands.
func waitForRedis(t *testing.T, client *redis.Client, output *bytes.Buffer) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		err := client.Ping(ctx).Err()
		cancel()
		if err == nil {
			return
		}

		time.Sleep(25 * time.Millisecond)
	}

	t.Fatalf("valkey-server did not become ready: %s", output.String())
}

// expectAffinityPresent waits for an active Redis-backed affinity record.
func expectAffinityPresent(t *testing.T, store state.AffinityStore, key state.AffinityKey, activeCount int) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		record, err := store.LookupAffinity(context.Background(), key)
		if err == nil && record.Present && record.ShardTag == e2eShardTag && record.ActiveSessionCount == activeCount {
			return
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("affinity %v was not present with %d active session(s)", key, activeCount)
}

// expectAffinityReleased waits for the active Redis-backed affinity to disappear.
func expectAffinityReleased(t *testing.T, store state.AffinityStore, key state.AffinityKey) {
	t.Helper()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		record, err := store.LookupAffinity(context.Background(), key)
		if err == nil && !record.Present {
			return
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("affinity %v was not released", key)
}

type fakeHTTPAuthority struct {
	server       *http.Server
	listener     net.Listener
	attributes   map[string][]string
	requests     []map[string]any
	requestsLock sync.Mutex
}

// startFakeHTTPAuthority starts a public HTTP auth socket.
func startFakeHTTPAuthority(t *testing.T, attributes map[string][]string) *fakeHTTPAuthority {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake HTTP authority: %v", err)
	}
	fake := &fakeHTTPAuthority{listener: ln, attributes: attributes}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/json", fake.handle)
	fake.server = &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}

	go func() {
		_ = fake.server.Serve(ln)
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = fake.server.Shutdown(ctx)
	})

	return fake
}

// URL returns the fake authority endpoint.
func (f *fakeHTTPAuthority) URL() string {
	return "http://" + f.listener.Addr().String() + "/api/v1/auth/json"
}

// ExpectRequest verifies the fake authority saw the expected safe context.
func (f *fakeHTTPAuthority) ExpectRequest(t *testing.T, protocol string, method string, clientID string) {
	t.Helper()

	f.requestsLock.Lock()
	defer f.requestsLock.Unlock()

	if len(f.requests) != 1 {
		t.Fatalf("fake authority requests = %d, want 1", len(f.requests))
	}
	request := f.requests[0]
	if request["protocol"] != protocol || request["method"] != method || request["client_id"] != clientID {
		t.Fatalf("fake authority request = %#v", request)
	}
	for _, forbidden := range []string{"backend_identifier", "listener", "session_id", "routing_hint"} {
		if _, ok := request[forbidden]; ok {
			t.Fatalf("fake authority received forbidden field %q: %#v", forbidden, request)
		}
	}
}

// handle maps one JSON auth request into a successful Nauthilus-shaped response.
func (f *fakeHTTPAuthority) handle(writer http.ResponseWriter, request *http.Request) {
	var body map[string]any
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		http.Error(writer, "bad request", http.StatusBadRequest)

		return
	}

	f.requestsLock.Lock()
	f.requests = append(f.requests, body)
	f.requestsLock.Unlock()

	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"ok":            true,
		"account_field": e2eAccount,
		"attributes":    f.attributes,
	})
}

// newHTTPAuthenticator creates the real HTTP authority client used by IMAP sessions.
func newHTTPAuthenticator(t *testing.T, endpoint string) nauthilus.Authenticator {
	t.Helper()

	client, err := nauthilus.NewHTTPClient(nauthilus.HTTPClientConfig{
		Endpoint:    endpoint,
		ContentType: "application/json",
	})
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}

	return client
}

type fakeGRPCService struct {
	mu    sync.Mutex
	calls int
}

// Authenticate records one scaffolded gRPC auth request.
func (s *fakeGRPCService) Authenticate(_ context.Context, request *nauthilus.GRPCAuthRequest) (*nauthilus.GRPCAuthResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.calls++
	return &nauthilus.GRPCAuthResponse{
		OK:           true,
		Decision:     nauthilus.GRPCDecisionOK,
		AccountField: request.Username,
		Attributes: map[string][]string{
			"account":   {request.Username},
			"tenant":    {e2eTenant},
			"mailShard": {e2eShardTag},
		},
	}, nil
}

// LookupIdentity returns a temporary failure because route lookup must not call it.
func (s *fakeGRPCService) LookupIdentity(context.Context, *nauthilus.GRPCLookupIdentityRequest) (*nauthilus.GRPCAuthResponse, error) {
	return &nauthilus.GRPCAuthResponse{Decision: nauthilus.GRPCDecisionTempFail}, nil
}

// ListAccounts returns an empty account list for unused gRPC surface.
func (s *fakeGRPCService) ListAccounts(context.Context, *nauthilus.GRPCListAccountsRequest) (*nauthilus.GRPCListAccountsResponse, error) {
	return &nauthilus.GRPCListAccountsResponse{Decision: nauthilus.GRPCDecisionOK}, nil
}

// AuthCalls returns the number of authentication requests.
func (s *fakeGRPCService) AuthCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.calls
}

type fakeBackendOptions struct {
	TLSConfig *tls.Config
	TLSMode   string
}

type fakeIMAPBackend struct {
	listener     net.Listener
	observations chan fakeBackendObservation
	options      fakeBackendOptions
}

type fakeBackendObservation struct {
	authLine  string
	proxyLine string
}

// startFakeIMAPBackend starts a public fake IMAP backend socket.
func startFakeIMAPBackend(t *testing.T, options fakeBackendOptions) *fakeIMAPBackend {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake backend: %v", err)
	}
	backend := &fakeIMAPBackend{
		listener:     ln,
		observations: make(chan fakeBackendObservation, 8),
		options:      options,
	}

	go backend.accept()
	t.Cleanup(func() {
		_ = ln.Close()
	})

	return backend
}

// Address returns the public fake backend address.
func (b *fakeIMAPBackend) Address() string {
	return b.listener.Addr().String()
}

// ExpectProxyLine verifies backend auth reached transparent proxy mode.
func (b *fakeIMAPBackend) ExpectProxyLine(t *testing.T, want string) {
	t.Helper()

	select {
	case observation := <-b.observations:
		if strings.TrimSpace(observation.proxyLine) != want {
			t.Fatalf("backend proxy line = %q, want %q", observation.proxyLine, want)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for fake backend observation")
	}
}

// accept serves backend connections until the listener closes.
func (b *fakeIMAPBackend) accept() {
	for {
		conn, err := b.listener.Accept()
		if err != nil {
			return
		}

		go b.serve(conn)
	}
}

// serve executes a minimal IMAP backend auth and proxy script.
func (b *fakeIMAPBackend) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	var ok bool
	conn, ok = b.prepareBackendConn(conn)
	if !ok {
		return
	}

	reader := bufio.NewReader(conn)
	_, _ = io.WriteString(conn, fakeBackendReady)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}

		var done bool
		conn, reader, done = b.handleBackendLine(conn, reader, line)
		if done {
			return
		}
	}
}

// prepareBackendConn applies implicit TLS when the fake backend is configured for it.
func (b *fakeIMAPBackend) prepareBackendConn(conn net.Conn) (net.Conn, bool) {
	if b.options.TLSMode == imap.TLSModeImplicit && b.options.TLSConfig != nil {
		tlsConn := tls.Server(conn, b.options.TLSConfig.Clone())
		if err := tlsConn.Handshake(); err != nil {
			return conn, false
		}

		conn = tlsConn
	}

	return conn, true
}

// handleBackendLine dispatches one minimal fake backend command.
func (b *fakeIMAPBackend) handleBackendLine(conn net.Conn, reader *bufio.Reader, line string) (net.Conn, *bufio.Reader, bool) {
	tag, command, _ := strings.Cut(strings.TrimSpace(line), " ")
	upper := strings.ToUpper(command)

	switch {
	case strings.HasPrefix(upper, "STARTTLS") && b.options.TLSConfig != nil:
		return b.handleBackendStartTLS(conn, tag)
	case strings.HasPrefix(upper, "CAPABILITY"):
		_, _ = io.WriteString(conn, "* CAPABILITY IMAP4rev1 AUTH=PLAIN AUTH=LOGIN AUTH=XOAUTH2 AUTH=OAUTHBEARER\r\n")
		_, _ = io.WriteString(conn, tag+" OK capability completed\r\n")
	case strings.HasPrefix(upper, "LOGIN") || strings.HasPrefix(upper, "AUTHENTICATE"):
		return conn, reader, b.handleBackendAuth(conn, reader, tag, line)
	default:
		_, _ = io.WriteString(conn, tag+" BAD unsupported\r\n")
	}

	return conn, reader, false
}

// handleBackendStartTLS upgrades the fake backend stream.
func (b *fakeIMAPBackend) handleBackendStartTLS(conn net.Conn, tag string) (net.Conn, *bufio.Reader, bool) {
	_, _ = io.WriteString(conn, tag+" OK begin TLS\r\n")
	tlsConn := tls.Server(conn, b.options.TLSConfig.Clone())
	if err := tlsConn.Handshake(); err != nil {
		return conn, bufio.NewReader(conn), true
	}

	return tlsConn, bufio.NewReader(tlsConn), false
}

// handleBackendAuth accepts backend auth and records the first proxied command.
func (b *fakeIMAPBackend) handleBackendAuth(conn net.Conn, reader *bufio.Reader, tag string, authLine string) bool {
	_, _ = io.WriteString(conn, tag+" OK backend auth completed\r\n")
	proxyLine, err := reader.ReadString('\n')
	if err != nil {
		return true
	}

	proxyTag, _, _ := strings.Cut(strings.TrimSpace(proxyLine), " ")
	_, _ = io.WriteString(conn, proxyTag+" OK backend noop\r\n")
	b.observations <- fakeBackendObservation{authLine: authLine, proxyLine: proxyLine}

	return true
}

type memorySessionStore struct {
	mu          sync.Mutex
	records     map[state.AffinityKey]state.AffinityRecord
	counts      map[state.AffinityKey]int
	attachments map[string]state.SessionBackendAttachment
}

// newMemorySessionStore creates deterministic lease semantics for the fake lane.
func newMemorySessionStore() *memorySessionStore {
	return &memorySessionStore{
		records:     make(map[state.AffinityKey]state.AffinityRecord),
		counts:      make(map[state.AffinityKey]int),
		attachments: make(map[string]state.SessionBackendAttachment),
	}
}

// OpenSession creates or reuses an active shard pin.
func (s *memorySessionStore) OpenSession(_ context.Context, record state.SessionRecord) (state.AffinityRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	current, ok := s.records[record.Key]
	if !ok {
		current = state.AffinityRecord{Key: record.Key, ShardTag: record.ShardTag, Status: "created", Present: true}
		s.records[record.Key] = current
	} else {
		current.Status = "reused"
	}
	s.counts[record.Key]++
	current.ActiveSessionCount = s.counts[record.Key]
	s.records[record.Key] = current

	return current, nil
}

// AttachSelectedBackend records selected-backend metadata for fake-lane sessions.
func (s *memorySessionStore) AttachSelectedBackend(
	_ context.Context,
	attachment state.SessionBackendAttachment,
) (state.SessionBackendRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.attachments[attachment.SessionID] = attachment

	return state.SessionBackendRecord{
		Status:             "attached",
		BackendIdentifier:  attachment.BackendIdentifier,
		BackendActiveCount: len(s.attachments),
	}, nil
}

// HeartbeatSession refreshes an active in-memory lease.
func (s *memorySessionStore) HeartbeatSession(_ context.Context, key state.AffinityKey, _ string, _ time.Duration) (state.AffinityRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.records[key], nil
}

// CloseSession releases an active in-memory lease.
func (s *memorySessionStore) CloseSession(_ context.Context, key state.AffinityKey, sessionID string) (state.AffinityRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.attachments, sessionID)

	current := s.records[key]
	if s.counts[key] > 0 {
		s.counts[key]--
	}
	current.ActiveSessionCount = s.counts[key]
	if current.ActiveSessionCount == 0 {
		current.Status = "released"
		delete(s.records, key)
	} else {
		current.Status = "closed"
		s.records[key] = current
	}

	return current, nil
}

type capturedRecorder struct {
	mu     sync.Mutex
	events []observability.Event
}

// newCapturedRecorder creates an in-memory event sink for assertions.
func newCapturedRecorder() *capturedRecorder {
	return &capturedRecorder{}
}

// Record stores one normalized event.
func (r *capturedRecorder) Record(_ context.Context, event observability.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.events = append(r.events, event)
}

// AssertSafe checks secret safety and label policy for every captured event.
func (r *capturedRecorder) AssertSafe(t *testing.T) {
	t.Helper()

	for _, event := range r.snapshot() {
		for key, value := range event.LogFields {
			if strings.Contains(value, e2ePassword) || strings.Contains(value, e2eToken) {
				t.Fatalf("event %s log field %s leaked secret value %q", event.Name, key, value)
			}
		}
		if err := event.MetricLabels.Validate(); err != nil {
			t.Fatalf("event %s has invalid metric labels: %v", event.Name, err)
		}
		for _, forbidden := range observability.ForbiddenMetricLabels() {
			if _, ok := event.MetricLabels[forbidden]; ok {
				t.Fatalf("event %s has forbidden metric label %q", event.Name, forbidden)
			}
		}
	}
}

// ExpectEvents checks that required event names were observed at least once.
func (r *capturedRecorder) ExpectEvents(t *testing.T, names ...string) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for {
		seen := map[string]bool{}
		for _, event := range r.snapshot() {
			seen[event.Name] = true
		}

		missing := ""
		for _, name := range names {
			if !seen[name] {
				missing = name
				break
			}
		}
		if missing == "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("event %s was not recorded; seen=%v", missing, seen)
		}

		time.Sleep(10 * time.Millisecond)
	}
}

// snapshot returns a detached event slice.
func (r *capturedRecorder) snapshot() []observability.Event {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]observability.Event(nil), r.events...)
}

type unavailableAuthenticator struct{}

// Authenticate returns a temporary failure for TLS-only E2E sessions.
func (unavailableAuthenticator) Authenticate(context.Context, nauthilus.AuthRequest) (nauthilus.AuthResult, error) {
	return nauthilus.AuthResult{Decision: nauthilus.DecisionTemporaryFailure}, nil
}

type stubProxyRunner struct{}

// Run closes the streams for tests that do not enter real proxy mode.
func (stubProxyRunner) Run(_ context.Context, pipeConfig proxy.PipeConfig) (proxy.Result, error) {
	_ = pipeConfig.Frontend.Close()
	_ = pipeConfig.Backend.Close()

	return proxy.Result{Class: proxy.ResultClientClosed}, nil
}

// dialPlain connects to one public TCP listener.
func dialPlain(t *testing.T, address string) net.Conn {
	t.Helper()

	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", address, err)
	}

	return conn
}

// dialTLS connects to one public TLS listener.
func dialTLS(t *testing.T, address string) net.Conn {
	t.Helper()

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("dial TLS %s: %v", address, err)
	}

	return conn
}

// writeLine writes one CRLF-terminated IMAP line.
func writeLine(t *testing.T, writer io.Writer, line string) {
	t.Helper()

	if _, err := io.WriteString(writer, line+"\r\n"); err != nil {
		t.Fatalf("write line %q: %v", line, err)
	}
}

// readLine reads one CRLF-terminated IMAP line.
func readLine(t *testing.T, reader *bufio.Reader) string {
	t.Helper()

	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read line: %v", err)
	}

	return line
}

// expectLine asserts one exact IMAP response line.
func expectLine(t *testing.T, reader *bufio.Reader, want string) {
	t.Helper()

	if got := readLine(t, reader); got != want {
		t.Fatalf("line = %q, want %q", got, want)
	}
}

// writeTestCertificate writes a localhost certificate usable by listener tests.
func writeTestCertificate(t *testing.T) (string, string, tls.Certificate) {
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
	certPath := writeTempFile(t, "e2e-listener-*.crt", certPEM)
	keyPath := writeTempFile(t, "e2e-listener-*.key", keyPEM)
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}

	return certPath, keyPath, certificate
}

// writeTempFile writes a temporary fixture file.
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
