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

//nolint:funlen,goconst,wsl_v5 // Pipeline tests keep IMAP transcripts and fake call assertions together.
package imap

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/proxy"
	"github.com/croessner/nauthilus-director/internal/routing"
	"github.com/croessner/nauthilus-director/internal/state"
)

// TestIMAPHTTPAuthBodyUsesProtocolAndClientID verifies IMAP auth reaches the HTTP authority safely.
func TestIMAPHTTPAuthBodyUsesProtocolAndClientID(t *testing.T) {
	var captured map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/auth/json" {
			t.Fatalf("path = %q, want /api/v1/auth/json", request.URL.Path)
		}

		if got := request.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("content type = %q, want application/json", got)
		}

		if err := json.NewDecoder(request.Body).Decode(&captured); err != nil {
			t.Fatalf("decode auth body: %v", err)
		}

		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"ok":true,"account_field":"alice@example.test","attributes":{"account":["alice@example.test"],"tenant":["` + defaultTenantName + `"],"mailShard":["mailstore-a"]}}`))
	}))
	defer server.Close()

	authenticator, err := nauthilus.NewHTTPClient(nauthilus.HTTPClientConfig{
		Endpoint:    server.URL + "/api/v1/auth/json",
		ContentType: "application/json",
	})
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}

	store := &recordingSessionStore{result: state.AffinityRecord{ShardTag: "mailstore-a"}}
	selector := &recordingBackendSelector{result: backend.SelectionResult{Backend: backend.Backend{Identifier: "mailstore-a-imap"}}}
	harness := startTestSession(t, pipelineSessionConfig(authenticator, mustPipelineChain(t), store, selector))
	harness.expectLine(t, greetingLine)

	harness.write(t, `A001 ID ("client_id" "director-test-client")`+"\r\n")
	harness.expectLine(t, "* ID NIL\r\n")
	harness.expectLine(t, "A001 OK ID completed\r\n")
	harness.write(t, `A002 LOGIN "alice@example.test" "secret-password"`+"\r\n")
	harness.expectLine(t, "A002 OK Authentication completed\r\n")

	assertHTTPBodyField(t, captured, "protocol", "imap")
	assertHTTPBodyField(t, captured, "client_id", "director-test-client")
	assertHTTPForbiddenFieldsAbsent(t, captured)
}

// TestRejectedAuthMapsAuthorityMessage verifies rejected auth keeps authority text with IMAP framing.
func TestRejectedAuthMapsAuthorityMessage(t *testing.T) {
	testCases := []struct {
		name    string
		message string
		want    string
	}{
		{
			name:    "authority message",
			message: "Account disabled",
			want:    "A001 NO [AUTHENTICATIONFAILED] Account disabled\r\n",
		},
		{
			name: "empty fallback",
			want: "A001 NO [AUTHENTICATIONFAILED] Authentication failed\r\n",
		},
		{
			name:    "control hygiene",
			message: "Bad\r\nA999 OK injected\x00done",
			want:    "A001 NO [AUTHENTICATIONFAILED] Bad A999 OK injected done\r\n",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			authenticator := &recordingAuthenticator{
				result: nauthilus.AuthResult{
					Decision:      nauthilus.DecisionRejected,
					StatusMessage: testCase.message,
				},
			}
			router := &recordingRoutingResolver{}
			store := &recordingSessionStore{}
			selector := &recordingBackendSelector{}
			harness := startTestSession(t, pipelineSessionConfig(authenticator, router, store, selector))

			harness.expectLine(t, greetingLine)
			harness.write(t, `A001 LOGIN "alice@example.test" "secret-password"`+"\r\n")
			harness.expectLine(t, testCase.want)

			assertNoPlacementCalls(t, router, store, selector)
		})
	}
}

// TestRejectedAuthResponseLengthIsBounded verifies authority text cannot create oversized lines.
func TestRejectedAuthResponseLengthIsBounded(t *testing.T) {
	authenticator := &recordingAuthenticator{
		result: nauthilus.AuthResult{
			Decision:      nauthilus.DecisionRejected,
			StatusMessage: strings.Repeat("x", maxRejectedStatusTextBytes*4),
		},
	}
	harness := startTestSession(t, pipelineSessionConfig(authenticator, &recordingRoutingResolver{}, &recordingSessionStore{}, &recordingBackendSelector{}))

	harness.expectLine(t, greetingLine)
	harness.write(t, `A001 LOGIN "alice@example.test" "secret-password"`+"\r\n")
	response := harness.readLine(t)

	if !strings.HasPrefix(response, "A001 NO [AUTHENTICATIONFAILED] ") || !strings.HasSuffix(response, "\r\n") {
		t.Fatalf("response framing = %q", response)
	}

	if len(response) > maxRejectedStatusResponseBytes {
		t.Fatalf("response length = %d, want <= %d", len(response), maxRejectedStatusResponseBytes)
	}
}

// TestUnavailableAuthOutcomesDoNotPlace verifies fail-closed authority outcomes stop side effects.
func TestUnavailableAuthOutcomesDoNotPlace(t *testing.T) {
	testCases := []struct {
		name   string
		result nauthilus.AuthResult
		err    error
	}{
		{
			name:   "tempfail decision",
			result: nauthilus.AuthResult{Decision: nauthilus.DecisionTemporaryFailure},
		},
		{
			name:   "transport error",
			result: nauthilus.AuthResult{Decision: nauthilus.DecisionTemporaryFailure},
			err:    errors.New("transport unavailable"),
		},
		{
			name:   "timeout error",
			result: nauthilus.AuthResult{Decision: nauthilus.DecisionTemporaryFailure},
			err:    context.DeadlineExceeded,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			authenticator := &recordingAuthenticator{result: testCase.result, err: testCase.err}
			router := &recordingRoutingResolver{}
			store := &recordingSessionStore{}
			selector := &recordingBackendSelector{}
			harness := startTestSession(t, pipelineSessionConfig(authenticator, router, store, selector))

			harness.expectLine(t, greetingLine)
			harness.write(t, `A001 LOGIN "alice@example.test" "secret-password"`+"\r\n")
			harness.expectLine(t, "A001 NO [UNAVAILABLE] Authentication service temporarily unavailable\r\n")

			assertNoPlacementCalls(t, router, store, selector)
		})
	}
}

// TestAuthenticatedPathBuildsRoutingAndPlacement verifies the successful call sequence.
func TestAuthenticatedPathBuildsRoutingAndPlacement(t *testing.T) {
	authenticator := &recordingAuthenticator{
		result: nauthilus.AuthResult{
			Decision: nauthilus.DecisionAuthenticated,
			Account:  "User@Example.TEST",
			Attributes: map[string][]string{
				"account":   {"User@Example.TEST"},
				"tenant":    {"blue"},
				"mailShard": {"mailstore-a"},
			},
		},
	}
	router := &recordingRoutingResolver{
		result: routing.RoutingResult{
			AccountKey:    "user@example.test",
			Tenant:        "blue",
			ShardTag:      "mailstore-a",
			RoutingSource: routing.SourceAuthAttribute,
		},
	}
	store := &recordingSessionStore{result: state.AffinityRecord{ShardTag: "mailstore-b"}}
	selector := &recordingBackendSelector{result: backend.SelectionResult{Backend: backend.Backend{Identifier: "mailstore-b-imap"}}}
	harness := startTestSession(t, pipelineSessionConfig(authenticator, router, store, selector))

	harness.expectLine(t, greetingLine)
	harness.write(t, `A001 ID ("client_id" "desktop-client")`+"\r\n")
	harness.expectLine(t, "* ID NIL\r\n")
	harness.expectLine(t, "A001 OK ID completed\r\n")
	harness.write(t, `A002 LOGIN "User@Example.TEST" "secret-password"`+"\r\n")
	harness.expectLine(t, "A002 OK Authentication completed\r\n")

	assertAuthenticatedPipelineCalls(t, authenticator, router, store, selector)
}

// TestReplaySecretsAreClearedBeforeProxyMode verifies credential replay does not enter long-lived state.
func TestReplaySecretsAreClearedBeforeProxyMode(t *testing.T) {
	credentials := plainCredentialsForBackendTest(t)
	defer credentials.Clear()

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	proxyStarted := make(chan struct{}, 1)
	runner := &recordingProxyRunner{
		check: func(proxy.PipeConfig) {
			if !credentials.Secret().IsZero() {
				t.Errorf("credential secret was still present at proxy start")
			}
			proxyStarted <- struct{}{}
		},
	}

	session, err := NewSession(pipelineSessionConfig(
		&recordingAuthenticator{},
		&recordingRoutingResolver{},
		&recordingSessionStore{},
		&recordingBackendSelector{},
	), server)
	if err != nil {
		t.Fatalf("NewSession returned error: %v", err)
	}
	session.sessionStore = &recordingSessionStore{}
	session.backendConnector = &recordingBackendConnector{}
	session.proxyRunner = runner
	session.placement = Placement{
		Routing: routing.RoutingResult{Tenant: defaultTenantName, AccountKey: "alice@example.test"},
		Affinity: state.AffinityRecord{
			Key: state.AffinityKey{Tenant: defaultTenantName, AccountKey: "alice@example.test"},
		},
		Backend: backend.SelectionResult{Backend: testReplayPipelineBackend()},
	}
	session.placed = true

	done := make(chan error, 1)
	go func() {
		_, transitionErr := session.transitionAuthenticatedSession(context.Background(), "A001", credentials)
		done <- transitionErr
	}()

	if line := readPipeLine(t, client); line != "A001 OK Authentication completed\r\n" {
		t.Fatalf("frontend auth response = %q, want OK", line)
	}

	select {
	case <-proxyStarted:
	case <-time.After(time.Second):
		t.Fatal("proxy mode did not start")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("transitionAuthenticatedSession returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for transition")
	}
}

// assertAuthenticatedPipelineCalls verifies the auth, routing, session and selector requests.
func assertAuthenticatedPipelineCalls(
	t *testing.T,
	authenticator *recordingAuthenticator,
	router *recordingRoutingResolver,
	store *recordingSessionStore,
	selector *recordingBackendSelector,
) {
	t.Helper()
	assertAuthRequest(t, authenticator)
	assertRoutingRequest(t, router)
	assertSessionOpenRequest(t, store)
	assertBackendSelectionRequest(t, selector)
}

// assertAuthRequest verifies the Nauthilus call from the frontend session.
func assertAuthRequest(t *testing.T, authenticator *recordingAuthenticator) {
	t.Helper()

	if len(authenticator.requests) != 1 {
		t.Fatalf("auth calls = %d, want 1", len(authenticator.requests))
	}

	if got := authenticator.requests[0].Context.Protocol; got != "imap" {
		t.Fatalf("auth protocol = %q, want imap", got)
	}

	if got := authenticator.requests[0].Context.ClientID; got != "desktop-client" {
		t.Fatalf("auth client ID = %q, want desktop-client", got)
	}
}

// assertRoutingRequest verifies authenticated attributes reached routing.
func assertRoutingRequest(t *testing.T, router *recordingRoutingResolver) {
	t.Helper()

	if router.calls != 1 {
		t.Fatalf("routing calls = %d, want 1", router.calls)
	}

	if router.request.ListenerName != testIMAPService || router.request.ServiceName != testIMAPService {
		t.Fatalf("routing listener context = %#v", router.request)
	}

	if router.request.BackendPool != "imap-default" || router.request.Protocol != "imap" {
		t.Fatalf("routing backend context = %#v", router.request)
	}

	if router.request.NormalizedAccount != "user@example.test" {
		t.Fatalf("normalized account = %q, want user@example.test", router.request.NormalizedAccount)
	}

	if got := router.request.AuthAttributes["mailShard"]; len(got) != 1 || got[0] != "mailstore-a" {
		t.Fatalf("routing attributes = %#v", router.request.AuthAttributes)
	}
}

// assertSessionOpenRequest verifies the Redis session-open input after routing.
func assertSessionOpenRequest(t *testing.T, store *recordingSessionStore) {
	t.Helper()

	if store.calls != 1 {
		t.Fatalf("store calls = %d, want 1", store.calls)
	}

	if store.record.Key != (state.AffinityKey{Tenant: "blue", AccountKey: "user@example.test"}) {
		t.Fatalf("session affinity key = %#v", store.record.Key)
	}

	if store.record.ShardTag != "mailstore-a" {
		t.Fatalf("session shard = %q, want routing shard mailstore-a", store.record.ShardTag)
	}
}

// assertBackendSelectionRequest verifies active affinity drives backend selection.
func assertBackendSelectionRequest(t *testing.T, selector *recordingBackendSelector) {
	t.Helper()

	if selector.calls != 1 {
		t.Fatalf("selector calls = %d, want 1", selector.calls)
	}

	if selector.request.ShardTag != "mailstore-b" {
		t.Fatalf("selector shard = %q, want active affinity shard mailstore-b", selector.request.ShardTag)
	}

	if selector.request.Protocol != "imap" || selector.request.BackendPool != "imap-default" {
		t.Fatalf("selector request = %#v", selector.request)
	}

	if !selector.request.ActiveAffinity {
		t.Fatal("selector did not receive active affinity marker")
	}
}

// TestAuthAttributeAndHashFallbackPlacement verifies real resolver chain flow from auth attributes.
func TestAuthAttributeAndHashFallbackPlacement(t *testing.T) {
	testCases := []struct {
		name       string
		attributes map[string][]string
		wantSource string
	}{
		{
			name: "auth attribute",
			attributes: map[string][]string{
				"account":   {"alice@example.test"},
				"tenant":    {defaultTenantName},
				"mailShard": {"mailstore-a"},
			},
			wantSource: routing.SourceAuthAttribute,
		},
		{
			name: "hash fallback",
			attributes: map[string][]string{
				"account": {"alice@example.test"},
				"tenant":  {defaultTenantName},
			},
			wantSource: routing.SourceHash,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			authenticator := &recordingAuthenticator{
				result: nauthilus.AuthResult{
					Decision:   nauthilus.DecisionAuthenticated,
					Account:    "alice@example.test",
					Attributes: testCase.attributes,
				},
			}
			store := &recordingSessionStore{}
			selector := &recordingBackendSelector{result: backend.SelectionResult{Backend: backend.Backend{Identifier: "selected-imap"}}}
			harness := startTestSession(t, pipelineSessionConfig(authenticator, mustPipelineChain(t), store, selector))

			harness.expectLine(t, greetingLine)
			harness.write(t, `A001 LOGIN "alice@example.test" "secret-password"`+"\r\n")
			harness.expectLine(t, "A001 OK Authentication completed\r\n")

			placement, ok := harness.session.Placement()
			if !ok {
				t.Fatal("session did not retain placement")
			}
			if placement.Routing.RoutingSource != testCase.wantSource {
				t.Fatalf("routing source = %q, want %q", placement.Routing.RoutingSource, testCase.wantSource)
			}
			if !slices.Contains([]string{"mailstore-a", "mailstore-b"}, store.record.ShardTag) {
				t.Fatalf("session shard = %q, want configured shard", store.record.ShardTag)
			}
		})
	}
}

// TestRoutingWithoutShardUsesEffectiveDefaultShard verifies placement fallback semantics.
func TestRoutingWithoutShardUsesEffectiveDefaultShard(t *testing.T) {
	authenticator := &recordingAuthenticator{
		result: nauthilus.AuthResult{
			Decision: nauthilus.DecisionAuthenticated,
			Account:  "alice@example.test",
			Attributes: map[string][]string{
				"account": {"alice@example.test"},
				"tenant":  {defaultTenantName},
			},
		},
	}
	router := &recordingRoutingResolver{
		result: routing.RoutingResult{
			AccountKey:    "alice@example.test",
			Tenant:        defaultTenantName,
			RoutingSource: "test",
		},
	}
	store := &recordingSessionStore{}
	selector := &recordingBackendSelector{result: backend.SelectionResult{Backend: backend.Backend{Identifier: "selected-imap"}}}
	config := pipelineSessionConfig(authenticator, router, store, selector)
	config.DefaultShard = "fallback-shard"
	harness := startTestSession(t, config)

	harness.expectLine(t, greetingLine)
	harness.write(t, `A001 LOGIN "alice@example.test" "secret-password"`+"\r\n")
	harness.expectLine(t, "A001 OK Authentication completed\r\n")

	if store.record.ShardTag != "fallback-shard" {
		t.Fatalf("session shard = %q, want fallback-shard", store.record.ShardTag)
	}
	if selector.request.ShardTag != "fallback-shard" {
		t.Fatalf("selector shard = %q, want fallback-shard", selector.request.ShardTag)
	}
}

type recordingAuthenticator struct {
	requests []nauthilus.AuthRequest
	result   nauthilus.AuthResult
	err      error
}

// Authenticate records the authority request and returns the configured outcome.
func (a *recordingAuthenticator) Authenticate(ctx context.Context, request nauthilus.AuthRequest) (nauthilus.AuthResult, error) {
	a.requests = append(a.requests, request)
	if a.err != nil && errors.Is(a.err, context.DeadlineExceeded) {
		<-ctx.Done()

		return a.result, a.err
	}

	return a.result, a.err
}

type recordingRoutingResolver struct {
	calls   int
	request routing.RoutingRequest
	result  routing.RoutingResult
	err     error
}

// Resolve records the routing request and returns the configured result.
func (r *recordingRoutingResolver) Resolve(_ context.Context, request routing.RoutingRequest) (routing.RoutingResult, error) {
	r.calls++
	r.request = request

	return r.result, r.err
}

type recordingSessionStore struct {
	calls          int
	heartbeatCalls int
	closeCalls     int
	record         state.SessionRecord
	result         state.AffinityRecord
	err            error
}

// OpenSession records the session-open request and returns the configured affinity.
func (s *recordingSessionStore) OpenSession(_ context.Context, record state.SessionRecord) (state.AffinityRecord, error) {
	s.calls++
	s.record = record
	if s.result.ShardTag == "" {
		s.result.ShardTag = record.ShardTag
	}

	return s.result, s.err
}

// HeartbeatSession is unused by the auth pipeline tests.
func (s *recordingSessionStore) HeartbeatSession(
	context.Context,
	state.AffinityKey,
	string,
	time.Duration,
) (state.AffinityRecord, error) {
	s.heartbeatCalls++

	return state.AffinityRecord{}, nil
}

// CloseSession records terminal lease release during fake proxy mode.
func (s *recordingSessionStore) CloseSession(context.Context, state.AffinityKey, string) (state.AffinityRecord, error) {
	s.closeCalls++

	return state.AffinityRecord{}, nil
}

type recordingBackendSelector struct {
	calls   int
	request backend.SelectionRequest
	result  backend.SelectionResult
	err     error
}

// Select records the selector request and returns the configured backend result.
func (s *recordingBackendSelector) Select(_ context.Context, request backend.SelectionRequest) (backend.SelectionResult, error) {
	s.calls++
	s.request = request
	if s.result.Backend.Protocol == "" {
		s.result.Backend = defaultPipelineBackend(s.result.Backend.Identifier)
	}

	return s.result, s.err
}

// pipelineSessionConfig returns a bounded IMAP config with auth pipeline dependencies installed.
func pipelineSessionConfig(
	authenticator nauthilus.Authenticator,
	resolver routing.RoutingResolver,
	sessionStore state.SessionStore,
	selector backend.Selector,
) SessionConfig {
	config := testPreauthConfig(TLSModeStartTLS, false)
	config.BackendPool = "imap-default"
	config.DefaultTenant = defaultTenantName
	config.SessionLeaseTTL = time.Minute
	config.AuthTimeout = 20 * time.Millisecond
	config.Authenticator = authenticator
	config.RoutingResolver = resolver
	config.SessionStore = sessionStore
	config.BackendSelector = selector
	config.BackendConnector = &recordingBackendConnector{}
	config.ProxyRunner = &recordingProxyRunner{}

	return config
}

// defaultPipelineBackend fills successful pipeline tests with explicit backend auth policy.
func defaultPipelineBackend(identifier string) backend.Backend {
	if strings.TrimSpace(identifier) == "" {
		identifier = "selected-imap"
	}

	return backend.Backend{
		Identifier: identifier,
		Protocol:   backendProtocol,
		Address:    "127.0.0.1:1143",
		TLS: backend.TLSConfig{
			Mode:          backendTLSStartTLS,
			ServerName:    "mailstore.example.test",
			MinTLSVersion: backendTLSMinDefault,
		},
		Auth: backend.AuthConfig{
			Mode: backendAuthModeMasterUser,
			MasterUser: backend.MasterUserConfig{
				Username:   "director-master",
				Password:   config.Secret("master-secret"),
				UserFormat: "{user}*{master_user}",
				Mechanism:  mechanismPlain,
			},
		},
	}
}

// testReplayPipelineBackend returns a credential-replay backend for transition tests.
func testReplayPipelineBackend() backend.Backend {
	target := defaultPipelineBackend("replay-imap")
	target.Auth = backend.AuthConfig{
		Mode: backendAuthModeCredentialReplay,
		CredentialReplay: backend.CredentialReplayConfig{
			RequireBackendTLS: true,
			PreserveMechanism: true,
			AllowedMechanisms: []string{mechanismPlain, mechanismLogin, mechanismXOAUTH2, mechanismOAuthBearer},
		},
	}

	return target
}

// readPipeLine reads one CRLF-terminated line from a net.Pipe connection.
func readPipeLine(t *testing.T, conn net.Conn) string {
	t.Helper()

	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read pipe line: %v", err)
	}

	return line
}

// recordingBackendConnector returns an already prepared fake backend connection.
type recordingBackendConnector struct {
	calls  int
	target backend.Backend
}

// Connect records the selected backend and prepares a fake auth-capable stream.
func (c *recordingBackendConnector) Connect(_ context.Context, target backend.Backend, _ time.Duration) (*BackendConnection, error) {
	c.calls++
	c.target = target

	client, server := net.Pipe()
	connection := newBackendConnection(client)
	connection.capabilities = testBackendCapabilities()
	connection.tlsActive = true
	connection.tlsVerified = true

	go serveOneBackendAuthCommand(server)

	return connection, nil
}

// serveOneBackendAuthCommand accepts one backend auth command and then waits for proxy close.
func serveOneBackendAuthCommand(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	tag, _, _ := strings.Cut(strings.TrimSpace(line), " ")
	if tag == "" {
		return
	}

	_, _ = io.WriteString(conn, tag+" OK backend auth completed\r\n")
	_, _ = io.Copy(io.Discard, reader)
}

// recordingProxyRunner records transparent proxy start and releases the test lease.
type recordingProxyRunner struct {
	calls  int
	config proxy.PipeConfig
	check  func(proxy.PipeConfig)
	err    error
}

// Run records proxy config, applies an optional assertion and closes both streams.
func (r *recordingProxyRunner) Run(ctx context.Context, config proxy.PipeConfig) (proxy.Result, error) {
	r.calls++
	r.config = config
	if r.check != nil {
		r.check(config)
	}
	if config.Lease != nil {
		_ = config.Lease.Close(ctx)
	}
	_ = config.Frontend.Close()
	_ = config.Backend.Close()

	return proxy.Result{Class: proxy.ResultClientClosed}, r.err
}

// mustPipelineChain creates the real auth-attribute plus hash fallback resolver chain.
func mustPipelineChain(t *testing.T) routing.RoutingResolver {
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
		ShardTags: []string{"mailstore-a", "mailstore-b"},
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

// assertNoPlacementCalls verifies unavailable/rejected auth stopped all side effects.
func assertNoPlacementCalls(
	t *testing.T,
	router *recordingRoutingResolver,
	store *recordingSessionStore,
	selector *recordingBackendSelector,
) {
	t.Helper()

	if router.calls != 0 || store.calls != 0 || selector.calls != 0 {
		t.Fatalf("placement calls = routing:%d state:%d backend:%d, want all zero", router.calls, store.calls, selector.calls)
	}
}

// assertHTTPBodyField verifies one captured JSON body field.
func assertHTTPBodyField(t *testing.T, body map[string]any, name string, want string) {
	t.Helper()

	got, ok := body[name].(string)
	if !ok || got != want {
		t.Fatalf("%s = %#v, want %q", name, body[name], want)
	}
}

// assertHTTPForbiddenFieldsAbsent verifies the IMAP session did not send director fields.
func assertHTTPForbiddenFieldsAbsent(t *testing.T, body map[string]any) {
	t.Helper()

	for _, field := range []string{"backend_identifier", "listener", "proxy", "routing_hint", "service", "session_id", "tls"} {
		if _, ok := body[field]; ok {
			t.Fatalf("forbidden field %q present in %#v", field, body)
		}
	}
}
