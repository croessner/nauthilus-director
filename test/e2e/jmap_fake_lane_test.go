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

//nolint:dupl,funlen,goconst,gocyclo,wsl_v5 // E2E flows keep public request and backend assertions visible.
package e2e

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	jmapbackend "github.com/croessner/nauthilus-director/test/e2e/fakes/jmap_backend"
	proxyproto "github.com/pires/go-proxyproto"
)

const (
	e2eJMAPListener        = "jmap"
	e2eJMAPPool            = "jmap-default"
	e2eJMAPBackendA        = "mailstore-a-jmap"
	e2eJMAPBackendB        = "mailstore-b-jmap"
	e2eJMAPShardA          = "mailstore-a"
	e2eJMAPShardB          = "mailstore-b"
	e2eJMAPAccount         = "jmap-alice@example.test"
	e2eJMAPBearerAccount   = "jmap-bob@example.test"
	e2eJMAPUnroutedAccount = "jmap-carol@example.test"
	e2eJMAPPassword        = "jmap-e2e-password-sentinel"
	e2eJMAPToken           = "jmap-e2e-bearer-token-sentinel"
	e2eJMAPForeignToken    = "jmap-e2e-foreign-resource-token-sentinel"
	e2eJMAPResource        = "https://mail.example.test/"
	e2eJMAPPublicBaseURL   = "https://mail.example.test"
	e2eJMAPScope           = "mail:account:read"
	e2eJMAPClientA         = "203.0.113.10"
	e2eJMAPClientB         = "203.0.113.20"
	e2eJMAPHealthPath      = "/director/healthz"
	e2eJMAPIntrospectionID = "jmap-e2e-introspection"
	e2eJMAPIntrospectionPW = "jmap-e2e-introspection-secret-sentinel"
)

// jmapFakeAuthority is a Nauthilus-shaped HTTP authority with password, lookup and introspection paths.
type jmapFakeAuthority struct {
	server   *http.Server
	listener net.Listener

	mu                   sync.Mutex
	requests             []map[string]any
	introspectionClients []string
}

// jmapShardFor returns the fixture shard attribute of one account.
func jmapShardFor(account string) []string {
	switch account {
	case e2eJMAPAccount:
		return []string{e2eJMAPShardA}
	case e2eJMAPBearerAccount:
		return []string{e2eJMAPShardB}
	default:
		return nil
	}
}

// startJMAPFakeAuthority starts the authority fixture on a loopback socket.
func startJMAPFakeAuthority(t *testing.T) *jmapFakeAuthority {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen JMAP authority: %v", err)
	}

	fake := &jmapFakeAuthority{listener: ln}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/json", fake.handleAuth)
	mux.HandleFunc(e2eOIDCDiscovery, fake.handleDiscovery)
	mux.HandleFunc("/oidc/introspect", fake.handleIntrospection)
	fake.server = &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}

	go func() { _ = fake.server.Serve(ln) }()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = fake.server.Shutdown(ctx)
	})

	return fake
}

// issuer returns the fixture OIDC issuer URL.
func (f *jmapFakeAuthority) issuer() string {
	return "http://" + f.listener.Addr().String()
}

// handleAuth checks passwords and answers no-auth identity lookups.
func (f *jmapFakeAuthority) handleAuth(writer http.ResponseWriter, request *http.Request) {
	var body map[string]any
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		http.Error(writer, "bad request", http.StatusBadRequest)

		return
	}

	lookup := request.URL.Query().Get("mode") == "no-auth"
	body["lookup"] = lookup

	f.mu.Lock()
	f.requests = append(f.requests, body)
	f.mu.Unlock()

	username, _ := body["username"].(string)
	password, _ := body["password"].(string)
	known := username == e2eJMAPAccount || username == e2eJMAPBearerAccount || username == e2eJMAPUnroutedAccount

	writer.Header().Set("Content-Type", "application/json")
	if !known || (!lookup && password != e2eJMAPPassword) {
		_ = json.NewEncoder(writer).Encode(map[string]any{"ok": false})

		return
	}

	attributes := map[string][]string{"account": {username}}
	if shard := jmapShardFor(username); shard != nil {
		attributes["mailShard"] = shard
	}

	_ = json.NewEncoder(writer).Encode(map[string]any{"ok": true, "account_field": "account", "attributes": attributes})
}

// handleDiscovery returns the minimal Nauthilus OIDC discovery document.
func (f *jmapFakeAuthority) handleDiscovery(writer http.ResponseWriter, _ *http.Request) {
	issuer := f.issuer()
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"issuer":                                issuer,
		"token_endpoint":                        issuer + "/oidc/token",
		"introspection_endpoint":                issuer + "/oidc/introspect",
		"jwks_uri":                              issuer + "/oidc/jwks",
		"grant_types_supported":                 []string{"client_credentials"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
		"introspection_endpoint_auth_methods_supported": []string{"client_secret_basic"},
		"response_types_supported":                      []string{"code"},
		"subject_types_supported":                       []string{"public"},
		"id_token_signing_alg_values_supported":         []string{"RS256"},
		"scopes_supported":                              []string{e2eJMAPScope},
		"claims_supported":                              []string{"sub", "scope", "dovecot_account", "resource"},
	})
}

// handleIntrospection answers RFC 7662 introspection for the fixture tokens.
func (f *jmapFakeAuthority) handleIntrospection(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		http.Error(writer, "bad request", http.StatusBadRequest)

		return
	}

	clientID, clientSecret, ok := request.BasicAuth()

	f.mu.Lock()
	f.introspectionClients = append(f.introspectionClients, clientID)
	f.mu.Unlock()

	// JMAP tokens are introspected only by the listener's dedicated client, never by the
	// authority-wide mail SASL client.
	if !ok || clientID != e2eJMAPIntrospectionID || clientSecret != e2eJMAPIntrospectionPW {
		http.Error(writer, "invalid client", http.StatusUnauthorized)

		return
	}

	claims := map[string]any{"active": false}

	switch request.Form.Get("token") {
	case e2eJMAPToken:
		claims = map[string]any{"active": true, "sub": "bob", "scope": "openid " + e2eJMAPScope, "resource": e2eJMAPResource, "dovecot_account": e2eJMAPBearerAccount}
	case e2eJMAPForeignToken:
		claims = map[string]any{"active": true, "sub": "bob", "scope": "openid " + e2eJMAPScope, "resource": "https://other.example.test/", "dovecot_account": e2eJMAPBearerAccount}
	}

	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(claims)
}

// authorityRequests returns recorded authority request bodies.
func (f *jmapFakeAuthority) authorityRequests() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]map[string]any(nil), f.requests...)
}

// jmapProcessFixture is one running director process with a JMAP listener and two backends.
type jmapProcessFixture struct {
	process    *directorProcess
	address    string
	controlURL string
	rootCAs    *x509.CertPool
	authority  *jmapFakeAuthority
	backendA   *jmapbackend.Server
	backendB   *jmapbackend.Server
	ctl        string
}

// TestServerBinaryPublicJMAPProxyFlow proves JMAP proxying through the real server binary.
func TestServerBinaryPublicJMAPProxyFlow(t *testing.T) {
	fixture := startJMAPProcess(t)

	exerciseJMAPBasicSessionAndClientAddress(t, fixture)
	exerciseJMAPClientsNeverShareBackendConnections(t, fixture)
	exerciseJMAPBearerRouting(t, fixture)
	exerciseJMAPRefusals(t, fixture)
	exerciseJMAPEventStreamKick(t, fixture)
	exerciseJMAPBackendHealthAndMetrics(t, fixture)

	stopDirectorProcess(t, fixture.process)
	assertOutputOmits(t, fixture.process.output.String(), e2eJMAPPassword, e2eJMAPToken, e2eJMAPForeignToken, e2eSASLClientSecret, e2eJMAPIntrospectionPW)
}

// startJMAPProcess starts Valkey, the fake authority, two JMAP backends and the director.
func startJMAPProcess(t *testing.T) jmapProcessFixture {
	t.Helper()

	binary := e2eServerBinary(t)
	ctl := buildDirectorctl(t)
	redisFixture := startValkeySessionStore(t)
	authority := startJMAPFakeAuthority(t)
	certPath, keyPath, certificate := writeTestCertificate(t)
	backendTLS := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	backendA := jmapbackend.Start(t, jmapbackend.Options{Name: "a", TLSConfig: backendTLS, RequireProxyProtocol: true, PublicBaseURL: e2eJMAPPublicBaseURL})
	backendB := jmapbackend.Start(t, jmapbackend.Options{Name: "b", TLSConfig: backendTLS, RequireProxyProtocol: true, PublicBaseURL: e2eJMAPPublicBaseURL})
	jmapAddress := loopbackAddress(t)
	controlAddress := loopbackAddress(t)

	configPath := writeJMAPProcessConfig(t, jmapProcessConfigOptions{
		RedisAddress:   redisFixture.addr,
		AuthorityURL:   "http://" + authority.listener.Addr().String() + "/api/v1/auth/json",
		Issuer:         authority.issuer(),
		JMAPAddress:    jmapAddress,
		ControlAddress: controlAddress,
		CertPath:       certPath,
		KeyPath:        keyPath,
		BackendA:       backendA.Address(),
		BackendB:       backendB.Address(),
	})

	process := startDirectorProcess(t, binary, configPath)
	controlURL := "http://" + controlAddress
	waitForTCPListener(t, jmapAddress, process)
	waitForControlReady(t, controlURL, process)

	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read certificate: %v", err)
	}

	rootCAs := x509.NewCertPool()
	rootCAs.AppendCertsFromPEM(pemBytes)

	return jmapProcessFixture{
		process:    process,
		address:    jmapAddress,
		controlURL: controlURL,
		rootCAs:    rootCAs,
		authority:  authority,
		backendA:   backendA,
		backendB:   backendB,
		ctl:        ctl,
	}
}

// jmapProcessConfigOptions are the addresses and files of one JMAP process config.
type jmapProcessConfigOptions struct {
	RedisAddress   string
	AuthorityURL   string
	Issuer         string
	JMAPAddress    string
	ControlAddress string
	CertPath       string
	KeyPath        string
	BackendA       string
	BackendB       string
}

// writeJMAPProcessConfig writes a config with only the JMAP listener, pool and backends.
func writeJMAPProcessConfig(t *testing.T, options jmapProcessConfigOptions) string {
	t.Helper()

	authorityPasswordPath := writeProcessSecretFile(t, "unused")
	content := fmt.Sprintf(`patch:
  - op: remove
    path: director.listeners
    value: [imap, imaps, lmtp, lmtps, sieve, sieves, pop3, pop3s]
  - op: remove
    path: director.backend_pools
    value: [imap-default, lmtp-default, sieve-default, pop3-default]
  - op: remove
    path: director.backends
    value: [mailstore-a-imap, mailstore-b-imap, mailstore-a-lmtp, mailstore-b-lmtp, mailstore-a-sieve, mailstore-b-sieve, mailstore-a-pop3, mailstore-b-pop3]
runtime:
  instance_name: "e2e-jmap-director"
  process:
    shutdown_timeout: 2s
  servers:
    control:
      enabled: true
      address: %q
%s
  timeouts:
    preauth: 2s
    auth: 2s
    nauthilus: 2s
    backend_connect: 2s
    proxy_idle: 30s
storage:
  redis:
    protocol: 2
    key_prefix: %q
    standalone:
      address: %q
    auth:
      username: ""
      password_file: ""
    tls:
      enabled: false
auth:
  authorities:
    default:
      transport: http
%s
      http:
        endpoint: %q
        basic_auth:
          password_file: %q
director:
  health:
    interval: 200ms
    timeout: 1s
    jitter: 0s
    unhealthy_after: 1
    healthy_after: 1
  listeners:
    jmap:
      protocol: jmap
      service_name: jmap
      network: tcp
      address: %q
      authority: default
      backend_pool: jmap-default
      proxy_protocol:
        enabled: true
        trusted_cidrs: ["127.0.0.0/8"]
      tls:
        mode: implicit
        cert: %q
        key: %q
        min_tls_version: TLS1.2
      jmap:
        public_base_url: %q
        health_path: %q
        auth:
          bearer:
            enabled: true
            required_resource: %q
            required_scope: %q
            account_claim: dovecot_account
            introspection_client:
              client_id: %q
              auth_method: client_secret_basic
              client_secret_file: %q
        event_source:
          heartbeat_interval: 200ms
  backend_pools:
    jmap-default:
      protocol: jmap
      selector: rendezvous_hash
      backends: [mailstore-a-jmap, mailstore-b-jmap]
  backends:
%s%s`,
		options.ControlAddress,
		processControlAuthYAML(t),
		e2eProcessKeyPrefix,
		options.RedisAddress,
		processAuthorityYAML(t, processAuthorityOIDCOptions{}, processAuthorityBearerOptions{
			Enabled:          true,
			Issuer:           options.Issuer,
			ClientID:         e2eSASLClientID,
			ClientSecret:     e2eSASLClientSecret,
			AuthMethod:       "client_secret_basic",
			RequiredAudience: e2eSASLClientID,
			RequiredScope:    e2eSASLRequiredScope,
		}),
		options.AuthorityURL,
		authorityPasswordPath,
		options.JMAPAddress,
		options.CertPath,
		options.KeyPath,
		e2eJMAPPublicBaseURL,
		e2eJMAPHealthPath,
		e2eJMAPResource,
		e2eJMAPScope,
		e2eJMAPIntrospectionID,
		writeProcessSecretFile(t, e2eJMAPIntrospectionPW),
		jmapBackendYAML(e2eJMAPBackendA, e2eJMAPShardA, options.BackendA, options.CertPath),
		jmapBackendYAML(e2eJMAPBackendB, e2eJMAPShardB, options.BackendB, options.CertPath),
	)

	path := filepath.Join(t.TempDir(), "nauthilus-director.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write JMAP process config: %v", err)
	}

	return path
}

// jmapBackendYAML renders one JMAP backend entry.
func jmapBackendYAML(identifier string, shard string, address string, caFile string) string {
	return fmt.Sprintf(`    %s:
      protocol: jmap
      shard_tag: %s
      backend_node: %s-node
      address: %q
      weight: 100
      max_connections: 100
      maintenance: disabled
      haproxy:
        enabled: true
      tls:
        mode: implicit
        ca_file: %q
        server_name: "127.0.0.1"
        min_tls_version: TLS1.2
      auth:
        mode: none
      health_check:
        enabled: true
        deep_check: false
`, identifier, shard, shard, address, caFile)
}

// jmapClient returns an HTTP client whose connections announce clientIP through PROXY v2.
func (f jmapProcessFixture) jmapClient(t *testing.T, clientIP string) *http.Client {
	t.Helper()

	dialer := &net.Dialer{Timeout: 2 * time.Second}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: f.rootCAs, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}

			destination, _ := conn.RemoteAddr().(*net.TCPAddr)
			header := proxyproto.HeaderProxyFromAddrs(2, &net.TCPAddr{IP: net.ParseIP(clientIP), Port: 40000}, destination)
			if _, err := header.WriteTo(conn); err != nil {
				_ = conn.Close()

				return nil, err
			}

			return conn, nil
		},
		MaxIdleConnsPerHost: 1,
	}
	t.Cleanup(transport.CloseIdleConnections)

	return &http.Client{Transport: transport, Timeout: 10 * time.Second}
}

// jmapDo sends one request and returns status, headers and body.
func jmapDo(t *testing.T, client *http.Client, method string, url string, body string, authorize func(*http.Request)) (int, http.Header, string) {
	t.Helper()

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}

	request, err := http.NewRequestWithContext(context.Background(), method, url, reader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	if authorize != nil {
		authorize(request)
	}

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer func() { _ = response.Body.Close() }()

	payload, _ := io.ReadAll(response.Body)

	return response.StatusCode, response.Header, string(payload)
}

// basicAuth returns a request decorator with fixture Basic credentials.
func basicAuth(account string, password string) func(*http.Request) {
	return func(request *http.Request) { request.SetBasicAuth(account, password) }
}

// bearerAuth returns a request decorator with a Bearer token.
func bearerAuth(token string) func(*http.Request) {
	return func(request *http.Request) { request.Header.Set("Authorization", "Bearer "+token) }
}

// url returns the public JMAP URL for a path.
func (f jmapProcessFixture) url(path string) string {
	return "https://" + f.address + path
}

// exerciseJMAPBasicSessionAndClientAddress proves Basic auth, routing and the PROXY chain.
func exerciseJMAPBasicSessionAndClientAddress(t *testing.T, f jmapProcessFixture) {
	t.Helper()

	client := f.jmapClient(t, e2eJMAPClientA)

	status, header, body := jmapDo(t, client, http.MethodGet, f.url("/.well-known/jmap"), "", basicAuth(e2eJMAPAccount, e2eJMAPPassword))
	if status != http.StatusOK || header.Get(jmapbackend.HeaderBackend) != "a" || !strings.Contains(body, e2eJMAPPublicBaseURL+"/jmap/api/") {
		t.Fatalf("session status=%d backend=%q body=%s\n%s", status, header.Get(jmapbackend.HeaderBackend), body, f.process.output.String())
	}

	seen, err := f.backendA.LastRequest("/.well-known/jmap")
	if err != nil {
		t.Fatalf("backend A did not see the session request: %v", err)
	}

	if host, _, _ := net.SplitHostPort(seen.ClientAddress); host != e2eJMAPClientA {
		t.Fatalf("backend client address = %q, want %s from the frontend PROXY header", seen.ClientAddress, e2eJMAPClientA)
	}

	if !strings.HasPrefix(seen.Authorization, "Basic ") {
		t.Fatal("backend did not receive the client's Authorization header")
	}

	var sawPlain bool
	for _, request := range f.authority.authorityRequests() {
		if request["protocol"] != "jmap" {
			t.Fatalf("authority request protocol = %v, want jmap", request["protocol"])
		}

		if request["method"] == "plain" && request["username"] == e2eJMAPAccount {
			sawPlain = true
		}
	}

	if !sawPlain {
		t.Fatal("authority did not receive a jmap/plain authentication")
	}

	status, _, body = jmapDo(t, client, http.MethodPost, f.url("/jmap/api/"), `{"using":[],"methodCalls":[]}`, basicAuth(e2eJMAPAccount, e2eJMAPPassword))
	if status != http.StatusOK || !strings.Contains(body, `"backend":"a"`) {
		t.Fatalf("api status=%d body=%s", status, body)
	}
}

// exerciseJMAPClientsNeverShareBackendConnections proves backend connections stay per client.
func exerciseJMAPClientsNeverShareBackendConnections(t *testing.T, f jmapProcessFixture) {
	t.Helper()

	before := len(f.backendA.Requests())
	clientA := f.jmapClient(t, e2eJMAPClientA)
	clientB := f.jmapClient(t, e2eJMAPClientB)

	for range 3 {
		for _, client := range []*http.Client{clientA, clientB} {
			if status, _, _ := jmapDo(t, client, http.MethodPost, f.url("/jmap/api/"), "{}", basicAuth(e2eJMAPAccount, e2eJMAPPassword)); status != http.StatusOK {
				t.Fatalf("api status = %d", status)
			}
		}
	}

	connectionsByClient := map[string]map[int64]struct{}{}
	for _, seen := range f.backendA.Requests()[before:] {
		host, _, _ := net.SplitHostPort(seen.ClientAddress)
		if connectionsByClient[host] == nil {
			connectionsByClient[host] = map[int64]struct{}{}
		}

		connectionsByClient[host][seen.Connection] = struct{}{}
	}

	if len(connectionsByClient) != 2 || len(connectionsByClient[e2eJMAPClientA]) == 0 || len(connectionsByClient[e2eJMAPClientB]) == 0 {
		t.Fatalf("backend client tuples = %v, want both frontend clients", connectionsByClient)
	}

	for connection := range connectionsByClient[e2eJMAPClientA] {
		if _, shared := connectionsByClient[e2eJMAPClientB][connection]; shared {
			t.Fatalf("backend connection %d carried both clients", connection)
		}
	}
}

// exerciseJMAPBearerRouting proves introspection with the listener resource plus identity lookup routing.
func exerciseJMAPBearerRouting(t *testing.T, f jmapProcessFixture) {
	t.Helper()

	client := f.jmapClient(t, e2eJMAPClientA)

	status, header, body := jmapDo(t, client, http.MethodGet, f.url("/.well-known/jmap"), "", bearerAuth(e2eJMAPToken))
	if status != http.StatusOK || header.Get(jmapbackend.HeaderBackend) != "b" {
		t.Fatalf("bearer session status=%d backend=%q body=%s\n%s", status, header.Get(jmapbackend.HeaderBackend), body, f.process.output.String())
	}

	seen, err := f.backendB.LastRequest("/.well-known/jmap")
	if err != nil || seen.Authorization != "Bearer "+e2eJMAPToken {
		t.Fatalf("backend B did not receive the bearer token unchanged: %v", err)
	}

	var sawLookup bool
	for _, request := range f.authority.authorityRequests() {
		if request["lookup"] == true && request["username"] == e2eJMAPBearerAccount && request["method"] == "recipient_lookup" {
			sawLookup = true
		}
	}

	if !sawLookup {
		t.Fatal("bearer login did not look up the token account")
	}

	f.authority.mu.Lock()
	clients := append([]string(nil), f.authority.introspectionClients...)
	f.authority.mu.Unlock()

	if len(clients) == 0 {
		t.Fatal("bearer login did not introspect the token")
	}

	for _, client := range clients {
		if client != e2eJMAPIntrospectionID {
			t.Fatalf("introspection client = %q, want the JMAP listener's dedicated client", client)
		}
	}

	status, header, _ = jmapDo(t, client, http.MethodGet, f.url("/.well-known/jmap"), "", bearerAuth(e2eJMAPForeignToken))
	if status != http.StatusUnauthorized || !strings.Contains(strings.Join(header.Values("WWW-Authenticate"), ";"), `error="invalid_token"`) {
		t.Fatalf("foreign resource token status=%d challenges=%q", status, header.Values("WWW-Authenticate"))
	}
}

// exerciseJMAPRefusals proves fail-closed routing, auth challenges and the path allowlist.
func exerciseJMAPRefusals(t *testing.T, f jmapProcessFixture) {
	t.Helper()

	client := f.jmapClient(t, e2eJMAPClientA)
	before := len(f.backendA.Requests()) + len(f.backendB.Requests())

	if status, _, _ := jmapDo(t, client, http.MethodGet, f.url("/.well-known/jmap"), "", basicAuth(e2eJMAPUnroutedAccount, e2eJMAPPassword)); status != http.StatusForbidden {
		t.Fatalf("account without shard status = %d, want 403", status)
	}

	status, header, _ := jmapDo(t, client, http.MethodGet, f.url("/.well-known/jmap"), "", nil)
	if status != http.StatusUnauthorized || len(header.Values("WWW-Authenticate")) != 2 {
		t.Fatalf("missing credentials status=%d challenges=%q", status, header.Values("WWW-Authenticate"))
	}

	if status, _, _ := jmapDo(t, client, http.MethodGet, f.url("/.well-known/jmap"), "", basicAuth(e2eJMAPAccount, "wrong")); status != http.StatusUnauthorized {
		t.Fatalf("wrong password status = %d, want 401", status)
	}

	for _, path := range []string{"/jmap/healthz", "/metrics", "/jmap/api/../healthz"} {
		if status, _, _ := jmapDo(t, client, http.MethodGet, f.url(path), "", basicAuth(e2eJMAPAccount, e2eJMAPPassword)); status != http.StatusNotFound {
			t.Fatalf("path %s status = %d, want 404", path, status)
		}
	}

	if status, _, body := jmapDo(t, client, http.MethodGet, f.url(e2eJMAPHealthPath), "", nil); status != http.StatusOK || body != "ok\n" {
		t.Fatalf("local health status=%d body=%q", status, body)
	}

	if after := len(f.backendA.Requests()) + len(f.backendB.Requests()); after != before {
		t.Fatalf("refused requests reached a backend: %d -> %d", before, after)
	}
}

// exerciseJMAPEventStreamKick proves streaming, the session lease and a kick through directorctl.
func exerciseJMAPEventStreamKick(t *testing.T, f jmapProcessFixture) {
	t.Helper()

	client := f.jmapClient(t, e2eJMAPClientA)
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, f.url("/jmap/eventsource/?types=*&closeafter=no&ping=0"), nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	request.SetBasicAuth(e2eJMAPAccount, e2eJMAPPassword)

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("open event stream: %v", err)
	}
	defer func() { _ = response.Body.Close() }()

	reader := bufio.NewReader(response.Body)
	if line, err := reader.ReadString('\n'); err != nil || line != "event: state\n" {
		t.Fatalf("first event line = %q err = %v", line, err)
	}

	f.backendA.WaitForOpenStreams(t, 1)
	waitForRESTSessionCount(t, f.controlURL, 1)

	runDirectorctl(t, f.ctl, f.controlURL, "users", "kick", e2eJMAPAccount, "--reason", "jmap stream kick")

	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, reader)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("event stream did not end after the kick")
	}

	f.backendA.WaitForOpenStreams(t, 0)
	waitForRESTSessionCount(t, f.controlURL, 0)
}

// exerciseJMAPBackendHealthAndMetrics proves HTTPS health probes with PROXY and bounded metrics.
func exerciseJMAPBackendHealthAndMetrics(t *testing.T, f jmapProcessFixture) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for f.backendA.HealthChecks() == 0 || f.backendB.HealthChecks() == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("health checks A=%d B=%d, want probes on both backends", f.backendA.HealthChecks(), f.backendB.HealthChecks())
		}

		time.Sleep(50 * time.Millisecond)
	}

	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, f.controlURL+"/metrics", nil)
	if err != nil {
		t.Fatalf("new metrics request: %v", err)
	}

	authorizeE2EControlRequest(request)

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("metrics request: %v", err)
	}
	defer func() { _ = response.Body.Close() }()

	body, _ := io.ReadAll(response.Body)
	metrics := string(body)

	for _, want := range []string{
		`nauthilus_director_jmap_requests_total{backend_pool="jmap-default",listener="jmap",operation="session",protocol="jmap",reason_class="ok",result="authenticated",status_class="2xx"}`,
		`operation="session",protocol="jmap",reason_class="routing",result="authenticated",status_class="4xx"`,
		`reason_class="control_action"`,
	} {
		if !strings.Contains(metrics, want) {
			t.Fatalf("metrics missing %q", want)
		}
	}

	for _, forbidden := range []string{e2eJMAPAccount, e2eJMAPClientA, "/jmap/api/"} {
		if strings.Contains(metrics, forbidden) {
			t.Fatalf("metrics leaked %q", forbidden)
		}
	}
}
