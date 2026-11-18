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

//nolint:goconst // Token fixture names are repeated by the cases that present them.
package mcpserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/rest/diagnostics"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/rest/adapters"
	"github.com/croessner/nauthilus-director/internal/rest/generated"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	testResource = "https://director.example.test/mcp"
	testIssuer   = "https://login.example.test"
	testHost     = "director.example.test"
	testProxy    = "192.0.2.10"
	staticClient = "support-cli"
	testSubject  = "alice"
	testGroup    = "admin"
)

// fakeAuthority is a hermetic token authority with a fixed introspection table.
type fakeAuthority struct {
	tokens      map[string]nauthilus.OIDCIntrospectionResult
	mu          sync.Mutex
	unavailable bool
}

// Introspect answers the fixed token table; unknown tokens are inactive.
func (a *fakeAuthority) Introspect(_ context.Context, token string) (nauthilus.OIDCIntrospectionResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.unavailable {
		return nauthilus.OIDCIntrospectionResult{}, errors.New("authority down")
	}

	result, ok := a.tokens[token]
	if !ok {
		return nauthilus.OIDCIntrospectionResult{Active: false}, nil
	}

	return result, nil
}

// setUnavailable toggles the authority outage.
func (a *fakeAuthority) setUnavailable(unavailable bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.unavailable = unavailable
}

// userToken returns an active introspection result of a user token.
func userToken(client string, subject string, audiences []string, expiry time.Time, scopes ...string) nauthilus.OIDCIntrospectionResult {
	claims := map[string]any{"groups": []any{"staff", testGroup}}
	if !expiry.IsZero() {
		claims[claimExpiry] = float64(expiry.Unix())
	}

	return nauthilus.OIDCIntrospectionResult{Active: true, Subject: subject, ClientID: client, Audiences: audiences,
		Scopes: scopes, Claims: claims}
}

// withGroups replaces the groups claim of an introspection result.
func withGroups(result nauthilus.OIDCIntrospectionResult, groups any) nauthilus.OIDCIntrospectionResult {
	result.Claims["groups"] = groups

	return result
}

// newAuthority returns the authority with the standard token table.
func newAuthority() *fakeAuthority {
	pair := []string{staticClient, testResource}
	later := time.Now().Add(10 * time.Minute)
	both := []string{diagnostics.ScopeRuntimeRead, diagnostics.ScopeUsersRead}

	return &fakeAuthority{tokens: map[string]nauthilus.OIDCIntrospectionResult{
		"good":           userToken(staticClient, testSubject, pair, later, both...),
		"resource-only":  userToken(staticClient, testSubject, []string{testResource}, later, both...),
		"runtime-only":   userToken(staticClient, testSubject, pair, later, diagnostics.ScopeRuntimeRead),
		"no-scope":       userToken(staticClient, testSubject, pair, later, "openid"),
		"wrong-audience": userToken(staticClient, testSubject, []string{staticClient, "https://mail.example.test/"}, later, both...),
		"extra-audience": userToken(staticClient, testSubject, []string{staticClient, testResource, "https://mail.example.test/"}, later, both...),
		"client-only":    userToken(staticClient, testSubject, []string{staticClient}, later, both...),
		"unlisted":       userToken("other-client", testSubject, []string{"other-client", testResource}, later, both...),
		"service-token":  userToken(staticClient, staticClient, pair, later, both...),
		"no-subject":     userToken(staticClient, "", pair, later, both...),
		"expired":        userToken(staticClient, testSubject, pair, time.Now().Add(-time.Minute), both...),
		"no-expiry":      userToken(staticClient, testSubject, pair, time.Time{}, both...),
		"not-entitled":   withGroups(userToken(staticClient, testSubject, pair, later, both...), []any{"staff"}),
		"group-string":   withGroups(userToken(staticClient, testSubject, pair, later, both...), "staff "+testGroup),
	}}
}

// fakeAPI is the read API of a handler without runtime services, with a controllable runtime summary.
type fakeAPI struct {
	diagnostics.ReadAPI

	summaryDelay time.Duration
	ignoreAbort  bool
}

// GetRuntimeSummary answers an empty summary after the configured delay; a context that ends
// first ends the wait unless ignoreAbort is set.
func (f fakeAPI) GetRuntimeSummary(ctx context.Context, _ generated.GetRuntimeSummaryRequestObject) (generated.GetRuntimeSummaryResponseObject, error) {
	if f.summaryDelay > 0 {
		timer := time.NewTimer(f.summaryDelay)
		defer timer.Stop()

		if f.ignoreAbort {
			<-timer.C
		} else {
			select {
			case <-timer.C:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}

	return generated.GetRuntimeSummary200JSONResponse{RoutingAuthority: true,
		GeneratedAt: time.Date(2026, time.November, 18, 8, 0, 0, 0, time.UTC)}, nil
}

// newFakeAPI returns the fake over a real handler without runtime services.
func newFakeAPI() fakeAPI {
	return fakeAPI{ReadAPI: adapters.NewHandler(adapters.HandlerOptions{Version: "test"})}
}

// eventLog collects recorded events for audit assertions.
type eventLog struct {
	events []observability.Event
	mu     sync.Mutex
}

// Record stores one event.
func (l *eventLog) Record(_ context.Context, event observability.Event) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.events = append(l.events, event)
}

// snapshot returns the recorded events.
func (l *eventLog) snapshot() []observability.Event {
	l.mu.Lock()
	defer l.mu.Unlock()

	return append([]observability.Event(nil), l.events...)
}

// testSettings returns enabled endpoint settings behind the test proxy.
func testSettings() config.MCPServerConfig {
	settings := config.DefaultConfig().Runtime.Servers.MCP
	settings.Enabled = true
	settings.Resource = testResource
	settings.AllowedClients = []string{staticClient}
	settings.RequiredGroups = []string{testGroup}
	settings.TrustedProxies = []string{testProxy + "/32"}
	settings.Limits.FailedAuthPerMinute = 3

	return settings
}

// testServerOptions adjusts one test endpoint.
type testServerOptions struct {
	adjust   func(*config.MCPServerConfig)
	api      diagnostics.ReadAPI
	recorder observability.Recorder
}

// newTestServer builds the endpoint over the fake authority.
func newTestServer(t *testing.T, authority *fakeAuthority, options testServerOptions) *Server {
	t.Helper()

	settings := testSettings()
	if options.adjust != nil {
		options.adjust(&settings)
	}

	api := options.api
	if api == nil {
		api = newFakeAPI()
	}

	server, err := New(Deps{Settings: settings, Tokens: authority, Diagnostics: diagnostics.NewExecutor(api),
		Recorder: options.recorder, Issuer: testIssuer, Version: "test"})
	if err != nil {
		t.Fatalf("New() = %v", err)
	}

	return server
}

// adjustSettings returns options that only adjust settings.
func adjustSettings(adjust func(*config.MCPServerConfig)) testServerOptions {
	return testServerOptions{adjust: adjust}
}

// trustLoopback lets SDK clients reach the endpoint through the loopback proxy transport.
func trustLoopback(settings *config.MCPServerConfig) {
	settings.TrustedProxies = []string{"127.0.0.1/32", "::1/128"}
}

// proxied returns a request as forwarded by the trusted TLS proxy.
func proxied(method string, path string, body string, token string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.RemoteAddr = testProxy + ":40000"
	request.Host = testHost
	request.Header.Set(headerForwardedProto, "https")
	request.Header.Set(headerForwardedFor, "203.0.113.7")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")

	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}

	return request
}

// serve runs one request against the endpoint.
func serve(server *Server, request *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)

	return recorder
}

// toolCall renders a tools/call JSON-RPC request.
func toolCall(name string, arguments string) string {
	return `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `","arguments":` + arguments + `}}`
}

// proxyTransport adds the bearer token and the trusted proxy headers to every SDK client request.
type proxyTransport struct {
	token string
}

// RoundTrip forwards the request as a trusted TLS-terminating proxy on the loopback address would.
func (p proxyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.Host = testHost
	clone.Header.Set("Authorization", "Bearer "+p.token)
	clone.Header.Set(headerForwardedProto, "https")
	clone.Header.Set(headerForwardedFor, "203.0.113.50")

	return http.DefaultTransport.RoundTrip(clone)
}

// connect serves the endpoint handler and runs an SDK client against it with the token and
// protocol version; the endpoint must trust the loopback proxy.
func connect(t *testing.T, server *Server, token string, version string) *mcp.ClientSession {
	t.Helper()

	listener := httptest.NewServer(server.Handler())
	t.Cleanup(listener.Close)

	return connectURL(t, listener.URL+"/mcp", token, version)
}

// connectURL runs an SDK client against an endpoint URL through the loopback proxy transport.
func connectURL(t *testing.T, endpoint string, token string, version string) *mcp.ClientSession {
	t.Helper()

	client := mcp.NewClient(&mcp.Implementation{Name: "director-test", Version: "1"}, nil)

	session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: endpoint,
		HTTPClient: &http.Client{Transport: proxyTransport{token: token}}}, &mcp.ClientSessionOptions{ProtocolVersion: version})
	if err != nil {
		t.Fatalf("Connect(%s) = %v", version, err)
	}

	t.Cleanup(func() { _ = session.Close() })

	return session
}

// resultText returns the text of the first content block.
func resultText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()

	if result == nil || len(result.Content) == 0 {
		t.Fatalf("result has no content: %+v", result)
	}

	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content = %T", result.Content[0])
	}

	return text.Text
}
