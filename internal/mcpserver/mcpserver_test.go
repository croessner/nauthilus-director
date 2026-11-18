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

//nolint:goconst // Transport and token cases repeat fixture names and documentation addresses intentionally.
package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/rest/diagnostics"
	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const initializeBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18",` +
	`"capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`

// TestTransportGuard pins the TLS-proxy boundary, the Host allowlist, the Origin deny gate and the method filter.
func TestTransportGuard(t *testing.T) {
	server := newTestServer(t, newAuthority(), testServerOptions{})

	for name, tc := range map[string]struct {
		mutate func(*http.Request)
		status int
	}{
		"direct untrusted peer": {func(r *http.Request) { r.RemoteAddr = "198.51.100.1:5000" }, http.StatusForbidden},
		"proxy without https":   {func(r *http.Request) { r.Header.Set(headerForwardedProto, "http") }, http.StatusForbidden},
		"foreign host":          {func(r *http.Request) { r.Host = "evil.example.test" }, http.StatusForbidden},
		"foreign origin":        {func(r *http.Request) { r.Header.Set(headerOrigin, "https://evil.example.test") }, http.StatusForbidden},
		"options method":        {func(r *http.Request) { r.Method = http.MethodOptions }, http.StatusMethodNotAllowed},
		"accepted transport":    {func(*http.Request) {}, http.StatusUnauthorized},
	} {
		t.Run(name, func(t *testing.T) {
			request := proxied(http.MethodPost, "/mcp", `{}`, "")
			tc.mutate(request)

			if recorder := serve(server, request); recorder.Code != tc.status {
				t.Fatalf("status = %d body = %s, want %d", recorder.Code, recorder.Body.String(), tc.status)
			}
		})
	}

	if serve(server, proxied(http.MethodGet, "/other", "", "good")).Code != http.StatusNotFound {
		t.Fatal("unknown paths must not be served")
	}
}

// TestDirectLoopbackResource pins that a plain-http loopback resource is reachable from loopback
// without a proxy, and from nowhere else.
func TestDirectLoopbackResource(t *testing.T) {
	server := newTestServer(t, newAuthority(), adjustSettings(func(s *config.MCPServerConfig) {
		s.Resource = "http://127.0.0.1:9097/mcp"
		s.TrustedProxies = nil
	}))

	request := proxied(http.MethodPost, "/mcp", `{}`, "")
	request.RemoteAddr = "127.0.0.1:50000"
	request.Host = "127.0.0.1:9097"
	request.Header.Del(headerForwardedProto)

	if code := serve(server, request).Code; code != http.StatusUnauthorized {
		t.Fatalf("direct loopback = %d, want 401 challenge", code)
	}

	request.RemoteAddr = "198.51.100.1:5000"

	if code := serve(server, request).Code; code != http.StatusForbidden {
		t.Fatalf("direct non-loopback = %d, want 403", code)
	}
}

// TestForwardedClientIgnoresSpoofedHops pins that only the right-most untrusted X-Forwarded-For
// hop is the client, that hops may carry ports, and that a chain without a parsable client hop is
// refused instead of collapsing into the proxy.
func TestForwardedClientIgnoresSpoofedHops(t *testing.T) {
	server := newTestServer(t, newAuthority(), adjustSettings(func(s *config.MCPServerConfig) {
		s.TrustedProxies = []string{testProxy + "/32", "10.0.0.0/8"}
	}))

	for name, tc := range map[string]struct {
		values []string
		want   string
		ok     bool
	}{
		"spoofed left hop": {[]string{"1.2.3.4, 203.0.113.7"}, "203.0.113.7", true},
		"internal hops":    {[]string{"203.0.113.7, 10.1.1.1", "10.2.2.2"}, "203.0.113.7", true},
		"hop with port":    {[]string{"203.0.113.7:51234"}, "203.0.113.7", true},
		"ipv6 with port":   {[]string{"[2001:db8::7]:443"}, "2001:db8::7", true},
		"garbage hop":      {[]string{"203.0.113.7, not-an-ip"}, "", false},
		"only proxies":     {[]string{"10.1.1.1"}, "", false},
		"no header":        {nil, "", false},
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := server.forwardedClient(tc.values)
			if ok != tc.ok || (ok && got.String() != tc.want) {
				t.Fatalf("forwardedClient() = %s %v, want %s %v", got, ok, tc.want, tc.ok)
			}
		})
	}

	request := proxied(http.MethodPost, "/mcp", `{}`, "")
	request.Header.Del(headerForwardedFor)

	if code := serve(server, request).Code; code != http.StatusForbidden {
		t.Fatalf("a trusted proxy request without client hop = %d, want 403", code)
	}

	request = proxied(http.MethodPost, "/mcp", `{}`, "")
	request.Header.Add(headerOrigin, "https://a.example.test")
	request.Header.Add(headerOrigin, "https://b.example.test")

	if code := serve(server, request).Code; code != http.StatusForbidden {
		t.Fatalf("multiple Origin headers = %d, want 403", code)
	}
}

// TestBearerVerificationMatrix pins 401/403/503 and the RFC 6750/9728 challenges for every rejected token class.
func TestBearerVerificationMatrix(t *testing.T) {
	authority := newAuthority()
	server := newTestServer(t, authority, adjustSettings(func(s *config.MCPServerConfig) { s.Limits.FailedAuthPerMinute = 100 }))

	for name, tc := range map[string]struct {
		token     string
		status    int
		challenge string
	}{
		"missing token":        {"", http.StatusUnauthorized, ""},
		"inactive token":       {"unknown", http.StatusUnauthorized, errorInvalidToken},
		"wrong audience":       {"wrong-audience", http.StatusUnauthorized, errorInvalidToken},
		"additional audience":  {"extra-audience", http.StatusUnauthorized, errorInvalidToken},
		"client audience only": {"client-only", http.StatusUnauthorized, errorInvalidToken},
		"unlisted client":      {"unlisted", http.StatusUnauthorized, errorInvalidToken},
		"service token":        {"service-token", http.StatusUnauthorized, errorInvalidToken},
		"no subject":           {"no-subject", http.StatusUnauthorized, errorInvalidToken},
		"expired":              {"expired", http.StatusUnauthorized, errorInvalidToken},
		"no expiry":            {"no-expiry", http.StatusUnauthorized, errorInvalidToken},
		"not entitled":         {"not-entitled", http.StatusUnauthorized, errorInvalidToken},
		"group string claim":   {"group-string", http.StatusOK, ""},
		"no resource scope":    {"no-scope", http.StatusForbidden, errorInsufficientScope},
		"resource audience":    {"resource-only", http.StatusOK, ""},
		"accepted":             {"good", http.StatusOK, ""},
	} {
		t.Run(name, func(t *testing.T) {
			recorder := serve(server, proxied(http.MethodPost, "/mcp", initializeBody, tc.token))
			if recorder.Code != tc.status {
				t.Fatalf("status = %d body = %s, want %d", recorder.Code, recorder.Body.String(), tc.status)
			}

			if tc.status == http.StatusOK {
				return
			}

			header := recorder.Header().Get("WWW-Authenticate")
			if !strings.HasPrefix(header, "Bearer ") ||
				!strings.Contains(header, `resource_metadata="https://director.example.test/.well-known/oauth-protected-resource/mcp"`) ||
				!strings.Contains(header, `scope="nauthilus-director.diagnostics.runtime nauthilus-director.diagnostics.users"`) ||
				(tc.challenge != "" && !strings.Contains(header, `error="`+tc.challenge+`"`)) {
				t.Fatalf("WWW-Authenticate = %q", header)
			}
		})
	}

	authority.setUnavailable(true)

	recorder := serve(server, proxied(http.MethodPost, "/mcp", initializeBody, "good"))
	if recorder.Code != http.StatusServiceUnavailable || recorder.Header().Get("Retry-After") == "" {
		t.Fatalf("unavailable authority = %d", recorder.Code)
	}
}

// TestBearerTokenHeaderShape pins that only exactly one well-formed Bearer header is read.
func TestBearerTokenHeaderShape(t *testing.T) {
	for name, values := range map[string][]string{
		"basic scheme":     {"Basic Zm9vOmJhcg=="},
		"two headers":      {"Bearer good", "Bearer good"},
		"empty token":      {"Bearer "},
		"embedded space":   {"Bearer go od"},
		"no token at all":  {"Bearer"},
		"lowercase scheme": {"bearer good"},
	} {
		request := proxied(http.MethodPost, "/mcp", `{}`, "")
		for _, value := range values {
			request.Header.Add("Authorization", value)
		}

		_, present := bearerToken(request)
		if want := name == "lowercase scheme"; present != want {
			t.Fatalf("%s: present = %v, want %v", name, present, want)
		}
	}
}

// TestFailedBearerLimiter pins the per-client-IP failure bound and that discovery probes are free.
func TestFailedBearerLimiter(t *testing.T) {
	server := newTestServer(t, newAuthority(), testServerOptions{})

	for range 5 {
		serve(server, proxied(http.MethodPost, "/mcp", `{}`, ""))
	}

	for attempt := range 3 {
		if code := serve(server, proxied(http.MethodPost, "/mcp", `{}`, "forged")).Code; code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d", attempt, code)
		}
	}

	if code := serve(server, proxied(http.MethodPost, "/mcp", `{}`, "good")).Code; code != http.StatusTooManyRequests {
		t.Fatalf("after the limit = %d, want 429 even for a valid token", code)
	}

	other := proxied(http.MethodPost, "/mcp", `{}`, "forged")
	other.Header.Set(headerForwardedFor, "203.0.113.8")

	if code := serve(server, other).Code; code != http.StatusUnauthorized {
		t.Fatalf("another client = %d, want 401", code)
	}

	limiter := newFailureLimiter(1, time.Minute, func() time.Time { return time.Unix(0, 0) })
	client := netip.MustParseAddr("203.0.113.9")
	limiter.fail(client)

	if !limiter.blocked(client) {
		t.Fatal("limiter must block after the limit")
	}

	limiter.now = func() time.Time { return time.Unix(61, 0) }

	if limiter.blocked(client) {
		t.Fatal("limiter must reset after the window")
	}
}

// TestFailedBearerLimiterKeysAndCapacity pins IPv6 accounting per /64 and that a full table of
// live windows never blocks an untracked client.
func TestFailedBearerLimiterKeysAndCapacity(t *testing.T) {
	limiter := newFailureLimiter(1, time.Minute, func() time.Time { return time.Unix(0, 0) })
	limiter.fail(netip.MustParseAddr("2001:db8:1:2::1"))

	if !limiter.blocked(netip.MustParseAddr("2001:db8:1:2:ffff::9")) {
		t.Fatal("addresses of one IPv6 /64 must share one window")
	}

	if limiter.blocked(netip.MustParseAddr("2001:db8:1:3::1")) {
		t.Fatal("another /64 must not be blocked")
	}

	full := newFailureLimiter(1, time.Minute, func() time.Time { return time.Unix(0, 0) })
	for index := range maxTrackedClients {
		full.fail(netip.AddrFrom4([4]byte{10, byte(index >> 16), byte(index >> 8), byte(index)}))
	}

	stranger := netip.MustParseAddr("198.51.100.77")
	full.fail(stranger)

	if full.blocked(stranger) || len(full.entries) != maxTrackedClients {
		t.Fatalf("a full table must stop tracking new clients instead of blocking them (entries=%d)", len(full.entries))
	}

	if !full.blocked(netip.AddrFrom4([4]byte{10, 0, 0, 1})) {
		t.Fatal("tracked clients stay limited while the table is full")
	}
}

// TestGateBoundsPrincipals pins the per-principal share and the global bound.
func TestGateBoundsPrincipals(t *testing.T) {
	bounded := newGate(2, 1, 10*time.Millisecond)

	release, ok := bounded.acquire(context.Background(), "a")
	if !ok {
		t.Fatal("first slot must be granted")
	}

	if _, again := bounded.acquire(context.Background(), "a"); again {
		t.Fatal("a principal must not exceed its share")
	}

	releaseB, okB := bounded.acquire(context.Background(), "b")
	if !okB {
		t.Fatal("another principal must get the second slot")
	}

	if _, full := bounded.acquire(context.Background(), "c"); full {
		t.Fatal("the global bound must hold")
	}

	release()
	release()
	releaseB()

	if len(bounded.perCaller) != 0 || len(bounded.slots) != 0 {
		t.Fatalf("released gate keeps state: %v %d", bounded.perCaller, len(bounded.slots))
	}
}

// TestProtectedResourceMetadata pins the RFC 9728 document at both locations.
func TestProtectedResourceMetadata(t *testing.T) {
	server := newTestServer(t, newAuthority(), testServerOptions{})

	for _, path := range []string{"/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource"} {
		recorder := serve(server, proxied(http.MethodGet, path, "", ""))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s = %d", path, recorder.Code)
		}

		var document struct {
			Resource             string   `json:"resource"`
			AuthorizationServers []string `json:"authorization_servers"`
			Scopes               []string `json:"scopes_supported"`
			BearerMethods        []string `json:"bearer_methods_supported"`
		}

		if err := json.Unmarshal(recorder.Body.Bytes(), &document); err != nil {
			t.Fatal(err)
		}

		if document.Resource != testResource || !slices.Equal(document.AuthorizationServers, []string{testIssuer}) ||
			!slices.Equal(document.Scopes, diagnostics.Scopes()) || !slices.Equal(document.BearerMethods, []string{"header"}) {
			t.Fatalf("%s = %+v", path, document)
		}
	}

	if code := serve(server, proxied(http.MethodPost, "/.well-known/oauth-protected-resource/mcp", "", "")).Code; code != http.StatusMethodNotAllowed {
		t.Fatalf("POST metadata = %d", code)
	}
}

// TestBodyInspection pins the refusals before the SDK and the per-tool scope challenge.
func TestBodyInspection(t *testing.T) {
	server := newTestServer(t, newAuthority(), adjustSettings(func(s *config.MCPServerConfig) { s.Limits.MaxRequestBytes = 512 }))
	summary := diagnostics.OperationRuntimeSummary
	sessions := diagnostics.OperationSessionsList

	for name, tc := range map[string]struct {
		token   string
		body    string
		headers map[string]string
		status  int
	}{
		"duplicate names":     {"good", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","name":"b"}}`, nil, http.StatusBadRequest},
		"batch":               {"good", `[` + toolCall(summary, `{}`) + `]`, nil, http.StatusBadRequest},
		"oversized":           {"good", toolCall(summary, `{"x":"`+strings.Repeat("a", 600)+`"}`), nil, http.StatusRequestEntityTooLarge},
		"method mismatch":     {"good", toolCall(summary, `{}`), map[string]string{headerMCPMethod: "tools/list"}, http.StatusBadRequest},
		"name mismatch":       {"good", toolCall(summary, `{}`), map[string]string{headerMCPName: sessions}, http.StatusBadRequest},
		"tool scope":          {"runtime-only", toolCall(sessions, `{}`), nil, http.StatusForbidden},
		"method case variant": {"runtime-only", `{"jsonrpc":"2.0","id":1,"method":"tools/call","Method":"ping","params":{"name":"` + sessions + `","arguments":{}}}`, nil, http.StatusBadRequest},
		"name case variant":   {"runtime-only", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + summary + `","Name":"` + sessions + `"}}`, nil, http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			request := proxied(http.MethodPost, "/mcp", tc.body, tc.token)
			for key, value := range tc.headers {
				request.Header.Set(key, value)
			}

			recorder := serve(server, request)
			if recorder.Code != tc.status {
				t.Fatalf("status = %d body = %s, want %d", recorder.Code, recorder.Body.String(), tc.status)
			}

			if tc.status == http.StatusForbidden && !strings.Contains(recorder.Header().Get("WWW-Authenticate"),
				`error="insufficient_scope", scope="`+diagnostics.ScopeUsersRead+`"`) {
				t.Fatalf("WWW-Authenticate = %q", recorder.Header().Get("WWW-Authenticate"))
			}
		})
	}
}

// TestProtocolErasListAndCallTools pins that the stateless 2026-07-28 protocol and the handshake
// era both list every read-only tool and run calls through the shared diagnostics table.
func TestProtocolErasListAndCallTools(t *testing.T) {
	server := newTestServer(t, newAuthority(), adjustSettings(trustLoopback))

	for _, version := range supportedProtocolVersions {
		t.Run(version, func(t *testing.T) {
			session := connect(t, server, "good", version)

			assertReadOnlyTools(t, session)
			assertToolCalls(t, session)
		})
	}
}

// assertReadOnlyTools checks that every operation is listed as a read-only, closed-world tool
// with the untrusted-data notice and an object input schema.
func assertReadOnlyTools(t *testing.T, session *mcp.ClientSession) {
	t.Helper()

	tools, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}

	names := make([]string, 0, len(tools.Tools))

	for _, tool := range tools.Tools {
		names = append(names, tool.Name)

		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint || *tool.Annotations.DestructiveHint ||
			*tool.Annotations.OpenWorldHint || !strings.Contains(tool.Description, "untrusted data") {
			t.Fatalf("tool %s annotations = %+v", tool.Name, tool.Annotations)
		}

		schema, _ := json.Marshal(tool.InputSchema)
		if !strings.Contains(string(schema), `"type":"object"`) {
			t.Fatalf("tool %s schema = %s", tool.Name, schema)
		}
	}

	want := make([]string, 0, len(diagnostics.Operations()))
	for _, operation := range diagnostics.Operations() {
		want = append(want, operation.Name)
	}

	slices.Sort(want)
	slices.Sort(names)

	if !slices.Equal(names, want) {
		t.Fatalf("tools = %v, want %v", names, want)
	}
}

// assertToolCalls checks one processed call, one handler error and argument refusals.
func assertToolCalls(t *testing.T, session *mcp.ClientSession) {
	t.Helper()

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: diagnostics.OperationRuntimeSummary,
		Arguments: map[string]any{}})
	if err != nil || result.IsError || !strings.Contains(resultText(t, result), `"routing_authority":true`) ||
		result.StructuredContent == nil {
		t.Fatalf("runtime summary = %+v, %v", result, err)
	}

	for name, tc := range map[string]struct {
		tool      string
		arguments map[string]any
		code      string
	}{
		"unknown backend":         {diagnostics.OperationBackendDetail, map[string]any{"identifier": "missing"}, "not_found"},
		"missing path parameter":  {diagnostics.OperationBackendDetail, map[string]any{}, diagnostics.ProblemCodeBadRequest},
		"unknown argument":        {diagnostics.OperationRuntimeSummary, map[string]any{"extra": true}, diagnostics.ProblemCodeBadRequest},
		"credential in lookup": {diagnostics.OperationRouteLookup, map[string]any{"protocol": "imap", "user_key": "u",
			"attributes": map[string]any{"password": []string{"x"}}}, diagnostics.ProblemCodeCredentialInput},
	} {
		call, callErr := session.CallTool(context.Background(), &mcp.CallToolParams{Name: tc.tool, Arguments: tc.arguments})
		if callErr != nil || !call.IsError || !strings.Contains(resultText(t, call), `"code":"`+tc.code) {
			t.Fatalf("%s = %+v, %v", name, call, callErr)
		}
	}
}

// TestResponseCap pins that a result above max_response_bytes is replaced by response_too_large.
func TestResponseCap(t *testing.T) {
	server := newTestServer(t, newAuthority(), adjustSettings(func(s *config.MCPServerConfig) {
		trustLoopback(s)
		s.Limits.MaxResponseBytes = 64
	}))

	result, err := connect(t, server, "good", "2025-06-18").CallTool(context.Background(),
		&mcp.CallToolParams{Name: diagnostics.OperationRuntimeSummary, Arguments: map[string]any{}})
	if err != nil || !result.IsError || !strings.Contains(resultText(t, result), diagnostics.ProblemCodeResponseTooLarge) {
		t.Fatalf("CallTool = %+v, %v", result, err)
	}
}

// TestAuditRecordsCarryNoSecrets pins that request events name the principal and outcome but
// never the bearer token or tool arguments, and that the client address stays collapsed.
func TestAuditRecordsCarryNoSecrets(t *testing.T) {
	events := &eventLog{}
	server := newTestServer(t, newAuthority(), testServerOptions{recorder: events, adjust: func(s *config.MCPServerConfig) {
		s.TrustedProxies = []string{"127.0.0.1/32", "::1/128", testProxy + "/32"}
	}})

	_, err := connect(t, server, "good", "2026-07-28").CallTool(context.Background(),
		&mcp.CallToolParams{Name: diagnostics.OperationUserDetail, Arguments: map[string]any{"user_key": "secret-user-key"}})
	if err != nil {
		t.Fatal(err)
	}

	serve(server, proxied(http.MethodPost, "/mcp", `{}`, "forged-token-sentinel"))

	var tool, rejected bool

	for _, event := range events.snapshot() {
		if event.Name != observability.EventMCPRequest {
			continue
		}

		rendered, _ := json.Marshal(event)
		if strings.Contains(string(rendered), "forged-token-sentinel") || strings.Contains(string(rendered), "secret-user-key") ||
			strings.Contains(string(rendered), "203.0.113.50") {
			t.Fatalf("event leaks request data: %s", rendered)
		}

		switch {
		case event.LogFields[fieldOperation] == diagnostics.OperationUserDetail:
			tool = event.LogFields[fieldActorID] == staticClient+"#"+testSubject && event.LogFields[fieldLevel] == levelInfo
		case event.LogFields[fieldReason] == "invalid_token":
			rejected = event.MetricLabels[fieldResult] == resultUnauthorized
		}
	}

	if !tool || !rejected {
		t.Fatalf("tool=%v rejected=%v events=%+v", tool, rejected, events.snapshot())
	}
}

// TestNewRequiresCompleteDeps pins the constructor boundary.
func TestNewRequiresCompleteDeps(t *testing.T) {
	if _, err := New(Deps{}); err == nil {
		t.Fatal("empty deps must be rejected")
	}

	settings := testSettings()
	settings.Resource = "/relative"

	if _, err := New(Deps{Settings: settings, Tokens: newAuthority(), Issuer: testIssuer}); err == nil {
		t.Fatal("a relative resource must be rejected")
	}

	if _, err := New(Deps{Settings: testSettings(), Tokens: newAuthority()}); err == nil {
		t.Fatal("a missing issuer must be rejected")
	}
}
