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

//nolint:goconst // MCP E2E fixtures repeat tool and argument names as the public contract spells them.
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	e2eMCPClient          = "support-cli"
	e2eMCPSubject         = "operator-alice"
	e2eMCPToken           = "mcp-user-token-secret-sentinel"
	e2eMCPRuntimeOnly     = "mcp-runtime-only-token-secret-sentinel"
	e2eMCPForeignAudience = "mcp-foreign-audience-token-secret-sentinel"
	e2eMCPScopeRuntime    = "nauthilus-director.diagnostics.runtime"
	e2eMCPScopeUsers      = "nauthilus-director.diagnostics.users"
	e2eMCPProtocolVersion = "2026-07-28"
	e2eMCPGroup           = "admin"
)

// mcpBearerTransport presents one bearer token on every SDK client request.
type mcpBearerTransport struct {
	token string
}

// RoundTrip adds the Authorization header to a cloned request.
func (m mcpBearerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.Header.Set("Authorization", "Bearer "+m.token)

	return http.DefaultTransport.RoundTrip(clone)
}

// mcpUserToken returns an introspection fixture of a user access token for the MCP resource.
func mcpUserToken(audience []string, scopes ...string) fakeSASLBearerToken {
	return fakeSASLBearerToken{
		Active:          true,
		Audience:        audience,
		AuthorizedParty: e2eMCPClient,
		Subject:         e2eMCPSubject,
		Scopes:          scopes,
		ExpiresAt:       time.Now().Add(10 * time.Minute),
		Groups:          []string{"staff", e2eMCPGroup},
		Tenant:          e2eTenant,
	}
}

// TestServerBinaryMCPDiagnosticsEndpoint proves the MCP diagnostics endpoint of a real process:
// RFC 9728 metadata, RFC 6750 challenges, bearer introspection through the fake Nauthilus issuer,
// tool listing and read-only tool calls over the public socket, and per-tool scope step-up.
func TestServerBinaryMCPDiagnosticsEndpoint(t *testing.T) {
	binary := e2eServerBinary(t)
	redisFixture := startValkeySessionStore(t)
	mcpAddress := loopbackAddress(t)
	resource := "http://" + mcpAddress + "/mcp"
	authority := startMappedFakeOIDCHTTPAuthority(t, nil, map[string][]string{
		"account":   {e2eAccount},
		"tenant":    {e2eTenant},
		"mailShard": {e2eShardTag},
	}, fakeOIDCAuthorityOptions{SASLBearerTokens: map[string]fakeSASLBearerToken{
		e2eMCPToken:           mcpUserToken([]string{e2eMCPClient, resource}, e2eMCPScopeRuntime, e2eMCPScopeUsers),
		e2eMCPRuntimeOnly:     mcpUserToken([]string{resource}, e2eMCPScopeRuntime),
		e2eMCPForeignAudience: mcpUserToken([]string{e2eMCPClient, "https://other.example.test/"}, e2eMCPScopeRuntime),
	}})
	fakeBackend := startFakeIMAPBackend(t, fakeBackendOptions{})
	directorAddress := loopbackAddress(t)
	configPath := writeProcessConfig(t, processConfigOptions{
		RedisAddress:    redisFixture.addr,
		AuthorityURL:    authority.URL(),
		AuthorityOIDC:   processAuthorityOIDCForFake(authority, nil),
		DirectorAddress: directorAddress,
		BackendAddress:  fakeBackend.Address(),
		BackendTLS:      config.BackendTLSConfig{Mode: "plaintext", MinTLSVersion: "TLS1.2"},
		BackendAuth:     masterUserBackendAuth(),
		RuntimeServersYAML: fmt.Sprintf(`    mcp:
      enabled: true
      address: %q
      resource: %q
      authority: default
      allowed_clients: [%q]
      required_groups: [%q]
      limits:
        timeout: 5s
`, mcpAddress, resource, e2eMCPClient, e2eMCPGroup),
	})
	process := startDirectorProcess(t, binary, configPath)

	waitForDirectorGreeting(t, directorAddress, process)
	waitForTCPListener(t, mcpAddress, process)

	assertMCPProtectedResourceMetadata(t, mcpAddress, resource, authority.Issuer())
	assertMCPChallenge(t, resource, "", http.StatusUnauthorized, "")
	assertMCPChallenge(t, resource, e2eMCPForeignAudience, http.StatusUnauthorized, `error="invalid_token"`)

	session := connectE2EMCP(t, resource, e2eMCPToken)
	assertMCPToolInventory(t, session)
	assertMCPBackendsAndRoute(t, session)

	runtimeOnly := connectE2EMCP(t, resource, e2eMCPRuntimeOnly)
	if _, err := runtimeOnly.CallTool(context.Background(), &mcp.CallToolParams{Name: "sessions_list",
		Arguments: map[string]any{}}); err == nil {
		t.Fatal("a runtime-only token must not list sessions")
	}

	if authority.SASLBearerIntrospectionCount() == 0 {
		t.Fatal("MCP tokens were not introspected at the Nauthilus issuer")
	}

	assertOutputOmits(t, process.output.String(), e2eMCPToken, e2eMCPRuntimeOnly, e2eMCPForeignAudience)
	assertNoSecretText(t, process.output.String())
}

// connectE2EMCP connects an SDK client to the real process with one bearer token.
func connectE2EMCP(t *testing.T, endpoint string, token string) *mcp.ClientSession {
	t.Helper()

	client := mcp.NewClient(&mcp.Implementation{Name: "director-e2e", Version: "1"}, nil)

	session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: endpoint,
		HTTPClient: &http.Client{Transport: mcpBearerTransport{token: token}, Timeout: 10 * time.Second}},
		&mcp.ClientSessionOptions{ProtocolVersion: e2eMCPProtocolVersion})
	if err != nil {
		t.Fatalf("connect MCP endpoint: %v", err)
	}

	t.Cleanup(func() { _ = session.Close() })

	return session
}

// assertMCPProtectedResourceMetadata checks the RFC 9728 document of the real process.
func assertMCPProtectedResourceMetadata(t *testing.T, address string, resource string, issuer string) {
	t.Helper()

	response, err := http.Get("http://" + address + "/.well-known/oauth-protected-resource/mcp")
	if err != nil {
		t.Fatalf("get protected resource metadata: %v", err)
	}

	defer func() { _ = response.Body.Close() }()

	var document struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
		Scopes               []string `json:"scopes_supported"`
	}

	if err = json.NewDecoder(response.Body).Decode(&document); err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("metadata = %d, %v", response.StatusCode, err)
	}

	if document.Resource != resource || !slices.Equal(document.AuthorizationServers, []string{strings.TrimRight(issuer, "/")}) ||
		!slices.Equal(document.Scopes, []string{e2eMCPScopeRuntime, e2eMCPScopeUsers}) {
		t.Fatalf("metadata = %+v", document)
	}
}

// assertMCPChallenge posts an initialize request and checks the status and the bearer challenge.
func assertMCPChallenge(t *testing.T, resource string, token string, status int, challenge string) {
	t.Helper()

	request, err := http.NewRequest(http.MethodPost, resource, strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"1"}}}`))
	if err != nil {
		t.Fatal(err)
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")

	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("post MCP request: %v", err)
	}

	defer func() { _ = response.Body.Close() }()

	_, _ = io.Copy(io.Discard, response.Body)

	header := response.Header.Get("WWW-Authenticate")
	if response.StatusCode != status || !strings.Contains(header, "resource_metadata=") || !strings.Contains(header, challenge) {
		t.Fatalf("challenge = %d %q, want %d %q", response.StatusCode, header, status, challenge)
	}
}

// assertMCPToolInventory checks that only read-only diagnostics are listed.
func assertMCPToolInventory(t *testing.T, session *mcp.ClientSession) {
	t.Helper()

	tools, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}

	names := make([]string, 0, len(tools.Tools))

	for _, tool := range tools.Tools {
		names = append(names, tool.Name)

		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Fatalf("tool %s is not marked read-only", tool.Name)
		}
	}

	for _, want := range []string{"runtime_summary", "backends_list", "route_lookup", "sessions_list", "user_detail"} {
		if !slices.Contains(names, want) {
			t.Fatalf("tools = %v, missing %s", names, want)
		}
	}

	for _, mutation := range []string{"delete_session", "move_user", "kick_user", "drain_backend"} {
		if slices.Contains(names, mutation) {
			t.Fatalf("tools = %v, must not contain %s", names, mutation)
		}
	}
}

// assertMCPBackendsAndRoute checks two real tool calls against the process runtime state.
func assertMCPBackendsAndRoute(t *testing.T, session *mcp.ClientSession) {
	t.Helper()

	backends, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "backends_list", Arguments: map[string]any{}})
	if err != nil || backends.IsError || !strings.Contains(mcpResultText(t, backends), `"identifier":"`+e2eBackendAID+`"`) {
		t.Fatalf("backends_list = %+v, %v", backends, err)
	}

	route, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "route_lookup", Arguments: map[string]any{
		"protocol": e2eProtocol, "user_key": e2eAccount, "listener": e2eListenerName}})
	if err != nil || route.IsError || !strings.Contains(mcpResultText(t, route), e2eBackendAID) {
		t.Fatalf("route_lookup = %+v, %v", route, err)
	}

	rejected, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "route_lookup", Arguments: map[string]any{
		"protocol": e2eProtocol, "user_key": e2eAccount, "attributes": map[string]any{"password": []string{"x"}}}})
	if err != nil || !rejected.IsError || !strings.Contains(mcpResultText(t, rejected), "credential_input_rejected") {
		t.Fatalf("route_lookup with credential input = %+v, %v", rejected, err)
	}
}

// mcpResultText returns the text of the first content block of a tool result.
func mcpResultText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()

	if result == nil || len(result.Content) == 0 {
		t.Fatalf("tool result without content: %+v", result)
	}

	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("tool content = %T", result.Content[0])
	}

	return text.Text
}
