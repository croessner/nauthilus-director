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

//nolint:funlen,goconst,wsl_v5 // Tests keep request fixtures and assertions together.
package nauthilus

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/croessner/nauthilus-director/internal/config"
)

// TestHTTPAuthenticateSendsStrictNauthilusJSON verifies the outbound JSON contract.
func TestHTTPAuthenticateSendsStrictNauthilusJSON(t *testing.T) {
	var captured map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		assertHTTPAuthorityRequest(t, request, "", defaultHTTPContentType)
		captured = decodeJSONMap(t, request)
		assertExactFieldSet(t, captured, []string{
			"auth_login_attempt",
			"client_ip",
			"client_port",
			"method",
			"password",
			"protocol",
			"ssl",
			"ssl_client_cn",
			"ssl_client_verify",
			"username",
		})
		assertForbiddenDirectorFieldsAbsent(t, captured)
		assertField(t, captured, "protocol", "imap")
		assertField(t, captured, "ssl", "true")
		assertField(t, captured, "ssl_client_verify", "SUCCESS")
		assertField(t, captured, "ssl_client_cn", "client.example.test")
		assertFieldAbsent(t, captured, "service")

		writer.Header().Set("Content-Type", defaultHTTPContentType)
		_, _ = writer.Write([]byte(`{"ok":true,"account_field":"uid","backend":7,"attributes":{"uid":["alice"],"tenant":["blue"]}}`))
	}))
	defer server.Close()

	client := newTestHTTPClient(t, server.URL+"/api/v1/auth/json", nil)
	result, err := client.Authenticate(context.Background(), AuthRequest{
		Context: RequestContext{
			Username:        "alice@example.test",
			ClientIP:        "203.0.113.10",
			ClientPort:      "12345",
			Protocol:        "imap",
			Method:          "plain",
			TLS:             "true",
			TLSClientVerify: "SUCCESS",
			TLSClientCN:     "client.example.test",
		},
		Credential:       NewSecret("correct horse battery staple"),
		AuthLoginAttempt: 1,
	})
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if result.Decision != DecisionAuthenticated || result.Account != "alice" {
		t.Fatalf("result = %#v, want authenticated alice", result)
	}
	if got := result.Attributes["tenant"]; len(got) != 1 || got[0] != "blue" {
		t.Fatalf("tenant attributes = %#v", got)
	}
	if _, exists := captured["service"]; exists {
		t.Fatal("outbound HTTP request contained forbidden service field")
	}
}

// TestHTTPLookupIdentityUsesNoAuthMode verifies the no-auth lookup boundary.
func TestHTTPLookupIdentityUsesNoAuthMode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		assertHTTPAuthorityRequest(t, request, "no-auth", defaultHTTPContentType)
		captured := decodeJSONMap(t, request)
		assertExactFieldSet(t, captured, []string{"method", "protocol", "username"})
		assertFieldAbsent(t, captured, "password")
		assertForbiddenDirectorFieldsAbsent(t, captured)

		writer.Header().Set("Content-Type", defaultHTTPContentType)
		_, _ = writer.Write([]byte(`{"ok":true,"account_field":"mail","attributes":{"mail":["lookup-account"],"shard":["s1"]}}`))
	}))
	defer server.Close()

	client := newTestHTTPClient(t, server.URL+"/api/v1/auth/json", nil)
	result, err := client.LookupIdentity(context.Background(), IdentityLookupRequest{
		Context: RequestContext{
			Username: "lookup@example.test",
			Protocol: "imap",
			Method:   "lookup",
		},
	})
	if err != nil {
		t.Fatalf("LookupIdentity returned error: %v", err)
	}
	if result.Decision != DecisionAuthenticated || result.Account != "lookup-account" {
		t.Fatalf("result = %#v, want lookup-account", result)
	}
}

// TestHTTPListAccountsUsesAuthorityBoundary verifies account listing stays account-only.
func TestHTTPListAccountsUsesAuthorityBoundary(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		assertHTTPAuthorityRequest(t, request, "list-accounts", defaultHTTPContentType)
		captured := decodeJSONMap(t, request)
		assertExactFieldSet(t, captured, []string{"method", "protocol", "username"})
		assertForbiddenDirectorFieldsAbsent(t, captured)

		writer.Header().Set("Content-Type", defaultHTTPContentType)
		_, _ = writer.Write([]byte(`["alpha@example.test","zeta@example.test"]`))
	}))
	defer server.Close()

	client := newTestHTTPClient(t, server.URL+"/api/v1/auth/json", nil)
	result, err := client.ListAccounts(context.Background(), ListAccountsRequest{
		Context: RequestContext{
			Username: "list@example.test",
			Protocol: "imap",
			Method:   "list",
		},
	})
	if err != nil {
		t.Fatalf("ListAccounts returned error: %v", err)
	}
	if !slices.Equal(result.Accounts, []string{"alpha@example.test", "zeta@example.test"}) {
		t.Fatalf("accounts = %#v", result.Accounts)
	}
	if result.Decision != DecisionAuthenticated {
		t.Fatalf("decision = %q, want %q", result.Decision, DecisionAuthenticated)
	}
}

// TestHTTPAuthorityContextHeadersSentForAllOperations verifies listener context reaches every HTTP operation.
func TestHTTPAuthorityContextHeadersSentForAllOperations(t *testing.T) {
	seen := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("X-Company-Domain"); got != "companyde" {
			t.Fatal("listener context header did not match expected value")
		}

		mode := request.URL.Query().Get(queryMode)
		switch mode {
		case "":
			seen["authenticate"] = true
			_, _ = writer.Write([]byte(`{"ok":true,"account_field":"uid","attributes":{"uid":["alice"]}}`))
		case "no-auth":
			seen["lookup"] = true
			_, _ = writer.Write([]byte(`{"ok":true,"account_field":"uid","attributes":{"uid":["alice"]}}`))
		case "list-accounts":
			seen["list"] = true
			_, _ = writer.Write([]byte(`["alice@example.test"]`))
		default:
			t.Fatalf("unexpected mode = %q", mode)
		}
	}))
	defer server.Close()

	client := newTestHTTPClientWithAuthorityContext(t, server.URL+"/api/v1/auth/json", AuthorityContext{
		HTTPHeaders: map[string]string{
			"X-Company-Domain": "companyde",
		},
	})

	if _, err := client.Authenticate(context.Background(), testAuthRequest()); err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if _, err := client.LookupIdentity(context.Background(), IdentityLookupRequest{Context: testAuthRequest().Context}); err != nil {
		t.Fatalf("LookupIdentity returned error: %v", err)
	}
	if _, err := client.ListAccounts(context.Background(), ListAccountsRequest{Context: testAuthRequest().Context}); err != nil {
		t.Fatalf("ListAccounts returned error: %v", err)
	}

	for _, operation := range []string{"authenticate", "lookup", "list"} {
		if !seen[operation] {
			t.Fatalf("%s request did not reach fake authority", operation)
		}
	}
}

// TestHTTPAuthorityPropagatesTraceContext verifies outbound auth calls carry the active trace.
func TestHTTPAuthorityPropagatesTraceContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("traceparent"); !strings.Contains(got, testTraceID) {
			t.Fatalf("traceparent = %q, want trace ID %s", got, testTraceID)
		}

		writer.Header().Set("Content-Type", defaultHTTPContentType)
		_, _ = writer.Write([]byte(`{"ok":true,"account_field":"uid","attributes":{"uid":["alice"]}}`))
	}))
	defer server.Close()

	client := newTestHTTPClient(t, server.URL+"/api/v1/auth/json", nil)
	if _, err := client.Authenticate(contextWithTestTrace(), testAuthRequest()); err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
}

// TestHTTPAuthorityContextDoesNotOverrideTransportHeaders verifies caller auth and content negotiation win.
func TestHTTPAuthorityContextDoesNotOverrideTransportHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		wantAuthorization := "Basic " + base64.StdEncoding.EncodeToString([]byte("director:api-secret"))
		if got := request.Header.Get("Authorization"); got != wantAuthorization {
			t.Fatal("authorization header did not preserve configured basic caller auth")
		}
		if got := request.Header.Get("Content-Type"); got != defaultHTTPContentType {
			t.Fatalf("content-type = %q, want %q", got, defaultHTTPContentType)
		}
		if got := request.Header.Get("Accept"); got != defaultHTTPContentType {
			t.Fatalf("accept = %q, want %q", got, defaultHTTPContentType)
		}
		if got := request.Header.Get("X-Company-Domain"); got != "companyde" {
			t.Fatal("listener context header did not match expected value")
		}

		_, _ = writer.Write([]byte(`{"ok":true,"account_field":"uid","attributes":{"uid":["alice"]}}`))
	}))
	defer server.Close()

	client, err := NewHTTPClient(HTTPClientConfig{
		Endpoint:          server.URL + "/api/v1/auth/json",
		ContentType:       defaultHTTPContentType,
		BasicAuthUsername: "director",
		BasicAuthPassword: NewSecret("api-secret"),
		AuthorityContext: AuthorityContext{
			HTTPHeaders: map[string]string{
				"Accept":           "text/plain",
				"Authorization":    "Bearer context-token",
				"Content-Type":     "text/plain",
				"X-Company-Domain": "companyde",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}

	if _, err := client.Authenticate(context.Background(), testAuthRequest()); err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
}

// TestHTTPAuthorityOIDCCallerAuthSendsBearerOnly verifies OIDC caller auth replaces Basic auth.
func TestHTTPAuthorityOIDCCallerAuthSendsBearerOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Authorization"); got != "Bearer oidc-caller-token" {
			t.Fatal("authorization header did not preserve OIDC caller auth")
		}
		if _, _, ok := request.BasicAuth(); ok {
			t.Fatal("OIDC caller auth also sent HTTP Basic credentials")
		}

		writer.Header().Set("Content-Type", defaultHTTPContentType)
		_, _ = writer.Write([]byte(`{"ok":true,"account_field":"uid","attributes":{"uid":["alice"]}}`))
	}))
	defer server.Close()

	client, err := NewHTTPClient(HTTPClientConfig{
		Endpoint:          server.URL + "/api/v1/auth/json",
		ContentType:       defaultHTTPContentType,
		BasicAuthUsername: "director",
		BasicAuthPassword: NewSecret("basic-secret"),
		TokenSource:       staticCallerTokenSource{token: "oidc-caller-token"},
	})
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}

	result, err := client.Authenticate(context.Background(), testAuthRequest())
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if result.Decision != DecisionAuthenticated {
		t.Fatalf("decision = %q, want authenticated", result.Decision)
	}
}

// TestHTTPAuthorityOutcomeClassification verifies rejection and fail-closed errors.
func TestHTTPAuthorityOutcomeClassification(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
		body       string
		want       string
		wantKind   ErrorKind
	}{
		{name: "rejected status", statusCode: http.StatusForbidden, body: `null`, want: DecisionRejected},
		{name: "rejected body", statusCode: http.StatusOK, body: `{"ok":false}`, want: DecisionRejected},
		{name: "tempfail status", statusCode: http.StatusInternalServerError, body: `null`, want: DecisionTemporaryFailure, wantKind: ErrorKindTemporaryFailure},
		{name: "malformed json", statusCode: http.StatusOK, body: `{`, want: DecisionTemporaryFailure, wantKind: ErrorKindMalformedResponse},
		{name: "missing account", statusCode: http.StatusOK, body: `{"ok":true}`, want: DecisionTemporaryFailure, wantKind: ErrorKindMalformedResponse},
		{name: "missing account attribute", statusCode: http.StatusOK, body: `{"ok":true,"account_field":"uid","attributes":{"mail":["alice"]}}`, want: DecisionTemporaryFailure, wantKind: ErrorKindMalformedResponse},
		{name: "ambiguous account attribute", statusCode: http.StatusOK, body: `{"ok":true,"account_field":"uid","attributes":{"uid":["alice","alice@example.test"]}}`, want: DecisionTemporaryFailure, wantKind: ErrorKindMalformedResponse},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", defaultHTTPContentType)
				writer.WriteHeader(testCase.statusCode)
				_, _ = writer.Write([]byte(testCase.body))
			}))
			defer server.Close()

			client := newTestHTTPClient(t, server.URL+"/api/v1/auth/json", nil)
			result, err := client.Authenticate(context.Background(), testAuthRequest())
			if result.Decision != testCase.want {
				t.Fatalf("decision = %q, want %q", result.Decision, testCase.want)
			}
			if testCase.wantKind == "" && err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if testCase.wantKind != "" && !IsAuthErrorKind(err, testCase.wantKind) {
				t.Fatalf("err = %v, want kind %q", err, testCase.wantKind)
			}
		})
	}
}

// TestHTTPTransportErrorsAreSecretSafe verifies transport failures do not leak credentials.
func TestHTTPTransportErrorsAreSecretSafe(t *testing.T) {
	transport := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return nil, errors.New("dial failed")
	})
	client := newTestHTTPClient(t, "http://authority.example.test/api/v1/auth/json", &http.Client{Transport: transport})

	result, err := client.Authenticate(context.Background(), testAuthRequest())
	if result.Decision != DecisionTemporaryFailure {
		t.Fatalf("decision = %q, want tempfail", result.Decision)
	}
	if !IsAuthErrorKind(err, ErrorKindTransport) {
		t.Fatalf("err = %v, want transport error", err)
	}
	assertDoesNotContainSecret(t, err.Error(), "secret-password")
}

// TestHTTPClientFromAuthorityUsesConfiguredTLS verifies authority TLS policy reaches the transport.
func TestHTTPClientFromAuthorityUsesConfiguredTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", defaultHTTPContentType)
		_, _ = writer.Write([]byte(`{"ok":true,"account_field":"uid","attributes":{"uid":["alice@example.test"]}}`))
	}))
	defer server.Close()

	caPath := writeHTTPTestCA(t, server.Certificate())
	authority := config.DefaultConfig().Auth.Authorities["default"]
	authority.Transport = "http"
	authority.OIDC.Enabled = false
	authority.HTTP.Endpoint = server.URL
	authority.HTTP.TLS.Enabled = true
	authority.HTTP.TLS.CAFile = caPath
	authority.HTTP.TLS.ServerName = ""
	authority.HTTP.BasicAuth.PasswordFile = config.Secret(writeOIDCSecretFile(t, "director-api-secret\n"))

	client, err := NewHTTPClientFromAuthority(authority, nil, AuthorityContext{})
	if err != nil {
		t.Fatalf("NewHTTPClientFromAuthority: %v", err)
	}

	result, err := client.Authenticate(context.Background(), testAuthRequest())
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if result.Decision != DecisionAuthenticated {
		t.Fatalf("decision = %q, want authenticated", result.Decision)
	}
}

// TestHTTPClientFromAuthorityReadsBasicPasswordFile verifies HTTP caller auth uses file contents.
func TestHTTPClientFromAuthorityReadsBasicPasswordFile(t *testing.T) {
	authority := config.DefaultConfig().Auth.Authorities["default"]
	authority.Transport = "http"
	authority.OIDC.Enabled = false
	authority.HTTP.Endpoint = "http://authority.example.test/api/v1/auth/json"
	authority.HTTP.BasicAuth.Username = "director"
	authority.HTTP.BasicAuth.PasswordFile = config.Secret(writeOIDCSecretFile(t, "director-api-secret\n"))

	client, err := NewHTTPClientFromAuthority(authority, nil, AuthorityContext{})
	if err != nil {
		t.Fatalf("NewHTTPClientFromAuthority returned error: %v", err)
	}
	if client.basicAuthPassword.Value() != "director-api-secret" {
		t.Fatalf("basic auth password = %q, want file content", client.basicAuthPassword.Value())
	}
	if client.basicAuthPassword.Value() == authority.HTTP.BasicAuth.PasswordFile.Value() {
		t.Fatal("basic auth password used the password_file path string")
	}
}

// TestHTTPClientFromAuthorityFailsClosedOnMissingPasswordFile rejects broken file refs.
func TestHTTPClientFromAuthorityFailsClosedOnMissingPasswordFile(t *testing.T) {
	authority := config.DefaultConfig().Auth.Authorities["default"]
	authority.Transport = "http"
	authority.OIDC.Enabled = false
	authority.HTTP.Endpoint = "http://authority.example.test/api/v1/auth/json"
	authority.HTTP.BasicAuth.Username = "director"
	authority.HTTP.BasicAuth.PasswordFile = config.Secret(t.TempDir() + "/missing")

	_, err := NewHTTPClientFromAuthority(authority, nil, AuthorityContext{})
	if err == nil {
		t.Fatal("NewHTTPClientFromAuthority accepted missing password_file")
	}
}

type roundTripFunc func(request *http.Request) (*http.Response, error)

// RoundTrip implements http.RoundTripper for focused transport tests.
func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type staticCallerTokenSource struct {
	token string
	err   error
}

// BearerToken returns the configured fake caller token.
func (s staticCallerTokenSource) BearerToken(context.Context) (string, error) {
	return s.token, s.err
}

// writeHTTPTestCA writes the test server certificate as a trusted authority file.
func writeHTTPTestCA(t *testing.T, certificate *x509.Certificate) string {
	t.Helper()

	path := t.TempDir() + "/authority-ca.pem"
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write test CA: %v", err)
	}

	return path
}

// newTestHTTPClient creates a test client for the supplied endpoint.
func newTestHTTPClient(t *testing.T, endpoint string, httpClient *http.Client) *HTTPClient {
	t.Helper()

	client, err := NewHTTPClient(HTTPClientConfig{
		Endpoint:    endpoint,
		ContentType: defaultHTTPContentType,
		Client:      httpClient,
	})
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}

	return client
}

// newTestHTTPClientWithAuthorityContext creates a test client with static context headers.
func newTestHTTPClientWithAuthorityContext(t *testing.T, endpoint string, authorityContext AuthorityContext) *HTTPClient {
	t.Helper()

	client, err := NewHTTPClient(HTTPClientConfig{
		Endpoint:         endpoint,
		ContentType:      defaultHTTPContentType,
		AuthorityContext: authorityContext,
	})
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}

	return client
}

// testAuthRequest returns a minimal valid authentication request.
func testAuthRequest() AuthRequest {
	return AuthRequest{
		Context: RequestContext{
			Username: "alice@example.test",
			Protocol: "imap",
			Method:   "plain",
		},
		Credential: NewSecret("secret-password"),
	}
}

// assertHTTPAuthorityRequest verifies common HTTP boundary details.
func assertHTTPAuthorityRequest(t *testing.T, request *http.Request, mode string, contentType string) {
	t.Helper()

	if request.Method != http.MethodPost {
		t.Fatalf("method = %s, want POST", request.Method)
	}
	if request.URL.Path != "/api/v1/auth/json" {
		t.Fatalf("path = %q, want /api/v1/auth/json", request.URL.Path)
	}
	if got := request.Header.Get("Content-Type"); got != contentType {
		t.Fatalf("content-type = %q, want %q", got, contentType)
	}
	if got := request.URL.Query().Get(queryMode); got != mode {
		t.Fatalf("mode = %q, want %q", got, mode)
	}
}

// decodeJSONMap decodes a captured JSON request body.
func decodeJSONMap(t *testing.T, request *http.Request) map[string]any {
	t.Helper()

	var body map[string]any
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		t.Fatalf("decode request body: %v", err)
	}

	return body
}

// assertExactFieldSet verifies the outbound body stays golden-field strict.
func assertExactFieldSet(t *testing.T, body map[string]any, want []string) {
	t.Helper()

	got := make([]string, 0, len(body))
	for key := range body {
		got = append(got, key)
	}
	slices.Sort(got)
	slices.Sort(want)

	if !slices.Equal(got, want) {
		t.Fatalf("body fields = %#v, want %#v", got, want)
	}
}

// assertForbiddenDirectorFieldsAbsent verifies director-owned data is not sent.
func assertForbiddenDirectorFieldsAbsent(t *testing.T, body map[string]any) {
	t.Helper()

	for _, field := range []string{
		"backend_identifier",
		"listener",
		"proxy",
		"routing_hint",
		"service",
		"session_id",
		"tls",
	} {
		assertFieldAbsent(t, body, field)
	}
}

// assertField verifies a JSON body field value.
func assertField(t *testing.T, body map[string]any, field string, want string) {
	t.Helper()

	if got, ok := body[field].(string); !ok || got != want {
		t.Fatalf("%s = %#v, want %q", field, body[field], want)
	}
}

// assertFieldAbsent verifies a JSON body field is not present.
func assertFieldAbsent(t *testing.T, body map[string]any, field string) {
	t.Helper()

	if _, ok := body[field]; ok {
		t.Fatalf("field %q unexpectedly present in %#v", field, body)
	}
}

// assertDoesNotContainSecret checks diagnostic text for leaked material.
func assertDoesNotContainSecret(t *testing.T, text string, secret string) {
	t.Helper()

	if strings.Contains(text, secret) {
		t.Fatalf("diagnostic %q leaked secret %q", text, secret)
	}
}
