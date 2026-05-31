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
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
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

type roundTripFunc func(request *http.Request) (*http.Response, error)

// RoundTrip implements http.RoundTripper for focused transport tests.
func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
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
