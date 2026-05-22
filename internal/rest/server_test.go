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

package rest_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/croessner/nauthilus-director/internal/rest"
	"github.com/croessner/nauthilus-director/internal/rest/generated"
)

const (
	testVersion            = "test-version"
	pathHealthz            = "/healthz"
	pathReadyz             = "/readyz"
	pathVersion            = "/api/v1/version"
	pathBackends           = "/api/v1/backends"
	pathRouteLookup        = "/api/v1/route/lookup"
	codeNotImplemented     = "not_implemented"
	codeCredentialRejected = "credential_input_rejected"
	secretLeakSentinel     = "do-not-leak"
)

// TestServerFoundationEndpoints verifies completed control API endpoints.
func TestServerFoundationEndpoints(t *testing.T) {
	server := httptest.NewServer(rest.NewServer(rest.Options{Version: testVersion}).Handler())
	t.Cleanup(server.Close)

	tests := []struct {
		name string
		path string
	}{
		{name: "health", path: pathHealthz},
		{name: "ready", path: pathReadyz},
		{name: "version", path: pathVersion},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := get(t, server, tt.path)
			defer closeBody(t, response)

			if response.StatusCode != http.StatusOK {
				t.Fatalf("%s status = %d, want %d", tt.path, response.StatusCode, http.StatusOK)
			}
		})
	}
}

// TestServerReturnsStructuredNotImplemented keeps planned routes registered.
func TestServerReturnsStructuredNotImplemented(t *testing.T) {
	server := httptest.NewServer(rest.NewServer(rest.Options{Version: testVersion}).Handler())
	t.Cleanup(server.Close)

	response := get(t, server, pathBackends)
	defer closeBody(t, response)

	if response.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusNotImplemented)
	}

	problem := decodeProblem(t, response)
	if problem.Code != codeNotImplemented || problem.Status != http.StatusNotImplemented {
		t.Fatalf("problem = %#v, want structured not_implemented 501", problem)
	}
}

// TestRouteLookupRejectsCredentialBearingInput enforces diagnostic-only input.
func TestRouteLookupRejectsCredentialBearingInput(t *testing.T) {
	server := httptest.NewServer(rest.NewServer(rest.Options{Version: testVersion}).Handler())
	t.Cleanup(server.Close)

	response, err := server.Client().Post(
		server.URL+pathRouteLookup,
		"application/json",
		strings.NewReader(`{"protocol":"imap","user_key":"user@example.org","password":"`+secretLeakSentinel+`"}`),
	)
	if err != nil {
		t.Fatalf("post route lookup: %v", err)
	}
	defer closeBody(t, response)

	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusBadRequest)
	}

	problem := decodeProblem(t, response)
	if problem.Code != codeCredentialRejected {
		t.Fatalf("problem code = %q, want credential_input_rejected", problem.Code)
	}

	if strings.Contains(problem.Message, secretLeakSentinel) {
		t.Fatalf("problem leaked request value: %#v", problem)
	}
}

// TestRouteLookupWithoutCredentialsStaysDomainIncomplete keeps lookup side-effect-free before implementation.
func TestRouteLookupWithoutCredentialsStaysDomainIncomplete(t *testing.T) {
	server := httptest.NewServer(rest.NewServer(rest.Options{Version: testVersion}).Handler())
	t.Cleanup(server.Close)

	response, err := server.Client().Post(
		server.URL+pathRouteLookup,
		"application/json",
		strings.NewReader(`{"protocol":"imap","user_key":"user@example.org"}`),
	)
	if err != nil {
		t.Fatalf("post route lookup: %v", err)
	}
	defer closeBody(t, response)

	if response.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusNotImplemented)
	}
}

// get performs a GET request with the test server client.
func get(t *testing.T, server *httptest.Server, path string) *http.Response {
	t.Helper()

	response, err := server.Client().Get(server.URL + path)
	if err != nil {
		t.Fatalf("get %s: %v", path, err)
	}

	return response
}

// closeBody closes a response body and reports close failures.
func closeBody(t *testing.T, response *http.Response) {
	t.Helper()

	if err := response.Body.Close(); err != nil {
		t.Fatalf("close response body: %v", err)
	}
}

// decodeProblem reads a generated problem response.
func decodeProblem(t *testing.T, response *http.Response) generated.ErrorResponse {
	t.Helper()

	var problem generated.ErrorResponse
	if err := rest.JSON.NewDecoder(response.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}

	return problem
}
