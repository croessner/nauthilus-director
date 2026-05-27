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
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/rest"
	"github.com/croessner/nauthilus-director/internal/rest/adapters"
	"github.com/croessner/nauthilus-director/internal/rest/generated"
)

const (
	testVersion            = "test-version"
	pathHealthz            = "/healthz"
	pathReadyz             = "/readyz"
	pathVersion            = "/api/v1/version"
	pathBackends           = "/api/v1/backends"
	pathRouteLookup        = "/api/v1/route/lookup"
	pathSessionWithQuery   = "/api/v1/sessions/session-123?token=do-not-use"
	codeCredentialRejected = "credential_input_rejected"
	secretLeakSentinel     = "do-not-leak"
)

// TestServerFoundationEndpoints verifies completed control API endpoints.
func TestServerFoundationEndpoints(t *testing.T) {
	server := rest.NewServer(rest.Options{Version: testVersion})

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
			response := request(t, server, http.MethodGet, tt.path, "")

			if response.Code != http.StatusOK {
				t.Fatalf("%s status = %d, want %d", tt.path, response.Code, http.StatusOK)
			}
		})
	}
}

// TestServerBackendListIsImplemented keeps the generated backend route active.
func TestServerBackendListIsImplemented(t *testing.T) {
	server := rest.NewServer(rest.Options{Version: testVersion})

	response := request(t, server, http.MethodGet, pathBackends, "")

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
}

// TestRouteLookupRejectsCredentialBearingInput enforces diagnostic-only input.
func TestRouteLookupRejectsCredentialBearingInput(t *testing.T) {
	server := rest.NewServer(rest.Options{Version: testVersion})
	response := request(t, server, http.MethodPost, pathRouteLookup, `{"protocol":"imap","user_key":"user@example.org","password":"`+secretLeakSentinel+`"}`)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}

	problem := decodeProblem(t, response)
	if problem.Code != codeCredentialRejected {
		t.Fatalf("problem code = %q, want credential_input_rejected", problem.Code)
	}

	if strings.Contains(problem.Message, secretLeakSentinel) {
		t.Fatalf("problem leaked request value: %#v", problem)
	}
}

// TestRouteLookupWithoutCredentialsIsImplemented keeps lookup side-effect-free and non-stubbed.
func TestRouteLookupWithoutCredentialsIsImplemented(t *testing.T) {
	server := rest.NewServer(rest.Options{Version: testVersion})
	response := request(t, server, http.MethodPost, pathRouteLookup, `{"protocol":"imap","user_key":"user@example.org"}`)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
}

// TestServerRESTObservabilityUsesRouteTemplate verifies REST telemetry avoids raw paths.
func TestServerRESTObservabilityUsesRouteTemplate(t *testing.T) {
	recorder := &recordingRESTRecorder{}
	server := rest.NewServer(rest.Options{
		Version: testVersion,
		HandlerOptions: adapters.HandlerOptions{
			Observability: recorder,
		},
	})

	_ = request(t, server, http.MethodGet, pathSessionWithQuery, "")

	event, ok := recorder.event(observability.EventRESTRequest)
	if !ok {
		t.Fatalf("REST request event not recorded: %#v", recorder.events)
	}

	if got := event.MetricLabels["route"]; got != "/api/v1/sessions/{session_id}" {
		t.Fatalf("route label = %q, want normalized session template", got)
	}

	if strings.Contains(event.MetricLabels["route"], "session-123") || strings.Contains(event.MetricLabels["route"], "token") {
		t.Fatalf("route label leaked raw path or query: %#v", event.MetricLabels)
	}

	if got := event.MetricLabels["operation"]; got != "GetSession" {
		t.Fatalf("operation label = %q, want GetSession", got)
	}
}

// request performs an in-process HTTP request without binding a local port.
func request(t *testing.T, server http.Handler, method string, path string, body string) *httptest.ResponseRecorder {
	t.Helper()

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}

	request := httptest.NewRequest(method, path, reader)
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}

	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)

	return response
}

// recordingRESTRecorder stores REST observability events from the server middleware.
type recordingRESTRecorder struct {
	mu     sync.Mutex
	events []observability.Event
}

// Record stores a copy of one event for route-template assertions.
func (r *recordingRESTRecorder) Record(_ context.Context, event observability.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.events = append(r.events, event)
}

// event returns the first recorded event with the requested name.
func (r *recordingRESTRecorder) event(name string) (observability.Event, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, event := range r.events {
		if event.Name == name {
			return event, true
		}
	}

	return observability.Event{}, false
}

// decodeProblem reads a generated problem response.
func decodeProblem(t *testing.T, response *httptest.ResponseRecorder) generated.ErrorResponse {
	t.Helper()

	var problem generated.ErrorResponse
	if err := rest.JSON.NewDecoder(response.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}

	return problem
}
