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

//nolint:goconst // REST secret-safety tests repeat sensitive key names intentionally.
package rest_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
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
	pathMetrics            = "/metrics"
	pathBackends           = "/api/v1/backends"
	pathReload             = "/api/v1/reload"
	pathRouteLookup        = "/api/v1/route/lookup"
	pathPProfIndex         = "/debug/pprof/"
	pathPProfGoroutine     = "/debug/pprof/goroutine?debug=1"
	pathPProfBlock         = "/debug/pprof/block"
	pathPProfMutex         = "/debug/pprof/mutex"
	pathSessionWithQuery   = "/api/v1/sessions/session-123?token=do-not-use"
	codeCredentialRejected = "credential_input_rejected"
	secretLeakSentinel     = "do-not-leak"
	restRequestsMetric     = "nauthilus_director_rest_requests_total"
)

// TestServerFoundationEndpoints verifies completed control API endpoints.
func TestServerFoundationEndpoints(t *testing.T) {
	server, token := authenticatedServer(t, rest.Options{Version: testVersion})

	tests := []struct {
		name      string
		path      string
		authorize bool
	}{
		{name: "health", path: pathHealthz},
		{name: "ready", path: pathReadyz},
		{name: "version", path: pathVersion, authorize: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := requestWithBearer(t, server, http.MethodGet, tt.path, "", token, tt.authorize)

			if response.Code != http.StatusOK {
				t.Fatalf("%s status = %d, want %d", tt.path, response.Code, http.StatusOK)
			}
		})
	}
}

// TestServerBackendListIsImplemented keeps the generated backend route active.
func TestServerBackendListIsImplemented(t *testing.T) {
	server, token := authenticatedServer(t, rest.Options{Version: testVersion})

	response := requestWithBearer(t, server, http.MethodGet, pathBackends, "", token, true)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
}

// TestServerControlAuthProtectsGeneratedRoutes verifies only health probes stay public.
func TestServerControlAuthProtectsGeneratedRoutes(t *testing.T) {
	server, token := authenticatedServer(t, rest.Options{Version: testVersion})

	for _, path := range []string{pathVersion, pathBackends, pathMetrics, pathReload, pathRouteLookup} {
		method := http.MethodGet
		body := ""

		if path == pathReload {
			method = http.MethodPost
		}

		if path == pathRouteLookup {
			method = http.MethodPost
			body = `{"protocol":"imap","user_key":"user@example.org"}`
		}

		response := request(t, server, method, path, body)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("%s status = %d, want 401", path, response.Code)
		}
	}

	response := requestWithBearer(t, server, http.MethodGet, pathVersion, "", token, true)
	if response.Code != http.StatusOK {
		t.Fatalf("authorized version status = %d, want 200", response.Code)
	}

	reload := requestWithBearer(t, server, http.MethodPost, pathReload, "", token, true)
	if reload.Code != http.StatusAccepted {
		t.Fatalf("authorized reload status = %d, want 202 body=%s", reload.Code, reload.Body.String())
	}
}

// TestStaticBearerAuthUsesStableFailures verifies 401 behavior for malformed or wrong tokens.
func TestStaticBearerAuthUsesStableFailures(t *testing.T) {
	server, token := authenticatedServer(t, rest.Options{Version: testVersion})

	tests := []struct {
		name   string
		header string
	}{
		{name: "missing"},
		{name: "malformed", header: "Basic " + token},
		{name: "mismatch", header: "Bearer wrong-token"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, pathVersion, nil)
			if test.header != "" {
				request.Header.Set("Authorization", test.header)
			}

			response := httptest.NewRecorder()
			server.ServeHTTP(response, request)

			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", response.Code)
			}

			problem := decodeProblem(t, response)
			if problem.Code != "unauthorized" {
				t.Fatalf("problem code = %q, want unauthorized", problem.Code)
			}

			if strings.Contains(response.Body.String(), token) {
				t.Fatalf("problem leaked bearer token: %s", response.Body.String())
			}
		})
	}
}

// TestProtectedConfigWithStaticBearerReturnsForbidden verifies no partial protected output leaks.
func TestProtectedConfigWithStaticBearerReturnsForbidden(t *testing.T) {
	server, token := authenticatedServer(t, rest.Options{Version: testVersion})

	response := requestWithBearer(t, server, http.MethodGet, "/api/v1/config/defaults?include_protected=true", "", token, true)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}

	if strings.Contains(response.Body.String(), "/etc/nauthilus-director/control-token") {
		t.Fatalf("protected config response leaked config data: %s", response.Body.String())
	}

	problem := decodeProblem(t, response)
	if problem.Code != "forbidden" {
		t.Fatalf("problem code = %q, want forbidden", problem.Code)
	}
}

// TestOIDCControlAuthEnforcesScopes verifies active tokens still require configured scopes.
func TestOIDCControlAuthEnforcesScopes(t *testing.T) {
	tests := []struct {
		name       string
		token      string
		result     nauthilus.OIDCIntrospectionResult
		err        error
		path       string
		wantStatus int
	}{
		{name: "introspection failure", token: "bad", err: errors.New("introspection failed"), path: pathVersion, wantStatus: http.StatusUnauthorized},
		{name: "inactive", token: "inactive", result: nauthilus.OIDCIntrospectionResult{Active: false}, path: pathVersion, wantStatus: http.StatusUnauthorized},
		{name: "missing ordinary scope", token: "scope-miss", result: oidcResult("operator-a", []string{"other"}), path: pathVersion, wantStatus: http.StatusForbidden},
		{name: "ordinary scope", token: "ordinary", result: oidcResult("operator-a", []string{"nauthilus-director.admin"}), path: pathVersion, wantStatus: http.StatusOK},
		{name: "protected scope missing", token: "ordinary", result: oidcResult("operator-a", []string{"nauthilus-director.admin"}), path: "/api/v1/config/defaults?include_protected=true", wantStatus: http.StatusForbidden},
		{name: "protected scope present", token: "protected", result: oidcResult("operator-a", []string{"nauthilus-director.admin", "nauthilus-director.protected"}), path: "/api/v1/config/defaults?include_protected=true", wantStatus: http.StatusOK},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			introspector := &fakeOIDCIntrospector{result: test.result, err: test.err}
			server := rest.NewServer(rest.Options{
				Version:          testVersion,
				Control:          oidcControlConfig(),
				OIDCIntrospector: introspector,
			})

			response := requestWithBearer(t, server, http.MethodGet, test.path, "", test.token, true)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d body=%s", response.Code, test.wantStatus, response.Body.String())
			}
		})
	}
}

// TestMTLSControlAuthRequiresVerifiedCertificate verifies mTLS uses verified TLS state only.
func TestMTLSControlAuthRequiresVerifiedCertificate(t *testing.T) {
	server := rest.NewServer(rest.Options{Version: testVersion, Control: mtlsControlConfig()})

	missing := request(t, server, http.MethodGet, pathVersion, "")
	if missing.Code != http.StatusUnauthorized {
		t.Fatalf("missing cert status = %d, want 401", missing.Code)
	}

	certificate := &x509.Certificate{Subject: pkix.Name{CommonName: "operator-mtls"}}
	request := httptest.NewRequest(http.MethodGet, pathVersion, nil)
	request.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{certificate},
		VerifiedChains:   [][]*x509.Certificate{{certificate}},
	}
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("verified cert status = %d, want 200", response.Code)
	}

	protectedRequest := httptest.NewRequest(http.MethodGet, "/api/v1/config/defaults?include_protected=true", nil)
	protectedRequest.TLS = request.TLS
	protected := httptest.NewRecorder()
	server.ServeHTTP(protected, protectedRequest)

	if protected.Code != http.StatusForbidden {
		t.Fatalf("mTLS protected status = %d, want 403", protected.Code)
	}
}

// TestRouteLookupRejectsCredentialAndMailboxBearingInput enforces diagnostic-only input.
func TestRouteLookupRejectsCredentialAndMailboxBearingInput(t *testing.T) {
	server, token := authenticatedServer(t, rest.Options{Version: testVersion})
	tests := []struct {
		name string
		body string
	}{
		{name: "password", body: `{"protocol":"imap","user_key":"user@example.org","password":"` + secretLeakSentinel + `"}`},
		{name: "script", body: `{"protocol":"sieve","user_key":"user@example.org","script_name":"` + secretLeakSentinel + `"}`},
		{name: "uidl", body: `{"protocol":"pop3","user_key":"user@example.org","attributes":{"uidl":["` + secretLeakSentinel + `"]}}`},
		{name: "message size", body: `{"protocol":"pop3","user_key":"user@example.org","message_size":"` + secretLeakSentinel + `"}`},
		{name: "mailbox", body: `{"protocol":"pop3","user_key":"user@example.org","mailbox":"` + secretLeakSentinel + `"}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := requestWithBearer(t, server, http.MethodPost, pathRouteLookup, test.body, token, true)

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
		})
	}
}

// TestRouteLookupWithoutCredentialsIsImplemented keeps lookup side-effect-free and non-stubbed.
func TestRouteLookupWithoutCredentialsIsImplemented(t *testing.T) {
	server, token := authenticatedServer(t, rest.Options{Version: testVersion})
	response := requestWithBearer(t, server, http.MethodPost, pathRouteLookup, `{"protocol":"imap","user_key":"user@example.org"}`, token, true)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
}

// TestServerRESTObservabilityUsesRouteTemplate verifies REST telemetry avoids raw paths.
func TestServerRESTObservabilityUsesRouteTemplate(t *testing.T) {
	recorder := &recordingRESTRecorder{}
	server, token := authenticatedServer(t, rest.Options{
		Version: testVersion,
		HandlerOptions: adapters.HandlerOptions{
			Observability: recorder,
		},
	})

	_ = requestWithBearer(t, server, http.MethodGet, pathSessionWithQuery, "", token, true)

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

// TestServerMetricsEndpointUsesGeneratedBoundary verifies /metrics returns Prometheus text.
func TestServerMetricsEndpointUsesGeneratedBoundary(t *testing.T) {
	cfg := testMetricsConfig()

	runtime, err := observability.NewRuntime(cfg, observability.WithLogWriter(io.Discard))
	if err != nil {
		t.Fatalf("NewRuntime returned error: %v", err)
	}

	server, token := authenticatedServer(t, rest.Options{
		Version: testVersion,
		HandlerOptions: adapters.HandlerOptions{
			Metrics:       runtime.MetricsProvider(),
			Observability: runtime.Recorder(),
		},
	})

	_ = requestWithBearer(t, server, http.MethodGet, pathVersion, "", token, true)
	response := requestWithBearer(t, server, http.MethodGet, pathMetrics, "", token, true)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}

	if contentType := response.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/plain") {
		t.Fatalf("content-type = %q, want text/plain", contentType)
	}

	body := response.Body.String()
	if !strings.Contains(body, restRequestsMetric) {
		t.Fatalf("metrics body missing REST request metric:\n%s", body)
	}

	if !strings.Contains(body, `route="/api/v1/version"`) {
		t.Fatalf("metrics body missing generated route label:\n%s", body)
	}
}

// TestServerProfileRoutesAreAbsentByDefault verifies disabled diagnostics behave like absent routes.
func TestServerProfileRoutesAreAbsentByDefault(t *testing.T) {
	server, token := authenticatedServer(t, rest.Options{Version: testVersion})

	for _, authorize := range []bool{false, true} {
		response := requestWithBearer(t, server, http.MethodGet, pathPProfGoroutine, "", token, authorize)
		if response.Code != http.StatusNotFound {
			t.Fatalf("authorized=%v status = %d, want 404", authorize, response.Code)
		}
	}
}

// TestServerProfileRoutesRequireControlAuth verifies enabled diagnostics reuse control auth.
func TestServerProfileRoutesRequireControlAuth(t *testing.T) {
	server, token := authenticatedServer(t, rest.Options{
		Version:  testVersion,
		Profiles: protectedProfileConfig(),
	})

	unauthenticated := request(t, server, http.MethodGet, pathPProfGoroutine, "")
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", unauthenticated.Code)
	}

	if strings.Contains(unauthenticated.Body.String(), "goroutine profile") {
		t.Fatalf("unauthenticated response exposed profile data: %s", unauthenticated.Body.String())
	}

	ordinary := requestWithBearer(t, server, http.MethodGet, pathPProfGoroutine, "", token, true)
	if ordinary.Code != http.StatusForbidden {
		t.Fatalf("ordinary status = %d, want 403", ordinary.Code)
	}

	if strings.Contains(ordinary.Body.String(), "goroutine profile") {
		t.Fatalf("ordinary auth response exposed profile data: %s", ordinary.Body.String())
	}
}

// TestServerProfileRoutesRequireProtectedAuthorization verifies protected OIDC scope gates pprof data.
func TestServerProfileRoutesRequireProtectedAuthorization(t *testing.T) {
	recorder := &recordingRESTRecorder{}
	server := rest.NewServer(rest.Options{
		Version:          testVersion,
		Control:          oidcControlConfig(),
		Profiles:         protectedProfileConfig(),
		OIDCIntrospector: &fakeOIDCIntrospector{result: oidcResult("operator-a", []string{"nauthilus-director.admin", "nauthilus-director.protected"})},
		HandlerOptions: adapters.HandlerOptions{
			Observability: recorder,
		},
	})

	response := requestWithBearer(t, server, http.MethodGet, pathPProfGoroutine, "", "protected-token", true)
	if response.Code != http.StatusOK {
		t.Fatalf("protected status = %d, want 200 body=%s", response.Code, response.Body.String())
	}

	if !strings.Contains(response.Body.String(), "goroutine") {
		t.Fatalf("profile response did not contain goroutine profile output")
	}

	event, ok := recorder.event(observability.EventDiagnosticProfileAccess)
	if !ok {
		t.Fatalf("profile audit event missing: %#v", recorder.events)
	}

	if event.LogFields["profile_route"] != "goroutine" {
		t.Fatalf("profile route = %q, want goroutine", event.LogFields["profile_route"])
	}

	if event.LogFields["actor_id"] != "operator-a" {
		t.Fatalf("actor_id = %q, want operator-a", event.LogFields["actor_id"])
	}

	if event.MetricLabels["route"] != "/debug/pprof/{profile}" {
		t.Fatalf("profile route label = %q, want template", event.MetricLabels["route"])
	}

	if _, ok := event.MetricLabels["actor_id"]; ok {
		t.Fatalf("profile metric labels leaked actor identity: %#v", event.MetricLabels)
	}

	if strings.Contains(strings.Join(mapValues(map[string]string(event.LogFields)), "\n"), "protected-token") {
		t.Fatalf("profile audit leaked bearer token: %#v", event.LogFields)
	}
}

// TestServerProfileSubroutesRequireExplicitEnablement verifies block, mutex and goroutine toggles are independent.
func TestServerProfileSubroutesRequireExplicitEnablement(t *testing.T) {
	profiles := config.DefaultConfig().Observability.Profiles
	profiles.PProf.Enabled = true

	server := rest.NewServer(rest.Options{
		Version:          testVersion,
		Control:          oidcControlConfig(),
		Profiles:         profiles,
		OIDCIntrospector: &fakeOIDCIntrospector{result: oidcResult("operator-a", []string{"nauthilus-director.admin", "nauthilus-director.protected"})},
	})

	for _, path := range []string{pathPProfGoroutine, pathPProfBlock, pathPProfMutex} {
		response := requestWithBearer(t, server, http.MethodGet, path, "", "protected-token", true)
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404", path, response.Code)
		}
	}

	index := requestWithBearer(t, server, http.MethodGet, pathPProfIndex, "", "protected-token", true)
	if index.Code != http.StatusOK {
		t.Fatalf("index status = %d, want 200", index.Code)
	}

	for _, disabled := range []string{"goroutine", "block", "mutex"} {
		if strings.Contains(index.Body.String(), "/debug/pprof/"+disabled) {
			t.Fatalf("index listed disabled %s profile:\n%s", disabled, index.Body.String())
		}
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

// requestWithBearer performs an optionally authenticated in-process HTTP request.
func requestWithBearer(
	t *testing.T,
	server http.Handler,
	method string,
	path string,
	body string,
	token string,
	authorize bool,
) *httptest.ResponseRecorder {
	t.Helper()

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}

	request := httptest.NewRequest(method, path, reader)
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}

	if authorize {
		request.Header.Set("Authorization", "Bearer "+token)
	}

	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)

	return response
}

// authenticatedServer returns a REST server configured with one static bearer token.
func authenticatedServer(t *testing.T, options rest.Options) (*rest.Server, string) {
	t.Helper()

	token := "test-control-token"

	tokenPath := filepath.Join(t.TempDir(), "control-token")
	if err := os.WriteFile(tokenPath, []byte(token+"\n"), 0o600); err != nil {
		t.Fatalf("write control token: %v", err)
	}

	control := config.DefaultConfig().Runtime.Servers.Control
	control.Auth.Bearer.Enabled = true
	control.Auth.Bearer.TokenFile = config.Secret(tokenPath)
	control.Auth.OIDC.Enabled = false
	control.Auth.OIDC.RequiredScopes = nil
	control.Auth.OIDC.ProtectedScopes = nil
	control.Auth.MTLS.Enabled = false
	options.Control = control

	return rest.NewServer(options), token
}

// oidcControlConfig returns control auth configured only for OIDC introspection.
func oidcControlConfig() config.ControlServerConfig {
	control := config.DefaultConfig().Runtime.Servers.Control
	control.Auth.Bearer.Enabled = false
	control.Auth.Bearer.TokenFile = config.Secret("")
	control.Auth.OIDC.Enabled = true
	control.Auth.OIDC.Authority = "default"
	control.Auth.OIDC.Validation = "nauthilus"
	control.Auth.OIDC.RequiredScopes = []string{"nauthilus-director.admin"}
	control.Auth.OIDC.ProtectedScopes = []string{"nauthilus-director.protected"}
	control.Auth.MTLS.Enabled = false

	return control
}

// mtlsControlConfig returns control auth configured only for verified client certificates.
func mtlsControlConfig() config.ControlServerConfig {
	control := config.DefaultConfig().Runtime.Servers.Control
	control.Auth.Bearer.Enabled = false
	control.Auth.Bearer.TokenFile = config.Secret("")
	control.Auth.OIDC.Enabled = false
	control.Auth.OIDC.RequiredScopes = nil
	control.Auth.OIDC.ProtectedScopes = nil
	control.Auth.MTLS.Enabled = true
	control.TLS.Enabled = true
	control.TLS.ClientCA = "test-ca.pem"

	return control
}

// oidcResult returns one active fake Nauthilus introspection result.
func oidcResult(subject string, scopes []string) nauthilus.OIDCIntrospectionResult {
	return nauthilus.OIDCIntrospectionResult{
		Active:  true,
		Subject: subject,
		Scopes:  scopes,
	}
}

// testMetricsConfig returns an enabled metrics config without remote tracing.
func testMetricsConfig() config.ObservabilityConfig {
	cfg := config.DefaultConfig().Observability
	cfg.Metrics.RuntimeMetrics = false
	cfg.Tracing.Enabled = false

	return cfg
}

// protectedProfileConfig enables pprof and the goroutine profile for protected-route tests.
func protectedProfileConfig() config.ProfilesConfig {
	profiles := config.DefaultConfig().Observability.Profiles
	profiles.PProf.Enabled = true
	profiles.Goroutine.Enabled = true

	return profiles
}

// recordingRESTRecorder stores REST observability events from the server middleware.
type recordingRESTRecorder struct {
	mu     sync.Mutex
	events []observability.Event
}

// fakeOIDCIntrospector returns one configured introspection result.
type fakeOIDCIntrospector struct {
	result nauthilus.OIDCIntrospectionResult
	err    error
}

// Introspect records the supplied token only through deterministic test behavior.
func (f *fakeOIDCIntrospector) Introspect(context.Context, string) (nauthilus.OIDCIntrospectionResult, error) {
	if f.err != nil {
		return nauthilus.OIDCIntrospectionResult{}, f.err
	}

	return f.result, nil
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

// mapValues returns map values for secret-leak assertions.
func mapValues(values map[string]string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}

	return out
}
