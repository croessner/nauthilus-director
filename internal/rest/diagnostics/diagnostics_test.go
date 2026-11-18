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

//nolint:goconst // Diagnostics fixtures repeat argument bodies and principals to show each refusal.
package diagnostics_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/croessner/nauthilus-director/internal/rest/diagnostics"
	"github.com/croessner/nauthilus-director/internal/rest/adapters"
	"github.com/croessner/nauthilus-director/internal/rest/generated"
	"github.com/croessner/nauthilus-director/internal/runtime"
)

// fullCredential holds every diagnostics scope.
var fullCredential = diagnostics.Credential{Method: diagnostics.CredentialOAuthUser, ClientID: "support-cli",
	Subject: "alice", Scopes: diagnostics.Scopes()}

// TestOperationsAreReadOnlyAndSchemaBacked pins that every tool names a GET operation of the
// control API, except the documented side-effect-free route lookup, and has an object schema.
func TestOperationsAreReadOnlyAndSchemaBacked(t *testing.T) {
	document, err := generated.GetSpec()
	if err != nil {
		t.Fatal(err)
	}

	methods := map[string]string{}

	for _, item := range document.Paths.Map() {
		for method, operation := range item.Operations() {
			methods[strings.ToLower(operation.OperationID)] = method
		}
	}

	seen := map[string]bool{}

	for _, operation := range diagnostics.Operations() {
		if seen[operation.Name] {
			t.Fatalf("duplicate operation %s", operation.Name)
		}

		seen[operation.Name] = true

		method := methods[strings.ToLower(operation.OperationID)]
		if method != http.MethodGet && (operation.Name != diagnostics.OperationRouteLookup || method != http.MethodPost) {
			t.Fatalf("%s maps to %s %s, want a read operation", operation.Name, method, operation.OperationID)
		}

		assertOperationContract(t, operation)
	}

	if _, ok := diagnostics.Lookup("delete_session"); ok {
		t.Fatal("mutations must never be operations")
	}
}

// assertOperationContract checks the description and the self-contained object schema of one operation.
func assertOperationContract(t *testing.T, operation diagnostics.Operation) {
	t.Helper()

	if len(operation.Scopes) == 0 || operation.Title == "" || !strings.Contains(operation.ModelDescription(), "untrusted data") {
		t.Fatalf("%s is incompletely described", operation.Name)
	}

	schema, err := operation.InputSchema()
	if err != nil {
		t.Fatalf("%s schema: %v", operation.Name, err)
	}

	var object map[string]any
	if err = json.Unmarshal(schema, &object); err != nil || object["type"] != "object" || object["additionalProperties"] != false {
		t.Fatalf("%s schema = %s", operation.Name, schema)
	}

	for _, marker := range []string{"$ref", "include_protected", `"x-`, "nullable"} {
		if strings.Contains(string(schema), marker) {
			t.Fatalf("%s schema is not self-contained JSON Schema: %s", operation.Name, schema)
		}
	}
}

// TestUserDataNeedsUserScope pins the scope classes: sessions, users and route lookups reveal
// user keys and need the user scope; topology needs the runtime scope.
func TestUserDataNeedsUserScope(t *testing.T) {
	for _, operation := range diagnostics.Operations() {
		want := diagnostics.ScopeRuntimeRead
		if strings.HasPrefix(operation.Name, "session") || strings.HasPrefix(operation.Name, "user") ||
			operation.Name == diagnostics.OperationRouteLookup {
			want = diagnostics.ScopeUsersRead
		}

		if !slices.Equal(operation.Scopes, []string{want}) {
			t.Fatalf("%s scopes = %v, want %s", operation.Name, operation.Scopes, want)
		}
	}
}

// TestCredentialIdentity pins that only user credentials with client and subject have an identity and scopes.
func TestCredentialIdentity(t *testing.T) {
	if fullCredential.Identity() != "support-cli#alice" || !fullCredential.HasScope(diagnostics.ScopeUsersRead) {
		t.Fatalf("identity = %q", fullCredential.Identity())
	}

	for name, credential := range map[string]diagnostics.Credential{
		"unknown method": {Method: "other", ClientID: "c", Subject: "s", Scopes: diagnostics.Scopes()},
		"no subject":     {Method: diagnostics.CredentialOAuthUser, ClientID: "c", Scopes: diagnostics.Scopes()},
		"no client":      {Method: diagnostics.CredentialOAuthUser, Subject: "s", Scopes: diagnostics.Scopes()},
	} {
		if credential.Verified() || credential.HasScope(diagnostics.ScopeRuntimeRead) {
			t.Fatalf("%s must not be verified", name)
		}
	}
}

// TestDecodeStrict pins the argument decoder: one object, no unknown or duplicate members, no trailing data.
func TestDecodeStrict(t *testing.T) {
	type target struct {
		Name string `json:"name"`
	}

	for raw, want := range map[string]bool{
		`{"name":"a"}`:          true,
		` {"name":"a"} `:        true,
		`{}`:                    true,
		`{"name":"a","x":1}`:    false,
		`{"name":"a","name":1}`: false,
		`{"name":"a"} {}`:       false,
		`["name"]`:              false,
		`null`:                  false,
		``:                      false,
	} {
		var decoded target
		if got := diagnostics.DecodeStrict([]byte(raw), &decoded); got != want {
			t.Fatalf("DecodeStrict(%q) = %v, want %v", raw, got, want)
		}
	}
}

// TestHasDuplicateNames pins duplicate detection at every depth.
func TestHasDuplicateNames(t *testing.T) {
	for raw, want := range map[string]bool{
		`{"a":1,"b":{"c":[{"d":1},{"d":2}]}}`: false,
		`{"a":1,"a":2}`:                       true,
		`{"a":{"b":1,"b":2}}`:                 true,
		`[{"x":1,"x":1}]`:                     true,
		`{"a":`:                               true,
		strings.Repeat("[", 80) + strings.Repeat("]", 80): true,
	} {
		if got := diagnostics.HasDuplicateNames([]byte(raw)); got != want {
			t.Fatalf("HasDuplicateNames(%.40q) = %v, want %v", raw, got, want)
		}
	}
}

// TestRouteLookupForbiddenKeys pins that credential and mailbox material is detected in keys only.
func TestRouteLookupForbiddenKeys(t *testing.T) {
	for raw, want := range map[string]bool{
		`{"protocol":"imap","user_key":"u"}`:                    false,
		`{"protocol":"imap","attributes":{"tenant":["token"]}}`: false,
		`{"protocol":"imap","attributes":{"Pass-Word":["x"]}}`:  true,
		`{"protocol":"imap","sasl_blob":"x"}`:                   true,
		`{"protocol":"imap","attributes":{"mailbox":["x"]}}`:    true,
		`{"nested":[{"bearerToken":1}]}`:                        true,
	} {
		if got := diagnostics.RouteLookupInputCarriesForbiddenKeys([]byte(raw)); got != want {
			t.Fatalf("RouteLookupInputCarriesForbiddenKeys(%s) = %v, want %v", raw, got, want)
		}
	}
}

// actorProbe records the actor the executor attached to the call context.
type actorProbe struct {
	diagnostics.ReadAPI

	actor runtime.Actor
}

// GetRuntimeSummary records the context actor and answers an empty summary.
func (p *actorProbe) GetRuntimeSummary(ctx context.Context, _ generated.GetRuntimeSummaryRequestObject) (generated.GetRuntimeSummaryResponseObject, error) {
	p.actor = runtime.ActorFromContext(ctx)

	return generated.GetRuntimeSummary200JSONResponse{}, nil
}

// TestExecuteAuthorizationAndArguments pins the executor refusals and the attached actor.
func TestExecuteAuthorizationAndArguments(t *testing.T) {
	probe := &actorProbe{ReadAPI: adapters.NewHandler(adapters.HandlerOptions{})}
	executor := diagnostics.NewExecutor(probe)
	summary, _ := diagnostics.Lookup(diagnostics.OperationRuntimeSummary)
	backend, _ := diagnostics.Lookup(diagnostics.OperationBackendDetail)
	route, _ := diagnostics.Lookup(diagnostics.OperationRouteLookup)
	runtimeOnly := fullCredential
	runtimeOnly.Scopes = []string{diagnostics.ScopeRuntimeRead}

	for name, tc := range map[string]struct {
		operation  diagnostics.Operation
		credential diagnostics.Credential
		raw        string
		status     int
		code       string
	}{
		"accepted":           {summary, runtimeOnly, `{}`, http.StatusOK, ""},
		"no scope":           {route, runtimeOnly, `{"protocol":"imap"}`, http.StatusForbidden, diagnostics.ProblemCodeForbidden},
		"unverified":         {summary, diagnostics.Credential{Scopes: diagnostics.Scopes()}, `{}`, http.StatusForbidden, diagnostics.ProblemCodeForbidden},
		"unknown member":     {summary, fullCredential, `{"x":1}`, http.StatusBadRequest, diagnostics.ProblemCodeBadRequest},
		"missing required":   {backend, fullCredential, `{}`, http.StatusBadRequest, diagnostics.ProblemCodeBadRequest},
		"wrong type":         {backend, fullCredential, `{"identifier":1}`, http.StatusBadRequest, diagnostics.ProblemCodeBadRequest},
		"credential input":   {route, fullCredential, `{"protocol":"imap","password":"x"}`, http.StatusBadRequest, diagnostics.ProblemCodeCredentialInput},
		"not an object":      {summary, fullCredential, `[]`, http.StatusBadRequest, diagnostics.ProblemCodeBadRequest},
		"handler error code": {backend, fullCredential, `{"identifier":"missing"}`, http.StatusNotFound, "not_found"},
	} {
		t.Run(name, func(t *testing.T) {
			response := executor.Execute(context.Background(), tc.operation, tc.credential, []byte(tc.raw))
			if response.Status != tc.status || response.Code != tc.code || !json.Valid(response.Body) {
				t.Fatalf("Execute = %d %q %s, want %d %q", response.Status, response.Code, response.Body, tc.status, tc.code)
			}
		})
	}

	if probe.actor.ID != "support-cli#alice" || probe.actor.AuthMethod != string(diagnostics.CredentialOAuthUser) || !probe.actor.Authenticated {
		t.Fatalf("actor = %+v", probe.actor)
	}
}

// TestRESTAndDiagnosticsAnswerTheSameBytes pins that a diagnostics call renders exactly the body
// and status the REST control API sends for the same request through the same handler.
func TestRESTAndDiagnosticsAnswerTheSameBytes(t *testing.T) {
	handler := adapters.NewHandler(adapters.HandlerOptions{Version: "parity"})
	rest := generated.Handler(generated.NewStrictHandler(handler, nil))
	executor := diagnostics.NewExecutor(handler)

	for _, tc := range []struct {
		operation string
		raw       string
		method    string
		path      string
		body      string
	}{
		{diagnostics.OperationBackendsList, `{}`, http.MethodGet, "/api/v1/backends", ""},
		{diagnostics.OperationBackendDetail, `{"identifier":"mailstore-a-imap"}`, http.MethodGet, "/api/v1/backends/mailstore-a-imap", ""},
		{diagnostics.OperationBackendDetail, `{"identifier":"missing"}`, http.MethodGet, "/api/v1/backends/missing", ""},
		{diagnostics.OperationConfigNonDefault, `{}`, http.MethodGet, "/api/v1/config/non-default?format=json", ""},
		{diagnostics.OperationSessionsList, `{"limit":5}`, http.MethodGet, "/api/v1/sessions?limit=5", ""},
		{diagnostics.OperationUserHold, `{"user_key":"u-1"}`, http.MethodGet, "/api/v1/users/u-1/hold", ""},
		{diagnostics.OperationRouteLookup, `{"protocol":"imap","user_key":"u-1"}`, http.MethodPost, "/api/v1/route/lookup",
			`{"protocol":"imap","user_key":"u-1"}`},
	} {
		t.Run(tc.operation+tc.raw, func(t *testing.T) {
			operation, ok := diagnostics.Lookup(tc.operation)
			if !ok {
				t.Fatalf("unknown operation %s", tc.operation)
			}

			request := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			request.Header.Set("Content-Type", "application/json")

			recorder := httptest.NewRecorder()
			rest.ServeHTTP(recorder, request)

			response := executor.Execute(context.Background(), operation, fullCredential, []byte(tc.raw))
			if response.Status != recorder.Code || !bytes.Equal(response.Body, bytes.TrimSpace(recorder.Body.Bytes())) {
				t.Fatalf("diagnostics %d %s\nREST %d %s", response.Status, response.Body, recorder.Code, recorder.Body.Bytes())
			}
		})
	}
}
