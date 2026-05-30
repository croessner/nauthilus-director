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
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

const (
	pathContractHealthz            = "/healthz"
	pathContractReadyz             = "/readyz"
	pathContractVersion            = "/api/v1/version"
	pathContractBackendMaintenance = "/api/v1/backends/{identifier}/maintenance"
	pathContractListeners          = "/api/v1/listeners"
	pathContractListener           = "/api/v1/listeners/{name}"
	pathContractListenerDrain      = "/api/v1/listeners/{name}/runtime/drain"
	pathContractListenerResume     = "/api/v1/listeners/{name}/runtime/resume"
	pathContractSession            = "/api/v1/sessions/{session_id}"
	pathContractUserAffinity       = "/api/v1/users/{user_key}/affinity"
	pathContractUserBackendPin     = "/api/v1/users/{user_key}/backend-pin"
	queryContractCursor            = "cursor"
	queryContractLimit             = "limit"
)

// TestOpenAPIContractIncludesPlannedEndpointGroupSet checks the planned route inventory.
func TestOpenAPIContractIncludesPlannedEndpointGroupSet(t *testing.T) {
	contract := loadContract(t)
	planned := []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: pathContractHealthz},
		{method: http.MethodGet, path: pathContractReadyz},
		{method: http.MethodGet, path: pathContractVersion},
		{method: http.MethodGet, path: "/api/v1/config/effective"},
		{method: http.MethodGet, path: "/api/v1/config/defaults"},
		{method: http.MethodGet, path: "/api/v1/config/non-default"},
		{method: http.MethodPost, path: "/api/v1/reload"},
		{method: http.MethodGet, path: "/api/v1/runtime/summary"},
		{method: http.MethodGet, path: pathContractListeners},
		{method: http.MethodGet, path: pathContractListener},
		{method: http.MethodPost, path: pathContractListenerDrain},
		{method: http.MethodPost, path: pathContractListenerResume},
		{method: http.MethodGet, path: "/api/v1/backends"},
		{method: http.MethodGet, path: "/api/v1/backends/{identifier}"},
		{method: http.MethodPost, path: pathContractBackendMaintenance},
		{method: http.MethodDelete, path: pathContractBackendMaintenance},
		{method: http.MethodPost, path: "/api/v1/backends/{identifier}/runtime/in"},
		{method: http.MethodPost, path: "/api/v1/backends/{identifier}/runtime/out"},
		{method: http.MethodPost, path: "/api/v1/backends/{identifier}/runtime/drain"},
		{method: http.MethodDelete, path: "/api/v1/backends/{identifier}/runtime"},
		{method: http.MethodGet, path: "/api/v1/sessions"},
		{method: http.MethodGet, path: pathContractSession},
		{method: http.MethodDelete, path: pathContractSession},
		{method: http.MethodGet, path: "/api/v1/users"},
		{method: http.MethodGet, path: "/api/v1/users/{user_key}"},
		{method: http.MethodGet, path: "/api/v1/users/{user_key}/sessions"},
		{method: http.MethodGet, path: pathContractUserAffinity},
		{method: http.MethodPut, path: pathContractUserAffinity},
		{method: http.MethodDelete, path: pathContractUserAffinity},
		{method: http.MethodGet, path: pathContractUserBackendPin},
		{method: http.MethodPut, path: pathContractUserBackendPin},
		{method: http.MethodDelete, path: pathContractUserBackendPin},
		{method: http.MethodPost, path: "/api/v1/users/{user_key}/move"},
		{method: http.MethodPost, path: "/api/v1/users/{user_key}/kick"},
		{method: http.MethodPost, path: "/api/v1/route/lookup"},
		{method: http.MethodGet, path: "/metrics"},
	}

	for _, endpoint := range planned {
		if operation := contract.Paths.Find(endpoint.path).GetOperation(endpoint.method); operation == nil {
			t.Fatalf("OpenAPI contract missing %s %s", endpoint.method, endpoint.path)
		}
	}
}

// TestOpenAPIContractIncludesUserBackendPinOperations checks the backend-pin contract.
func TestOpenAPIContractIncludesUserBackendPinOperations(t *testing.T) {
	contract := loadContract(t)
	expectedOperations := []struct {
		method      string
		operationID string
	}{
		{method: http.MethodGet, operationID: "getUserBackendPin"},
		{method: http.MethodPut, operationID: "setUserBackendPin"},
		{method: http.MethodDelete, operationID: "clearUserBackendPin"},
	}

	for _, expected := range expectedOperations {
		operation := contract.Paths.Find(pathContractUserBackendPin).GetOperation(expected.method)
		if operation == nil {
			t.Fatalf("OpenAPI contract missing %s %s", expected.method, pathContractUserBackendPin)
		}

		if operation.OperationID != expected.operationID {
			t.Fatalf("%s %s operationId = %q, want %q", expected.method, pathContractUserBackendPin, operation.OperationID, expected.operationID)
		}
	}

	pinSchema := contract.Components.Schemas["UserBackendPin"].Value
	if !schemaRejectsAdditionalProperties(pinSchema) {
		t.Fatal("UserBackendPin must reject additional properties")
	}

	assertSchemaRequires(t, pinSchema, "present", "user_key")

	setSchema := contract.Components.Schemas["UserBackendPinRequest"].Value
	if !schemaRejectsAdditionalProperties(setSchema) {
		t.Fatal("UserBackendPinRequest must reject additional properties")
	}

	assertSchemaRequires(t, setSchema, "backend", "strategy", "reason")
	assertSchemaPropertyRef(t, setSchema, "strategy", "#/components/schemas/UserMoveRequestStrategy")

	clearSchema := contract.Components.Schemas["UserBackendPinClearRequest"].Value
	if !schemaRejectsAdditionalProperties(clearSchema) {
		t.Fatal("UserBackendPinClearRequest must reject additional properties")
	}

	assertSchemaRequires(t, clearSchema, "reason")
}

// TestOpenAPIContractIncludesRouteLookupBackendPin checks route diagnostics.
func TestOpenAPIContractIncludesRouteLookupBackendPin(t *testing.T) {
	contract := loadContract(t)
	responseSchema := contract.Components.Schemas["RouteLookupResponse"].Value
	assertSchemaRequires(t, responseSchema, "backend_pin")

	pinSchema := contract.Components.Schemas["RouteLookupBackendPin"].Value
	if !schemaRejectsAdditionalProperties(pinSchema) {
		t.Fatal("RouteLookupBackendPin must reject additional properties")
	}

	assertSchemaRequires(t, pinSchema, "present", "applied", "reason")
}

// TestDomainPackagesDoNotImportGeneratedDTOs keeps generated models at the REST boundary.
func TestDomainPackagesDoNotImportGeneratedDTOs(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate repository root")
	}

	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	forbiddenImports := map[string]struct{}{
		"github.com/croessner/nauthilus-director/internal/client/generated": {},
		"github.com/croessner/nauthilus-director/internal/rest/generated":   {},
	}

	for _, directory := range []string{"internal/backend", "internal/runtime", "internal/state"} {
		root := filepath.Join(repositoryRoot, directory)

		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}

			if entry.IsDir() || filepath.Ext(path) != ".go" {
				return nil
			}

			file, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if parseErr != nil {
				return parseErr
			}

			for _, importSpec := range file.Imports {
				importPath, unquoteErr := strconv.Unquote(importSpec.Path.Value)
				if unquoteErr != nil {
					return unquoteErr
				}

				if _, forbidden := forbiddenImports[importPath]; forbidden {
					t.Fatalf("%s imports generated DTO package %s", path, importPath)
				}
			}

			return nil
		})
		if err != nil {
			t.Fatalf("scan %s: %v", directory, err)
		}
	}
}

// TestOpenAPIContractKeepsUserMoveShardScoped checks the move request boundary.
func TestOpenAPIContractKeepsUserMoveShardScoped(t *testing.T) {
	contract := loadContract(t)
	schema := contract.Components.Schemas["UserMoveRequest"].Value

	if _, ok := schema.Properties["to_backend"]; ok {
		t.Fatal("UserMoveRequest must not expose to_backend")
	}

	assertSchemaRequires(t, schema, "to_shard", "strategy", "reason")
	assertSchemaPropertyRef(t, schema, "strategy", "#/components/schemas/UserMoveRequestStrategy")
}

// TestOpenAPIContractIncludesRuntimeSummary checks aggregate summary semantics.
func TestOpenAPIContractIncludesRuntimeSummary(t *testing.T) {
	contract := loadContract(t)

	operation := contract.Paths.Find("/api/v1/runtime/summary").GetOperation(http.MethodGet)
	if operation == nil {
		t.Fatal("OpenAPI contract missing runtime summary")
	}

	if operation.OperationID != "getRuntimeSummary" {
		t.Fatalf("runtime summary operationId = %q, want getRuntimeSummary", operation.OperationID)
	}

	schema := contract.Components.Schemas["RuntimeSummaryResponse"].Value
	for _, field := range []string{"active_sessions", "idle_affinities", "backend_capacity", "repairs", "routing_authority"} {
		if _, ok := schema.Properties[field]; !ok {
			t.Fatalf("RuntimeSummaryResponse missing %q", field)
		}
	}
}

// TestOpenAPIContractIncludesListenerOperations checks the listener v1 REST contract.
func TestOpenAPIContractIncludesListenerOperations(t *testing.T) {
	contract := loadContract(t)
	expectedOperations := []struct {
		method      string
		path        string
		operationID string
	}{
		{method: http.MethodGet, path: pathContractListeners, operationID: "listListeners"},
		{method: http.MethodGet, path: pathContractListener, operationID: "getListener"},
		{method: http.MethodPost, path: pathContractListenerDrain, operationID: "drainListener"},
		{method: http.MethodPost, path: pathContractListenerResume, operationID: "resumeListener"},
	}

	for _, expected := range expectedOperations {
		operation := contract.Paths.Find(expected.path).GetOperation(expected.method)
		if operation == nil {
			t.Fatalf("OpenAPI contract missing %s %s", expected.method, expected.path)
		}

		if operation.OperationID != expected.operationID {
			t.Fatalf("%s %s operationId = %q, want %q", expected.method, expected.path, operation.OperationID, expected.operationID)
		}
	}

	enumValues := contract.Components.Schemas["ListenerState"].Value.Enum
	if len(enumValues) != 4 {
		t.Fatalf("ListenerState enum length = %d, want 4", len(enumValues))
	}

	for _, expected := range []string{"accepting", "draining", "drained", "stopped"} {
		if !schemaEnumContains(enumValues, expected) {
			t.Fatalf("ListenerState enum missing %q: %#v", expected, enumValues)
		}
	}
}

// TestOpenAPIContractIncludesRuntimeReadPagination checks bounded list contracts.
func TestOpenAPIContractIncludesRuntimeReadPagination(t *testing.T) {
	contract := loadContract(t)

	sessionOperation := contract.Paths.Find("/api/v1/sessions").GetOperation(http.MethodGet)
	for _, parameter := range []string{"protocol", "backend", queryContractCursor, queryContractLimit} {
		if !operationHasParameter(sessionOperation, parameter) {
			t.Fatalf("GET /api/v1/sessions missing %q parameter", parameter)
		}
	}

	userOperation := contract.Paths.Find("/api/v1/users").GetOperation(http.MethodGet)
	for _, parameter := range []string{queryContractCursor, queryContractLimit} {
		if !operationHasParameter(userOperation, parameter) {
			t.Fatalf("GET /api/v1/users missing %q parameter", parameter)
		}
	}

	for _, schemaName := range []string{"SessionListResponse", "UserListResponse"} {
		schema := contract.Components.Schemas[schemaName].Value
		if _, ok := schema.Properties["next_cursor"]; !ok {
			t.Fatalf("%s missing next_cursor", schemaName)
		}
	}
}

// TestRouteLookupContractExcludesCredentials keeps credential-bearing fields out of the DTO.
func TestRouteLookupContractExcludesCredentials(t *testing.T) {
	contract := loadContract(t)
	schema := contract.Components.Schemas["RouteLookupRequest"].Value

	for _, field := range []string{"password", "credential", "token", "secret", "bearer"} {
		if _, ok := schema.Properties[field]; ok {
			t.Fatalf("RouteLookupRequest exposes credential field %q", field)
		}
	}
}

// assertSchemaRequires fails when a schema does not require all expected fields.
func assertSchemaRequires(t *testing.T, schema *openapi3.Schema, fields ...string) {
	t.Helper()

	for _, field := range fields {
		found := slices.Contains(schema.Required, field)
		if !found {
			t.Fatalf("schema missing required field %q", field)
		}
	}
}

// assertSchemaPropertyRef fails when a schema property does not reference the expected schema.
func assertSchemaPropertyRef(t *testing.T, schema *openapi3.Schema, property string, ref string) {
	t.Helper()

	propertySchema, ok := schema.Properties[property]
	if !ok {
		t.Fatalf("schema missing property %q", property)
	}

	if propertySchema.Ref != ref {
		t.Fatalf("schema property %q ref = %q, want %q", property, propertySchema.Ref, ref)
	}
}

// operationHasParameter reports whether an operation declares one query parameter.
func operationHasParameter(operation *openapi3.Operation, name string) bool {
	if operation == nil {
		return false
	}

	for _, parameter := range operation.Parameters {
		if parameter.Value != nil && parameter.Value.Name == name {
			return true
		}
	}

	return false
}

// loadContract parses and validates the source OpenAPI document.
func loadContract(t *testing.T) *openapi3.T {
	t.Helper()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test file")
	}

	specPath := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", "..", "docs", "specs", "openapi", "nauthilus-director.yaml"))
	loader := openapi3.NewLoader()

	contract, err := loader.LoadFromFile(specPath)
	if err != nil {
		t.Fatalf("load OpenAPI contract: %v", err)
	}

	if err := contract.Validate(context.Background()); err != nil {
		t.Fatalf("validate OpenAPI contract: %v", err)
	}

	return contract
}

// schemaRejectsAdditionalProperties reports whether a schema explicitly forbids extra fields.
func schemaRejectsAdditionalProperties(schema *openapi3.Schema) bool {
	return schema != nil && schema.AdditionalProperties.Has != nil && !*schema.AdditionalProperties.Has
}

// schemaEnumContains reports whether an OpenAPI enum contains a string value.
func schemaEnumContains(values []any, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}

	return false
}
