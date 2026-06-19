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

//nolint:dupl,goconst,wsl_v5 // OpenAPI contract tests repeat schema sentinel strings intentionally.
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
	pathContractUserHold           = "/api/v1/users/{user_key}/hold"
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
		{method: http.MethodGet, path: pathContractUserHold},
		{method: http.MethodPut, path: pathContractUserHold},
		{method: http.MethodDelete, path: pathContractUserHold},
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

// TestOpenAPIContractIncludesSessionKillOutcomes checks deterministic kill responses.
//
//nolint:gocyclo // The test keeps related status, schema and enum assertions together.
func TestOpenAPIContractIncludesSessionKillOutcomes(t *testing.T) {
	contract := loadContract(t)
	operation := contract.Paths.Find(pathContractSession).GetOperation(http.MethodDelete)
	if operation == nil {
		t.Fatalf("OpenAPI contract missing DELETE %s", pathContractSession)
	}

	if operation.OperationID != "deleteSession" {
		t.Fatalf("DELETE %s operationId = %q, want deleteSession", pathContractSession, operation.OperationID)
	}

	if got := operationResponseSchemaRef(t, operation, http.StatusAccepted); got != "#/components/schemas/SessionKillResponse" {
		t.Fatalf("202 response schema = %q, want SessionKillResponse", got)
	}
	if got := operationResponseSchemaRef(t, operation, http.StatusNotFound); got != "#/components/schemas/SessionKillResponse" {
		t.Fatalf("404 response schema = %q, want SessionKillResponse", got)
	}

	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusServiceUnavailable} {
		if operation.Responses.Status(status) == nil {
			t.Fatalf("DELETE %s missing %d response", pathContractSession, status)
		}
	}

	responseSchema := contract.Components.Schemas["SessionKillResponse"].Value
	if !schemaRejectsAdditionalProperties(responseSchema) {
		t.Fatal("SessionKillResponse must reject additional properties")
	}

	assertSchemaRequires(t, responseSchema, "outcome", "session_id", "lifecycle", "stale_index_repaired")
	assertSchemaPropertiesExactly(t, responseSchema, "control_action", "control_generation", "lifecycle", "outcome", "session_id", "stale_index_repaired")
	assertSchemaPropertyRef(t, responseSchema, "outcome", "#/components/schemas/SessionKillOutcome")
	assertSchemaPropertyRef(t, responseSchema, "control_action", "#/components/schemas/SessionKillControlAction")
	assertSchemaPropertyRef(t, responseSchema, "lifecycle", "#/components/schemas/SessionKillLifecycle")
	assertStringPropertyMinLength(t, responseSchema, "session_id", 1)

	for _, forbidden := range []string{"reason", "operator_reason", "reason_text", "user_key", "recipient", "client_ip", "backend", "backend_identifier", "raw_error"} {
		if _, ok := responseSchema.Properties[forbidden]; ok {
			t.Fatalf("SessionKillResponse exposes forbidden field %q", forbidden)
		}
	}

	outcomeSchema := contract.Components.Schemas["SessionKillOutcome"].Value
	for _, outcome := range []string{"marked", "missing", "stale_index_repaired", "ambiguous_state"} {
		if !schemaEnumContains(outcomeSchema.Enum, outcome) {
			t.Fatalf("SessionKillOutcome enum missing %q: %#v", outcome, outcomeSchema.Enum)
		}
	}

	lifecycleSchema := contract.Components.Schemas["SessionKillLifecycle"].Value
	for _, lifecycle := range []string{"local_close_or_remote_heartbeat", "already_absent", "stale_locator_repaired", "fail_closed_ambiguous"} {
		if !schemaEnumContains(lifecycleSchema.Enum, lifecycle) {
			t.Fatalf("SessionKillLifecycle enum missing %q: %#v", lifecycle, lifecycleSchema.Enum)
		}
	}
}

// TestOpenAPIContractIncludesVisibleSessionHolderKind checks session holder diagnostics.
func TestOpenAPIContractIncludesVisibleSessionHolderKind(t *testing.T) {
	contract := loadContract(t)
	schema := contract.Components.Schemas["SessionDetail"].Value
	if !schemaRejectsAdditionalProperties(schema) {
		t.Fatal("SessionDetail must reject additional properties")
	}

	assertSchemaRequires(t, schema, "session_id", "user_key", "protocol", "holder_kind", "backend", "backend_node", "shard_tag", "expires_at")
	assertSchemaPropertiesExactly(t, schema, "backend", "backend_node", "expires_at", "holder_kind", "protocol", "session_id", "shard_tag", "user_key")

	holderKind := schema.Properties["holder_kind"].Value
	if holderKind == nil || !schemaEnumContains(holderKind.Enum, "session") {
		t.Fatalf("SessionDetail holder_kind enum = %#v, want session", holderKind)
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
	assertBackendPinAggregateSchema(t, "UserBackendPin", pinSchema)

	pinsSchema := contract.Components.Schemas["UserBackendPins"].Value
	assertBackendPinAggregateSchema(t, "UserBackendPins", pinsSchema)

	entrySchema := contract.Components.Schemas["UserBackendPinEntry"].Value
	if !schemaRejectsAdditionalProperties(entrySchema) {
		t.Fatal("UserBackendPinEntry must reject additional properties")
	}

	assertSchemaRequires(t, entrySchema, "backend", "protocol", "backend_pool", "shard_tag", "backend_node", "strategy")
	assertSchemaPropertiesExactly(t, entrySchema, "active_session_count", "backend", "backend_node", "backend_pool", "generation", "protocol", "shard_tag", "strategy")
	assertSchemaPropertyRef(t, entrySchema, "strategy", "#/components/schemas/UserMoveRequestStrategy")
	for _, field := range []string{"backend", "protocol", "backend_pool", "shard_tag", "backend_node"} {
		assertStringPropertyMinLength(t, entrySchema, field, 1)
	}

	setSchema := contract.Components.Schemas["UserBackendPinRequest"].Value
	if !schemaRejectsAdditionalProperties(setSchema) {
		t.Fatal("UserBackendPinRequest must reject additional properties")
	}

	assertSchemaRequires(t, setSchema, "strategy", "reason")
	assertSchemaPropertiesExactly(t, setSchema, "backend", "backend_node", "backend_pool", "protocol", "reason", "strategy")
	assertSchemaRejectsBothAndNeitherTargets(t, setSchema)
	assertSchemaPropertyRef(t, setSchema, "strategy", "#/components/schemas/UserMoveRequestStrategy")
	for _, field := range []string{"backend", "backend_node", "protocol", "backend_pool", "reason"} {
		assertStringPropertyMinLength(t, setSchema, field, 1)
	}

	clearSchema := contract.Components.Schemas["UserBackendPinClearRequest"].Value
	if !schemaRejectsAdditionalProperties(clearSchema) {
		t.Fatal("UserBackendPinClearRequest must reject additional properties")
	}

	assertSchemaRequires(t, clearSchema, "reason")
	assertSchemaPropertiesExactly(t, clearSchema, "backend_pool", "protocol", "reason")
	assertSchemaRejectsPartialScope(t, clearSchema)
	for _, field := range []string{"protocol", "backend_pool", "reason"} {
		assertStringPropertyMinLength(t, clearSchema, field, 1)
	}
}

// TestOpenAPIContractIncludesUserHoldOperations checks the user-hold contract.
func TestOpenAPIContractIncludesUserHoldOperations(t *testing.T) {
	contract := loadContract(t)
	expectedOperations := []struct {
		method      string
		operationID string
	}{
		{method: http.MethodGet, operationID: "getUserHold"},
		{method: http.MethodPut, operationID: "setUserHold"},
		{method: http.MethodDelete, operationID: "clearUserHold"},
	}

	for _, expected := range expectedOperations {
		operation := contract.Paths.Find(pathContractUserHold).GetOperation(expected.method)
		if operation == nil {
			t.Fatalf("OpenAPI contract missing %s %s", expected.method, pathContractUserHold)
		}

		if operation.OperationID != expected.operationID {
			t.Fatalf("%s %s operationId = %q, want %q", expected.method, pathContractUserHold, operation.OperationID, expected.operationID)
		}
	}

	holdSchema := contract.Components.Schemas["UserHold"].Value
	if !schemaRejectsAdditionalProperties(holdSchema) {
		t.Fatal("UserHold must reject additional properties")
	}

	assertSchemaRequires(t, holdSchema, "present", "user_key")

	if _, ok := holdSchema.Properties["reason"]; ok {
		t.Fatal("UserHold must not expose operator reason text")
	}

	setSchema := contract.Components.Schemas["UserHoldRequest"].Value
	if !schemaRejectsAdditionalProperties(setSchema) {
		t.Fatal("UserHoldRequest must reject additional properties")
	}

	assertSchemaRequires(t, setSchema, "duration_seconds", "reason")

	if _, ok := setSchema.Properties["expires_at"]; ok {
		t.Fatal("UserHoldRequest must not accept operator-supplied expires_at")
	}

	clearSchema := contract.Components.Schemas["UserHoldClearRequest"].Value
	if !schemaRejectsAdditionalProperties(clearSchema) {
		t.Fatal("UserHoldClearRequest must reject additional properties")
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

	for _, field := range []string{"operator_reason", "reason_text", "user_key", "recipient"} {
		if _, ok := pinSchema.Properties[field]; ok {
			t.Fatalf("RouteLookupBackendPin must not expose %q", field)
		}
	}

	if _, ok := pinSchema.Properties["backend_node"]; !ok {
		t.Fatal("RouteLookupBackendPin must expose backend_node for aggregate diagnostics")
	}

	if _, ok := pinSchema.Properties["scope_count"]; !ok {
		t.Fatal("RouteLookupBackendPin must expose bounded scope_count")
	}

	if _, ok := pinSchema.Properties["current_scope_unpinned"]; !ok {
		t.Fatal("RouteLookupBackendPin must expose current_scope_unpinned")
	}

	assertSchemaArrayItemsRef(t, pinSchema, "other_scopes", "#/components/schemas/RouteLookupBackendPinScope")

	scopeSchema := contract.Components.Schemas["RouteLookupBackendPinScope"].Value
	if !schemaRejectsAdditionalProperties(scopeSchema) {
		t.Fatal("RouteLookupBackendPinScope must reject additional properties")
	}

	assertSchemaRequires(t, scopeSchema, "protocol", "backend_pool")
	assertSchemaPropertiesExactly(t, scopeSchema, "backend_pool", "protocol")
	assertStringPropertyMinLength(t, scopeSchema, "protocol", 1)
	assertStringPropertyMinLength(t, scopeSchema, "backend_pool", 1)
}

// TestOpenAPIContractIncludesRouteLookupUserHold checks hold diagnostics.
func TestOpenAPIContractIncludesRouteLookupUserHold(t *testing.T) {
	contract := loadContract(t)
	responseSchema := contract.Components.Schemas["RouteLookupResponse"].Value
	assertSchemaRequires(t, responseSchema, "user_hold")

	holdSchema := contract.Components.Schemas["RouteLookupUserHold"].Value
	if !schemaRejectsAdditionalProperties(holdSchema) {
		t.Fatal("RouteLookupUserHold must reject additional properties")
	}

	assertSchemaRequires(t, holdSchema, "present", "placement_deferred", "reason")

	if _, ok := holdSchema.Properties["operator_reason"]; ok {
		t.Fatal("RouteLookupUserHold must not expose operator reason text")
	}

	effectsSchema := contract.Components.Schemas["RouteLookupEffects"].Value
	assertSchemaRequires(t, effectsSchema, "user_hold")

	if _, ok := effectsSchema.Properties["user_hold"]; !ok {
		t.Fatal("RouteLookupEffects must expose user_hold context")
	}
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

// TestRouteLookupContractExcludesForbiddenFields keeps credential and script fields out of the DTO.
func TestRouteLookupContractExcludesForbiddenFields(t *testing.T) {
	contract := loadContract(t)
	schema := contract.Components.Schemas["RouteLookupRequest"].Value

	for _, field := range []string{"password", "credential", "token", "secret", "bearer", "script_name", "script_content"} {
		if _, ok := schema.Properties[field]; ok {
			t.Fatalf("RouteLookupRequest exposes credential field %q", field)
		}
	}
}

// assertBackendPinAggregateSchema checks the aggregate backend-pin read shape.
func assertBackendPinAggregateSchema(t *testing.T, name string, schema *openapi3.Schema) {
	t.Helper()

	if !schemaRejectsAdditionalProperties(schema) {
		t.Fatalf("%s must reject additional properties", name)
	}

	assertSchemaRequires(t, schema, "present", "user_key", "pins")
	assertSchemaPropertiesExactly(
		t,
		schema,
		"active_session_count",
		"backend",
		"backend_node",
		"backend_pool",
		"generation",
		"pins",
		"present",
		"protocol",
		"shard_tag",
		"strategy",
		"user_key",
	)
	assertSchemaArrayItemsRef(t, schema, "pins", "#/components/schemas/UserBackendPinEntry")
	assertSchemaPropertyRef(t, schema, "strategy", "#/components/schemas/UserMoveRequestStrategy")
	assertStringPropertyMinLength(t, schema, "user_key", 1)
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

// assertSchemaPropertiesExactly fails when a schema exposes a different field set.
func assertSchemaPropertiesExactly(t *testing.T, schema *openapi3.Schema, fields ...string) {
	t.Helper()

	got := make([]string, 0, len(schema.Properties))
	for field := range schema.Properties {
		got = append(got, field)
	}

	want := slices.Clone(fields)
	slices.Sort(got)
	slices.Sort(want)

	if !slices.Equal(got, want) {
		t.Fatalf("schema properties = %#v, want %#v", got, want)
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

// assertSchemaArrayItemsRef fails when an array property does not reference the expected item schema.
func assertSchemaArrayItemsRef(t *testing.T, schema *openapi3.Schema, property string, ref string) {
	t.Helper()

	propertySchema, ok := schema.Properties[property]
	if !ok || propertySchema.Value == nil {
		t.Fatalf("schema missing array property %q", property)
	}

	if propertySchema.Value.Items == nil || propertySchema.Value.Items.Ref != ref {
		t.Fatalf("schema property %q item ref = %#v, want %q", property, propertySchema.Value.Items, ref)
	}
}

// assertStringPropertyMinLength fails when a string property omits the expected minimum length.
func assertStringPropertyMinLength(t *testing.T, schema *openapi3.Schema, property string, minimum uint64) {
	t.Helper()

	propertySchema, ok := schema.Properties[property]
	if !ok || propertySchema.Value == nil {
		t.Fatalf("schema missing string property %q", property)
	}

	if propertySchema.Value.MinLength != minimum {
		t.Fatalf("schema property %q minLength = %d, want %d", property, propertySchema.Value.MinLength, minimum)
	}
}

// assertSchemaRejectsBothAndNeitherTargets checks backend/backend_node exclusivity.
func assertSchemaRejectsBothAndNeitherTargets(t *testing.T, schema *openapi3.Schema) {
	t.Helper()

	if schema.Not == nil || schema.Not.Value == nil || len(schema.Not.Value.AnyOf) != 2 {
		t.Fatal("set schema must declare two rejected target combinations")
	}

	if !schemaBranchRequiresPair(schema.Not.Value.AnyOf[0], "backend", "backend_node") {
		t.Fatal("set schema must reject backend and backend_node together")
	}

	if !schemaBranchMatchesMissingBoth(schema.Not.Value.AnyOf[1], "backend", "backend_node") {
		t.Fatal("set schema must reject missing backend and backend_node")
	}
}

// assertSchemaRejectsPartialScope checks clear request scope pairing.
func assertSchemaRejectsPartialScope(t *testing.T, schema *openapi3.Schema) {
	t.Helper()

	if schema.Not == nil || schema.Not.Value == nil || len(schema.Not.Value.AnyOf) != 2 {
		t.Fatal("clear schema must declare two rejected partial-scope combinations")
	}

	if !schemaBranchMatchesRequiredWithoutPair(schema.Not.Value.AnyOf[0], "protocol", "backend_pool") {
		t.Fatal("clear schema must reject protocol without backend_pool")
	}
	if !schemaBranchMatchesRequiredWithoutPair(schema.Not.Value.AnyOf[1], "backend_pool", "protocol") {
		t.Fatal("clear schema must reject backend_pool without protocol")
	}
}

// schemaBranchRequiresPair reports whether a branch requires two fields together.
func schemaBranchRequiresPair(branch *openapi3.SchemaRef, first string, second string) bool {
	if branch == nil || branch.Value == nil {
		return false
	}

	required := branch.Value.Required
	return len(required) == 2 && slices.Contains(required, first) && slices.Contains(required, second)
}

// schemaBranchMatchesMissingBoth reports whether a branch matches both fields being absent.
func schemaBranchMatchesMissingBoth(branch *openapi3.SchemaRef, first string, second string) bool {
	if branch == nil || branch.Value == nil {
		return false
	}

	nested := branch.Value.AllOf
	if len(nested) != 2 {
		return false
	}

	return schemaBranchMatchesMissingOne(nested[0], first) && schemaBranchMatchesMissingOne(nested[1], second)
}

// schemaBranchMatchesMissingOne reports whether a nested not branch matches one absent field.
func schemaBranchMatchesMissingOne(branch *openapi3.SchemaRef, field string) bool {
	if branch == nil || branch.Value == nil || branch.Value.Not == nil || branch.Value.Not.Value == nil {
		return false
	}

	required := branch.Value.Not.Value.Required
	return len(required) == 1 && required[0] == field
}

// schemaBranchMatchesRequiredWithoutPair reports whether one half-scoped payload is matched.
func schemaBranchMatchesRequiredWithoutPair(branch *openapi3.SchemaRef, present string, missing string) bool {
	if branch == nil || branch.Value == nil {
		return false
	}

	nested := branch.Value.AllOf
	if len(nested) != 2 {
		return false
	}

	if nested[0].Value == nil {
		return false
	}

	return len(nested[0].Value.Required) == 1 &&
		nested[0].Value.Required[0] == present &&
		schemaBranchMatchesMissingOne(nested[1], missing)
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

// operationResponseSchemaRef returns the JSON response schema reference for one status.
func operationResponseSchemaRef(t *testing.T, operation *openapi3.Operation, status int) string {
	t.Helper()

	if operation == nil || operation.Responses == nil {
		t.Fatal("operation has no responses")
	}

	response := operation.Responses.Status(status)
	if response == nil || response.Value == nil {
		t.Fatalf("operation missing %d response", status)
	}

	media := response.Value.Content.Get("application/json")
	if media == nil || media.Schema == nil {
		t.Fatalf("%d response missing application/json schema", status)
	}

	return media.Schema.Ref
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
