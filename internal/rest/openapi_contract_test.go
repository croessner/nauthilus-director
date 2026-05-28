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
	"net/http"
	"path/filepath"
	"runtime"
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

// schemaEnumContains reports whether an OpenAPI enum contains a string value.
func schemaEnumContains(values []any, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}

	return false
}
