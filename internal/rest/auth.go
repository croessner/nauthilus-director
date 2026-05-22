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

package rest

import (
	"bytes"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/croessner/nauthilus-director/internal/rest/generated"
)

const maxRouteLookupInspectionBytes = 1 << 20

// ControlAuthenticator is the M0 control-plane guard around generated routes.
type ControlAuthenticator struct{}

// NewControlAuthenticator creates the initial control API guard.
func NewControlAuthenticator() ControlAuthenticator {
	return ControlAuthenticator{}
}

// Wrap applies M0 request guards before generated request decoding.
func (a ControlAuthenticator) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.shouldInspectRouteLookup(r) {
			if ok := a.inspectRouteLookupBody(w, r); !ok {
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// shouldInspectRouteLookup reports whether the request targets route lookup.
func (a ControlAuthenticator) shouldInspectRouteLookup(r *http.Request) bool {
	return r.Method == http.MethodPost && r.URL.Path == "/api/v1/route/lookup"
}

// inspectRouteLookupBody rejects credential-bearing route diagnostics early.
func (a ControlAuthenticator) inspectRouteLookupBody(w http.ResponseWriter, r *http.Request) bool {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRouteLookupInspectionBytes+1))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "bad_request", "route lookup request body could not be read", "LookupRoute")
		return false
	}

	_ = r.Body.Close()

	if len(body) > maxRouteLookupInspectionBytes {
		writeProblem(w, http.StatusBadRequest, "bad_request", "route lookup request body is too large", "LookupRoute")
		return false
	}

	if containsCredentialKey(body) {
		writeProblem(w, http.StatusBadRequest, "credential_input_rejected", "route lookup does not accept authentication material", "LookupRoute")
		return false
	}

	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))

	return true
}

// containsCredentialKey detects secret-like JSON object keys without reading values.
func containsCredentialKey(body []byte) bool {
	var value any
	if err := JSON.Unmarshal(body, &value); err != nil {
		return false
	}

	return containsCredentialKeyValue(value)
}

// containsCredentialKeyValue walks decoded JSON looking only at object keys.
func containsCredentialKeyValue(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			if isCredentialKey(key) || containsCredentialKeyValue(nested) {
				return true
			}
		}
	case []any:
		if slices.ContainsFunc(typed, containsCredentialKeyValue) {
			return true
		}
	}

	return false
}

// isCredentialKey reports whether a JSON key appears to carry credentials.
func isCredentialKey(key string) bool {
	fragments := [...]string{
		"auth",
		"bearer",
		"credential",
		"password",
		"passwd",
		"sasl",
		"secret",
		"token",
	}

	normalized := strings.ToLower(strings.TrimSpace(key))
	for _, fragment := range fragments {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}

	return false
}

// writeProblem writes structured error JSON without echoing request values.
func writeProblem(w http.ResponseWriter, status int, code string, message string, operation string) {
	var operationPtr *string
	if operation != "" {
		operationPtr = &operation
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = JSON.NewEncoder(w).Encode(generated.ErrorResponse{
		Code:      code,
		Message:   message,
		Operation: operationPtr,
		Status:    status,
	})
}
