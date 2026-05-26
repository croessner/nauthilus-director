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

package adapters

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/croessner/nauthilus-director/internal/rest/generated"
	"github.com/croessner/nauthilus-director/internal/runtime"
)

const (
	testBackendIdentifier = "mailstore-a-imap"
	testConfigView        = configViewDefaults
	testHandlerVersion    = "test"
)

// TestLookupRouteUsesInjectedSideEffectFreeDomainService verifies route lookup is no longer a stub.
func TestLookupRouteUsesInjectedSideEffectFreeDomainService(t *testing.T) {
	lookup := &recordingRouteLookup{}
	handler := NewHandler(HandlerOptions{Version: testHandlerVersion, RouteLookup: lookup})

	body := generated.LookupRouteJSONRequestBody{
		Protocol: "imap",
		UserKey:  "alice-hash",
	}

	response, err := handler.LookupRoute(context.Background(), generated.LookupRouteRequestObject{Body: &body})
	if err != nil {
		t.Fatalf("LookupRoute returned error: %v", err)
	}

	if lookup.calls != 1 {
		t.Fatalf("route lookup calls = %d, want 1", lookup.calls)
	}

	if _, ok := response.(generated.LookupRoute200JSONResponse); !ok {
		t.Fatalf("LookupRoute response = %T, want 200 response", response)
	}
}

// TestMutatingHandlersRejectMissingReasons verifies generated DTOs are validated at the REST edge.
func TestMutatingHandlersRejectMissingReasons(t *testing.T) {
	handler := NewHandler(HandlerOptions{Version: testHandlerVersion})

	response, err := handler.ClearBackendRuntime(context.Background(), generated.ClearBackendRuntimeRequestObject{
		Identifier: testBackendIdentifier,
		Body:       &generated.RuntimeReasonRequest{},
	})
	if err != nil {
		t.Fatalf("ClearBackendRuntime returned error: %v", err)
	}

	problem, ok := response.(generated.ClearBackendRuntimedefaultJSONResponse)
	if !ok {
		t.Fatalf("ClearBackendRuntime response = %T, want default problem", response)
	}

	if problem.StatusCode != 400 {
		t.Fatalf("status = %d, want 400", problem.StatusCode)
	}
}

// TestDefaultConfigResponseIsRedacted verifies REST config output is redacted by default.
func TestDefaultConfigResponseIsRedacted(t *testing.T) {
	handler := NewHandler(HandlerOptions{Version: testHandlerVersion})

	response, err := handler.GetDefaultConfig(context.Background(), generated.GetDefaultConfigRequestObject{})
	if err != nil {
		t.Fatalf("GetDefaultConfig returned error: %v", err)
	}

	document, ok := response.(generated.GetDefaultConfig200JSONResponse)
	if !ok {
		t.Fatalf("GetDefaultConfig response = %T, want 200 config document", response)
	}

	if !document.Redacted {
		t.Fatal("GetDefaultConfig returned an unredacted document by default")
	}

	rendered := fmt.Sprintf("%#v", document.Data)
	if strings.Contains(rendered, "/etc/nauthilus-director/control-token") {
		t.Fatalf("default config response leaked protected token path: %s", rendered)
	}

	if !strings.Contains(rendered, "<redacted>") {
		t.Fatalf("default config response did not contain redaction marker: %s", rendered)
	}
}

// TestProtectedConfigRequiresAuthorizationAndAuditsWithoutValues verifies protected reads are explicit.
func TestProtectedConfigRequiresAuthorizationAndAuditsWithoutValues(t *testing.T) {
	audit := &recordingProtectedAudit{}
	handler := NewHandler(HandlerOptions{
		Version:              testHandlerVersion,
		ProtectedConfigAudit: audit,
	})

	includeProtected := generated.IncludeProtected(true)

	response, err := handler.GetDefaultConfig(context.Background(), generated.GetDefaultConfigRequestObject{
		Params: generated.GetDefaultConfigParams{IncludeProtected: &includeProtected},
	})
	if err != nil {
		t.Fatalf("GetDefaultConfig returned error: %v", err)
	}

	problem, ok := response.(generated.GetDefaultConfigdefaultJSONResponse)
	if !ok {
		t.Fatalf("GetDefaultConfig response = %T, want protected problem", response)
	}

	if problem.StatusCode != 403 {
		t.Fatalf("status = %d, want 403", problem.StatusCode)
	}

	if len(audit.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(audit.events))
	}

	if audit.events[0].View != testConfigView || audit.events[0].Authorized {
		t.Fatalf("audit event = %#v, want denied defaults event", audit.events[0])
	}
}

// TestRuntimeErrorsMapToStableStatuses checks the REST error classifier.
func TestRuntimeErrorsMapToStableStatuses(t *testing.T) {
	err := &runtime.Error{Kind: runtime.ErrorKindConflict, Operation: "test", Message: "state conflict"}
	if got := statusForError(err); got != 409 {
		t.Fatalf("statusForError = %d, want 409", got)
	}
}

// recordingRouteLookup captures route lookup calls without mutating state.
type recordingRouteLookup struct {
	calls int
}

// Lookup records a call and returns a deterministic route diagnostic.
func (r *recordingRouteLookup) Lookup(_ context.Context, request runtime.RouteLookupRequest) (runtime.RouteLookupResponse, error) {
	r.calls++

	if request.AccountKey == "" {
		return runtime.RouteLookupResponse{}, errors.New("account key missing")
	}

	return runtime.RouteLookupResponse{
		Routing: runtime.RouteLookupRoutingState{
			EffectiveShard: "default",
		},
		SelectedBackend: "mailstore-a-imap",
		ReasonClass:     "initial_placement",
	}, nil
}

// recordingProtectedAudit records protected config audit events.
type recordingProtectedAudit struct {
	events []ProtectedConfigAuditEvent
}

// AuditProtectedConfigRead stores only audit metadata.
func (r *recordingProtectedAudit) AuditProtectedConfigRead(_ context.Context, event ProtectedConfigAuditEvent) error {
	r.events = append(r.events, event)

	return nil
}
