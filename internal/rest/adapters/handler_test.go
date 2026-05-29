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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/rest/generated"
	"github.com/croessner/nauthilus-director/internal/routing"
	"github.com/croessner/nauthilus-director/internal/runtime"
)

const (
	testBackendIdentifier = "mailstore-a-imap"
	testConfigView        = configViewDefaults
	testHandlerVersion    = "test"
	testListenerBound     = "127.0.0.1:2143"
	testListenerName      = "imap"
	testListenerReason    = "node maintenance"
)

// TestLookupRouteUsesInjectedSideEffectFreeDomainService verifies route lookup is no longer a stub.
func TestLookupRouteUsesInjectedSideEffectFreeDomainService(t *testing.T) {
	lookup := &recordingRouteLookup{}
	handler := NewHandler(HandlerOptions{Version: testHandlerVersion, RouteLookup: lookup})

	userKey := "alice-hash"
	body := generated.LookupRouteJSONRequestBody{
		Protocol: "imap",
		UserKey:  &userKey,
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

// TestRouteLookupResolverUsesConfiguredAuthAttributeNames verifies diagnostic routing uses config too.
func TestRouteLookupResolverUsesConfiguredAuthAttributeNames(t *testing.T) {
	const (
		configuredTenantAttribute = "organization"
		configuredShardAttribute  = "mailboxShard"
		expectedTenant            = "blue"
		expectedShardTag          = "mailstore-a"
		expectedAccountKey        = "user@example.test"
	)

	cfg := config.DefaultConfig()
	cfg.Director.Routing.AuthAttributes = config.RoutingAuthAttributesConfig{
		Tenant:   configuredTenantAttribute,
		ShardTag: configuredShardAttribute,
	}

	registry, err := backend.NewStaticRegistry(cfg.Director)
	if err != nil {
		t.Fatalf("NewStaticRegistry returned error: %v", err)
	}

	resolver, err := routeLookupResolver(cfg.Normalize(), registry)
	if err != nil {
		t.Fatalf("routeLookupResolver returned error: %v", err)
	}

	result, err := resolver.Resolve(context.Background(), routing.RoutingRequest{
		Tenant:            defaultTenant,
		Protocol:          protocolIMAP,
		ListenerName:      protocolIMAP,
		ServiceName:       protocolIMAP,
		BackendPool:       "imap-default",
		NormalizedAccount: expectedAccountKey,
		AuthAttributes: map[string][]string{
			configuredTenantAttribute: {expectedTenant},
			configuredShardAttribute:  {expectedShardTag},
			"mailShard":               {"mailstore-b"},
		},
	})
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}

	if result.Tenant != expectedTenant || result.ShardTag != expectedShardTag || result.AccountKey != expectedAccountKey {
		t.Fatalf("routing result = %#v, want configured tenant/shard attributes and account_field-derived account", result)
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

// TestRuntimeListHandlersMapPaginationClientErrors verifies list cursors and limits fail as client errors.
func TestRuntimeListHandlersMapPaginationClientErrors(t *testing.T) {
	reader := &recordingRuntimeReadService{}
	handler := NewHandler(HandlerOptions{
		Version:       testHandlerVersion,
		SessionReader: reader,
		UserReader:    reader,
	})

	badCursor := generated.RuntimeReadCursor("invalid")

	sessionResponse, err := handler.ListSessions(context.Background(), generated.ListSessionsRequestObject{
		Params: generated.ListSessionsParams{Cursor: &badCursor},
	})
	if err != nil {
		t.Fatalf("ListSessions returned error: %v", err)
	}

	sessionProblem, ok := sessionResponse.(generated.ListSessionsdefaultJSONResponse)
	if !ok {
		t.Fatalf("ListSessions response = %T, want problem", sessionResponse)
	}

	if sessionProblem.StatusCode != http.StatusBadRequest {
		t.Fatalf("session status = %d, want 400", sessionProblem.StatusCode)
	}

	if reader.sessionRequest.Cursor != "invalid" {
		t.Fatalf("session cursor = %q, want invalid", reader.sessionRequest.Cursor)
	}

	limit := generated.RuntimeReadLimit(1001)

	userResponse, err := handler.ListUsers(context.Background(), generated.ListUsersRequestObject{
		Params: generated.ListUsersParams{Limit: &limit},
	})
	if err != nil {
		t.Fatalf("ListUsers returned error: %v", err)
	}

	userProblem, ok := userResponse.(generated.ListUsersdefaultJSONResponse)
	if !ok {
		t.Fatalf("ListUsers response = %T, want problem", userResponse)
	}

	if userProblem.StatusCode != http.StatusBadRequest {
		t.Fatalf("user status = %d, want 400", userProblem.StatusCode)
	}

	if reader.userRequest.Limit != 1001 {
		t.Fatalf("user limit = %d, want 1001", reader.userRequest.Limit)
	}
}

// TestSummaryHandlerUsesAggregateReader verifies summaries do not call list readers.
func TestSummaryHandlerUsesAggregateReader(t *testing.T) {
	reader := &recordingRuntimeReadService{summary: runtime.Summary{
		RoutingAuthority: false,
		ActiveSessions: runtime.ActiveSessionSummary{
			Total:      runtime.CountSummary{Count: 7, Accuracy: runtime.AccuracyEventuallyRepaired},
			ByProtocol: []runtime.DimensionCount{{Value: "imap", Count: 7, Accuracy: runtime.AccuracyEventuallyRepaired}},
		},
		IdleAffinities: runtime.CountSummary{Count: 2, Accuracy: runtime.AccuracyEventuallyRepaired},
		Repairs: runtime.RepairSummary{
			ExpiredSessions:     runtime.CountSummary{Count: 1, Accuracy: runtime.AccuracyCumulative},
			StaleIndexEntries:   runtime.CountSummary{Count: 3, Accuracy: runtime.AccuracyCumulative},
			BackendReservations: runtime.CountSummary{Count: 4, Accuracy: runtime.AccuracyCumulative},
		},
	}}
	handler := NewHandler(HandlerOptions{
		Version:              testHandlerVersion,
		SessionReader:        reader,
		UserReader:           reader,
		RuntimeSummaryReader: reader,
	})

	response, err := handler.GetRuntimeSummary(context.Background(), generated.GetRuntimeSummaryRequestObject{})
	if err != nil {
		t.Fatalf("GetRuntimeSummary returned error: %v", err)
	}

	summary, ok := response.(generated.GetRuntimeSummary200JSONResponse)
	if !ok {
		t.Fatalf("GetRuntimeSummary response = %T, want summary", response)
	}

	if reader.summaryCalls != 1 || reader.sessionListCalls != 0 || reader.userListCalls != 0 {
		t.Fatalf("calls summary=%d sessions=%d users=%d, want summary only", reader.summaryCalls, reader.sessionListCalls, reader.userListCalls)
	}

	if summary.ActiveSessions.Total.Count != 7 || summary.RoutingAuthority {
		t.Fatalf("summary = %#v, want repairable non-authority totals", summary)
	}
}

// TestListListenersMapsRuntimeDetails verifies listener inventory uses generated DTOs.
func TestListListenersMapsRuntimeDetails(t *testing.T) {
	listenerRuntime := &recordingListenerRuntime{
		listResult: runtime.ListListenersResult{Listeners: []runtime.ListenerDetail{
			listenerRuntimeDetail(testListenerName, runtime.ListenerStateDraining, 3),
		}},
	}
	handler := NewHandler(HandlerOptions{Version: testHandlerVersion, ListenerRuntime: listenerRuntime})

	response, err := handler.ListListeners(context.Background(), generated.ListListenersRequestObject{})
	if err != nil {
		t.Fatalf("ListListeners returned error: %v", err)
	}

	list, ok := response.(generated.ListListeners200JSONResponse)
	if !ok {
		t.Fatalf("ListListeners response = %T, want 200 listener list", response)
	}

	if listenerRuntime.listCalls != 1 {
		t.Fatalf("ListListeners calls = %d, want 1", listenerRuntime.listCalls)
	}

	if len(list.Listeners) != 1 {
		t.Fatalf("listeners = %d, want 1", len(list.Listeners))
	}

	detail := list.Listeners[0]
	if detail.Name != testListenerName || detail.State != generated.ListenerState(runtime.ListenerStateDraining) || detail.ActiveLocalSessions != 3 {
		t.Fatalf("listener detail = %#v, want mapped runtime detail", detail)
	}

	if detail.BoundAddress == nil || *detail.BoundAddress != testListenerBound {
		t.Fatalf("bound address = %#v, want configured safe bound address", detail.BoundAddress)
	}

	if detail.DrainMode == nil || *detail.DrainMode != generated.DrainModeSoft {
		t.Fatalf("drain mode = %#v, want soft", detail.DrainMode)
	}

	assertListenerDTOSecretSafe(t, detail)
}

// TestGetListenerMapsKnownAndUnknownNames verifies lookup status mapping.
func TestGetListenerMapsKnownAndUnknownNames(t *testing.T) {
	listenerRuntime := &recordingListenerRuntime{
		getResult: listenerRuntimeDetail(testListenerName, runtime.ListenerStateAccepting, 0),
	}
	handler := NewHandler(HandlerOptions{Version: testHandlerVersion, ListenerRuntime: listenerRuntime})

	response, err := handler.GetListener(context.Background(), generated.GetListenerRequestObject{Name: testListenerName})
	if err != nil {
		t.Fatalf("GetListener returned error: %v", err)
	}

	detail, ok := response.(generated.GetListener200JSONResponse)
	if !ok {
		t.Fatalf("GetListener response = %T, want 200 detail", response)
	}

	if listenerRuntime.getRequest.Name != testListenerName {
		t.Fatalf("get request name = %q, want %q", listenerRuntime.getRequest.Name, testListenerName)
	}

	if detail.Name != testListenerName || detail.State != generated.ListenerState(runtime.ListenerStateAccepting) {
		t.Fatalf("GetListener detail = %#v, want accepting listener", detail)
	}

	listenerRuntime.getErr = newRuntimeError(runtime.ErrorKindNotFound, "listener_get", "listener not found")

	response, err = handler.GetListener(context.Background(), generated.GetListenerRequestObject{Name: "missing"})
	if err != nil {
		t.Fatalf("GetListener missing returned error: %v", err)
	}

	problem, ok := response.(generated.GetListenerdefaultJSONResponse)
	if !ok {
		t.Fatalf("GetListener missing response = %T, want problem", response)
	}

	if problem.StatusCode != http.StatusNotFound {
		t.Fatalf("GetListener missing status = %d, want 404", problem.StatusCode)
	}
}

// TestDrainListenerMapsRequestAndResponse verifies drain DTO conversion in both directions.
func TestDrainListenerMapsRequestAndResponse(t *testing.T) {
	graceSeconds := 7
	listenerRuntime := &recordingListenerRuntime{
		drainResult: runtime.ListenerMutationResult{
			Listener: listenerRuntimeDetail(testListenerName, runtime.ListenerStateDrained, 0),
		},
	}
	handler := NewHandler(HandlerOptions{Version: testHandlerVersion, ListenerRuntime: listenerRuntime})

	response, err := handler.DrainListener(context.Background(), generated.DrainListenerRequestObject{
		Name: testListenerName,
		Body: &generated.DrainListenerJSONRequestBody{
			GraceSeconds: &graceSeconds,
			Mode:         generated.DrainModeHard,
			Reason:       testListenerReason,
		},
	})
	if err != nil {
		t.Fatalf("DrainListener returned error: %v", err)
	}

	if listenerRuntime.drainRequest.Name != testListenerName {
		t.Fatalf("drain name = %q, want %q", listenerRuntime.drainRequest.Name, testListenerName)
	}

	if listenerRuntime.drainRequest.Mode != runtime.ListenerDrainModeHard {
		t.Fatalf("drain mode = %q, want hard", listenerRuntime.drainRequest.Mode)
	}

	if listenerRuntime.drainRequest.Reason != testListenerReason {
		t.Fatalf("drain reason = %q, want %q", listenerRuntime.drainRequest.Reason, testListenerReason)
	}

	if listenerRuntime.drainRequest.Grace == nil || *listenerRuntime.drainRequest.Grace != 7*time.Second {
		t.Fatalf("drain grace = %v, want 7s", listenerRuntime.drainRequest.Grace)
	}

	detail, ok := response.(generated.DrainListener202JSONResponse)
	if !ok {
		t.Fatalf("DrainListener response = %T, want 202 detail", response)
	}

	if detail.State != generated.ListenerState(runtime.ListenerStateDrained) {
		t.Fatalf("drain response state = %q, want drained", detail.State)
	}
}

// TestDrainListenerHardModeRequiresExplicitGrace verifies runtime validation reaches REST clients.
func TestDrainListenerHardModeRequiresExplicitGrace(t *testing.T) {
	manager := &adapterListenerManager{
		drainDetail: listenerRuntimeDetail(testListenerName, runtime.ListenerStateDrained, 0),
	}
	handler := NewHandler(HandlerOptions{
		Version:         testHandlerVersion,
		ListenerRuntime: runtime.NewListenerService(manager),
	})

	response, err := handler.DrainListener(context.Background(), generated.DrainListenerRequestObject{
		Name: testListenerName,
		Body: &generated.DrainListenerJSONRequestBody{
			Mode:   generated.DrainModeHard,
			Reason: testListenerReason,
		},
	})
	if err != nil {
		t.Fatalf("DrainListener returned error: %v", err)
	}

	problem, ok := response.(generated.DrainListenerdefaultJSONResponse)
	if !ok {
		t.Fatalf("DrainListener response = %T, want problem", response)
	}

	if problem.StatusCode != http.StatusBadRequest {
		t.Fatalf("hard drain status = %d, want 400", problem.StatusCode)
	}

	if !strings.Contains(problem.Body.Message, "hard drain requires explicit grace") {
		t.Fatalf("hard drain message = %q, want explicit grace diagnostic", problem.Body.Message)
	}

	if manager.drainCalls != 0 {
		t.Fatalf("manager drain calls = %d, want validation before manager access", manager.drainCalls)
	}
}

// TestResumeListenerMapsRequestAndResponse verifies resume returns updated listener detail.
func TestResumeListenerMapsRequestAndResponse(t *testing.T) {
	listenerRuntime := &recordingListenerRuntime{
		resumeResult: runtime.ListenerMutationResult{
			Listener: listenerRuntimeDetail(testListenerName, runtime.ListenerStateAccepting, 0),
		},
	}
	handler := NewHandler(HandlerOptions{Version: testHandlerVersion, ListenerRuntime: listenerRuntime})

	response, err := handler.ResumeListener(context.Background(), generated.ResumeListenerRequestObject{
		Name: testListenerName,
		Body: &generated.ResumeListenerJSONRequestBody{Reason: testListenerReason},
	})
	if err != nil {
		t.Fatalf("ResumeListener returned error: %v", err)
	}

	if listenerRuntime.resumeRequest.Name != testListenerName || listenerRuntime.resumeRequest.Reason != testListenerReason {
		t.Fatalf("resume request = %#v, want name and reason", listenerRuntime.resumeRequest)
	}

	detail, ok := response.(generated.ResumeListener202JSONResponse)
	if !ok {
		t.Fatalf("ResumeListener response = %T, want 202 detail", response)
	}

	if detail.State != generated.ListenerState(runtime.ListenerStateAccepting) {
		t.Fatalf("resume response state = %q, want accepting", detail.State)
	}
}

// TestListenerErrorMappingCoversRuntimeStatuses verifies public listener status mapping.
func TestListenerErrorMappingCoversRuntimeStatuses(t *testing.T) {
	testCases := []struct {
		name   string
		err    error
		status int
	}{
		{name: "bad request", err: newRuntimeError(runtime.ErrorKindInvalidRequest, "listener", "bad request"), status: http.StatusBadRequest},
		{name: "not found", err: newRuntimeError(runtime.ErrorKindNotFound, "listener", "not found"), status: http.StatusNotFound},
		{name: "conflict", err: newRuntimeError(runtime.ErrorKindConflict, "listener", "conflict"), status: http.StatusConflict},
		{name: "unavailable", err: newRuntimeError(runtime.ErrorKindUnavailable, "listener", "unavailable"), status: http.StatusServiceUnavailable},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			handler := NewHandler(HandlerOptions{
				Version:         testHandlerVersion,
				ListenerRuntime: &recordingListenerRuntime{drainErr: testCase.err},
			})

			response, err := handler.DrainListener(context.Background(), generated.DrainListenerRequestObject{
				Name: testListenerName,
				Body: &generated.DrainListenerJSONRequestBody{
					Mode:   generated.DrainModeSoft,
					Reason: testListenerReason,
				},
			})
			if err != nil {
				t.Fatalf("DrainListener returned error: %v", err)
			}

			problem, ok := response.(generated.DrainListenerdefaultJSONResponse)
			if !ok {
				t.Fatalf("DrainListener response = %T, want problem", response)
			}

			if problem.StatusCode != testCase.status {
				t.Fatalf("status = %d, want %d", problem.StatusCode, testCase.status)
			}
		})
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

// recordingRuntimeReadService captures paginated read requests.
type recordingRuntimeReadService struct {
	sessionRequest   runtime.SessionListRequest
	userRequest      runtime.UserListRequest
	summary          runtime.Summary
	sessionListCalls int
	userListCalls    int
	summaryCalls     int
}

// ListSessions records session list requests and rejects invalid test cursors.
func (r *recordingRuntimeReadService) ListSessions(_ context.Context, request runtime.SessionListRequest) (runtime.SessionListResult, error) {
	r.sessionListCalls++
	r.sessionRequest = request
	if request.Cursor != "" {
		return runtime.SessionListResult{}, newRuntimeError(runtime.ErrorKindInvalidRequest, "session_read", "cursor invalid")
	}

	return runtime.SessionListResult{}, nil
}

// GetSession is unused by pagination handler tests.
func (r *recordingRuntimeReadService) GetSession(context.Context, string) (runtime.SessionRuntimeState, error) {
	return runtime.SessionRuntimeState{}, newRuntimeError(runtime.ErrorKindNotFound, "session", "session not found")
}

// ListUserSessions is unused by pagination handler tests.
func (r *recordingRuntimeReadService) ListUserSessions(context.Context, runtime.UserKey) ([]runtime.SessionRuntimeState, error) {
	return nil, nil
}

// ListUsers records user list requests and rejects excessive test limits.
func (r *recordingRuntimeReadService) ListUsers(_ context.Context, request runtime.UserListRequest) (runtime.UserListResult, error) {
	r.userListCalls++
	r.userRequest = request
	if request.Limit > 1000 {
		return runtime.UserListResult{}, newRuntimeError(runtime.ErrorKindInvalidRequest, "user_read", "limit must not exceed 1000")
	}

	return runtime.UserListResult{}, nil
}

// GetUser is unused by pagination handler tests.
func (r *recordingRuntimeReadService) GetUser(context.Context, runtime.UserKey) (runtime.UserRuntimeState, error) {
	return runtime.UserRuntimeState{}, newRuntimeError(runtime.ErrorKindNotFound, "user", "user not found")
}

// GetUserAffinity is unused by pagination handler tests.
func (r *recordingRuntimeReadService) GetUserAffinity(context.Context, runtime.UserKey) (runtime.UserRuntimeState, error) {
	return runtime.UserRuntimeState{}, newRuntimeError(runtime.ErrorKindNotFound, "user_affinity", "user affinity not found")
}

// RuntimeSummary records summary calls without listing sessions or users.
func (r *recordingRuntimeReadService) RuntimeSummary(context.Context) (runtime.Summary, error) {
	r.summaryCalls++

	return r.summary, nil
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

// recordingListenerRuntime captures listener runtime requests for adapter assertions.
type recordingListenerRuntime struct {
	listCalls     int
	listResult    runtime.ListListenersResult
	listErr       error
	getRequest    runtime.GetListenerRequest
	getResult     runtime.ListenerDetail
	getErr        error
	drainRequest  runtime.DrainListenerRequest
	drainResult   runtime.ListenerMutationResult
	drainErr      error
	resumeRequest runtime.ResumeListenerRequest
	resumeResult  runtime.ListenerMutationResult
	resumeErr     error
}

// ListListeners records inventory calls and returns configured snapshots.
func (r *recordingListenerRuntime) ListListeners(context.Context, runtime.ListListenersRequest) (runtime.ListListenersResult, error) {
	r.listCalls++
	if r.listErr != nil {
		return runtime.ListListenersResult{}, r.listErr
	}

	return r.listResult, nil
}

// GetListener records a single listener lookup and returns configured detail.
func (r *recordingListenerRuntime) GetListener(_ context.Context, request runtime.GetListenerRequest) (runtime.ListenerDetail, error) {
	r.getRequest = request
	if r.getErr != nil {
		return runtime.ListenerDetail{}, r.getErr
	}

	return r.getResult, nil
}

// DrainListener records a listener drain and returns the configured mutation detail.
func (r *recordingListenerRuntime) DrainListener(_ context.Context, request runtime.DrainListenerRequest) (runtime.ListenerMutationResult, error) {
	r.drainRequest = request
	if r.drainErr != nil {
		return runtime.ListenerMutationResult{}, r.drainErr
	}

	return r.drainResult, nil
}

// ResumeListener records a listener resume and returns the configured mutation detail.
func (r *recordingListenerRuntime) ResumeListener(_ context.Context, request runtime.ResumeListenerRequest) (runtime.ListenerMutationResult, error) {
	r.resumeRequest = request
	if r.resumeErr != nil {
		return runtime.ListenerMutationResult{}, r.resumeErr
	}

	return r.resumeResult, nil
}

// adapterListenerManager lets REST tests exercise the real runtime listener service.
type adapterListenerManager struct {
	drainCalls  int
	drainDetail runtime.ListenerDetail
}

// Snapshots returns no inventory because validation tests do not need snapshots.
func (m *adapterListenerManager) Snapshots() []runtime.ListenerDetail {
	return nil
}

// Drain records manager access after runtime validation.
func (m *adapterListenerManager) Drain(context.Context, runtime.ListenerManagerDrainRequest) (runtime.ListenerDetail, error) {
	m.drainCalls++

	return m.drainDetail, nil
}

// Resume is unused by validation tests and returns a stopped detail.
func (m *adapterListenerManager) Resume(context.Context, string) (runtime.ListenerDetail, error) {
	return runtime.ListenerDetail{}, nil
}

// listenerRuntimeDetail builds one secret-safe listener runtime projection.
func listenerRuntimeDetail(name string, state runtime.ListenerState, active int) runtime.ListenerDetail {
	detail := runtime.ListenerDetail{
		Name:                name,
		Protocol:            "imap",
		ServiceName:         "imap-login",
		Network:             "tcp",
		Address:             "127.0.0.1:1143",
		TLSMode:             "starttls",
		ImplicitTLS:         false,
		ProxyProtocol:       true,
		BoundAddress:        testListenerBound,
		State:               state,
		ActiveLocalSessions: active,
	}
	if state == runtime.ListenerStateDraining || state == runtime.ListenerStateDrained {
		detail.DrainMode = runtime.ListenerDrainModeSoft
	}

	return detail
}

// assertListenerDTOSecretSafe rejects fields outside the public listener contract.
func assertListenerDTOSecretSafe(t *testing.T, detail generated.ListenerDetail) {
	t.Helper()

	payload, err := json.Marshal(detail)
	if err != nil {
		t.Fatalf("marshal listener DTO: %v", err)
	}

	rendered := string(payload)
	for _, forbidden := range []string{"peer", "username", "recipient", "session_id", "credential", "private_key"} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("listener DTO exposed forbidden field %q in %s", forbidden, rendered)
		}
	}
}

var _ ListenerRuntimeService = (*recordingListenerRuntime)(nil)
var _ runtime.ListenerManager = (*adapterListenerManager)(nil)
