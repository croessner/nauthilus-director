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
	testBackendIdentifier   = "mailstore-a-imap"
	testBackendPinOperation = "user_backend_pin_set"
	testBackendPinPool      = "imap-default"
	testBackendPinApplied   = "backend_pin_applied"
	testBackendPinReason    = "commission backend"
	testBackendPinShard     = "mailstore-a"
	testBackendPinTenant    = "tenant-a"
	testBackendPinUserKey   = "tenant-a:alice-hash"
	testBackendPinUserHash  = "alice-hash"
	testBackendPinProtocol  = "imap"
	testConfigView          = configViewDefaults
	testHandlerVersion      = "test"
	testHoldReason          = "pause placement"
	testHoldSetOperation    = "user_hold_set"
	testRuntimeBadRequest   = "hold bad request"
	testRuntimeConflict     = "hold conflict"
	testRuntimeUnavailable  = "hold unavailable"
	testListenerBound       = "127.0.0.1:2143"
	testListenerName        = "imap"
	testListenerReason      = "node maintenance"
	testPinnedBackend       = "mailstore-c-imap"
)

// TestLookupRouteUsesInjectedSideEffectFreeDomainService verifies route lookup is no longer a stub.
func TestLookupRouteUsesInjectedSideEffectFreeDomainService(t *testing.T) {
	lookup := &recordingRouteLookup{}
	handler := NewHandler(HandlerOptions{Version: testHandlerVersion, RouteLookup: lookup})

	userKey := testBackendPinUserHash
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

	routeResponse, ok := response.(generated.LookupRoute200JSONResponse)
	if !ok {
		t.Fatalf("LookupRoute response = %T, want 200 response", response)
	}

	if !routeResponse.BackendPin.Present || !routeResponse.BackendPin.Applied || routeResponse.BackendPin.Reason != testBackendPinApplied {
		t.Fatalf("backend pin = %#v, want applied diagnostics", routeResponse.BackendPin)
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

// TestGetUserBackendPinMapsAbsentDTO verifies absent read DTO mapping.
func TestGetUserBackendPinMapsAbsentDTO(t *testing.T) {
	service := &recordingUserBackendPinService{
		readResult: runtime.UserBackendPinReadResult{
			Pin: runtime.UserBackendPin{Present: false},
		},
	}
	handler := NewHandler(HandlerOptions{
		Version:              testHandlerVersion,
		UserBackendPinReader: service,
	})

	response, err := handler.GetUserBackendPin(context.Background(), generated.GetUserBackendPinRequestObject{UserKey: testBackendPinUserHash})
	if err != nil {
		t.Fatalf("GetUserBackendPin returned error: %v", err)
	}

	pin, ok := response.(generated.GetUserBackendPin200JSONResponse)
	if !ok {
		t.Fatalf("GetUserBackendPin response = %T, want 200 backend pin", response)
	}

	if service.readCalls != 1 {
		t.Fatalf("read calls = %d, want 1", service.readCalls)
	}

	if service.readRequest.Key != (runtime.UserKey{Tenant: defaultTenant, UserHash: testBackendPinUserHash}) {
		t.Fatalf("read key = %#v, want parsed default tenant key", service.readRequest.Key)
	}

	if pin.Present || pin.UserKey != testBackendPinUserHash || pin.Backend != nil || pin.Strategy != nil {
		t.Fatalf("absent pin DTO = %#v, want only present=false and user key", pin)
	}
}

// TestGetUserBackendPinMapsPresentDTO verifies present read DTO mapping.
func TestGetUserBackendPinMapsPresentDTO(t *testing.T) {
	service := &recordingUserBackendPinService{
		readResult: runtime.UserBackendPinReadResult{
			Pin: runtime.UserBackendPin{
				Present:            true,
				Key:                runtime.UserKey{Tenant: testBackendPinTenant, UserHash: testBackendPinUserHash},
				BackendIdentifier:  testPinnedBackend,
				Protocol:           testBackendPinProtocol,
				BackendPool:        testBackendPinPool,
				EffectiveShard:     testBackendPinShard,
				Strategy:           runtime.MoveStrategyKickExisting,
				Generation:         "42",
				ActiveSessionCount: 3,
			},
		},
	}
	handler := NewHandler(HandlerOptions{
		Version:              testHandlerVersion,
		UserBackendPinReader: service,
	})

	response, err := handler.GetUserBackendPin(context.Background(), generated.GetUserBackendPinRequestObject{UserKey: testBackendPinUserKey})
	if err != nil {
		t.Fatalf("GetUserBackendPin returned error: %v", err)
	}

	pin, ok := response.(generated.GetUserBackendPin200JSONResponse)
	if !ok {
		t.Fatalf("GetUserBackendPin response = %T, want 200 backend pin", response)
	}

	if !pin.Present {
		t.Fatalf("present = false, want true for %#v", pin)
	}

	if pin.UserKey != testBackendPinUserKey {
		t.Fatalf("user key = %q, want %q", pin.UserKey, testBackendPinUserKey)
	}

	assertStringPtrValue(t, "backend", pin.Backend, testPinnedBackend)
	assertStringPtrValue(t, "protocol", pin.Protocol, testBackendPinProtocol)
	assertStringPtrValue(t, "backend pool", pin.BackendPool, testBackendPinPool)
	assertStringPtrValue(t, "shard tag", pin.ShardTag, testBackendPinShard)
	assertStringPtrValue(t, "generation", pin.Generation, "42")
	assertBackendPinStrategy(t, pin.Strategy, generated.KickExisting)
	assertIntPtrValue(t, "active session count", pin.ActiveSessionCount, 3)
}

// TestDefaultBackendPinReaderReturnsAbsent verifies unassembled servers stay deterministic.
func TestDefaultBackendPinReaderReturnsAbsent(t *testing.T) {
	handler := NewHandler(HandlerOptions{Version: testHandlerVersion})

	response, err := handler.GetUserBackendPin(context.Background(), generated.GetUserBackendPinRequestObject{UserKey: testBackendPinUserHash})
	if err != nil {
		t.Fatalf("GetUserBackendPin returned error: %v", err)
	}

	pin, ok := response.(generated.GetUserBackendPin200JSONResponse)
	if !ok {
		t.Fatalf("GetUserBackendPin response = %T, want 200 backend pin", response)
	}

	if pin.Present || pin.UserKey != testBackendPinUserHash {
		t.Fatalf("default pin DTO = %#v, want absent pin for request key", pin)
	}
}

// TestSetUserBackendPinMapsGeneratedRequest verifies REST input stays at the adapter edge.
func TestSetUserBackendPinMapsGeneratedRequest(t *testing.T) {
	service := &recordingUserBackendPinService{}
	handler := NewHandler(HandlerOptions{
		Version:               testHandlerVersion,
		UserBackendPinMutator: service,
		UserBackendPinReader:  service,
	})

	body := generated.SetUserBackendPinJSONRequestBody{
		Backend:  " " + testPinnedBackend + " ",
		Reason:   " " + testBackendPinReason + " ",
		Strategy: generated.KickExisting,
	}

	response, err := handler.SetUserBackendPin(context.Background(), generated.SetUserBackendPinRequestObject{
		UserKey: testBackendPinUserKey,
		Body:    &body,
	})
	if err != nil {
		t.Fatalf("SetUserBackendPin returned error: %v", err)
	}

	if _, ok := response.(generated.SetUserBackendPin202JSONResponse); !ok {
		t.Fatalf("SetUserBackendPin response = %T, want 202 accepted", response)
	}

	if service.setCalls != 1 {
		t.Fatalf("set calls = %d, want 1", service.setCalls)
	}

	wantKey := runtime.UserKey{Tenant: testBackendPinTenant, UserHash: testBackendPinUserHash}
	if service.setRequest.Key != wantKey ||
		service.setRequest.BackendIdentifier != testPinnedBackend ||
		service.setRequest.Strategy != runtime.MoveStrategyKickExisting ||
		service.setRequest.Reason != testBackendPinReason {
		t.Fatalf("set request = %#v, want trimmed runtime request", service.setRequest)
	}
}

// TestClearUserBackendPinRequiresReasonAndCallsRuntime verifies clear validation and mutation flow.
func TestClearUserBackendPinRequiresReasonAndCallsRuntime(t *testing.T) {
	service := &recordingUserBackendPinService{}
	handler := NewHandler(HandlerOptions{
		Version:               testHandlerVersion,
		UserBackendPinMutator: service,
		UserBackendPinReader:  service,
	})

	emptyBody := generated.ClearUserBackendPinJSONRequestBody{Reason: "   "}

	emptyResponse, err := handler.ClearUserBackendPin(context.Background(), generated.ClearUserBackendPinRequestObject{
		UserKey: testBackendPinUserHash,
		Body:    &emptyBody,
	})
	if err != nil {
		t.Fatalf("ClearUserBackendPin empty reason returned error: %v", err)
	}

	assertBackendPinProblemStatus(t, emptyResponse, http.StatusBadRequest)

	if service.clearCalls != 0 {
		t.Fatalf("clear calls = %d, want 0 for invalid reason", service.clearCalls)
	}

	body := generated.ClearUserBackendPinJSONRequestBody{Reason: " " + testBackendPinReason + " "}

	response, err := handler.ClearUserBackendPin(context.Background(), generated.ClearUserBackendPinRequestObject{
		UserKey: testBackendPinUserHash,
		Body:    &body,
	})
	if err != nil {
		t.Fatalf("ClearUserBackendPin returned error: %v", err)
	}

	if _, ok := response.(generated.ClearUserBackendPin202JSONResponse); !ok {
		t.Fatalf("ClearUserBackendPin response = %T, want 202 accepted", response)
	}

	if service.clearCalls != 1 {
		t.Fatalf("clear calls = %d, want 1", service.clearCalls)
	}

	if service.clearRequest.Key != (runtime.UserKey{Tenant: defaultTenant, UserHash: testBackendPinUserHash}) ||
		service.clearRequest.Reason != testBackendPinReason {
		t.Fatalf("clear request = %#v, want parsed key and trimmed reason", service.clearRequest)
	}
}

// TestBackendPinRequestValidationMapsToBadRequest verifies missing bodies and empty reasons.
func TestBackendPinRequestValidationMapsToBadRequest(t *testing.T) {
	handler := NewHandler(HandlerOptions{
		Version:               testHandlerVersion,
		UserBackendPinMutator: &recordingUserBackendPinService{},
	})

	setMissing, err := handler.SetUserBackendPin(context.Background(), generated.SetUserBackendPinRequestObject{UserKey: testBackendPinUserHash})
	if err != nil {
		t.Fatalf("SetUserBackendPin missing body returned error: %v", err)
	}

	assertBackendPinProblemStatus(t, setMissing, http.StatusBadRequest)

	setBody := generated.SetUserBackendPinJSONRequestBody{
		Backend:  testPinnedBackend,
		Reason:   "",
		Strategy: generated.NewSessionsOnly,
	}

	setEmptyReason, err := handler.SetUserBackendPin(context.Background(), generated.SetUserBackendPinRequestObject{
		UserKey: testBackendPinUserHash,
		Body:    &setBody,
	})
	if err != nil {
		t.Fatalf("SetUserBackendPin empty reason returned error: %v", err)
	}

	assertBackendPinProblemStatus(t, setEmptyReason, http.StatusBadRequest)

	clearMissing, err := handler.ClearUserBackendPin(context.Background(), generated.ClearUserBackendPinRequestObject{UserKey: testBackendPinUserHash})
	if err != nil {
		t.Fatalf("ClearUserBackendPin missing body returned error: %v", err)
	}

	assertBackendPinProblemStatus(t, clearMissing, http.StatusBadRequest)
}

// TestBackendPinRuntimeErrorsMapToStableStatuses verifies generated problems remain deterministic.
func TestBackendPinRuntimeErrorsMapToStableStatuses(t *testing.T) {
	testCases := []struct {
		name   string
		err    error
		status int
	}{
		{
			name:   "unknown backend",
			err:    &runtime.Error{Kind: runtime.ErrorKindNotFound, Operation: testBackendPinOperation, Message: "backend not found"},
			status: http.StatusNotFound,
		},
		{
			name:   "state conflict",
			err:    &runtime.Error{Kind: runtime.ErrorKindConflict, Operation: testBackendPinOperation, Message: "state conflict"},
			status: http.StatusConflict,
		},
		{
			name:   "runtime unavailable",
			err:    &runtime.Error{Kind: runtime.ErrorKindUnavailable, Operation: testBackendPinOperation, Message: "redis unavailable"},
			status: http.StatusServiceUnavailable,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			service := &recordingUserBackendPinService{setErr: testCase.err}
			handler := NewHandler(HandlerOptions{
				Version:               testHandlerVersion,
				UserBackendPinMutator: service,
			})

			body := generated.SetUserBackendPinJSONRequestBody{
				Backend:  testPinnedBackend,
				Reason:   testBackendPinReason,
				Strategy: generated.NewSessionsOnly,
			}

			response, err := handler.SetUserBackendPin(context.Background(), generated.SetUserBackendPinRequestObject{
				UserKey: testBackendPinUserHash,
				Body:    &body,
			})
			if err != nil {
				t.Fatalf("SetUserBackendPin returned error: %v", err)
			}

			assertBackendPinProblemStatus(t, response, testCase.status)
		})
	}
}

// TestGetUserHoldMapsAbsentDTO verifies absent hold reads keep reason-free DTOs.
func TestGetUserHoldMapsAbsentDTO(t *testing.T) {
	service := &recordingUserHoldService{
		readResult: runtime.GetUserHoldResult{
			Hold: runtime.UserHold{Present: false},
		},
	}
	handler := NewHandler(HandlerOptions{
		Version:        testHandlerVersion,
		UserHoldReader: service,
	})

	response, err := handler.GetUserHold(context.Background(), generated.GetUserHoldRequestObject{UserKey: testBackendPinUserHash})
	if err != nil {
		t.Fatalf("GetUserHold returned error: %v", err)
	}

	hold, ok := response.(generated.GetUserHold200JSONResponse)
	if !ok {
		t.Fatalf("GetUserHold response = %T, want 200 hold", response)
	}

	if service.readCalls != 1 {
		t.Fatalf("hold read calls = %d, want 1", service.readCalls)
	}

	if service.readRequest.Key != (runtime.UserKey{Tenant: defaultTenant, UserHash: testBackendPinUserHash}) {
		t.Fatalf("hold read key = %#v, want parsed default tenant key", service.readRequest.Key)
	}

	if hold.Present || hold.UserKey != testBackendPinUserHash || hold.CreatedAt != nil || hold.ExpiresAt != nil || hold.RemainingSeconds != nil || hold.Generation != nil {
		t.Fatalf("absent hold DTO = %#v, want only present=false and user key", hold)
	}
}

// TestGetUserHoldMapsPresentDTO verifies hold reads stay bounded and reason-free.
func TestGetUserHoldMapsPresentDTO(t *testing.T) {
	createdAt := time.Now().Add(-time.Minute).UTC()
	expiresAt := time.Now().Add(time.Minute).UTC()
	service := &recordingUserHoldService{
		readResult: runtime.GetUserHoldResult{
			Hold: runtime.UserHold{
				Present:    true,
				Key:        runtime.UserKey{Tenant: testBackendPinTenant, UserHash: testBackendPinUserHash},
				Generation: "7",
				CreatedAt:  createdAt,
				ExpiresAt:  expiresAt,
			},
		},
	}
	handler := NewHandler(HandlerOptions{
		Version:        testHandlerVersion,
		UserHoldReader: service,
	})

	response, err := handler.GetUserHold(context.Background(), generated.GetUserHoldRequestObject{UserKey: testBackendPinUserKey})
	if err != nil {
		t.Fatalf("GetUserHold returned error: %v", err)
	}

	hold, ok := response.(generated.GetUserHold200JSONResponse)
	if !ok {
		t.Fatalf("GetUserHold response = %T, want 200 hold", response)
	}

	if service.readCalls != 1 {
		t.Fatalf("hold read calls = %d, want 1", service.readCalls)
	}

	if !hold.Present || hold.UserKey != testBackendPinUserKey {
		t.Fatalf("hold DTO = %#v, want present user hold", hold)
	}

	assertStringPtrValue(t, "hold generation", hold.Generation, "7")

	if hold.CreatedAt == nil || hold.ExpiresAt == nil || hold.RemainingSeconds == nil {
		t.Fatalf("hold timestamps = created=%v expires=%v remaining=%v, want present", hold.CreatedAt, hold.ExpiresAt, hold.RemainingSeconds)
	}
}

// TestSetUserHoldMapsGeneratedRequest verifies duration_seconds converts at the REST boundary.
func TestSetUserHoldMapsGeneratedRequest(t *testing.T) {
	service := &recordingUserHoldService{}
	handler := NewHandler(HandlerOptions{
		Version:         testHandlerVersion,
		UserHoldMutator: service,
	})

	body := generated.SetUserHoldJSONRequestBody{
		DurationSeconds: 90,
		Reason:          " " + testHoldReason + " ",
	}

	response, err := handler.SetUserHold(context.Background(), generated.SetUserHoldRequestObject{
		UserKey: testBackendPinUserKey,
		Body:    &body,
	})
	if err != nil {
		t.Fatalf("SetUserHold returned error: %v", err)
	}

	if _, ok := response.(generated.SetUserHold202JSONResponse); !ok {
		t.Fatalf("SetUserHold response = %T, want 202 accepted", response)
	}

	if service.setCalls != 1 {
		t.Fatalf("hold set calls = %d, want 1", service.setCalls)
	}

	wantKey := runtime.UserKey{Tenant: testBackendPinTenant, UserHash: testBackendPinUserHash}
	if service.setRequest.Key != wantKey || service.setRequest.Duration != 90*time.Second || service.setRequest.Reason != testHoldReason {
		t.Fatalf("hold set request = %#v, want parsed key, duration and trimmed reason", service.setRequest)
	}
}

// TestSetUserHoldRejectsInvalidRequests keeps malformed DTOs local to the REST edge.
func TestSetUserHoldRejectsInvalidRequests(t *testing.T) {
	testCases := []struct {
		name string
		body *generated.SetUserHoldJSONRequestBody
	}{
		{name: "missing body", body: nil},
		{name: "zero duration", body: &generated.SetUserHoldJSONRequestBody{Reason: testHoldReason}},
		{name: "negative duration", body: &generated.SetUserHoldJSONRequestBody{DurationSeconds: -1, Reason: testHoldReason}},
		{name: "missing reason", body: &generated.SetUserHoldJSONRequestBody{DurationSeconds: 60, Reason: "  "}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			service := &recordingUserHoldService{}
			handler := NewHandler(HandlerOptions{
				Version:         testHandlerVersion,
				UserHoldMutator: service,
			})

			response, err := handler.SetUserHold(context.Background(), generated.SetUserHoldRequestObject{
				UserKey: testBackendPinUserHash,
				Body:    testCase.body,
			})
			if err != nil {
				t.Fatalf("SetUserHold returned error: %v", err)
			}

			assertUserHoldProblemStatus(t, response, http.StatusBadRequest)

			if service.setCalls != 0 {
				t.Fatalf("hold set calls = %d, want 0 for invalid request", service.setCalls)
			}
		})
	}
}

// TestUserHoldRuntimeErrorsMapToRESTStatuses verifies generated problem status mapping.
func TestUserHoldRuntimeErrorsMapToRESTStatuses(t *testing.T) {
	testCases := []struct {
		name   string
		err    error
		status int
	}{
		{name: testRuntimeBadRequest, err: newRuntimeError(runtime.ErrorKindInvalidRequest, testHoldSetOperation, testRuntimeBadRequest), status: http.StatusBadRequest},
		{name: testRuntimeConflict, err: newRuntimeError(runtime.ErrorKindConflict, testHoldSetOperation, testRuntimeConflict), status: http.StatusConflict},
		{name: testRuntimeUnavailable, err: newRuntimeError(runtime.ErrorKindUnavailable, testHoldSetOperation, "redis unavailable"), status: http.StatusServiceUnavailable},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			service := &recordingUserHoldService{setErr: testCase.err}
			handler := NewHandler(HandlerOptions{
				Version:         testHandlerVersion,
				UserHoldMutator: service,
			})

			body := generated.SetUserHoldJSONRequestBody{
				DurationSeconds: 60,
				Reason:          testHoldReason,
			}

			response, err := handler.SetUserHold(context.Background(), generated.SetUserHoldRequestObject{
				UserKey: testBackendPinUserHash,
				Body:    &body,
			})
			if err != nil {
				t.Fatalf("SetUserHold returned error: %v", err)
			}

			assertUserHoldProblemStatus(t, response, testCase.status)
		})
	}
}

// TestClearUserHoldRequiresReasonAndCallsRuntime verifies clear validation and mutation flow.
func TestClearUserHoldRequiresReasonAndCallsRuntime(t *testing.T) {
	service := &recordingUserHoldService{}
	handler := NewHandler(HandlerOptions{
		Version:         testHandlerVersion,
		UserHoldMutator: service,
	})

	emptyBody := generated.ClearUserHoldJSONRequestBody{Reason: "   "}

	emptyResponse, err := handler.ClearUserHold(context.Background(), generated.ClearUserHoldRequestObject{
		UserKey: testBackendPinUserHash,
		Body:    &emptyBody,
	})
	if err != nil {
		t.Fatalf("ClearUserHold empty reason returned error: %v", err)
	}

	assertUserHoldProblemStatus(t, emptyResponse, http.StatusBadRequest)

	if service.clearCalls != 0 {
		t.Fatalf("hold clear calls = %d, want 0 for invalid reason", service.clearCalls)
	}

	body := generated.ClearUserHoldJSONRequestBody{Reason: " " + testHoldReason + " "}

	response, err := handler.ClearUserHold(context.Background(), generated.ClearUserHoldRequestObject{
		UserKey: testBackendPinUserHash,
		Body:    &body,
	})
	if err != nil {
		t.Fatalf("ClearUserHold returned error: %v", err)
	}

	if _, ok := response.(generated.ClearUserHold202JSONResponse); !ok {
		t.Fatalf("ClearUserHold response = %T, want 202 accepted", response)
	}

	if service.clearCalls != 1 {
		t.Fatalf("hold clear calls = %d, want 1", service.clearCalls)
	}

	if service.clearRequest.Key != (runtime.UserKey{Tenant: defaultTenant, UserHash: testBackendPinUserHash}) ||
		service.clearRequest.Reason != testHoldReason {
		t.Fatalf("hold clear request = %#v, want parsed key and trimmed reason", service.clearRequest)
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
		BackendPin: runtime.RouteLookupBackendPinState{
			Present:        true,
			BackendID:      testPinnedBackend,
			Protocol:       testBackendPinProtocol,
			BackendPool:    testBackendPinPool,
			EffectiveShard: testBackendPinShard,
			Applied:        true,
			ReasonClass:    testBackendPinApplied,
		},
		SelectedBackend: "mailstore-a-imap",
		ReasonClass:     "initial_placement",
	}, nil
}

// recordingUserBackendPinService captures backend-pin runtime requests.
type recordingUserBackendPinService struct {
	readCalls    int
	readRequest  runtime.GetUserBackendPinRequest
	readResult   runtime.UserBackendPinReadResult
	readErr      error
	setCalls     int
	setRequest   runtime.SetUserBackendPinRequest
	setResult    runtime.UserBackendPinMutationResult
	setErr       error
	clearCalls   int
	clearRequest runtime.ClearUserBackendPinRequest
	clearResult  runtime.UserBackendPinMutationResult
	clearErr     error
}

// GetUserBackendPin records one backend-pin read request.
func (r *recordingUserBackendPinService) GetUserBackendPin(_ context.Context, request runtime.GetUserBackendPinRequest) (runtime.UserBackendPinReadResult, error) {
	r.readCalls++

	r.readRequest = request
	if r.readErr != nil {
		return runtime.UserBackendPinReadResult{}, r.readErr
	}

	return r.readResult, nil
}

// SetUserBackendPin records one backend-pin set request.
func (r *recordingUserBackendPinService) SetUserBackendPin(_ context.Context, request runtime.SetUserBackendPinRequest) (runtime.UserBackendPinMutationResult, error) {
	r.setCalls++

	r.setRequest = request
	if r.setErr != nil {
		return runtime.UserBackendPinMutationResult{}, r.setErr
	}

	return r.setResult, nil
}

// ClearUserBackendPin records one backend-pin clear request.
func (r *recordingUserBackendPinService) ClearUserBackendPin(_ context.Context, request runtime.ClearUserBackendPinRequest) (runtime.UserBackendPinMutationResult, error) {
	r.clearCalls++

	r.clearRequest = request
	if r.clearErr != nil {
		return runtime.UserBackendPinMutationResult{}, r.clearErr
	}

	return r.clearResult, nil
}

// recordingUserHoldService captures placement-hold runtime requests.
type recordingUserHoldService struct {
	readCalls    int
	readRequest  runtime.GetUserHoldRequest
	readResult   runtime.GetUserHoldResult
	readErr      error
	setCalls     int
	setRequest   runtime.SetUserHoldRequest
	setResult    runtime.SetUserHoldResult
	setErr       error
	clearCalls   int
	clearRequest runtime.ClearUserHoldRequest
	clearResult  runtime.ClearUserHoldResult
	clearErr     error
}

// GetUserHold records one placement-hold read request.
func (r *recordingUserHoldService) GetUserHold(_ context.Context, request runtime.GetUserHoldRequest) (runtime.GetUserHoldResult, error) {
	r.readCalls++

	r.readRequest = request
	if r.readErr != nil {
		return runtime.GetUserHoldResult{}, r.readErr
	}

	return r.readResult, nil
}

// SetUserHold records one placement-hold set request.
func (r *recordingUserHoldService) SetUserHold(_ context.Context, request runtime.SetUserHoldRequest) (runtime.SetUserHoldResult, error) {
	r.setCalls++

	r.setRequest = request
	if r.setErr != nil {
		return runtime.SetUserHoldResult{}, r.setErr
	}

	return r.setResult, nil
}

// ClearUserHold records one placement-hold clear request.
func (r *recordingUserHoldService) ClearUserHold(_ context.Context, request runtime.ClearUserHoldRequest) (runtime.ClearUserHoldResult, error) {
	r.clearCalls++

	r.clearRequest = request
	if r.clearErr != nil {
		return runtime.ClearUserHoldResult{}, r.clearErr
	}

	return r.clearResult, nil
}

// assertBackendPinProblemStatus checks backend-pin generated problem responses.
func assertBackendPinProblemStatus(t *testing.T, response any, want int) {
	t.Helper()

	assertGeneratedUserProblemStatus(t, response, want, "backend-pin")
}

// assertUserHoldProblemStatus checks placement-hold generated problem responses.
func assertUserHoldProblemStatus(t *testing.T, response any, want int) {
	t.Helper()

	assertGeneratedUserProblemStatus(t, response, want, "user-hold")
}

// assertGeneratedUserProblemStatus checks generated user-runtime problem responses.
func assertGeneratedUserProblemStatus(t *testing.T, response any, want int, label string) {
	t.Helper()

	var got int

	switch typed := response.(type) {
	case generated.ClearUserBackendPindefaultJSONResponse:
		got = typed.StatusCode
	case generated.GetUserBackendPindefaultJSONResponse:
		got = typed.StatusCode
	case generated.SetUserBackendPindefaultJSONResponse:
		got = typed.StatusCode
	case generated.ClearUserHolddefaultJSONResponse:
		got = typed.StatusCode
	case generated.GetUserHolddefaultJSONResponse:
		got = typed.StatusCode
	case generated.SetUserHolddefaultJSONResponse:
		got = typed.StatusCode
	default:
		t.Fatalf("response = %T, want %s problem", response, label)
	}

	if got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
}

// assertStringPtrValue checks generated optional string fields.
func assertStringPtrValue(t *testing.T, name string, value *string, want string) {
	t.Helper()

	if stringPtrValue(value) != want {
		t.Fatalf("%s = %q, want %q", name, stringPtrValue(value), want)
	}
}

// assertBackendPinStrategy checks generated optional strategy fields.
func assertBackendPinStrategy(t *testing.T, value *generated.UserMoveRequestStrategy, want generated.UserMoveRequestStrategy) {
	t.Helper()

	if value == nil {
		t.Fatalf("strategy = nil, want %s", want)
	}

	if *value != want {
		t.Fatalf("strategy = %s, want %s", *value, want)
	}
}

// assertIntPtrValue checks generated optional integer fields.
func assertIntPtrValue(t *testing.T, name string, value *int, want int) {
	t.Helper()

	if value == nil {
		t.Fatalf("%s = nil, want %d", name, want)
	}

	if *value != want {
		t.Fatalf("%s = %d, want %d", name, *value, want)
	}
}

// stringPtrValue unwraps generated optional strings for assertions.
func stringPtrValue(value *string) string {
	if value == nil {
		return ""
	}

	return *value
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
