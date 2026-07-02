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

//nolint:goconst,wsl_v5 // REST adapter fixtures repeat generated DTO field values intentionally.
package adapters

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
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
	testBackendNode         = "mailstore-a-node-1"
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
	testSessionKillID       = "session-a"
	testSessionKillReason   = "operator killed holder"
	testPinnedBackend       = "mailstore-c-imap"
	testPrivateKeyField     = "private_key"
	testRecipientField      = "recipient"
	testSecretField         = "credential"
	testSessionIDField      = "session_id"
	testUsernameField       = "username"
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
	assertStringPtrValue(t, "backend pin node", routeResponse.BackendPin.BackendNode, testBackendNode)
	if routeResponse.BackendPin.ScopeCount == nil || *routeResponse.BackendPin.ScopeCount != 2 {
		t.Fatalf("scope count = %#v, want 2", routeResponse.BackendPin.ScopeCount)
	}
	if routeResponse.BackendPin.CurrentScopeUnpinned == nil || *routeResponse.BackendPin.CurrentScopeUnpinned {
		t.Fatalf("current scope unpinned = %#v, want false", routeResponse.BackendPin.CurrentScopeUnpinned)
	}
	if routeResponse.BackendPin.OtherScopes == nil || len(*routeResponse.BackendPin.OtherScopes) != 1 || (*routeResponse.BackendPin.OtherScopes)[0].Protocol != "lmtp" {
		t.Fatalf("other scopes = %#v, want bounded LMTP context", routeResponse.BackendPin.OtherScopes)
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

// TestRouteLookupShardTagsIncludeSieveBackends verifies diagnostics do not depend on IMAP-only shards.
func TestRouteLookupShardTagsIncludeSieveBackends(t *testing.T) {
	const sieveOnlyShard = "sieve-only-shard"

	cfg := config.DefaultConfig()
	sieveBackend := cfg.Director.Backends["mailstore-a-sieve"]
	sieveBackend.BackendNode = "sieve-only-node"
	sieveBackend.ShardTag = sieveOnlyShard
	cfg.Director.Backends["mailstore-a-sieve"] = sieveBackend
	cfg = cfg.Normalize()

	registry, err := backend.NewStaticRegistry(cfg.Director)
	if err != nil {
		t.Fatalf("NewStaticRegistry returned error: %v", err)
	}

	shards := routeLookupShardTags(cfg, registry)
	if !slices.Contains(shards, sieveOnlyShard) {
		t.Fatalf("route lookup shards = %#v, want %s", shards, sieveOnlyShard)
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

// TestBackendRuntimeHandlersUseConfiguredOverridePolicy verifies REST mutations honor typed config.
//
//nolint:funlen // The table keeps backend REST policy denials in one matrix.
func TestBackendRuntimeHandlersUseConfiguredOverridePolicy(t *testing.T) {
	testCases := []struct {
		name    string
		config  func(*config.Config)
		request func(*Handler) (any, error)
	}{
		{
			name: "global runtime overrides disabled rejects weight",
			config: func(cfg *config.Config) {
				cfg.Director.RuntimeOverrides.Enabled = false
			},
			request: func(handler *Handler) (any, error) {
				return handler.SetBackendWeight(context.Background(), generated.SetBackendWeightRequestObject{
					Identifier: testBackendIdentifier,
					Body: &generated.SetBackendWeightJSONRequestBody{
						Weight: 10,
						Reason: "adjust weight",
					},
				})
			},
		},
		{
			name: "weight override disabled rejects weight",
			config: func(cfg *config.Config) {
				cfg.Director.RuntimeOverrides.Backends.AllowWeightOverride = false
			},
			request: func(handler *Handler) (any, error) {
				return handler.SetBackendWeight(context.Background(), generated.SetBackendWeightRequestObject{
					Identifier: testBackendIdentifier,
					Body: &generated.SetBackendWeightJSONRequestBody{
						Weight: 10,
						Reason: "adjust weight",
					},
				})
			},
		},
		{
			name: "weight outside bounds rejects weight",
			config: func(cfg *config.Config) {
				cfg.Director.RuntimeOverrides.Backends.MinWeight = 10
				cfg.Director.RuntimeOverrides.Backends.MaxWeight = 20
			},
			request: func(handler *Handler) (any, error) {
				return handler.SetBackendWeight(context.Background(), generated.SetBackendWeightRequestObject{
					Identifier: testBackendIdentifier,
					Body: &generated.SetBackendWeightJSONRequestBody{
						Weight: 25,
						Reason: "adjust weight",
					},
				})
			},
		},
		{
			name: "in out override disabled rejects mark out",
			config: func(cfg *config.Config) {
				cfg.Director.RuntimeOverrides.Backends.AllowInOut = false
			},
			request: func(handler *Handler) (any, error) {
				return handler.MarkBackendOut(context.Background(), generated.MarkBackendOutRequestObject{
					Identifier: testBackendIdentifier,
					Body:       &generated.MarkBackendOutJSONRequestBody{Reason: "stop placement"},
				})
			},
		},
		{
			name: "in out override disabled rejects mark in",
			config: func(cfg *config.Config) {
				cfg.Director.RuntimeOverrides.Backends.AllowInOut = false
			},
			request: func(handler *Handler) (any, error) {
				return handler.MarkBackendIn(context.Background(), generated.MarkBackendInRequestObject{
					Identifier: testBackendIdentifier,
					Body:       &generated.MarkBackendInJSONRequestBody{Reason: "resume placement"},
				})
			},
		},
		{
			name: "drain override disabled rejects drain",
			config: func(cfg *config.Config) {
				cfg.Director.RuntimeOverrides.Backends.AllowDrain = false
			},
			request: func(handler *Handler) (any, error) {
				return handler.DrainBackend(context.Background(), generated.DrainBackendRequestObject{
					Identifier: testBackendIdentifier,
					Body: &generated.DrainBackendJSONRequestBody{
						Mode:   generated.DrainModeSoft,
						Reason: "host drain",
					},
				})
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			testCase.config(&cfg)
			mutator := &recordingBackendRuntimeMutator{}
			handler := NewHandler(HandlerOptions{
				Version:        testHandlerVersion,
				Snapshot:       &config.Snapshot{Config: cfg},
				BackendMutator: mutator,
			})

			response, err := testCase.request(handler)
			if err != nil {
				t.Fatalf("handler returned error: %v", err)
			}

			assertBackendRuntimeProblemStatus(t, response, http.StatusBadRequest)
			if mutator.calls != 0 {
				t.Fatalf("mutator calls = %d, want policy denial before mutation", mutator.calls)
			}
		})
	}
}

// TestUserRuntimeHandlersUseConfiguredOverridePolicy verifies REST user mutations honor typed config.
//
//nolint:funlen // The table keeps user REST policy denials in one matrix.
func TestUserRuntimeHandlersUseConfiguredOverridePolicy(t *testing.T) {
	testCases := []struct {
		name    string
		config  func(*config.Config)
		request func(*Handler) (any, error)
	}{
		{
			name: "global runtime overrides disabled rejects move",
			config: func(cfg *config.Config) {
				cfg.Director.RuntimeOverrides.Enabled = false
			},
			request: func(handler *Handler) (any, error) {
				return handler.MoveUser(context.Background(), generated.MoveUserRequestObject{
					UserKey: testBackendPinUserKey,
					Body: &generated.MoveUserJSONRequestBody{
						Reason:   "move user",
						Strategy: generated.NewSessionsOnly,
						ToShard:  testBackendPinShard,
					},
				})
			},
		},
		{
			name: "allow move disabled rejects move",
			config: func(cfg *config.Config) {
				cfg.Director.RuntimeOverrides.Users.AllowMove = false
			},
			request: func(handler *Handler) (any, error) {
				return handler.MoveUser(context.Background(), generated.MoveUserRequestObject{
					UserKey: testBackendPinUserKey,
					Body: &generated.MoveUserJSONRequestBody{
						Reason:   "move user",
						Strategy: generated.NewSessionsOnly,
						ToShard:  testBackendPinShard,
					},
				})
			},
		},
		{
			name: "move strategy allowlist rejects move",
			config: func(cfg *config.Config) {
				cfg.Director.RuntimeOverrides.Users.MoveStrategies = []string{"new_sessions_only"}
			},
			request: func(handler *Handler) (any, error) {
				return handler.MoveUser(context.Background(), generated.MoveUserRequestObject{
					UserKey: testBackendPinUserKey,
					Body: &generated.MoveUserJSONRequestBody{
						Reason:   "move user",
						Strategy: generated.KickExisting,
						ToShard:  testBackendPinShard,
					},
				})
			},
		},
		{
			name: "allow kick disabled rejects kick",
			config: func(cfg *config.Config) {
				cfg.Director.RuntimeOverrides.Users.AllowKick = false
			},
			request: func(handler *Handler) (any, error) {
				return handler.KickUser(context.Background(), generated.KickUserRequestObject{
					UserKey: testBackendPinUserKey,
					Body:    &generated.KickUserJSONRequestBody{Reason: "kick user"},
				})
			},
		},
		{
			name: "allow affinity clear disabled rejects clear",
			config: func(cfg *config.Config) {
				cfg.Director.RuntimeOverrides.Users.AllowAffinityClear = false
			},
			request: func(handler *Handler) (any, error) {
				return handler.ClearUserAffinity(context.Background(), generated.ClearUserAffinityRequestObject{
					UserKey: testBackendPinUserKey,
					Body:    &generated.ClearUserAffinityJSONRequestBody{Reason: "clear affinity"},
				})
			},
		},
		{
			name: "backend pin strategy allowlist rejects pin",
			config: func(cfg *config.Config) {
				cfg.Director.RuntimeOverrides.Users.MoveStrategies = []string{"new_sessions_only"}
			},
			request: func(handler *Handler) (any, error) {
				return handler.SetUserBackendPin(context.Background(), generated.SetUserBackendPinRequestObject{
					UserKey: testBackendPinUserKey,
					Body: &generated.SetUserBackendPinJSONRequestBody{
						Backend:  testBackendIdentifier,
						Reason:   testBackendPinReason,
						Strategy: generated.KickExisting,
					},
				})
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			testCase.config(&cfg)
			userMutator := &recordingUserRuntimeMutator{}
			pinMutator := &recordingUserBackendPinService{}
			handler := NewHandler(HandlerOptions{
				Version:               testHandlerVersion,
				Snapshot:              &config.Snapshot{Config: cfg},
				UserMutator:           userMutator,
				UserBackendPinMutator: pinMutator,
			})

			response, err := testCase.request(handler)
			if err != nil {
				t.Fatalf("handler returned error: %v", err)
			}

			assertUserRuntimeOverrideProblemStatus(t, response, http.StatusBadRequest)
			assertNoUserRuntimeAdapterMutation(t, userMutator, pinMutator)
		})
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
		listResult: runtime.UserBackendPinsReadResult{},
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

	if service.listRequest.Key != (runtime.UserKey{Tenant: defaultTenant, UserHash: testBackendPinUserHash}) {
		t.Fatalf("read key = %#v, want parsed default tenant key", service.listRequest.Key)
	}

	if pin.Present || pin.UserKey != testBackendPinUserHash || pin.Backend != nil || pin.Strategy != nil || len(pin.Pins) != 0 {
		t.Fatalf("absent pin DTO = %#v, want only present=false and user key", pin)
	}
}

// TestGetUserBackendPinMapsPresentDTO verifies one-pin read DTO mapping.
func TestGetUserBackendPinMapsPresentDTO(t *testing.T) {
	service := &recordingUserBackendPinService{
		listResult: runtime.UserBackendPinsReadResult{
			Pins: []runtime.UserBackendPin{{
				Present:            true,
				Key:                runtime.UserKey{Tenant: testBackendPinTenant, UserHash: testBackendPinUserHash},
				BackendIdentifier:  testPinnedBackend,
				Protocol:           testBackendPinProtocol,
				BackendPool:        testBackendPinPool,
				EffectiveShard:     testBackendPinShard,
				BackendNode:        testBackendNode,
				Strategy:           runtime.MoveStrategyKickExisting,
				Generation:         "42",
				ActiveSessionCount: 3,
			}},
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
	assertStringPtrValue(t, "backend node", pin.BackendNode, testBackendNode)
	assertStringPtrValue(t, "generation", pin.Generation, "42")
	assertBackendPinStrategy(t, pin.Strategy, generated.KickExisting)
	assertIntPtrValue(t, "active session count", pin.ActiveSessionCount, 3)

	if len(pin.Pins) != 1 {
		t.Fatalf("pins = %d, want one scoped entry", len(pin.Pins))
	}
	if entry := pin.Pins[0]; entry.Backend != testPinnedBackend || entry.BackendNode != testBackendNode || entry.Protocol != testBackendPinProtocol || entry.BackendPool != testBackendPinPool {
		t.Fatalf("pin entry = %#v, want scoped backend facts", entry)
	}
}

// TestGetUserBackendPinMapsAggregateDTO verifies multi-pin output is sorted and compatibility-free.
func TestGetUserBackendPinMapsAggregateDTO(t *testing.T) {
	service := &recordingUserBackendPinService{
		listResult: runtime.UserBackendPinsReadResult{
			Pins: []runtime.UserBackendPin{
				{
					Present:            true,
					Key:                runtime.UserKey{Tenant: testBackendPinTenant, UserHash: testBackendPinUserHash},
					BackendIdentifier:  "mailstore-a-sieve",
					Protocol:           "sieve",
					BackendPool:        "sieve-default",
					EffectiveShard:     testBackendPinShard,
					BackendNode:        testBackendNode,
					Strategy:           runtime.MoveStrategyNewSessionsOnly,
					Generation:         "sieve-gen",
					ActiveSessionCount: 1,
				},
				{
					Present:            true,
					Key:                runtime.UserKey{Tenant: testBackendPinTenant, UserHash: testBackendPinUserHash},
					BackendIdentifier:  testPinnedBackend,
					Protocol:           testBackendPinProtocol,
					BackendPool:        testBackendPinPool,
					EffectiveShard:     testBackendPinShard,
					BackendNode:        testBackendNode,
					Strategy:           runtime.MoveStrategyNewSessionsOnly,
					Generation:         "imap-gen",
					ActiveSessionCount: 2,
				},
			},
		},
	}
	handler := NewHandler(HandlerOptions{Version: testHandlerVersion, UserBackendPinReader: service})

	response, err := handler.GetUserBackendPin(context.Background(), generated.GetUserBackendPinRequestObject{UserKey: testBackendPinUserKey})
	if err != nil {
		t.Fatalf("GetUserBackendPin returned error: %v", err)
	}

	pin, ok := response.(generated.GetUserBackendPin200JSONResponse)
	if !ok {
		t.Fatalf("GetUserBackendPin response = %T, want 200 backend pin", response)
	}

	if !pin.Present || len(pin.Pins) != 2 {
		t.Fatalf("aggregate pin = %#v, want two scoped pins", pin)
	}
	if pin.Backend != nil || pin.Protocol != nil || pin.BackendPool != nil || pin.Strategy != nil {
		t.Fatalf("compatibility fields = %#v, want omitted for multi-pin response", pin)
	}
	if pin.Pins[0].Protocol != testBackendPinProtocol || pin.Pins[0].BackendPool != testBackendPinPool {
		t.Fatalf("pins = %#v, want sorted by protocol and backend pool", pin.Pins)
	}
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

	actor := runtime.Actor{ID: "operator-a", AuthMethod: "oidc", Authenticated: true}

	response, err := handler.SetUserBackendPin(runtime.WithActor(context.Background(), actor), generated.SetUserBackendPinRequestObject{
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
	if service.targetRequest.Key != wantKey ||
		service.targetRequest.BackendIdentifier != testPinnedBackend ||
		service.targetRequest.BackendNode != "" ||
		service.targetRequest.Strategy != runtime.MoveStrategyKickExisting ||
		service.targetRequest.Reason != testBackendPinReason ||
		service.targetRequest.Actor != actor {
		t.Fatalf("set request = %#v, want trimmed runtime request", service.targetRequest)
	}
}

// TestSetUserBackendPinMapsBackendNodeRequests verifies backend-node workflows cross only the REST adapter.
func TestSetUserBackendPinMapsBackendNodeRequests(t *testing.T) {
	testCases := []struct {
		name         string
		body         generated.SetUserBackendPinJSONRequestBody
		wantNode     string
		wantProtocol string
		wantPool     string
	}{
		{
			name: "all protocol node",
			body: generated.SetUserBackendPinJSONRequestBody{
				BackendNode: " " + testBackendNode + " ",
				Reason:      testBackendPinReason,
				Strategy:    generated.NewSessionsOnly,
			},
			wantNode: testBackendNode,
		},
		{
			name: "scoped node",
			body: generated.SetUserBackendPinJSONRequestBody{
				BackendNode: " " + testBackendNode + " ",
				Protocol:    " IMAP ",
				BackendPool: " " + testBackendPinPool + " ",
				Reason:      testBackendPinReason,
				Strategy:    generated.NewSessionsOnly,
			},
			wantNode:     testBackendNode,
			wantProtocol: testBackendPinProtocol,
			wantPool:     testBackendPinPool,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			service := &recordingUserBackendPinService{}
			handler := NewHandler(HandlerOptions{Version: testHandlerVersion, UserBackendPinMutator: service})

			response, err := handler.SetUserBackendPin(context.Background(), generated.SetUserBackendPinRequestObject{
				UserKey: testBackendPinUserHash,
				Body:    &testCase.body,
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
			if service.targetRequest.BackendIdentifier != "" ||
				service.targetRequest.BackendNode != testCase.wantNode ||
				service.targetRequest.Protocol != testCase.wantProtocol ||
				service.targetRequest.BackendPool != testCase.wantPool {
				t.Fatalf("target request = %#v, want backend-node mapping", service.targetRequest)
			}
		})
	}
}

// TestClearUserBackendPinRequiresReasonAndCallsRuntime verifies all-clear validation and mutation flow.
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

	if service.clearAllCalls != 1 {
		t.Fatalf("clear-all calls = %d, want 1", service.clearAllCalls)
	}

	if service.clearAllRequest.Key != (runtime.UserKey{Tenant: defaultTenant, UserHash: testBackendPinUserHash}) ||
		service.clearAllRequest.Reason != testBackendPinReason {
		t.Fatalf("clear request = %#v, want parsed key and trimmed reason", service.clearAllRequest)
	}
}

// TestClearUserBackendPinMapsScopedRequest verifies scoped clear stays explicit.
func TestClearUserBackendPinMapsScopedRequest(t *testing.T) {
	service := &recordingUserBackendPinService{}
	handler := NewHandler(HandlerOptions{Version: testHandlerVersion, UserBackendPinMutator: service})

	body := generated.ClearUserBackendPinJSONRequestBody{
		Protocol:    " IMAP ",
		BackendPool: " " + testBackendPinPool + " ",
		Reason:      " " + testBackendPinReason + " ",
	}

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

	if service.clearCalls != 1 || service.clearAllCalls != 0 {
		t.Fatalf("clear calls scoped=%d all=%d, want one scoped clear", service.clearCalls, service.clearAllCalls)
	}
	if service.clearRequest.Protocol != testBackendPinProtocol ||
		service.clearRequest.BackendPool != testBackendPinPool ||
		service.clearRequest.Reason != testBackendPinReason {
		t.Fatalf("scoped clear request = %#v, want trimmed scope and reason", service.clearRequest)
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

	setBothTargets := generated.SetUserBackendPinJSONRequestBody{
		Backend:     testPinnedBackend,
		BackendNode: testBackendNode,
		Reason:      testBackendPinReason,
		Strategy:    generated.NewSessionsOnly,
	}
	setBothResponse, err := handler.SetUserBackendPin(context.Background(), generated.SetUserBackendPinRequestObject{
		UserKey: testBackendPinUserHash,
		Body:    &setBothTargets,
	})
	if err != nil {
		t.Fatalf("SetUserBackendPin both targets returned error: %v", err)
	}

	assertBackendPinProblemStatus(t, setBothResponse, http.StatusBadRequest)

	clearMissing, err := handler.ClearUserBackendPin(context.Background(), generated.ClearUserBackendPinRequestObject{UserKey: testBackendPinUserHash})
	if err != nil {
		t.Fatalf("ClearUserBackendPin missing body returned error: %v", err)
	}

	assertBackendPinProblemStatus(t, clearMissing, http.StatusBadRequest)

	clearIncompleteScope := generated.ClearUserBackendPinJSONRequestBody{Protocol: testBackendPinProtocol, Reason: testBackendPinReason}
	clearIncompleteResponse, err := handler.ClearUserBackendPin(context.Background(), generated.ClearUserBackendPinRequestObject{
		UserKey: testBackendPinUserHash,
		Body:    &clearIncompleteScope,
	})
	if err != nil {
		t.Fatalf("ClearUserBackendPin incomplete scope returned error: %v", err)
	}

	assertBackendPinProblemStatus(t, clearIncompleteResponse, http.StatusBadRequest)
}

// TestBackendPinRuntimeErrorsMapToStableStatuses verifies generated problems remain deterministic.
func TestBackendPinRuntimeErrorsMapToStableStatuses(t *testing.T) {
	testCases := []struct {
		name   string
		err    error
		status int
	}{
		{
			name:   "malformed request",
			err:    &runtime.Error{Kind: runtime.ErrorKindInvalidRequest, Operation: testBackendPinOperation, Message: "bad request"},
			status: http.StatusBadRequest,
		},
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
			service := &recordingUserBackendPinService{targetErr: testCase.err}
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

// TestDeleteSessionRejectsMissingReason verifies bad kill requests stay at the REST boundary.
func TestDeleteSessionRejectsMissingReason(t *testing.T) {
	mutator := &recordingSessionMutator{}
	handler := NewHandler(HandlerOptions{
		Version:        testHandlerVersion,
		SessionMutator: mutator,
	})

	response, err := handler.DeleteSession(context.Background(), generated.DeleteSessionRequestObject{
		SessionID: testSessionKillID,
		Body:      &generated.DeleteSessionJSONRequestBody{Reason: "  "},
	})
	if err != nil {
		t.Fatalf("DeleteSession returned error: %v", err)
	}

	problem, ok := response.(generated.DeleteSessiondefaultJSONResponse)
	if !ok {
		t.Fatalf("DeleteSession response = %T, want problem", response)
	}

	if problem.StatusCode != http.StatusBadRequest {
		t.Fatalf("DeleteSession status = %d, want 400", problem.StatusCode)
	}

	if mutator.calls != 0 {
		t.Fatalf("session mutator calls = %d, want 0 for invalid request", mutator.calls)
	}
}

// TestDeleteSessionMapsMarkedOutcome verifies accepted session kill DTO mapping.
//
//nolint:gocyclo // The test keeps the generated response mapping assertions in one public-contract proof.
func TestDeleteSessionMapsMarkedOutcome(t *testing.T) {
	mutator := &recordingSessionMutator{result: sessionKillMutationResult(runtime.SessionMutationOutcomeMarked)}
	handler := NewHandler(HandlerOptions{
		Version:        testHandlerVersion,
		SessionMutator: mutator,
	})

	response, err := handler.DeleteSession(context.Background(), generated.DeleteSessionRequestObject{
		SessionID: testSessionKillID,
		Body:      &generated.DeleteSessionJSONRequestBody{Reason: " " + testSessionKillReason + " "},
	})
	if err != nil {
		t.Fatalf("DeleteSession returned error: %v", err)
	}

	accepted, ok := response.(generated.DeleteSession202JSONResponse)
	if !ok {
		t.Fatalf("DeleteSession response = %T, want 202 session kill", response)
	}

	body := generated.SessionKillResponse(accepted)
	if body.Outcome != generated.SessionKillOutcome(runtime.SessionMutationOutcomeMarked) ||
		body.SessionID != testSessionKillID ||
		body.Lifecycle != generated.SessionKillLifecycle(runtime.SessionMutationLifecycleLocalOrHeartbeatClose) ||
		body.StaleIndexRepaired {
		t.Fatalf("session kill body = %#v, want marked outcome", body)
	}

	if body.ControlAction == nil || *body.ControlAction != generated.SessionKillControlAction(runtime.SessionMutationControlActionKick) {
		t.Fatalf("control action = %#v, want kick", body.ControlAction)
	}

	if body.ControlGeneration == nil || *body.ControlGeneration != "7" {
		t.Fatalf("control generation = %#v, want 7", body.ControlGeneration)
	}

	if mutator.calls != 1 || mutator.request.SessionID != testSessionKillID || mutator.request.Reason != testSessionKillReason {
		t.Fatalf("mutator request = %#v after %d calls, want trimmed kill request", mutator.request, mutator.calls)
	}
}

// TestDeleteSessionMapsMissingAndStaleOutcomes verifies bounded 404 kill evidence.
func TestDeleteSessionMapsMissingAndStaleOutcomes(t *testing.T) {
	testCases := []struct {
		name      string
		outcome   runtime.SessionMutationOutcome
		lifecycle runtime.SessionMutationLifecycle
		stale     bool
	}{
		{
			name:      "missing",
			outcome:   runtime.SessionMutationOutcomeMissing,
			lifecycle: runtime.SessionMutationLifecycleAlreadyAbsent,
			stale:     false,
		},
		{
			name:      "stale repaired",
			outcome:   runtime.SessionMutationOutcomeStaleIndexRepaired,
			lifecycle: runtime.SessionMutationLifecycleStaleLocatorRepaired,
			stale:     true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			mutator := &recordingSessionMutator{result: sessionKillMutationResult(testCase.outcome)}
			handler := NewHandler(HandlerOptions{
				Version:        testHandlerVersion,
				SessionMutator: mutator,
			})

			response, err := handler.DeleteSession(context.Background(), generated.DeleteSessionRequestObject{
				SessionID: testSessionKillID,
				Body:      &generated.DeleteSessionJSONRequestBody{Reason: testSessionKillReason},
			})
			if err != nil {
				t.Fatalf("DeleteSession returned error: %v", err)
			}

			missing, ok := response.(generated.DeleteSession404JSONResponse)
			if !ok {
				t.Fatalf("DeleteSession response = %T, want 404 session kill", response)
			}

			body := generated.SessionKillResponse(missing)
			if body.Outcome != generated.SessionKillOutcome(testCase.outcome) ||
				body.SessionID != testSessionKillID ||
				body.Lifecycle != generated.SessionKillLifecycle(testCase.lifecycle) ||
				body.StaleIndexRepaired != testCase.stale {
				t.Fatalf("session kill body = %#v, want %s/%s stale=%t", body, testCase.outcome, testCase.lifecycle, testCase.stale)
			}

			if body.ControlAction != nil || body.ControlGeneration != nil {
				t.Fatalf("missing/stale body included control mark: %#v", body)
			}
		})
	}
}

// TestDeleteSessionRuntimeFailureFailsClosed verifies ambiguous runtime errors map to 503.
func TestDeleteSessionRuntimeFailureFailsClosed(t *testing.T) {
	mutator := &recordingSessionMutator{
		err: newRuntimeError(runtime.ErrorKindUnavailable, "session_kill", "ambiguous session state"),
	}
	handler := NewHandler(HandlerOptions{
		Version:        testHandlerVersion,
		SessionMutator: mutator,
	})

	response, err := handler.DeleteSession(context.Background(), generated.DeleteSessionRequestObject{
		SessionID: testSessionKillID,
		Body:      &generated.DeleteSessionJSONRequestBody{Reason: testSessionKillReason},
	})
	if err != nil {
		t.Fatalf("DeleteSession returned error: %v", err)
	}

	problem, ok := response.(generated.DeleteSessiondefaultJSONResponse)
	if !ok {
		t.Fatalf("DeleteSession response = %T, want fail-closed problem", response)
	}

	if problem.StatusCode != http.StatusServiceUnavailable ||
		problem.Body.Code != string(runtime.ErrorKindUnavailable) ||
		!strings.Contains(problem.Body.Message, "ambiguous session state") {
		t.Fatalf("problem = %#v, want fail-closed 503 ambiguous state", problem)
	}
}

// TestRuntimeReapHandlerMapsRequest verifies generated reap DTOs stop at the REST adapter.
//
//nolint:gocyclo // The test keeps generated request and response mapping in one contract proof.
func TestRuntimeReapHandlerMapsRequest(t *testing.T) {
	dryRun := true
	mutator := &recordingSessionMutator{
		reapResult: runtime.ReapSessionsResult{
			Status:                  "preview",
			ScannedSessions:         25,
			ExpiredSessions:         7,
			StaleIndexEntries:       2,
			RepairedBackends:        3,
			AggregateMarkersRemoved: 7,
			IdleAffinitiesAdded:     4,
			ServerTime:              time.Unix(100, 0),
		},
	}
	handler := NewHandler(HandlerOptions{
		Version:        testHandlerVersion,
		SessionMutator: mutator,
	})

	response, err := handler.ReapRuntime(context.Background(), generated.ReapRuntimeRequestObject{
		Body: &generated.ReapRuntimeJSONRequestBody{
			DryRun:          &dryRun,
			Limit:           25,
			MaxPassDuration: "5s",
			Reason:          "repair stale leases",
		},
	})
	if err != nil {
		t.Fatalf("ReapRuntime returned error: %v", err)
	}

	okResponse, ok := response.(generated.ReapRuntime200JSONResponse)
	if !ok {
		t.Fatalf("ReapRuntime response = %T, want 200", response)
	}

	body := generated.RuntimeReapResponse(okResponse)
	if body.Status != generated.RuntimeReapResponseStatusPreview ||
		body.ScannedSessions != 25 ||
		body.ExpiredSessions != 7 ||
		body.StaleIndexEntries != 2 ||
		body.RepairedBackends != 3 ||
		body.AggregateMarkersRemoved != 7 ||
		body.IdleAffinitiesAdded != 4 {
		t.Fatalf("reap body = %#v, want preview counts", body)
	}

	if mutator.reapCalls != 1 ||
		mutator.reapRequest.Reason != "repair stale leases" ||
		mutator.reapRequest.Limit != 25 ||
		mutator.reapRequest.MaxPassDuration != 5*time.Second ||
		!mutator.reapRequest.DryRun {
		t.Fatalf("reap request = %#v after %d calls, want generated-boundary mapping", mutator.reapRequest, mutator.reapCalls)
	}
}

// TestAggregateReconcileHandlerMapsRequest verifies aggregate repair uses the runtime domain service.
//
//nolint:gocyclo // The test keeps generated aggregate repair mapping in one contract proof.
func TestAggregateReconcileHandlerMapsRequest(t *testing.T) {
	dryRun := true
	reconciler := &recordingRuntimeAggregateReconciler{
		result: runtime.RuntimeAggregateReconcileResult{
			Status:                 "preview",
			Scope:                  runtime.RuntimeAggregateReconcileScopeActiveSessions,
			ScannedMarkers:         1000,
			StaleMarkersRemoved:    2,
			MarkersUpserted:        1,
			CounterFieldsChanged:   4,
			CounterFieldsRemoved:   1,
			AuthoritativeConflicts: 0,
			ServerTime:             time.Unix(200, 0),
		},
	}
	handler := NewHandler(HandlerOptions{
		Version:                    testHandlerVersion,
		RuntimeAggregateReconciler: reconciler,
	})

	response, err := handler.ReconcileRuntimeAggregates(context.Background(), generated.ReconcileRuntimeAggregatesRequestObject{
		Body: &generated.ReconcileRuntimeAggregatesJSONRequestBody{
			DryRun:          &dryRun,
			Limit:           1000,
			MaxPassDuration: "5s",
			Reason:          "repair aggregate drift",
			Scope:           generated.ActiveSessions,
		},
	})
	if err != nil {
		t.Fatalf("ReconcileRuntimeAggregates returned error: %v", err)
	}

	okResponse, ok := response.(generated.ReconcileRuntimeAggregates200JSONResponse)
	if !ok {
		t.Fatalf("ReconcileRuntimeAggregates response = %T, want 200", response)
	}

	body := generated.RuntimeAggregateReconcileResponse(okResponse)
	if body.Status != generated.RuntimeAggregateReconcileResponseStatusPreview ||
		body.ScannedMarkers != 1000 ||
		body.StaleMarkersRemoved != 2 ||
		body.MarkersUpserted != 1 ||
		body.CounterFieldsChanged != 4 ||
		body.CounterFieldsRemoved != 1 ||
		body.AuthoritativeConflicts != 0 {
		t.Fatalf("aggregate reconcile body = %#v, want preview counts", body)
	}

	if reconciler.calls != 1 ||
		reconciler.request.Reason != "repair aggregate drift" ||
		reconciler.request.Limit != 1000 ||
		reconciler.request.MaxPassDuration != 5*time.Second ||
		reconciler.request.Scope != runtime.RuntimeAggregateReconcileScopeActiveSessions ||
		!reconciler.request.DryRun {
		t.Fatalf("aggregate reconcile request = %#v after %d calls, want runtime-domain mapping", reconciler.request, reconciler.calls)
	}
}

// TestAggregateReconcileHandlerFailsClosed verifies authoritative ambiguity stays unavailable.
func TestAggregateReconcileHandlerFailsClosed(t *testing.T) {
	reconciler := &recordingRuntimeAggregateReconciler{
		err: newRuntimeError(runtime.ErrorKindUnavailable, "runtime_aggregate_reconcile", "authoritative conflict"),
	}
	handler := NewHandler(HandlerOptions{
		Version:                    testHandlerVersion,
		RuntimeAggregateReconciler: reconciler,
	})

	response, err := handler.ReconcileRuntimeAggregates(context.Background(), generated.ReconcileRuntimeAggregatesRequestObject{
		Body: &generated.ReconcileRuntimeAggregatesJSONRequestBody{
			Limit:           10,
			MaxPassDuration: "5s",
			Reason:          "repair aggregate drift",
			Scope:           generated.ActiveSessions,
		},
	})
	if err != nil {
		t.Fatalf("ReconcileRuntimeAggregates returned error: %v", err)
	}

	problem, ok := response.(generated.ReconcileRuntimeAggregatesdefaultJSONResponse)
	if !ok {
		t.Fatalf("ReconcileRuntimeAggregates response = %T, want problem", response)
	}

	if problem.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", problem.StatusCode)
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

// TestListBackendsMapsSafeTransportReadback verifies generated backend DTOs expose only safe transport state.
func TestListBackendsMapsSafeTransportReadback(t *testing.T) {
	reader := &recordingBackendReader{states: []backend.EffectiveBackendState{
		{
			Backend: backend.Backend{
				BackendNode: testBackendNode,
				HAProxy:     backend.HAProxyConfig{Enabled: true},
			},
			Identifier:           testBackendIdentifier,
			Protocol:             "imap",
			BackendPool:          testBackendPinPool,
			EffectiveShardTag:    testBackendPinShard,
			EffectiveWeight:      100,
			RuntimeInService:     true,
			EffectiveMaintenance: backend.MaintenanceModeDisabled,
		},
	}}
	handler := NewHandler(HandlerOptions{Version: testHandlerVersion, BackendReader: reader})

	response, err := handler.ListBackends(context.Background(), generated.ListBackendsRequestObject{})
	if err != nil {
		t.Fatalf("ListBackends returned error: %v", err)
	}

	list, ok := response.(generated.ListBackends200JSONResponse)
	if !ok {
		t.Fatalf("ListBackends response = %T, want list", response)
	}

	if len(list.Backends) != 1 {
		t.Fatalf("backends = %d, want 1", len(list.Backends))
	}

	detail := list.Backends[0]
	if detail.BackendNode != testBackendNode || !detail.OutboundProxyProtocol {
		t.Fatalf("backend transport read-back = %#v, want backend node and enabled PROXY", detail)
	}

	if detail.Identifier != testBackendIdentifier || detail.BackendPool != testBackendPinPool || detail.ShardTag != testBackendPinShard {
		t.Fatalf("backend identity = %#v, want stable safe fields", detail)
	}

	assertBackendDTOSecretSafe(t, detail)
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
			BackendNode:    testBackendNode,
			EffectiveShard: testBackendPinShard,
			Applied:        true,
			ReasonClass:    testBackendPinApplied,
			ScopeCount:     2,
			OtherScopes: []runtime.RouteLookupBackendPinScope{
				{Protocol: "lmtp", BackendPool: "lmtp-default"},
			},
		},
		SelectedBackend: "mailstore-a-imap",
		ReasonClass:     "initial_placement",
	}, nil
}

// recordingUserBackendPinService captures backend-pin runtime requests.
type recordingUserBackendPinService struct {
	readCalls       int
	listRequest     runtime.ListUserBackendPinsRequest
	listResult      runtime.UserBackendPinsReadResult
	readErr         error
	setCalls        int
	targetRequest   runtime.SetUserBackendPinTargetRequest
	targetResult    runtime.UserBackendPinsMutationResult
	targetErr       error
	clearCalls      int
	clearRequest    runtime.ClearUserBackendPinRequest
	clearResult     runtime.UserBackendPinMutationResult
	clearErr        error
	clearAllCalls   int
	clearAllRequest runtime.ClearUserBackendPinsRequest
	clearAllResult  runtime.UserBackendPinsMutationResult
	clearAllErr     error
}

// ListUserBackendPins records one aggregate backend-pin read request.
func (r *recordingUserBackendPinService) ListUserBackendPins(_ context.Context, request runtime.ListUserBackendPinsRequest) (runtime.UserBackendPinsReadResult, error) {
	r.readCalls++

	r.listRequest = request
	if r.readErr != nil {
		return runtime.UserBackendPinsReadResult{}, r.readErr
	}

	return r.listResult, nil
}

// SetUserBackendPinTarget validates policy and records one backend or backend-node set request.
func (r *recordingUserBackendPinService) SetUserBackendPinTarget(
	_ context.Context,
	request runtime.SetUserBackendPinTargetRequest,
	policy runtime.UserRuntimeOverridePolicy,
) (runtime.UserBackendPinsMutationResult, error) {
	if err := request.Validate(policy); err != nil {
		return runtime.UserBackendPinsMutationResult{}, err
	}

	r.setCalls++
	r.targetRequest = request
	if r.targetErr != nil {
		return runtime.UserBackendPinsMutationResult{}, r.targetErr
	}

	return r.targetResult, nil
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

// ClearUserBackendPins records one all-scope backend-pin clear request.
func (r *recordingUserBackendPinService) ClearUserBackendPins(_ context.Context, request runtime.ClearUserBackendPinsRequest) (runtime.UserBackendPinsMutationResult, error) {
	r.clearAllCalls++

	r.clearAllRequest = request
	if r.clearAllErr != nil {
		return runtime.UserBackendPinsMutationResult{}, r.clearAllErr
	}

	return r.clearAllResult, nil
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

// assertBackendRuntimeProblemStatus checks backend-runtime generated problem responses.
//
//nolint:dupl // Generated response unions require parallel type switches.
func assertBackendRuntimeProblemStatus(t *testing.T, response any, want int) {
	t.Helper()

	var got int

	switch typed := response.(type) {
	case generated.SetBackendWeightdefaultJSONResponse:
		got = typed.StatusCode
	case generated.MarkBackendIndefaultJSONResponse:
		got = typed.StatusCode
	case generated.MarkBackendOutdefaultJSONResponse:
		got = typed.StatusCode
	case generated.DrainBackenddefaultJSONResponse:
		got = typed.StatusCode
	default:
		t.Fatalf("response = %T, want backend-runtime problem", response)
	}

	if got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
}

// assertUserRuntimeOverrideProblemStatus checks user-runtime generated problem responses.
//
//nolint:dupl // Generated response unions require parallel type switches.
func assertUserRuntimeOverrideProblemStatus(t *testing.T, response any, want int) {
	t.Helper()

	var got int

	switch typed := response.(type) {
	case generated.MoveUserdefaultJSONResponse:
		got = typed.StatusCode
	case generated.KickUserdefaultJSONResponse:
		got = typed.StatusCode
	case generated.ClearUserAffinitydefaultJSONResponse:
		got = typed.StatusCode
	case generated.SetUserBackendPindefaultJSONResponse:
		got = typed.StatusCode
	default:
		t.Fatalf("response = %T, want user-runtime override problem", response)
	}

	if got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
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

// assertNoUserRuntimeAdapterMutation verifies policy rejection happened before fake persistence.
func assertNoUserRuntimeAdapterMutation(t *testing.T, user *recordingUserRuntimeMutator, pins *recordingUserBackendPinService) {
	t.Helper()

	if user.moveCalls != 0 || user.kickCalls != 0 || user.clearCalls != 0 {
		t.Fatalf("unexpected user runtime calls: %#v", user)
	}

	if pins.setCalls != 0 || pins.clearCalls != 0 || pins.clearAllCalls != 0 {
		t.Fatalf("unexpected backend-pin calls: %#v", pins)
	}
}

// recordingUserRuntimeMutator validates user policy and records accepted mutations.
type recordingUserRuntimeMutator struct {
	moveCalls  int
	kickCalls  int
	clearCalls int
}

// MoveUser validates move policy and records accepted user moves.
func (r *recordingUserRuntimeMutator) MoveUser(
	_ context.Context,
	request runtime.MoveUserRequest,
	policy runtime.UserRuntimeOverridePolicy,
) (runtime.UserMutationResult, error) {
	if err := request.Validate(policy); err != nil {
		return runtime.UserMutationResult{}, err
	}

	r.moveCalls++

	return runtime.UserMutationResult{}, nil
}

// KickUser validates kick policy and records accepted user kicks.
func (r *recordingUserRuntimeMutator) KickUser(
	_ context.Context,
	request runtime.KickUserRequest,
	policy runtime.UserRuntimeOverridePolicy,
) (runtime.UserMutationResult, error) {
	if err := request.Validate(policy); err != nil {
		return runtime.UserMutationResult{}, err
	}

	r.kickCalls++

	return runtime.UserMutationResult{}, nil
}

// ClearUserAffinity validates clear policy and records accepted affinity clears.
func (r *recordingUserRuntimeMutator) ClearUserAffinity(
	_ context.Context,
	request runtime.ClearUserAffinityRequest,
	policy runtime.UserRuntimeOverridePolicy,
) (runtime.UserMutationResult, error) {
	if err := request.Validate(policy); err != nil {
		return runtime.UserMutationResult{}, err
	}

	r.clearCalls++

	return runtime.UserMutationResult{}, nil
}

// recordingBackendRuntimeMutator validates backend policy and records accepted mutations.
type recordingBackendRuntimeMutator struct {
	calls int
}

// SetInService validates in/out policy and records accepted in/out mutations.
func (r *recordingBackendRuntimeMutator) SetInService(
	_ context.Context,
	request runtime.SetBackendInServiceRequest,
	policy backend.RuntimeOverridePolicy,
) (runtime.BackendMutationResult, error) {
	if err := request.Validate(policy); err != nil {
		return runtime.BackendMutationResult{}, err
	}

	r.calls++

	return runtime.BackendMutationResult{}, nil
}

// SetWeight validates weight policy and records accepted weight mutations.
func (r *recordingBackendRuntimeMutator) SetWeight(
	_ context.Context,
	request runtime.SetBackendWeightRequest,
	policy backend.RuntimeOverridePolicy,
) (runtime.BackendMutationResult, error) {
	if err := request.Validate(policy); err != nil {
		return runtime.BackendMutationResult{}, err
	}

	r.calls++

	return runtime.BackendMutationResult{}, nil
}

// SetMaintenance records accepted maintenance mutations.
func (r *recordingBackendRuntimeMutator) SetMaintenance(
	context.Context,
	runtime.SetBackendMaintenanceRequest,
) (runtime.BackendMutationResult, error) {
	r.calls++

	return runtime.BackendMutationResult{}, nil
}

// StartDrain validates drain policy and records accepted drain mutations.
func (r *recordingBackendRuntimeMutator) StartDrain(
	_ context.Context,
	request runtime.StartBackendDrainRequest,
	policy backend.RuntimeOverridePolicy,
) (runtime.BackendMutationResult, error) {
	if err := request.Validate(policy); err != nil {
		return runtime.BackendMutationResult{}, err
	}

	r.calls++

	return runtime.BackendMutationResult{}, nil
}

// ClearRuntime records accepted backend runtime clear mutations.
func (r *recordingBackendRuntimeMutator) ClearRuntime(
	context.Context,
	runtime.ClearBackendRuntimeRequest,
) (runtime.BackendMutationResult, error) {
	r.calls++

	return runtime.BackendMutationResult{}, nil
}

// recordingBackendReader returns stable backend details for REST adapter tests.
type recordingBackendReader struct {
	states []backend.EffectiveBackendState
}

// ListBackends returns the configured effective backend states.
func (r *recordingBackendReader) ListBackends(context.Context) ([]backend.EffectiveBackendState, error) {
	return append([]backend.EffectiveBackendState(nil), r.states...), nil
}

// GetBackend returns the first configured effective backend state.
func (r *recordingBackendReader) GetBackend(context.Context, string) (backend.EffectiveBackendState, error) {
	if len(r.states) == 0 {
		return backend.EffectiveBackendState{}, errors.New("backend not found")
	}

	return r.states[0], nil
}

// recordingSessionMutator captures one generated-boundary session mutation.
type recordingSessionMutator struct {
	calls       int
	request     runtime.KillSessionRequest
	result      runtime.SessionMutationResult
	err         error
	reapCalls   int
	reapRequest runtime.ReapSessionsRequest
	reapResult  runtime.ReapSessionsResult
	reapErr     error
}

// KillSession records the domain request and returns the configured outcome.
func (r *recordingSessionMutator) KillSession(_ context.Context, request runtime.KillSessionRequest) (runtime.SessionMutationResult, error) {
	r.calls++
	r.request = request
	if r.err != nil {
		return runtime.SessionMutationResult{}, r.err
	}

	return r.result, nil
}

// ReapSessions records the domain reap request and returns the configured outcome.
func (r *recordingSessionMutator) ReapSessions(_ context.Context, request runtime.ReapSessionsRequest) (runtime.ReapSessionsResult, error) {
	r.reapCalls++
	r.reapRequest = request
	if r.reapErr != nil {
		return runtime.ReapSessionsResult{}, r.reapErr
	}

	return r.reapResult, nil
}

// recordingRuntimeAggregateReconciler captures one generated-boundary aggregate repair request.
type recordingRuntimeAggregateReconciler struct {
	calls   int
	request runtime.RuntimeAggregateReconcileRequest
	result  runtime.RuntimeAggregateReconcileResult
	err     error
}

// ReconcileRuntimeAggregates records the domain request and returns the configured outcome.
func (r *recordingRuntimeAggregateReconciler) ReconcileRuntimeAggregates(
	_ context.Context,
	request runtime.RuntimeAggregateReconcileRequest,
) (runtime.RuntimeAggregateReconcileResult, error) {
	r.calls++
	r.request = request
	if r.err != nil {
		return runtime.RuntimeAggregateReconcileResult{}, r.err
	}

	return r.result, nil
}

// sessionKillMutationResult builds one bounded runtime kill result for REST tests.
func sessionKillMutationResult(outcome runtime.SessionMutationOutcome) runtime.SessionMutationResult {
	result := runtime.SessionMutationResult{
		State: runtime.SessionRuntimeState{
			SessionID: testSessionKillID,
			Status:    runtime.SessionStatusExpired,
		},
		Outcome:       outcome,
		ControlAction: runtime.SessionMutationControlActionNone,
	}

	switch outcome {
	case runtime.SessionMutationOutcomeMarked:
		result.State.ControlGeneration = "7"
		result.State.Status = runtime.SessionStatusClosing
		result.ControlAction = runtime.SessionMutationControlActionKick
		result.Lifecycle = runtime.SessionMutationLifecycleLocalOrHeartbeatClose
	case runtime.SessionMutationOutcomeMissing:
		result.Lifecycle = runtime.SessionMutationLifecycleAlreadyAbsent
	case runtime.SessionMutationOutcomeStaleIndexRepaired:
		result.Lifecycle = runtime.SessionMutationLifecycleStaleLocatorRepaired
		result.StaleIndexRepaired = true
	default:
		result.Lifecycle = runtime.SessionMutationLifecycleFailClosedAmbiguous
	}

	return result
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

// assertBackendDTOSecretSafe rejects fields outside the public backend contract.
func assertBackendDTOSecretSafe(t *testing.T, detail generated.BackendDetail) {
	t.Helper()

	payload, err := json.Marshal(detail)
	if err != nil {
		t.Fatalf("marshal backend DTO: %v", err)
	}

	rendered := string(payload)
	for _, forbidden := range []string{"address", testUsernameField, testRecipientField, testSessionIDField, testSecretField, testPrivateKeyField, "password", "token"} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("backend DTO exposed forbidden field %q in %s", forbidden, rendered)
		}
	}
}

// assertListenerDTOSecretSafe rejects fields outside the public listener contract.
func assertListenerDTOSecretSafe(t *testing.T, detail generated.ListenerDetail) {
	t.Helper()

	payload, err := json.Marshal(detail)
	if err != nil {
		t.Fatalf("marshal listener DTO: %v", err)
	}

	rendered := string(payload)
	for _, forbidden := range []string{"peer", testUsernameField, testRecipientField, testSessionIDField, testSecretField, testPrivateKeyField} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("listener DTO exposed forbidden field %q in %s", forbidden, rendered)
		}
	}
}

var _ ListenerRuntimeService = (*recordingListenerRuntime)(nil)
var _ runtime.ListenerManager = (*adapterListenerManager)(nil)
