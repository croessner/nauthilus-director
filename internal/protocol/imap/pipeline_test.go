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

//nolint:funlen,goconst,wsl_v5 // Pipeline tests keep IMAP transcripts and fake call assertions together.
package imap

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/proxy"
	"github.com/croessner/nauthilus-director/internal/routing"
	runtimectl "github.com/croessner/nauthilus-director/internal/runtime"
	"github.com/croessner/nauthilus-director/internal/state"
)

// TestIMAPHTTPAuthBodyUsesProtocolAndClientID verifies IMAP auth reaches the HTTP authority safely.
func TestIMAPHTTPAuthBodyUsesProtocolAndClientID(t *testing.T) {
	var captured map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/auth/json" {
			t.Fatalf("path = %q, want /api/v1/auth/json", request.URL.Path)
		}

		if got := request.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("content type = %q, want application/json", got)
		}

		if err := json.NewDecoder(request.Body).Decode(&captured); err != nil {
			t.Fatalf("decode auth body: %v", err)
		}

		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"ok":true,"account_field":"account","attributes":{"account":["alice@example.test"],"tenant":["` + defaultTenantName + `"],"mailShard":["mailstore-a"]}}`))
	}))
	defer server.Close()

	authenticator, err := nauthilus.NewHTTPClient(nauthilus.HTTPClientConfig{
		Endpoint:    server.URL + "/api/v1/auth/json",
		ContentType: "application/json",
	})
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}

	store := &recordingSessionStore{result: state.AffinityRecord{ShardTag: "mailstore-a"}}
	selector := &recordingBackendSelector{result: backend.SelectionResult{Backend: backend.Backend{Identifier: "mailstore-a-imap"}}}
	harness := startTestSession(t, pipelineSessionConfig(authenticator, mustPipelineChain(t), store, selector))
	harness.expectLine(t, greetingLine)

	harness.write(t, `A001 ID ("client_id" "director-test-client")`+"\r\n")
	harness.expectLine(t, "* ID NIL\r\n")
	harness.expectLine(t, "A001 OK ID completed\r\n")
	harness.write(t, `A002 LOGIN "alice@example.test" "secret-password"`+"\r\n")
	harness.expectLine(t, "A002 OK Authentication completed\r\n")

	assertHTTPBodyField(t, captured, "protocol", "imap")
	assertHTTPBodyField(t, captured, "client_id", "director-test-client")
	assertHTTPForbiddenFieldsAbsent(t, captured)
}

// TestRejectedAuthMapsAuthorityMessage verifies rejected auth keeps authority text with IMAP framing.
func TestRejectedAuthMapsAuthorityMessage(t *testing.T) {
	testCases := []struct {
		name    string
		message string
		want    string
	}{
		{
			name:    "authority message",
			message: "Account disabled",
			want:    "A001 NO [AUTHENTICATIONFAILED] Account disabled\r\n",
		},
		{
			name: "empty fallback",
			want: "A001 NO [AUTHENTICATIONFAILED] Authentication failed\r\n",
		},
		{
			name:    "control hygiene",
			message: "Bad\r\nA999 OK injected\x00done",
			want:    "A001 NO [AUTHENTICATIONFAILED] Bad A999 OK injected done\r\n",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			authenticator := &recordingAuthenticator{
				result: nauthilus.AuthResult{
					Decision:      nauthilus.DecisionRejected,
					StatusMessage: testCase.message,
				},
			}
			router := &recordingRoutingResolver{}
			store := &recordingSessionStore{}
			selector := &recordingBackendSelector{}
			harness := startTestSession(t, pipelineSessionConfig(authenticator, router, store, selector))

			harness.expectLine(t, greetingLine)
			harness.write(t, `A001 LOGIN "alice@example.test" "secret-password"`+"\r\n")
			harness.expectLine(t, testCase.want)

			assertNoPlacementCalls(t, router, store, selector)
		})
	}
}

// TestRejectedAuthResponseLengthIsBounded verifies authority text cannot create oversized lines.
func TestRejectedAuthResponseLengthIsBounded(t *testing.T) {
	authenticator := &recordingAuthenticator{
		result: nauthilus.AuthResult{
			Decision:      nauthilus.DecisionRejected,
			StatusMessage: strings.Repeat("x", maxRejectedStatusTextBytes*4),
		},
	}
	harness := startTestSession(t, pipelineSessionConfig(authenticator, &recordingRoutingResolver{}, &recordingSessionStore{}, &recordingBackendSelector{}))

	harness.expectLine(t, greetingLine)
	harness.write(t, `A001 LOGIN "alice@example.test" "secret-password"`+"\r\n")
	response := harness.readLine(t)

	if !strings.HasPrefix(response, "A001 NO [AUTHENTICATIONFAILED] ") || !strings.HasSuffix(response, "\r\n") {
		t.Fatalf("response framing = %q", response)
	}

	if len(response) > maxRejectedStatusResponseBytes {
		t.Fatalf("response length = %d, want <= %d", len(response), maxRejectedStatusResponseBytes)
	}
}

// TestUnavailableAuthOutcomesDoNotPlace verifies fail-closed authority outcomes stop side effects.
func TestUnavailableAuthOutcomesDoNotPlace(t *testing.T) {
	testCases := []struct {
		name   string
		result nauthilus.AuthResult
		err    error
	}{
		{
			name:   "tempfail decision",
			result: nauthilus.AuthResult{Decision: nauthilus.DecisionTemporaryFailure},
		},
		{
			name:   "transport error",
			result: nauthilus.AuthResult{Decision: nauthilus.DecisionTemporaryFailure},
			err:    errors.New("transport unavailable"),
		},
		{
			name:   "timeout error",
			result: nauthilus.AuthResult{Decision: nauthilus.DecisionTemporaryFailure},
			err:    context.DeadlineExceeded,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			authenticator := &recordingAuthenticator{result: testCase.result, err: testCase.err}
			router := &recordingRoutingResolver{}
			store := &recordingSessionStore{}
			selector := &recordingBackendSelector{}
			harness := startTestSession(t, pipelineSessionConfig(authenticator, router, store, selector))

			harness.expectLine(t, greetingLine)
			harness.write(t, `A001 LOGIN "alice@example.test" "secret-password"`+"\r\n")
			harness.expectLine(t, "A001 NO [UNAVAILABLE] Authentication service temporarily unavailable\r\n")

			assertNoPlacementCalls(t, router, store, selector)
		})
	}
}

// TestAuthenticatedPathBuildsRoutingAndPlacement verifies the successful call sequence.
func TestAuthenticatedPathBuildsRoutingAndPlacement(t *testing.T) {
	authenticator := &recordingAuthenticator{
		result: nauthilus.AuthResult{
			Decision: nauthilus.DecisionAuthenticated,
			Account:  "User@Example.TEST",
			Attributes: map[string][]string{
				"account":   {"User@Example.TEST"},
				"tenant":    {"blue"},
				"mailShard": {"mailstore-a"},
			},
		},
	}
	router := &recordingRoutingResolver{
		result: routing.RoutingResult{
			AccountKey:    "user@example.test",
			Tenant:        "blue",
			ShardTag:      "mailstore-a",
			RoutingSource: routing.SourceAuthAttribute,
		},
	}
	store := &recordingSessionStore{result: state.AffinityRecord{ShardTag: "mailstore-b"}}
	selector := &recordingBackendSelector{result: backend.SelectionResult{Backend: backend.Backend{Identifier: "mailstore-b-imap"}}}
	harness := startTestSession(t, pipelineSessionConfig(authenticator, router, store, selector))

	harness.expectLine(t, greetingLine)
	harness.write(t, `A001 ID ("client_id" "desktop-client")`+"\r\n")
	harness.expectLine(t, "* ID NIL\r\n")
	harness.expectLine(t, "A001 OK ID completed\r\n")
	harness.write(t, `A002 LOGIN "User@Example.TEST" "secret-password"`+"\r\n")
	harness.expectLine(t, "A002 OK Authentication completed\r\n")

	assertAuthenticatedPipelineCalls(t, authenticator, router, store, selector)
}

// TestAuthenticatedPathPassesApplicableOperatorBackendPin verifies IMAP pin scoping.
func TestAuthenticatedPathPassesApplicableOperatorBackendPin(t *testing.T) {
	authenticator := &recordingAuthenticator{
		result: nauthilus.AuthResult{
			Decision: nauthilus.DecisionAuthenticated,
			Account:  "alice@example.test",
		},
	}
	router := &recordingRoutingResolver{
		result: routing.RoutingResult{
			AccountKey:    "alice@example.test",
			Tenant:        defaultTenantName,
			ShardTag:      "mailstore-a",
			RoutingSource: routing.SourceAuthAttribute,
		},
	}
	store := &recordingSessionStore{
		backendPin: state.UserBackendPinRecord{
			Present:           true,
			BackendIdentifier: "mailstore-c-imap",
			Protocol:          protocolIMAP,
			BackendPool:       "imap-default",
			ShardTag:          "mailstore-a",
		},
	}
	selector := &recordingBackendSelector{result: backend.SelectionResult{Backend: backend.Backend{Identifier: "mailstore-c-imap"}}}
	harness := startTestSession(t, pipelineSessionConfig(authenticator, router, store, selector))

	harness.expectLine(t, greetingLine)
	harness.write(t, `A001 LOGIN "alice@example.test" "secret-password"`+"\r\n")
	harness.expectLine(t, "A001 OK Authentication completed\r\n")

	if store.backendPinCalls != 1 {
		t.Fatalf("backend pin reads = %d, want 1", store.backendPinCalls)
	}

	if store.record.ShardTag != "mailstore-a" {
		t.Fatalf("session open shard = %q, want routed shard", store.record.ShardTag)
	}

	if selector.request.OperatorBackendIdentifier != "mailstore-c-imap" {
		t.Fatalf("operator backend pin = %q, want mailstore-c-imap", selector.request.OperatorBackendIdentifier)
	}

	if store.reserveCalls != 1 || store.attachCalls != 1 || store.attachment.BackendIdentifier != "mailstore-c-imap" {
		t.Fatalf("reservation/attachment = %d/%d %#v, want pinned backend accounted", store.reserveCalls, store.attachCalls, store.attachment)
	}
}

// TestAuthenticatedPathIgnoresCrossShardOperatorBackendPin verifies pins cannot move shards.
func TestAuthenticatedPathIgnoresCrossShardOperatorBackendPin(t *testing.T) {
	authenticator := &recordingAuthenticator{
		result: nauthilus.AuthResult{
			Decision: nauthilus.DecisionAuthenticated,
			Account:  "alice@example.test",
		},
	}
	router := &recordingRoutingResolver{
		result: routing.RoutingResult{
			AccountKey:    "alice@example.test",
			Tenant:        defaultTenantName,
			ShardTag:      "mailstore-a",
			RoutingSource: routing.SourceAuthAttribute,
		},
	}
	store := &recordingSessionStore{
		backendPin: state.UserBackendPinRecord{
			Present:           true,
			BackendIdentifier: "mailstore-c-imap",
			Protocol:          protocolIMAP,
			BackendPool:       "imap-default",
			ShardTag:          "mailstore-c",
		},
	}
	selector := &recordingBackendSelector{result: backend.SelectionResult{Backend: backend.Backend{Identifier: "mailstore-a-imap"}}}
	harness := startTestSession(t, pipelineSessionConfig(authenticator, router, store, selector))

	harness.expectLine(t, greetingLine)
	harness.write(t, `A001 LOGIN "alice@example.test" "secret-password"`+"\r\n")
	harness.expectLine(t, "A001 OK Authentication completed\r\n")

	if store.record.ShardTag != "mailstore-a" {
		t.Fatalf("session open shard = %q, want routed shard", store.record.ShardTag)
	}

	if selector.request.OperatorBackendIdentifier != "" {
		t.Fatalf("operator backend pin = %q, want ignored across shard boundary", selector.request.OperatorBackendIdentifier)
	}
}

// TestAuthenticatedPathKeepsActiveBackendSeparateFromOperatorPin verifies active pins win.
func TestAuthenticatedPathKeepsActiveBackendSeparateFromOperatorPin(t *testing.T) {
	authenticator := &recordingAuthenticator{result: nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: "alice@example.test"}}
	router := &recordingRoutingResolver{
		result: routing.RoutingResult{
			AccountKey: "alice@example.test",
			Tenant:     defaultTenantName,
			ShardTag:   "mailstore-a",
		},
	}
	store := &recordingSessionStore{
		result: state.AffinityRecord{
			Present:           true,
			Status:            affinityStatusReused,
			ShardTag:          "mailstore-b",
			BackendIdentifier: "mailstore-b-imap",
		},
		backendPin: state.UserBackendPinRecord{
			Present:           true,
			BackendIdentifier: "mailstore-c-imap",
			Protocol:          protocolIMAP,
			BackendPool:       "imap-default",
			ShardTag:          "mailstore-c",
		},
	}
	selector := &recordingBackendSelector{result: backend.SelectionResult{Backend: backend.Backend{Identifier: "mailstore-b-imap"}}}
	harness := startTestSession(t, pipelineSessionConfig(authenticator, router, store, selector))

	harness.expectLine(t, greetingLine)
	harness.write(t, `A001 LOGIN "alice@example.test" "secret-password"`+"\r\n")
	harness.expectLine(t, "A001 OK Authentication completed\r\n")

	if selector.request.PinnedBackendIdentifier != "mailstore-b-imap" {
		t.Fatalf("active backend pin = %q, want mailstore-b-imap", selector.request.PinnedBackendIdentifier)
	}

	if selector.request.OperatorBackendIdentifier != "" {
		t.Fatalf("operator backend pin = %q, want inactive while active backend is present", selector.request.OperatorBackendIdentifier)
	}
}

// TestAuthenticatedPlacementGateRunsBeforeRuntimeReads verifies release re-enters state reads.
func TestAuthenticatedPlacementGateRunsBeforeRuntimeReads(t *testing.T) {
	authenticator := &recordingAuthenticator{result: nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: "alice@example.test"}}
	router := &recordingRoutingResolver{
		result: routing.RoutingResult{
			AccountKey: "alice@example.test",
			Tenant:     defaultTenantName,
			ShardTag:   "mailstore-a",
		},
	}
	store := &recordingSessionStore{}
	selector := &recordingBackendSelector{result: backend.SelectionResult{Backend: backend.Backend{Identifier: "mailstore-c-imap"}}}
	connector := &recordingBackendConnector{}
	gate := &recordingPlacementGate{
		wait: func(_ context.Context, request runtimectl.PlacementGateRequest) (runtimectl.PlacementGateResult, error) {
			if request.Protocol != protocolIMAP || request.ListenerName == "" || request.ServiceName == "" {
				t.Fatalf("placement-gate request = %#v, want IMAP listener context", request)
			}

			if store.backendPinCalls != 0 || store.calls != 0 || store.reserveCalls != 0 || store.attachCalls != 0 || selector.calls != 0 || connector.calls != 0 {
				t.Fatalf("runtime side effects before gate release = pin:%d session:%d reserve:%d attach:%d selector:%d connect:%d", store.backendPinCalls, store.calls, store.reserveCalls, store.attachCalls, selector.calls, connector.calls)
			}

			store.backendPin = state.UserBackendPinRecord{
				Present:           true,
				BackendIdentifier: "mailstore-c-imap",
				Protocol:          protocolIMAP,
				BackendPool:       "imap-default",
				ShardTag:          "mailstore-a",
			}

			return runtimectl.PlacementGateResult{
				Outcome:                     runtimectl.PlacementGateOutcomeReleased,
				RuntimeStateRecheckRequired: true,
			}, nil
		},
	}

	config := pipelineSessionConfig(authenticator, router, store, selector)
	config.PlacementGate = gate
	config.BackendConnector = connector
	harness := startTestSession(t, config)

	harness.expectLine(t, greetingLine)
	harness.write(t, `A001 LOGIN "alice@example.test" "secret-password"`+"\r\n")
	harness.expectLine(t, "A001 OK Authentication completed\r\n")

	if gate.calls != 1 {
		t.Fatalf("placement gate calls = %d, want 1", gate.calls)
	}

	if selector.request.OperatorBackendIdentifier != "mailstore-c-imap" {
		t.Fatalf("operator backend pin after gate release = %q, want re-read pin", selector.request.OperatorBackendIdentifier)
	}

	if store.calls != 1 || store.reserveCalls != 1 || store.attachCalls != 1 || connector.calls != 1 {
		t.Fatalf("placement side effects after release = session:%d reserve:%d attach:%d connect:%d, want all once", store.calls, store.reserveCalls, store.attachCalls, connector.calls)
	}
}

// TestAuthenticatedPlacementGateTemporaryFailureStopsPlacement verifies timeout does not route.
func TestAuthenticatedPlacementGateTemporaryFailureStopsPlacement(t *testing.T) {
	authenticator := &recordingAuthenticator{result: nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: "alice@example.test"}}
	router := &recordingRoutingResolver{
		result: routing.RoutingResult{
			AccountKey: "alice@example.test",
			Tenant:     defaultTenantName,
			ShardTag:   "mailstore-a",
		},
	}
	store := &recordingSessionStore{}
	selector := &recordingBackendSelector{}
	connector := &recordingBackendConnector{}
	gate := &recordingPlacementGate{
		err: &runtimectl.Error{Kind: runtimectl.ErrorKindUnavailable, Operation: "user_hold_check", Message: "user hold wait timeout"},
	}

	config := pipelineSessionConfig(authenticator, router, store, selector)
	config.PlacementGate = gate
	config.BackendConnector = connector
	harness := startTestSession(t, config)

	harness.expectLine(t, greetingLine)
	harness.write(t, `A001 LOGIN "alice@example.test" "secret-password"`+"\r\n")
	harness.expectLine(t, "A001 NO [UNAVAILABLE] Authentication service temporarily unavailable\r\n")

	if gate.calls != 1 {
		t.Fatalf("placement gate calls = %d, want 1", gate.calls)
	}

	if store.backendPinCalls != 0 || store.calls != 0 || store.reserveCalls != 0 || store.attachCalls != 0 || selector.calls != 0 || connector.calls != 0 {
		t.Fatalf("placement after gate failure = pin:%d session:%d reserve:%d attach:%d selector:%d connect:%d, want none", store.backendPinCalls, store.calls, store.reserveCalls, store.attachCalls, selector.calls, connector.calls)
	}
}

// TestAuthenticatedPathDefersOperatorPinDuringActiveAffinity verifies deferred pin strategies keep stickiness.
func TestAuthenticatedPathDefersOperatorPinDuringActiveAffinity(t *testing.T) {
	authenticator := &recordingAuthenticator{result: nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: "alice@example.test"}}
	router := &recordingRoutingResolver{
		result: routing.RoutingResult{
			AccountKey: "alice@example.test",
			Tenant:     defaultTenantName,
			ShardTag:   "mailstore-a",
		},
	}
	store := &recordingSessionStore{
		result: state.AffinityRecord{
			Present:            true,
			Status:             affinityStatusReused,
			ShardTag:           "mailstore-a",
			ActiveSessionCount: 2,
		},
		backendPin: state.UserBackendPinRecord{
			Present:           true,
			BackendIdentifier: "mailstore-c-imap",
			Protocol:          protocolIMAP,
			BackendPool:       "imap-default",
			ShardTag:          "mailstore-a",
			Strategy:          "drain_existing",
		},
	}
	selector := &recordingBackendSelector{result: backend.SelectionResult{Backend: backend.Backend{Identifier: "mailstore-a-imap"}}}
	harness := startTestSession(t, pipelineSessionConfig(authenticator, router, store, selector))

	harness.expectLine(t, greetingLine)
	harness.write(t, `A001 LOGIN "alice@example.test" "secret-password"`+"\r\n")
	harness.expectLine(t, "A001 OK Authentication completed\r\n")

	if selector.request.OperatorBackendIdentifier != "" {
		t.Fatalf("operator backend pin = %q, want deferred during active affinity", selector.request.OperatorBackendIdentifier)
	}
}

// TestReplaySecretsAreClearedBeforeProxyMode verifies credential replay does not enter long-lived state.
func TestReplaySecretsAreClearedBeforeProxyMode(t *testing.T) {
	credentials := plainCredentialsForBackendTest(t)
	defer credentials.Clear()

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	proxyStarted := make(chan struct{}, 1)
	runner := &recordingProxyRunner{
		check: func(proxy.PipeConfig) {
			if !credentials.Secret().IsZero() {
				t.Errorf("credential secret was still present at proxy start")
			}
			proxyStarted <- struct{}{}
		},
	}

	session, err := NewSession(pipelineSessionConfig(
		&recordingAuthenticator{},
		&recordingRoutingResolver{},
		&recordingSessionStore{},
		&recordingBackendSelector{},
	), server)
	if err != nil {
		t.Fatalf("NewSession returned error: %v", err)
	}
	session.sessionStore = &recordingSessionStore{}
	session.backendConnector = &recordingBackendConnector{}
	session.proxyRunner = runner
	session.placement = Placement{
		Routing: routing.RoutingResult{Tenant: defaultTenantName, AccountKey: "alice@example.test"},
		Affinity: state.AffinityRecord{
			Key: state.AffinityKey{Tenant: defaultTenantName, AccountKey: "alice@example.test"},
		},
		Backend: backend.SelectionResult{Backend: testReplayPipelineBackend()},
	}
	session.placed = true

	done := make(chan error, 1)
	go func() {
		_, transitionErr := session.transitionAuthenticatedSession(context.Background(), "A001", credentials)
		done <- transitionErr
	}()

	if line := readPipeLine(t, client); line != "A001 OK Authentication completed\r\n" {
		t.Fatalf("frontend auth response = %q, want OK", line)
	}

	select {
	case <-proxyStarted:
	case <-time.After(time.Second):
		t.Fatal("proxy mode did not start")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("transitionAuthenticatedSession returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for transition")
	}
}

// TestAttachedIMAPSessionDoesNotReenterPlacementGate verifies proxy mode stays attached.
func TestAttachedIMAPSessionDoesNotReenterPlacementGate(t *testing.T) {
	authenticator := &recordingAuthenticator{result: nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: "alice@example.test"}}
	router := &recordingRoutingResolver{
		result: routing.RoutingResult{
			AccountKey: "alice@example.test",
			Tenant:     defaultTenantName,
			ShardTag:   "mailstore-a",
		},
	}
	store := &recordingSessionStore{}
	selector := &recordingBackendSelector{result: backend.SelectionResult{Backend: backend.Backend{Identifier: "mailstore-a-imap"}}}
	gate := &recordingPlacementGate{}

	proxyStarted := make(chan struct{})
	releaseProxy := make(chan struct{})
	runner := &recordingProxyRunner{
		check: func(proxy.PipeConfig) {
			close(proxyStarted)
			<-releaseProxy
		},
	}

	config := pipelineSessionConfig(authenticator, router, store, selector)
	config.PlacementGate = gate
	config.ProxyRunner = runner
	harness := startTestSession(t, config)

	harness.expectLine(t, greetingLine)
	harness.write(t, `A001 LOGIN "alice@example.test" "secret-password"`+"\r\n")
	harness.expectLine(t, "A001 OK Authentication completed\r\n")

	select {
	case <-proxyStarted:
	case <-time.After(time.Second):
		t.Fatal("proxy mode did not start")
	}

	select {
	case err := <-harness.done:
		t.Fatalf("attached IMAP session stopped while proxy was active: %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	if gate.calls != 1 {
		t.Fatalf("placement gate calls after proxy attach = %d, want initial placement only", gate.calls)
	}

	close(releaseProxy)
	if err := harness.wait(t); err != nil {
		t.Fatalf("session returned error after proxy release: %v", err)
	}
}

// TestBackendConnectFailureClosesRegisteredSession verifies placement rollback after attach.
func TestBackendConnectFailureClosesRegisteredSession(t *testing.T) {
	credentials := plainCredentialsForBackendTest(t)
	defer credentials.Clear()

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	store := &recordingSessionStore{}
	session := newPlacedTransitionSession(t, server, store)
	session.backendConnector = &recordingBackendConnector{err: errors.New("connect failed")}

	_, err := session.transitionAuthenticatedSession(context.Background(), "A001", credentials)
	if err != nil {
		t.Fatalf("transitionAuthenticatedSession returned transport error: %v", err)
	}

	if store.closeCalls != 1 {
		t.Fatalf("close calls after connect failure = %d, want 1", store.closeCalls)
	}
}

// TestBackendAuthFailureClosesRegisteredSession verifies backend auth rollback after attach.
func TestBackendAuthFailureClosesRegisteredSession(t *testing.T) {
	credentials := plainCredentialsForBackendTest(t)
	defer credentials.Clear()

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	store := &recordingSessionStore{}
	session := newPlacedTransitionSession(t, server, store)
	session.backendConnector = &recordingBackendConnector{authResponse: "NO backend auth rejected"}

	_, err := session.transitionAuthenticatedSession(context.Background(), "A001", credentials)
	if err != nil {
		t.Fatalf("transitionAuthenticatedSession returned transport error: %v", err)
	}

	if store.closeCalls != 1 {
		t.Fatalf("close calls after backend auth failure = %d, want 1", store.closeCalls)
	}
}

// TestSessionLeaseLifecycleClosesRedisLeaseOnce verifies proxy cleanup is idempotent.
func TestSessionLeaseLifecycleClosesRedisLeaseOnce(t *testing.T) {
	store := &recordingSessionStore{}
	lease := &sessionLeaseLifecycle{
		store:     store,
		key:       state.AffinityKey{Tenant: defaultTenantName, AccountKey: "alice@example.test"},
		sessionID: "session-1",
		ttl:       time.Second,
	}

	if err := lease.Close(context.Background()); err != nil {
		t.Fatalf("first Close returned error: %v", err)
	}
	if err := lease.Close(context.Background()); err != nil {
		t.Fatalf("second Close returned error: %v", err)
	}
	if store.closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1", store.closeCalls)
	}
}

// newPlacedTransitionSession creates a session positioned after Redis attach.
func newPlacedTransitionSession(t *testing.T, conn net.Conn, store *recordingSessionStore) *Session {
	t.Helper()

	session, err := NewSession(pipelineSessionConfig(
		&recordingAuthenticator{},
		&recordingRoutingResolver{},
		store,
		&recordingBackendSelector{},
	), conn)
	if err != nil {
		t.Fatalf("NewSession returned error: %v", err)
	}

	session.sessionStore = store
	session.proxyRunner = &recordingProxyRunner{}
	session.placement = Placement{
		Routing: routing.RoutingResult{Tenant: defaultTenantName, AccountKey: "alice@example.test"},
		Affinity: state.AffinityRecord{
			Key: state.AffinityKey{Tenant: defaultTenantName, AccountKey: "alice@example.test"},
		},
		Backend: backend.SelectionResult{Backend: defaultPipelineBackend("selected-imap")},
	}
	session.placed = true

	return session
}

// assertAuthenticatedPipelineCalls verifies the auth, routing, session and selector requests.
func assertAuthenticatedPipelineCalls(
	t *testing.T,
	authenticator *recordingAuthenticator,
	router *recordingRoutingResolver,
	store *recordingSessionStore,
	selector *recordingBackendSelector,
) {
	t.Helper()
	assertAuthRequest(t, authenticator)
	assertRoutingRequest(t, router)
	assertSessionOpenRequest(t, store)
	assertBackendSelectionRequest(t, selector)
}

// assertAuthRequest verifies the Nauthilus call from the frontend session.
func assertAuthRequest(t *testing.T, authenticator *recordingAuthenticator) {
	t.Helper()

	if len(authenticator.requests) != 1 {
		t.Fatalf("auth calls = %d, want 1", len(authenticator.requests))
	}

	if got := authenticator.requests[0].Context.Protocol; got != "imap" {
		t.Fatalf("auth protocol = %q, want imap", got)
	}

	if got := authenticator.requests[0].Context.ClientID; got != "desktop-client" {
		t.Fatalf("auth client ID = %q, want desktop-client", got)
	}

	if got := authenticator.requests[0].Context.TLS; got != "true" {
		t.Fatalf("auth TLS = %q, want true", got)
	}
}

// assertRoutingRequest verifies authenticated attributes reached routing.
func assertRoutingRequest(t *testing.T, router *recordingRoutingResolver) {
	t.Helper()

	if router.calls != 1 {
		t.Fatalf("routing calls = %d, want 1", router.calls)
	}

	if router.request.ListenerName != testIMAPService || router.request.ServiceName != testIMAPService {
		t.Fatalf("routing listener context = %#v", router.request)
	}

	if router.request.BackendPool != "imap-default" || router.request.Protocol != "imap" {
		t.Fatalf("routing backend context = %#v", router.request)
	}

	if router.request.NormalizedAccount != "user@example.test" {
		t.Fatalf("normalized account = %q, want user@example.test", router.request.NormalizedAccount)
	}

	if got := router.request.AuthAttributes["mailShard"]; len(got) != 1 || got[0] != "mailstore-a" {
		t.Fatalf("routing attributes = %#v", router.request.AuthAttributes)
	}
}

// assertSessionOpenRequest verifies the Redis session-open input after routing.
func assertSessionOpenRequest(t *testing.T, store *recordingSessionStore) {
	t.Helper()

	if store.calls != 1 {
		t.Fatalf("store calls = %d, want 1", store.calls)
	}

	if store.record.Key != (state.AffinityKey{Tenant: "blue", AccountKey: "user@example.test"}) {
		t.Fatalf("session affinity key = %#v", store.record.Key)
	}

	if store.record.ShardTag != "mailstore-a" {
		t.Fatalf("session shard = %q, want routing shard mailstore-a", store.record.ShardTag)
	}

	if store.attachCalls != 1 {
		t.Fatalf("backend attach calls = %d, want 1", store.attachCalls)
	}

	if store.reserveCalls != 1 {
		t.Fatalf("backend reservation calls = %d, want 1", store.reserveCalls)
	}

	if store.attachment.BackendIdentifier != "mailstore-b-imap" || store.attachment.MaxConnections <= 0 || store.attachment.ReservationID == "" {
		t.Fatalf("backend attachment = %#v", store.attachment)
	}
}

// assertBackendSelectionRequest verifies active affinity drives backend selection.
func assertBackendSelectionRequest(t *testing.T, selector *recordingBackendSelector) {
	t.Helper()

	if selector.calls != 1 {
		t.Fatalf("selector calls = %d, want 1", selector.calls)
	}

	if selector.request.ShardTag != "mailstore-b" {
		t.Fatalf("selector shard = %q, want active affinity shard mailstore-b", selector.request.ShardTag)
	}

	if selector.request.Protocol != "imap" || selector.request.BackendPool != "imap-default" {
		t.Fatalf("selector request = %#v", selector.request)
	}

	if !selector.request.ActiveAffinity {
		t.Fatal("selector did not receive active affinity marker")
	}
}

// TestAuthAttributeAndHashFallbackPlacement verifies real resolver chain flow from auth attributes.
func TestAuthAttributeAndHashFallbackPlacement(t *testing.T) {
	testCases := []struct {
		name       string
		attributes map[string][]string
		wantSource string
	}{
		{
			name: "auth attribute",
			attributes: map[string][]string{
				"account":   {"alice@example.test"},
				"tenant":    {defaultTenantName},
				"mailShard": {"mailstore-a"},
			},
			wantSource: routing.SourceAuthAttribute,
		},
		{
			name: "hash fallback",
			attributes: map[string][]string{
				"account": {"alice@example.test"},
				"tenant":  {defaultTenantName},
			},
			wantSource: routing.SourceHash,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			authenticator := &recordingAuthenticator{
				result: nauthilus.AuthResult{
					Decision:   nauthilus.DecisionAuthenticated,
					Account:    "alice@example.test",
					Attributes: testCase.attributes,
				},
			}
			store := &recordingSessionStore{}
			selector := &recordingBackendSelector{result: backend.SelectionResult{Backend: backend.Backend{Identifier: "selected-imap"}}}
			harness := startTestSession(t, pipelineSessionConfig(authenticator, mustPipelineChain(t), store, selector))

			harness.expectLine(t, greetingLine)
			harness.write(t, `A001 LOGIN "alice@example.test" "secret-password"`+"\r\n")
			harness.expectLine(t, "A001 OK Authentication completed\r\n")

			placement, ok := harness.session.Placement()
			if !ok {
				t.Fatal("session did not retain placement")
			}
			if placement.Routing.RoutingSource != testCase.wantSource {
				t.Fatalf("routing source = %q, want %q", placement.Routing.RoutingSource, testCase.wantSource)
			}
			if !slices.Contains([]string{"mailstore-a", "mailstore-b"}, store.record.ShardTag) {
				t.Fatalf("session shard = %q, want configured shard", store.record.ShardTag)
			}
		})
	}
}

// TestRoutingWithoutShardUsesEffectiveDefaultShard verifies placement fallback semantics.
func TestRoutingWithoutShardUsesEffectiveDefaultShard(t *testing.T) {
	authenticator := &recordingAuthenticator{
		result: nauthilus.AuthResult{
			Decision: nauthilus.DecisionAuthenticated,
			Account:  "alice@example.test",
			Attributes: map[string][]string{
				"account": {"alice@example.test"},
				"tenant":  {defaultTenantName},
			},
		},
	}
	router := &recordingRoutingResolver{
		result: routing.RoutingResult{
			AccountKey:    "alice@example.test",
			Tenant:        defaultTenantName,
			RoutingSource: "test",
		},
	}
	store := &recordingSessionStore{}
	selector := &recordingBackendSelector{result: backend.SelectionResult{Backend: backend.Backend{Identifier: "selected-imap"}}}
	config := pipelineSessionConfig(authenticator, router, store, selector)
	config.DefaultShard = "fallback-shard"
	harness := startTestSession(t, config)

	harness.expectLine(t, greetingLine)
	harness.write(t, `A001 LOGIN "alice@example.test" "secret-password"`+"\r\n")
	harness.expectLine(t, "A001 OK Authentication completed\r\n")

	if store.record.ShardTag != "fallback-shard" {
		t.Fatalf("session shard = %q, want fallback-shard", store.record.ShardTag)
	}
	if selector.request.ShardTag != "fallback-shard" {
		t.Fatalf("selector shard = %q, want fallback-shard", selector.request.ShardTag)
	}
}

// TestSessionLeaseLifecycleReturnsControlAction verifies heartbeat actions propagate to proxy mode.
func TestSessionLeaseLifecycleReturnsControlAction(t *testing.T) {
	store := &recordingSessionStore{
		heartbeatResult: state.AffinityRecord{ControlAction: state.ControlActionDrain},
	}
	lease := &sessionLeaseLifecycle{
		store:     store,
		key:       state.AffinityKey{Tenant: defaultTenantName, AccountKey: "alice@example.test"},
		sessionID: "session-1",
		ttl:       time.Second,
	}

	err := lease.Heartbeat(context.Background())
	if !proxy.IsControlActionError(err) {
		t.Fatalf("heartbeat error = %v, want proxy control action", err)
	}

	if store.heartbeatCalls != 1 {
		t.Fatalf("heartbeat calls = %d, want 1", store.heartbeatCalls)
	}
}

type recordingAuthenticator struct {
	requests []nauthilus.AuthRequest
	result   nauthilus.AuthResult
	err      error
}

// Authenticate records the authority request and returns the configured outcome.
func (a *recordingAuthenticator) Authenticate(ctx context.Context, request nauthilus.AuthRequest) (nauthilus.AuthResult, error) {
	a.requests = append(a.requests, request)
	if a.err != nil && errors.Is(a.err, context.DeadlineExceeded) {
		<-ctx.Done()

		return a.result, a.err
	}

	return a.result, a.err
}

type recordingRoutingResolver struct {
	calls   int
	request routing.RoutingRequest
	result  routing.RoutingResult
	err     error
}

// Resolve records the routing request and returns the configured result.
func (r *recordingRoutingResolver) Resolve(_ context.Context, request routing.RoutingRequest) (routing.RoutingResult, error) {
	r.calls++
	r.request = request

	return r.result, r.err
}

type recordingSessionStore struct {
	calls           int
	attachCalls     int
	heartbeatCalls  int
	closeCalls      int
	reserveCalls    int
	releaseCalls    int
	backendPinCalls int
	record          state.SessionRecord
	attachment      state.SessionBackendAttachment
	reservation     state.BackendReservationRequest
	result          state.AffinityRecord
	attachResult    state.SessionBackendRecord
	heartbeatResult state.AffinityRecord
	backendPin      state.UserBackendPinRecord
	err             error
	attachErr       error
	heartbeatErr    error
	backendPinErr   error
}

// OpenSession records the session-open request and returns the configured affinity.
func (s *recordingSessionStore) OpenSession(_ context.Context, record state.SessionRecord) (state.AffinityRecord, error) {
	s.calls++
	s.record = record
	if s.result.ShardTag == "" {
		s.result.ShardTag = record.ShardTag
	}

	return s.result, s.err
}

// GetUserBackendPin records a read-only backend-pin lookup for placement tests.
func (s *recordingSessionStore) GetUserBackendPin(
	_ context.Context,
	request state.UserBackendPinGetRequest,
) (state.UserBackendPinRecord, error) {
	s.backendPinCalls++
	if s.backendPin.Key == (state.AffinityKey{}) {
		s.backendPin.Key = request.Key
	}

	return s.backendPin, s.backendPinErr
}

// ReserveBackendCapacity records backend reservation before selected-backend attach.
func (s *recordingSessionStore) ReserveBackendCapacity(
	_ context.Context,
	request state.BackendReservationRequest,
) (state.BackendReservationRecord, error) {
	s.reserveCalls++
	s.reservation = request

	return state.BackendReservationRecord{
		Status:             "reserved",
		BackendIdentifier:  request.BackendIdentifier,
		ReservationID:      request.ReservationID,
		BackendActiveCount: 1,
		LeaseExpiresAt:     time.Now().Add(request.LeaseTTL),
	}, nil
}

// ReleaseBackendReservation records rollback of a reservation.
func (s *recordingSessionStore) ReleaseBackendReservation(
	context.Context,
	state.BackendReservationReleaseRequest,
) (state.BackendReservationRecord, error) {
	s.releaseCalls++

	return state.BackendReservationRecord{Status: "released", RepairedCount: 1}, nil
}

// ReapBackendReservations is unused by the auth pipeline tests.
func (s *recordingSessionStore) ReapBackendReservations(
	context.Context,
	state.BackendReservationReapRequest,
) (state.BackendReservationRecord, error) {
	return state.BackendReservationRecord{}, nil
}

// AttachSelectedBackend records selected-backend registration after placement.
func (s *recordingSessionStore) AttachSelectedBackend(
	_ context.Context,
	attachment state.SessionBackendAttachment,
) (state.SessionBackendRecord, error) {
	s.attachCalls++
	s.attachment = attachment
	if s.attachResult.BackendIdentifier == "" {
		s.attachResult.BackendIdentifier = attachment.BackendIdentifier
	}
	if s.attachResult.ReservationID == "" {
		s.attachResult.ReservationID = attachment.ReservationID
	}

	return s.attachResult, s.attachErr
}

// HeartbeatSession is unused by the auth pipeline tests.
func (s *recordingSessionStore) HeartbeatSession(
	context.Context,
	state.AffinityKey,
	string,
	time.Duration,
) (state.AffinityRecord, error) {
	s.heartbeatCalls++

	return s.heartbeatResult, s.heartbeatErr
}

// CloseSession records terminal lease release during fake proxy mode.
func (s *recordingSessionStore) CloseSession(context.Context, state.AffinityKey, string) (state.AffinityRecord, error) {
	s.closeCalls++

	return state.AffinityRecord{}, nil
}

type recordingBackendSelector struct {
	calls   int
	request backend.SelectionRequest
	result  backend.SelectionResult
	err     error
}

type recordingPlacementGate struct {
	calls   int
	request runtimectl.PlacementGateRequest
	result  runtimectl.PlacementGateResult
	err     error
	wait    func(context.Context, runtimectl.PlacementGateRequest) (runtimectl.PlacementGateResult, error)
}

// Select records the selector request and returns the configured backend result.
func (s *recordingBackendSelector) Select(_ context.Context, request backend.SelectionRequest) (backend.SelectionResult, error) {
	s.calls++
	s.request = request
	if s.result.Backend.Protocol == "" {
		s.result.Backend = defaultPipelineBackend(s.result.Backend.Identifier)
	}

	return s.result, s.err
}

// WaitForPlacement records the shared hold gate request and returns the configured result.
func (g *recordingPlacementGate) WaitForPlacement(
	ctx context.Context,
	request runtimectl.PlacementGateRequest,
) (runtimectl.PlacementGateResult, error) {
	g.calls++
	g.request = request
	if g.wait != nil {
		return g.wait(ctx, request)
	}

	return g.result, g.err
}

// pipelineSessionConfig returns a bounded IMAP config with auth pipeline dependencies installed.
func pipelineSessionConfig(
	authenticator nauthilus.Authenticator,
	resolver routing.RoutingResolver,
	sessionStore state.SessionStore,
	selector backend.Selector,
) SessionConfig {
	config := testPreauthConfig(TLSModeImplicit, false)
	config.BackendPool = "imap-default"
	config.DirectorInstanceID = "pipeline-director"
	config.DefaultTenant = defaultTenantName
	config.SessionLeaseTTL = time.Minute
	config.AuthTimeout = 20 * time.Millisecond
	config.Authenticator = authenticator
	config.RoutingResolver = resolver
	config.SessionStore = sessionStore
	config.BackendSelector = selector
	config.BackendConnector = &recordingBackendConnector{}
	config.ProxyRunner = &recordingProxyRunner{}

	return config
}

// defaultPipelineBackend fills successful pipeline tests with explicit backend auth policy.
func defaultPipelineBackend(identifier string) backend.Backend {
	if strings.TrimSpace(identifier) == "" {
		identifier = "selected-imap"
	}

	return backend.Backend{
		Identifier:     identifier,
		Protocol:       backendProtocol,
		Address:        "127.0.0.1:1143",
		MaxConnections: 100,
		TLS: backend.TLSConfig{
			Mode:          backendTLSStartTLS,
			ServerName:    "mailstore.example.test",
			MinTLSVersion: backendTLSMinDefault,
		},
		Auth: backend.AuthConfig{
			Mode: backendAuthModeMasterUser,
			MasterUser: backend.MasterUserConfig{
				Username:   "director-master",
				Password:   config.Secret("master-secret"),
				UserFormat: "{user}*{master_user}",
				Mechanism:  mechanismPlain,
			},
		},
	}
}

// testReplayPipelineBackend returns a credential-replay backend for transition tests.
func testReplayPipelineBackend() backend.Backend {
	target := defaultPipelineBackend("replay-imap")
	target.Auth = backend.AuthConfig{
		Mode: backendAuthModeCredentialReplay,
		CredentialReplay: backend.CredentialReplayConfig{
			RequireBackendTLS: true,
			PreserveMechanism: true,
			AllowedMechanisms: []string{mechanismPlain, mechanismLogin, mechanismXOAUTH2, mechanismOAuthBearer},
		},
	}

	return target
}

// readPipeLine reads one CRLF-terminated line from a net.Pipe connection.
func readPipeLine(t *testing.T, conn net.Conn) string {
	t.Helper()

	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read pipe line: %v", err)
	}

	return line
}

// recordingBackendConnector returns an already prepared fake backend connection.
type recordingBackendConnector struct {
	calls        int
	target       backend.Backend
	err          error
	authResponse string
}

// Connect records the selected backend and prepares a fake auth-capable stream.
func (c *recordingBackendConnector) Connect(_ context.Context, target backend.Backend, _ time.Duration) (*BackendConnection, error) {
	c.calls++
	c.target = target
	if c.err != nil {
		return nil, c.err
	}

	client, server := net.Pipe()
	connection := newBackendConnection(client)
	connection.capabilities = testBackendCapabilities()
	connection.tlsActive = true
	connection.tlsVerified = true

	go serveOneBackendAuthCommand(server, c.authResponse)

	return connection, nil
}

// serveOneBackendAuthCommand accepts one backend auth command and then waits for proxy close.
func serveOneBackendAuthCommand(conn net.Conn, response string) {
	defer func() { _ = conn.Close() }()

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	tag, _, _ := strings.Cut(strings.TrimSpace(line), " ")
	if tag == "" {
		return
	}

	if response == "" {
		response = "OK backend auth completed"
	}

	_, _ = io.WriteString(conn, tag+" "+response+"\r\n")
	_, _ = io.Copy(io.Discard, reader)
}

// recordingProxyRunner records transparent proxy start and releases the test lease.
type recordingProxyRunner struct {
	calls  int
	config proxy.PipeConfig
	check  func(proxy.PipeConfig)
	err    error
}

// Run records proxy config, applies an optional assertion and closes both streams.
func (r *recordingProxyRunner) Run(ctx context.Context, config proxy.PipeConfig) (proxy.Result, error) {
	r.calls++
	r.config = config
	if r.check != nil {
		r.check(config)
	}
	if config.Lease != nil {
		_ = config.Lease.Close(ctx)
	}
	_ = config.Frontend.Close()
	_ = config.Backend.Close()

	return proxy.Result{Class: proxy.ResultClientClosed}, r.err
}

// mustPipelineChain creates the real auth-attribute plus hash fallback resolver chain.
func mustPipelineChain(t *testing.T) routing.RoutingResolver {
	t.Helper()

	authResolver, err := routing.NewAuthAttributeResolver(routing.AuthAttributeResolverConfig{
		AccountKeyAttribute: "account",
		TenantAttribute:     "tenant",
		ShardTagAttribute:   "mailShard",
		Sticky:              true,
	})
	if err != nil {
		t.Fatalf("NewAuthAttributeResolver: %v", err)
	}

	hashResolver, err := routing.NewHashResolver(routing.HashResolverConfig{
		ShardTags: []string{"mailstore-a", "mailstore-b"},
		Sticky:    true,
	})
	if err != nil {
		t.Fatalf("NewHashResolver: %v", err)
	}

	chain, err := routing.NewChainResolver(authResolver, hashResolver)
	if err != nil {
		t.Fatalf("NewChainResolver: %v", err)
	}

	return chain
}

// assertNoPlacementCalls verifies unavailable/rejected auth stopped all side effects.
func assertNoPlacementCalls(
	t *testing.T,
	router *recordingRoutingResolver,
	store *recordingSessionStore,
	selector *recordingBackendSelector,
) {
	t.Helper()

	if router.calls != 0 || store.calls != 0 || selector.calls != 0 {
		t.Fatalf("placement calls = routing:%d state:%d backend:%d, want all zero", router.calls, store.calls, selector.calls)
	}
}

// assertHTTPBodyField verifies one captured JSON body field.
func assertHTTPBodyField(t *testing.T, body map[string]any, name string, want string) {
	t.Helper()

	got, ok := body[name].(string)
	if !ok || got != want {
		t.Fatalf("%s = %#v, want %q", name, body[name], want)
	}
}

// assertHTTPForbiddenFieldsAbsent verifies the IMAP session did not send director fields.
func assertHTTPForbiddenFieldsAbsent(t *testing.T, body map[string]any) {
	t.Helper()

	for _, field := range []string{"backend_identifier", "listener", "proxy", "routing_hint", "service", "session_id", "tls"} {
		if _, ok := body[field]; ok {
			t.Fatalf("forbidden field %q present in %#v", field, body)
		}
	}
}
