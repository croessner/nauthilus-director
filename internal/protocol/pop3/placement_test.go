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

//nolint:goconst,wsl_v5 // Placement tests repeat stable protocol and account fixtures intentionally.
package pop3

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/placement"
	"github.com/croessner/nauthilus-director/internal/routing"
	runtimectl "github.com/croessner/nauthilus-director/internal/runtime"
	"github.com/croessner/nauthilus-director/internal/state"
)

// TestAuthenticatedPOP3AuthFeedsSharedRouting verifies Nauthilus facts reach the shared resolver.
func TestAuthenticatedPOP3AuthFeedsSharedRouting(t *testing.T) {
	authenticator := &recordingAuthenticator{
		result: nauthilus.AuthResult{
			Decision: nauthilus.DecisionAuthenticated,
			Account:  "Canonical@Example.Test",
			Attributes: map[string][]string{
				"tenant": {"blue"},
			},
		},
	}
	resolver := &recordingRoutingResolver{
		result: routing.RoutingResult{
			AccountKey:    "canonical@example.test",
			Tenant:        "blue",
			ShardTag:      "mailstore-a",
			RoutingSource: routing.SourceAuthAttribute,
		},
	}
	placer := &recordingSessionPlacer{}
	harness := startPOP3Harness(t, testPlacementPOP3Config(TLSModeImplicit, authenticator, resolver, placer))
	harness.expectOK(t)

	harness.write(t, "USER Raw-Input@Example.Test\r\n")
	harness.expectOK(t)
	harness.write(t, "PASS correct-password\r\n")
	harness.expectERR(t)

	request := resolver.singleRequest(t)
	if request.Protocol != ProtocolPOP3 || request.ListenerName != "pop3" || request.ServiceName != "pop3" {
		t.Fatalf("routing context = %#v, want POP3 listener facts", request)
	}

	if request.LoginName != "Raw-Input@Example.Test" {
		t.Fatalf("routing login name = %q, want provisional diagnostic input", request.LoginName)
	}

	if request.NormalizedAccount != "canonical@example.test" {
		t.Fatalf("routing account = %q, want canonical account", request.NormalizedAccount)
	}

	placementRequest := placer.singleRequest(t)
	if placementRequest.Key.AccountKey != "canonical@example.test" {
		t.Fatalf("placement account = %q, want canonical key", placementRequest.Key.AccountKey)
	}
}

// TestAuthenticatedPOP3PlacementGateRunsBeforePlacement verifies holds block runtime side effects.
func TestAuthenticatedPOP3PlacementGateRunsBeforePlacement(t *testing.T) {
	authenticator := &recordingAuthenticator{
		result: nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: "alice@example.test"},
	}
	resolver := &recordingRoutingResolver{}
	placer := &recordingSessionPlacer{}
	gate := &recordingPlacementGate{
		wait: func(_ context.Context, request runtimectl.PlacementGateRequest) (runtimectl.PlacementGateResult, error) {
			if request.Protocol != ProtocolPOP3 || request.ListenerName != "pop3" || request.ServiceName != "pop3" {
				t.Fatalf("placement gate request = %#v, want POP3 listener context", request)
			}

			if request.Key.UserHash != "alice@example.test" {
				t.Fatalf("placement gate key = %#v, want canonical account", request.Key)
			}

			if placer.callCount() != 0 {
				t.Fatalf("placement calls before hold release = %d, want 0", placer.callCount())
			}

			return runtimectl.PlacementGateResult{
				Outcome:                     runtimectl.PlacementGateOutcomeReleased,
				RuntimeStateRecheckRequired: true,
			}, nil
		},
	}
	config := testPlacementPOP3Config(TLSModeImplicit, authenticator, resolver, placer)
	config.PlacementGate = gate
	harness := startPOP3Harness(t, config)
	harness.expectOK(t)

	harness.write(t, "USER raw-before-auth@example.test\r\n")
	harness.expectOK(t)
	harness.write(t, "PASS correct-password\r\n")
	harness.expectERR(t)

	if gate.callCount() != 1 || placer.callCount() != 1 {
		t.Fatalf("gate/placement calls = %d/%d, want 1/1", gate.callCount(), placer.callCount())
	}
}

// TestAuthenticatedPOP3PlacementGateTimeoutStopsPlacement verifies held users do not open sessions.
func TestAuthenticatedPOP3PlacementGateTimeoutStopsPlacement(t *testing.T) {
	authenticator := &recordingAuthenticator{
		result: nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: "alice@example.test"},
	}
	placer := &recordingSessionPlacer{}
	gate := &recordingPlacementGate{
		err: &runtimectl.Error{Kind: runtimectl.ErrorKindUnavailable, Operation: "user_hold_check", Message: "user hold wait timeout"},
	}
	config := testPlacementPOP3Config(TLSModeImplicit, authenticator, nil, placer)
	config.PlacementGate = gate
	harness := startPOP3Harness(t, config)
	harness.expectOK(t)

	harness.write(t, "USER alice@example.test\r\n")
	harness.expectOK(t)
	harness.write(t, "PASS correct-password\r\n")
	harness.expectERR(t)

	if gate.callCount() != 1 {
		t.Fatalf("placement gate calls = %d, want 1", gate.callCount())
	}

	if placer.callCount() != 0 || placer.closeCount() != 0 {
		t.Fatalf("placement calls close=%d place=%d, want none", placer.closeCount(), placer.callCount())
	}
}

// TestAuthenticatedPOP3PlacementRequestAndRollback verifies POP3 uses one shared session placement.
func TestAuthenticatedPOP3PlacementRequestAndRollback(t *testing.T) {
	authenticator := &recordingAuthenticator{
		result: nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: "alice@example.test"},
	}
	placer := &recordingSessionPlacer{}
	harness := startPOP3Harness(t, testPlacementPOP3Config(TLSModeImplicit, authenticator, nil, placer))
	harness.expectOK(t)

	harness.write(t, "USER provisional@example.test\r\n")
	harness.expectOK(t)
	harness.write(t, "PASS correct-password\r\n")
	harness.expectERR(t)

	request := placer.singleRequest(t)
	if request.Protocol != ProtocolPOP3 || request.ListenerName != "pop3" || request.ServiceName != "pop3" {
		t.Fatalf("placement request = %#v, want POP3 listener context", request)
	}

	if request.BackendPool != "pop3-default" || request.HolderKind != state.HolderKindSession {
		t.Fatalf("placement backend pool/kind = %q/%q, want pop3-default/session", request.BackendPool, request.HolderKind)
	}

	if request.Key.AccountKey != "alice@example.test" || request.LeaseTTL != time.Minute || request.RetentionTTL != 15*time.Minute {
		t.Fatalf("placement key/timing = %#v ttl=%v retention=%v", request.Key, request.LeaseTTL, request.RetentionTTL)
	}

	if placer.callCount() != 1 {
		t.Fatalf("placement calls = %d, want 1", placer.callCount())
	}

	if placer.closeCount() != 1 {
		t.Fatalf("lease close calls = %d, want rollback at backend-readiness boundary", placer.closeCount())
	}

	if _, ok := harness.session.Placement(); ok {
		t.Fatal("session still exposes placement after backend-readiness rollback")
	}
}

// TestAuthenticatedPOP3ProvisionalUSERIsNotPlacementKey verifies raw USER is never authoritative.
func TestAuthenticatedPOP3ProvisionalUSERIsNotPlacementKey(t *testing.T) {
	authenticator := &recordingAuthenticator{
		result: nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: "canonical@example.test"},
	}
	placer := &recordingSessionPlacer{}
	gate := &recordingPlacementGate{}
	config := testPlacementPOP3Config(TLSModeImplicit, authenticator, nil, placer)
	config.PlacementGate = gate
	harness := startPOP3Harness(t, config)
	harness.expectOK(t)

	harness.write(t, "USER raw-user@example.test\r\n")
	harness.expectOK(t)
	harness.write(t, "PASS correct-password\r\n")
	harness.expectERR(t)

	if gate.request.Key.UserHash == "raw-user@example.test" {
		t.Fatal("placement gate used provisional USER as key")
	}

	request := placer.singleRequest(t)
	if request.Key.AccountKey == "raw-user@example.test" {
		t.Fatal("placement used provisional USER as affinity key")
	}

	if request.Key.AccountKey != "canonical@example.test" || gate.request.Key.UserHash != "canonical@example.test" {
		t.Fatalf("canonical keys = placement %q gate %q, want canonical@example.test", request.Key.AccountKey, gate.request.Key.UserHash)
	}
}

// testPlacementPOP3Config builds a POP3 fixture with shared placement collaborators.
func testPlacementPOP3Config(
	tlsMode string,
	authenticator nauthilus.Authenticator,
	resolver routing.RoutingResolver,
	placer placement.SessionPlacer,
) SessionConfig {
	config := testPOP3Config(tlsMode, authenticator)
	if resolver == nil {
		resolver = &recordingRoutingResolver{}
	}

	if placer == nil {
		placer = &recordingSessionPlacer{}
	}

	config.DirectorInstanceID = "director-a"
	config.DefaultTenant = "default"
	config.DefaultShard = "mailstore-a"
	config.SessionLeaseTTL = time.Minute
	config.SessionIdleGrace = time.Minute
	config.BackendRetentionTTL = 15 * time.Minute
	config.RoutingResolver = resolver
	config.PlacementService = placer
	config.BackendConnector = &recordingPOP3BackendConnector{err: ErrBackendConnect}

	return config
}

type recordingRoutingResolver struct {
	mu       sync.Mutex
	requests []routing.RoutingRequest
	result   routing.RoutingResult
	err      error
}

// Resolve records the routing input and returns a complete default route when none is configured.
func (r *recordingRoutingResolver) Resolve(_ context.Context, request routing.RoutingRequest) (routing.RoutingResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.requests = append(r.requests, request)
	if r.err != nil {
		return routing.RoutingResult{}, r.err
	}

	if r.result.Complete() {
		return r.result.Clone(), nil
	}

	return routing.RoutingResult{
		AccountKey:    request.NormalizedAccount,
		Tenant:        request.Tenant,
		ShardTag:      "mailstore-a",
		RoutingSource: routing.SourceHash,
	}, nil
}

// singleRequest returns the only recorded routing request.
func (r *recordingRoutingResolver) singleRequest(t *testing.T) routing.RoutingRequest {
	t.Helper()

	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.requests) != 1 {
		t.Fatalf("routing requests = %d, want 1", len(r.requests))
	}

	return r.requests[0]
}

type recordingSessionPlacer struct {
	mu       sync.Mutex
	requests []placement.SessionRequest
	lease    *recordingPlacementLease
	err      error
}

// PlaceSession records the placement input and returns a closeable lease fixture.
func (p *recordingSessionPlacer) PlaceSession(_ context.Context, request placement.SessionRequest) (placement.LeaseHandle, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.requests = append(p.requests, request)
	if p.err != nil {
		return nil, p.err
	}

	lease := p.lease
	if lease == nil {
		lease = newRecordingPlacementLease(request)
	}

	p.lease = lease

	return lease, nil
}

// callCount returns the number of placement attempts.
func (p *recordingSessionPlacer) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return len(p.requests)
}

// closeCount returns how often the current fixture lease was closed.
func (p *recordingSessionPlacer) closeCount() int {
	p.mu.Lock()
	lease := p.lease
	p.mu.Unlock()

	if lease == nil {
		return 0
	}

	return lease.closeCount()
}

// singleRequest returns the only recorded placement request.
func (p *recordingSessionPlacer) singleRequest(t *testing.T) placement.SessionRequest {
	t.Helper()

	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.requests) != 1 {
		t.Fatalf("placement requests = %d, want 1", len(p.requests))
	}

	return p.requests[0]
}

type recordingPlacementLease struct {
	mu       sync.Mutex
	request  placement.SessionRequest
	affinity state.AffinityRecord
	backend  backend.SelectionResult
	binding  placement.BackendBinding
	closed   int
	beats    int
	beatErr  error
}

// newRecordingPlacementLease creates a lease fixture from one placement request.
func newRecordingPlacementLease(request placement.SessionRequest) *recordingPlacementLease {
	backendNode := "mailstore-a-node"
	backendID := "mailstore-a-pop3"

	return &recordingPlacementLease{
		request: request,
		affinity: state.AffinityRecord{
			Key:                request.Key,
			ShardTag:           request.ShardTag,
			BackendNode:        backendNode,
			Present:            true,
			BindingStatus:      state.BindingStatusActive,
			ActiveSessionCount: 1,
			ActiveHolderCount:  1,
		},
		backend: backend.SelectionResult{
			Backend: backend.Backend{
				Identifier:  backendID,
				Protocol:    ProtocolPOP3,
				BackendPool: request.BackendPool,
				ShardTag:    request.ShardTag,
				BackendNode: backendNode,
				Address:     "127.0.0.1:110",
			},
		},
		binding: placement.BackendBinding{
			Key:               request.Key,
			ShardTag:          request.ShardTag,
			BackendNode:       backendNode,
			BackendIdentifier: backendID,
			Source:            placement.BindingSourceInitialPlacement,
			ActiveHolderCount: 1,
		},
	}
}

// Affinity returns the lease affinity record.
func (l *recordingPlacementLease) Affinity() state.AffinityRecord {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.affinity
}

// AttachBackend satisfies the placement lease interface for tests.
func (l *recordingPlacementLease) AttachBackend(context.Context) error {
	return nil
}

// Backend returns the selected backend fixture.
func (l *recordingPlacementLease) Backend() backend.SelectionResult {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.backend
}

// Binding returns the backend-node binding fixture.
func (l *recordingPlacementLease) Binding() placement.BackendBinding {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.binding
}

// Close records lease rollback or session cleanup.
func (l *recordingPlacementLease) Close(context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.closed++

	return nil
}

// Heartbeat returns the current affinity fixture.
func (l *recordingPlacementLease) Heartbeat(context.Context, time.Duration) (state.AffinityRecord, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.beats++
	if l.beatErr != nil {
		return state.AffinityRecord{}, l.beatErr
	}

	return l.affinity, nil
}

// SessionID returns the placement session ID.
func (l *recordingPlacementLease) SessionID() string {
	return l.request.SessionID
}

// closeCount reports how many times Close was called.
func (l *recordingPlacementLease) closeCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.closed
}

// heartbeatCount reports how many times Heartbeat was called.
func (l *recordingPlacementLease) heartbeatCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.beats
}

type recordingPlacementGate struct {
	mu      sync.Mutex
	request runtimectl.PlacementGateRequest
	err     error
	calls   int
	wait    func(context.Context, runtimectl.PlacementGateRequest) (runtimectl.PlacementGateResult, error)
}

// WaitForPlacement records the gate request and returns the configured wait outcome.
func (g *recordingPlacementGate) WaitForPlacement(
	ctx context.Context,
	request runtimectl.PlacementGateRequest,
) (runtimectl.PlacementGateResult, error) {
	g.mu.Lock()
	g.calls++
	g.request = request
	g.mu.Unlock()

	if g.wait != nil {
		return g.wait(ctx, request)
	}

	if g.err != nil {
		return runtimectl.PlacementGateResult{}, g.err
	}

	return runtimectl.PlacementGateResult{Outcome: runtimectl.PlacementGateOutcomeAllowed}, nil
}

// callCount returns how many times the gate was evaluated.
func (g *recordingPlacementGate) callCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()

	return g.calls
}
