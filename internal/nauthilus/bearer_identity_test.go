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

package nauthilus

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/croessner/nauthilus-director/internal/observability"
)

const (
	bindingAccount       = "Bearer-User@example.test"
	bindingShardAttr     = "mailShard"
	bindingTokenShard    = "shard-token"
	bindingLookupShard   = "shard-lookup"
	bindingTokenSentinel = "bearer-token-binding-sentinel"
	bindingSessionID     = "token-session"
	bindingMechanism     = "xoauth2"
	bindingTLS           = "on"
	bindingLocalPort     = "143"
	bindingOpenIDScope   = "openid"
)

// recordingIdentityLookuper returns one configured lookup outcome and records requests.
type recordingIdentityLookuper struct {
	result   AuthResult
	err      error
	requests []IdentityLookupRequest
}

// LookupIdentity records the no-auth request and returns the configured outcome.
func (l *recordingIdentityLookuper) LookupIdentity(_ context.Context, request IdentityLookupRequest) (AuthResult, error) {
	l.requests = append(l.requests, request)

	return l.result, l.err
}

// bindingTokenResult returns an active introspection principal with token claims.
func bindingTokenResult(attributes map[string][]string) AuthResult {
	return AuthResult{
		Decision:   DecisionAuthenticated,
		Account:    bindingAccount,
		SessionID:  bindingSessionID,
		Attributes: attributes,
	}
}

// bindingRequest returns a bearer request carrying listener request context.
func bindingRequest() BearerIntrospectionRequest {
	return BearerIntrospectionRequest{
		Context: RequestContext{
			ClientIP:  observationClientIP,
			LocalPort: bindingLocalPort,
			Protocol:  observationProtocolIMAP,
			Method:    bindingMechanism,
			TLS:       bindingTLS,
		},
		Mechanism:   bindingMechanism,
		Protocol:    observationProtocolIMAP,
		BearerToken: NewSecret(bindingTokenSentinel),
	}
}

// bindForTest wraps one fake introspector and lookuper with a recorder.
func bindForTest(t *testing.T, token AuthResult, tokenErr error, lookuper *recordingIdentityLookuper) (BearerIntrospector, *recordingAuthObservation) {
	t.Helper()

	recorder := &recordingAuthObservation{}

	binder, err := BindBearerIdentity(fakeBearerIntrospector{result: token, err: tokenErr}, BearerIdentityConfig{
		Lookuper:          lookuper,
		ShardTagAttribute: bindingShardAttr,
		Observation: ObservationConfig{
			AuthorityName: observationAuthorityDefault,
			BackendPool:   observationBackendPool,
			ListenerName:  observationProtocolIMAP,
			Recorder:      recorder,
			ServiceName:   observationServiceIMAP,
			Transport:     transportGRPC,
		},
	})
	if err != nil {
		t.Fatalf("BindBearerIdentity returned error: %v", err)
	}

	return binder, recorder
}

// TestBindBearerIdentityRequiresLookup keeps the binding fail-closed at construction.
func TestBindBearerIdentityRequiresLookup(t *testing.T) {
	if _, err := BindBearerIdentity(fakeBearerIntrospector{}, BearerIdentityConfig{}); err == nil {
		t.Fatal("BindBearerIdentity accepted a missing identity lookup")
	}

	if _, err := BindBearerIdentity(nil, BearerIdentityConfig{Lookuper: &recordingIdentityLookuper{}}); err == nil {
		t.Fatal("BindBearerIdentity accepted a missing introspector")
	}
}

// TestBindBearerIdentityLooksUpTokenAccountAndMergesAttributes proves routing facts come from the authority.
func TestBindBearerIdentityLooksUpTokenAccountAndMergesAttributes(t *testing.T) {
	lookuper := &recordingIdentityLookuper{result: AuthResult{
		Decision: DecisionAuthenticated,
		Account:  strings.ToLower(bindingAccount),
		Attributes: map[string][]string{
			bindingShardAttr:       {bindingLookupShard},
			observationClaimTenant: {observationTenantBlue},
		},
	}}
	binder, recorder := bindForTest(t, bindingTokenResult(map[string][]string{
		bindingShardAttr: {bindingTokenShard},
		oidcClaimScope:   {bindingOpenIDScope, defaultBearerIntrospectionRequiredScope},
	}), nil, lookuper)

	result, err := binder.Introspect(context.Background(), bindingRequest())
	if err != nil {
		t.Fatalf("Introspect returned error: %v", err)
	}

	assertBindingLookupRequest(t, lookuper)
	assertBoundPrincipal(t, result)

	event := requireAuthObservation(t, recorder)
	if event.MetricLabels["reason_class"] != authObservationResultOK || event.MetricLabels["mechanism"] != IdentityLookupMethod ||
		event.MetricLabels["transport"] != transportGRPC {
		t.Fatalf("lookup observation labels = %v, want ok lookup over the authority transport", event.MetricLabels)
	}

	assertAuthEventOmitsValue(t, event, bindingTokenSentinel)
}

// assertBindingLookupRequest verifies one lookup for the token account with the listener context.
func assertBindingLookupRequest(t *testing.T, lookuper *recordingIdentityLookuper) {
	t.Helper()

	if len(lookuper.requests) != 1 {
		t.Fatalf("identity lookups = %d, want exactly one", len(lookuper.requests))
	}

	lookup := lookuper.requests[0].Context
	if lookup.Username != bindingAccount || lookup.Method != IdentityLookupMethod || lookup.Protocol != observationProtocolIMAP {
		t.Fatalf("lookup identity = %q method %q protocol %q, want token account with no-auth lookup method", lookup.Username, lookup.Method, lookup.Protocol)
	}

	if lookup.ClientIP != observationClientIP || lookup.LocalPort != bindingLocalPort || lookup.TLS != bindingTLS {
		t.Fatal("lookup did not keep the listener client and TLS context")
	}
}

// assertBoundPrincipal verifies the token identity with authority attributes merged over token claims.
func assertBoundPrincipal(t *testing.T, result AuthResult) {
	t.Helper()

	if result.Decision != DecisionAuthenticated || result.Account != bindingAccount || result.SessionID != bindingSessionID {
		t.Fatalf("bound principal = %+v, want token account and session", result)
	}

	if got := result.Attributes[bindingShardAttr]; len(got) != 1 || got[0] != bindingLookupShard {
		t.Fatalf("bound shard = %v, want the authority lookup value", got)
	}

	if got := result.Attributes[observationClaimTenant]; len(got) != 1 || got[0] != observationTenantBlue {
		t.Fatalf("bound tenant = %v, want the authority lookup value", got)
	}

	if got := result.Attributes[oidcClaimScope]; len(got) != 2 {
		t.Fatalf("bound scope = %v, want token-only claims preserved", got)
	}
}

// bindingFailureCase is one non-success lookup outcome and its expected fail-closed mapping.
type bindingFailureCase struct {
	name         string
	lookup       AuthResult
	lookupErr    error
	wantDecision string
	wantErr      bool
	wantReason   string
}

// bindingFailureCases lists every lookup outcome that must refuse or tempfail the login.
func bindingFailureCases() []bindingFailureCase {
	return []bindingFailureCase{
		{
			name:         "account mismatch",
			lookup:       AuthResult{Decision: DecisionAuthenticated, Account: "other@example.test", Attributes: map[string][]string{bindingShardAttr: {bindingLookupShard}}},
			wantDecision: DecisionRejected,
			wantReason:   bearerIdentityReasonAccountMismatch,
		},
		{
			name:         "identity rejected",
			lookup:       AuthResult{Decision: DecisionRejected, StatusMessage: "user unknown"},
			wantDecision: DecisionRejected,
			wantReason:   bearerIdentityReasonRejected,
		},
		{
			name:         "lookup transport failure",
			lookupErr:    transportError(operationLookupIdentity, errors.New("connection refused")),
			wantDecision: DecisionTemporaryFailure,
			wantErr:      true,
			wantReason:   string(ErrorKindTransport),
		},
		{
			name:         "lookup tempfail decision",
			lookup:       AuthResult{Decision: DecisionTemporaryFailure},
			wantDecision: DecisionTemporaryFailure,
			wantErr:      true,
			wantReason:   authObservationReasonTemporary,
		},
		{
			name:         "lookup without account",
			lookup:       AuthResult{Decision: DecisionAuthenticated, Attributes: map[string][]string{bindingShardAttr: {bindingLookupShard}}},
			wantDecision: DecisionTemporaryFailure,
			wantErr:      true,
			wantReason:   string(ErrorKindMalformedResponse),
		},
	}
}

// TestBindBearerIdentityRefusesOrTempfails proves every non-success lookup outcome fails closed.
func TestBindBearerIdentityRefusesOrTempfails(t *testing.T) {
	for _, test := range bindingFailureCases() {
		t.Run(test.name, func(t *testing.T) {
			lookuper := &recordingIdentityLookuper{result: test.lookup, err: test.lookupErr}
			binder, recorder := bindForTest(t, bindingTokenResult(map[string][]string{bindingShardAttr: {bindingTokenShard}}), nil, lookuper)

			result, err := binder.Introspect(context.Background(), bindingRequest())
			if (err != nil) != test.wantErr {
				t.Fatalf("Introspect error = %v, want error %v", err, test.wantErr)
			}

			if result.Decision != test.wantDecision {
				t.Fatalf("decision = %q, want %q", result.Decision, test.wantDecision)
			}

			if result.Account != "" || len(result.Attributes) != 0 || result.StatusMessage != "" {
				t.Fatalf("refused principal leaked routing facts or status text: %+v", result)
			}

			event := requireAuthObservation(t, recorder)
			if event.MetricLabels["reason_class"] != test.wantReason {
				t.Fatalf("reason_class = %q, want %q", event.MetricLabels["reason_class"], test.wantReason)
			}
		})
	}
}

// TestBindBearerIdentityReportsMissingShardDistinctly keeps unchanged routing semantics with a distinct signal.
func TestBindBearerIdentityReportsMissingShardDistinctly(t *testing.T) {
	lookuper := &recordingIdentityLookuper{result: AuthResult{Decision: DecisionAuthenticated, Account: bindingAccount}}
	binder, recorder := bindForTest(t, bindingTokenResult(nil), nil, lookuper)

	result, err := binder.Introspect(context.Background(), bindingRequest())
	if err != nil || result.Decision != DecisionAuthenticated {
		t.Fatalf("Introspect = %+v, %v; want authenticated principal", result, err)
	}

	if len(result.Attributes[bindingShardAttr]) != 0 {
		t.Fatal("binder invented a shard attribute")
	}

	event := requireAuthObservation(t, recorder)
	if event.MetricLabels["result"] != authObservationResultOK || event.MetricLabels["reason_class"] != bearerIdentityReasonShardMissing {
		t.Fatalf("labels = %v, want ok result with bearer_shard_missing reason", event.MetricLabels)
	}
}

// TestBindBearerIdentitySkipsLookupForRefusedTokens proves invalid tokens never reach the lookup.
func TestBindBearerIdentitySkipsLookupForRefusedTokens(t *testing.T) {
	for _, token := range []struct {
		result AuthResult
		err    error
	}{
		{result: AuthResult{Decision: DecisionRejected, StatusMessage: "bearer token inactive"}},
		{result: AuthResult{Decision: DecisionTemporaryFailure}, err: tempfailError(operationAuthenticate, 503, "")},
	} {
		lookuper := &recordingIdentityLookuper{}
		binder, _ := bindForTest(t, token.result, token.err, lookuper)

		result, err := binder.Introspect(context.Background(), bindingRequest())
		if !errors.Is(err, token.err) || result.Decision != token.result.Decision || result.StatusMessage != token.result.StatusMessage {
			t.Fatalf("Introspect = %+v, %v; want introspection outcome unchanged", result, err)
		}

		if len(lookuper.requests) != 0 {
			t.Fatal("refused token reached the identity lookup")
		}
	}
}

// TestBindBearerIdentityRecordsSafeReasonClasses keeps new reason classes on the metric allowlist.
func TestBindBearerIdentityRecordsSafeReasonClasses(t *testing.T) {
	for _, reason := range []string{bearerIdentityReasonAccountMismatch, bearerIdentityReasonRejected, bearerIdentityReasonShardMissing} {
		if observability.NormalizeReasonClass(reason) != reason {
			t.Fatalf("reason class %q is not allowlisted", reason)
		}
	}
}
