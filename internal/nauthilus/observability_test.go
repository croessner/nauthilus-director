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
	"testing"

	"github.com/croessner/nauthilus-director/internal/observability"
)

const (
	observationAuthorityDefault = "default"
	observationAuthorityPrimary = "primary"
	observationBackendPool      = "imap-default"
	observationClientIP         = "203.0.113.10"
	observationMechanismPlain   = "plain"
	observationPassword         = "secret-password"
	observationProtocolIMAP     = "imap"
	observationClaimTenant      = "tenant"
	observationCustomClaimName  = "custom_claim"
	observationMechanismBearer  = "OAUTHBEARER"
	observationTenantBlue       = "blue"
	observationSecret           = "secret-observation-body"
	observationServiceIMAP      = "imap"
	observationServiceSubmit    = "imap-submission"
	observationUsername         = "alice@example.test"
	observationBearerAccount    = "account-observation-sentinel"
	observationBearerClaim      = "claim-observation-sentinel"
	observationBearerToken      = "bearer-token-observation-sentinel"
)

// TestObservedAuthenticatorClassifiesAuthorityOutcomes verifies bounded auth reasons.
func TestObservedAuthenticatorClassifiesAuthorityOutcomes(t *testing.T) {
	tests := []struct {
		name       string
		result     AuthResult
		err        error
		wantResult string
		wantReason string
	}{
		{
			name:       "timeout",
			result:     resultWithDecision(DecisionTemporaryFailure, "", "", "", nil),
			err:        context.DeadlineExceeded,
			wantResult: authObservationResultFailure,
			wantReason: authObservationReasonTimeout,
		},
		{
			name:       "denied",
			result:     resultWithDecision(DecisionRejected, "", "", "", nil),
			wantResult: authObservationResultRejected,
			wantReason: authObservationReasonDenied,
		},
		{
			name:       string(ErrorKindTemporaryFailure),
			result:     resultWithDecision(DecisionTemporaryFailure, "", "", "", nil),
			wantResult: authObservationResultFailure,
			wantReason: authObservationReasonTemporary,
		},
		{
			name:       "malformed",
			result:     resultWithDecision(DecisionTemporaryFailure, "", "", "", nil),
			err:        malformedResponseError(operationAuthenticate, "invalid auth response", errors.New(observationSecret)),
			wantResult: authObservationResultFailure,
			wantReason: string(ErrorKindMalformedResponse),
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := runObservedAuth(t, fakeAuthenticator{result: testCase.result, err: testCase.err})
			event := requireAuthObservation(t, recorder)

			if got := event.MetricLabels[authObservationFieldResult]; got != testCase.wantResult {
				t.Fatalf("result label = %q, want %q", got, testCase.wantResult)
			}

			if got := event.MetricLabels[authObservationFieldReasonClass]; got != testCase.wantReason {
				t.Fatalf("reason_class = %q, want %q", got, testCase.wantReason)
			}

			assertAuthEventSecretSafe(t, event)
		})
	}
}

// TestObservedAuthenticatorRecordsAuthorityContext verifies authority metadata is present.
func TestObservedAuthenticatorRecordsAuthorityContext(t *testing.T) {
	recorder := &recordingAuthObservation{}
	client := ObserveAuthenticator(fakeAuthenticator{
		result: resultWithDecision(DecisionAuthenticated, "alice", "", "", nil),
	}, ObservationConfig{
		AuthorityName: observationAuthorityPrimary,
		BackendPool:   observationBackendPool,
		ListenerName:  "imaps",
		Recorder:      recorder,
		ServiceName:   observationServiceSubmit,
		Transport:     transportGRPC,
	})

	_, err := client.Authenticate(context.Background(), observedAuthRequest())
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}

	event, ok := recorder.last(observability.EventNauthilusAuth)
	if !ok {
		t.Fatalf("auth observation missing: %#v", recorder.events)
	}

	if got := event.LogFields[authObservationFieldAuthority]; got != observationAuthorityPrimary {
		t.Fatalf("authority field = %q, want primary", got)
	}

	if got := event.MetricLabels[authObservationFieldService]; got != observationServiceSubmit {
		t.Fatalf("service label = %q, want imap-submission", got)
	}

	if got := event.MetricLabels[authObservationFieldTransport]; got != transportGRPC {
		t.Fatalf("transport label = %q, want grpc", got)
	}

	if got := event.MetricLabels[authObservationFieldMechanism]; got != observationMechanismPlain {
		t.Fatalf("mechanism label = %q, want plain", got)
	}
}

// TestObservedBearerIntrospectorOmitsSecretAndClaimValues verifies bounded bearer telemetry.
func TestObservedBearerIntrospectorOmitsSecretAndClaimValues(t *testing.T) {
	recorder := &recordingAuthObservation{}
	client := ObserveBearerIntrospector(fakeBearerIntrospector{
		result: resultWithDecision(DecisionAuthenticated, observationBearerAccount, "session-observation-sentinel", "", map[string][]string{
			observationClaimTenant:     {observationTenantBlue},
			observationCustomClaimName: {observationBearerClaim},
		}),
	}, ObservationConfig{
		AuthorityName: observationAuthorityPrimary,
		BackendPool:   observationBackendPool,
		ListenerName:  observationProtocolIMAP,
		Recorder:      recorder,
		ServiceName:   observationServiceIMAP,
		Transport:     transportHTTP,
	})

	_, err := client.Introspect(context.Background(), BearerIntrospectionRequest{
		Context: RequestContext{
			ClientIP:          observationClientIP,
			ExternalSessionID: observationSecret,
			Protocol:          observationProtocolIMAP,
			Method:            observationMechanismBearer,
		},
		Mechanism:             observationMechanismBearer,
		AuthorizationIdentity: observationBearerAccount,
		BearerToken:           NewSecret(observationBearerToken),
	})
	if err != nil {
		t.Fatalf("Introspect returned error: %v", err)
	}

	event := requireAuthObservation(t, recorder)
	if got := event.MetricLabels[authObservationFieldTransport]; got != authObservationTransportBearer {
		t.Fatalf("transport label = %q, want %q", got, authObservationTransportBearer)
	}

	if got := event.MetricLabels[authObservationFieldMechanism]; got != "oauthbearer" {
		t.Fatalf("mechanism label = %q, want oauthbearer", got)
	}

	if err := event.MetricLabels.Validate(); err != nil {
		t.Fatalf("metric labels failed policy: %v", err)
	}

	for _, forbidden := range []string{
		observationBearerAccount,
		observationBearerClaim,
		observationBearerToken,
		observationSecret,
		observationCustomClaimName,
	} {
		assertAuthEventOmitsValue(t, event, forbidden)
	}

	for _, label := range observability.ForbiddenMetricLabels() {
		if _, ok := event.MetricLabels[label]; ok {
			t.Fatalf("metric labels included forbidden %q: %#v", label, event.MetricLabels)
		}
	}
}

type fakeAuthenticator struct {
	result AuthResult
	err    error
}

// Authenticate returns the configured auth result for observability tests.
func (a fakeAuthenticator) Authenticate(context.Context, AuthRequest) (AuthResult, error) {
	return a.result, a.err
}

type fakeBearerIntrospector struct {
	result AuthResult
	err    error
}

// Introspect returns the configured bearer result for observability tests.
func (i fakeBearerIntrospector) Introspect(context.Context, BearerIntrospectionRequest) (AuthResult, error) {
	return i.result, i.err
}

// runObservedAuth executes one observed authority call and returns its recorder.
func runObservedAuth(t *testing.T, authenticator fakeAuthenticator) *recordingAuthObservation {
	t.Helper()

	recorder := &recordingAuthObservation{}
	client := ObserveAuthenticator(authenticator, ObservationConfig{
		AuthorityName: observationAuthorityDefault,
		BackendPool:   observationBackendPool,
		ListenerName:  observationProtocolIMAP,
		Recorder:      recorder,
		ServiceName:   observationServiceIMAP,
		Transport:     transportHTTP,
	})

	_, _ = client.Authenticate(context.Background(), observedAuthRequest())

	return recorder
}

type recordingAuthObservation struct {
	events []observability.Event
}

// Record stores one auth observation for assertions.
func (r *recordingAuthObservation) Record(_ context.Context, event observability.Event) {
	r.events = append(r.events, event)
}

// last returns the latest auth observation with the supplied event name.
func (r *recordingAuthObservation) last(name string) (observability.Event, bool) {
	for index := len(r.events) - 1; index >= 0; index-- {
		if r.events[index].Name == name {
			return r.events[index], true
		}
	}

	return observability.Event{}, false
}

// requireAuthObservation returns the latest auth observation or fails the test.
func requireAuthObservation(t *testing.T, recorder *recordingAuthObservation) observability.Event {
	t.Helper()

	event, ok := recorder.last(observability.EventNauthilusAuth)
	if !ok {
		t.Fatalf("auth observation missing: %#v", recorder.events)
	}

	return event
}

// observedAuthRequest returns a credential-bearing request for telemetry safety tests.
func observedAuthRequest() AuthRequest {
	return AuthRequest{
		Context: RequestContext{
			Username:          observationUsername,
			ClientIP:          observationClientIP,
			ExternalSessionID: observationSecret,
			Protocol:          observationProtocolIMAP,
			Method:            observationMechanismPlain,
		},
		Credential: NewSecret(observationPassword),
	}
}

// assertAuthEventSecretSafe checks auth observations do not carry raw secrets.
func assertAuthEventSecretSafe(t *testing.T, event observability.Event) {
	t.Helper()

	for _, fields := range []map[string]string{event.LogFields, event.MetricLabels} {
		for key, value := range fields {
			assertDoesNotContainSecret(t, key, observationPassword)
			assertDoesNotContainSecret(t, value, observationPassword)
			assertDoesNotContainSecret(t, value, observationSecret)
		}
	}
}

// assertAuthEventOmitsValue checks bearer observations for forbidden sentinel text.
func assertAuthEventOmitsValue(t *testing.T, event observability.Event, value string) {
	t.Helper()

	for _, fields := range []map[string]string{event.LogFields, event.MetricLabels} {
		for key, fieldValue := range fields {
			assertDoesNotContainSecret(t, key, value)
			assertDoesNotContainSecret(t, fieldValue, value)
		}
	}
}
