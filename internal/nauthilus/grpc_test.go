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

//nolint:funlen,goconst,wsl_v5 // Tests keep gRPC mapping fixtures local.
package nauthilus

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestGRPCAuthenticateMapsAuthResult verifies AuthService maps to AuthResult only.
func TestGRPCAuthenticateMapsAuthResult(t *testing.T) {
	service := &recordingGRPCService{
		authResponse: &GRPCAuthResponse{
			OK:             true,
			Decision:       GRPCDecisionOK,
			Session:        "grpc-session",
			AccountField:   "alice",
			Backend:        42,
			BackendRefName: "mailstore-a",
			Attributes:     map[string][]string{"tenant": []string{"blue"}},
		},
	}
	client := newTestGRPCClient(t, service)

	result, err := client.Authenticate(context.Background(), testAuthRequest())
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if result.Decision != DecisionAuthenticated || result.Account != "alice" || result.SessionID != "grpc-session" {
		t.Fatalf("result = %#v", result)
	}
	if service.authRequest == nil {
		t.Fatal("gRPC service did not receive auth request")
	}
	if service.authRequest.Protocol != "imap" {
		t.Fatalf("protocol = %q, want imap", service.authRequest.Protocol)
	}
	if service.authRequest.Password.Value() != "secret-password" {
		t.Fatal("gRPC auth request did not carry credential material to authority adapter")
	}
	if strings.Contains(result.StatusMessage, "mailstore-a") {
		t.Fatalf("result leaked backend name: %#v", result)
	}
}

// TestGRPCLookupAndListAccountsMapBoundaries verifies non-auth RPC boundaries.
func TestGRPCLookupAndListAccountsMapBoundaries(t *testing.T) {
	service := &recordingGRPCService{
		lookupResponse: &GRPCAuthResponse{
			OK:           true,
			Decision:     GRPCDecisionOK,
			Session:      "lookup-session",
			AccountField: "lookup-account",
			Attributes:   map[string][]string{"shard": []string{"s1"}},
		},
		listResponse: &GRPCListAccountsResponse{
			Accounts: []string{"alpha@example.test", "zeta@example.test"},
			Decision: GRPCDecisionOK,
			Session:  "list-session",
		},
	}
	client := newTestGRPCClient(t, service)

	lookup, err := client.LookupIdentity(context.Background(), IdentityLookupRequest{
		Context: RequestContext{
			Username: "lookup@example.test",
			Protocol: "imap",
			Method:   "lookup",
		},
	})
	if err != nil {
		t.Fatalf("LookupIdentity returned error: %v", err)
	}
	if lookup.Account != "lookup-account" || lookup.Attributes["shard"][0] != "s1" {
		t.Fatalf("lookup = %#v", lookup)
	}

	list, err := client.ListAccounts(context.Background(), ListAccountsRequest{
		Context: RequestContext{
			Username: "list@example.test",
			Protocol: "imap",
			Method:   "list",
		},
	})
	if err != nil {
		t.Fatalf("ListAccounts returned error: %v", err)
	}
	if list.Decision != DecisionAuthenticated || list.SessionID != "list-session" {
		t.Fatalf("list = %#v", list)
	}
	if len(list.Accounts) != 2 || list.Accounts[0] != "alpha@example.test" {
		t.Fatalf("accounts = %#v", list.Accounts)
	}
}

// TestGRPCOutcomeClassification verifies rejected, tempfail and malformed mapping.
func TestGRPCOutcomeClassification(t *testing.T) {
	cases := []struct {
		name     string
		response *GRPCAuthResponse
		err      error
		want     string
		wantKind ErrorKind
	}{
		{name: "rejected", response: &GRPCAuthResponse{Decision: GRPCDecisionFail}, want: DecisionRejected},
		{name: "tempfail", response: &GRPCAuthResponse{Decision: GRPCDecisionTempFail}, want: DecisionTemporaryFailure, wantKind: ErrorKindTemporaryFailure},
		{name: "nil response", want: DecisionTemporaryFailure, wantKind: ErrorKindMalformedResponse},
		{name: "unknown decision", response: &GRPCAuthResponse{Decision: 99}, want: DecisionTemporaryFailure, wantKind: ErrorKindMalformedResponse},
		{name: "transport", err: errors.New("grpc unavailable"), want: DecisionTemporaryFailure, wantKind: ErrorKindTransport},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			client := newTestGRPCClient(t, &recordingGRPCService{
				authResponse: testCase.response,
				authErr:      testCase.err,
			})

			result, err := client.Authenticate(context.Background(), testAuthRequest())
			if result.Decision != testCase.want {
				t.Fatalf("decision = %q, want %q", result.Decision, testCase.want)
			}
			if testCase.wantKind == "" && err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if testCase.wantKind != "" && !IsAuthErrorKind(err, testCase.wantKind) {
				t.Fatalf("err = %v, want kind %q", err, testCase.wantKind)
			}
		})
	}
}

// TestGRPCRequestStringRedactsSecrets verifies scaffold request formatting is safe.
func TestGRPCRequestStringRedactsSecrets(t *testing.T) {
	request := GRPCAuthRequest{
		RequestContext: RequestContext{
			Username: "alice@example.test",
			Protocol: "imap",
			Method:   "plain",
		},
		Password: NewSecret("secret-password"),
	}

	text := request.String()
	assertDoesNotContainSecret(t, text, "secret-password")
	if !strings.Contains(text, redactedSecret) {
		t.Fatalf("redacted request = %q, want redacted marker", text)
	}
}

type recordingGRPCService struct {
	authRequest    *GRPCAuthRequest
	authResponse   *GRPCAuthResponse
	authErr        error
	lookupRequest  *GRPCLookupIdentityRequest
	lookupResponse *GRPCAuthResponse
	listRequest    *GRPCListAccountsRequest
	listResponse   *GRPCListAccountsResponse
}

// Authenticate records the request and returns the configured response.
func (s *recordingGRPCService) Authenticate(
	_ context.Context,
	request *GRPCAuthRequest,
) (*GRPCAuthResponse, error) {
	s.authRequest = request

	return s.authResponse, s.authErr
}

// LookupIdentity records the request and returns the configured response.
func (s *recordingGRPCService) LookupIdentity(
	_ context.Context,
	request *GRPCLookupIdentityRequest,
) (*GRPCAuthResponse, error) {
	s.lookupRequest = request

	return s.lookupResponse, nil
}

// ListAccounts records the request and returns the configured response.
func (s *recordingGRPCService) ListAccounts(
	_ context.Context,
	request *GRPCListAccountsRequest,
) (*GRPCListAccountsResponse, error) {
	s.listRequest = request

	return s.listResponse, nil
}

// newTestGRPCClient creates a scaffolded gRPC client for tests.
func newTestGRPCClient(t *testing.T, service GRPCAuthService) *GRPCClient {
	t.Helper()

	client, err := NewGRPCClient(service)
	if err != nil {
		t.Fatalf("NewGRPCClient: %v", err)
	}

	return client
}
