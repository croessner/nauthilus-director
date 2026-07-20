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

package certauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/croessner/nauthilus-director/internal/nauthilus"
)

const (
	testAliasIdentity       = "alias@example.test"
	testCanonicalAccount    = "canonical@example.test"
	testCertificateIdentity = "cert@example.test"
	testOtherIdentity       = "other@example.test"
)

// TestServiceBindsVerifiedSANToCanonicalAccount proves the external identity and authzid contract.
func TestServiceBindsVerifiedSANToCanonicalAccount(t *testing.T) {
	lookuper := &recordingLookuper{results: map[string]nauthilus.AuthResult{
		testCertificateIdentity: authenticatedResult(testCanonicalAccount),
		testAliasIdentity:       authenticatedResult(testCanonicalAccount),
		testOtherIdentity:       authenticatedResult("other-account@example.test"),
	}}
	service := NewService(lookuper)
	request := Request{
		TLSActive:      true,
		State:          verifiedState(testCertificateIdentity),
		StateAvailable: true,
		Context:        nauthilus.RequestContext{Protocol: "imap"},
	}

	result, err := service.Authenticate(context.Background(), request)
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}

	if result.Account != testCanonicalAccount {
		t.Fatalf("account = %q, want canonical account", result.Account)
	}

	request.AuthorizationID = testAliasIdentity
	request.AllowAuthorizationID = true

	result, err = service.Authenticate(context.Background(), request)
	if err != nil {
		t.Fatalf("Authenticate alias returned error: %v", err)
	}

	if result.Account != testCanonicalAccount {
		t.Fatalf("alias account = %q, want canonical account", result.Account)
	}

	request.AuthorizationID = testOtherIdentity

	_, err = service.Authenticate(context.Background(), request)
	if !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("error = %v, want ErrAuthorizationDenied", err)
	}
}

// TestServiceRejectsUnverifiedOrAmbiguousCertificates proves certificate state fails closed.
func TestServiceRejectsUnverifiedOrAmbiguousCertificates(t *testing.T) {
	service := NewService(&recordingLookuper{})

	tests := []struct {
		name      string
		request   Request
		wantError error
	}{
		{name: "tls inactive", request: Request{}, wantError: ErrCertificateUnavailable},
		{
			name: "unverified",
			request: Request{
				TLSActive:      true,
				StateAvailable: true,
				State:          tls.ConnectionState{PeerCertificates: []*x509.Certificate{{EmailAddresses: []string{testCertificateIdentity}}}},
			},
			wantError: ErrCertificateUnverified,
		},
		{
			name: "missing email san",
			request: Request{
				TLSActive:      true,
				StateAvailable: true,
				State:          verifiedState(),
			},
			wantError: ErrIdentityUnavailable,
		},
		{
			name: "multiple email sans",
			request: Request{
				TLSActive:      true,
				StateAvailable: true,
				State:          verifiedState("one@example.test", "two@example.test"),
			},
			wantError: ErrIdentityAmbiguous,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := service.Authenticate(context.Background(), test.request)
			if !errors.Is(err, test.wantError) {
				t.Fatalf("error = %v, want %v", err, test.wantError)
			}
		})
	}
}

// TestServiceRejectsDistinctAuthorizationIDByDefault proves delegation is opt-in.
func TestServiceRejectsDistinctAuthorizationIDByDefault(t *testing.T) {
	service := NewService(&recordingLookuper{results: map[string]nauthilus.AuthResult{
		testCertificateIdentity: authenticatedResult(testCanonicalAccount),
	}})

	_, err := service.Authenticate(context.Background(), Request{
		TLSActive:       true,
		StateAvailable:  true,
		State:           verifiedState(testCertificateIdentity),
		AuthorizationID: testAliasIdentity,
		Context:         nauthilus.RequestContext{Protocol: "sieve"},
	})
	if !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("error = %v, want ErrAuthorizationDenied", err)
	}
}

// TestServicePreservesAuthorityFailures proves delegated lookup outages remain temporary failures.
func TestServicePreservesAuthorityFailures(t *testing.T) {
	service := NewService(&recordingLookuper{results: map[string]nauthilus.AuthResult{
		testCertificateIdentity: authenticatedResult(testCanonicalAccount),
		testAliasIdentity:       {Decision: nauthilus.DecisionTemporaryFailure},
	}})

	_, err := service.Authenticate(context.Background(), Request{
		TLSActive:            true,
		StateAvailable:       true,
		State:                verifiedState(testCertificateIdentity),
		AuthorizationID:      testAliasIdentity,
		AllowAuthorizationID: true,
	})
	if !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("error = %v, want ErrAuthorityUnavailable", err)
	}

	if Rejected(err) {
		t.Fatal("authority outage was classified as an authentication rejection")
	}
}

type recordingLookuper struct {
	results  map[string]nauthilus.AuthResult
	requests []nauthilus.IdentityLookupRequest
}

// LookupIdentity records one lookup and returns the configured canonical result.
func (l *recordingLookuper) LookupIdentity(_ context.Context, request nauthilus.IdentityLookupRequest) (nauthilus.AuthResult, error) {
	l.requests = append(l.requests, request)

	result, ok := l.results[request.Context.Username]
	if !ok {
		return nauthilus.AuthResult{Decision: nauthilus.DecisionRejected}, nil
	}

	return result, nil
}

// authenticatedResult creates one canonical authority success fixture.
func authenticatedResult(account string) nauthilus.AuthResult {
	return nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: account}
}

// verifiedState creates a minimal verified TLS client-certificate state.
func verifiedState(emails ...string) tls.ConnectionState {
	leaf := &x509.Certificate{EmailAddresses: emails}

	return tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf}},
	}
}
