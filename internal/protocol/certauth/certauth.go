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

// Package certauth binds verified TLS client certificates to canonical
// Nauthilus accounts for SASL EXTERNAL.
package certauth

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"

	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/protocol/tlscontext"
)

const methodExternal = "external"

var (
	// ErrCertificateUnavailable reports a missing active TLS certificate boundary.
	ErrCertificateUnavailable = errors.New("external authentication certificate unavailable")
	// ErrCertificateUnverified reports a presented certificate without a verified chain.
	ErrCertificateUnverified = errors.New("external authentication certificate unverified")
	// ErrIdentityUnavailable reports a verified certificate without one usable email SAN.
	ErrIdentityUnavailable = errors.New("external authentication identity unavailable")
	// ErrIdentityAmbiguous reports a verified certificate with multiple email SAN identities.
	ErrIdentityAmbiguous = errors.New("external authentication identity ambiguous")
	// ErrIdentityRejected reports that Nauthilus did not accept the certificate identity.
	ErrIdentityRejected = errors.New("external authentication identity rejected")
	// ErrAuthorizationDenied reports an authzid not bound to the certificate account.
	ErrAuthorizationDenied = errors.New("external authorization identity denied")
	// ErrAuthorityUnavailable reports a missing identity lookup dependency.
	ErrAuthorityUnavailable = errors.New("external authentication authority unavailable")
)

// Request contains one certificate-backed authentication attempt.
type Request struct {
	Context              nauthilus.RequestContext
	State                tls.ConnectionState
	AuthorizationID      string
	TLSActive            bool
	StateAvailable       bool
	AllowAuthorizationID bool
}

// Service resolves verified certificate identities through Nauthilus.
type Service struct {
	lookuper nauthilus.IdentityLookuper
}

// NewService creates a certificate identity service around one authority boundary.
func NewService(lookuper nauthilus.IdentityLookuper) *Service {
	return &Service{lookuper: lookuper}
}

// Available reports whether the connection has a successfully verified client certificate.
func Available(active bool, state tls.ConnectionState, stateAvailable bool) bool {
	return active && stateAvailable && len(state.PeerCertificates) > 0 && len(state.VerifiedChains) > 0
}

// Rejected reports whether an EXTERNAL failure is a local authentication denial.
func Rejected(err error) bool {
	return errors.Is(err, ErrCertificateUnavailable) ||
		errors.Is(err, ErrCertificateUnverified) ||
		errors.Is(err, ErrIdentityUnavailable) ||
		errors.Is(err, ErrIdentityAmbiguous) ||
		errors.Is(err, ErrIdentityRejected) ||
		errors.Is(err, ErrAuthorizationDenied)
}

// Authenticate resolves the certificate and optional authorization identity to one canonical account.
func (s *Service) Authenticate(ctx context.Context, request Request) (nauthilus.AuthResult, error) {
	identity, err := certificateIdentity(request)
	if err != nil {
		return nauthilus.AuthResult{}, err
	}

	if s == nil || s.lookuper == nil {
		return nauthilus.AuthResult{}, ErrAuthorityUnavailable
	}

	certificateResult, err := s.lookup(ctx, request, identity)
	if err != nil {
		return nauthilus.AuthResult{}, err
	}

	authorizationID := strings.TrimSpace(request.AuthorizationID)
	if authorizationID == "" || authorizationID == identity {
		return certificateResult, nil
	}

	if !request.AllowAuthorizationID {
		return nauthilus.AuthResult{}, ErrAuthorizationDenied
	}

	authorizationResult, err := s.lookup(ctx, request, authorizationID)
	if err != nil {
		if errors.Is(err, ErrIdentityRejected) {
			return nauthilus.AuthResult{}, ErrAuthorizationDenied
		}

		return nauthilus.AuthResult{}, err
	}

	if strings.TrimSpace(authorizationResult.Account) != strings.TrimSpace(certificateResult.Account) {
		return nauthilus.AuthResult{}, ErrAuthorizationDenied
	}

	return certificateResult, nil
}

// lookup asks Nauthilus to resolve one identity while preserving verified TLS facts.
func (s *Service) lookup(ctx context.Context, request Request, identity string) (nauthilus.AuthResult, error) {
	requestContext := tlscontext.Apply(request.Context, request.TLSActive, request.State, request.StateAvailable)
	requestContext.Username = identity
	requestContext.Method = methodExternal

	result, err := s.lookuper.LookupIdentity(ctx, nauthilus.IdentityLookupRequest{Context: requestContext})
	if err != nil {
		return nauthilus.AuthResult{}, err
	}

	if result.Decision == nauthilus.DecisionRejected {
		return nauthilus.AuthResult{}, ErrIdentityRejected
	}

	if result.Decision != nauthilus.DecisionAuthenticated || strings.TrimSpace(result.Account) == "" {
		return nauthilus.AuthResult{}, ErrAuthorityUnavailable
	}

	return result, nil
}

// certificateIdentity extracts exactly one rfc822Name SAN from a verified leaf certificate.
func certificateIdentity(request Request) (string, error) {
	if !request.TLSActive || !request.StateAvailable || len(request.State.PeerCertificates) == 0 {
		return "", ErrCertificateUnavailable
	}

	if len(request.State.VerifiedChains) == 0 {
		return "", ErrCertificateUnverified
	}

	identities := distinctEmailSANs(request.State.PeerCertificates[0].EmailAddresses)
	switch len(identities) {
	case 0:
		return "", ErrIdentityUnavailable
	case 1:
		return identities[0], nil
	default:
		return "", ErrIdentityAmbiguous
	}
}

// distinctEmailSANs trims empty values and removes exact duplicate certificate identities.
func distinctEmailSANs(values []string) []string {
	identities := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))

	for _, value := range values {
		identity := strings.TrimSpace(value)
		if identity == "" {
			continue
		}

		if _, exists := seen[identity]; exists {
			continue
		}

		seen[identity] = struct{}{}
		identities = append(identities, identity)
	}

	return identities
}
