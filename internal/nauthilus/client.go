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
	"net/http"
	"strings"

	"github.com/croessner/nauthilus-director/internal/config"
)

const (
	transportHTTP = "http"
	transportGRPC = "grpc"
)

type authOperation string

const (
	operationConfigure      authOperation = "configure"
	operationAuthenticate   authOperation = "authenticate"
	operationLookupIdentity authOperation = "lookup-identity"
	operationListAccounts   authOperation = "list-accounts"
)

// Authenticator verifies credentials through Nauthilus.
type Authenticator interface {
	Authenticate(ctx context.Context, request AuthRequest) (AuthResult, error)
}

// IdentityLookuper resolves identity attributes without sending credentials.
type IdentityLookuper interface {
	LookupIdentity(ctx context.Context, request IdentityLookupRequest) (AuthResult, error)
}

// AccountLister lists authority-owned accounts without director routing state.
type AccountLister interface {
	ListAccounts(ctx context.Context, request ListAccountsRequest) (ListAccountsResult, error)
}

// Client is the full director-to-Nauthilus authority boundary.
type Client interface {
	Authenticator
	IdentityLookuper
	AccountLister
}

// ClientOptions supplies transport dependencies that are not config values.
type ClientOptions struct {
	HTTPClient  *http.Client
	GRPCService GRPCAuthService
}

// NewClient selects the configured Nauthilus transport.
func NewClient(authority config.AuthorityConfig, options ClientOptions) (Client, error) {
	switch strings.ToLower(strings.TrimSpace(authority.Transport)) {
	case transportHTTP:
		return NewHTTPClientFromAuthority(authority, options.HTTPClient)
	case transportGRPC:
		if options.GRPCService == nil {
			return NewGRPCClientFromAuthority(authority)
		}

		return NewGRPCClient(options.GRPCService)
	default:
		return nil, configError("transport must be http or grpc")
	}
}

// validateAuthRequest enforces fail-closed credential auth input.
func validateAuthRequest(request AuthRequest) error {
	if err := validateRequestContext(operationAuthenticate, request.Context); err != nil {
		return err
	}

	if request.Credential.IsZero() {
		return invalidRequestError(operationAuthenticate, "credential")
	}

	return nil
}

// validateIdentityLookupRequest enforces fail-closed lookup input.
func validateIdentityLookupRequest(request IdentityLookupRequest) error {
	return validateRequestContext(operationLookupIdentity, request.Context)
}

// validateListAccountsRequest enforces fail-closed account-listing input.
func validateListAccountsRequest(request ListAccountsRequest) error {
	return validateRequestContext(operationListAccounts, request.Context)
}

// validateRequestContext rejects ambiguous authority request context.
func validateRequestContext(operation authOperation, context RequestContext) error {
	if strings.TrimSpace(context.Username) == "" {
		return invalidRequestError(operation, "username")
	}

	if strings.TrimSpace(context.Protocol) == "" {
		return invalidRequestError(operation, "protocol")
	}

	return nil
}
