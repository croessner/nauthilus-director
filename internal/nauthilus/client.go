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
	"sort"
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

const (
	authorityContextNameAuthorization      = "authorization"
	authorityContextNameProxyAuthorization = "proxy-authorization"
	authorityContextNameCookie             = "cookie"
	authorityContextNameSetCookie          = "set-cookie"
	authorityContextNameContentType        = "content-type"
	authorityContextNameAccept             = "accept"
	authorityContextNameHost               = "host"
	authorityContextNameTE                 = "te"
	authorityContextGRPCPrefix             = "grpc-"
)

// Authenticator verifies credentials through Nauthilus.
type Authenticator interface {
	Authenticate(ctx context.Context, request AuthRequest) (AuthResult, error)
}

// BearerIntrospector verifies mail SASL bearer tokens through Nauthilus OIDC.
type BearerIntrospector interface {
	Introspect(ctx context.Context, request BearerIntrospectionRequest) (AuthResult, error)
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
	HTTPClient       *http.Client
	GRPCService      GRPCAuthService
	AuthorityContext AuthorityContext
}

// AuthorityContext contains listener-owned static facts for authority transports.
type AuthorityContext struct {
	HTTPHeaders  map[string]string
	GRPCMetadata map[string]string
}

// authorityContextPair carries one deterministic authority context key-value pair.
type authorityContextPair struct {
	name  string
	value string
}

// NewClient selects the configured Nauthilus transport.
func NewClient(authority config.AuthorityConfig, options ClientOptions) (Client, error) {
	authorityContext := options.AuthorityContext.Normalize()

	switch strings.ToLower(strings.TrimSpace(authority.Transport)) {
	case transportHTTP:
		return NewHTTPClientFromAuthority(authority, options.HTTPClient, authorityContext)
	case transportGRPC:
		if options.GRPCService == nil {
			return NewGRPCClientFromAuthority(authority, authorityContext)
		}

		return NewGRPCClient(options.GRPCService)
	default:
		return nil, configError("transport must be http or grpc")
	}
}

// AuthorityContextFromConfig converts typed listener context into the client boundary type.
func AuthorityContextFromConfig(cfg config.AuthorityContextConfig) AuthorityContext {
	httpHeaders := make(map[string]string, len(cfg.HTTPHeaders))
	for name, value := range cfg.HTTPHeaders {
		httpHeaders[name] = string(value)
	}

	grpcMetadata := make(map[string]string, len(cfg.GRPCMetadata))
	for name, value := range cfg.GRPCMetadata {
		grpcMetadata[name] = string(value)
	}

	return AuthorityContext{
		HTTPHeaders:  httpHeaders,
		GRPCMetadata: grpcMetadata,
	}.Normalize()
}

// Normalize returns detached maps with stable transport spelling and trimmed values.
func (c AuthorityContext) Normalize() AuthorityContext {
	return AuthorityContext{
		HTTPHeaders:  normalizeHTTPContextValues(c.HTTPHeaders),
		GRPCMetadata: normalizeGRPCContextValues(c.GRPCMetadata),
	}
}

// httpHeaderPairs returns deterministic non-empty HTTP context headers.
func (c AuthorityContext) httpHeaderPairs() []authorityContextPair {
	return authorityContextPairs(c.Normalize().HTTPHeaders)
}

// grpcMetadataPairs returns deterministic non-empty gRPC context metadata.
func (c AuthorityContext) grpcMetadataPairs() []authorityContextPair {
	return authorityContextPairs(c.Normalize().GRPCMetadata)
}

// authorityContextPairs returns sorted non-empty context pairs accepted by transports.
func authorityContextPairs(values map[string]string) []authorityContextPair {
	pairs := make([]authorityContextPair, 0, len(values))

	for _, name := range sortedContextNames(values) {
		value := strings.TrimSpace(values[name])
		if value == "" || reservedAuthorityContextName(name) {
			continue
		}

		pairs = append(pairs, authorityContextPair{name: name, value: value})
	}

	return pairs
}

// grpcMetadataAppendPairs returns key-value pairs accepted by metadata.AppendToOutgoingContext.
func (c AuthorityContext) grpcMetadataAppendPairs() []string {
	metadataPairs := c.grpcMetadataPairs()
	values := make([]string, 0, len(metadataPairs)*2)

	for _, pair := range metadataPairs {
		values = append(values, pair.name, pair.value)
	}

	return values
}

// normalizeHTTPContextValues canonicalizes header names and trims configured values.
func normalizeHTTPContextValues(values map[string]string) map[string]string {
	if values == nil {
		return map[string]string{}
	}

	normalized := make(map[string]string, len(values))
	for _, name := range sortedContextNames(values) {
		canonical := http.CanonicalHeaderKey(strings.TrimSpace(name))
		normalized[canonical] = strings.TrimSpace(values[name])
	}

	return normalized
}

// normalizeGRPCContextValues trims metadata names and values without changing key case.
func normalizeGRPCContextValues(values map[string]string) map[string]string {
	if values == nil {
		return map[string]string{}
	}

	normalized := make(map[string]string, len(values))
	for _, name := range sortedContextNames(values) {
		normalized[strings.TrimSpace(name)] = strings.TrimSpace(values[name])
	}

	return normalized
}

// sortedContextNames returns deterministic map keys for authority context values.
func sortedContextNames(values map[string]string) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}

	sort.Strings(names)

	return names
}

// reservedAuthorityContextName reports names owned by credentials, sessions or transports.
func reservedAuthorityContextName(name string) bool {
	normalized := strings.ToLower(strings.TrimSpace(name))
	if strings.HasPrefix(normalized, authorityContextGRPCPrefix) {
		return true
	}

	switch normalized {
	case authorityContextNameAuthorization,
		authorityContextNameProxyAuthorization,
		authorityContextNameCookie,
		authorityContextNameSetCookie,
		authorityContextNameContentType,
		authorityContextNameAccept,
		authorityContextNameHost,
		authorityContextNameTE:
		return true
	default:
		return false
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
