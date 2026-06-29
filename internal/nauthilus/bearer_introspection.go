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
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/croessner/nauthilus-director/internal/config"
)

const (
	defaultBearerIntrospectionRequiredScope = "email"
	bearerClaimAccount                      = "account"
	bearerClaimAccountKey                   = "account_key"
	bearerClaimMailAccount                  = "mail_account"
	bearerClaimDovecotAccount               = "dovecot_account"
	bearerClaimUsername                     = "username"
	bearerClaimPreferredUsername            = "preferred_username"
	bearerClaimSessionID                    = "session_id"
	bearerClaimSession                      = "session"
	bearerClaimSID                          = "sid"
	bearerClaimAccessToken                  = "access_token"
	bearerClaimRefreshToken                 = "refresh_token"
	bearerClaimIDToken                      = "id_token"
	bearerClaimToken                        = "token"
	bearerClaimClientSecret                 = "client_secret"
	bearerClaimPassword                     = "password"
	bearerClaimSecret                       = "secret"
	maxBearerAttributeNameBytes             = 128
	maxBearerAttributeValueBytes            = 1024
	maxBearerAttributeValues                = 32
	maxBearerSessionIDBytes                 = 128
)

var defaultBearerAccountClaimChain = []string{
	bearerClaimAccount,
	bearerClaimAccountKey,
	bearerClaimMailAccount,
	bearerClaimDovecotAccount,
	bearerClaimUsername,
	bearerClaimPreferredUsername,
	defaultBearerIntrospectionRequiredScope,
	jwtClaimSubject,
}

var safeBearerSessionClaimChain = []string{bearerClaimSessionID, bearerClaimSession, bearerClaimSID}

// BearerIntrospectionRequest carries one mail SASL bearer validation input.
type BearerIntrospectionRequest struct {
	Context               RequestContext
	Mechanism             string
	Protocol              string
	ListenerName          string
	AuthorityName         string
	AuthorizationIdentity string
	BearerToken           Secret
}

// LogFields returns secret-free fields for bearer introspection diagnostics.
func (r BearerIntrospectionRequest) LogFields() SafeFields {
	fields := safeContextFields(r.normalized().Context, operationAuthenticate)
	fields[safeFieldHasCredential] = boolString(!r.BearerToken.IsZero())

	return fields
}

// SASLBearerIntrospector validates mail SASL bearer tokens through Nauthilus OIDC.
type SASLBearerIntrospector struct {
	config   config.BearerIntrospectionConfig
	client   *http.Client
	metadata oidcMetadata
	now      func() time.Time
}

// NewSASLBearerIntrospectorFromAuthority builds a startup-time introspector for one authority.
func NewSASLBearerIntrospectorFromAuthority(
	ctx context.Context,
	authority config.AuthorityConfig,
	client *http.Client,
) (*SASLBearerIntrospector, error) {
	return NewSASLBearerIntrospector(ctx, authority.Mechanisms.Bearer.Introspection, client)
}

// NewSASLBearerIntrospector discovers and validates the Nauthilus introspection endpoint.
func NewSASLBearerIntrospector(
	ctx context.Context,
	introspection config.BearerIntrospectionConfig,
	client *http.Client,
) (*SASLBearerIntrospector, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if client == nil {
		client = http.DefaultClient
	}

	introspection = introspection.Normalize()
	if err := validateSASLBearerIntrospectionConfig(introspection); err != nil {
		return nil, err
	}

	metadata, err := fetchOIDCDiscoveryMetadata(ctx, client, oidcDiscoveryOptions{
		Issuer:                       introspection.Issuer,
		DiscoveryURL:                 introspection.DiscoveryURL,
		IntrospectionAuthMethod:      normalizedOIDCAuthMethod(introspection.AuthMethod),
		RequireIntrospectionEndpoint: true,
	})
	if err != nil {
		return nil, err
	}

	return &SASLBearerIntrospector{
		config:   introspection,
		client:   client,
		metadata: metadata,
		now:      time.Now,
	}, nil
}

// Introspect maps an active RFC 7662 response into the director auth result shape.
func (i *SASLBearerIntrospector) Introspect(ctx context.Context, request BearerIntrospectionRequest) (AuthResult, error) {
	if i == nil || i.client == nil {
		return resultWithDecision(DecisionTemporaryFailure, "", "", "", nil), configError("sasl bearer introspector is not configured")
	}

	if ctx == nil {
		ctx = context.Background()
	}

	result, err := i.requestIntrospection(ctx, request.normalized())
	if err != nil {
		return resultWithDecision(DecisionTemporaryFailure, "", "", "", nil), err
	}

	return i.mapIntrospectionResult(result)
}

// normalized returns canonical request metadata without mutating secret-bearing input.
func (r BearerIntrospectionRequest) normalized() BearerIntrospectionRequest {
	r.Mechanism = strings.ToLower(strings.TrimSpace(r.Mechanism))
	r.Protocol = strings.ToLower(strings.TrimSpace(r.Protocol))
	r.ListenerName = strings.TrimSpace(r.ListenerName)
	r.AuthorityName = strings.TrimSpace(r.AuthorityName)
	r.AuthorizationIdentity = strings.TrimSpace(r.AuthorizationIdentity)

	if r.Context.Method == "" {
		r.Context.Method = r.Mechanism
	}

	if r.Context.Protocol == "" {
		r.Context.Protocol = r.Protocol
	}

	if r.Context.Username == "" {
		r.Context.Username = r.AuthorizationIdentity
	}

	return r
}

// requestIntrospection performs one uncached RFC 7662 request.
func (i *SASLBearerIntrospector) requestIntrospection(
	ctx context.Context,
	request BearerIntrospectionRequest,
) (OIDCIntrospectionResult, error) {
	token := strings.TrimSpace(request.BearerToken.Value())
	if token == "" {
		return OIDCIntrospectionResult{}, invalidRequestError(operationAuthenticate, "bearer token")
	}

	form := url.Values{}
	form.Set(oidcIntrospectionTokenParam, token)

	method := normalizedOIDCAuthMethod(i.config.AuthMethod)
	clientAuth := oidcEndpointAuthFromBearerIntrospection(i.config)

	clientSecret, err := applyOIDCEndpointClientAuth(form, i.metadata.IntrospectionEndpoint, method, clientAuth, i.now)
	if err != nil {
		return OIDCIntrospectionResult{}, err
	}

	httpRequest, err := newOIDCFormRequest(ctx, i.metadata.IntrospectionEndpoint, form, "oidc introspection_endpoint is invalid")
	if err != nil {
		return OIDCIntrospectionResult{}, err
	}

	applyOIDCRequestClientAuth(httpRequest, method, clientAuth, clientSecret)

	response, err := i.client.Do(httpRequest)
	if err != nil {
		return OIDCIntrospectionResult{}, transportError(operationAuthenticate, err)
	}
	defer func() {
		_ = response.Body.Close()
	}()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return OIDCIntrospectionResult{}, tempfailError(operationAuthenticate, response.StatusCode, "oidc introspection failed")
	}

	var payload map[string]any

	decoder := json.NewDecoder(io.LimitReader(response.Body, maxHTTPResponseBytes))
	if err := decoder.Decode(&payload); err != nil {
		return OIDCIntrospectionResult{}, malformedResponseError(operationAuthenticate, "invalid oidc introspection response", err)
	}

	return saslBearerIntrospectionFromClaims(payload)
}

// mapIntrospectionResult enforces active, scope and account policy before success.
func (i *SASLBearerIntrospector) mapIntrospectionResult(result OIDCIntrospectionResult) (AuthResult, error) {
	if !result.Active {
		return resultWithDecision(DecisionRejected, "", "", "bearer token inactive", nil), nil
	}

	if !result.MatchesAudienceOrResource(i.config.RequiredAudience, i.config.RequiredResource) {
		return resultWithDecision(DecisionRejected, "", "", "bearer token audience or resource mismatch", nil), nil
	}

	requiredScope := strings.TrimSpace(i.config.RequiredScope)
	if requiredScope == "" {
		requiredScope = defaultBearerIntrospectionRequiredScope
	}

	if !bearerScopePresent(result.Scopes, requiredScope) {
		return resultWithDecision(DecisionRejected, "", "", "required bearer scope missing", nil), nil
	}

	account, ok := bearerAccountFromClaims(result.Claims, i.config.AccountClaim)
	if !ok {
		return resultWithDecision(DecisionRejected, "", "", "bearer account claim missing", nil), nil
	}

	return resultWithDecision(
		DecisionAuthenticated,
		account,
		bearerSessionIDFromClaims(result.Claims),
		"",
		safeBearerAttributes(result.Claims, i.config.AccountClaim),
	), nil
}

// validateSASLBearerIntrospectionConfig checks local endpoint auth inputs.
func validateSASLBearerIntrospectionConfig(introspection config.BearerIntrospectionConfig) error {
	if !introspection.Enabled {
		return configError("sasl bearer introspection is not enabled")
	}

	if strings.TrimSpace(introspection.Issuer) == "" && strings.TrimSpace(introspection.DiscoveryURL) == "" {
		return configError("oidc issuer or discovery_url is required")
	}

	if strings.TrimSpace(introspection.ClientID) == "" {
		return configError("oidc client_id is required")
	}

	if strings.TrimSpace(introspection.RequiredScope) == "" {
		return configError("oidc required_scope is required")
	}

	if strings.TrimSpace(introspection.RequiredAudience) == "" && strings.TrimSpace(introspection.RequiredResource) == "" {
		return configError("oidc required_audience or required_resource is required")
	}

	if secretBearingBearerClaimName(introspection.AccountClaim) {
		return configError("oidc account_claim must not name a secret-bearing claim")
	}

	secretCount := enabledSecretCount(introspection.ClientSecret, introspection.ClientSecretFile)
	if secretCount > 1 {
		return configError("oidc must not configure both client_secret and client_secret_file")
	}

	if err := validateSASLBearerEndpointAuthMaterial(introspection, secretCount); err != nil {
		return err
	}

	return validateOIDCAssertionAlg(introspection.ClientAssertionAlg)
}

// validateSASLBearerEndpointAuthMaterial checks one configured endpoint auth method.
func validateSASLBearerEndpointAuthMaterial(introspection config.BearerIntrospectionConfig, secretCount int) error {
	switch normalizedOIDCAuthMethod(introspection.AuthMethod) {
	case oidcAuthMethodClientSecretBasic, oidcAuthMethodClientSecretPost:
		return validateOIDCSecretMaterial(secretCount, oidcAuthPurposeIntrospection)
	case oidcAuthMethodPrivateKeyJWT:
		if introspection.ClientPrivateKeyFile.IsZero() {
			return configError("oidc client_private_key_file is required for private_key_jwt introspection")
		}

		return nil
	default:
		return validateOIDCUnsupportedAuthMethod(oidcAuthPurposeIntrospection)
	}
}

// saslBearerIntrospectionFromClaims normalizes Nauthilus introspection response fields.
func saslBearerIntrospectionFromClaims(claims map[string]any) (OIDCIntrospectionResult, error) {
	return introspectionFromClaimsForOperation(claims, operationAuthenticate)
}

// bearerScopePresent reports whether the required end-user scope is present.
func bearerScopePresent(scopes []string, required string) bool {
	required = strings.TrimSpace(required)
	for _, scope := range scopes {
		if strings.TrimSpace(scope) == required {
			return true
		}
	}

	return false
}

// bearerAccountFromClaims resolves the configured or default account claim.
func bearerAccountFromClaims(claims map[string]any, configuredClaim string) (string, bool) {
	configuredClaim = strings.TrimSpace(configuredClaim)
	if configuredClaim != "" {
		return safeBearerStringClaim(claims, configuredClaim, maxBearerAttributeValueBytes)
	}

	for _, claim := range defaultBearerAccountClaimChain {
		if value, ok := safeBearerStringClaim(claims, claim, maxBearerAttributeValueBytes); ok {
			return value, true
		}
	}

	return "", false
}

// bearerSessionIDFromClaims returns only accepted bounded session-oriented values.
func bearerSessionIDFromClaims(claims map[string]any) string {
	for _, claim := range safeBearerSessionClaimChain {
		if value, ok := safeBearerStringClaim(claims, claim, maxBearerSessionIDBytes); ok {
			return value
		}
	}

	return ""
}

// safeBearerAttributes copies bounded non-secret non-identity scalar claims for routing.
func safeBearerAttributes(claims map[string]any, configuredAccountClaim string) map[string][]string {
	attributes := make(map[string][]string, len(claims))
	for name, value := range claims {
		name = strings.TrimSpace(name)
		if !safeBearerClaimName(name) ||
			secretBearingBearerClaimName(name) ||
			identityBearingBearerClaimName(name, configuredAccountClaim) {
			continue
		}

		values := safeBearerAttributeValues(name, value)
		if len(values) > 0 {
			attributes[name] = values
		}
	}

	if len(attributes) == 0 {
		return nil
	}

	return attributes
}

// safeBearerAttributeValues converts bounded scalar and scope-list claims.
func safeBearerAttributeValues(name string, value any) []string {
	switch typed := value.(type) {
	case string:
		if name == oidcClaimScope {
			return safeBearerScopeTextValues(typed)
		}

		if text, ok := safeBearerAttributeString(typed, maxBearerAttributeValueBytes); ok {
			return []string{text}
		}
	case bool:
		return []string{strconv.FormatBool(typed)}
	case float64:
		if !math.IsInf(typed, 0) && !math.IsNaN(typed) {
			return []string{strconv.FormatFloat(typed, 'g', -1, 64)}
		}
	case []any:
		if name == oidcClaimScope {
			return safeBearerScopeAttributeValues(typed)
		}
	}

	return nil
}

// safeBearerScopeTextValues accepts bounded scope values from a string claim.
func safeBearerScopeTextValues(value string) []string {
	scopes := make([]string, 0, min(len(strings.Fields(value)), maxBearerAttributeValues))
	for scope := range strings.FieldsSeq(value) {
		if len(scopes) >= maxBearerAttributeValues {
			return scopes
		}

		if scope, ok := safeBearerAttributeString(scope, maxBearerAttributeValueBytes); ok {
			scopes = append(scopes, scope)
		}
	}

	return scopes
}

// safeBearerScopeAttributeValues accepts only bounded string-list scope values.
func safeBearerScopeAttributeValues(values []any) []string {
	scopes := make([]string, 0, min(len(values), maxBearerAttributeValues))
	for _, value := range values {
		text, ok := value.(string)
		if !ok {
			continue
		}

		for scope := range strings.FieldsSeq(text) {
			if len(scopes) >= maxBearerAttributeValues {
				return scopes
			}

			if scope, ok := safeBearerAttributeString(scope, maxBearerAttributeValueBytes); ok {
				scopes = append(scopes, scope)
			}
		}
	}

	return scopes
}

// safeBearerStringClaim returns one bounded string claim.
func safeBearerStringClaim(claims map[string]any, name string, maxBytes int) (string, bool) {
	value, ok := claims[name].(string)
	if !ok {
		return "", false
	}

	return safeBearerAttributeString(value, maxBytes)
}

// safeBearerAttributeString trims and validates a bounded printable scalar.
func safeBearerAttributeString(value string, maxBytes int) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxBytes {
		return "", false
	}

	for _, char := range value {
		if !unicode.IsPrint(char) || char == '\n' || char == '\r' || char == '\t' {
			return "", false
		}
	}

	return value, true
}

// safeBearerClaimName reports whether the claim key is bounded and printable.
func safeBearerClaimName(value string) bool {
	if value == "" || len(value) > maxBearerAttributeNameBytes {
		return false
	}

	for _, char := range value {
		if !unicode.IsPrint(char) || unicode.IsSpace(char) {
			return false
		}
	}

	return true
}

// identityBearingBearerClaimName reports account/session claims that should not become generic attributes.
func identityBearingBearerClaimName(value string, configuredAccountClaim string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return false
	}

	if configured := strings.ToLower(strings.TrimSpace(configuredAccountClaim)); configured != "" && normalized == configured {
		return true
	}

	if slices.Contains(defaultBearerAccountClaimChain, normalized) {
		return true
	}

	return slices.Contains(safeBearerSessionClaimChain, normalized)
}

// secretBearingBearerClaimName reports claims that must not be copied or used as accounts.
func secretBearingBearerClaimName(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case "":
		return false
	case bearerClaimAccessToken,
		bearerClaimRefreshToken,
		bearerClaimIDToken,
		bearerClaimToken,
		bearerClaimClientSecret,
		bearerClaimPassword,
		bearerClaimSecret:
		return true
	}

	return strings.Contains(normalized, bearerClaimToken) ||
		strings.Contains(normalized, bearerClaimSecret) ||
		strings.Contains(normalized, bearerClaimPassword) ||
		strings.Contains(normalized, "credential") ||
		strings.Contains(normalized, "assertion") ||
		strings.Contains(normalized, "private_key")
}
