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
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/croessner/nauthilus-director/internal/config"
)

const (
	defaultOIDCDiscoveryPath        = "/.well-known/openid-configuration"
	grantTypeClientCredentials      = "client_credentials"
	oidcAuthMethodClientSecretBasic = "client_secret_basic"
	oidcAuthMethodClientSecretPost  = "client_secret_post"
	oidcAuthMethodPrivateKeyJWT     = "private_key_jwt"
	oidcAssertionAlgRS256           = "RS256"
	oidcAssertionAlgEdDSA           = "EdDSA"
	oidcAssertionTypeJWTBearer      = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	oidcFormClientAssertion         = "client_assertion"
	oidcFormClientAssertionType     = "client_assertion_type"
	oidcFormClientID                = "client_id"
	oidcFormClientSecret            = "client_secret"
	oidcFormContentType             = "application/x-www-form-urlencoded"
	oidcIntrospectionTokenParam     = "token"
	oidcClaimActive                 = "active"
	oidcClaimAuthorizedParty        = "azp"
	oidcClaimScope                  = "scope"
	jwtClaimAudience                = "aud"
	jwtClaimIssuer                  = "iss"
	jwtClaimSubject                 = "sub"
	jwtHeaderAlgorithm              = "alg"
	jwtHeaderKeyID                  = "kid"
	jwtHeaderType                   = "typ"
	tokenTypeBearer                 = "bearer"
	maxOIDCPrivateKeyFileBytes      = 64 * 1024
	pemTypePrivateKey               = "PRIVATE KEY"
	pemTypeRSAPrivateKey            = "RSA PRIVATE KEY"
)

type callerTokenSource interface {
	BearerToken(ctx context.Context) (string, error)
}

// OIDCIntrospectionResult contains secret-safe token introspection claims.
type OIDCIntrospectionResult struct {
	Active   bool
	Subject  string
	ClientID string
	Audience string
	Scopes   []string
	Claims   map[string]any
}

// OIDCIntrospector validates incoming control-plane bearer tokens through Nauthilus.
type OIDCIntrospector struct {
	source *oidcTokenSource
}

type oidcTokenSource struct {
	config config.AuthorityOIDCConfig
	client *http.Client
	now    func() time.Time
	jitter func(time.Duration) time.Duration

	mu       sync.Mutex
	metadata *oidcMetadata
	cached   cachedOIDCToken
}

type oidcTokenSourceOptions struct {
	client *http.Client
	now    func() time.Time
	jitter func(time.Duration) time.Duration
}

type oidcDiscoveryOptions struct {
	Issuer                                      string
	DiscoveryURL                                string
	TokenEndpointOverride                       string
	TokenAuthMethod                             string
	IntrospectionAuthMethod                     string
	RequireTokenEndpoint                        bool
	RequireIntrospectionEndpoint                bool
	RequireClientCredentialsGrant               bool
	RequireTokenAuthMethodAdvertisement         bool
	RequireIntrospectionAuthMethodAdvertisement bool
}

type oidcEndpointClientAuth struct {
	ClientID             string
	ClientSecret         config.SecretString
	ClientSecretFile     config.SecretString
	ClientPrivateKeyFile config.SecretString
	ClientKeyID          string
	ClientAssertionAlg   string
	Audience             string
}

type oidcMetadata struct {
	Issuer                string
	TokenEndpoint         string
	IntrospectionEndpoint string
}

type cachedOIDCToken struct {
	accessToken string
	expiresAt   time.Time
	refreshAt   time.Time
}

type oidcDiscoveryDocument struct {
	Issuer                                    string   `json:"issuer"`
	TokenEndpoint                             string   `json:"token_endpoint"`
	IntrospectionEndpoint                     string   `json:"introspection_endpoint"`
	GrantTypesSupported                       []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported         []string `json:"token_endpoint_auth_methods_supported"`
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported"`
}

type oidcTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

// NewOIDCIntrospectorFromAuthority builds an introspector for one configured Nauthilus authority.
func NewOIDCIntrospectorFromAuthority(authority config.AuthorityConfig, client *http.Client) (*OIDCIntrospector, error) {
	return NewOIDCIntrospector(authority.OIDC, client)
}

// NewOIDCIntrospector builds a lazy discovery-backed token introspector.
func NewOIDCIntrospector(oidcConfig config.AuthorityOIDCConfig, client *http.Client) (*OIDCIntrospector, error) {
	source, err := newOIDCTokenSource(oidcConfig, oidcTokenSourceOptions{client: client})
	if err != nil {
		return nil, err
	}

	return &OIDCIntrospector{source: source}, nil
}

// Introspect validates one bearer token through the discovered Nauthilus endpoint.
func (i *OIDCIntrospector) Introspect(ctx context.Context, token string) (OIDCIntrospectionResult, error) {
	if i == nil || i.source == nil {
		return OIDCIntrospectionResult{}, configError("oidc introspector is not configured")
	}

	return i.source.introspect(ctx, token)
}

// newOIDCTokenSourceFromAuthority builds the caller token source for one authority.
func newOIDCTokenSourceFromAuthority(authority config.AuthorityConfig, client *http.Client) (*oidcTokenSource, error) {
	return newOIDCTokenSource(authority.OIDC, oidcTokenSourceOptions{client: client})
}

// newOIDCTokenSource builds a lazy discovery and client-credentials token source.
func newOIDCTokenSource(oidcConfig config.AuthorityOIDCConfig, options oidcTokenSourceOptions) (*oidcTokenSource, error) {
	if !oidcConfig.Enabled || !oidcConfig.ClientCredentials.Enabled {
		return nil, configError("oidc client credentials are not enabled")
	}

	client := options.client
	if client == nil {
		client = http.DefaultClient
	}

	now := options.now
	if now == nil {
		now = time.Now
	}

	jitter := options.jitter
	if jitter == nil {
		jitter = defaultOIDCJitter
	}

	source := &oidcTokenSource{
		config: oidcConfig,
		client: client,
		now:    now,
		jitter: jitter,
	}

	if err := source.validateLocalConfig(); err != nil {
		return nil, err
	}

	return source, nil
}

// BearerToken returns an unexpired caller token, refreshing early when needed.
func (s *oidcTokenSource) BearerToken(ctx context.Context) (string, error) {
	if s == nil {
		return "", configError("oidc token source is not configured")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	if s.cached.freshAt(now) {
		return s.cached.accessToken, nil
	}

	previous := s.cached

	token, err := s.refreshLocked(ctx, now)
	if err == nil {
		return token.accessToken, nil
	}

	if previous.validAt(s.now()) {
		return previous.accessToken, nil
	}

	return "", err
}

// validateLocalConfig checks secret-bearing client-credentials inputs before use.
func (s *oidcTokenSource) validateLocalConfig() error {
	credentials := s.config.ClientCredentials

	if err := s.validateLocalIssuer(); err != nil {
		return err
	}

	if strings.TrimSpace(credentials.ClientID) == "" {
		return configError("oidc client_id is required")
	}

	secretCount := enabledSecretCount(credentials.ClientSecret, credentials.ClientSecretFile)
	if secretCount > 1 {
		return configError("oidc must not configure both client_secret and client_secret_file")
	}

	if err := validateOIDCAuthMaterial(
		normalizedOIDCAuthMethod(credentials.TokenEndpointAuthMethod),
		secretCount,
		credentials,
		oidcAuthPurposeToken,
	); err != nil {
		return err
	}

	introspectionMethod := s.introspectionAuthMethod()
	if introspectionMethod != "" {
		if err := validateOIDCAuthMaterial(introspectionMethod, secretCount, credentials, oidcAuthPurposeIntrospection); err != nil {
			return err
		}
	}

	if err := validateOIDCAssertionAlg(credentials.ClientAssertionAlg); err != nil {
		return err
	}

	if len(credentials.Scopes) == 0 {
		return configError("oidc client_credentials scopes are required")
	}

	if credentials.RefreshBeforeExpiry <= 0 {
		return configError("oidc refresh_before_expiry must be greater than zero")
	}

	return nil
}

// validateLocalIssuer checks the minimum discovery input.
func (s *oidcTokenSource) validateLocalIssuer() error {
	if strings.TrimSpace(s.config.Issuer) == "" && strings.TrimSpace(s.config.DiscoveryURL) == "" {
		return configError("oidc issuer or discovery_url is required")
	}

	return nil
}

const (
	oidcAuthPurposeToken         = "token"
	oidcAuthPurposeIntrospection = "introspection"
)

// validateOIDCAuthMaterial checks the configured client authentication material.
func validateOIDCAuthMaterial(
	method string,
	secretCount int,
	credentials config.AuthorityOIDCClientCredentialsConfig,
	purpose string,
) error {
	switch method {
	case oidcAuthMethodClientSecretBasic, oidcAuthMethodClientSecretPost:
		return validateOIDCSecretMaterial(secretCount, purpose)
	case oidcAuthMethodPrivateKeyJWT:
		return validateOIDCPrivateKeyMaterial(credentials, purpose)
	default:
		return validateOIDCUnsupportedAuthMethod(purpose)
	}
}

// validateOIDCSecretMaterial requires exactly one configured client secret.
func validateOIDCSecretMaterial(secretCount int, purpose string) error {
	if secretCount == 1 {
		return nil
	}

	if purpose == oidcAuthPurposeIntrospection {
		return configError("oidc must configure exactly one client_secret or client_secret_file for introspection auth")
	}

	return configError("oidc must configure exactly one client_secret or client_secret_file for secret-based token auth")
}

// validateOIDCPrivateKeyMaterial requires mounted private-key material.
func validateOIDCPrivateKeyMaterial(
	credentials config.AuthorityOIDCClientCredentialsConfig,
	purpose string,
) error {
	if !credentials.ClientPrivateKeyFile.IsZero() {
		return nil
	}

	if purpose == oidcAuthPurposeIntrospection {
		return configError("oidc client_private_key_file is required for private_key_jwt introspection")
	}

	return configError("oidc client_private_key_file is required for private_key_jwt")
}

// validateOIDCUnsupportedAuthMethod reports the configured unsupported auth field.
func validateOIDCUnsupportedAuthMethod(purpose string) error {
	if purpose == oidcAuthPurposeIntrospection {
		return configError("oidc introspection_endpoint_auth_method is unsupported")
	}

	return configError("oidc token_endpoint_auth_method is unsupported")
}

// validateOIDCAssertionAlg checks the private_key_jwt signing algorithm.
func validateOIDCAssertionAlg(value string) error {
	switch strings.TrimSpace(value) {
	case "", oidcAssertionAlgRS256, oidcAssertionAlgEdDSA:
		return nil
	default:
		return configError("oidc client_assertion_alg is unsupported")
	}
}

// refreshLocked obtains a replacement token while the source mutex is held.
func (s *oidcTokenSource) refreshLocked(ctx context.Context, now time.Time) (cachedOIDCToken, error) {
	metadata, err := s.discoveryMetadataLocked(ctx)
	if err != nil {
		return cachedOIDCToken{}, err
	}

	response, err := s.requestToken(ctx, metadata.TokenEndpoint)
	if err != nil {
		return cachedOIDCToken{}, err
	}

	token, err := s.cacheToken(response, now)
	if err != nil {
		return cachedOIDCToken{}, err
	}

	s.cached = token

	return token, nil
}

// discoveryMetadataLocked returns validated cached discovery metadata.
func (s *oidcTokenSource) discoveryMetadataLocked(ctx context.Context) (oidcMetadata, error) {
	if s.metadata != nil {
		return *s.metadata, nil
	}

	metadata, err := fetchOIDCDiscoveryMetadata(ctx, s.client, s.discoveryOptions())
	if err != nil {
		return oidcMetadata{}, err
	}

	s.metadata = &metadata

	return metadata, nil
}

// discoveryOptions returns the caller-token discovery requirements.
func (s *oidcTokenSource) discoveryOptions() oidcDiscoveryOptions {
	introspectionMethod := s.introspectionAuthMethod()

	return oidcDiscoveryOptions{
		Issuer:                                      s.config.Issuer,
		DiscoveryURL:                                s.config.DiscoveryURL,
		TokenEndpointOverride:                       s.config.ClientCredentials.TokenEndpoint,
		TokenAuthMethod:                             normalizedOIDCAuthMethod(s.config.ClientCredentials.TokenEndpointAuthMethod),
		IntrospectionAuthMethod:                     introspectionMethod,
		RequireTokenEndpoint:                        true,
		RequireIntrospectionEndpoint:                true,
		RequireClientCredentialsGrant:               true,
		RequireTokenAuthMethodAdvertisement:         true,
		RequireIntrospectionAuthMethodAdvertisement: introspectionMethod != "",
	}
}

// fetchOIDCDiscoveryMetadata fetches and validates process-local OIDC metadata.
func fetchOIDCDiscoveryMetadata(
	ctx context.Context,
	client *http.Client,
	options oidcDiscoveryOptions,
) (oidcMetadata, error) {
	discoveryURL, err := resolveOIDCDiscoveryURL(options)
	if err != nil {
		return oidcMetadata{}, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return oidcMetadata{}, configError("oidc discovery_url is invalid")
	}

	request.Header.Set("Accept", defaultHTTPContentType)

	response, err := client.Do(request)
	if err != nil {
		return oidcMetadata{}, transportError(operationConfigure, err)
	}
	defer func() {
		_ = response.Body.Close()
	}()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return oidcMetadata{}, tempfailError(operationConfigure, response.StatusCode, "oidc discovery failed")
	}

	var document oidcDiscoveryDocument

	decoder := json.NewDecoder(io.LimitReader(response.Body, maxHTTPResponseBytes))
	if err := decoder.Decode(&document); err != nil {
		return oidcMetadata{}, malformedResponseError(operationConfigure, "invalid oidc discovery document", err)
	}

	return validateOIDCDiscoveryDocument(document, options)
}

// resolveOIDCDiscoveryURL resolves the configured issuer or direct discovery URL.
func resolveOIDCDiscoveryURL(options oidcDiscoveryOptions) (string, error) {
	if discoveryURL := strings.TrimSpace(options.DiscoveryURL); discoveryURL != "" {
		return discoveryURL, nil
	}

	issuer := strings.TrimRight(strings.TrimSpace(options.Issuer), "/")
	if issuer == "" {
		return "", configError("oidc issuer or discovery_url is required")
	}

	return issuer + defaultOIDCDiscoveryPath, nil
}

// validateOIDCDiscoveryDocument checks Nauthilus metadata before endpoint use.
func validateOIDCDiscoveryDocument(document oidcDiscoveryDocument, options oidcDiscoveryOptions) (oidcMetadata, error) {
	if err := validateOIDCDiscoveryIssuer(document, options); err != nil {
		return oidcMetadata{}, err
	}

	if err := validateOIDCDiscoveryCapabilities(document, options); err != nil {
		return oidcMetadata{}, err
	}

	tokenEndpoint, err := oidcDiscoveryTokenEndpoint(document, options)
	if err != nil {
		return oidcMetadata{}, err
	}

	introspectionEndpoint := strings.TrimSpace(document.IntrospectionEndpoint)
	if options.RequireIntrospectionEndpoint {
		if err := validateOIDCEndpointURL(introspectionEndpoint, "oidc discovery introspection_endpoint"); err != nil {
			return oidcMetadata{}, err
		}
	}

	return oidcMetadata{
		Issuer:                strings.TrimSpace(document.Issuer),
		TokenEndpoint:         tokenEndpoint,
		IntrospectionEndpoint: introspectionEndpoint,
	}, nil
}

// validateOIDCDiscoveryIssuer checks issuer presence and optional issuer pinning.
func validateOIDCDiscoveryIssuer(document oidcDiscoveryDocument, options oidcDiscoveryOptions) error {
	if strings.TrimSpace(document.Issuer) == "" {
		return malformedResponseError(operationConfigure, "oidc discovery issuer is required", nil)
	}

	configuredIssuer := strings.TrimRight(strings.TrimSpace(options.Issuer), "/")
	if configuredIssuer == "" {
		return nil
	}

	if strings.TrimRight(strings.TrimSpace(document.Issuer), "/") != configuredIssuer {
		return malformedResponseError(operationConfigure, "oidc discovery issuer mismatch", nil)
	}

	return nil
}

// validateOIDCDiscoveryCapabilities checks advertised Nauthilus OIDC capabilities.
func validateOIDCDiscoveryCapabilities(document oidcDiscoveryDocument, options oidcDiscoveryOptions) error {
	if options.RequireTokenEndpoint && strings.TrimSpace(document.TokenEndpoint) == "" {
		return malformedResponseError(operationConfigure, "oidc discovery token_endpoint is required", nil)
	}

	if options.RequireIntrospectionEndpoint && strings.TrimSpace(document.IntrospectionEndpoint) == "" {
		return malformedResponseError(operationConfigure, "oidc discovery introspection_endpoint is required", nil)
	}

	if options.RequireClientCredentialsGrant && !containsFold(document.GrantTypesSupported, grantTypeClientCredentials) {
		return malformedResponseError(operationConfigure, "oidc discovery does not support client_credentials", nil)
	}

	if err := validateOIDCDiscoveryAuthMethod(
		document.TokenEndpointAuthMethodsSupported,
		options.TokenAuthMethod,
		options.RequireTokenAuthMethodAdvertisement,
		"configured token auth method",
	); err != nil {
		return err
	}

	return validateOIDCDiscoveryAuthMethod(
		document.IntrospectionEndpointAuthMethodsSupported,
		options.IntrospectionAuthMethod,
		options.RequireIntrospectionAuthMethodAdvertisement,
		"configured introspection auth method",
	)
}

// validateOIDCDiscoveryAuthMethod checks a configured method against advertised support.
func validateOIDCDiscoveryAuthMethod(supported []string, method string, requireAdvertisement bool, label string) error {
	method = normalizedOIDCAuthMethod(method)
	if method == "" {
		return nil
	}

	if len(supported) == 0 && !requireAdvertisement {
		return nil
	}

	if !containsFold(supported, method) {
		return malformedResponseError(operationConfigure, "oidc discovery does not support "+label, nil)
	}

	return nil
}

// oidcDiscoveryTokenEndpoint returns the validated token endpoint when required.
func oidcDiscoveryTokenEndpoint(document oidcDiscoveryDocument, options oidcDiscoveryOptions) (string, error) {
	tokenEndpoint := strings.TrimSpace(document.TokenEndpoint)
	if override := strings.TrimSpace(options.TokenEndpointOverride); override != "" {
		tokenEndpoint = override
	}

	if !options.RequireTokenEndpoint && tokenEndpoint == "" {
		return "", nil
	}

	if err := validateOIDCEndpointURL(tokenEndpoint, "oidc discovery token_endpoint"); err != nil {
		return "", err
	}

	return tokenEndpoint, nil
}

// requestToken performs the client-credentials token endpoint call.
func (s *oidcTokenSource) requestToken(ctx context.Context, tokenEndpoint string) (oidcTokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", grantTypeClientCredentials)
	form.Set("scope", strings.Join(s.config.ClientCredentials.Scopes, " "))

	method := normalizedOIDCAuthMethod(s.config.ClientCredentials.TokenEndpointAuthMethod)
	clientAuth := oidcEndpointAuthFromClientCredentials(s.config.ClientCredentials)

	clientSecret, err := s.applyOIDCClientAuth(form, tokenEndpoint, method)
	if err != nil {
		return oidcTokenResponse{}, err
	}

	request, err := newOIDCFormRequest(ctx, tokenEndpoint, form, "oidc token_endpoint is invalid")
	if err != nil {
		return oidcTokenResponse{}, err
	}

	applyOIDCRequestClientAuth(request, method, clientAuth, clientSecret)

	response, err := s.client.Do(request)
	if err != nil {
		return oidcTokenResponse{}, transportError(operationConfigure, err)
	}
	defer func() {
		_ = response.Body.Close()
	}()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return oidcTokenResponse{}, tempfailError(operationConfigure, response.StatusCode, "oidc token request failed")
	}

	var tokenResponse oidcTokenResponse

	decoder := json.NewDecoder(io.LimitReader(response.Body, maxHTTPResponseBytes))
	if err := decoder.Decode(&tokenResponse); err != nil {
		return oidcTokenResponse{}, malformedResponseError(operationConfigure, "invalid oidc token response", err)
	}

	return tokenResponse, nil
}

// introspect performs the RFC 7662 request with Nauthilus client authentication.
func (s *oidcTokenSource) introspect(ctx context.Context, token string) (OIDCIntrospectionResult, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return OIDCIntrospectionResult{}, configError("oidc introspection token is required")
	}

	metadata, err := s.discoveryMetadataForUse(ctx)
	if err != nil {
		return OIDCIntrospectionResult{}, err
	}

	form := url.Values{}
	form.Set(oidcIntrospectionTokenParam, token)

	method := s.introspectionAuthMethod()
	if method == "" {
		return OIDCIntrospectionResult{}, configError("oidc introspection_endpoint_auth_method is required")
	}

	clientAuth := oidcEndpointAuthFromClientCredentials(s.config.ClientCredentials)

	clientSecret, err := s.applyOIDCClientAuth(form, metadata.IntrospectionEndpoint, method)
	if err != nil {
		return OIDCIntrospectionResult{}, err
	}

	request, err := newOIDCFormRequest(ctx, metadata.IntrospectionEndpoint, form, "oidc introspection_endpoint is invalid")
	if err != nil {
		return OIDCIntrospectionResult{}, err
	}

	applyOIDCRequestClientAuth(request, method, clientAuth, clientSecret)

	response, err := s.client.Do(request)
	if err != nil {
		return OIDCIntrospectionResult{}, transportError(operationConfigure, err)
	}
	defer func() {
		_ = response.Body.Close()
	}()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return OIDCIntrospectionResult{}, tempfailError(operationConfigure, response.StatusCode, "oidc introspection failed")
	}

	var payload map[string]any

	decoder := json.NewDecoder(io.LimitReader(response.Body, maxHTTPResponseBytes))
	if err := decoder.Decode(&payload); err != nil {
		return OIDCIntrospectionResult{}, malformedResponseError(operationConfigure, "invalid oidc introspection response", err)
	}

	return oidcIntrospectionFromClaims(payload)
}

// applyOIDCClientAuth adds selected Nauthilus client authentication to a form.
func (s *oidcTokenSource) applyOIDCClientAuth(form url.Values, endpoint string, method string) (string, error) {
	return applyOIDCEndpointClientAuth(
		form,
		endpoint,
		method,
		oidcEndpointAuthFromClientCredentials(s.config.ClientCredentials),
		s.now,
	)
}

// applyOIDCEndpointClientAuth adds selected Nauthilus client authentication to a form.
func applyOIDCEndpointClientAuth(
	form url.Values,
	endpoint string,
	method string,
	clientAuth oidcEndpointClientAuth,
	now func() time.Time,
) (string, error) {
	switch method {
	case oidcAuthMethodClientSecretBasic:
		return clientAuth.clientSecret()
	case oidcAuthMethodClientSecretPost:
		clientSecret, err := clientAuth.clientSecret()
		if err != nil {
			return "", err
		}

		form.Set(oidcFormClientID, strings.TrimSpace(clientAuth.ClientID))
		form.Set(oidcFormClientSecret, clientSecret)

		return clientSecret, nil
	case oidcAuthMethodPrivateKeyJWT:
		assertion, err := clientAuth.privateKeyJWT(endpoint, now)
		if err != nil {
			return "", err
		}

		form.Set(oidcFormClientID, strings.TrimSpace(clientAuth.ClientID))
		form.Set(oidcFormClientAssertionType, oidcAssertionTypeJWTBearer)
		form.Set(oidcFormClientAssertion, assertion)

		return "", nil
	default:
		return "", configError("oidc client authentication method is unsupported")
	}
}

// applyOIDCRequestClientAuth clears stale Authorization before request client auth is applied.
func applyOIDCRequestClientAuth(request *http.Request, method string, clientAuth oidcEndpointClientAuth, clientSecret string) {
	request.Header.Del("Authorization")

	if method == oidcAuthMethodClientSecretBasic {
		request.SetBasicAuth(strings.TrimSpace(clientAuth.ClientID), clientSecret)
	}
}

// newOIDCFormRequest builds a bounded form request with shared headers.
func newOIDCFormRequest(
	ctx context.Context,
	endpoint string,
	form url.Values,
	invalidEndpointMessage string,
) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, configError(invalidEndpointMessage)
	}

	request.Header.Set("Content-Type", oidcFormContentType)
	request.Header.Set("Accept", defaultHTTPContentType)

	return request, nil
}

// discoveryMetadataForUse serializes lazy discovery for introspection callers.
func (s *oidcTokenSource) discoveryMetadataForUse(ctx context.Context) (oidcMetadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.discoveryMetadataLocked(ctx)
}

// oidcEndpointAuthFromClientCredentials adapts caller-auth config to endpoint auth material.
func oidcEndpointAuthFromClientCredentials(credentials config.AuthorityOIDCClientCredentialsConfig) oidcEndpointClientAuth {
	return oidcEndpointClientAuth{
		ClientID:             credentials.ClientID,
		ClientSecret:         credentials.ClientSecret,
		ClientSecretFile:     credentials.ClientSecretFile,
		ClientPrivateKeyFile: credentials.ClientPrivateKeyFile,
		ClientKeyID:          credentials.ClientKeyID,
		ClientAssertionAlg:   credentials.ClientAssertionAlg,
		Audience:             credentials.Audience,
	}
}

// oidcEndpointAuthFromBearerIntrospection adapts SASL bearer config to endpoint auth material.
func oidcEndpointAuthFromBearerIntrospection(introspection config.BearerIntrospectionConfig) oidcEndpointClientAuth {
	return oidcEndpointClientAuth{
		ClientID:             introspection.ClientID,
		ClientSecret:         introspection.ClientSecret,
		ClientSecretFile:     introspection.ClientSecretFile,
		ClientPrivateKeyFile: introspection.ClientPrivateKeyFile,
		ClientKeyID:          introspection.ClientKeyID,
		ClientAssertionAlg:   introspection.ClientAssertionAlg,
	}
}

// privateKeyJWT builds an RFC 7523 client assertion for Nauthilus endpoint requests.
func (a oidcEndpointClientAuth) privateKeyJWT(endpoint string, now func() time.Time) (string, error) {
	header := map[string]any{
		jwtHeaderAlgorithm: a.clientAssertionAlg(),
		jwtHeaderType:      "JWT",
	}
	if keyID := strings.TrimSpace(a.ClientKeyID); keyID != "" {
		header[jwtHeaderKeyID] = keyID
	}

	if now == nil {
		now = time.Now
	}

	timestamp := now()
	claims := map[string]any{
		jwtClaimIssuer:   strings.TrimSpace(a.ClientID),
		jwtClaimSubject:  strings.TrimSpace(a.ClientID),
		jwtClaimAudience: a.clientAssertionAudience(endpoint),
		"iat":            timestamp.Unix(),
		"exp":            timestamp.Add(time.Minute).Unix(),
	}

	jti, err := randomJWTID()
	if err != nil {
		return "", configError("failed to create oidc client assertion id")
	}

	claims["jti"] = jti

	encodedHeader, err := encodeJWTPart(header)
	if err != nil {
		return "", configError("failed to encode oidc client assertion header")
	}

	encodedClaims, err := encodeJWTPart(claims)
	if err != nil {
		return "", configError("failed to encode oidc client assertion claims")
	}

	signingInput := encodedHeader + "." + encodedClaims

	signature, err := a.signJWTAssertion([]byte(signingInput))
	if err != nil {
		return "", err
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// clientAssertionAlg returns the configured signing algorithm with Nauthilus' default.
func (a oidcEndpointClientAuth) clientAssertionAlg() string {
	if alg := strings.TrimSpace(a.ClientAssertionAlg); alg != "" {
		return alg
	}

	return oidcAssertionAlgRS256
}

// clientAssertionAudience returns the audience Nauthilus verifies for private_key_jwt.
func (a oidcEndpointClientAuth) clientAssertionAudience(endpoint string) string {
	if audience := strings.TrimSpace(a.Audience); audience != "" {
		return audience
	}

	return strings.TrimSpace(endpoint)
}

// signJWTAssertion signs a prepared JWT signing input with the configured private key.
func (a oidcEndpointClientAuth) signJWTAssertion(signingInput []byte) ([]byte, error) {
	raw, err := a.readClientPrivateKey()
	if err != nil {
		return nil, err
	}

	key, err := parseClientPrivateKey(raw)
	if err != nil {
		return nil, err
	}

	switch a.clientAssertionAlg() {
	case oidcAssertionAlgRS256:
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, configError("oidc private_key_jwt RS256 requires an RSA private key")
		}

		digest := sha256.Sum256(signingInput)

		return rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest[:])
	case oidcAssertionAlgEdDSA:
		edKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, configError("oidc private_key_jwt EdDSA requires an Ed25519 private key")
		}

		return ed25519.Sign(edKey, signingInput), nil
	default:
		return nil, configError("oidc client_assertion_alg is unsupported")
	}
}

// readClientPrivateKey reads mounted private-key material with a conservative size bound.
func (a oidcEndpointClientAuth) readClientPrivateKey() ([]byte, error) {
	path := strings.TrimSpace(a.ClientPrivateKeyFile.Value())
	if path == "" {
		return nil, configError("oidc client_private_key_file is required")
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, configError("failed to read oidc client_private_key_file")
	}
	defer func() {
		_ = file.Close()
	}()

	content, err := io.ReadAll(io.LimitReader(file, maxOIDCPrivateKeyFileBytes+1))
	if err != nil {
		return nil, configError("failed to read oidc client_private_key_file")
	}

	if len(content) > maxOIDCPrivateKeyFileBytes {
		return nil, configError("oidc client_private_key_file is too large")
	}

	return content, nil
}

// clientSecret resolves inline protected secret material or a mounted secret file.
func (a oidcEndpointClientAuth) clientSecret() (string, error) {
	if !a.ClientSecretFile.IsZero() {
		content, err := os.ReadFile(a.ClientSecretFile.Value())
		if err != nil {
			return "", configError("failed to read oidc client_secret_file")
		}

		secret := strings.TrimRight(string(content), "\r\n")
		if secret == "" {
			return "", configError("oidc client_secret_file is empty")
		}

		return secret, nil
	}

	secret := a.ClientSecret.Value()
	if secret == "" {
		return "", configError("oidc client_secret is empty")
	}

	return secret, nil
}

// cacheToken validates token fields and computes conservative refresh timing.
func (s *oidcTokenSource) cacheToken(response oidcTokenResponse, now time.Time) (cachedOIDCToken, error) {
	accessToken := strings.TrimSpace(response.AccessToken)
	if accessToken == "" {
		return cachedOIDCToken{}, malformedResponseError(operationConfigure, "oidc token response access_token is required", nil)
	}

	if response.TokenType != "" && !strings.EqualFold(strings.TrimSpace(response.TokenType), tokenTypeBearer) {
		return cachedOIDCToken{}, malformedResponseError(operationConfigure, "oidc token response token_type is unsupported", nil)
	}

	if response.ExpiresIn <= 0 {
		return cachedOIDCToken{}, malformedResponseError(operationConfigure, "oidc token response expires_in must be positive", nil)
	}

	expiresAt := now.Add(time.Duration(response.ExpiresIn) * time.Second)
	refreshBefore := s.config.ClientCredentials.RefreshBeforeExpiry.Std()
	refreshAt := expiresAt.Add(-refreshBefore).Add(-s.jitter(refreshBefore))

	return cachedOIDCToken{
		accessToken: accessToken,
		expiresAt:   expiresAt,
		refreshAt:   refreshAt,
	}, nil
}

// validAt reports whether the cached token can still be sent to Nauthilus.
func (t cachedOIDCToken) validAt(now time.Time) bool {
	return t.accessToken != "" && now.Before(t.expiresAt)
}

// freshAt reports whether the cached token does not need early refresh yet.
func (t cachedOIDCToken) freshAt(now time.Time) bool {
	return t.validAt(now) && now.Before(t.refreshAt)
}

// enabledSecretCount counts configured protected secret sources.
func enabledSecretCount(values ...config.SecretString) int {
	count := 0

	for _, value := range values {
		if !value.IsZero() {
			count++
		}
	}

	return count
}

// parseClientPrivateKey accepts RSA and Ed25519 PEM private keys for private_key_jwt.
func parseClientPrivateKey(raw []byte) (any, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, configError("oidc client_private_key_file must contain PEM private key material")
	}

	switch block.Type {
	case pemTypeRSAPrivateKey:
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, configError("oidc RSA private key is invalid")
		}

		return key, nil
	case pemTypePrivateKey:
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, configError("oidc private key is invalid")
		}

		switch typed := key.(type) {
		case *rsa.PrivateKey, ed25519.PrivateKey:
			return typed, nil
		default:
			return nil, configError("oidc private_key_jwt requires RSA or Ed25519 key material")
		}
	default:
		return nil, configError("oidc client_private_key_file must contain an RSA or PKCS8 private key")
	}
}

// encodeJWTPart serializes one JWT part with unpadded base64url encoding.
func encodeJWTPart(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(data), nil
}

// randomJWTID returns a cryptographically random compact assertion identifier.
func randomJWTID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

// introspectionAuthMethod returns a Nauthilus-supported RFC 7662 client auth method.
func (s *oidcTokenSource) introspectionAuthMethod() string {
	method := normalizedOIDCAuthMethod(s.config.ClientCredentials.IntrospectionEndpointAuthMethod)
	if method != "" {
		return method
	}

	switch tokenMethod := normalizedOIDCAuthMethod(s.config.ClientCredentials.TokenEndpointAuthMethod); tokenMethod {
	case oidcAuthMethodClientSecretBasic, oidcAuthMethodClientSecretPost, oidcAuthMethodPrivateKeyJWT:
		return tokenMethod
	default:
		return ""
	}
}

// normalizedOIDCAuthMethod canonicalizes configured token endpoint auth methods.
func normalizedOIDCAuthMethod(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// containsFold reports whether a list contains value case-insensitively.
func containsFold(values []string, value string) bool {
	for _, candidate := range values {
		if strings.EqualFold(strings.TrimSpace(candidate), value) {
			return true
		}
	}

	return false
}

// oidcIntrospectionFromClaims normalizes Nauthilus introspection response fields.
func oidcIntrospectionFromClaims(claims map[string]any) (OIDCIntrospectionResult, error) {
	return introspectionFromClaimsForOperation(claims, operationConfigure)
}

// introspectionFromClaimsForOperation normalizes shared RFC 7662 response fields.
func introspectionFromClaimsForOperation(claims map[string]any, operation authOperation) (OIDCIntrospectionResult, error) {
	active, ok := claims[oidcClaimActive].(bool)
	if !ok {
		return OIDCIntrospectionResult{}, malformedResponseError(operation, "oidc introspection active field is required", nil)
	}

	if !active {
		return OIDCIntrospectionResult{Active: false, Claims: cloneClaims(claims)}, nil
	}

	return OIDCIntrospectionResult{
		Active:   true,
		Subject:  stringClaim(claims, jwtClaimSubject),
		ClientID: firstNonEmptyClaim(claims, oidcFormClientID, oidcClaimAuthorizedParty),
		Audience: audienceClaim(claims[jwtClaimAudience]),
		Scopes:   scopesClaim(claims[oidcClaimScope]),
		Claims:   cloneClaims(claims),
	}, nil
}

// stringClaim returns one trimmed string claim.
func stringClaim(claims map[string]any, name string) string {
	value, ok := claims[name].(string)
	if !ok {
		return ""
	}

	return strings.TrimSpace(value)
}

// firstNonEmptyClaim returns the first non-empty string claim.
func firstNonEmptyClaim(claims map[string]any, names ...string) string {
	for _, name := range names {
		if value := stringClaim(claims, name); value != "" {
			return value
		}
	}

	return ""
}

// audienceClaim normalizes string and array audience shapes.
func audienceClaim(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case []any:
		values := make([]string, 0, len(typed))
		for _, entry := range typed {
			text, ok := entry.(string)
			if !ok {
				continue
			}

			text = strings.TrimSpace(text)
			if text != "" {
				values = append(values, text)
			}
		}

		return strings.Join(values, " ")
	default:
		return ""
	}
}

// scopesClaim normalizes string and array scope response shapes.
func scopesClaim(value any) []string {
	switch typed := value.(type) {
	case string:
		return fieldsWithoutEmpty(typed)
	case []any:
		scopes := make([]string, 0, len(typed))
		for _, entry := range typed {
			text, ok := entry.(string)
			if !ok {
				continue
			}

			scopes = append(scopes, fieldsWithoutEmpty(text)...)
		}

		return scopes
	default:
		return nil
	}
}

// fieldsWithoutEmpty splits whitespace-separated claims and drops empty entries.
func fieldsWithoutEmpty(value string) []string {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return nil
	}

	return fields
}

// cloneClaims detaches introspection claims from the JSON decoder map.
func cloneClaims(claims map[string]any) map[string]any {
	if len(claims) == 0 {
		return nil
	}

	clone := make(map[string]any, len(claims))
	maps.Copy(clone, claims)

	return clone
}

// validateOIDCEndpointURL rejects non-HTTPS non-loopback metadata endpoints.
func validateOIDCEndpointURL(value string, field string) error {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return malformedResponseError(operationConfigure, field+" is invalid", err)
	}

	if parsed.Scheme == "https" {
		return nil
	}

	if parsed.Scheme == "http" && isLoopbackOIDCHost(parsed.Hostname()) {
		return nil
	}

	return malformedResponseError(operationConfigure, field+" must use https outside loopback", nil)
}

// isLoopbackOIDCHost reports whether an HTTP endpoint is restricted to local tests.
func isLoopbackOIDCHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return strings.HasPrefix(host, "127.")
	}
}

// defaultOIDCJitter returns a small random skew bounded by the refresh window.
func defaultOIDCJitter(window time.Duration) time.Duration {
	if window <= 0 {
		return 0
	}

	maxJitter := min(window/10, 30*time.Second)
	if maxJitter <= 0 {
		return 0
	}

	value, err := rand.Int(rand.Reader, big.NewInt(int64(maxJitter)))
	if err != nil {
		return 0
	}

	return time.Duration(value.Int64())
}
