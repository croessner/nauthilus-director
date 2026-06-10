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

//nolint:wsl_v5 // REST auth parsing keeps small fail-closed validation steps adjacent.
package rest

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/rest/adapters"
	"github.com/croessner/nauthilus-director/internal/rest/generated"
	"github.com/croessner/nauthilus-director/internal/runtime"
)

const (
	authMethodBasic               = "basic"
	authMethodMTLS                = "mtls"
	authMethodOIDC                = "oidc"
	authMethodStaticBearer        = "static_bearer"
	authSchemeBearer              = "bearer"
	defaultActorStatic            = "static-bearer"
	pathHealthz                   = "/healthz"
	pathMetrics                   = "/metrics"
	pathReadyz                    = "/readyz"
	maxRouteLookupInspectionBytes = 1 << 20
	maxStaticBearerTokenBytes     = 64 << 10
	problemCodeForbidden          = "forbidden"
	problemCodeUnauthorized       = "unauthorized"
)

var (
	errControlForbidden    = errors.New("control auth forbidden")
	errControlUnauthorized = errors.New("control auth unauthorized")
)

// ControlAuthOptions configures the control-plane authentication boundary.
type ControlAuthOptions struct {
	Config           config.ControlServerConfig
	Authorities      map[string]config.AuthorityConfig
	HTTPClient       *http.Client
	OIDCIntrospector OIDCIntrospector
}

// OIDCIntrospector validates incoming bearer tokens through Nauthilus.
type OIDCIntrospector interface {
	Introspect(ctx context.Context, token string) (nauthilus.OIDCIntrospectionResult, error)
}

// ControlAuthenticator is the control-plane guard around generated routes.
type ControlAuthenticator struct {
	config       config.ControlServerConfig
	introspector OIDCIntrospector
}

// ControlAuthState carries authorization facts for stronger protected operations.
type ControlAuthState struct {
	Actor      runtime.Actor
	Protected  bool
	Scopes     []string
	AuthMethod string
}

type controlAuthContextKey struct{}

// NewControlAuthenticator creates the configured control API guard.
func NewControlAuthenticator(options ControlAuthOptions) ControlAuthenticator {
	control := options.Config
	if zeroControlAuth(control.Auth) {
		control = config.DefaultConfig().Runtime.Servers.Control
	}

	authenticator := ControlAuthenticator{config: control, introspector: options.OIDCIntrospector}
	if authenticator.introspector == nil && control.Auth.OIDC.Enabled {
		authorityName := strings.TrimSpace(control.Auth.OIDC.Authority)
		if authority, ok := options.Authorities[authorityName]; ok {
			introspector, err := nauthilus.NewOIDCIntrospectorFromAuthority(authority, options.HTTPClient)
			if err == nil {
				authenticator.introspector = introspector
			}
		}
	}

	return authenticator
}

// zeroControlAuth reports whether no authentication configuration was supplied.
func zeroControlAuth(auth config.ControlAuthConfig) bool {
	return !auth.Basic.Enabled &&
		strings.TrimSpace(auth.Basic.Username) == "" &&
		auth.Basic.PasswordFile.IsZero() &&
		!auth.Bearer.Enabled &&
		auth.Bearer.TokenFile.IsZero() &&
		!auth.OIDC.Enabled &&
		strings.TrimSpace(auth.OIDC.Authority) == "" &&
		strings.TrimSpace(auth.OIDC.Validation) == "" &&
		len(auth.OIDC.RequiredScopes) == 0 &&
		len(auth.OIDC.ProtectedScopes) == 0 &&
		!auth.MTLS.Enabled
}

// Wrap applies request guards before generated request decoding.
func (a ControlAuthenticator) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.publicControlPath(r) {
			next.ServeHTTP(w, r)
			return
		}

		state, err := a.authenticate(r)
		if err != nil {
			a.writeAuthFailure(w, err)
			return
		}

		ctx := WithControlAuthState(runtime.WithActor(r.Context(), state.Actor), state)
		r = r.WithContext(ctx)

		if a.shouldInspectRouteLookup(r) {
			if ok := a.inspectRouteLookupBody(w, r); !ok {
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// WithControlAuthState stores control authorization state in a request context.
func WithControlAuthState(ctx context.Context, state ControlAuthState) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}

	return context.WithValue(ctx, controlAuthContextKey{}, state)
}

// ControlAuthStateFromContext returns authorization state set by the REST boundary.
func ControlAuthStateFromContext(ctx context.Context) (ControlAuthState, bool) {
	if ctx == nil {
		return ControlAuthState{}, false
	}

	state, ok := ctx.Value(controlAuthContextKey{}).(ControlAuthState)
	return state, ok
}

// ProtectedContextAuthorizer grants protected config only to protected control actors.
type ProtectedContextAuthorizer struct{}

// AuthorizeProtectedConfig checks the stronger protected authorization bit from context.
func (ProtectedContextAuthorizer) AuthorizeProtectedConfig(
	ctx context.Context,
	_ adapters.ProtectedConfigRequest,
) (bool, error) {
	state, ok := ControlAuthStateFromContext(ctx)
	if !ok {
		return false, nil
	}

	return state.Protected, nil
}

// publicControlPath reports endpoints documented as safe without authentication.
func (a ControlAuthenticator) publicControlPath(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}

	switch r.URL.Path {
	case pathHealthz, pathReadyz:
		return true
	default:
		return false
	}
}

// authenticate resolves one configured authentication mode for a protected request.
func (a ControlAuthenticator) authenticate(r *http.Request) (ControlAuthState, error) {
	if username, password, basicPresent := r.BasicAuth(); basicPresent {
		if a.config.Auth.Basic.Enabled && a.basicAuthPath(r) {
			state, ok := a.authenticateBasic(username, password)
			if ok {
				return state, nil
			}
		}

		return ControlAuthState{}, errControlUnauthorized
	}

	token, bearerPresent, malformed := bearerToken(r.Header.Get("Authorization"))
	if malformed {
		return ControlAuthState{}, errControlUnauthorized
	}

	if bearerPresent {
		if a.config.Auth.Bearer.Enabled {
			state, ok := a.authenticateStaticBearer(token)
			if ok {
				return state, nil
			}
		}
		if a.config.Auth.OIDC.Enabled {
			return a.authenticateOIDC(r.Context(), token)
		}

		return ControlAuthState{}, errControlUnauthorized
	}

	if a.config.Auth.MTLS.Enabled {
		state, ok := a.authenticateMTLS(r)
		if ok {
			return state, nil
		}
	}

	return ControlAuthState{}, errControlUnauthorized
}

// basicAuthPath limits Prometheus-friendly Basic auth to the scrape endpoint.
func (a ControlAuthenticator) basicAuthPath(r *http.Request) bool {
	return r.Method == http.MethodGet && r.URL.Path == pathMetrics
}

// authenticateBasic checks the configured username and password file in constant time.
func (a ControlAuthenticator) authenticateBasic(username string, password string) (ControlAuthState, bool) {
	expectedPassword, err := readStaticBasicPassword(a.config.Auth.Basic.PasswordFile)
	if err != nil {
		return ControlAuthState{}, false
	}
	if !constantTimeEqualString(username, strings.TrimSpace(a.config.Auth.Basic.Username)) {
		return ControlAuthState{}, false
	}
	if !constantTimeEqualString(password, expectedPassword) {
		return ControlAuthState{}, false
	}

	actor := runtime.Actor{ID: username, AuthMethod: authMethodBasic, Authenticated: true}

	return ControlAuthState{Actor: actor, AuthMethod: authMethodBasic}, true
}

// authenticateStaticBearer checks the configured token file in constant time.
func (a ControlAuthenticator) authenticateStaticBearer(token string) (ControlAuthState, bool) {
	expected, err := readStaticBearerToken(a.config.Auth.Bearer.TokenFile)
	if err != nil {
		return ControlAuthState{}, false
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(expected)) != 1 {
		return ControlAuthState{}, false
	}

	actor := runtime.Actor{ID: defaultActorStatic, AuthMethod: authMethodStaticBearer, Authenticated: true}

	return ControlAuthState{Actor: actor, AuthMethod: authMethodStaticBearer}, true
}

// authenticateOIDC calls Nauthilus introspection and enforces configured scopes.
func (a ControlAuthenticator) authenticateOIDC(ctx context.Context, token string) (ControlAuthState, error) {
	if a.introspector == nil {
		return ControlAuthState{}, errControlUnauthorized
	}

	result, err := a.introspector.Introspect(ctx, token)
	if err != nil || !result.Active {
		return ControlAuthState{}, errControlUnauthorized
	}
	if !hasRequiredScopes(result.Scopes, a.config.Auth.OIDC.RequiredScopes) {
		return ControlAuthState{}, errControlForbidden
	}

	actor := runtime.Actor{
		ID:            oidcActorID(result),
		AuthMethod:    authMethodOIDC,
		Authenticated: true,
	}

	return ControlAuthState{
		Actor:      actor,
		Protected:  hasRequiredScopes(result.Scopes, a.config.Auth.OIDC.ProtectedScopes),
		Scopes:     append([]string(nil), result.Scopes...),
		AuthMethod: authMethodOIDC,
	}, nil
}

// authenticateMTLS accepts only verified TLS client certificates.
func (a ControlAuthenticator) authenticateMTLS(r *http.Request) (ControlAuthState, bool) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return ControlAuthState{}, false
	}

	certificate := r.TLS.PeerCertificates[0]
	actor := runtime.Actor{
		ID:            mtlsActorID(certificate),
		AuthMethod:    authMethodMTLS,
		Authenticated: true,
	}

	return ControlAuthState{Actor: actor, AuthMethod: authMethodMTLS}, true
}

// writeAuthFailure writes stable auth failure responses without mode-specific details.
func (a ControlAuthenticator) writeAuthFailure(w http.ResponseWriter, err error) {
	if errors.Is(err, errControlForbidden) {
		writeProblem(w, http.StatusForbidden, problemCodeForbidden, "requested operation is not authorized", "")
		return
	}

	if a.config.Auth.Basic.Enabled {
		w.Header().Set("WWW-Authenticate", `Basic realm="nauthilus-director"`)
	}
	writeProblem(w, http.StatusUnauthorized, problemCodeUnauthorized, "authentication required", "")
}

// shouldInspectRouteLookup reports whether the request targets route lookup.
func (a ControlAuthenticator) shouldInspectRouteLookup(r *http.Request) bool {
	return r.Method == http.MethodPost && r.URL.Path == "/api/v1/route/lookup"
}

// inspectRouteLookupBody rejects credential- or mailbox-bearing route diagnostics early.
func (a ControlAuthenticator) inspectRouteLookupBody(w http.ResponseWriter, r *http.Request) bool {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRouteLookupInspectionBytes+1))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "bad_request", "route lookup request body could not be read", "LookupRoute")
		return false
	}

	_ = r.Body.Close()

	if len(body) > maxRouteLookupInspectionBytes {
		writeProblem(w, http.StatusBadRequest, "bad_request", "route lookup request body is too large", "LookupRoute")
		return false
	}

	if containsForbiddenRouteLookupKey(body) {
		writeProblem(w, http.StatusBadRequest, "credential_input_rejected", "route lookup does not accept authentication or mailbox material", "LookupRoute")
		return false
	}

	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))

	return true
}

// bearerToken parses an Authorization header as one Bearer token.
func bearerToken(header string) (string, bool, bool) {
	header = strings.TrimSpace(header)
	if header == "" {
		return "", false, false
	}

	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, authSchemeBearer) {
		return "", false, true
	}
	token = strings.TrimSpace(token)
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", false, true
	}

	return token, true, false
}

// readStaticBearerToken loads one newline-terminated token from a secret file.
func readStaticBearerToken(tokenFile config.SecretString) (string, error) {
	if tokenFile.IsZero() {
		return "", errControlUnauthorized
	}

	file, err := os.Open(tokenFile.Value())
	if err != nil {
		return "", errControlUnauthorized
	}
	defer func() {
		_ = file.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(file, maxStaticBearerTokenBytes+1))
	if err != nil {
		return "", errControlUnauthorized
	}
	if len(body) > maxStaticBearerTokenBytes {
		return "", errControlUnauthorized
	}

	token := strings.TrimRight(string(body), "\r\n")
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", errControlUnauthorized
	}

	return token, nil
}

// readStaticBasicPassword loads one newline-terminated HTTP Basic password from a secret file.
func readStaticBasicPassword(passwordFile config.SecretString) (string, error) {
	if passwordFile.IsZero() {
		return "", errControlUnauthorized
	}

	file, err := os.Open(passwordFile.Value())
	if err != nil {
		return "", errControlUnauthorized
	}
	defer func() {
		_ = file.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(file, maxStaticBearerTokenBytes+1))
	if err != nil {
		return "", errControlUnauthorized
	}
	if len(body) > maxStaticBearerTokenBytes {
		return "", errControlUnauthorized
	}

	password := strings.TrimRight(string(body), "\r\n")
	if password == "" {
		return "", errControlUnauthorized
	}

	return password, nil
}

// constantTimeEqualString compares strings without leaking prefix matches.
func constantTimeEqualString(got string, want string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// hasRequiredScopes reports whether every required scope is present.
func hasRequiredScopes(actual []string, required []string) bool {
	if len(required) == 0 {
		return false
	}

	actualSet := make(map[string]struct{}, len(actual))
	for _, scope := range actual {
		scope = strings.TrimSpace(scope)
		if scope != "" {
			actualSet[scope] = struct{}{}
		}
	}
	for _, scope := range required {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			return false
		}
		if _, ok := actualSet[scope]; !ok {
			return false
		}
	}

	return true
}

// oidcActorID chooses a stable non-secret actor identity from introspection claims.
func oidcActorID(result nauthilus.OIDCIntrospectionResult) string {
	for _, value := range []string{result.Subject, result.ClientID, result.Audience} {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}

	return authMethodOIDC
}

// mtlsActorID chooses a stable non-secret actor identity from a verified certificate.
func mtlsActorID(certificate *x509.Certificate) string {
	if certificate == nil {
		return authMethodMTLS
	}
	if cn := strings.TrimSpace(certificate.Subject.CommonName); cn != "" {
		return cn
	}
	if subject := strings.TrimSpace(certificate.Subject.String()); subject != "" {
		return subject
	}

	return authMethodMTLS
}

// containsForbiddenRouteLookupKey detects forbidden JSON object keys without reading values.
func containsForbiddenRouteLookupKey(body []byte) bool {
	var value any
	if err := JSON.Unmarshal(body, &value); err != nil {
		return false
	}

	return containsForbiddenRouteLookupKeyValue(value)
}

// containsForbiddenRouteLookupKeyValue walks decoded JSON looking only at object keys.
func containsForbiddenRouteLookupKeyValue(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			if isForbiddenRouteLookupKey(key) || containsForbiddenRouteLookupKeyValue(nested) {
				return true
			}
		}
	case []any:
		if slices.ContainsFunc(typed, containsForbiddenRouteLookupKeyValue) {
			return true
		}
	}

	return false
}

// isForbiddenRouteLookupKey reports whether a JSON key appears to carry forbidden material.
func isForbiddenRouteLookupKey(key string) bool {
	fragments := [...]string{
		"auth",
		"bearer",
		"credential",
		"mailboxcontent",
		"mailboxdata",
		"mailboxmessage",
		"messagecontent",
		"messagedata",
		"messagenum",
		"messagenumber",
		"messagesize",
		"msgcontent",
		"msgnum",
		"msgsize",
		"password",
		"passwd",
		"sasl",
		"script",
		"secret",
		"token",
		"uidl",
	}

	normalized := canonicalRouteLookupKey(key)
	for _, fragment := range fragments {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}

	return normalized == "mailbox"
}

// canonicalRouteLookupKey removes separators before marker matching.
func canonicalRouteLookupKey(key string) string {
	var builder strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(key)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
		}
	}

	return builder.String()
}

// writeProblem writes structured error JSON without echoing request values.
func writeProblem(w http.ResponseWriter, status int, code string, message string, operation string) {
	var operationPtr *string
	if operation != "" {
		operationPtr = &operation
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = JSON.NewEncoder(w).Encode(generated.ErrorResponse{
		Code:      code,
		Message:   message,
		Operation: operationPtr,
		Status:    status,
	})
}
