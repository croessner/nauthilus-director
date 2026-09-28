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

package jmap

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/protocol/authbinding"
	"github.com/croessner/nauthilus-director/internal/protocol/tlscontext"
)

const (
	schemeBasic               = "basic"
	schemeBearer              = "bearer"
	methodPlain               = "plain"
	methodBearer              = "bearer"
	methodIdentityLookup      = nauthilus.IdentityLookupMethod
	maxBasicUsernameBytes     = 512
	maxBasicPasswordBytes     = 4096
	defaultMaxBearerBytes     = 16384
	maxUserAgentBytes         = 256
	defaultAuthorityTimeout   = 10 * time.Second
	authorizationHeader       = "Authorization"
	authenticateHeader        = "WWW-Authenticate"
	bearerInvalidTokenPostfix = `, error="invalid_token"`
)

// authOutcome classifies one request authentication attempt with bounded values.
type authOutcome string

const (
	authOutcomeAuthenticated authOutcome = "authenticated"
	authOutcomeCached        authOutcome = "cached"
	authOutcomeMissing       authOutcome = "missing"
	authOutcomeMalformed     authOutcome = "malformed"
	authOutcomeRejected      authOutcome = "rejected"
	authOutcomeTempfail      authOutcome = "tempfail"
	authOutcomeNone          authOutcome = "none"
)

// credential is one parsed Authorization header; its secret parts are never logged.
type credential struct {
	scheme   string
	username string
	secret   nauthilus.Secret
}

// principal is the authenticated account and the authority attributes used for routing.
type principal struct {
	account    string
	attributes map[string][]string
	scheme     string
}

// authenticator turns Authorization headers into principals through Nauthilus and the cache.
type authenticator struct {
	cfg            Config
	cache          *authCache
	basicEnabled   bool
	bearerEnabled  bool
	maxBearerBytes int
	timeout        time.Duration
}

// newAuthenticator validates the configured schemes against the supplied authority clients.
func newAuthenticator(cfg Config) (*authenticator, error) {
	auth := cfg.Settings.Auth
	if auth.BasicEnabled() && cfg.Authenticator == nil {
		return nil, errors.New("jmap: basic authentication requires an authenticator")
	}

	if auth.Bearer.Enabled && (cfg.BearerIntrospector == nil || cfg.IdentityLookuper == nil) {
		return nil, errors.New("jmap: bearer authentication requires introspection and identity lookup")
	}

	cache, err := newAuthCache(auth.Cache.TTL.Std(), auth.Cache.MaxEntries, time.Now)
	if err != nil {
		return nil, err
	}

	maxBearer := cfg.MaxBearerTokenBytes
	if maxBearer <= 0 {
		maxBearer = defaultMaxBearerBytes
	}

	timeout := cfg.AuthTimeout
	if timeout <= 0 {
		timeout = defaultAuthorityTimeout
	}

	return &authenticator{
		cfg:            cfg,
		cache:          cache,
		basicEnabled:   auth.BasicEnabled(),
		bearerEnabled:  auth.Bearer.Enabled,
		maxBearerBytes: maxBearer,
		timeout:        timeout,
	}, nil
}

// authenticate resolves the request principal, consulting the cache before the authority.
func (a *authenticator) authenticate(ctx context.Context, request *http.Request) (principal, authOutcome) {
	cred, outcome := a.parseCredential(request.Header.Values(authorizationHeader))
	if outcome != "" {
		return principal{}, outcome
	}

	clientIP := requestClientIP(request)
	key := a.cache.key(cred, clientIP)

	if cached, ok := a.cache.get(key); ok {
		return cached, authOutcomeCached
	}

	authCtx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()

	resolved, outcome := a.authenticateWithAuthority(authCtx, request, cred)
	if outcome == authOutcomeAuthenticated {
		a.cache.put(key, resolved)
	}

	return resolved, outcome
}

// parseCredential extracts exactly one supported Authorization credential.
func (a *authenticator) parseCredential(values []string) (credential, authOutcome) {
	if len(values) == 0 {
		return credential{}, authOutcomeMissing
	}

	if len(values) > 1 {
		return credential{}, authOutcomeMalformed
	}

	scheme, payload, found := strings.Cut(strings.TrimSpace(values[0]), " ")
	if !found || strings.TrimSpace(payload) == "" {
		return credential{}, authOutcomeMalformed
	}

	payload = strings.TrimSpace(payload)

	switch strings.ToLower(scheme) {
	case schemeBasic:
		if !a.basicEnabled {
			return credential{}, authOutcomeMalformed
		}

		return parseBasicCredential(payload)
	case schemeBearer:
		if !a.bearerEnabled || len(payload) > a.maxBearerBytes || !printableToken(payload) {
			return credential{}, authOutcomeMalformed
		}

		return credential{scheme: schemeBearer, secret: nauthilus.NewSecret(payload)}, ""
	default:
		return credential{}, authOutcomeMalformed
	}
}

// parseBasicCredential decodes RFC 7617 user-pass material with strict bounds.
func parseBasicCredential(payload string) (credential, authOutcome) {
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil || !utf8.Valid(decoded) {
		return credential{}, authOutcomeMalformed
	}

	username, password, found := strings.Cut(string(decoded), ":")
	username = strings.TrimSpace(username)

	if !found || username == "" || password == "" ||
		len(username) > maxBasicUsernameBytes || len(password) > maxBasicPasswordBytes ||
		strings.ContainsAny(username, "\x00\r\n") || strings.ContainsAny(password, "\x00\r\n") {
		return credential{}, authOutcomeMalformed
	}

	return credential{scheme: schemeBasic, username: username, secret: nauthilus.NewSecret(password)}, ""
}

// printableToken accepts exactly the RFC 6750 b64token syntax:
// 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"=".
func printableToken(token string) bool {
	body := strings.TrimRight(token, "=")
	if body == "" {
		return false
	}

	for _, char := range body {
		switch {
		case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z', char >= '0' && char <= '9':
		case strings.ContainsRune("-._~+/", char):
		default:
			return false
		}
	}

	return true
}

// authenticateWithAuthority asks Nauthilus for a decision on one uncached credential.
func (a *authenticator) authenticateWithAuthority(ctx context.Context, request *http.Request, cred credential) (principal, authOutcome) {
	switch cred.scheme {
	case schemeBasic:
		return a.authenticateBasic(ctx, request, cred)
	case schemeBearer:
		return a.authenticateBearer(ctx, request, cred)
	default:
		return principal{}, authOutcomeMalformed
	}
}

// authenticateBasic verifies username and password through the Nauthilus password path.
func (a *authenticator) authenticateBasic(ctx context.Context, request *http.Request, cred credential) (principal, authOutcome) {
	requestContext := a.requestContext(request, methodPlain)
	requestContext.Username = cred.username

	result, err := a.cfg.Authenticator.Authenticate(ctx, nauthilus.AuthRequest{
		Context:    requestContext,
		Credential: cred.secret,
	})

	return principalFromResult(result, err, schemeBasic)
}

// authenticateBearer introspects the token with the listener policy and resolves its account.
func (a *authenticator) authenticateBearer(ctx context.Context, request *http.Request, cred credential) (principal, authOutcome) {
	introspection, err := a.cfg.BearerIntrospector.Introspect(ctx, nauthilus.BearerIntrospectionRequest{
		Context:       a.requestContext(request, methodBearer),
		Mechanism:     methodBearer,
		Protocol:      Protocol,
		ListenerName:  a.cfg.ListenerName,
		AuthorityName: a.cfg.AuthorityName,
		BearerToken:   cred.secret,
	})

	tokenPrincipal, outcome := principalFromResult(introspection, err, schemeBearer)
	if outcome != authOutcomeAuthenticated {
		return principal{}, outcome
	}

	lookupContext := a.requestContext(request, methodIdentityLookup)
	lookupContext.Username = tokenPrincipal.account

	lookup, err := a.cfg.IdentityLookuper.LookupIdentity(ctx, nauthilus.IdentityLookupRequest{Context: lookupContext})

	return principalFromResult(lookup, err, schemeBearer)
}

// principalFromResult maps one authority result into a principal or a bounded outcome.
func principalFromResult(result nauthilus.AuthResult, err error, scheme string) (principal, authOutcome) {
	if err != nil {
		return principal{}, authOutcomeTempfail
	}

	switch result.Decision {
	case nauthilus.DecisionAuthenticated:
		account, accountErr := authbinding.CanonicalAccount(result.Account)
		if accountErr != nil {
			return principal{}, authOutcomeTempfail
		}

		return principal{account: account, attributes: cloneAttributes(result.Attributes), scheme: scheme}, authOutcomeAuthenticated
	case nauthilus.DecisionRejected:
		return principal{}, authOutcomeRejected
	default:
		return principal{}, authOutcomeTempfail
	}
}

// requestContext builds the secret-free Nauthilus context for one HTTP request.
func (a *authenticator) requestContext(request *http.Request, method string) nauthilus.RequestContext {
	clientIP, clientPort := splitHostPort(request.RemoteAddr)
	localIP, localPort := "", ""

	if local, ok := request.Context().Value(http.LocalAddrContextKey).(net.Addr); ok && local != nil {
		localIP, localPort = splitHostPort(local.String())
	}

	requestContext := nauthilus.RequestContext{
		ClientIP:   clientIP,
		ClientPort: clientPort,
		LocalIP:    localIP,
		LocalPort:  localPort,
		UserAgent:  boundedUserAgent(request.UserAgent()),
		Protocol:   Protocol,
		Method:     method,
	}

	if request.TLS == nil {
		return tlscontext.Apply(requestContext, false, tls.ConnectionState{}, false)
	}

	return tlscontext.Apply(requestContext, true, *request.TLS, true)
}

// challenges returns the WWW-Authenticate values for one refused request; invalid_token is added
// only when the refused credential was a Bearer token.
func (a *authenticator) challenges(outcome authOutcome, bearerAttempt bool) []string {
	realm := `realm="` + a.cfg.Settings.Auth.Realm + `"`

	values := make([]string, 0, 2)
	if a.basicEnabled {
		values = append(values, `Basic `+realm+`, charset="UTF-8"`)
	}

	if a.bearerEnabled {
		bearer := `Bearer ` + realm
		if bearerAttempt && (outcome == authOutcomeRejected || outcome == authOutcomeMalformed) {
			bearer += bearerInvalidTokenPostfix
		}

		values = append(values, bearer)
	}

	return values
}

// bearerAttempt reports whether the request presented a Bearer credential.
func bearerAttempt(request *http.Request) bool {
	scheme, _, _ := strings.Cut(strings.TrimSpace(request.Header.Get(authorizationHeader)), " ")

	return strings.EqualFold(scheme, schemeBearer)
}

// requestClientIP returns the frontend client address after trusted PROXY handling.
func requestClientIP(request *http.Request) string {
	host, _ := splitHostPort(request.RemoteAddr)

	return host
}

// splitHostPort splits a TCP address string without failing on unusual shapes.
func splitHostPort(address string) (string, string) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", ""
	}

	return host, port
}

// boundedUserAgent keeps the user agent printable and bounded before it reaches the authority.
func boundedUserAgent(value string) string {
	value = strings.Map(func(char rune) rune {
		if !unicode.IsPrint(char) {
			return -1
		}

		return char
	}, value)

	if len(value) > maxUserAgentBytes {
		value = value[:maxUserAgentBytes]
		for !utf8.ValidString(value) {
			value = value[:len(value)-1]
		}
	}

	return value
}

// cloneAttributes detaches authority attribute slices from caller-owned results.
func cloneAttributes(attributes map[string][]string) map[string][]string {
	if attributes == nil {
		return nil
	}

	cloned := make(map[string][]string, len(attributes))
	for name, values := range attributes {
		cloned[name] = append([]string(nil), values...)
	}

	return cloned
}
