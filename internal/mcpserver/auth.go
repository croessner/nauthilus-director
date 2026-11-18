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

package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/rest/diagnostics"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/modelcontextprotocol/go-sdk/auth"
)

const (
	extraCredential     = "nauthilus-director.credential"
	extraRequestContext = "nauthilus-director.request_context"

	errorInvalidToken      = "invalid_token"
	errorInsufficientScope = "insufficient_scope"
	retryAfterSeconds      = "60"

	claimExpiry = "exp"
)

var (
	// errInvalidToken rejects a token with 401; the reason is never published.
	errInvalidToken = errors.New("invalid token")

	// errInsufficientScope rejects a valid token without any scope of the resource with 403.
	errInsufficientScope = errors.New("insufficient scope")

	// errUnavailable answers 503 when the authorization server cannot be asked.
	errUnavailable = errors.New("token authority unavailable")
)

// verifiedKey carries the SDK token info of an authenticated request to the SDK bridge.
type verifiedKey struct{}

// authenticate verifies the bearer token of every endpoint request, answers RFC 6750 / RFC 9728
// challenges, bounds failed attempts per client IP and in-flight requests per principal, inspects
// the JSON-RPC body, and hands the verified facts to the SDK. No anonymous request reaches a tool.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		clientIP := clientIPOf(request.Context())

		if s.limiter.blocked(clientIP) {
			writer.Header().Set("Retry-After", retryAfterSeconds)
			s.reject(writer, request, http.StatusTooManyRequests, resultRateLimited, "failed_authentication_limit")

			return
		}

		token, present := bearerToken(request)
		if !present {
			s.challenge(writer, request, http.StatusUnauthorized, "", diagnostics.Scopes(), "missing_token")

			return
		}

		credential, expiry, err := s.verify(request.Context(), token)
		if !s.answerVerification(writer, request, err) {
			return
		}

		release, acquired := s.gate.acquire(request.Context(), credential.Identity())
		if !acquired {
			writer.Header().Set("Retry-After", "1")
			s.reject(writer, request, http.StatusTooManyRequests, resultBusy, "too_many_requests")

			return
		}

		defer release()

		if !s.inspectBody(writer, request, credential) {
			return
		}

		info := &auth.TokenInfo{Scopes: credential.Scopes, Expiration: expiry, UserID: credential.Identity(),
			Extra: map[string]any{extraCredential: credential, extraRequestContext: request.Context()}}

		next.ServeHTTP(writer, request.WithContext(context.WithValue(request.Context(), verifiedKey{}, info)))
	})
}

// answerVerification answers a failed verification and reports whether the request may continue.
func (s *Server) answerVerification(writer http.ResponseWriter, request *http.Request, err error) bool {
	switch {
	case err == nil:
		return true
	case errors.Is(err, errUnavailable):
		writer.Header().Set("Retry-After", "5")
		s.reject(writer, request, http.StatusServiceUnavailable, resultError, "token_authority_unavailable")
	case errors.Is(err, errInsufficientScope):
		s.challenge(writer, request, http.StatusForbidden, errorInsufficientScope, diagnostics.Scopes(), "insufficient_scope")
	default:
		s.limiter.fail(clientIPOf(request.Context()))
		s.challenge(writer, request, http.StatusUnauthorized, errorInvalidToken, diagnostics.Scopes(), "invalid_token")
	}

	return false
}

// sdkBridge hands the already verified token info to the SDK, which only accepts it through its
// bearer middleware. The bridge verifier never validates anything itself; a request without
// verified facts is refused.
func sdkBridge(next http.Handler) http.Handler {
	return auth.RequireBearerToken(func(_ context.Context, _ string, request *http.Request) (*auth.TokenInfo, error) {
		info, ok := request.Context().Value(verifiedKey{}).(*auth.TokenInfo)
		if !ok || info == nil {
			return nil, auth.ErrInvalidToken
		}

		return info, nil
	}, nil)(next)
}

// bearerToken returns the token of exactly one Authorization header in the Bearer scheme.
func bearerToken(request *http.Request) (string, bool) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}

	scheme, token, found := strings.Cut(values[0], " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", false
	}

	return token, true
}

// verify accepts only an active, unexpired user access token whose audience is this resource
// (alone or together with the issuing client), issued to an admitted client, naming a subject
// other than the client who belongs to an entitled group, with at least one diagnostics scope. Nauthilus answers the
// introspection; every binding decision is repeated here and fails closed.
func (s *Server) verify(ctx context.Context, token string) (diagnostics.Credential, time.Time, error) {
	result, err := s.deps.Tokens.Introspect(ctx, token)
	if err != nil {
		return diagnostics.Credential{}, time.Time{}, errUnavailable
	}

	if !result.Active {
		return diagnostics.Credential{}, time.Time{}, errInvalidToken
	}

	clientID, subject := strings.TrimSpace(result.ClientID), strings.TrimSpace(result.Subject)
	if clientID == "" || subject == "" || subject == clientID || !s.deps.Settings.AdmitsClient(clientID) {
		return diagnostics.Credential{}, time.Time{}, errInvalidToken
	}

	if !s.deps.Settings.EntitlesGroups(stringsClaim(result.Claims[s.deps.Settings.GroupsClaim])) {
		return diagnostics.Credential{}, time.Time{}, errInvalidToken
	}

	if !boundToResource(result, clientID, s.resource.String()) {
		return diagnostics.Credential{}, time.Time{}, errInvalidToken
	}

	expiry, ok := expiresAt(result.Claims)
	if !ok || !expiry.After(time.Now()) {
		return diagnostics.Credential{}, time.Time{}, errInvalidToken
	}

	scopes := slices.DeleteFunc(diagnostics.Scopes(), func(scope string) bool { return !slices.Contains(result.Scopes, scope) })
	if len(scopes) == 0 {
		return diagnostics.Credential{}, time.Time{}, errInsufficientScope
	}

	return diagnostics.Credential{Method: diagnostics.CredentialOAuthUser, ClientID: clientID, Subject: subject,
		Scopes: scopes}, expiry, nil
}

// boundToResource reports whether the token audience names the resource and nothing but the
// resource and the issuing client, as Nauthilus encodes RFC 8707 resource tokens.
func boundToResource(result nauthilus.OIDCIntrospectionResult, clientID string, resource string) bool {
	if !slices.Contains(result.Audiences, resource) {
		return false
	}

	return !slices.ContainsFunc(result.Audiences, func(audience string) bool {
		return audience != resource && audience != clientID
	})
}

// stringsClaim reads a claim holding a list of strings or one space-separated string.
func stringsClaim(value any) []string {
	switch typed := value.(type) {
	case string:
		return strings.Fields(typed)
	case []string:
		return typed
	case []any:
		values := make([]string, 0, len(typed))

		for _, item := range typed {
			if text, ok := item.(string); ok {
				values = append(values, text)
			}
		}

		return values
	default:
		return nil
	}
}

// expiresAt reads the numeric exp claim of the introspection response.
func expiresAt(claims map[string]any) (time.Time, bool) {
	var seconds float64

	switch value := claims[claimExpiry].(type) {
	case float64:
		seconds = value
	case int64:
		seconds = float64(value)
	case int:
		seconds = float64(value)
	case json.Number:
		parsed, err := value.Float64()
		if err != nil {
			return time.Time{}, false
		}

		seconds = parsed
	default:
		return time.Time{}, false
	}

	if seconds <= 0 || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds > math.MaxInt32*4 {
		return time.Time{}, false
	}

	return time.Unix(int64(seconds), 0), true
}

// challenge answers 401 or 403 with an RFC 6750 challenge that points to the RFC 9728 protected
// resource metadata.
func (s *Server) challenge(writer http.ResponseWriter, request *http.Request, status int, errorCode string, scopes []string, reason string) {
	params := []string{fmt.Sprintf("resource_metadata=%q", s.metadataURL)}

	if errorCode != "" {
		params = append(params, fmt.Sprintf("error=%q", errorCode))
	}

	if len(scopes) > 0 {
		params = append(params, fmt.Sprintf("scope=%q", strings.Join(scopes, " ")))
	}

	writer.Header().Set("WWW-Authenticate", "Bearer "+strings.Join(params, ", "))

	result := resultUnauthorized
	if status == http.StatusForbidden {
		result = resultForbidden
	}

	s.reject(writer, request, status, result, reason)
}

// protectedResourceMetadata serves the RFC 9728 document of the protected resource.
func (s *Server) protectedResourceMetadata(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed")

		return
	}

	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "max-age=60")

	_ = json.NewEncoder(writer).Encode(map[string]any{
		"resource":                 s.resource.String(),
		"authorization_servers":    []string{strings.TrimSpace(s.deps.Issuer)},
		"scopes_supported":         diagnostics.Scopes(),
		"bearer_methods_supported": []string{"header"},
		"resource_name":            implementationTitle,
	})
}
