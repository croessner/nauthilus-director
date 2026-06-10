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

//nolint:funlen,goconst,wsl_v5 // Bearer introspection tests keep fake Nauthilus fixtures close to behavior.
package nauthilus

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/croessner/nauthilus-director/internal/config"
)

const (
	testBearerClientID = "director-sasl-client"
	testBearerSecret   = "client-secret"
	testBearerToken    = "end-user-token-sentinel"
	testSecretSentinel = "secret-claim-sentinel"
)

// TestSASLBearerDiscoverySucceedsWithNauthilusDocument verifies startup discovery.
func TestSASLBearerDiscoverySucceedsWithNauthilusDocument(t *testing.T) {
	server := newSASLBearerServer(t, oidcAuthMethodClientSecretBasic, activeBearerPayload(), nil)
	defer server.Close()

	introspector, err := NewSASLBearerIntrospector(
		context.Background(),
		testBearerIntrospectionConfig(server.URL, oidcAuthMethodClientSecretBasic),
		server.Client(),
	)
	if err != nil {
		t.Fatalf("NewSASLBearerIntrospector returned error: %v", err)
	}

	if introspector.metadata.IntrospectionEndpoint != server.URL+"/oidc/introspect" {
		t.Fatalf("introspection endpoint = %q, want discovered endpoint", introspector.metadata.IntrospectionEndpoint)
	}
}

// TestSASLBearerDiscoveryRejectsInvalidMetadata keeps startup fail-closed.
func TestSASLBearerDiscoveryRejectsInvalidMetadata(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{
			name:   "missing introspection endpoint",
			mutate: func(document map[string]any) { delete(document, "introspection_endpoint") },
			want:   "introspection_endpoint",
		},
		{
			name:   "issuer mismatch",
			mutate: func(document map[string]any) { document["issuer"] = "https://other.example.test" },
			want:   "issuer mismatch",
		},
		{
			name: "unsupported introspection auth method",
			mutate: func(document map[string]any) {
				document["introspection_endpoint_auth_methods_supported"] = []string{oidcAuthMethodClientSecretPost}
			},
			want: "configured introspection auth method",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				document := oidcDiscoveryFixture(request.Host, oidcAuthMethodClientSecretBasic)
				test.mutate(document)
				writeOIDCDiscovery(t, writer, document)
			}))
			defer server.Close()

			_, err := NewSASLBearerIntrospector(
				context.Background(),
				testBearerIntrospectionConfig(server.URL, oidcAuthMethodClientSecretBasic),
				server.Client(),
			)
			if err == nil {
				t.Fatal("NewSASLBearerIntrospector accepted invalid metadata")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %q, want %q", err.Error(), test.want)
			}
		})
	}
}

// TestSASLBearerIntrospectionEndpointAuthMethods verifies request client auth.
//
//nolint:gocyclo // The table keeps endpoint-auth variants in one contract test.
func TestSASLBearerIntrospectionEndpointAuthMethods(t *testing.T) {
	tests := []struct {
		name       string
		authMethod string
		configure  func(*config.BearerIntrospectionConfig)
		assert     func(*testing.T, capturedIntrospectionRequest)
	}{
		{
			name:       "client secret basic",
			authMethod: oidcAuthMethodClientSecretBasic,
			assert: func(t *testing.T, captured capturedIntrospectionRequest) {
				t.Helper()
				want := "Basic " + base64.StdEncoding.EncodeToString([]byte(testBearerClientID+":"+testBearerSecret))
				if captured.authorization != want {
					t.Fatalf("authorization = %q, want %q", captured.authorization, want)
				}
				if captured.form.Get(oidcFormClientSecret) != "" {
					t.Fatal("client_secret_basic leaked client_secret into request body")
				}
			},
		},
		{
			name:       "client secret post",
			authMethod: oidcAuthMethodClientSecretPost,
			assert: func(t *testing.T, captured capturedIntrospectionRequest) {
				t.Helper()
				if captured.authorization != "" {
					t.Fatalf("authorization = %q, want empty", captured.authorization)
				}
				if captured.form.Get(oidcFormClientID) != testBearerClientID ||
					captured.form.Get(oidcFormClientSecret) != testBearerSecret {
					t.Fatalf("post auth form = %#v, want client credentials", captured.form)
				}
			},
		},
		{
			name:       "private key jwt",
			authMethod: oidcAuthMethodPrivateKeyJWT,
			configure: func(cfg *config.BearerIntrospectionConfig) {
				privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatalf("generate RSA key: %v", err)
				}
				cfg.ClientSecret = config.Secret("")
				cfg.ClientPrivateKeyFile = config.Secret(writeOIDCPrivateKeyFile(t, privateKey))
				cfg.ClientKeyID = "sasl-key-1"
				cfg.ClientAssertionAlg = oidcAssertionAlgRS256
			},
			assert: func(t *testing.T, captured capturedIntrospectionRequest) {
				t.Helper()
				if captured.authorization != "" {
					t.Fatalf("authorization = %q, want empty", captured.authorization)
				}
				if captured.form.Get(oidcFormClientID) != testBearerClientID {
					t.Fatalf("client_id = %q, want %q", captured.form.Get(oidcFormClientID), testBearerClientID)
				}
				if captured.form.Get(oidcFormClientAssertionType) != oidcAssertionTypeJWTBearer {
					t.Fatalf("client_assertion_type = %q, want JWT bearer", captured.form.Get(oidcFormClientAssertionType))
				}

				assertBearerClientAssertion(t, captured)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			captured := capturedIntrospectionRequest{}
			server := newSASLBearerServer(t, test.authMethod, activeBearerPayload(), &captured)
			defer server.Close()

			cfg := testBearerIntrospectionConfig(server.URL, test.authMethod)
			if test.configure != nil {
				test.configure(&cfg)
			}
			introspector := newTestSASLBearerIntrospector(t, server, cfg)

			result, err := introspector.Introspect(context.Background(), testBearerRequest())
			if err != nil {
				t.Fatalf("Introspect returned error: %v", err)
			}
			if result.Decision != DecisionAuthenticated || result.Account != "account-a" {
				t.Fatalf("result = %#v, want authenticated account-a", result)
			}

			test.assert(t, captured)
			assertBearerTokenOnlyInBody(t, captured)
		})
	}
}

// TestOIDCRequestClientAuthClearsAuthorization verifies stale headers are removed.
func TestOIDCRequestClientAuthClearsAuthorization(t *testing.T) {
	clientAuth := oidcEndpointClientAuth{ClientID: testBearerClientID}
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/oidc/introspect", nil)
	request.Header.Set("Authorization", "Bearer "+testBearerToken)

	applyOIDCRequestClientAuth(request, oidcAuthMethodClientSecretPost, clientAuth, "")
	if got := request.Header.Get("Authorization"); got != "" {
		t.Fatalf("authorization = %q, want cleared", got)
	}

	request.Header.Set("Authorization", "Bearer "+testBearerToken)
	applyOIDCRequestClientAuth(request, oidcAuthMethodClientSecretBasic, clientAuth, testBearerSecret)
	if got := request.Header.Get("Authorization"); strings.Contains(got, testBearerToken) || !strings.HasPrefix(got, "Basic ") {
		t.Fatalf("authorization = %q, want Basic without bearer token", got)
	}
}

// TestSASLBearerIntrospectionPolicyMapping verifies active, scope and account policy.
func TestSASLBearerIntrospectionPolicyMapping(t *testing.T) {
	tests := []struct {
		name         string
		payload      map[string]any
		configure    func(*config.BearerIntrospectionConfig)
		wantDecision string
		wantAccount  string
		wantSession  string
	}{
		{
			name:         "inactive token rejected",
			payload:      map[string]any{"active": false, "scope": "email", "account": "account-a"},
			wantDecision: DecisionRejected,
		},
		{
			name:         "missing required scope rejected",
			payload:      map[string]any{"active": true, "scope": "profile", "account": "account-a"},
			wantDecision: DecisionRejected,
		},
		{
			name:         "string scope accepted",
			payload:      activeBearerPayload(),
			wantDecision: DecisionAuthenticated,
			wantAccount:  "account-a",
			wantSession:  "session-a",
		},
		{
			name: "list scope accepted",
			payload: map[string]any{
				"active":     true,
				"scope":      []string{"openid", "email"},
				"account":    "account-a",
				"session_id": "session-a",
			},
			wantDecision: DecisionAuthenticated,
			wantAccount:  "account-a",
			wantSession:  "session-a",
		},
		{
			name: "configured account claim authoritative",
			payload: map[string]any{
				"active":          true,
				"scope":           "email",
				"account":         "wrong-account",
				"dovecot_account": "right-account",
			},
			configure:    func(cfg *config.BearerIntrospectionConfig) { cfg.AccountClaim = "dovecot_account" },
			wantDecision: DecisionAuthenticated,
			wantAccount:  "right-account",
		},
		{
			name: "missing configured account claim rejected",
			payload: map[string]any{
				"active":  true,
				"scope":   "email",
				"account": "fallback-account",
			},
			configure:    func(cfg *config.BearerIntrospectionConfig) { cfg.AccountClaim = "dovecot_account" },
			wantDecision: DecisionRejected,
		},
		{
			name: "default account chain chooses first safe value",
			payload: map[string]any{
				"active":             true,
				"scope":              "email",
				"account":            "",
				"account_key":        "account-key",
				"preferred_username": "preferred",
				"sub":                "subject",
			},
			wantDecision: DecisionAuthenticated,
			wantAccount:  "account-key",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newSASLBearerServer(t, oidcAuthMethodClientSecretBasic, test.payload, nil)
			defer server.Close()

			cfg := testBearerIntrospectionConfig(server.URL, oidcAuthMethodClientSecretBasic)
			if test.configure != nil {
				test.configure(&cfg)
			}
			introspector := newTestSASLBearerIntrospector(t, server, cfg)

			result, err := introspector.Introspect(context.Background(), testBearerRequest())
			if err != nil {
				t.Fatalf("Introspect returned error: %v", err)
			}
			if result.Decision != test.wantDecision || result.Account != test.wantAccount || result.SessionID != test.wantSession {
				t.Fatalf("result = %#v, want decision=%q account=%q session=%q", result, test.wantDecision, test.wantAccount, test.wantSession)
			}
		})
	}
}

// TestSASLBearerAttributesDropUnsafeClaims keeps response mapping bounded.
func TestSASLBearerAttributesDropUnsafeClaims(t *testing.T) {
	payload := activeBearerPayload()
	payload["tenant"] = "blue"
	payload["mailShard"] = "mailstore-a"
	payload["active_user"] = true
	payload["login_count"] = float64(7)
	payload["email"] = "user@example.test"
	payload["sub"] = "subject-sentinel"
	payload["sid"] = "session-sentinel"
	payload["dovecot_account"] = "account-sentinel"
	payload["access_token"] = testSecretSentinel
	payload["refresh_token"] = testSecretSentinel
	payload["profile"] = map[string]any{"nested": "object"}
	payload["roles"] = []string{"admin"}
	payload["large"] = strings.Repeat("x", maxBearerAttributeValueBytes+1)

	server := newSASLBearerServer(t, oidcAuthMethodClientSecretBasic, payload, nil)
	defer server.Close()

	result, err := newTestSASLBearerIntrospector(
		t,
		server,
		testBearerIntrospectionConfig(server.URL, oidcAuthMethodClientSecretBasic),
	).Introspect(context.Background(), testBearerRequest())
	if err != nil {
		t.Fatalf("Introspect returned error: %v", err)
	}

	if result.Attributes["tenant"][0] != "blue" ||
		result.Attributes["mailShard"][0] != "mailstore-a" ||
		result.Attributes["active_user"][0] != "true" ||
		result.Attributes["login_count"][0] != "7" {
		t.Fatalf("safe attributes = %#v, want scalar claims copied", result.Attributes)
	}
	for _, forbidden := range []string{
		"access_token",
		"account",
		"dovecot_account",
		"email",
		"refresh_token",
		"profile",
		"roles",
		"sid",
		"sub",
		"session_id",
		"large",
	} {
		if _, ok := result.Attributes[forbidden]; ok {
			t.Fatalf("attribute %q was copied from unsafe claim set: %#v", forbidden, result.Attributes)
		}
	}
	if got := result.Attributes["scope"]; len(got) != 2 || got[0] != "openid" || got[1] != "email" {
		t.Fatalf("scope attributes = %#v, want split scope values", got)
	}
}

// TestSASLBearerErrorsDoNotLeakSecrets verifies temporary and malformed errors are secret-safe.
func TestSASLBearerErrorsDoNotLeakSecrets(t *testing.T) {
	t.Run("transport", func(t *testing.T) {
		server := newSASLBearerServer(t, oidcAuthMethodClientSecretBasic, activeBearerPayload(), nil)
		cfg := testBearerIntrospectionConfig(server.URL, oidcAuthMethodClientSecretBasic)
		introspector := newTestSASLBearerIntrospector(t, server, cfg)
		server.Close()

		_, err := introspector.Introspect(context.Background(), testBearerRequest())
		assertSecretSafeError(t, err)
	})

	t.Run("malformed", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			switch request.URL.Path {
			case defaultOIDCDiscoveryPath:
				writeOIDCDiscovery(t, writer, oidcDiscoveryFixture(request.Host, oidcAuthMethodClientSecretBasic))
			case "/oidc/introspect":
				writer.Header().Set("Content-Type", defaultHTTPContentType)
				_, _ = writer.Write([]byte(`{"active":"yes","access_token":"` + testSecretSentinel + `"}`))
			default:
				t.Fatalf("unexpected path %q", request.URL.Path)
			}
		}))
		defer server.Close()

		introspector := newTestSASLBearerIntrospector(
			t,
			server,
			testBearerIntrospectionConfig(server.URL, oidcAuthMethodClientSecretBasic),
		)

		_, err := introspector.Introspect(context.Background(), testBearerRequest())
		assertSecretSafeError(t, err)
	})
}

type capturedIntrospectionRequest struct {
	authorization string
	form          url.Values
}

// newSASLBearerServer starts a fake discovery and introspection endpoint.
func newSASLBearerServer(
	t *testing.T,
	authMethod string,
	payload map[string]any,
	captured *capturedIntrospectionRequest,
) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case defaultOIDCDiscoveryPath:
			writeOIDCDiscovery(t, writer, oidcDiscoveryFixture(request.Host, authMethod))
		case "/oidc/introspect":
			captureSASLBearerIntrospectionRequest(t, request, captured)
			writer.Header().Set("Content-Type", defaultHTTPContentType)
			if err := json.NewEncoder(writer).Encode(payload); err != nil {
				t.Fatalf("encode introspection payload: %v", err)
			}
		default:
			t.Fatalf("unexpected path %q", request.URL.Path)
		}
	}))
}

// captureSASLBearerIntrospectionRequest records secret-safe request facts.
func captureSASLBearerIntrospectionRequest(
	t *testing.T,
	request *http.Request,
	captured *capturedIntrospectionRequest,
) {
	t.Helper()

	if request.Method != http.MethodPost {
		t.Fatalf("introspection method = %s, want POST", request.Method)
	}
	if got := request.Header.Get("Content-Type"); got != oidcFormContentType {
		t.Fatalf("introspection content-type = %q, want form", got)
	}
	if err := request.ParseForm(); err != nil {
		t.Fatalf("parse introspection form: %v", err)
	}
	if captured != nil {
		captured.authorization = request.Header.Get("Authorization")
		captured.form = cloneURLValues(request.PostForm)
	}
}

// testBearerIntrospectionConfig returns a complete SASL bearer introspection config.
func testBearerIntrospectionConfig(issuer string, authMethod string) config.BearerIntrospectionConfig {
	return config.BearerIntrospectionConfig{
		Enabled:       true,
		Issuer:        issuer,
		DiscoveryURL:  issuer + defaultOIDCDiscoveryPath,
		ClientID:      testBearerClientID,
		ClientSecret:  config.Secret(testBearerSecret),
		AuthMethod:    authMethod,
		RequiredScope: "email",
	}
}

// cloneURLValues returns detached form values for assertions.
func cloneURLValues(values url.Values) url.Values {
	cloned := make(url.Values, len(values))
	for key, entries := range values {
		cloned[key] = append([]string(nil), entries...)
	}

	return cloned
}

// newTestSASLBearerIntrospector builds an introspector or fails the test.
func newTestSASLBearerIntrospector(
	t *testing.T,
	server *httptest.Server,
	cfg config.BearerIntrospectionConfig,
) *SASLBearerIntrospector {
	t.Helper()

	introspector, err := NewSASLBearerIntrospector(context.Background(), cfg, server.Client())
	if err != nil {
		t.Fatalf("NewSASLBearerIntrospector: %v", err)
	}

	return introspector
}

// testBearerRequest returns a redaction-aware bearer token request.
func testBearerRequest() BearerIntrospectionRequest {
	return BearerIntrospectionRequest{
		Mechanism:             "XOAUTH2",
		Protocol:              "imap",
		ListenerName:          "imap-public",
		AuthorityName:         "default",
		AuthorizationIdentity: "authz@example.test",
		BearerToken:           NewSecret(testBearerToken),
	}
}

// activeBearerPayload returns an active RFC 7662-style response with extensions.
func activeBearerPayload() map[string]any {
	return map[string]any{
		"active":     true,
		"scope":      "openid email",
		"account":    "account-a",
		"session_id": "session-a",
	}
}

// assertBearerTokenOnlyInBody verifies end-user token placement.
func assertBearerTokenOnlyInBody(t *testing.T, captured capturedIntrospectionRequest) {
	t.Helper()

	if captured.form.Get(oidcIntrospectionTokenParam) != testBearerToken {
		t.Fatalf("token form value = %q, want bearer token in body", captured.form.Get(oidcIntrospectionTokenParam))
	}
	if strings.Contains(captured.authorization, testBearerToken) {
		t.Fatalf("authorization header leaked bearer token: %q", captured.authorization)
	}
}

// assertBearerClientAssertion verifies private_key_jwt audience and identity.
func assertBearerClientAssertion(t *testing.T, captured capturedIntrospectionRequest) {
	t.Helper()

	parts := strings.Split(captured.form.Get(oidcFormClientAssertion), ".")
	if len(parts) != 3 {
		t.Fatalf("client_assertion has %d parts, want 3", len(parts))
	}

	header := decodeJWTPart(t, parts[0])
	if header["alg"] != oidcAssertionAlgRS256 || header["kid"] != "sasl-key-1" {
		t.Fatalf("client_assertion header = %#v, want RS256 sasl key", header)
	}

	claims := decodeJWTPart(t, parts[1])
	if claims["iss"] != testBearerClientID || claims["sub"] != testBearerClientID {
		t.Fatalf("client_assertion identity claims = %#v, want SASL client", claims)
	}
	if claims["aud"] != "http://"+capturedHostFromEndpoint(t, captured.form)+"/oidc/introspect" {
		t.Fatalf("client_assertion aud = %#v, want introspection endpoint", claims["aud"])
	}
}

// capturedHostFromEndpoint extracts the host from the assertion audience test form.
func capturedHostFromEndpoint(t *testing.T, form url.Values) string {
	t.Helper()

	assertion := form.Get(oidcFormClientAssertion)
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		t.Fatalf("client_assertion has %d parts, want 3", len(parts))
	}

	claims := decodeJWTPart(t, parts[1])
	audience, ok := claims["aud"].(string)
	if !ok {
		t.Fatalf("client_assertion aud missing: %#v", claims)
	}

	parsed, err := url.Parse(audience)
	if err != nil {
		t.Fatalf("parse audience: %v", err)
	}

	return parsed.Host
}

// assertSecretSafeError checks returned errors do not include bearer or secret sentinels.
func assertSecretSafeError(t *testing.T, err error) {
	t.Helper()

	if err == nil {
		t.Fatal("expected error")
	}
	if errors.Is(err, context.Canceled) {
		t.Fatal("unexpected context cancellation")
	}

	rendered := err.Error()
	for _, forbidden := range []string{testBearerToken, testBearerSecret, testSecretSentinel} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("error %q leaked %q", rendered, forbidden)
		}
	}
}
