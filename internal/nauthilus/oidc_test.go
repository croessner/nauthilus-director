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

//nolint:funlen,goconst,wsl_v5 // OIDC tests keep fake Nauthilus fixtures local to each behavior.
package nauthilus

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/config"
)

// TestOIDCDiscoverySucceedsWithNauthilusDocument verifies discovery metadata resolution.
func TestOIDCDiscoverySucceedsWithNauthilusDocument(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != defaultOIDCDiscoveryPath {
			t.Fatalf("path = %q, want discovery", request.URL.Path)
		}

		writeOIDCDiscovery(t, writer, oidcDiscoveryFixture(request.Host, "client_secret_basic"))
	}))
	defer server.Close()

	source := newTestOIDCSource(t, testOIDCConfig(server.URL, "client_secret_basic"), nil)
	metadata, err := source.discoveryMetadataLocked(context.Background())
	if err != nil {
		t.Fatalf("discovery returned error: %v", err)
	}

	if metadata.Issuer != server.URL ||
		metadata.TokenEndpoint != server.URL+"/oidc/token" ||
		metadata.IntrospectionEndpoint != server.URL+"/oidc/introspect" {
		t.Fatalf("metadata = %#v, want Nauthilus endpoints", metadata)
	}
}

// TestOIDCFormRequestPropagatesTraceContext verifies token and introspection posts keep trace linkage.
func TestOIDCFormRequestPropagatesTraceContext(t *testing.T) {
	request, err := newOIDCFormRequest(
		contextWithTestTrace(),
		"https://issuer.example.test/token",
		url.Values{"grant_type": []string{grantTypeClientCredentials}},
		"oidc token_endpoint is invalid",
	)
	if err != nil {
		t.Fatalf("newOIDCFormRequest returned error: %v", err)
	}

	if got := request.Header.Get("traceparent"); !strings.Contains(got, testTraceID) {
		t.Fatalf("traceparent = %q, want trace ID %s", got, testTraceID)
	}
}

// TestOIDCDiscoveryRejectsInvalidMetadata keeps discovery fail-closed.
func TestOIDCDiscoveryRejectsInvalidMetadata(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(map[string]any)
		configure func(config.AuthorityOIDCConfig) config.AuthorityOIDCConfig
		want      string
	}{
		{
			name:   "missing token endpoint",
			mutate: func(document map[string]any) { delete(document, "token_endpoint") },
			want:   "token_endpoint",
		},
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
			name:   "unsupported auth method",
			mutate: func(document map[string]any) { document["token_endpoint_auth_methods_supported"] = []string{"none"} },
			want:   "configured token auth method",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				document := oidcDiscoveryFixture(request.Host, "client_secret_basic")
				testCase.mutate(document)
				writeOIDCDiscovery(t, writer, document)
			}))
			defer server.Close()

			cfg := testOIDCConfig(server.URL, "client_secret_basic")
			if testCase.configure != nil {
				cfg = testCase.configure(cfg)
			}

			source := newTestOIDCSource(t, cfg, nil)
			_, err := source.discoveryMetadataLocked(context.Background())
			if err == nil {
				t.Fatal("discovery accepted invalid metadata")
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error = %q, want %q", err.Error(), testCase.want)
			}
		})
	}
}

// TestOIDCTokenAcquisitionSupportsSecretAuthMethods verifies secret-backed token endpoint auth.
func TestOIDCTokenAcquisitionSupportsSecretAuthMethods(t *testing.T) {
	tests := []struct {
		name       string
		authMethod string
		wantToken  string
	}{
		{name: "basic", authMethod: oidcAuthMethodClientSecretBasic, wantToken: "basic-token"},
		{name: "post", authMethod: oidcAuthMethodClientSecretPost, wantToken: "post-token"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newOIDCTokenServer(t, test.authMethod, test.wantToken, 3600, nil)
			defer server.Close()

			cfg := testOIDCConfig(server.URL, test.authMethod)
			source := newTestOIDCSource(t, cfg, nil)

			token, err := source.BearerToken(context.Background())
			if err != nil {
				t.Fatalf("BearerToken returned error: %v", err)
			}

			if token != test.wantToken {
				t.Fatalf("token = %q, want %q", token, test.wantToken)
			}
		})
	}
}

// TestOIDCTokenAcquisitionSupportsPrivateKeyJWT verifies Nauthilus-compatible JWT client auth.
func TestOIDCTokenAcquisitionSupportsPrivateKeyJWT(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	keyFile := writeOIDCPrivateKeyFile(t, privateKey)

	server := newOIDCTokenServer(t, oidcAuthMethodPrivateKeyJWT, "jwt-token", 3600, nil)
	defer server.Close()

	cfg := testOIDCConfig(server.URL, oidcAuthMethodPrivateKeyJWT)
	cfg.ClientCredentials.ClientPrivateKeyFile = config.Secret(keyFile)
	cfg.ClientCredentials.ClientKeyID = "director-key-1"
	cfg.ClientCredentials.ClientAssertionAlg = oidcAssertionAlgRS256
	source := newTestOIDCSource(t, cfg, nil)

	token, err := source.BearerToken(context.Background())
	if err != nil {
		t.Fatalf("BearerToken returned error: %v", err)
	}
	if token != "jwt-token" {
		t.Fatalf("token = %q, want jwt-token", token)
	}
}

// TestOIDCIntrospectionSupportsPrivateKeyJWT verifies Nauthilus-compatible introspection client auth.
func TestOIDCIntrospectionSupportsPrivateKeyJWT(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	keyFile := writeOIDCPrivateKeyFile(t, privateKey)

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case defaultOIDCDiscoveryPath:
			writeOIDCDiscovery(t, writer, oidcDiscoveryFixture(request.Host, oidcAuthMethodClientSecretBasic))
		case "/oidc/introspect":
			assertOIDCIntrospectionRequest(t, request, oidcAuthMethodPrivateKeyJWT)
			writer.Header().Set("Content-Type", defaultHTTPContentType)
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"active":    true,
				"sub":       "operator",
				"client_id": "director-client",
				"aud":       "director-client",
				"scope":     "nauthilus-director.admin",
			})
		default:
			t.Fatalf("unexpected OIDC path %q", request.URL.Path)
		}
	}))
	defer server.Close()

	cfg := testOIDCConfig(server.URL, oidcAuthMethodClientSecretBasic)
	cfg.ClientCredentials.IntrospectionEndpointAuthMethod = oidcAuthMethodPrivateKeyJWT
	cfg.ClientCredentials.ClientPrivateKeyFile = config.Secret(keyFile)
	cfg.ClientCredentials.ClientKeyID = "director-key-1"
	cfg.ClientCredentials.ClientAssertionAlg = oidcAssertionAlgRS256
	introspector, err := NewOIDCIntrospector(cfg, nil)
	if err != nil {
		t.Fatalf("NewOIDCIntrospector returned error: %v", err)
	}

	result, err := introspector.Introspect(context.Background(), "incoming-control-token")
	if err != nil {
		t.Fatalf("Introspect returned error: %v", err)
	}
	if !result.Active || result.Subject != "operator" || result.ClientID != "director-client" {
		t.Fatalf("introspection result = %#v, want active operator client", result)
	}
}

// TestOIDCTokenAcquisitionReadsClientSecretFile verifies mounted secret support.
func TestOIDCTokenAcquisitionReadsClientSecretFile(t *testing.T) {
	secretFile := writeOIDCSecretFile(t, "client-secret\n")
	server := newOIDCTokenServer(t, "client_secret_basic", "file-token", 3600, nil)
	defer server.Close()

	cfg := testOIDCConfig(server.URL, "client_secret_basic")
	cfg.ClientCredentials.ClientSecret = config.Secret("")
	cfg.ClientCredentials.ClientSecretFile = config.Secret(secretFile)
	source := newTestOIDCSource(t, cfg, nil)

	token, err := source.BearerToken(context.Background())
	if err != nil {
		t.Fatalf("BearerToken returned error: %v", err)
	}
	if token != "file-token" {
		t.Fatalf("token = %q, want file-token", token)
	}
}

// TestOIDCTokenSourceCacheHitAndEarlyRefresh verifies cache reuse and refresh timing.
func TestOIDCTokenSourceCacheHitAndEarlyRefresh(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	tokenCalls := 0
	server := newOIDCTokenServer(t, "client_secret_basic", "", 120, func() string {
		tokenCalls++
		if tokenCalls == 1 {
			return "cached-token"
		}

		return "refreshed-token"
	})
	defer server.Close()

	cfg := testOIDCConfig(server.URL, "client_secret_basic")
	source := newTestOIDCSource(t, cfg, &clock)

	first, err := source.BearerToken(context.Background())
	if err != nil {
		t.Fatalf("first token: %v", err)
	}

	clock = clock.Add(30 * time.Second)
	second, err := source.BearerToken(context.Background())
	if err != nil {
		t.Fatalf("cached token: %v", err)
	}
	if first != "cached-token" || second != "cached-token" || tokenCalls != 1 {
		t.Fatalf("cache result = %q/%q calls=%d, want cached token once", first, second, tokenCalls)
	}

	clock = clock.Add(40 * time.Second)
	third, err := source.BearerToken(context.Background())
	if err != nil {
		t.Fatalf("refreshed token: %v", err)
	}
	if third != "refreshed-token" || tokenCalls != 2 {
		t.Fatalf("refresh result = %q calls=%d, want refreshed token", third, tokenCalls)
	}
}

// TestOIDCTokenSourceRefreshFailureUsesUnexpiredCache preserves a usable token.
func TestOIDCTokenSourceRefreshFailureUsesUnexpiredCache(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	failToken := false
	server := newOIDCTokenServer(t, "client_secret_basic", "stable-token", 120, func() string {
		if failToken {
			return ""
		}

		return "stable-token"
	})
	defer server.Close()

	cfg := testOIDCConfig(server.URL, "client_secret_basic")
	source := newTestOIDCSource(t, cfg, &clock)

	if _, err := source.BearerToken(context.Background()); err != nil {
		t.Fatalf("initial token: %v", err)
	}

	failToken = true
	clock = clock.Add(70 * time.Second)
	token, err := source.BearerToken(context.Background())
	if err != nil {
		t.Fatalf("refresh failure with cache returned error: %v", err)
	}
	if token != "stable-token" {
		t.Fatalf("token = %q, want stable-token", token)
	}
}

// TestOIDCTokenSourceRefreshFailureFailsExpiredCache keeps expired tokens fail-closed.
func TestOIDCTokenSourceRefreshFailureFailsExpiredCache(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	failToken := false
	server := newOIDCTokenServer(t, "client_secret_basic", "short-token", 60, func() string {
		if failToken {
			return ""
		}

		return "short-token"
	})
	defer server.Close()

	cfg := testOIDCConfig(server.URL, "client_secret_basic")
	source := newTestOIDCSource(t, cfg, &clock)

	if _, err := source.BearerToken(context.Background()); err != nil {
		t.Fatalf("initial token: %v", err)
	}

	failToken = true
	clock = clock.Add(61 * time.Second)
	_, err := source.BearerToken(context.Background())
	if err == nil {
		t.Fatal("expired token refresh failure returned nil error")
	}
}

// TestOIDCTokenSourceCoalescesConcurrentRefresh verifies one refresh serves concurrent callers.
func TestOIDCTokenSourceCoalescesConcurrentRefresh(t *testing.T) {
	var tokenCalls atomic.Int32
	server := newOIDCTokenServer(t, "client_secret_basic", "", 120, func() string {
		tokenCalls.Add(1)
		time.Sleep(25 * time.Millisecond)

		return "shared-token"
	})
	defer server.Close()

	cfg := testOIDCConfig(server.URL, "client_secret_basic")
	source := newTestOIDCSource(t, cfg, nil)

	var waitGroup sync.WaitGroup
	for range 12 {
		waitGroup.Go(func() {

			token, err := source.BearerToken(context.Background())
			if err != nil {
				t.Errorf("BearerToken returned error: %v", err)
				return
			}
			if token != "shared-token" {
				t.Errorf("token = %q, want shared-token", token)
			}
		})
	}
	waitGroup.Wait()

	if got := tokenCalls.Load(); got != 1 {
		t.Fatalf("token calls = %d, want one coalesced refresh", got)
	}
}

// newTestOIDCSource creates a token source with deterministic refresh jitter.
func newTestOIDCSource(t *testing.T, cfg config.AuthorityOIDCConfig, clock *time.Time) *oidcTokenSource {
	t.Helper()

	options := oidcTokenSourceOptions{
		jitter: func(time.Duration) time.Duration { return 0 },
	}
	if clock != nil {
		options.now = func() time.Time { return *clock }
	}

	source, err := newOIDCTokenSource(cfg, options)
	if err != nil {
		t.Fatalf("newOIDCTokenSource: %v", err)
	}

	return source
}

// testOIDCConfig returns a complete client-credentials authority config.
func testOIDCConfig(issuer string, authMethod string) config.AuthorityOIDCConfig {
	return config.AuthorityOIDCConfig{
		Enabled:      true,
		Issuer:       issuer,
		DiscoveryURL: issuer + defaultOIDCDiscoveryPath,
		ClientCredentials: config.AuthorityOIDCClientCredentialsConfig{
			Enabled:                 true,
			ClientID:                "director-client",
			ClientSecret:            config.Secret("client-secret"),
			TokenEndpointAuthMethod: authMethod,
			Scopes: []string{
				"nauthilus:authenticate",
				"nauthilus:lookup_identity",
				"nauthilus:list_accounts",
			},
			RefreshBeforeExpiry: config.NewDuration(time.Minute),
		},
	}
}

// newOIDCTokenServer starts a fake Nauthilus discovery and token endpoint.
func newOIDCTokenServer(
	t *testing.T,
	authMethod string,
	staticToken string,
	expiresIn int64,
	nextToken func() string,
) *httptest.Server {
	t.Helper()

	var mu sync.Mutex
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case defaultOIDCDiscoveryPath:
			writeOIDCDiscovery(t, writer, oidcDiscoveryFixture(request.Host, authMethod))
		case "/oidc/token":
			assertOIDCTokenRequest(t, request, authMethod)
			mu.Lock()
			token := staticToken
			if nextToken != nil {
				token = nextToken()
			}
			mu.Unlock()
			if token == "" {
				writer.WriteHeader(http.StatusBadGateway)
				_, _ = writer.Write([]byte(`{"error":"temporarily_unavailable"}`))

				return
			}
			writer.Header().Set("Content-Type", defaultHTTPContentType)
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"access_token": token,
				"token_type":   "Bearer",
				"expires_in":   expiresIn,
			})
		default:
			t.Fatalf("unexpected OIDC path %q on %s", request.URL.Path, serverURL)
		}
	}))
	serverURL = server.URL

	return server
}

// oidcDiscoveryFixture returns Nauthilus-style discovery metadata.
func oidcDiscoveryFixture(host string, authMethod string) map[string]any {
	issuer := "http://" + host

	return map[string]any{
		"issuer":                                issuer,
		"token_endpoint":                        issuer + "/oidc/token",
		"introspection_endpoint":                issuer + "/oidc/introspect",
		"jwks_uri":                              issuer + "/oidc/jwks",
		"grant_types_supported":                 []string{"authorization_code", "client_credentials"},
		"token_endpoint_auth_methods_supported": []string{authMethod},
		"introspection_endpoint_auth_methods_supported": []string{
			oidcAuthMethodClientSecretBasic,
			oidcAuthMethodClientSecretPost,
			oidcAuthMethodPrivateKeyJWT,
		},
	}
}

// writeOIDCDiscovery writes a JSON discovery document.
func writeOIDCDiscovery(t *testing.T, writer http.ResponseWriter, document map[string]any) {
	t.Helper()

	writer.Header().Set("Content-Type", defaultHTTPContentType)
	if err := json.NewEncoder(writer).Encode(document); err != nil {
		t.Fatalf("encode discovery: %v", err)
	}
}

// assertOIDCTokenRequest verifies form encoding and selected client auth.
func assertOIDCTokenRequest(t *testing.T, request *http.Request, authMethod string) {
	t.Helper()

	if request.Method != http.MethodPost {
		t.Fatalf("token method = %s, want POST", request.Method)
	}
	if got := request.Header.Get("Content-Type"); got != oidcFormContentType {
		t.Fatalf("token content-type = %q, want form", got)
	}

	if err := request.ParseForm(); err != nil {
		t.Fatalf("parse token form: %v", err)
	}

	if got := request.PostForm.Get("grant_type"); got != grantTypeClientCredentials {
		t.Fatalf("grant_type = %q, want client_credentials", got)
	}

	if got := request.PostForm.Get("scope"); got != "nauthilus:authenticate nauthilus:lookup_identity nauthilus:list_accounts" {
		t.Fatalf("scope = %q, want configured scopes", got)
	}

	assertOIDCTokenClientAuth(t, request, authMethod)
}

// assertOIDCTokenClientAuth verifies token endpoint client auth.
func assertOIDCTokenClientAuth(t *testing.T, request *http.Request, authMethod string) {
	t.Helper()

	switch authMethod {
	case oidcAuthMethodClientSecretBasic:
		if got := request.Header.Get("Authorization"); got != "Basic "+base64.StdEncoding.EncodeToString([]byte("director-client:client-secret")) {
			t.Fatalf("authorization = %q, want client_secret_basic", got)
		}
		if request.PostForm.Get("client_secret") != "" {
			t.Fatal("client_secret_basic leaked client_secret into request body")
		}
	case oidcAuthMethodClientSecretPost:
		assertClientSecretPostRequest(t, request)
	case oidcAuthMethodPrivateKeyJWT:
		assertPrivateKeyJWTRequest(t, request, "http://"+request.Host+"/oidc/token", "private_key_jwt")
	default:
		t.Fatalf("unsupported test auth method %q", authMethod)
	}
}

// assertClientSecretPostRequest verifies secret-in-body client auth.
func assertClientSecretPostRequest(t *testing.T, request *http.Request) {
	t.Helper()

	if strings.HasPrefix(request.Header.Get("Authorization"), "Basic ") {
		t.Fatalf("client_secret_post sent Basic authorization: %q", request.Header.Get("Authorization"))
	}

	if request.PostForm.Get(oidcFormClientID) != "director-client" ||
		request.PostForm.Get(oidcFormClientSecret) != "client-secret" {
		t.Fatalf("post auth form = %#v, want client credentials", request.PostForm)
	}
}

// assertOIDCIntrospectionRequest verifies form encoding and selected introspection client auth.
func assertOIDCIntrospectionRequest(t *testing.T, request *http.Request, authMethod string) {
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

	if got := request.PostForm.Get(oidcIntrospectionTokenParam); got != "incoming-control-token" {
		t.Fatalf("introspection token = %q, want incoming control token", got)
	}

	switch authMethod {
	case oidcAuthMethodPrivateKeyJWT:
		assertPrivateKeyJWTRequest(t, request, "http://"+request.Host+"/oidc/introspect", "private_key_jwt introspection")
	default:
		t.Fatalf("unsupported test introspection auth method %q", authMethod)
	}
}

// assertPrivateKeyJWTRequest verifies JWT assertion client auth without secret leakage.
func assertPrivateKeyJWTRequest(t *testing.T, request *http.Request, audience string, context string) {
	t.Helper()

	if strings.HasPrefix(request.Header.Get("Authorization"), "Basic ") {
		t.Fatalf("%s sent Basic authorization: %q", context, request.Header.Get("Authorization"))
	}

	if request.PostForm.Get(oidcFormClientSecret) != "" {
		t.Fatalf("%s leaked client_secret into request body", context)
	}

	if request.PostForm.Get(oidcFormClientID) != "director-client" {
		t.Fatalf("client_id = %q, want director-client", request.PostForm.Get(oidcFormClientID))
	}

	if request.PostForm.Get(oidcFormClientAssertionType) != oidcAssertionTypeJWTBearer {
		t.Fatalf("client_assertion_type = %q, want JWT bearer", request.PostForm.Get(oidcFormClientAssertionType))
	}

	assertPrivateKeyJWTClaims(t, request.PostForm.Get(oidcFormClientAssertion), audience)
}

// assertPrivateKeyJWTClaims verifies the secret-safe parts of a client assertion.
func assertPrivateKeyJWTClaims(t *testing.T, assertion string, audience string) {
	t.Helper()

	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		t.Fatalf("client_assertion has %d JWT parts, want 3", len(parts))
	}

	header := decodeJWTPart(t, parts[0])
	if header["alg"] != oidcAssertionAlgRS256 || header["kid"] != "director-key-1" {
		t.Fatalf("client_assertion header = %#v, want RS256 kid", header)
	}

	claims := decodeJWTPart(t, parts[1])
	if claims["iss"] != "director-client" || claims["sub"] != "director-client" || claims["aud"] != audience {
		t.Fatalf("client_assertion claims = %#v, want director-client audience %q", claims, audience)
	}
	if _, ok := claims["jti"].(string); !ok {
		t.Fatalf("client_assertion jti missing or non-string: %#v", claims["jti"])
	}
	if exp, ok := claims["exp"].(float64); !ok || exp <= 0 {
		t.Fatalf("client_assertion exp missing or invalid: %#v", claims["exp"])
	}
}

// decodeJWTPart decodes one JSON JWT part from a test assertion.
func decodeJWTPart(t *testing.T, part string) map[string]any {
	t.Helper()

	decoded, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		t.Fatalf("decode JWT part: %v", err)
	}

	var payload map[string]any
	if err = json.Unmarshal(decoded, &payload); err != nil {
		t.Fatalf("unmarshal JWT part: %v", err)
	}

	return payload
}

// writeOIDCSecretFile writes one temporary client secret file.
func writeOIDCSecretFile(t *testing.T, content string) string {
	t.Helper()

	path := t.TempDir() + "/client-secret"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write client secret file: %v", err)
	}

	return path
}

// writeOIDCPrivateKeyFile writes a temporary RSA private key for client assertions.
func writeOIDCPrivateKeyFile(t *testing.T, privateKey *rsa.PrivateKey) string {
	t.Helper()

	path := t.TempDir() + "/client-private-key.pem"
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal client private key: %v", err)
	}
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}
	if err = os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write client private key file: %v", err)
	}

	return path
}
