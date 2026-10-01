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

//nolint:goconst,gocyclo,wsl_v5 // Unit fixtures repeat stable paths and credentials intentionally.
package jmap

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
	jmapbackend "github.com/croessner/nauthilus-director/test/e2e/fakes/jmap_backend"
)

// TestClassifyEndpointAllowlist maps only the JMAP surface and the configured health path.
func TestClassifyEndpointAllowlist(t *testing.T) {
	for path, want := range map[string]endpoint{
		"/.well-known/jmap":                  endpointSession,
		"/jmap/api/":                         endpointAPI,
		"/jmap/api":                          endpointAPI,
		"/jmap/upload/alice@example.test/":   endpointUpload,
		"/jmap/download/alice/blob/name.txt": endpointDownload,
		"/jmap/eventsource/":                 endpointEventSource,
		"/director/healthz":                  endpointHealth,
		"/jmap/healthz":                      endpointUnknown,
		"/jmap/download/":                    endpointUnknown,
		"/jmap/upload/":                      endpointUnknown,
		"/jmap/api/../healthz":               endpointUnknown,
		"/jmap/./api/":                       endpointUnknown,
		"//jmap/api/":                        endpointUnknown,
		"/.well-known/jmap/":                 endpointUnknown,
		"/metrics":                           endpointUnknown,
		"":                                   endpointUnknown,
	} {
		if got := classifyEndpoint(path, "/director/healthz"); got != want {
			t.Fatalf("classifyEndpoint(%q) = %q, want %q", path, got, want)
		}
	}
}

// TestEndpointBodyLimits applies the upload limit only to uploads.
func TestEndpointBodyLimits(t *testing.T) {
	limits := config.JMAPLimitsConfig{MaxRequestBodyBytes: 10, MaxUploadBodyBytes: 50}
	if endpointUpload.bodyLimit(limits) != 50 || endpointAPI.bodyLimit(limits) != 10 || endpointDownload.bodyLimit(limits) != 10 {
		t.Fatal("endpoint body limits do not follow the configured policy")
	}
}

// TestAuthCacheExpiresEvictsAndSeparatesClients covers TTL, LRU bound and key separation.
func TestAuthCacheExpiresEvictsAndSeparatesClients(t *testing.T) {
	now := time.Unix(1000, 0)
	cache, err := newAuthCache(30*time.Second, 2, func() time.Time { return now })
	if err != nil {
		t.Fatalf("newAuthCache returned error: %v", err)
	}

	cred := credential{scheme: schemeBasic, username: testAccount, secret: nauthilus.NewSecret(testPassword)}
	keyA := cache.key(cred, "192.0.2.1")

	if keyA == cache.key(cred, "192.0.2.2") {
		t.Fatal("cache key must depend on the client address")
	}

	if keyA == cache.key(credential{scheme: schemeBasic, username: testAccount, secret: nauthilus.NewSecret("other")}, "192.0.2.1") {
		t.Fatal("cache key must depend on the secret")
	}

	if bytes.Contains(keyA[:], []byte(testPassword)) {
		t.Fatal("cache key contains the raw credential")
	}

	cache.put(keyA, principal{account: testAccount, attributes: map[string][]string{testShardAttribute: {testShardA}}})

	got, ok := cache.get(keyA)
	if !ok || got.account != testAccount {
		t.Fatal("fresh entry was not returned")
	}

	got.attributes[testShardAttribute][0] = "mutated"
	if again, _ := cache.get(keyA); again.attributes[testShardAttribute][0] != testShardA {
		t.Fatal("cache returned shared attribute slices")
	}

	now = now.Add(31 * time.Second)
	if _, ok := cache.get(keyA); ok || cache.len() != 0 {
		t.Fatal("expired entry was returned or kept")
	}

	for index, client := range []string{"192.0.2.10", "192.0.2.11", "192.0.2.12"} {
		cache.put(cache.key(cred, client), principal{account: testAccount})

		if cache.len() > 2 {
			t.Fatalf("cache size %d after %d inserts exceeds the bound", cache.len(), index+1)
		}
	}

	if _, ok := cache.get(cache.key(cred, "192.0.2.10")); ok {
		t.Fatal("least recently used entry was not evicted")
	}
}

// TestParseCredentialBounds rejects ambiguous and oversized Authorization headers.
func TestParseCredentialBounds(t *testing.T) {
	auth := &authenticator{basicEnabled: true, bearerEnabled: true, maxBearerBytes: 16}
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(testAccount+":"+testPassword))

	if cred, outcome := auth.parseCredential([]string{basic}); outcome != "" || cred.username != testAccount || cred.secret.Value() != testPassword {
		t.Fatalf("valid basic outcome = %q", outcome)
	}

	for name, values := range map[string][]string{
		"missing":          nil,
		"duplicate":        {basic, basic},
		"no payload":       {"Basic"},
		"bad base64":       {"Basic !!!"},
		"no colon":         {"Basic " + base64.StdEncoding.EncodeToString([]byte(testAccount))},
		"empty password":   {"Basic " + base64.StdEncoding.EncodeToString([]byte(testAccount+":"))},
		"long bearer":      {"Bearer " + strings.Repeat("a", 17)},
		"bearer with ctrl": {"Bearer abc\x01"},
		"bearer non b64":   {"Bearer abc!def"},
		"bearer only pad":  {"Bearer =="},
		"unknown scheme":   {"Negotiate abc"},
	} {
		if _, outcome := auth.parseCredential(values); outcome == "" {
			t.Fatalf("%s: credential accepted", name)
		}
	}

	if _, outcome := auth.parseCredential([]string{"Bearer aB3-._~+/=="}); outcome != "" {
		t.Fatalf("b64token rejected: %q", outcome)
	}

	auth.bearerEnabled = false
	if _, outcome := auth.parseCredential([]string{"Bearer abc"}); outcome != authOutcomeMalformed {
		t.Fatal("bearer accepted on a basic-only listener")
	}
}

// TestSameOriginComparesSchemeAndAuthority accepts URL templates under the public origin.
func TestSameOriginComparesSchemeAndAuthority(t *testing.T) {
	origin := publicOrigin("https://Mail.Example.Test/")
	for value, want := range map[string]bool{
		"https://mail.example.test/jmap/api/":                            true,
		"https://mail.example.test/jmap/download/{accountId}/{blobId}/x": true,
		"https://mail.example.test:8443/jmap/api/":                       false,
		"http://mail.example.test/jmap/api/":                             false,
		"https://shardpost.internal/jmap/api/":                           false,
		"/jmap/api/":                                                     false,
	} {
		if got := sameOrigin(value, origin); got != want {
			t.Fatalf("sameOrigin(%q) = %v, want %v", value, got, want)
		}
	}
}

// TestHealthCheckerProbesWithProxyHeader proves the HTTPS probe works against a PROXY-only backend.
func TestHealthCheckerProbesWithProxyHeader(t *testing.T) {
	certificate := newTestCertificate(t)
	backendTLS := &tls.Config{Certificates: []tls.Certificate{certificate.certificate}, MinVersion: tls.VersionTLS12}
	healthy := jmapbackend.Start(t, jmapbackend.Options{Name: "healthy", TLSConfig: backendTLS, RequireProxyProtocol: true})
	failing := jmapbackend.Start(t, jmapbackend.Options{Name: "failing", TLSConfig: backendTLS, RequireProxyProtocol: true, HealthStatus: http.StatusServiceUnavailable})
	checker := NewHealthChecker(nil)
	request := backend.HealthCheckRequest{Timeout: 2 * time.Second}

	result := checker.CheckBackend(context.Background(), harnessBackend("healthy", testShardA, healthy.Address(), certificate.caFile), request)
	if !result.Healthy || healthy.HealthChecks() != 1 {
		t.Fatalf("healthy result = %+v checks = %d", result, healthy.HealthChecks())
	}

	result = checker.CheckBackend(context.Background(), harnessBackend("failing", testShardA, failing.Address(), certificate.caFile), request)
	if result.Healthy || result.ReasonClass != healthReasonUnhealthy {
		t.Fatalf("failing result = %+v, want unhealthy", result)
	}

	withoutProxy := harnessBackend("no-proxy", testShardA, healthy.Address(), certificate.caFile)
	withoutProxy.HAProxy.Enabled = false

	result = checker.CheckBackend(context.Background(), withoutProxy, request)
	if result.Healthy {
		t.Fatal("backend requiring PROXY answered a probe without the preface")
	}

	untrusted := harnessBackend("untrusted", testShardA, healthy.Address(), "")
	if result = checker.CheckBackend(context.Background(), untrusted, request); result.Healthy || result.ReasonClass != healthReasonTLS {
		t.Fatalf("untrusted certificate result = %+v, want tls failure", result)
	}
}

// TestChallengesMarkInvalidTokenOnlyForBearer keeps Basic failures free of token error codes.
func TestChallengesMarkInvalidTokenOnlyForBearer(t *testing.T) {
	auth := &authenticator{basicEnabled: true, bearerEnabled: true, cfg: Config{Settings: config.JMAPListenerConfig{Auth: config.JMAPAuthConfig{Realm: "jmap"}}}}

	for _, value := range auth.challenges(authOutcomeMalformed, false) {
		if strings.Contains(value, "invalid_token") {
			t.Fatalf("basic failure challenge = %q", value)
		}
	}

	if got := strings.Join(auth.challenges(authOutcomeRejected, true), ";"); !strings.Contains(got, `error="invalid_token"`) {
		t.Fatalf("bearer failure challenges = %q", got)
	}
}

// TestRequestContextReportsFrontendTLS pins the Nauthilus ssl value for JMAP requests: empty for
// cleartext HTTP (the only value Nauthilus treats as unencrypted) and "on" behind TLS.
func TestRequestContextReportsFrontendTLS(t *testing.T) {
	auth := &authenticator{}

	cleartext, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://jmap.example.test/jmap/api/", nil)
	if err != nil {
		t.Fatalf("build cleartext request: %v", err)
	}

	if got := auth.requestContext(cleartext, "plain").TLS; got != "" {
		t.Fatalf("cleartext TLS = %q, want empty", got)
	}

	encrypted := cleartext.Clone(cleartext.Context())
	encrypted.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256}

	requestContext := auth.requestContext(encrypted, "plain")
	if requestContext.TLS != "on" || requestContext.TLSProtocol != "TLS1.3" {
		t.Fatalf("TLS context = %q/%q, want on/TLS1.3", requestContext.TLS, requestContext.TLSProtocol)
	}
}
