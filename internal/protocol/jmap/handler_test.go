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

//nolint:funlen,goconst,gocyclo,wsl_v5 // Proxy tests keep request and backend assertions adjacent.
package jmap

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/observability"
	runtimectl "github.com/croessner/nauthilus-director/internal/runtime"
	"github.com/croessner/nauthilus-director/internal/state"
	jmapbackend "github.com/croessner/nauthilus-director/test/e2e/fakes/jmap_backend"
)

// newRequest builds one frontend request with optional Basic credentials.
func newRequest(t *testing.T, method string, url string, body io.Reader, basic bool) *http.Request {
	t.Helper()

	request, err := http.NewRequestWithContext(context.Background(), method, url, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	if basic {
		request.SetBasicAuth(testAccount, testPassword)
	}

	return request
}

// do sends a request and returns status, headers and body.
func do(t *testing.T, client *http.Client, request *http.Request) (int, http.Header, string) {
	t.Helper()

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("request %s %s: %v", request.Method, request.URL.Path, err)
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	return response.StatusCode, response.Header, string(body)
}

// TestBasicAuthProxiesAPIRequestUnchanged proves Basic auth, header forwarding and stripping.
func TestBasicAuthProxiesAPIRequestUnchanged(t *testing.T) {
	h := startHarness(t, harnessOptions{})
	client, _ := h.client()

	request := newRequest(t, http.MethodPost, h.url("/jmap/api/"), strings.NewReader(`{"using":[],"methodCalls":[]}`), true)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Forwarded-For", "198.51.100.66")
	request.Header.Set("Forwarded", "for=198.51.100.66")
	request.Header.Set("X-Real-IP", "198.51.100.66")
	request.Header.Set("X-Forwarded-Host", "evil.example")

	status, header, body := do(t, client, request)
	if status != http.StatusOK || header.Get(jmapbackend.HeaderBackend) != "a" {
		t.Fatalf("status = %d backend = %q body = %s", status, header.Get(jmapbackend.HeaderBackend), body)
	}

	seen, err := h.backendA.LastRequest("/jmap/api/")
	if err != nil {
		t.Fatalf("backend did not receive the API request: %v", err)
	}

	if seen.Authorization != request.Header.Get("Authorization") {
		t.Fatal("backend did not receive the Authorization header unchanged")
	}

	for _, name := range []string{"X-Forwarded-For", "Forwarded", "X-Real-Ip", "X-Forwarded-Host", "X-Forwarded-Proto"} {
		if value := seen.Header.Get(name); value != "" {
			t.Fatalf("backend received client-supplied %s = %q", name, value)
		}
	}

	if seen.Host != h.address {
		t.Fatalf("backend host = %q, want frontend host %q", seen.Host, h.address)
	}

	if seen.BodyBytes != int64(len(`{"using":[],"methodCalls":[]}`)) {
		t.Fatalf("backend body bytes = %d", seen.BodyBytes)
	}

	holds, sessions := h.placer.counts()
	if holds != 1 || sessions != 0 || h.placer.openLeases() != 0 {
		t.Fatalf("placement holds=%d sessions=%d open=%d, want one closed request hold", holds, sessions, h.placer.openLeases())
	}

	if h.placer.keys[0].AccountKey != testAccount || h.placer.keys[0].Tenant != testTenant {
		t.Fatalf("placement key = %+v, want canonical authenticated account", h.placer.keys[0])
	}

	h.assertEventsRedacted()
}

// TestAuthenticationFailuresAnswerChallenges covers missing, rejected, malformed and tempfail credentials.
func TestAuthenticationFailuresAnswerChallenges(t *testing.T) {
	h := startHarness(t, harnessOptions{})
	client, _ := h.client()

	missing := newRequest(t, http.MethodGet, h.url("/.well-known/jmap"), nil, false)
	status, header, _ := do(t, client, missing)
	challenges := header.Values("WWW-Authenticate")

	if status != http.StatusUnauthorized || len(challenges) != 2 ||
		!strings.HasPrefix(challenges[0], `Basic realm="jmap"`) || challenges[1] != `Bearer realm="jmap"` {
		t.Fatalf("missing credentials: status=%d challenges=%q", status, challenges)
	}

	wrong := newRequest(t, http.MethodGet, h.url("/.well-known/jmap"), nil, false)
	wrong.SetBasicAuth(testAccount, "wrong")
	if status, _, _ := do(t, client, wrong); status != http.StatusUnauthorized {
		t.Fatalf("wrong password status = %d, want 401", status)
	}

	badToken := newRequest(t, http.MethodGet, h.url("/.well-known/jmap"), nil, false)
	badToken.Header.Set("Authorization", "Bearer not-the-token")
	status, header, _ = do(t, client, badToken)
	if status != http.StatusUnauthorized || !strings.Contains(strings.Join(header.Values("WWW-Authenticate"), ";"), `error="invalid_token"`) {
		t.Fatalf("bad token: status=%d challenges=%q", status, header.Values("WWW-Authenticate"))
	}

	malformed := newRequest(t, http.MethodGet, h.url("/.well-known/jmap"), nil, false)
	malformed.Header.Set("Authorization", "Digest abc")
	if status, _, _ := do(t, client, malformed); status != http.StatusUnauthorized {
		t.Fatalf("unsupported scheme status = %d, want 401", status)
	}

	h.authority.mu.Lock()
	h.authority.tempfail = true
	h.authority.mu.Unlock()

	other := newRequest(t, http.MethodGet, h.url("/.well-known/jmap"), nil, false)
	other.SetBasicAuth(testAccount, testPassword+"-other")
	status, header, _ = do(t, client, other)
	if status != http.StatusServiceUnavailable || header.Get("Retry-After") == "" {
		t.Fatalf("tempfail status = %d retry-after=%q, want 503", status, header.Get("Retry-After"))
	}

	if len(h.backendA.Requests()) != 0 || len(h.backendB.Requests()) != 0 {
		t.Fatal("refused requests reached a backend")
	}

	h.assertEventsRedacted()
}

// TestBearerAuthIntrospectsAndLooksUpIdentity routes a token-only principal by the lookup attributes.
func TestBearerAuthIntrospectsAndLooksUpIdentity(t *testing.T) {
	h := startHarness(t, harnessOptions{attributes: map[string][]string{testShardAttribute: {testShardB}}})
	client, _ := h.client()

	request := newRequest(t, http.MethodGet, h.url("/.well-known/jmap"), nil, false)
	request.Header.Set("Authorization", "Bearer "+testToken)

	status, header, body := do(t, client, request)
	if status != http.StatusOK || header.Get(jmapbackend.HeaderBackend) != "b" {
		t.Fatalf("status = %d backend = %q body = %s", status, header.Get(jmapbackend.HeaderBackend), body)
	}

	auths, lookups := h.authority.calls()
	if h.introspector.calls.Load() != 1 || lookups != 1 || auths != 0 {
		t.Fatalf("introspections=%d lookups=%d auths=%d, want 1/1/0", h.introspector.calls.Load(), lookups, auths)
	}

	h.authority.mu.Lock()
	lookup := h.authority.lastRequests[len(h.authority.lastRequests)-1]
	h.authority.mu.Unlock()

	if lookup.Protocol != Protocol || lookup.Method != methodIdentityLookup || lookup.Username != testAccount {
		t.Fatalf("lookup context protocol=%q method=%q", lookup.Protocol, lookup.Method)
	}

	h.assertEventsRedacted()
}

// TestMissingShardFailsClosedByDefault refuses accounts without a shard attribute.
func TestMissingShardFailsClosedByDefault(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		policy string
		want   int
	}{
		{name: "default forbidden", policy: "", want: http.StatusForbidden},
		{name: "unavailable", policy: config.JMAPMissingShardUnavailable, want: http.StatusServiceUnavailable},
		{name: "hash fallback", policy: config.JMAPMissingShardHashFallback, want: http.StatusOK},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			h := startHarness(t, harnessOptions{
				attributes: map[string][]string{"unrelated": {"x"}},
				settings: func(settings *config.JMAPListenerConfig) {
					settings.Routing.MissingShard = testCase.policy
				},
			})
			client, _ := h.client()

			status, _, _ := do(t, client, newRequest(t, http.MethodGet, h.url("/.well-known/jmap"), nil, true))
			if status != testCase.want {
				t.Fatalf("status = %d, want %d", status, testCase.want)
			}

			forwarded := len(h.backendA.Requests()) + len(h.backendB.Requests())
			if (testCase.want == http.StatusOK) != (forwarded == 1) {
				t.Fatalf("forwarded requests = %d for status %d", forwarded, testCase.want)
			}
		})
	}
}

// TestPathAndMethodAllowlist keeps everything outside the JMAP surface local and unauthenticated.
func TestPathAndMethodAllowlist(t *testing.T) {
	h := startHarness(t, harnessOptions{})
	client, _ := h.client()

	for _, path := range []string{"/", "/jmap/healthz", "/admin", "/jmap/api/../healthz", "/jmap//api/", "/jmap/download/"} {
		status, _, _ := do(t, client, newRequest(t, http.MethodGet, h.url(path), nil, true))
		if status != http.StatusNotFound {
			t.Fatalf("path %q status = %d, want 404", path, status)
		}
	}

	status, header, _ := do(t, client, newRequest(t, http.MethodDelete, h.url("/jmap/api/"), nil, true))
	if status != http.StatusMethodNotAllowed || header.Get("Allow") != http.MethodPost {
		t.Fatalf("DELETE status = %d allow = %q", status, header.Get("Allow"))
	}

	status, _, body := do(t, client, newRequest(t, http.MethodGet, h.url("/director/healthz"), nil, false))
	if status != http.StatusOK || body != "ok\n" {
		t.Fatalf("health status = %d body = %q", status, body)
	}

	if auths, _ := h.authority.calls(); auths != 0 || len(h.backendA.Requests()) != 0 {
		t.Fatalf("allowlist refusals called the authority %d times or reached the backend", auths)
	}
}

// TestBodyLimitsRejectOversizedRequests enforces declared and streamed body limits.
func TestBodyLimitsRejectOversizedRequests(t *testing.T) {
	h := startHarness(t, harnessOptions{settings: func(settings *config.JMAPListenerConfig) {
		settings.Limits.MaxRequestBodyBytes = 16
		settings.Limits.MaxUploadBodyBytes = 64
	}})
	client, _ := h.client()

	declared := newRequest(t, http.MethodPost, h.url("/jmap/api/"), strings.NewReader(strings.Repeat("x", 17)), true)
	if status, _, _ := do(t, client, declared); status != http.StatusRequestEntityTooLarge {
		t.Fatalf("declared oversize status = %d, want 413", status)
	}

	streamed := newRequest(t, http.MethodPost, h.url("/jmap/upload/"+testAccount+"/"), io.NopCloser(strings.NewReader(strings.Repeat("y", 65))), true)
	streamed.ContentLength = -1
	if status, _, _ := do(t, client, streamed); status != http.StatusRequestEntityTooLarge {
		t.Fatalf("streamed oversize status = %d, want 413", status)
	}

	fitting := newRequest(t, http.MethodPost, h.url("/jmap/upload/"+testAccount+"/"), strings.NewReader(strings.Repeat("z", 64)), true)
	status, _, body := do(t, client, fitting)
	if status != http.StatusCreated || !strings.Contains(body, `"size":64`) {
		t.Fatalf("upload within limit status = %d body = %s", status, body)
	}
}

// TestDownloadPassesRangeAndSecurityHeaders keeps backend download semantics unchanged.
func TestDownloadPassesRangeAndSecurityHeaders(t *testing.T) {
	h := startHarness(t, harnessOptions{})
	client, _ := h.client()

	request := newRequest(t, http.MethodGet, h.url("/jmap/download/"+testAccount+"/blob/name.bin?accept=application/octet-stream"), nil, true)
	request.Header.Set("Range", "bytes=2-5")

	status, header, body := do(t, client, request)
	if status != http.StatusPartialContent || body != jmapbackend.DownloadContent[2:6] {
		t.Fatalf("range status = %d body = %q", status, body)
	}

	for name, want := range map[string]string{
		"Content-Disposition":     `attachment; filename="fixture.bin"`,
		"Content-Security-Policy": "default-src 'none'; sandbox",
		"X-Content-Type-Options":  "nosniff",
	} {
		if header.Get(name) != want {
			t.Fatalf("%s = %q, want %q", name, header.Get(name), want)
		}
	}

	seen, err := h.backendA.LastRequest("/jmap/download/")
	if err != nil || seen.RawQuery != "accept=application/octet-stream" || seen.Header.Get("Range") != "bytes=2-5" {
		t.Fatalf("backend download request = %+v err = %v", seen, err)
	}
}

// TestClientsNeverShareBackendConnections proves per-frontend-connection PROXY tuples.
func TestClientsNeverShareBackendConnections(t *testing.T) {
	h := startHarness(t, harnessOptions{})
	clientA, localsA := h.client()
	clientB, localsB := h.client()

	for range 3 {
		for _, client := range []*http.Client{clientA, clientB} {
			status, _, _ := do(t, client, newRequest(t, http.MethodPost, h.url("/jmap/api/"), strings.NewReader("{}"), true))
			if status != http.StatusOK {
				t.Fatalf("status = %d", status)
			}
		}
	}

	if len(*localsA) != 1 || len(*localsB) != 1 {
		t.Fatalf("frontend connections A=%v B=%v, want one each", *localsA, *localsB)
	}

	connectionsByClient := map[string]map[int64]struct{}{}
	for _, seen := range h.backendA.Requests() {
		if connectionsByClient[seen.ClientAddress] == nil {
			connectionsByClient[seen.ClientAddress] = map[int64]struct{}{}
		}

		connectionsByClient[seen.ClientAddress][seen.Connection] = struct{}{}
	}

	connectionsA := connectionsByClient[(*localsA)[0]]
	connectionsB := connectionsByClient[(*localsB)[0]]

	if len(connectionsByClient) != 2 || len(connectionsA) == 0 || len(connectionsB) == 0 {
		t.Fatalf("backend saw client tuples %v, want exactly the two frontend clients", connectionsByClient)
	}

	for connection := range connectionsA {
		if _, shared := connectionsB[connection]; shared {
			t.Fatalf("backend connection %d carried requests of both clients", connection)
		}
	}

	if len(connectionsA) != 1 || len(connectionsB) != 1 {
		t.Fatalf("backend connections A=%d B=%d, want one reused connection per client", len(connectionsA), len(connectionsB))
	}
}

// TestEventStreamFlushesAndEndsOnKick streams events immediately and closes on a local kick.
func TestEventStreamFlushesAndEndsOnKick(t *testing.T) {
	h := startHarness(t, harnessOptions{})
	client, _ := h.client()

	response, reader := openEventStream(t, h, client)
	defer func() { _ = response.Body.Close() }()

	h.backendA.WaitForOpenStreams(t, 1)

	if _, sessions := h.placer.counts(); sessions != 1 {
		t.Fatalf("event stream sessions = %d, want one session lease", sessions)
	}

	closed, err := h.sessions.CloseUser(context.Background(), runtimectl.UserKey{Tenant: testTenant, UserHash: testAccount}, runtimectl.LocalSessionControl{Action: "kick", Reason: "test"})
	if err != nil || closed != 1 {
		t.Fatalf("CloseUser closed=%d err=%v, want one local stream", closed, err)
	}

	assertStreamEnds(t, reader)
	h.backendA.WaitForOpenStreams(t, 0)
	waitForOpenLeases(t, h.placer, 0)
}

// TestEventStreamEndsOnHeartbeatControlAction honors kicks delivered through Redis heartbeats.
func TestEventStreamEndsOnHeartbeatControlAction(t *testing.T) {
	h := startHarness(t, harnessOptions{})
	client, _ := h.client()

	response, reader := openEventStream(t, h, client)
	defer func() { _ = response.Body.Close() }()

	h.backendA.WaitForOpenStreams(t, 1)
	h.placer.controlAction.Store(state.ControlActionKick)

	assertStreamEnds(t, reader)
	h.backendA.WaitForOpenStreams(t, 0)
	waitForOpenLeases(t, h.placer, 0)

	if h.placer.heartbeats.Load() == 0 {
		t.Fatal("event stream never heartbeat its session lease")
	}
}

// openEventStream opens the event source and requires the first event without waiting for more.
func openEventStream(t *testing.T, h *harness, client *http.Client) (*http.Response, *bufio.Reader) {
	t.Helper()

	request := newRequest(t, http.MethodGet, h.url("/jmap/eventsource/?types=*&closeafter=no&ping=0"), nil, true)

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("open event stream: %v", err)
	}

	if response.StatusCode != http.StatusOK || !strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("event stream status = %d content-type = %q", response.StatusCode, response.Header.Get("Content-Type"))
	}

	reader := bufio.NewReader(response.Body)
	deadline := time.AfterFunc(2*time.Second, func() { _ = response.Body.Close() })
	defer deadline.Stop()

	first, err := reader.ReadString('\n')
	if err != nil || first != "event: state\n" {
		t.Fatalf("first event line = %q err = %v", first, err)
	}

	return response, reader
}

// assertStreamEnds requires the event stream to terminate within a bound.
func assertStreamEnds(t *testing.T, reader *bufio.Reader) {
	t.Helper()

	done := make(chan error, 1)

	go func() {
		_, err := io.Copy(io.Discard, reader)
		done <- err
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("event stream did not end after the control action")
	}
}

// waitForOpenLeases waits until the fake placement reports the wanted number of open leases.
func waitForOpenLeases(t *testing.T, placer *fakePlacer, want int) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if placer.openLeases() == want {
			return
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("open leases = %d, want %d", placer.openLeases(), want)
}

// TestAuthCacheSkipsAuthorityWithinTTL reuses successful results and never caches failures.
func TestAuthCacheSkipsAuthorityWithinTTL(t *testing.T) {
	h := startHarness(t, harnessOptions{})
	client, _ := h.client()

	for range 3 {
		if status, _, _ := do(t, client, newRequest(t, http.MethodGet, h.url("/.well-known/jmap"), nil, true)); status != http.StatusOK {
			t.Fatalf("status = %d", status)
		}
	}

	if auths, _ := h.authority.calls(); auths != 1 {
		t.Fatalf("authority calls = %d, want 1 with the cache", auths)
	}

	for range 2 {
		wrong := newRequest(t, http.MethodGet, h.url("/.well-known/jmap"), nil, false)
		wrong.SetBasicAuth(testAccount, "wrong")
		_, _, _ = do(t, client, wrong)
	}

	if auths, _ := h.authority.calls(); auths != 3 {
		t.Fatalf("authority calls = %d, want failures to bypass the cache", auths)
	}

	var results []string
	for _, event := range h.events.snapshot() {
		if event.Name == observability.EventJMAPRequest {
			results = append(results, event.MetricLabels["result"])
		}
	}

	if strings.Count(strings.Join(results, ","), string(authOutcomeCached)) != 2 {
		t.Fatalf("request auth results = %v, want two cached", results)
	}

	h.assertEventsRedacted()
}

// TestSessionURLMismatchIsReported logs a backend session resource outside the public origin.
func TestSessionURLMismatchIsReported(t *testing.T) {
	h := startHarness(t, harnessOptions{attributes: map[string][]string{testShardAttribute: {testShardB}}})
	client, _ := h.client()

	status, _, body := do(t, client, newRequest(t, http.MethodGet, h.url("/.well-known/jmap"), nil, true))
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}

	var session map[string]any
	if err := json.Unmarshal([]byte(body), &session); err != nil || session["apiUrl"] != "https://other.example.test/jmap/api/" {
		t.Fatalf("session resource was altered: %v %v", session["apiUrl"], err)
	}

	mismatches := 0
	for _, event := range h.events.snapshot() {
		if event.Name == observability.EventJMAPSessionURL {
			mismatches++
		}
	}

	if mismatches != len(sessionURLFields) {
		t.Fatalf("session URL mismatch events = %d, want %d", mismatches, len(sessionURLFields))
	}
}

// TestAcceptStateChangedClosesIdleConnections releases keep-alive connections on drain.
func TestAcceptStateChangedClosesIdleConnections(t *testing.T) {
	h := startHarness(t, harnessOptions{})
	client, locals := h.client()

	if status, _, _ := do(t, client, newRequest(t, http.MethodGet, h.url("/.well-known/jmap"), nil, true)); status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}

	h.handler.AcceptStateChanged(false)
	time.Sleep(50 * time.Millisecond)
	h.handler.AcceptStateChanged(true)

	if status, _, _ := do(t, client, newRequest(t, http.MethodGet, h.url("/.well-known/jmap"), nil, true)); status != http.StatusOK {
		t.Fatalf("status after drain = %d", status)
	}

	if len(*locals) != 2 {
		t.Fatalf("frontend connections = %d, want the idle one closed by the drain", len(*locals))
	}
}

// TestEventStreamOutlivesReadTimeout proves request read bounds never cut an open event stream.
func TestEventStreamOutlivesReadTimeout(t *testing.T) {
	h := startHarness(t, harnessOptions{settings: func(settings *config.JMAPListenerConfig) {
		settings.Timeouts.ReadHeader = config.NewDuration(150 * time.Millisecond)
		settings.Timeouts.Read = config.NewDuration(150 * time.Millisecond)
		settings.EventSource.HeartbeatInterval = config.NewDuration(time.Second)
	}})
	client, _ := h.client()

	response, reader := openEventStream(t, h, client)
	defer func() { _ = response.Body.Close() }()

	time.Sleep(600 * time.Millisecond)

	deadline := time.AfterFunc(2*time.Second, func() { _ = response.Body.Close() })
	defer deadline.Stop()

	for range 3 {
		if _, err := reader.ReadString('\n'); err != nil {
			t.Fatalf("event stream ended after the read timeout: %v", err)
		}
	}

	if h.backendA.OpenStreams() != 1 {
		t.Fatalf("backend open streams = %d, want the stream still open", h.backendA.OpenStreams())
	}
}
