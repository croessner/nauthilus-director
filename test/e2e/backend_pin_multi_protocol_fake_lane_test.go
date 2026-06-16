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

//nolint:funlen,goconst,gocyclo,wsl_v5 // The public-boundary scenario keeps the topology and transcript visible.
package e2e

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/rest/generated"
	lmtpbackend "github.com/croessner/nauthilus-director/test/e2e/fakes/lmtp_backend"
	managesievebackend "github.com/croessner/nauthilus-director/test/e2e/fakes/managesieve_backend"
)

const (
	e2eMultiPinAccountKey         = "multi-pin-account-key-e2e"
	e2eMultiPinLogin              = "multi-pin-login@example.test"
	e2eMultiPinRecipient          = "multi-pin-recipient@example.test"
	e2eMultiPinUnrelatedAccount   = "multi-pin-unrelated-key-e2e"
	e2eMultiPinUnrelatedLogin     = "multi-pin-unrelated@example.test"
	e2eMultiPinUnrelatedRecipient = "multi-pin-unrelated-recipient@example.test"
	e2eMultiPinNode2              = "node2"
	e2eMultiPinCanaryNode         = "mailstack-canary"
	e2eMultiPinNode2IMAP          = "node2-imap"
	e2eMultiPinNode2Sieve         = "node2-sieve"
	e2eMultiPinNode2LMTP          = "node2-lmtp"
	e2eMultiPinCanaryIMAP         = "mailstack-canary-imap"
	e2eMultiPinCanarySieve        = "mailstack-canary-sieve"
	e2eMultiPinCanaryLMTP         = "mailstack-canary-lmtp"
)

// TestServerBinaryBackendNodeAllProtocolPinPublicFlow proves backend-node pinning across IMAP, Sieve and LMTP.
func TestServerBinaryBackendNodeAllProtocolPinPublicFlow(t *testing.T) {
	binary := e2eServerBinary(t)
	ctl := buildDirectorctl(t)
	redisFixture := startValkeySessionStore(t)
	authority := startMappedFakeHTTPAuthority(t, multiProtocolBackendPinAuthorityIdentities(), nil)
	node2IMAP := startFakeIMAPBackend(t, fakeBackendOptions{})
	canaryIMAP := startFakeIMAPBackend(t, fakeBackendOptions{})
	node2Sieve := managesievebackend.Start(t, managesievebackend.Options{})
	canarySieve := managesievebackend.Start(t, managesievebackend.Options{})
	node2LMTP := lmtpbackend.Start(t, lmtpbackend.Options{Capabilities: []string{"CHUNKING"}})
	canaryLMTP := lmtpbackend.Start(t, lmtpbackend.Options{Capabilities: []string{"CHUNKING"}})
	imapAddress := loopbackAddress(t)
	sieveAddress := loopbackAddress(t)
	lmtpAddress := loopbackAddress(t)
	controlAddress := loopbackAddress(t)
	controlURL := "http://" + controlAddress

	publishHealthyLMTPBackends(t, redisFixture, []string{e2eMultiPinNode2LMTP, e2eMultiPinCanaryLMTP}, "CHUNKING")
	configPath := writeMultiProtocolBackendPinProcessConfig(t, multiProtocolBackendPinProcessConfigOptions{
		RedisAddress:   redisFixture.addr,
		AuthorityURL:   authority.URL(),
		IMAPAddress:    imapAddress,
		SieveAddress:   sieveAddress,
		LMTPAddress:    lmtpAddress,
		ControlAddress: controlAddress,
		IMAPBackends: map[string]string{
			e2eMultiPinNode2IMAP:  node2IMAP.Address(),
			e2eMultiPinCanaryIMAP: canaryIMAP.Address(),
		},
		SieveBackends: map[string]string{
			e2eMultiPinNode2Sieve:  node2Sieve.Address(),
			e2eMultiPinCanarySieve: canarySieve.Address(),
		},
		LMTPBackends: map[string]string{
			e2eMultiPinNode2LMTP:  node2LMTP.Address(),
			e2eMultiPinCanaryLMTP: canaryLMTP.Address(),
		},
	})
	process := startDirectorProcess(t, binary, configPath)

	waitForDirectorGreeting(t, imapAddress, process)
	waitForSieveGreeting(t, sieveAddress, process)
	waitForLMTPGreeting(t, lmtpAddress, process)
	waitForControlReady(t, controlURL, process)

	assertMultiProtocolNormalPlacement(t, controlURL, imapAddress, sieveAddress, lmtpAddress, node2IMAP, node2Sieve, node2LMTP)

	runDirectorctl(t, ctl, controlURL, "users", "move", e2eMultiPinAccountKey,
		"--to-shard", e2eMultiPinCanaryNode,
		"--strategy", "new_sessions_only",
		"--reason", "e2e canary shard")
	runDirectorctl(t, ctl, controlURL, "users", "backend-pin", "set", e2eMultiPinAccountKey,
		"--backend-node", e2eMultiPinCanaryNode,
		"--strategy", "new_sessions_only",
		"--reason", "e2e all protocol pin")

	showPins := runDirectorctl(t, ctl, controlURL, "users", "backend-pin", "show", e2eMultiPinAccountKey)
	assertCLIOutputFields(t, showPins,
		"backend="+e2eMultiPinCanaryIMAP,
		"backend="+e2eMultiPinCanarySieve,
		"backend="+e2eMultiPinCanaryLMTP,
		"protocol=imap",
		"protocol=sieve",
		"protocol=lmtp",
		"backend_node="+e2eMultiPinCanaryNode,
	)

	beforeLookupPins := showPins
	beforeLookupSessions := len(waitForRESTSessionCount(t, controlURL, 0))
	assertMultiProtocolPinnedRoute(t, ctl, controlURL, e2eProtocol, e2eListenerName, e2eMultiPinCanaryIMAP)
	assertMultiProtocolPinnedRoute(t, ctl, controlURL, e2eSieveProtocol, e2eSieveListener, e2eMultiPinCanarySieve)
	assertMultiProtocolPinnedRoute(t, ctl, controlURL, e2eLMTPProtocol, e2eLMTPListenerName, e2eMultiPinCanaryLMTP)
	afterLookupSessions := len(waitForRESTSessionCount(t, controlURL, 0))
	afterLookupPins := runDirectorctl(t, ctl, controlURL, "users", "backend-pin", "show", e2eMultiPinAccountKey)
	if beforeLookupSessions != afterLookupSessions || beforeLookupPins != afterLookupPins {
		t.Fatal("route lookup changed public session count or scoped pin state")
	}

	pinnedIMAP, pinnedIMAPReader := loginProcessIMAP(t, imapAddress, e2eMultiPinLogin)
	expectBackendProxy(t, pinnedIMAP, pinnedIMAPReader, canaryIMAP, "PIM002")
	_ = pinnedIMAP.Close()
	waitForRESTSessionCount(t, controlURL, 0)

	pinnedSieve := authenticatedSieveClient(t, sieveAddress, e2eMultiPinLogin)
	pinnedSieve.WriteLine(sieveCommandNoop)
	pinnedSieve.ExpectStatusPrefix("OK")
	pinnedSieve.Close()
	assertSieveObservation(t, canarySieve.ExpectObservation(t), "plain", false)
	waitForRESTSessionCount(t, controlURL, 0)

	marker := "marker-" + fmt.Sprint(time.Now().UnixNano())
	pinnedLMTP := authenticatedLMTPClient(t, lmtpAddress)
	deliverLMTPMessage(t, pinnedLMTP, e2eMultiPinRecipient, "Subject: e2e marker\r\n\r\n"+marker)
	pinnedLMTP.Close()
	lmtpObservation := canaryLMTP.ExpectObservation(t)
	assertLMTPBackendObservation(t, lmtpObservation, []string{lmtpPath(e2eMultiPinRecipient)}, true)
	assertContainsMarkerWithoutLogging(t, lmtpObservation.Body, marker)

	markerIMAP, markerIMAPReader := loginProcessIMAP(t, imapAddress, e2eMultiPinLogin)
	expectIMAPProxyMarker(t, markerIMAP, markerIMAPReader, canaryIMAP, "MIM002", marker)
	_ = markerIMAP.Close()
	waitForRESTSessionCount(t, controlURL, 0)

	runDirectorctl(t, ctl, controlURL, "users", "backend-pin", "clear", e2eMultiPinAccountKey, "--reason", "e2e clear scoped pins")
	clearedPins := runDirectorctl(t, ctl, controlURL, "users", "backend-pin", "show", e2eMultiPinAccountKey)
	assertCLIOutputFields(t, clearedPins, "present=false")
	runDirectorctl(t, ctl, controlURL, "users", "affinity", "clear", e2eMultiPinAccountKey, "--reason", "e2e clear canary affinity")

	resumedRoute := lookupRouteWithAttributes(t, controlURL, e2eProtocol, e2eListenerName, e2eMultiPinAccountKey, map[string][]string{
		"mailShard": {e2eMultiPinNode2},
	})
	if resumedRoute.BackendPin.Present || resumedRoute.SelectedBackend != e2eMultiPinNode2IMAP {
		t.Fatalf("resumed route selected_backend=%q backend_pin_present=%t, want normal node2 placement", resumedRoute.SelectedBackend, resumedRoute.BackendPin.Present)
	}

	assertMultiProtocolPinOutputSafe(t, process.output.String(), marker)
}

// assertMultiProtocolNormalPlacement proves unpinned users avoid weight-zero canary backends.
func assertMultiProtocolNormalPlacement(
	t *testing.T,
	controlURL string,
	imapAddress string,
	sieveAddress string,
	lmtpAddress string,
	node2IMAP *fakeIMAPBackend,
	node2Sieve *managesievebackend.Server,
	node2LMTP *lmtpbackend.Server,
) {
	t.Helper()

	for _, check := range []struct {
		protocol string
		listener string
		backend  string
		canary   string
	}{
		{protocol: e2eProtocol, listener: e2eListenerName, backend: e2eMultiPinNode2IMAP, canary: e2eMultiPinCanaryIMAP},
		{protocol: e2eSieveProtocol, listener: e2eSieveListener, backend: e2eMultiPinNode2Sieve, canary: e2eMultiPinCanarySieve},
		{protocol: e2eLMTPProtocol, listener: e2eLMTPListenerName, backend: e2eMultiPinNode2LMTP, canary: e2eMultiPinCanaryLMTP},
	} {
		route := lookupRouteWithAttributes(t, controlURL, check.protocol, check.listener, e2eMultiPinUnrelatedAccount, map[string][]string{
			"mailShard": {e2eMultiPinNode2},
		})
		if route.FailClosed || route.SelectedBackend != check.backend || route.SelectedBackend == check.canary {
			t.Fatalf("normal %s route selected_backend=%q fail_closed=%t, want %s and no weight-zero canary placement", check.protocol, route.SelectedBackend, route.FailClosed, check.backend)
		}
	}

	imapClient, imapReader := loginProcessIMAP(t, imapAddress, e2eMultiPinUnrelatedLogin)
	expectBackendProxy(t, imapClient, imapReader, node2IMAP, "UIM002")
	_ = imapClient.Close()
	waitForRESTSessionCount(t, controlURL, 0)

	sieveClient := authenticatedSieveClient(t, sieveAddress, e2eMultiPinUnrelatedLogin)
	sieveClient.WriteLine(sieveCommandNoop)
	sieveClient.ExpectStatusPrefix("OK")
	sieveClient.Close()
	assertSieveObservation(t, node2Sieve.ExpectObservation(t), "plain", false)
	waitForRESTSessionCount(t, controlURL, 0)

	lmtpClient := authenticatedLMTPClient(t, lmtpAddress)
	deliverLMTPMessage(t, lmtpClient, e2eMultiPinUnrelatedRecipient, "normal placement body")
	lmtpClient.Close()
	assertLMTPBackendObservation(t, node2LMTP.ExpectObservation(t), []string{lmtpPath(e2eMultiPinUnrelatedRecipient)}, true)
	waitForRESTSessionCount(t, controlURL, 0)
}

// assertMultiProtocolPinnedRoute proves route lookup reports the scoped operator pin.
func assertMultiProtocolPinnedRoute(t *testing.T, ctl string, controlURL string, protocol string, listener string, backendID string) {
	t.Helper()

	output := runDirectorctl(t, ctl, controlURL,
		"route", "lookup",
		"--protocol", protocol,
		"--user", e2eMultiPinAccountKey,
		"--listener", listener,
		"--include-affinity",
	)
	assertCLIOutputFields(t, output,
		"selected_backend="+backendID,
		"source=operator_backend_pin",
		"backend_pin_present=true",
		"backend_pin_applied=true",
		"backend_pin_scope_count=3",
		"backend_pin_other_scope_count=2",
		"backend_pin_reason=backend_pin_applied",
	)
}

// lookupRouteWithAttributes posts one public route lookup request with safe routing attributes.
func lookupRouteWithAttributes(
	t *testing.T,
	baseURL string,
	protocol string,
	listener string,
	userKey string,
	attributes map[string][]string,
) generated.RouteLookupResponse {
	t.Helper()

	includeAffinity := true
	body := generated.LookupRouteJSONRequestBody{
		Attributes:      &attributes,
		IncludeAffinity: &includeAffinity,
		Listener:        &listener,
		Protocol:        protocol,
		UserKey:         &userKey,
	}

	var response generated.RouteLookupResponse
	requestJSON(t, http.MethodPost, baseURL+"/api/v1/route/lookup", body, http.StatusOK, &response)

	return response
}

// expectIMAPProxyMarker proves a public IMAP command with a marker reached the expected backend.
func expectIMAPProxyMarker(t *testing.T, client net.Conn, reader *bufio.Reader, backend *fakeIMAPBackend, tag string, marker string) {
	t.Helper()

	writeLine(t, client, tag+" NOOP "+marker)
	expectLine(t, reader, tag+" OK backend noop\r\n")

	select {
	case observation := <-backend.observations:
		if !strings.Contains(observation.proxyLine, marker) {
			t.Fatal("IMAP marker command did not reach the expected fake backend")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for fake IMAP backend marker observation")
	}
}

// assertContainsMarkerWithoutLogging checks marker correlation without printing message content.
func assertContainsMarkerWithoutLogging(t *testing.T, value string, marker string) {
	t.Helper()

	if !strings.Contains(value, marker) {
		t.Fatal("LMTP backend observation did not contain the generated marker")
	}
}

// assertMultiProtocolPinOutputSafe verifies process diagnostics omit protocol identities and message markers.
func assertMultiProtocolPinOutputSafe(t *testing.T, output string, marker string) {
	t.Helper()

	assertNoSecretText(t, output)
	for _, forbidden := range []string{
		e2eMultiPinLogin,
		e2eMultiPinRecipient,
		e2eMultiPinUnrelatedLogin,
		e2eMultiPinUnrelatedRecipient,
		marker,
	} {
		if strings.TrimSpace(forbidden) != "" && strings.Contains(output, forbidden) {
			t.Fatal("process output leaked a multi-protocol pin E2E identity or marker")
		}
	}
}

type multiProtocolBackendPinProcessConfigOptions struct {
	RedisAddress   string
	AuthorityURL   string
	IMAPAddress    string
	SieveAddress   string
	LMTPAddress    string
	ControlAddress string
	IMAPBackends   map[string]string
	SieveBackends  map[string]string
	LMTPBackends   map[string]string
}

// writeMultiProtocolBackendPinProcessConfig writes the all-protocol canary topology.
func writeMultiProtocolBackendPinProcessConfig(t *testing.T, options multiProtocolBackendPinProcessConfigOptions) string {
	t.Helper()

	certPath, keyPath, _ := writeTestCertificate(t)
	content := fmt.Sprintf(`patch:
  - op: remove
    path: director.listeners
    value: [imaps, lmtps, sieves, pop3, pop3s]
  - op: remove
    path: director.backend_pools
    value: [pop3-default]
  - op: remove
    path: director.backends
    value: [mailstore-a-imap, mailstore-b-imap, mailstore-a-lmtp, mailstore-b-lmtp, mailstore-a-sieve, mailstore-b-sieve, mailstore-a-pop3, mailstore-b-pop3]
runtime:
  instance_name: "e2e-director"
  process:
    shutdown_timeout: 2s
  servers:
    control:
      enabled: true
      address: %q
%s
  timeouts:
    preauth: 2s
    auth: 2s
    nauthilus: 2s
    backend_connect: 2s
    proxy_idle: 2s
storage:
  redis:
    protocol: 2
    key_prefix: %q
    standalone:
      address: %q
    auth:
      username: ""
      password_file: ""
    tls:
      enabled: false
auth:
  authorities:
    default:
      transport: http
%s
      http:
        endpoint: %q
        basic_auth:
          password_file: "unused"
director:
  health:
    interval: 200ms
    timeout: 1s
    jitter: 0s
    unhealthy_after: 1
    healthy_after: 1
  affinity:
    backend_retention:
      enabled: true
      default_ttl: 2s
      max_ttl: 24h
  routing:
    default_selector: rendezvous_hash
    default_shard: %q
  listeners:
    imap:
      protocol: imap
      service_name: imap
      network: tcp
      address: %q
      authority: default
      backend_pool: imap-default
      tls:
        mode: starttls
        cert: %q
        key: %q
        client_ca: ""
        require_client_cert: false
        min_tls_version: TLS1.2
      imap:
        capabilities: [IMAP4rev1, ID, SASL-IR, STARTTLS, AUTH=PLAIN]
        auth_mechanisms: [plain]
    lmtp:
      protocol: lmtp
      service_name: lmtp
      network: tcp
      address: %q
      authority: default
      backend_pool: lmtp-default
      tls:
        mode: starttls
        cert: %q
        key: %q
        client_ca: ""
        require_client_cert: false
        min_tls_version: TLS1.2
      lmtp:
        client_auth:
          required: true
          authority: default
          mechanisms: [plain]
          mtls:
            satisfies_required: false
            identity_source: subject_common_name
        capabilities: [SMTPUTF8, STARTTLS, AUTH PLAIN, CHUNKING]
    sieve:
      protocol: sieve
      service_name: sieve
      network: tcp
      address: %q
      authority: default
      backend_pool: sieve-default
      tls:
        mode: starttls
        cert: %q
        key: %q
        client_ca: ""
        require_client_cert: false
        min_tls_version: TLS1.2
      sieve:
        auth_mechanisms: [plain]
        capabilities:
          script_extensions: [fileinto]
          language: en
  backend_pools:
    imap-default:
      protocol: imap
      selector: rendezvous_hash
      backends: [%s]
    lmtp-default:
      protocol: lmtp
      selector: recipient_hash
      backends: [%s]
    sieve-default:
      protocol: sieve
      selector: rendezvous_hash
      backends: [%s]
  backends:
%s`, options.ControlAddress,
		processControlAuthYAML(t),
		e2eProcessKeyPrefix,
		options.RedisAddress,
		processAuthorityYAML(t, processAuthorityOIDCOptions{}, processAuthorityBearerOptions{}),
		options.AuthorityURL,
		e2eMultiPinNode2,
		options.IMAPAddress,
		certPath,
		keyPath,
		options.LMTPAddress,
		certPath,
		keyPath,
		options.SieveAddress,
		certPath,
		keyPath,
		quotedYAMLStrings([]string{e2eMultiPinNode2IMAP, e2eMultiPinCanaryIMAP}),
		quotedYAMLStrings([]string{e2eMultiPinNode2LMTP, e2eMultiPinCanaryLMTP}),
		quotedYAMLStrings([]string{e2eMultiPinNode2Sieve, e2eMultiPinCanarySieve}),
		multiProtocolBackendPinBackendsYAML(options),
	)
	content = strings.ReplaceAll(content, "\t", "")

	path := filepath.Join(t.TempDir(), "nauthilus-director-multi-protocol-pin.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write multi-protocol backend-pin process config: %v", err)
	}

	return path
}

// multiProtocolBackendPinBackendsYAML renders the node2 plus canary backend set.
func multiProtocolBackendPinBackendsYAML(options multiProtocolBackendPinProcessConfigOptions) string {
	return fmt.Sprintf(`    %s:
      protocol: imap
      shard_tag: %q
      backend_node: %q
      address: %q
      weight: 100
      max_connections: 100
      maintenance: disabled
      tls:
        mode: plaintext
        min_tls_version: TLS1.2
      auth:
        mode: master_user
        master_user:
          username: director-master
          password_file: backend-master-secret
          user_format: "{user}*{master_user}"
          mechanism: plain
      health_check:
        enabled: false
    %s:
      protocol: imap
      shard_tag: %q
      backend_node: %q
      address: %q
      weight: 0
      max_connections: 100
      maintenance: disabled
      tls:
        mode: plaintext
        min_tls_version: TLS1.2
      auth:
        mode: master_user
        master_user:
          username: director-master
          password_file: backend-master-secret
          user_format: "{user}*{master_user}"
          mechanism: plain
      health_check:
        enabled: false
    %s:
      protocol: lmtp
      shard_tag: %q
      backend_node: %q
      address: %q
      weight: 100
      max_connections: 100
      maintenance: disabled
      tls:
        mode: plaintext
        min_tls_version: TLS1.2
      auth:
        mode: none
      health_check:
        enabled: false
    %s:
      protocol: lmtp
      shard_tag: %q
      backend_node: %q
      address: %q
      weight: 0
      max_connections: 100
      maintenance: disabled
      tls:
        mode: plaintext
        min_tls_version: TLS1.2
      auth:
        mode: none
      health_check:
        enabled: false
    %s:
      protocol: sieve
      shard_tag: %q
      backend_node: %q
      address: %q
      weight: 100
      max_connections: 100
      maintenance: disabled
      tls:
        mode: plaintext
        min_tls_version: TLS1.2
      auth:
        mode: master_user
        master_user:
          username: director-master
          password_file: backend-master-secret
          user_format: "{user}*{master_user}"
          mechanism: plain
      health_check:
        enabled: false
    %s:
      protocol: sieve
      shard_tag: %q
      backend_node: %q
      address: %q
      weight: 0
      max_connections: 100
      maintenance: disabled
      tls:
        mode: plaintext
        min_tls_version: TLS1.2
      auth:
        mode: master_user
        master_user:
          username: director-master
          password_file: backend-master-secret
          user_format: "{user}*{master_user}"
          mechanism: plain
      health_check:
        enabled: false
`, e2eMultiPinNode2IMAP, e2eMultiPinNode2, e2eMultiPinNode2, options.IMAPBackends[e2eMultiPinNode2IMAP],
		e2eMultiPinCanaryIMAP, e2eMultiPinCanaryNode, e2eMultiPinCanaryNode, options.IMAPBackends[e2eMultiPinCanaryIMAP],
		e2eMultiPinNode2LMTP, e2eMultiPinNode2, e2eMultiPinNode2, options.LMTPBackends[e2eMultiPinNode2LMTP],
		e2eMultiPinCanaryLMTP, e2eMultiPinCanaryNode, e2eMultiPinCanaryNode, options.LMTPBackends[e2eMultiPinCanaryLMTP],
		e2eMultiPinNode2Sieve, e2eMultiPinNode2, e2eMultiPinNode2, options.SieveBackends[e2eMultiPinNode2Sieve],
		e2eMultiPinCanarySieve, e2eMultiPinCanaryNode, e2eMultiPinCanaryNode, options.SieveBackends[e2eMultiPinCanarySieve],
	)
}

// multiProtocolBackendPinAuthorityIdentities maps public protocol identities onto stable account keys.
func multiProtocolBackendPinAuthorityIdentities() map[string]map[string][]string {
	node2Account := func(account string) map[string][]string {
		return map[string][]string{"account": {account}, "tenant": {e2eTenant}, "mailShard": {e2eMultiPinNode2}}
	}

	return map[string]map[string][]string{
		e2eLMTPSubmitter:              node2Account(e2eLMTPSubmitter),
		e2eMultiPinLogin:              node2Account(e2eMultiPinAccountKey),
		e2eMultiPinRecipient:          node2Account(e2eMultiPinAccountKey),
		e2eMultiPinUnrelatedLogin:     node2Account(e2eMultiPinUnrelatedAccount),
		e2eMultiPinUnrelatedRecipient: node2Account(e2eMultiPinUnrelatedAccount),
		e2eMultiPinAccountKey:         node2Account(e2eMultiPinAccountKey),
		e2eMultiPinUnrelatedAccount:   node2Account(e2eMultiPinUnrelatedAccount),
	}
}
