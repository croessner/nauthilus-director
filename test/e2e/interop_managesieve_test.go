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

//go:build interop

package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	interopDefaultASieveAddressEnv = "NAUTHILUS_DIRECTOR_INTEROP_DEFAULT_A_SIEVE_ADDR"
	interopDefaultBSieveAddressEnv = "NAUTHILUS_DIRECTOR_INTEROP_DEFAULT_B_SIEVE_ADDR"
	interopMasterPasswordEnv       = "NAUTHILUS_DIRECTOR_INTEROP_MASTER_PASSWORD"
	interopManageSieveScriptName   = "interop-m6-sieve-proof"
	interopManageSieveScriptBody   = "keep;"
	interopManageSieveUser         = "interop-ready@example.test"
)

// TestDovecotManageSieveInterop proves real Dovecot ManageSieve proxying through the Director.
func TestDovecotManageSieveInterop(t *testing.T) {
	binary := e2eServerBinary(t)
	imapA := os.Getenv(interopDefaultAAddressEnv)
	imapB := os.Getenv(interopDefaultBAddressEnv)
	sieveA := os.Getenv(interopDefaultASieveAddressEnv)
	sieveB := os.Getenv(interopDefaultBSieveAddressEnv)
	if imapA == "" || imapB == "" || sieveA == "" || sieveB == "" {
		t.Skip("real ManageSieve interop requires mapped Dovecot IMAP and ManageSieve backend addresses")
	}

	redisFixture := startValkeySessionStore(t)
	authority := startMappedFakeOIDCHTTPAuthority(t, map[string]map[string][]string{
		interopManageSieveUser: {
			"account":   {interopManageSieveUser},
			"tenant":    {e2eTenant},
			"mailShard": {e2eShardTag},
		},
	}, nil, fakeOIDCAuthorityOptions{})
	tlsBundle := writeLMTPPeerTLSBundle(t)
	sieveAddress := loopbackAddress(t)
	imapAddress := loopbackAddress(t)
	controlAddress := loopbackAddress(t)
	configPath := writeDovecotManageSieveProcessConfig(t, interopManageSieveProcessConfigOptions{
		RedisAddress:    redisFixture.addr,
		AuthorityURL:    authority.URL(),
		AuthorityOIDC:   processAuthorityOIDCForFake(authority, nil),
		SieveAddress:    sieveAddress,
		IMAPAddress:     imapAddress,
		ControlAddress:  controlAddress,
		SieveBackendA:   sieveA,
		SieveBackendB:   sieveB,
		IMAPBackendA:    imapA,
		IMAPBackendB:    imapB,
		ListenerCert:    tlsBundle.ServerCertPath,
		ListenerKey:     tlsBundle.ServerKeyPath,
		MasterPassword:  interopBackendMasterPassword(),
		BackendTLSMode:  "starttls",
		BackendInsecure: true,
	})
	process := startDirectorProcess(t, binary, configPath)
	controlURL := "http://" + controlAddress
	waitForSieveGreeting(t, sieveAddress, process)
	waitForDirectorGreeting(t, imapAddress, process)
	waitForControlReady(t, controlURL, process)

	ctl := buildDirectorctl(t)
	client := authenticatedDovecotSieveClient(t, sieveAddress, interopManageSieveUser, process)
	defer client.Close()
	proveRealManageSieveCommands(t, client)

	sieveSessions := waitForDirectorctlProtocolSessions(t, ctl, controlURL, e2eSieveProtocol, 1)
	sieveSession := sessionsForUser(sieveSessions, interopManageSieveUser)
	if len(sieveSession) != 1 || sieveSession[0].Backend != e2eSieveBackendAID || sieveSession[0].BackendNode != "mailstore-a-node" {
		t.Fatalf("Sieve session placement = %#v, want %s on mailstore-a-node", sieveSession, e2eSieveBackendAID)
	}

	routeOutput := runDirectorctl(t, ctl, controlURL,
		"route", "lookup",
		"--protocol", e2eSieveProtocol,
		"--user", interopManageSieveUser,
		"--listener", e2eSieveListener,
		"--include-affinity",
	)
	routeFields := parseDirectorctlFields(routeOutput)
	if routeFields["selected_backend"] != e2eSieveBackendAID {
		t.Fatalf("Sieve route lookup = %q, want selected backend %s", routeOutput, e2eSieveBackendAID)
	}
	assertOutputOmits(t, routeOutput, interopManageSieveScriptName, interopManageSieveScriptBody, e2ePassword)

	imapClient, imapReader := loginProcessIMAP(t, imapAddress, interopManageSieveUser)
	defer func() { _ = imapClient.Close() }()
	expectDovecotNOOP(t, imapClient, imapReader, "MS002")
	imapSessions := waitForDirectorctlSessions(t, ctl, controlURL, 1)
	interopIMAPSessions := sessionsForUser(imapSessions, interopManageSieveUser)
	if len(interopIMAPSessions) != 1 || interopIMAPSessions[0].Backend != e2eBackendAID {
		t.Fatalf("IMAP session placement = %#v, want %s", interopIMAPSessions, e2eBackendAID)
	}
	if interopIMAPSessions[0].BackendNode != sieveSession[0].BackendNode {
		t.Fatalf("backend-node mismatch: sieve=%#v imap=%#v", sieveSession[0], interopIMAPSessions[0])
	}

	assertOutputOmits(t, process.output.String(), interopManageSieveScriptName, interopManageSieveScriptBody, e2ePassword)
	authority.ExpectOIDCCallerAuth(t)
}

type interopManageSieveProcessConfigOptions struct {
	RedisAddress    string
	AuthorityURL    string
	AuthorityOIDC   processAuthorityOIDCOptions
	SieveAddress    string
	IMAPAddress     string
	ControlAddress  string
	SieveBackendA   string
	SieveBackendB   string
	IMAPBackendA    string
	IMAPBackendB    string
	ListenerCert    string
	ListenerKey     string
	MasterPassword  string
	BackendTLSMode  string
	BackendInsecure bool
}

// proveRealManageSieveCommands verifies real backend script-management operations.
func proveRealManageSieveCommands(t *testing.T, client *sieveClient) {
	t.Helper()

	client.WriteLine(sieveCommandListScripts)
	client.ExpectStatusPrefix("OK")
	client.WriteLine(`PUTSCRIPT "` + interopManageSieveScriptName + `" "` + interopManageSieveScriptBody + `"`)
	client.ExpectStatusPrefix("OK")
	client.WriteLine(`SETACTIVE "` + interopManageSieveScriptName + `"`)
	client.ExpectStatusPrefix("OK")
	client.WriteLine(sieveCommandListScripts)
	readSieveResponseUntilContains(t, client, interopManageSieveScriptName)
	client.WriteLine(`GETSCRIPT "` + interopManageSieveScriptName + `"`)
	readSieveResponseUntilContains(t, client, interopManageSieveScriptBody)
}

// readSieveResponseUntilContains skips preceding OK statuses until a response carries expected backend bytes.
func readSieveResponseUntilContains(t *testing.T, client *sieveClient, want string) []string {
	t.Helper()

	var last []string
	for range 3 {
		last = client.ReadResponse()
		if strings.Contains(strings.Join(last, "\n"), want) {
			return last
		}
	}

	t.Fatalf("Sieve response = %v, want %q", last, want)
	return nil
}

// authenticatedDovecotSieveClient returns an authenticated Sieve client with interop diagnostics.
func authenticatedDovecotSieveClient(t *testing.T, address string, username string, process *directorProcess) *sieveClient {
	t.Helper()

	client := dialSieveStartedTLS(t, address)
	client.WriteLine(`AUTHENTICATE "PLAIN" "` + sievePlainPayload(username, e2ePassword) + `"`)
	response := client.ReadResponse()
	if len(response) == 0 || !strings.HasPrefix(response[len(response)-1], "OK") {
		client.Close()
		t.Fatalf("Dovecot ManageSieve auth response = %v, want OK; director output:\n%s", response, process.output.String())
	}

	return client
}

// writeDovecotManageSieveProcessConfig writes a real-backend Sieve/IMAP interop config.
func writeDovecotManageSieveProcessConfig(t *testing.T, options interopManageSieveProcessConfigOptions) string {
	t.Helper()

	backendTLSMode := strings.TrimSpace(options.BackendTLSMode)
	if backendTLSMode == "" {
		backendTLSMode = "starttls"
	}
	authorityPasswordPath := writeProcessSecretFile(t, "unused")
	backendPasswordPath := writeProcessSecretFile(t, options.MasterPassword)

	content := fmt.Sprintf(`patch:
  - op: remove
    path: director.listeners
    value: [imaps, lmtp, lmtps, sieves, pop3, pop3s]
  - op: remove
    path: director.backend_pools
    value: [lmtp-default, pop3-default]
  - op: remove
    path: director.backends
    value: [mailstore-a-lmtp, mailstore-b-lmtp, mailstore-a-pop3, mailstore-b-pop3]
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
    proxy_idle: 3s
storage:
  redis:
    protocol: 2
    key_prefix: "nauthilus-director-e2e-managesieve-interop"
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
          password_file: %q
director:
  health:
    interval: 500ms
    timeout: 1s
    jitter: 0s
    unhealthy_after: 1
    healthy_after: 1
  affinity:
    backend_retention:
      enabled: true
      default_ttl: 15m
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
          script_extensions: [fileinto, reject]
          language: en
  backend_pools:
    imap-default:
      protocol: imap
      selector: rendezvous_hash
      backends: [mailstore-a-imap, mailstore-b-imap]
    sieve-default:
      protocol: sieve
      selector: rendezvous_hash
      backends: [mailstore-a-sieve, mailstore-b-sieve]
  backends:
    mailstore-a-imap:
      protocol: imap
      shard_tag: %q
      backend_node: mailstore-a-node
      address: %q
      weight: 100
      max_connections: 100
      maintenance: disabled
      tls:
        mode: starttls
        ca_file: ""
        cert: ""
        key: ""
        server_name: ""
        min_tls_version: TLS1.2
        insecure_skip_verify: true
      auth:
        mode: credential_replay
        credential_replay:
          require_backend_tls: false
          preserve_mechanism: false
          allowed_mechanisms: [plain]
      health_check:
        enabled: false
    mailstore-b-imap:
      protocol: imap
      shard_tag: %q
      backend_node: mailstore-b-node
      address: %q
      weight: 100
      max_connections: 100
      maintenance: disabled
      tls:
        mode: starttls
        ca_file: ""
        cert: ""
        key: ""
        server_name: ""
        min_tls_version: TLS1.2
        insecure_skip_verify: true
      auth:
        mode: credential_replay
        credential_replay:
          require_backend_tls: false
          preserve_mechanism: false
          allowed_mechanisms: [plain]
      health_check:
        enabled: false
    mailstore-a-sieve:
      protocol: sieve
      shard_tag: %q
      backend_node: mailstore-a-node
      address: %q
      weight: 100
      max_connections: 100
      maintenance: disabled
      tls:
        mode: %q
        ca_file: ""
        cert: ""
        key: ""
        server_name: ""
        min_tls_version: TLS1.2
        insecure_skip_verify: %t
      auth:
        mode: master_user
        master_user:
          username: nauthilus-director
          password_file: %q
          user_format: "{user}*{master_user}"
          mechanism: plain
      health_check:
        enabled: false
    mailstore-b-sieve:
      protocol: sieve
      shard_tag: %q
      backend_node: mailstore-b-node
      address: %q
      weight: 100
      max_connections: 100
      maintenance: disabled
      tls:
        mode: %q
        ca_file: ""
        cert: ""
        key: ""
        server_name: ""
        min_tls_version: TLS1.2
        insecure_skip_verify: %t
      auth:
        mode: master_user
        master_user:
          username: nauthilus-director
          password_file: %q
          user_format: "{user}*{master_user}"
          mechanism: plain
      health_check:
        enabled: false
`, options.ControlAddress,
		processControlAuthYAML(t),
		options.RedisAddress,
		processAuthorityOIDCYAMLForOptions(t, options.AuthorityOIDC),
		options.AuthorityURL,
		authorityPasswordPath,
		e2eShardTag,
		options.IMAPAddress,
		options.ListenerCert,
		options.ListenerKey,
		options.SieveAddress,
		options.ListenerCert,
		options.ListenerKey,
		e2eShardTag,
		options.IMAPBackendA,
		e2eShardTagB,
		options.IMAPBackendB,
		e2eShardTag,
		options.SieveBackendA,
		backendTLSMode,
		options.BackendInsecure,
		backendPasswordPath,
		e2eShardTagB,
		options.SieveBackendB,
		backendTLSMode,
		options.BackendInsecure,
		backendPasswordPath,
	)

	path := filepath.Join(t.TempDir(), "nauthilus-director-managesieve-interop.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write ManageSieve interop config: %v", err)
	}

	return path
}

// waitForDirectorctlProtocolSessions polls the CLI for sessions of one protocol.
func waitForDirectorctlProtocolSessions(t *testing.T, ctl string, controlURL string, protocol string, count int) []directorctlSession {
	t.Helper()

	var sessions []directorctlSession
	for attempt := 0; attempt < 50; attempt++ {
		output := runDirectorctl(t, ctl, controlURL, "sessions", "list", "--protocol", protocol)
		sessions = parseDirectorctlSessions(output)
		if len(sessions) == count {
			return sessions
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("directorctl %s sessions count = %d, want %d: %#v", protocol, len(sessions), count, sessions)
	return nil
}

// interopBackendMasterPassword returns the backend master-user secret used by Dovecot interop.
func interopBackendMasterPassword() string {
	if value := os.Getenv(interopMasterPasswordEnv); strings.TrimSpace(value) != "" {
		return value
	}

	return e2ePassword
}
