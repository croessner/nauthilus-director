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
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	interopDefaultAPOP3AddressEnv = "NAUTHILUS_DIRECTOR_INTEROP_DEFAULT_A_POP3_ADDR"
	interopPOP3User               = "pop3-interop@example.test"
)

// TestDovecotPOP3Interop proves real Dovecot POP3 proxying through the Director.
func TestDovecotPOP3Interop(t *testing.T) {
	binary := e2eServerBinary(t)
	dockerCommand := os.Getenv(interopDockerCommandEnv)
	if dockerCommand == "" {
		t.Skipf("%s is required for POP3 interop delivery proof", interopDockerCommandEnv)
	}
	imapBackend := os.Getenv(interopDefaultAAddressEnv)
	lmtpBackend := os.Getenv(interopDefaultALMTPAddressEnv)
	pop3Backend := os.Getenv(interopDefaultAPOP3AddressEnv)
	if imapBackend == "" || lmtpBackend == "" || pop3Backend == "" {
		t.Skip("real POP3 interop requires mapped Dovecot IMAP, LMTP and POP3 backend addresses")
	}

	redisFixture := startValkeySessionStore(t)
	identities := lmtpAuthorityIdentities()
	identities[interopPOP3User] = lmtpAuthorityIdentity{Account: interopPOP3User, Tenant: e2eTenant, Shard: e2eShardTag}
	authority := startMappedFakeOIDCHTTPAuthority(
		t,
		mappedAttributesFromLMTPIdentities(identities),
		nil,
		fakeOIDCAuthorityOptions{},
	)
	pop3Address := loopbackAddress(t)
	imapAddress := loopbackAddress(t)
	lmtpAddress := loopbackAddress(t)
	controlAddress := loopbackAddress(t)
	publishHealthyLMTPBackends(t, redisFixture, []string{e2eLMTPBackendAID}, "CHUNKING")
	configPath := writeDovecotPOP3ProcessConfig(t, dovecotPOP3ProcessConfigOptions{
		RedisAddress:   redisFixture.addr,
		AuthorityURL:   authority.URL(),
		AuthorityOIDC:  processAuthorityOIDCForFake(authority, nil),
		POP3Address:    pop3Address,
		IMAPAddress:    imapAddress,
		LMTPAddress:    lmtpAddress,
		ControlAddress: controlAddress,
		POP3Backend:    pop3Backend,
		IMAPBackend:    imapBackend,
		LMTPBackend:    lmtpBackend,
	})
	process := startDirectorProcess(t, binary, configPath)
	controlURL := "http://" + controlAddress
	waitForPOP3Greeting(t, pop3Address, process)
	waitForDirectorGreeting(t, imapAddress, process)
	waitForLMTPGreeting(t, lmtpAddress, process)
	waitForControlReady(t, controlURL, process)

	deliveryToken := fmt.Sprintf("real-pop3-%d", time.Now().UnixNano())
	provePOP3InteropRecipientAccepted(t, lmtpAddress, interopPOP3User, process)
	runPostfixSwaksSubmit(t, dockerCommand, lmtpAddress, []string{interopPOP3User}, deliveryToken)
	assertCurlIMAPSeesDelivery(t, imapBackend, interopPOP3User, deliveryToken)

	pop3Client := authenticatedPOP3Client(t, pop3Address, interopPOP3User)
	defer pop3Client.Close()
	proveRealPOP3MailboxCommands(t, pop3Client, deliveryToken)
	routeOutput := runDirectorctl(t, buildDirectorctl(t), controlURL,
		"route", "lookup",
		"--protocol", e2eProtocol,
		"--user", interopPOP3User,
		"--listener", e2eListenerName,
		"--include-affinity",
	)
	assertCLIOutputFields(t, routeOutput, "selected_backend="+e2eBackendAID, "source=active_affinity")
	imapClient, imapReader := loginProcessIMAP(t, imapAddress, interopPOP3User)
	expectDovecotNOOP(t, imapClient, imapReader, "P300")
	_ = imapClient.Close()
	pop3Client.WriteLine(pop3CommandQuit)
	pop3Client.ExpectStatusPrefix("+OK")
	pop3Client.Close()
	assertOutputOmits(t, routeOutput, deliveryToken, e2ePassword)
	assertOutputOmits(t, process.output.String(), deliveryToken, e2ePassword)
	authority.ExpectOIDCCallerAuth(t)
}

// provePOP3InteropRecipientAccepted verifies the POP3 mailbox seed recipient crosses public LMTP RCPT.
func provePOP3InteropRecipientAccepted(t *testing.T, lmtpAddress string, recipient string, process *directorProcess) {
	t.Helper()

	client := dialLMTP(t, lmtpAddress)
	defer client.Close()
	client.ExpectLine("220 2.0.0 nauthilus-director LMTP ready\r\n")
	client.WriteLine("LHLO pop3-interop.example")
	_ = client.ReadResponse()
	client.WriteLine("MAIL FROM:<sender@example.test>")
	client.ExpectLine("250 2.0.0 Sender accepted\r\n")
	client.WriteLine("RCPT TO:<" + recipient + ">")
	line := client.readLine()
	if !strings.HasPrefix(line, "250 ") {
		t.Fatalf("POP3 interop LMTP RCPT response = %q, want accepted; director output:\n%s", line, process.output.String())
	}
	client.WriteLine("RSET")
	client.ExpectLine("250 2.0.0 Transaction reset\r\n")
}

type dovecotPOP3ProcessConfigOptions struct {
	RedisAddress   string
	AuthorityURL   string
	AuthorityOIDC  processAuthorityOIDCOptions
	POP3Address    string
	IMAPAddress    string
	LMTPAddress    string
	ControlAddress string
	POP3Backend    string
	IMAPBackend    string
	LMTPBackend    string
}

// proveRealPOP3MailboxCommands verifies real Dovecot POP3 post-auth commands.
func proveRealPOP3MailboxCommands(t *testing.T, client *pop3Client, deliveryToken string) {
	t.Helper()

	client.WriteLine(pop3CommandCapa)
	capability := client.ReadMultiline()
	assertPOP3HasCapability(t, capability, "UIDL")
	client.WriteLine(pop3CommandStat)
	statLine := client.ExpectStatusPrefix("+OK")
	messageNumber := firstPOP3MessageNumber(t, statLine)
	client.WriteLine(pop3CommandList)
	listing := client.ReadMultiline()
	assertPOP3ResponseContains(t, listing, strconv.Itoa(messageNumber))
	client.WriteLine(pop3CommandUIDL)
	uidls := client.ReadMultiline()
	assertPOP3ResponseContains(t, uidls, strconv.Itoa(messageNumber))
	client.WriteLine(pop3CommandRetr + " " + strconv.Itoa(messageNumber))
	message := client.ReadMultiline()
	assertPOP3ResponseContains(t, message, deliveryToken)
}

// firstPOP3MessageNumber returns the first real POP3 message number after STAT.
func firstPOP3MessageNumber(t *testing.T, statLine string) int {
	t.Helper()

	fields := strings.Fields(statLine)
	if len(fields) < 2 {
		t.Fatalf("POP3 STAT response = %q, want message count", statLine)
	}
	count, err := strconv.Atoi(fields[1])
	if err != nil || count <= 0 {
		t.Fatalf("POP3 STAT response = %q, want at least one message", statLine)
	}

	return 1
}

// writeDovecotPOP3ProcessConfig writes a real-backend POP3/IMAP/LMTP interop config.
func writeDovecotPOP3ProcessConfig(t *testing.T, options dovecotPOP3ProcessConfigOptions) string {
	t.Helper()

	listenerCertPath, listenerKeyPath, _ := writeTestCertificate(t)
	authorityPasswordPath := writeProcessSecretFile(t, "unused")
	backendPasswordPath := writeProcessSecretFile(t, os.Getenv("NAUTHILUS_DIRECTOR_INTEROP_MASTER_PASSWORD"))
	content := fmt.Sprintf(`patch:
  - op: remove
    path: director.listeners
    value: [imaps, lmtps, sieve, sieves, pop3s]
  - op: remove
    path: director.backend_pools
    value: [sieve-default]
  - op: remove
    path: director.backends
    value: [mailstore-b-imap, mailstore-b-lmtp, mailstore-a-sieve, mailstore-b-sieve, mailstore-b-pop3]
runtime:
  instance_name: "e2e-pop3-interop-director"
  process:
    shutdown_timeout: 2s
  servers:
    control:
      enabled: true
      address: %q
%s
  timeouts:
    preauth: 3s
    auth: 3s
    nauthilus: 3s
    backend_connect: 3s
    proxy_idle: 5s
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
          password_file: %q
director:
  routing:
    default_shard: %q
  health:
    interval: 250ms
    timeout: 1s
    jitter: 0s
    unhealthy_after: 1
    healthy_after: 1
  affinity:
    backend_retention:
      enabled: true
      default_ttl: 2s
      max_ttl: 24h
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
          required: false
          authority: default
          mechanisms: [plain]
          mtls:
            satisfies_required: false
            identity_source: subject_common_name
        capabilities: [SMTPUTF8, STARTTLS]
    pop3:
      protocol: pop3
      service_name: pop3
      network: tcp
      address: %q
      authority: default
      backend_pool: pop3-default
      tls:
        mode: starttls
        cert: %q
        key: %q
        min_tls_version: TLS1.2
      pop3:
        auth_mechanisms: [userpass]
        capabilities: [STLS, USER, UIDL, TOP, RESP-CODES]
  backend_pools:
    imap-default:
      protocol: imap
      selector: rendezvous_hash
      backends: [mailstore-a-imap]
    lmtp-default:
      protocol: lmtp
      selector: recipient_hash
      backends: [mailstore-a-lmtp]
    pop3-default:
      protocol: pop3
      selector: rendezvous_hash
      backends: [mailstore-a-pop3]
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
    mailstore-a-lmtp:
      protocol: lmtp
      shard_tag: %q
      backend_node: mailstore-a-node
      address: %q
      weight: 100
      max_connections: 100
      maintenance: disabled
      tls:
        mode: implicit
        ca_file: ""
        cert: ""
        key: ""
        server_name: ""
        min_tls_version: TLS1.2
        insecure_skip_verify: true
      auth:
        mode: none
      health_check:
        enabled: false
    mailstore-a-pop3:
      protocol: pop3
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
		e2eProcessKeyPrefix,
		options.RedisAddress,
		processAuthorityOIDCYAMLForOptions(t, options.AuthorityOIDC),
		options.AuthorityURL,
		authorityPasswordPath,
		e2eShardTag,
		options.IMAPAddress,
		listenerCertPath,
		listenerKeyPath,
		options.LMTPAddress,
		listenerCertPath,
		listenerKeyPath,
		options.POP3Address,
		listenerCertPath,
		listenerKeyPath,
		e2eShardTag,
		options.IMAPBackend,
		e2eShardTag,
		options.LMTPBackend,
		e2eShardTag,
		options.POP3Backend,
		backendPasswordPath,
	)

	path := filepath.Join(t.TempDir(), "nauthilus-director-pop3-interop.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write POP3 interop config: %v", err)
	}

	return path
}
