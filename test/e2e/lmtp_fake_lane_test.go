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

//nolint:dupl,funlen,goconst,gocyclo,wsl_v5 // E2E fixtures keep the public socket transcript visible.
package e2e

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/state"
	lmtpbackend "github.com/croessner/nauthilus-director/test/e2e/fakes/lmtp_backend"
)

const (
	e2eLMTPBackendAID       = "mailstore-a-lmtp"
	e2eLMTPBackendBID       = "mailstore-b-lmtp"
	e2eLMTPBackendPool      = "lmtp-default"
	e2eLMTPListenerName     = "lmtp"
	e2eLMTPSListenerName    = "lmtps"
	e2eLMTPProtocol         = "lmtp"
	e2eLMTPSubmitter        = "submitter@example.test"
	e2eLMTPSSubmitter       = "mtls-submitter.example.test"
	e2eLMTPRecipientA       = "same-a@example.test"
	e2eLMTPRecipientASecond = "same-a-alt@example.test"
	e2eLMTPRecipientB       = "other-b@example.test"
	e2eLMTPRecipientMixed   = "temp-a@example.test"
	e2eLMTPMessageSecret    = "top-secret-message-body"
)

// TestServerBinaryPublicLMTPProductionFlow proves LMTP behavior through process, socket, REST and CLI boundaries.
func TestServerBinaryPublicLMTPProductionFlow(t *testing.T) {
	binary := e2eServerBinary(t)
	ctl := buildDirectorctl(t)
	redisFixture := startValkeySessionStore(t)
	authority := startLMTPAuthority(t, lmtpAuthorityIdentities())
	tlsBundle := writeLMTPPeerTLSBundle(t)
	fakeLMTPA := lmtpbackend.Start(t, lmtpbackend.Options{
		Capabilities: []string{"CHUNKING"},
		FinalStatus: map[string]lmtpbackend.Status{
			lmtpPath(e2eLMTPRecipientMixed): {Code: "451", Enhanced: "4.2.0", Text: "temporary policy detail"},
		},
	})
	fakeLMTPB := lmtpbackend.Start(t, lmtpbackend.Options{Capabilities: []string{"CHUNKING"}})
	fakeIMAPA := startFakeIMAPBackend(t, fakeBackendOptions{})
	fakeIMAPB := startFakeIMAPBackend(t, fakeBackendOptions{})
	lmtpAddress := loopbackAddress(t)
	lmtpsAddress := loopbackAddress(t)
	imapAddress := loopbackAddress(t)
	controlAddress := loopbackAddress(t)
	publishHealthyLMTPBackends(t, redisFixture, []string{e2eLMTPBackendAID, e2eLMTPBackendBID}, "CHUNKING")
	configPath := writeLMTPProcessConfig(t, lmtpProcessConfigOptions{
		RedisAddress:   redisFixture.addr,
		AuthorityURL:   authority.URL(),
		LMTPAddress:    lmtpAddress,
		LMTPSAddress:   lmtpsAddress,
		IMAPAddress:    imapAddress,
		ControlAddress: controlAddress,
		LMTPBackends: map[string]string{
			e2eLMTPBackendAID: fakeLMTPA.Address(),
			e2eLMTPBackendBID: fakeLMTPB.Address(),
		},
		IMAPBackends: map[string]string{
			e2eBackendAID: fakeIMAPA.Address(),
			e2eBackendBID: fakeIMAPB.Address(),
		},
		TLS: tlsBundle,
	})
	process := startDirectorProcess(t, binary, configPath)
	controlURL := "http://" + controlAddress

	waitForLMTPGreeting(t, lmtpAddress, process)
	waitForControlReady(t, controlURL, process)
	exerciseStartTLSLMTPFlow(t, lmtpAddress, imapAddress, controlURL, ctl, authority, fakeLMTPA, fakeIMAPA)
	exerciseBDATAndMixedStatusFlow(t, lmtpAddress, fakeLMTPA)
	exerciseLMTPSMTLSPeerAuth(t, lmtpsAddress, tlsBundle, fakeLMTPA)
	exerciseLMTPMaintenanceEffects(t, lmtpAddress, controlURL, ctl, fakeLMTPA)
	exerciseLMTPRuntimeOut(t, lmtpAddress, controlURL, ctl)
	assertLMTPProcessOutputSafe(t, process.output.String())
}

// TestServerBinaryPublicLMTPChunkingSuppression proves CHUNKING is hidden without backend proof.
func TestServerBinaryPublicLMTPChunkingSuppression(t *testing.T) {
	binary := e2eServerBinary(t)
	redisFixture := startValkeySessionStore(t)
	authority := startLMTPAuthority(t, lmtpAuthorityIdentities())
	tlsBundle := writeLMTPPeerTLSBundle(t)
	fakeLMTPA := lmtpbackend.Start(t, lmtpbackend.Options{})
	fakeLMTPB := lmtpbackend.Start(t, lmtpbackend.Options{})
	fakeIMAPA := startFakeIMAPBackend(t, fakeBackendOptions{})
	fakeIMAPB := startFakeIMAPBackend(t, fakeBackendOptions{})
	lmtpAddress := loopbackAddress(t)
	lmtpsAddress := loopbackAddress(t)
	imapAddress := loopbackAddress(t)
	controlAddress := loopbackAddress(t)
	configPath := writeLMTPProcessConfig(t, lmtpProcessConfigOptions{
		RedisAddress:   redisFixture.addr,
		AuthorityURL:   authority.URL(),
		LMTPAddress:    lmtpAddress,
		LMTPSAddress:   lmtpsAddress,
		IMAPAddress:    imapAddress,
		ControlAddress: controlAddress,
		LMTPBackends: map[string]string{
			e2eLMTPBackendAID: fakeLMTPA.Address(),
			e2eLMTPBackendBID: fakeLMTPB.Address(),
		},
		IMAPBackends: map[string]string{
			e2eBackendAID: fakeIMAPA.Address(),
			e2eBackendBID: fakeIMAPB.Address(),
		},
		TLS: tlsBundle,
	})
	process := startDirectorProcess(t, binary, configPath)

	waitForLMTPGreeting(t, lmtpAddress, process)
	client := dialLMTPS(t, lmtpsAddress, tlsBundle.ClientCertificate)
	defer client.Close()
	client.ExpectLine("220 2.0.0 nauthilus-director LMTP ready\r\n")
	client.WriteLine("LHLO suppress.example")
	capabilities := client.ReadResponse()
	assertLMTPHasCapability(t, capabilities, "SMTPUTF8")
	assertLMTPNoCapability(t, capabilities, "CHUNKING")
	assertLMTPProcessOutputSafe(t, process.output.String())
}

// TestFakeGRPCLMTPRecipientLookup proves the scaffolded gRPC authority uses LookupIdentity for LMTP recipients.
func TestFakeGRPCLMTPRecipientLookup(t *testing.T) {
	service := &fakeGRPCService{
		lookupIdentities: map[string]lmtpAuthorityIdentity{
			e2eLMTPRecipientA: {Account: e2eLMTPRecipientA, Tenant: e2eTenant, Shard: e2eShardTag},
		},
	}
	client, err := nauthilus.NewGRPCClient(service)
	if err != nil {
		t.Fatalf("NewGRPCClient: %v", err)
	}

	result, err := client.LookupIdentity(context.Background(), nauthilus.IdentityLookupRequest{
		Context: nauthilus.RequestContext{
			Username: e2eLMTPRecipientA,
			Protocol: e2eLMTPProtocol,
			Method:   "recipient_lookup",
		},
	})
	if err != nil {
		t.Fatalf("LookupIdentity returned error: %v", err)
	}
	if result.Decision != nauthilus.DecisionAuthenticated || result.Account != e2eLMTPRecipientA {
		t.Fatalf("lookup result = %#v, want authenticated recipient identity", result)
	}
	if lookup := service.SingleLookup(t); lookup.Username != e2eLMTPRecipientA || lookup.Protocol != e2eLMTPProtocol || lookup.Method != "recipient_lookup" {
		t.Fatalf("gRPC lookup request = %#v", lookup)
	}
}

// exerciseStartTLSLMTPFlow proves STARTTLS, SASL peer auth, DATA, route lookup and affinity behavior.
func exerciseStartTLSLMTPFlow(
	t *testing.T,
	address string,
	imapAddress string,
	controlURL string,
	ctl string,
	authority *lmtpAuthority,
	fakeLMTPA *lmtpbackend.Server,
	fakeIMAPA *fakeIMAPBackend,
) {
	t.Helper()

	client := dialLMTP(t, address)
	defer client.Close()
	client.ExpectLine("220 2.0.0 nauthilus-director LMTP ready\r\n")
	client.WriteLine("LHLO starttls.example")
	capabilities := client.ReadResponse()
	assertLMTPHasCapability(t, capabilities, "STARTTLS")
	assertLMTPHasCapability(t, capabilities, "CHUNKING")
	assertLMTPNoCapability(t, capabilities, "AUTH PLAIN")
	client.WriteLine("STARTTLS")
	client.ExpectLine("220 2.0.0 Ready to start TLS\r\n")
	client.UpgradeTLS(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	client.WriteLine("LHLO starttls.example")
	capabilities = client.ReadResponse()
	assertLMTPHasCapability(t, capabilities, "AUTH PLAIN")
	assertLMTPHasCapability(t, capabilities, "CHUNKING")
	assertLMTPNoCapability(t, capabilities, "STARTTLS")
	client.WriteLine("AUTH PLAIN " + plainLMTPPayload(e2eLMTPSubmitter, e2ePassword))
	client.ExpectLine("235 2.7.0 Authentication successful\r\n")
	authority.ExpectPeerAuth(t, e2eLMTPSubmitter)
	client.WriteLine("MAIL FROM:<sender@example.test>")
	client.ExpectLine("250 2.0.0 Sender accepted\r\n")
	client.WriteLine("RCPT TO:<" + e2eLMTPRecipientA + ">")
	client.ExpectLine("250 2.0.0 Recipient accepted\r\n")
	assertNoLMTPSessionsListed(t, ctl, controlURL)
	imapClient, imapReader := loginIMAP(t, imapAddress, e2eLMTPRecipientA)
	defer func() { _ = imapClient.Close() }()
	expectBackendProxy(t, imapClient, imapReader, fakeIMAPA, "A002")
	client.WriteLine("RCPT TO:<" + e2eLMTPRecipientASecond + ">")
	client.ExpectLine("250 2.0.0 Recipient accepted\r\n")
	client.WriteLine("RCPT TO:<" + e2eLMTPRecipientB + ">")
	client.ExpectLine("451 4.3.2 Recipient must be retried separately\r\n")
	client.WriteLine("DATA")
	client.ExpectLine("354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	client.WriteRaw("line-one\r\n" + e2eLMTPMessageSecret + "\r\n.\r\n")
	client.ExpectLine("250 2.1.5 Message accepted\r\n")
	client.ExpectLine("250 2.1.5 Message accepted\r\n")
	observation := fakeLMTPA.ExpectObservation(t)
	assertLMTPBackendObservation(t, observation, []string{lmtpPath(e2eLMTPRecipientA), lmtpPath(e2eLMTPRecipientASecond)}, false)
	if !strings.Contains(observation.Body, e2eLMTPMessageSecret) {
		t.Fatalf("fake backend did not receive DATA body")
	}
	authority.ExpectLookupMode(t, e2eLMTPRecipientA, "no-auth")
	authority.ExpectLookupMode(t, e2eLMTPRecipientASecond, "no-auth")
	routeOutput := runDirectorctl(t, ctl, controlURL, "route", "lookup", "--protocol", e2eLMTPProtocol, "--recipient", e2eLMTPRecipientMixed, "--listener", e2eLMTPListenerName, "--include-affinity")
	if !strings.Contains(routeOutput, "selected_backend="+e2eLMTPBackendAID) || !strings.Contains(routeOutput, "identity_source=nauthilus_lookup") {
		t.Fatalf("route lookup output = %q, want LMTP backend and no-auth identity source", routeOutput)
	}
	authority.ExpectLookupMode(t, e2eLMTPRecipientMixed, "no-auth")
}

// exerciseBDATAndMixedStatusFlow proves BDAT streaming and mixed final status relay.
func exerciseBDATAndMixedStatusFlow(t *testing.T, address string, fakeLMTPA *lmtpbackend.Server) {
	t.Helper()

	client := authenticatedLMTPClient(t, address)
	defer client.Close()
	client.WriteLine("MAIL FROM:<sender@example.test>")
	client.ExpectLine("250 2.0.0 Sender accepted\r\n")
	client.WriteLine("RCPT TO:<" + e2eLMTPRecipientA + ">")
	client.ExpectLine("250 2.0.0 Recipient accepted\r\n")
	client.WriteLine("RCPT TO:<" + e2eLMTPRecipientMixed + ">")
	client.ExpectLine("250 2.0.0 Recipient accepted\r\n")
	client.WriteRaw("BDAT 5\r\nhello")
	client.ExpectLine("250 2.0.0 Message accepted\r\n")
	client.WriteLine("BDAT 0 LAST")
	client.ExpectLine("250 2.1.5 Message accepted\r\n")
	client.ExpectLine("451 4.2.0 Message delivery temporarily failed\r\n")
	observation := fakeLMTPA.ExpectObservation(t)
	assertLMTPBackendObservation(t, observation, []string{lmtpPath(e2eLMTPRecipientA), lmtpPath(e2eLMTPRecipientMixed)}, true)
}

// exerciseLMTPSMTLSPeerAuth proves implicit TLS and explicit mTLS peer-auth policy.
func exerciseLMTPSMTLSPeerAuth(t *testing.T, address string, bundle lmtpPeerTLSBundle, fakeLMTPA *lmtpbackend.Server) {
	t.Helper()

	client := dialLMTPS(t, address, bundle.ClientCertificate)
	defer client.Close()
	client.ExpectLine("220 2.0.0 nauthilus-director LMTP ready\r\n")
	client.WriteLine("LHLO mtls.example")
	capabilities := client.ReadResponse()
	assertLMTPHasCapability(t, capabilities, "CHUNKING")
	assertLMTPNoCapability(t, capabilities, "STARTTLS")
	client.WriteLine("MAIL FROM:<sender@example.test>")
	client.ExpectLine("250 2.0.0 Sender accepted\r\n")
	client.WriteLine("RCPT TO:<" + e2eLMTPRecipientA + ">")
	client.ExpectLine("250 2.0.0 Recipient accepted\r\n")
	client.WriteLine("DATA")
	client.ExpectLine("354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	client.WriteRaw("mtls-body\r\n.\r\n")
	client.ExpectLine("250 2.1.5 Message accepted\r\n")
	observation := fakeLMTPA.ExpectObservation(t)
	assertLMTPBackendObservation(t, observation, []string{lmtpPath(e2eLMTPRecipientA)}, false)
}

// exerciseLMTPMaintenanceEffects proves soft maintenance preserves accepted transactions and excludes new ones.
func exerciseLMTPMaintenanceEffects(t *testing.T, address string, controlURL string, ctl string, fakeLMTPA *lmtpbackend.Server) {
	t.Helper()

	client := authenticatedLMTPClient(t, address)
	defer client.Close()
	client.WriteLine("MAIL FROM:<sender@example.test>")
	client.ExpectLine("250 2.0.0 Sender accepted\r\n")
	client.WriteLine("RCPT TO:<" + e2eLMTPRecipientA + ">")
	client.ExpectLine("250 2.0.0 Recipient accepted\r\n")
	runDirectorctl(t, ctl, controlURL, "backends", "maintenance", "enable", e2eLMTPBackendAID, "--mode", "soft", "--reason", "lmtp soft maintenance proof")
	client.WriteLine("DATA")
	client.ExpectLine("354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	client.WriteRaw("maintenance-body\r\n.\r\n")
	client.ExpectLine("250 2.1.5 Message accepted\r\n")
	assertLMTPBackendObservation(t, fakeLMTPA.ExpectObservation(t), []string{lmtpPath(e2eLMTPRecipientA)}, false)

	rejected := authenticatedLMTPClient(t, address)
	defer rejected.Close()
	rejected.WriteLine("MAIL FROM:<sender@example.test>")
	rejected.ExpectLine("250 2.0.0 Sender accepted\r\n")
	rejected.WriteLine("RCPT TO:<" + e2eLMTPRecipientA + ">")
	rejected.ExpectLine("451 4.3.0 Recipient lookup temporarily unavailable\r\n")
	runDirectorctl(t, ctl, controlURL, "backends", "maintenance", "disable", e2eLMTPBackendAID, "--reason", "lmtp soft maintenance proof complete")
}

// exerciseLMTPRuntimeOut proves runtime out prevents new LMTP placement through the public CLI.
func exerciseLMTPRuntimeOut(t *testing.T, address string, controlURL string, ctl string) {
	t.Helper()

	runDirectorctl(t, ctl, controlURL, "backends", "out", e2eLMTPBackendAID, "--reason", "lmtp out proof")
	client := authenticatedLMTPClient(t, address)
	defer client.Close()
	client.WriteLine("MAIL FROM:<sender@example.test>")
	client.ExpectLine("250 2.0.0 Sender accepted\r\n")
	client.WriteLine("RCPT TO:<" + e2eLMTPRecipientA + ">")
	client.ExpectLine("451 4.3.0 Recipient lookup temporarily unavailable\r\n")
	runDirectorctl(t, ctl, controlURL, "backends", "in", e2eLMTPBackendAID, "--reason", "lmtp out proof complete")
}

// authenticatedLMTPClient returns a STARTTLS and SASL-authenticated LMTP client.
func authenticatedLMTPClient(t *testing.T, address string) *lmtpClient {
	t.Helper()

	client := dialLMTP(t, address)
	client.ExpectLine("220 2.0.0 nauthilus-director LMTP ready\r\n")
	client.WriteLine("LHLO auth.example")
	client.ReadResponse()
	client.WriteLine("STARTTLS")
	client.ExpectLine("220 2.0.0 Ready to start TLS\r\n")
	client.UpgradeTLS(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	client.WriteLine("LHLO auth.example")
	client.ReadResponse()
	client.WriteLine("AUTH PLAIN " + plainLMTPPayload(e2eLMTPSubmitter, e2ePassword))
	client.ExpectLine("235 2.7.0 Authentication successful\r\n")

	return client
}

type lmtpProcessConfigOptions struct {
	RedisAddress                string
	AuthorityURL                string
	LMTPAddress                 string
	LMTPSAddress                string
	IMAPAddress                 string
	ControlAddress              string
	LMTPBackends                map[string]string
	IMAPBackends                map[string]string
	TLS                         lmtpPeerTLSBundle
	DisableLMTPPeerAuth         bool
	IMAPBackendTLSMode          string
	IMAPBackendTLSInsecure      bool
	IMAPBackendCredentialReplay bool
	LMTPBackendTLSMode          string
	LMTPBackendTLSInsecure      bool
}

// writeLMTPProcessConfig writes a production-style config for real LMTP E2E.
func writeLMTPProcessConfig(t *testing.T, options lmtpProcessConfigOptions) string {
	t.Helper()

	imapBackendTLSMode := options.IMAPBackendTLSMode
	if strings.TrimSpace(imapBackendTLSMode) == "" {
		imapBackendTLSMode = "plaintext"
	}
	imapBackendAuthMode := "master_user"
	if options.IMAPBackendCredentialReplay {
		imapBackendAuthMode = "credential_replay"
	}
	lmtpBackendTLSMode := options.LMTPBackendTLSMode
	if strings.TrimSpace(lmtpBackendTLSMode) == "" {
		lmtpBackendTLSMode = "plaintext"
	}
	lmtpPeerAuthRequired := !options.DisableLMTPPeerAuth

	content := fmt.Sprintf(`patch:
  - op: remove
    path: director.listeners
    value: [imaps]
runtime:
  instance_name: "e2e-director"
  process:
    shutdown_timeout: 2s
  servers:
    control:
      enabled: true
      address: %q
  timeouts:
    preauth: 2s
    auth: 2s
    nauthilus: 2s
    backend_connect: 2s
    proxy_idle: 2s
storage:
  redis:
    protocol: 2
    key_prefix: "nauthilus-director-e2e"
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
      http:
        endpoint: %q
        basic_auth:
          password_file: "unused"
director:
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
      proxy_protocol:
        enabled: false
        trusted_cidrs: []
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
        require_id_before_auth: false
    lmtp:
      protocol: lmtp
      service_name: lmtp
      network: tcp
      address: %q
      authority: default
      backend_pool: lmtp-default
      proxy_protocol:
        enabled: false
        trusted_cidrs: []
      tls:
        mode: starttls
        cert: %q
        key: %q
        client_ca: ""
        require_client_cert: false
        min_tls_version: TLS1.2
      lmtp:
        smtputf8: true
        client_auth:
          required: %t
          authority: default
          mechanisms: [plain]
          mtls:
            satisfies_required: false
            identity_source: subject_common_name
        capabilities: [SMTPUTF8, STARTTLS, AUTH PLAIN, CHUNKING]
    lmtps:
      protocol: lmtp
      service_name: lmtps
      network: tcp
      address: %q
      authority: default
      backend_pool: lmtp-default
      proxy_protocol:
        enabled: false
        trusted_cidrs: []
      tls:
        mode: implicit
        cert: %q
        key: %q
        client_ca: %q
        require_client_cert: true
        min_tls_version: TLS1.2
      lmtp:
        smtputf8: true
        client_auth:
          required: true
          authority: default
          mechanisms: [plain]
          mtls:
            satisfies_required: true
            identity_source: subject_common_name
        capabilities: [SMTPUTF8, AUTH PLAIN, CHUNKING]
  backend_pools:
    imap-default:
      protocol: imap
      selector: rendezvous_hash
      backends: [mailstore-a-imap, mailstore-b-imap]
    lmtp-default:
      protocol: lmtp
      selector: recipient_hash
      backends: [mailstore-a-lmtp, mailstore-b-lmtp]
  backends:
    mailstore-a-imap:
      protocol: imap
      shard_tag: %q
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
        mode: %q
        master_user:
          username: director-master
          password_file: backend-master-secret
          user_format: "{user}*{master_user}"
          mechanism: plain
        credential_replay:
          require_backend_tls: false
          preserve_mechanism: false
          allowed_mechanisms: [plain]
      health_check:
        enabled: false
    mailstore-b-imap:
      protocol: imap
      shard_tag: %q
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
        mode: %q
        master_user:
          username: director-master
          password_file: backend-master-secret
          user_format: "{user}*{master_user}"
          mechanism: plain
        credential_replay:
          require_backend_tls: false
          preserve_mechanism: false
          allowed_mechanisms: [plain]
      health_check:
        enabled: false
    mailstore-a-lmtp:
      protocol: lmtp
      shard_tag: %q
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
        mode: none
      health_check:
        enabled: false
    mailstore-b-lmtp:
      protocol: lmtp
      shard_tag: %q
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
        mode: none
      health_check:
        enabled: false
`, options.ControlAddress,
		options.RedisAddress,
		options.AuthorityURL,
		e2eShardTag,
		options.IMAPAddress,
		options.TLS.ServerCertPath,
		options.TLS.ServerKeyPath,
		options.LMTPAddress,
		options.TLS.ServerCertPath,
		options.TLS.ServerKeyPath,
		lmtpPeerAuthRequired,
		options.LMTPSAddress,
		options.TLS.ServerCertPath,
		options.TLS.ServerKeyPath,
		options.TLS.CAPath,
		e2eShardTag,
		options.IMAPBackends[e2eBackendAID],
		imapBackendTLSMode,
		options.IMAPBackendTLSInsecure,
		imapBackendAuthMode,
		e2eShardTagB,
		options.IMAPBackends[e2eBackendBID],
		imapBackendTLSMode,
		options.IMAPBackendTLSInsecure,
		imapBackendAuthMode,
		e2eShardTag,
		options.LMTPBackends[e2eLMTPBackendAID],
		lmtpBackendTLSMode,
		options.LMTPBackendTLSInsecure,
		e2eShardTagB,
		options.LMTPBackends[e2eLMTPBackendBID],
		lmtpBackendTLSMode,
		options.LMTPBackendTLSInsecure,
	)

	path := filepath.Join(t.TempDir(), "nauthilus-director-lmtp.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write LMTP process config: %v", err)
	}

	return path
}

// publishHealthyLMTPBackends seeds backend CHUNKING capability proof before process startup.
func publishHealthyLMTPBackends(t *testing.T, fixture redisSessionFixture, backendIDs []string, capabilities ...string) {
	t.Helper()

	for _, backendID := range backendIDs {
		ctx := context.Background()
		if err := fixture.store.PublishInstanceHeartbeat(ctx, "e2e-director", time.Minute); err != nil {
			t.Fatalf("PublishInstanceHeartbeat: %v", err)
		}
		owner, err := fixture.store.AcquireHealthOwner(ctx, state.HealthOwnershipRequest{
			InstanceID:        "e2e-director",
			BackendIdentifier: backendID,
			LeaseTTL:          time.Minute,
		})
		if err != nil {
			t.Fatalf("AcquireHealthOwner %s: %v", backendID, err)
		}
		_, err = fixture.store.PublishHealthState(ctx, state.HealthPublishRequest{
			InstanceID:        "e2e-director",
			BackendIdentifier: backendID,
			FencingToken:      owner.FencingToken,
			State: backend.HealthState{
				Enabled:      true,
				Status:       backend.HealthStatusHealthy,
				ReasonClass:  "ok",
				Capabilities: backend.NewCapabilitySet(capabilities...),
			},
			TTL: time.Minute,
		})
		if err != nil {
			t.Fatalf("PublishHealthState %s: %v", backendID, err)
		}
	}
}

type lmtpAuthorityIdentity struct {
	Account string
	Tenant  string
	Shard   string
}

type lmtpAuthorityRequest struct {
	Mode string
	Body map[string]any
}

type lmtpAuthority struct {
	server     *http.Server
	listener   net.Listener
	identities map[string]lmtpAuthorityIdentity
	requests   []lmtpAuthorityRequest
	mu         sync.Mutex
}

// startLMTPAuthority starts a public fake HTTP Nauthilus authority for LMTP E2E.
func startLMTPAuthority(t *testing.T, identities map[string]lmtpAuthorityIdentity) *lmtpAuthority {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake LMTP authority: %v", err)
	}
	fake := &lmtpAuthority{listener: ln, identities: identities}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/json", fake.handle)
	fake.server = &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}

	go func() {
		_ = fake.server.Serve(ln)
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = fake.server.Shutdown(ctx)
	})

	return fake
}

// URL returns the public HTTP endpoint.
func (a *lmtpAuthority) URL() string {
	return "http://" + a.listener.Addr().String() + "/api/v1/auth/json"
}

// ExpectPeerAuth verifies the peer-auth credential path used the submitter identity.
func (a *lmtpAuthority) ExpectPeerAuth(t *testing.T, username string) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if a.hasRequest(username, "", "plain") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("peer auth request for %q not observed: %#v", username, a.snapshot())
}

// ExpectLookupMode verifies recipient lookup used the no-auth authority mode.
func (a *lmtpAuthority) ExpectLookupMode(t *testing.T, username string, mode string) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if a.hasRequest(username, mode, "recipient_lookup") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("lookup request for %q mode=%q not observed: %#v", username, mode, a.snapshot())
}

// handle maps one HTTP auth or lookup request to deterministic identity facts.
func (a *lmtpAuthority) handle(writer http.ResponseWriter, request *http.Request) {
	var body map[string]any
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		http.Error(writer, "bad request", http.StatusBadRequest)

		return
	}

	mode := request.URL.Query().Get("mode")
	a.mu.Lock()
	a.requests = append(a.requests, lmtpAuthorityRequest{Mode: mode, Body: body})
	a.mu.Unlock()

	username, _ := body["username"].(string)
	identity := a.identityFor(username)
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"ok":            true,
		"account_field": identity.Account,
		"attributes": map[string][]string{
			"account":   {identity.Account},
			"tenant":    {identity.Tenant},
			"mailShard": {identity.Shard},
		},
	})
}

// identityFor returns a stable identity or a default shard-A identity.
func (a *lmtpAuthority) identityFor(username string) lmtpAuthorityIdentity {
	if identity, ok := a.identities[username]; ok {
		return identity
	}

	return lmtpAuthorityIdentity{Account: username, Tenant: e2eTenant, Shard: e2eShardTag}
}

// hasRequest reports whether a recorded request matches the expected safe fields.
func (a *lmtpAuthority) hasRequest(username string, mode string, method string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	for _, request := range a.requests {
		if request.Mode != mode {
			continue
		}
		if request.Body["username"] == username && request.Body["protocol"] == e2eLMTPProtocol && request.Body["method"] == method {
			return true
		}
	}

	return false
}

// snapshot returns a detached copy of observed fake authority requests.
func (a *lmtpAuthority) snapshot() []lmtpAuthorityRequest {
	a.mu.Lock()
	defer a.mu.Unlock()

	requests := make([]lmtpAuthorityRequest, len(a.requests))
	copy(requests, a.requests)

	return requests
}

// lmtpAuthorityIdentities returns deterministic account-to-shard facts for E2E.
func lmtpAuthorityIdentities() map[string]lmtpAuthorityIdentity {
	return map[string]lmtpAuthorityIdentity{
		e2eLMTPSubmitter:        {Account: e2eLMTPSubmitter, Tenant: e2eTenant, Shard: e2eShardTag},
		e2eLMTPSSubmitter:       {Account: e2eLMTPSSubmitter, Tenant: e2eTenant, Shard: e2eShardTag},
		e2eLMTPRecipientA:       {Account: e2eLMTPRecipientA, Tenant: e2eTenant, Shard: e2eShardTag},
		e2eLMTPRecipientASecond: {Account: e2eLMTPRecipientASecond, Tenant: e2eTenant, Shard: e2eShardTag},
		e2eLMTPRecipientMixed:   {Account: e2eLMTPRecipientMixed, Tenant: e2eTenant, Shard: e2eShardTag},
		e2eLMTPRecipientB:       {Account: e2eLMTPRecipientB, Tenant: e2eTenant, Shard: e2eShardTagB},
	}
}

type lmtpClient struct {
	conn   net.Conn
	reader *bufio.Reader
}

// dialLMTP connects to a public plaintext LMTP listener.
func dialLMTP(t *testing.T, address string) *lmtpClient {
	t.Helper()

	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatalf("dial LMTP %s: %v", address, err)
	}

	return &lmtpClient{conn: conn, reader: bufio.NewReader(conn)}
}

// dialLMTPS connects to a public implicit-TLS LMTP listener.
func dialLMTPS(t *testing.T, address string, certificate tls.Certificate) *lmtpClient {
	t.Helper()

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: time.Second},
		"tcp",
		address,
		&tls.Config{
			Certificates:       []tls.Certificate{certificate},
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	)
	if err != nil {
		t.Fatalf("dial LMTPS %s: %v", address, err)
	}

	return &lmtpClient{conn: conn, reader: bufio.NewReader(conn)}
}

// Close closes the public LMTP connection.
func (c *lmtpClient) Close() {
	_ = c.conn.Close()
}

// WriteLine writes one CRLF-terminated LMTP command.
func (c *lmtpClient) WriteLine(line string) {
	_, _ = io.WriteString(c.conn, line+"\r\n")
}

// WriteRaw writes a raw LMTP payload.
func (c *lmtpClient) WriteRaw(payload string) {
	_, _ = io.WriteString(c.conn, payload)
}

// ExpectLine verifies the next LMTP response line exactly.
func (c *lmtpClient) ExpectLine(want string) {
	line := c.readLine()
	if line != want {
		panic(fmt.Sprintf("LMTP line = %q, want %q", line, want))
	}
}

// ReadResponse reads a single or multi-line SMTP-style response.
func (c *lmtpClient) ReadResponse() []string {
	var lines []string
	for {
		line := c.readLine()
		lines = append(lines, strings.TrimRight(line, "\r\n"))
		if len(line) < 4 || line[3] != '-' {
			return lines
		}
	}
}

// UpgradeTLS performs a STARTTLS handshake on the existing connection.
func (c *lmtpClient) UpgradeTLS(config *tls.Config) {
	tlsConn := tls.Client(c.conn, config.Clone())
	if err := tlsConn.Handshake(); err != nil {
		panic(fmt.Sprintf("STARTTLS handshake failed: %v", err))
	}
	c.conn = tlsConn
	c.reader = bufio.NewReader(tlsConn)
}

// readLine reads one LMTP response line with a bounded deadline.
func (c *lmtpClient) readLine() string {
	_ = c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := c.reader.ReadString('\n')
	if err != nil {
		panic(fmt.Sprintf("read LMTP line: %v", err))
	}

	return line
}

// assertLMTPHasCapability verifies a normalized LHLO capability is present.
func assertLMTPHasCapability(t *testing.T, lines []string, capability string) {
	t.Helper()

	if !lmtpCapabilityPresent(lines, capability) {
		t.Fatalf("capabilities = %v, want %q", lines, capability)
	}
}

// assertLMTPNoCapability verifies a normalized LHLO capability is absent.
func assertLMTPNoCapability(t *testing.T, lines []string, capability string) {
	t.Helper()

	if lmtpCapabilityPresent(lines, capability) {
		t.Fatalf("capabilities = %v, did not want %q", lines, capability)
	}
}

// lmtpCapabilityPresent reports whether the LHLO response contains a capability token.
func lmtpCapabilityPresent(lines []string, capability string) bool {
	want := strings.ToUpper(strings.TrimSpace(capability))
	for _, line := range lines {
		if len(line) < 4 {
			continue
		}
		value := strings.ToUpper(strings.TrimSpace(line[4:]))
		if value == want || strings.HasPrefix(value, want+" ") {
			return true
		}
	}

	return false
}

// assertLMTPBackendObservation verifies recipient forwarding and DATA/BDAT mode.
func assertLMTPBackendObservation(t *testing.T, observation lmtpbackend.Observation, recipients []string, usedBDAT bool) {
	t.Helper()

	if !equalStringSlices(observation.Recipients, recipients) {
		t.Fatalf("backend recipients = %v, want %v", observation.Recipients, recipients)
	}
	if observation.UsedBDAT != usedBDAT {
		t.Fatalf("backend BDAT = %t, want %t", observation.UsedBDAT, usedBDAT)
	}
}

// equalStringSlices compares two ordered string slices.
func equalStringSlices(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}

	return true
}

// assertNoLMTPSessionsListed proves delivery holds are not exposed as login sessions.
func assertNoLMTPSessionsListed(t *testing.T, ctl string, controlURL string) {
	t.Helper()

	output := runDirectorctl(t, ctl, controlURL, "sessions", "list", "--protocol", e2eLMTPProtocol)
	if strings.TrimSpace(output) != "" {
		t.Fatalf("LMTP sessions list output = %q, want empty delivery-hold view", output)
	}
}

// waitForLMTPGreeting waits until the process exposes its public LMTP socket.
func waitForLMTPGreeting(t *testing.T, address string, process *directorProcess) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			line, readErr := bufio.NewReader(conn).ReadString('\n')
			_ = conn.Close()
			if readErr == nil && line == "220 2.0.0 nauthilus-director LMTP ready\r\n" {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("director process did not expose LMTP at %s:\n%s", address, process.output.String())
}

// waitForControlReady waits until the public control API reports readiness.
func waitForControlReady(t *testing.T, controlURL string, process *directorProcess) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		response, err := http.Get(controlURL + "/readyz")
		if err == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("control API did not become ready at %s:\n%s", controlURL, process.output.String())
}

// loopbackAddress reserves one public loopback port for a child process.
func loopbackAddress(t *testing.T) string {
	t.Helper()

	return net.JoinHostPort("127.0.0.1", strconv.Itoa(reserveLoopbackPort(t)))
}

// plainLMTPPayload renders an AUTH PLAIN initial response.
func plainLMTPPayload(username string, password string) string {
	payload := "\x00" + username + "\x00" + password

	return base64.StdEncoding.EncodeToString([]byte(payload))
}

// lmtpPath returns one backend wire recipient path.
func lmtpPath(recipient string) string {
	return "<" + recipient + ">"
}

// assertLMTPProcessOutputSafe verifies process diagnostics did not leak LMTP payloads or identities.
func assertLMTPProcessOutputSafe(t *testing.T, output string) {
	t.Helper()

	assertNoSecretText(t, output)
	for _, forbidden := range []string{
		e2eLMTPRecipientA,
		e2eLMTPRecipientASecond,
		e2eLMTPRecipientB,
		e2eLMTPRecipientMixed,
		e2eLMTPMessageSecret,
		"maintenance-body",
		"mtls-body",
	} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("process output leaked LMTP value %q: %s", forbidden, output)
		}
	}
}

type lmtpPeerTLSBundle struct {
	CAPath            string
	ServerCertPath    string
	ServerKeyPath     string
	ClientCertificate tls.Certificate
}

// writeLMTPPeerTLSBundle creates CA, server and client certificates for listener mTLS.
func writeLMTPPeerTLSBundle(t *testing.T) lmtpPeerTLSBundle {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "LMTP E2E CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}

	serverCertPath, serverKeyPath := writeSignedCertificate(t, caTemplate, caKey, "localhost", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	clientCertPath, clientKeyPath := writeSignedCertificate(t, caTemplate, caKey, e2eLMTPSSubmitter, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	clientCertificate, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		t.Fatalf("load client certificate: %v", err)
	}

	return lmtpPeerTLSBundle{
		CAPath:            writeTempPEM(t, "lmtp-ca-*.pem", "CERTIFICATE", caDER),
		ServerCertPath:    serverCertPath,
		ServerKeyPath:     serverKeyPath,
		ClientCertificate: clientCertificate,
	}
}

// writeSignedCertificate writes a leaf certificate signed by the test CA.
func writeSignedCertificate(t *testing.T, ca *x509.Certificate, caKey *rsa.PrivateKey, commonName string, usages []x509.ExtKeyUsage) (string, string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  usages,
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca, &privateKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	return writeTempPEM(t, "lmtp-leaf-*.crt", "CERTIFICATE", certDER), writeTempBytes(t, "lmtp-leaf-*.key", keyPEM)
}

// writeTempPEM writes DER bytes as one PEM file.
func writeTempPEM(t *testing.T, pattern string, blockType string, der []byte) string {
	t.Helper()

	return writeTempBytes(t, pattern, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}))
}

// writeTempBytes writes temporary bytes to a test-owned file.
func writeTempBytes(t *testing.T, pattern string, contents []byte) string {
	t.Helper()

	file, err := os.CreateTemp(t.TempDir(), pattern)
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer func() { _ = file.Close() }()

	if _, err := file.Write(contents); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	return file.Name()
}
