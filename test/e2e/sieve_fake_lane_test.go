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

//nolint:funlen,goconst,gocyclo,wsl_v5 // E2E transcripts stay visible for review.
package e2e

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	lmtpbackend "github.com/croessner/nauthilus-director/test/e2e/fakes/lmtp_backend"
	managesievebackend "github.com/croessner/nauthilus-director/test/e2e/fakes/managesieve_backend"
)

const (
	e2eSieveBearerAccount    = "sieve-bearer@example.test"
	e2eSieveCrossAccount     = "sieve-cross@example.test"
	e2eSieveHoldAccount      = "sieve-hold@example.test"
	e2eSievePinnedAccount    = "sieve-pinned@example.test"
	e2eSieveRuntimeAccount   = "sieve-runtime@example.test"
	e2eSieveSentinelContent  = "require [\"fileinto\"]; # sentinel-script-content"
	e2eSieveSentinelName     = "sentinel-script-name"
	e2eSieveShardBAccount    = "sieve-b@example.test"
	e2eSieveMaintenanceProof = "sieve-maintenance@example.test"
	sieveCommandCapability   = "CAPABILITY"
	sieveCommandListScripts  = "LISTSCRIPTS"
	sieveCommandNoop         = "NOOP"
	sieveCommandPutScript    = "PUTSCRIPT"
	sieveCommandStartTLS     = "STARTTLS"
)

// TestServerBinaryPublicSieveProductionFlow proves ManageSieve through public process boundaries.
func TestServerBinaryPublicSieveProductionFlow(t *testing.T) {
	binary := e2eServerBinary(t)
	ctl := buildDirectorctl(t)
	redisFixture := startValkeySessionStore(t)
	authority := startMappedFakeHTTPAuthority(t, sieveAuthorityIdentities(), nil)
	fakeSieveA := managesievebackend.Start(t, managesievebackend.Options{
		ExpectedScripts: map[string]string{e2eSieveSentinelName: e2eSieveSentinelContent},
	})
	fakeSieveB := managesievebackend.Start(t, managesievebackend.Options{})
	fakeIMAPA := startFakeIMAPBackend(t, fakeBackendOptions{})
	fakeIMAPB := startFakeIMAPBackend(t, fakeBackendOptions{})
	fakeLMTPA := lmtpbackend.Start(t, lmtpbackend.Options{})
	fakeLMTPB := lmtpbackend.Start(t, lmtpbackend.Options{})
	sieveAddress := loopbackAddress(t)
	sievesAddress := loopbackAddress(t)
	imapAddress := loopbackAddress(t)
	lmtpAddress := loopbackAddress(t)
	controlAddress := loopbackAddress(t)
	configPath := writeSieveProductionProcessConfig(t, sieveProductionProcessConfigOptions{
		RedisAddress:   redisFixture.addr,
		AuthorityURL:   authority.URL(),
		SieveAddress:   sieveAddress,
		SievesAddress:  sievesAddress,
		IMAPAddress:    imapAddress,
		LMTPAddress:    lmtpAddress,
		ControlAddress: controlAddress,
		SieveBackends: map[string]string{
			e2eSieveBackendAID: fakeSieveA.Address(),
			e2eSieveBackendBID: fakeSieveB.Address(),
		},
		IMAPBackends: map[string]string{
			e2eBackendAID: fakeIMAPA.Address(),
			e2eBackendBID: fakeIMAPB.Address(),
		},
		LMTPBackends: map[string]string{
			e2eLMTPBackendAID: fakeLMTPA.Address(),
			e2eLMTPBackendBID: fakeLMTPB.Address(),
		},
		UserHoldMaxWait:      175 * time.Millisecond,
		UserHoldPollInterval: 25 * time.Millisecond,
	})
	process := startDirectorProcess(t, binary, configPath)
	controlURL := "http://" + controlAddress

	waitForSieveGreeting(t, sieveAddress, process)
	waitForTCPListener(t, sievesAddress, process)
	waitForDirectorGreeting(t, imapAddress, process)
	waitForLMTPGreeting(t, lmtpAddress, process)
	waitForControlReady(t, controlURL, process)

	exerciseSieveStartTLSAuthProxyAndRouteLookup(t, sieveAddress, controlURL, ctl, authority, fakeSieveA, process)
	exerciseSieveImplicitBearerAuth(t, sievesAddress, authority, fakeSieveB)
	exerciseIMAPAndLMTPAffinityInfluenceSieve(t, sieveAddress, imapAddress, lmtpAddress, controlURL, fakeIMAPA, fakeSieveA, fakeLMTPA)
	exerciseSieveAffinityInfluencesIMAP(t, sieveAddress, imapAddress, controlURL, ctl, fakeSieveA, fakeIMAPA)
	exerciseSieveRuntimeControls(t, sieveAddress, controlURL, ctl, fakeSieveA, fakeSieveB, process)

	assertSieveProcessOutputSafe(t, process.output.String())
}

// exerciseSieveStartTLSAuthProxyAndRouteLookup proves frontend TLS, auth, proxying and diagnostics.
func exerciseSieveStartTLSAuthProxyAndRouteLookup(
	t *testing.T,
	address string,
	controlURL string,
	ctl string,
	authority *fakeHTTPAuthority,
	fakeSieveA *managesievebackend.Server,
	process *directorProcess,
) {
	t.Helper()

	beforeAuth := authority.RequestCount()
	client := dialSieve(t, address)
	defer client.Close()
	greeting := client.ReadResponse()
	assertSieveHasCapability(t, greeting, "STARTTLS")
	assertSieveSASLValue(t, greeting, "")
	client.WriteLine(`AUTHENTICATE "PLAIN" "` + sievePlainPayload(e2eSieveAccount, e2ePassword) + `"`)
	client.ExpectStatusPrefix("NO (ENCRYPT-NEEDED)")
	if authority.RequestCount() != beforeAuth {
		t.Fatal("plaintext Sieve auth reached Nauthilus before STARTTLS")
	}

	client.WriteLine(sieveCommandStartTLS)
	client.ExpectStatusPrefix("OK")
	client.UpgradeTLS(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	client.WriteLine(sieveCommandCapability)
	capability := client.ReadResponse()
	assertSieveNoCapability(t, capability, "STARTTLS")
	assertSieveSASLValue(t, capability, "PLAIN XOAUTH2 OAUTHBEARER")

	routeOutput := runDirectorctl(t, ctl, controlURL,
		"route", "lookup",
		"--protocol", e2eSieveProtocol,
		"--user", e2eSieveAccount,
		"--listener", e2eSieveListener,
		"--include-affinity",
	)
	assertCLIOutputFields(t, routeOutput, "selected_backend="+e2eSieveBackendAID, "source=initial_placement")
	assertOutputOmits(t, routeOutput, e2eSieveSentinelName, e2eSieveSentinelContent, e2ePassword, e2eToken)

	client.WriteLine(`AUTHENTICATE "PLAIN" "` + sievePlainPayload(e2eSieveAccount, e2ePassword) + `"`)
	client.ExpectStatusPrefix("OK")
	client.WriteLine(`PUTSCRIPT "` + e2eSieveSentinelName + `" {` + strconv.Itoa(len(e2eSieveSentinelContent)) + `}`)
	client.WriteRaw(e2eSieveSentinelContent + "\r\n")
	client.ExpectStatusPrefix("OK")
	client.WriteLine(`SETACTIVE "` + e2eSieveSentinelName + `"`)
	client.ExpectStatusPrefix("OK")
	client.WriteLine(sieveCommandListScripts)
	listResponse := client.ReadResponse()
	assertSieveResponseContains(t, listResponse, e2eSieveSentinelName)
	client.WriteLine(`GETSCRIPT "` + e2eSieveSentinelName + `"`)
	getResponse := client.ReadResponse()
	assertSieveResponseContains(t, getResponse, e2eSieveSentinelContent)
	client.Close()

	observation := fakeSieveA.ExpectObservation(t)
	assertSieveObservation(t, observation, "plain", true)
	sessionsOutput := runDirectorctl(t, ctl, controlURL, "sessions", "list", "--protocol", e2eSieveProtocol)
	assertOutputOmits(t, sessionsOutput, e2eSieveSentinelName, e2eSieveSentinelContent)
	assertOutputOmits(t, process.output.String(), e2eSieveSentinelName, e2eSieveSentinelContent)
}

// exerciseSieveImplicitBearerAuth proves implicit TLS and bearer SASL mechanisms over public sockets.
func exerciseSieveImplicitBearerAuth(t *testing.T, address string, authority *fakeHTTPAuthority, fakeSieveB *managesievebackend.Server) {
	t.Helper()

	xoauth2 := dialSieveTLS(t, address)
	defer xoauth2.Close()
	greeting := xoauth2.ReadResponse()
	assertSieveNoCapability(t, greeting, "STARTTLS")
	assertSieveSASLValue(t, greeting, "PLAIN XOAUTH2 OAUTHBEARER")
	xoauth2.WriteLine(`AUTHENTICATE "XOAUTH2" "` + sieveXOAUTH2Payload(e2eSieveShardBAccount, e2eToken) + `"`)
	xoauth2.ExpectStatusPrefix("OK")
	xoauth2.Close()
	expectAuthorityRequest(t, authority, e2eSieveProtocol, "xoauth2", e2eSieveShardBAccount)
	assertSieveObservation(t, fakeSieveB.ExpectObservation(t), "plain", false)

	oauthbearer := dialSieveTLS(t, address)
	defer oauthbearer.Close()
	oauthbearer.ReadResponse()
	oauthbearer.WriteLine(`AUTHENTICATE "OAUTHBEARER" "` + sieveOAuthBearerPayload(e2eSieveBearerAccount, e2eToken) + `"`)
	oauthbearer.ExpectStatusPrefix("OK")
	oauthbearer.Close()
	expectAuthorityRequest(t, authority, e2eSieveProtocol, "oauthbearer", e2eSieveBearerAccount)
	assertSieveObservation(t, fakeSieveB.ExpectObservation(t), "plain", false)
}

// exerciseIMAPAndLMTPAffinityInfluenceSieve proves existing state selects the Sieve backend node.
func exerciseIMAPAndLMTPAffinityInfluenceSieve(
	t *testing.T,
	sieveAddress string,
	imapAddress string,
	lmtpAddress string,
	controlURL string,
	fakeIMAPA *fakeIMAPBackend,
	fakeSieveA *managesievebackend.Server,
	fakeLMTPA *lmtpbackend.Server,
) {
	t.Helper()

	imapClient, imapReader := loginProcessIMAP(t, imapAddress, e2eSieveCrossAccount)
	defer func() { _ = imapClient.Close() }()
	expectBackendProxy(t, imapClient, imapReader, fakeIMAPA, "SIA002")

	routeOutput := runDirectorctl(t, buildDirectorctl(t), controlURL,
		"route", "lookup",
		"--protocol", e2eSieveProtocol,
		"--user", e2eSieveCrossAccount,
		"--listener", e2eSieveListener,
		"--include-affinity",
	)
	assertCLIOutputFields(t, routeOutput, "selected_backend="+e2eSieveBackendAID, "source=active_affinity")
	activeSieve := authenticatedSieveClient(t, sieveAddress, e2eSieveCrossAccount)
	activeSieve.Close()
	assertSieveObservation(t, fakeSieveA.ExpectObservation(t), "plain", false)
	_ = imapClient.Close()
	waitForRESTSessionCount(t, controlURL, 0)

	lmtpClient := dialLMTP(t, lmtpAddress)
	defer lmtpClient.Close()
	lmtpClient.ExpectLine("220 2.0.0 nauthilus-director LMTP ready\r\n")
	lmtpClient.WriteLine("LHLO sieve-affinity.example")
	lmtpClient.ReadResponse()
	lmtpClient.WriteLine("MAIL FROM:<sender@example.test>")
	lmtpClient.ExpectLine("250 2.0.0 Sender accepted\r\n")
	lmtpClient.WriteLine("RCPT TO:<" + e2eLMTPRecipientA + ">")
	lmtpClient.ExpectLine("250 2.0.0 Recipient accepted\r\n")

	duringDelivery := authenticatedSieveClient(t, sieveAddress, e2eLMTPRecipientA)
	duringDelivery.Close()
	assertSieveObservation(t, fakeSieveA.ExpectObservation(t), "plain", false)

	lmtpClient.WriteLine("DATA")
	lmtpClient.ExpectLine("354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	lmtpClient.WriteRaw("sieve-affinity-body\r\n.\r\n")
	lmtpClient.ExpectLine("250 2.1.5 Message accepted\r\n")
	assertLMTPBackendObservation(t, fakeLMTPA.ExpectObservation(t), []string{lmtpPath(e2eLMTPRecipientA)}, false)

	retainedSieve := authenticatedSieveClient(t, sieveAddress, e2eLMTPRecipientA)
	retainedSieve.Close()
	assertSieveObservation(t, fakeSieveA.ExpectObservation(t), "plain", false)
}

// exerciseSieveAffinityInfluencesIMAP proves active and retained Sieve placement feeds IMAP.
func exerciseSieveAffinityInfluencesIMAP(
	t *testing.T,
	sieveAddress string,
	imapAddress string,
	controlURL string,
	ctl string,
	fakeSieveA *managesievebackend.Server,
	fakeIMAPA *fakeIMAPBackend,
) {
	t.Helper()

	activeSieve := authenticatedSieveClient(t, sieveAddress, e2eSievePinnedAccount)
	imapClient, imapReader := loginProcessIMAP(t, imapAddress, e2eSievePinnedAccount)
	expectBackendProxy(t, imapClient, imapReader, fakeIMAPA, "SIP002")
	_ = imapClient.Close()
	activeSieve.Close()
	assertSieveObservation(t, fakeSieveA.ExpectObservation(t), "plain", false)
	waitForRESTSessionCount(t, controlURL, 0)

	retainedSieve := authenticatedSieveClient(t, sieveAddress, e2eSieveRuntimeAccount)
	retainedSieve.Close()
	assertSieveObservation(t, fakeSieveA.ExpectObservation(t), "plain", false)
	retainedRoute := runDirectorctl(t, ctl, controlURL,
		"route", "lookup",
		"--protocol", e2eProtocol,
		"--user", e2eSieveRuntimeAccount,
		"--listener", e2eListenerName,
		"--include-affinity",
	)
	assertCLIOutputFields(t, retainedRoute, "selected_backend="+e2eBackendAID, "source=retained_backend_binding")
	retainedIMAP, retainedReader := loginProcessIMAP(t, imapAddress, e2eSieveRuntimeAccount)
	expectBackendProxy(t, retainedIMAP, retainedReader, fakeIMAPA, "SIR002")
	_ = retainedIMAP.Close()
	waitForRESTSessionCount(t, controlURL, 0)
}

// exerciseSieveRuntimeControls proves hold, pin, runtime out and maintenance through public APIs.
func exerciseSieveRuntimeControls(
	t *testing.T,
	address string,
	controlURL string,
	ctl string,
	fakeSieveA *managesievebackend.Server,
	fakeSieveB *managesievebackend.Server,
	process *directorProcess,
) {
	t.Helper()

	runDirectorctl(t, ctl, controlURL, "users", "hold", "set", e2eSieveHoldAccount, "--duration", "5s", "--reason", "sieve hold timeout")
	beforeConnections := fakeSieveA.ConnectionCount() + fakeSieveB.ConnectionCount()
	held := dialSieveStartedTLS(t, address)
	held.WriteLine(`AUTHENTICATE "PLAIN" "` + sievePlainPayload(e2eSieveHoldAccount, e2ePassword) + `"`)
	held.ExpectStatusPrefix("NO (TRYLATER)")
	held.Close()
	afterConnections := fakeSieveA.ConnectionCount() + fakeSieveB.ConnectionCount()
	if beforeConnections != afterConnections {
		t.Fatalf("hold timeout opened backend connections before=%d after=%d", beforeConnections, afterConnections)
	}
	heldRoute := runDirectorctl(t, ctl, controlURL,
		"route", "lookup",
		"--protocol", e2eSieveProtocol,
		"--user", e2eSieveHoldAccount,
		"--listener", e2eSieveListener,
		"--include-affinity",
	)
	assertCLIOutputFields(t, heldRoute, "user_hold_present=true", "user_hold_reason=user_hold_active")
	assertOutputOmits(t, heldRoute, "sieve hold timeout")
	runDirectorctl(t, ctl, controlURL, "users", "hold", "clear", e2eSieveHoldAccount, "--reason", "sieve hold cleanup")

	runDirectorctl(t, ctl, controlURL, "users", "backend-pin", "set", e2eSievePinnedAccount,
		"--backend", e2eBackendAID,
		"--strategy", "kick_existing",
		"--reason", "imap pin mismatch")
	mismatched := runDirectorctl(t, ctl, controlURL,
		"route", "lookup",
		"--protocol", e2eSieveProtocol,
		"--user", e2eSievePinnedAccount,
		"--listener", e2eSieveListener,
		"--attribute", "mailShard="+e2eShardTag,
		"--include-affinity",
	)
	assertCLIOutputFields(t, mismatched, "backend_pin_present=true", "backend_pin_applied=false")
	runDirectorctl(t, ctl, controlURL, "users", "backend-pin", "clear", e2eSievePinnedAccount, "--reason", "clear imap mismatch")

	runDirectorctl(t, ctl, controlURL, "users", "backend-pin", "set", e2eSievePinnedAccount,
		"--backend", e2eSieveBackendAID,
		"--strategy", "kick_existing",
		"--reason", "sieve pin match")
	matched := runDirectorctl(t, ctl, controlURL,
		"route", "lookup",
		"--protocol", e2eSieveProtocol,
		"--user", e2eSievePinnedAccount,
		"--listener", e2eSieveListener,
		"--attribute", "mailShard="+e2eShardTag,
		"--include-affinity",
	)
	assertCLIOutputFields(t, matched, "selected_backend="+e2eSieveBackendAID, "backend_pin_applied=true")

	runDirectorctl(t, ctl, controlURL, "backends", "out", e2eSieveBackendAID, "--reason", "sieve out proof")
	outClient := dialSieveStartedTLS(t, address)
	outClient.WriteLine(`AUTHENTICATE "PLAIN" "` + sievePlainPayload(e2eSievePinnedAccount, e2ePassword) + `"`)
	outClient.ExpectStatusPrefix("NO (TRYLATER)")
	outClient.Close()
	runDirectorctl(t, ctl, controlURL, "backends", "in", e2eSieveBackendAID, "--reason", "sieve out cleanup")
	runDirectorctl(t, ctl, controlURL, "users", "backend-pin", "clear", e2eSievePinnedAccount, "--reason", "clear sieve pin")
	runDirectorctl(t, ctl, controlURL, "users", "affinity", "clear", e2eSievePinnedAccount, "--reason", "clear sieve affinity")

	active := authenticatedSieveClient(t, address, e2eSieveMaintenanceProof)
	runDirectorctl(t, ctl, controlURL, "backends", "maintenance", "enable", e2eSieveBackendAID, "--mode", "soft", "--reason", "sieve soft maintenance")
	active.WriteLine(sieveCommandNoop)
	active.ExpectStatusPrefix("OK")
	rejected := dialSieveStartedTLS(t, address)
	rejected.WriteLine(`AUTHENTICATE "PLAIN" "` + sievePlainPayload(e2eSieveHoldAccount, e2ePassword) + `"`)
	rejected.ExpectStatusPrefix("NO (TRYLATER)")
	rejected.Close()
	runDirectorctl(t, ctl, controlURL, "backends", "maintenance", "disable", e2eSieveBackendAID, "--reason", "sieve maintenance cleanup")
	active.Close()
	assertSieveObservation(t, fakeSieveA.ExpectObservation(t), "plain", false)
	assertOutputOmits(t, process.output.String(), "sieve hold timeout", "sieve pin match", "sieve soft maintenance")
}

type sieveProductionProcessConfigOptions struct {
	RedisAddress         string
	AuthorityURL         string
	SieveAddress         string
	SievesAddress        string
	IMAPAddress          string
	LMTPAddress          string
	ControlAddress       string
	SieveBackends        map[string]string
	IMAPBackends         map[string]string
	LMTPBackends         map[string]string
	UserHoldMaxWait      time.Duration
	UserHoldPollInterval time.Duration
}

// writeSieveProductionProcessConfig writes a production-style multiprotocol fixture.
func writeSieveProductionProcessConfig(t *testing.T, options sieveProductionProcessConfigOptions) string {
	t.Helper()

	certPath, keyPath, _ := writeTestCertificate(t)
	userHold := ""
	if options.UserHoldMaxWait > 0 {
		userHold = fmt.Sprintf(`  affinity:
    backend_retention:
      enabled: true
      default_ttl: 2s
      max_ttl: 24h
    user_holds:
      enabled: true
      max_duration: 30m
      max_wait: %q
      poll_interval: %q
      max_local_waiters: 1024
      max_local_waiters_per_user: 16
`, options.UserHoldMaxWait.String(), options.UserHoldPollInterval.String())
	} else {
		userHold = `  affinity:
    backend_retention:
      enabled: true
      default_ttl: 2s
      max_ttl: 24h
`
	}

	content := fmt.Sprintf(`patch:
  - op: remove
    path: director.listeners
    value: [imaps, lmtps]
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
%s
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
          required: false
          authority: default
          mechanisms: [plain]
          mtls:
            satisfies_required: false
            identity_source: subject_common_name
        capabilities: [SMTPUTF8, STARTTLS]
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
        auth_mechanisms: [plain, xoauth2, oauthbearer]
        capabilities:
          script_extensions: [fileinto, reject]
          language: en
    sieves:
      protocol: sieve
      service_name: sieves
      network: tcp
      address: %q
      authority: default
      backend_pool: sieve-default
      tls:
        mode: implicit
        cert: %q
        key: %q
        client_ca: ""
        require_client_cert: false
        min_tls_version: TLS1.2
      sieve:
        auth_mechanisms: [plain, xoauth2, oauthbearer]
        capabilities:
          script_extensions: [fileinto, reject]
          language: en
  backend_pools:
    imap-default:
      protocol: imap
      selector: rendezvous_hash
      backends: [mailstore-a-imap, mailstore-b-imap]
    lmtp-default:
      protocol: lmtp
      selector: recipient_hash
      backends: [mailstore-a-lmtp, mailstore-b-lmtp]
    sieve-default:
      protocol: sieve
      selector: rendezvous_hash
      backends: [mailstore-a-sieve, mailstore-b-sieve]
  backends:
%s`, options.ControlAddress,
		e2eProcessKeyPrefix,
		options.RedisAddress,
		options.AuthorityURL,
		userHold,
		e2eShardTag,
		options.IMAPAddress,
		certPath,
		keyPath,
		options.LMTPAddress,
		certPath,
		keyPath,
		options.SieveAddress,
		certPath,
		keyPath,
		options.SievesAddress,
		certPath,
		keyPath,
		sieveProductionBackendsYAML(options),
	)

	path := filepath.Join(t.TempDir(), "nauthilus-director-sieve-production.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write Sieve production process config: %v", err)
	}

	return path
}

// sieveProductionBackendsYAML renders matching backend-node entries across IMAP, LMTP and Sieve.
func sieveProductionBackendsYAML(options sieveProductionProcessConfigOptions) string {
	return fmt.Sprintf(`    mailstore-a-imap:
      protocol: imap
      shard_tag: %q
      backend_node: mailstore-a-node
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
    mailstore-b-imap:
      protocol: imap
      shard_tag: %q
      backend_node: mailstore-b-node
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
    mailstore-a-lmtp:
      protocol: lmtp
      shard_tag: %q
      backend_node: mailstore-a-node
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
    mailstore-b-lmtp:
      protocol: lmtp
      shard_tag: %q
      backend_node: mailstore-b-node
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
    mailstore-a-sieve:
      protocol: sieve
      shard_tag: %q
      backend_node: mailstore-a-node
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
    mailstore-b-sieve:
      protocol: sieve
      shard_tag: %q
      backend_node: mailstore-b-node
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
`, e2eShardTag,
		options.IMAPBackends[e2eBackendAID],
		e2eShardTagB,
		options.IMAPBackends[e2eBackendBID],
		e2eShardTag,
		options.LMTPBackends[e2eLMTPBackendAID],
		e2eShardTagB,
		options.LMTPBackends[e2eLMTPBackendBID],
		e2eShardTag,
		options.SieveBackends[e2eSieveBackendAID],
		e2eShardTagB,
		options.SieveBackends[e2eSieveBackendBID],
	)
}

type sieveClient struct {
	conn   net.Conn
	reader *bufio.Reader
}

// dialSieve connects to a public plaintext ManageSieve listener.
func dialSieve(t *testing.T, address string) *sieveClient {
	t.Helper()

	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatalf("dial Sieve %s: %v", address, err)
	}

	return &sieveClient{conn: conn, reader: bufio.NewReader(conn)}
}

// dialSieveTLS connects to a public implicit-TLS ManageSieve listener.
func dialSieveTLS(t *testing.T, address string) *sieveClient {
	t.Helper()

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: time.Second},
		"tcp",
		address,
		&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
	)
	if err != nil {
		t.Fatalf("dial Sieve TLS %s: %v", address, err)
	}

	return &sieveClient{conn: conn, reader: bufio.NewReader(conn)}
}

// dialSieveStartedTLS connects and negotiates STARTTLS.
func dialSieveStartedTLS(t *testing.T, address string) *sieveClient {
	t.Helper()

	client := dialSieve(t, address)
	client.ReadResponse()
	client.WriteLine(sieveCommandStartTLS)
	client.ExpectStatusPrefix("OK")
	client.UpgradeTLS(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})

	return client
}

// authenticatedSieveClient returns a STARTTLS-authenticated public Sieve client.
func authenticatedSieveClient(t *testing.T, address string, username string) *sieveClient {
	t.Helper()

	client := dialSieveStartedTLS(t, address)
	client.WriteLine(`AUTHENTICATE "PLAIN" "` + sievePlainPayload(username, e2ePassword) + `"`)
	client.ExpectStatusPrefix("OK")

	return client
}

// Close closes the public Sieve connection.
func (c *sieveClient) Close() {
	if c != nil && c.conn != nil {
		_ = c.conn.Close()
	}
}

// WriteLine writes one CRLF-terminated ManageSieve command.
func (c *sieveClient) WriteLine(line string) {
	_, _ = io.WriteString(c.conn, line+"\r\n")
}

// WriteRaw writes raw ManageSieve bytes.
func (c *sieveClient) WriteRaw(payload string) {
	_, _ = io.WriteString(c.conn, payload)
}

// UpgradeTLS performs a STARTTLS handshake on the existing connection.
func (c *sieveClient) UpgradeTLS(config *tls.Config) {
	tlsConn := tls.Client(c.conn, config.Clone())
	if err := tlsConn.Handshake(); err != nil {
		panic(fmt.Sprintf("Sieve STARTTLS handshake failed: %v", err))
	}
	c.conn = tlsConn
	c.reader = bufio.NewReader(tlsConn)
}

// ReadResponse reads a ManageSieve response block through the next status line.
func (c *sieveClient) ReadResponse() []string {
	var lines []string
	for {
		line := c.readLine()
		lines = append(lines, strings.TrimRight(line, "\r\n"))
		if sieveStatusLine(line) {
			return lines
		}
	}
}

// ExpectStatusPrefix verifies the next response status prefix.
func (c *sieveClient) ExpectStatusPrefix(want string) {
	response := c.ReadResponse()
	if len(response) == 0 || !strings.HasPrefix(response[len(response)-1], want) {
		panic(fmt.Sprintf("Sieve response = %v, want final status prefix %q", response, want))
	}
}

// readLine reads one ManageSieve line with a bounded deadline.
func (c *sieveClient) readLine() string {
	_ = c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := c.reader.ReadString('\n')
	if err != nil {
		panic(fmt.Sprintf("read Sieve line: %v", err))
	}

	return line
}

// waitForSieveGreeting waits until the process exposes its public Sieve socket.
func waitForSieveGreeting(t *testing.T, address string, process *directorProcess) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			line, readErr := bufio.NewReader(conn).ReadString('\n')
			_ = conn.Close()
			if readErr == nil && strings.HasPrefix(line, "\"IMPLEMENTATION\"") {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("director process did not expose Sieve at %s:\n%s", address, process.output.String())
}

// sieveStatusLine reports whether a line terminates one ManageSieve response.
func sieveStatusLine(line string) bool {
	line = strings.TrimSpace(line)

	return strings.HasPrefix(line, "OK") || strings.HasPrefix(line, "NO") || strings.HasPrefix(line, "BYE")
}

// assertSieveHasCapability verifies one capability token is present.
func assertSieveHasCapability(t *testing.T, lines []string, capability string) {
	t.Helper()

	if !sieveCapabilityPresent(lines, capability) {
		t.Fatalf("Sieve capabilities = %v, want %q", lines, capability)
	}
}

// assertSieveNoCapability verifies one capability token is absent.
func assertSieveNoCapability(t *testing.T, lines []string, capability string) {
	t.Helper()

	if sieveCapabilityPresent(lines, capability) {
		t.Fatalf("Sieve capabilities = %v, did not want %q", lines, capability)
	}
}

// assertSieveSASLValue verifies the effective SASL capability line.
func assertSieveSASLValue(t *testing.T, lines []string, want string) {
	t.Helper()

	for _, line := range lines {
		if strings.HasPrefix(line, "\"SASL\" ") {
			if !strings.Contains(line, "\""+want+"\"") {
				t.Fatalf("SASL capability line = %q, want value %q", line, want)
			}

			return
		}
	}

	t.Fatalf("Sieve capabilities = %v, missing SASL line", lines)
}

// sieveCapabilityPresent reports whether a quoted capability token is present.
func sieveCapabilityPresent(lines []string, capability string) bool {
	want := "\"" + strings.ToUpper(strings.TrimSpace(capability)) + "\""
	for _, line := range lines {
		if strings.HasPrefix(strings.ToUpper(line), want) {
			return true
		}
	}

	return false
}

// assertSieveResponseContains verifies a client-visible response contains expected backend bytes.
func assertSieveResponseContains(t *testing.T, lines []string, want string) {
	t.Helper()

	if !strings.Contains(strings.Join(lines, "\n"), want) {
		t.Fatalf("Sieve response = %v, want %q", lines, want)
	}
}

// assertSieveObservation verifies redacted fake backend observation facts.
func assertSieveObservation(t *testing.T, observation managesievebackend.Observation, mechanism string, wantScriptMatch bool) {
	t.Helper()

	if len(observation.AuthMechanisms) == 0 || observation.AuthMechanisms[0] != mechanism {
		t.Fatalf("Sieve auth mechanisms = %v, want first %q", observation.AuthMechanisms, mechanism)
	}
	if wantScriptMatch {
		for _, command := range observation.Commands {
			if command.Command == sieveCommandPutScript && command.ScriptNameMatched && command.ScriptContentMatched {
				return
			}
		}

		t.Fatalf("Sieve commands = %#v, missing redacted sentinel match", observation.Commands)
	}
}

// expectAuthorityRequest verifies one frontend auth method reached fake Nauthilus.
func expectAuthorityRequest(t *testing.T, authority *fakeHTTPAuthority, protocol string, method string, username string) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		authority.requestsLock.Lock()
		for _, request := range authority.requests {
			if request["protocol"] == protocol && request["method"] == method && request["username"] == username {
				authority.requestsLock.Unlock()

				return
			}
		}
		authority.requestsLock.Unlock()
		time.Sleep(10 * time.Millisecond)
	}

	authority.requestsLock.Lock()
	defer authority.requestsLock.Unlock()
	t.Fatalf("authority request protocol=%s method=%s username=%s not observed: %#v", protocol, method, username, authority.requests)
}

// sievePlainPayload renders a ManageSieve AUTHENTICATE PLAIN initial response.
func sievePlainPayload(username string, password string) string {
	return base64.StdEncoding.EncodeToString([]byte("\x00" + username + "\x00" + password))
}

// sieveXOAUTH2Payload renders a ManageSieve AUTHENTICATE XOAUTH2 initial response.
func sieveXOAUTH2Payload(username string, token string) string {
	payload := "user=" + username + "\x01auth=Bearer " + token + "\x01\x01"

	return base64.StdEncoding.EncodeToString([]byte(payload))
}

// sieveOAuthBearerPayload renders a ManageSieve AUTHENTICATE OAUTHBEARER initial response.
func sieveOAuthBearerPayload(username string, token string) string {
	payload := "n,a=" + username + ",\x01auth=Bearer " + token + "\x01\x01"

	return base64.StdEncoding.EncodeToString([]byte(payload))
}

// sieveAuthorityIdentities returns deterministic Nauthilus auth and lookup facts.
func sieveAuthorityIdentities() map[string]map[string][]string {
	shardA := func(account string) map[string][]string {
		return map[string][]string{"account": {account}, "tenant": {e2eTenant}, "mailShard": {e2eShardTag}}
	}
	shardB := func(account string) map[string][]string {
		return map[string][]string{"account": {account}, "tenant": {e2eTenant}, "mailShard": {e2eShardTagB}}
	}

	return map[string]map[string][]string{
		e2eSieveAccount:          shardA(e2eSieveAccount),
		e2eSieveBearerAccount:    shardB(e2eSieveBearerAccount),
		e2eSieveCrossAccount:     shardA(e2eSieveCrossAccount),
		e2eSieveHoldAccount:      shardA(e2eSieveHoldAccount),
		e2eSievePinnedAccount:    shardA(e2eSievePinnedAccount),
		e2eSieveRuntimeAccount:   shardA(e2eSieveRuntimeAccount),
		e2eSieveShardBAccount:    shardB(e2eSieveShardBAccount),
		e2eSieveMaintenanceProof: shardA(e2eSieveMaintenanceProof),
		e2eLMTPRecipientA:        shardA(e2eLMTPRecipientA),
		e2eLMTPRecipientB:        shardB(e2eLMTPRecipientB),
	}
}

// assertSieveProcessOutputSafe verifies process diagnostics did not leak Sieve payloads or identities.
func assertSieveProcessOutputSafe(t *testing.T, output string) {
	t.Helper()

	assertNoSecretText(t, output)
	for _, forbidden := range []string{
		e2eSieveSentinelName,
		e2eSieveSentinelContent,
		e2eSieveHoldAccount,
		e2eSievePinnedAccount,
		e2eSieveRuntimeAccount,
		e2eSieveBearerAccount,
		e2eSieveShardBAccount,
	} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("process output leaked Sieve value %q: %s", forbidden, output)
		}
	}
}
