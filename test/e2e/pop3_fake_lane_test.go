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

//nolint:dupl,funlen,goconst,gocyclo,wsl_v5 // E2E transcripts stay visible for POP3 review.
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
	"strings"
	"testing"
	"time"

	lmtpbackend "github.com/croessner/nauthilus-director/test/e2e/fakes/lmtp_backend"
	managesievebackend "github.com/croessner/nauthilus-director/test/e2e/fakes/managesieve_backend"
	pop3backend "github.com/croessner/nauthilus-director/test/e2e/fakes/pop3_backend"
)

const (
	e2ePOP3BackendAID       = "mailstore-a-pop3"
	e2ePOP3BackendBID       = "mailstore-b-pop3"
	e2ePOP3BackendPool      = "pop3-default"
	e2ePOP3Listener         = "pop3"
	e2ePOP3SListener        = "pop3s"
	e2ePOP3Protocol         = "pop3"
	e2ePOP3Service          = "pop3"
	e2ePOP3SService         = "pop3s"
	e2ePOP3Account          = "pop3-alice@example.test"
	e2ePOP3BearerAccount    = "pop3-bearer@example.test"
	e2ePOP3CrossAccount     = "pop3-cross@example.test"
	e2ePOP3HoldAccount      = "pop3-hold@example.test"
	e2ePOP3PinnedAccount    = "pop3-pinned@example.test"
	e2ePOP3RuntimeAccount   = "pop3-runtime@example.test"
	e2ePOP3RetainedAccount  = "pop3-retained@example.test"
	e2ePOP3ShardBAccount    = "pop3-b@example.test"
	e2ePOP3SieveAccount     = "pop3-sieve@example.test"
	e2ePOP3MaintenanceUser  = "pop3-maintenance@example.test"
	e2ePOP3UIDLSentinel     = "UIDL-POP3-OPAQUE-SENTINEL"
	e2ePOP3SubjectSentinel  = "Subject: POP3 opaque sentinel"
	e2ePOP3BodySentinel     = "opaque message body for POP3"
	e2ePOP3MessageSentinel  = e2ePOP3SubjectSentinel + "\r\n\r\n" + e2ePOP3BodySentinel
	e2ePOP3XOAuth2Token     = "e2e-pop3-xoauth2-token-sentinel"
	e2ePOP3OAuthBearerToken = "e2e-pop3-oauthbearer-token-sentinel"
	pop3CommandAuth         = "AUTH"
	pop3CommandCapa         = "CAPA"
	pop3CommandDele         = "DELE"
	pop3CommandList         = "LIST"
	pop3CommandPass         = "PASS"
	pop3CommandQuit         = "QUIT"
	pop3CommandRetr         = "RETR"
	pop3CommandRset         = "RSET"
	pop3CommandStat         = "STAT"
	pop3CommandSTLS         = "STLS"
	pop3CommandUIDL         = "UIDL"
	pop3CommandUser         = "USER"
)

// TestServerBinaryPublicPOP3ProductionFlow proves POP3 through public process boundaries.
func TestServerBinaryPublicPOP3ProductionFlow(t *testing.T) {
	binary := e2eServerBinary(t)
	ctl := buildDirectorctl(t)
	redisFixture := startValkeySessionStore(t)
	authority := startMappedFakeOIDCHTTPAuthority(t, pop3AuthorityIdentities(), nil, fakeOIDCAuthorityOptions{
		SASLBearerTokens: map[string]fakeSASLBearerToken{
			e2ePOP3XOAuth2Token:     activeFakeSASLBearerToken(e2ePOP3ShardBAccount, e2eShardTagB),
			e2ePOP3OAuthBearerToken: activeFakeSASLBearerToken(e2ePOP3BearerAccount, e2eShardTagB),
		},
		SkipBackchannelAuth: true,
	})
	backendCertPath, _, backendCertificate := writeTestCertificate(t)
	pop3BackendTLS := &tls.Config{Certificates: []tls.Certificate{backendCertificate}, MinVersion: tls.VersionTLS12}
	fakePOP3A := pop3backend.Start(t, pop3backend.Options{
		Messages:  pop3SentinelMessages(),
		TLSConfig: pop3BackendTLS,
		TLSMode:   "starttls",
	})
	fakePOP3B := pop3backend.Start(t, pop3backend.Options{
		Messages:  pop3SentinelMessages(),
		TLSConfig: pop3BackendTLS,
		TLSMode:   "starttls",
	})
	fakeIMAPA := startFakeIMAPBackend(t, fakeBackendOptions{})
	fakeIMAPB := startFakeIMAPBackend(t, fakeBackendOptions{})
	fakeLMTPA := lmtpbackend.Start(t, lmtpbackend.Options{})
	fakeLMTPB := lmtpbackend.Start(t, lmtpbackend.Options{})
	fakeSieveA := managesievebackend.Start(t, managesievebackend.Options{})
	fakeSieveB := managesievebackend.Start(t, managesievebackend.Options{})
	pop3Address := loopbackAddress(t)
	pop3sAddress := loopbackAddress(t)
	imapAddress := loopbackAddress(t)
	lmtpAddress := loopbackAddress(t)
	sieveAddress := loopbackAddress(t)
	controlAddress := loopbackAddress(t)
	configPath := writePOP3ProductionProcessConfig(t, pop3ProductionProcessConfigOptions{
		RedisAddress:         redisFixture.addr,
		AuthorityURL:         authority.URL(),
		AuthorityBearer:      processAuthorityBearerForFake(authority),
		POP3Address:          pop3Address,
		POP3SAddress:         pop3sAddress,
		IMAPAddress:          imapAddress,
		LMTPAddress:          lmtpAddress,
		SieveAddress:         sieveAddress,
		ControlAddress:       controlAddress,
		POP3BackendTLSMode:   "starttls",
		POP3BackendTLSCAFile: backendCertPath,
		POP3Backends: map[string]string{
			e2ePOP3BackendAID: fakePOP3A.Address(),
			e2ePOP3BackendBID: fakePOP3B.Address(),
		},
		IMAPBackends: map[string]string{
			e2eBackendAID: fakeIMAPA.Address(),
			e2eBackendBID: fakeIMAPB.Address(),
		},
		LMTPBackends: map[string]string{
			e2eLMTPBackendAID: fakeLMTPA.Address(),
			e2eLMTPBackendBID: fakeLMTPB.Address(),
		},
		SieveBackends: map[string]string{
			e2eSieveBackendAID: fakeSieveA.Address(),
			e2eSieveBackendBID: fakeSieveB.Address(),
		},
		UserHoldMaxWait:      175 * time.Millisecond,
		UserHoldPollInterval: 25 * time.Millisecond,
	})
	process := startDirectorProcess(t, binary, configPath)
	controlURL := "http://" + controlAddress

	waitForPOP3Greeting(t, pop3Address, process)
	waitForTCPListener(t, pop3sAddress, process)
	waitForDirectorGreeting(t, imapAddress, process)
	waitForLMTPGreeting(t, lmtpAddress, process)
	waitForSieveGreeting(t, sieveAddress, process)
	waitForControlReady(t, controlURL, process)

	exercisePOP3StartTLSAuthProxyAndRouteLookup(t, pop3Address, controlURL, ctl, authority, fakePOP3A, process)
	exercisePOP3ImplicitBearerAuth(t, pop3sAddress, authority, fakePOP3B)
	exerciseIMAPSieveAndLMTPAffinityInfluencePOP3(t, pop3Address, imapAddress, sieveAddress, lmtpAddress, controlURL, fakeIMAPA, fakeSieveA, fakeLMTPA, fakePOP3A)
	exercisePOP3AffinityInfluencesIMAPAndSieve(t, pop3Address, imapAddress, sieveAddress, controlURL, ctl, fakePOP3A, fakeIMAPA, fakeSieveA)
	exercisePOP3RuntimeControls(t, pop3Address, controlURL, ctl, fakePOP3A, fakePOP3B, process)

	assertPOP3ProcessOutputSafe(t, process.output.String())
}

// TestServerBinaryPublicPOP3GreetingDisclosurePolicy proves POP3 greeting policy through a public socket.
func TestServerBinaryPublicPOP3GreetingDisclosurePolicy(t *testing.T) {
	binary := e2eServerBinaryWithVersion(t, e2eGreetingProcessVersion)
	testCases := protocolGreetingLineFixtures(
		"+OK nauthilus-director POP3 ready\r\n",
		"+OK nauthilus-director "+e2eGreetingProcessVersion+" POP3 ready\r\n",
		"+OK nauthilus-director POP3 ready\r\n",
		"+OK Norbert POP3 ready\r\n",
	)

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			redisFixture := startValkeySessionStore(t)
			authority := startMappedFakeOIDCHTTPAuthority(t, pop3AuthorityIdentities(), nil, fakeOIDCAuthorityOptions{
				SkipBackchannelAuth: true,
			})
			backendCertPath, _, backendCertificate := writeTestCertificate(t)
			pop3BackendTLS := &tls.Config{Certificates: []tls.Certificate{backendCertificate}, MinVersion: tls.VersionTLS12}
			fakePOP3A := pop3backend.Start(t, pop3backend.Options{
				TLSConfig: pop3BackendTLS,
				TLSMode:   "starttls",
			})
			fakePOP3B := pop3backend.Start(t, pop3backend.Options{
				TLSConfig: pop3BackendTLS,
				TLSMode:   "starttls",
			})
			fakeIMAPA := startFakeIMAPBackend(t, fakeBackendOptions{})
			fakeIMAPB := startFakeIMAPBackend(t, fakeBackendOptions{})
			fakeLMTPA := lmtpbackend.Start(t, lmtpbackend.Options{})
			fakeLMTPB := lmtpbackend.Start(t, lmtpbackend.Options{})
			fakeSieveA := managesievebackend.Start(t, managesievebackend.Options{})
			fakeSieveB := managesievebackend.Start(t, managesievebackend.Options{})
			pop3Address := loopbackAddress(t)
			configPath := writePOP3ProductionProcessConfig(t, pop3ProductionProcessConfigOptions{
				RedisAddress:    redisFixture.addr,
				AuthorityURL:    authority.URL(),
				AuthorityBearer: processAuthorityBearerForFake(authority),
				POP3Address:     pop3Address,
				POP3SAddress:    loopbackAddress(t),
				IMAPAddress:     loopbackAddress(t),
				LMTPAddress:     loopbackAddress(t),
				SieveAddress:    loopbackAddress(t),
				ControlAddress:  loopbackAddress(t),
				POP3Backends: map[string]string{
					e2ePOP3BackendAID: fakePOP3A.Address(),
					e2ePOP3BackendBID: fakePOP3B.Address(),
				},
				IMAPBackends: map[string]string{
					e2eBackendAID: fakeIMAPA.Address(),
					e2eBackendBID: fakeIMAPB.Address(),
				},
				LMTPBackends: map[string]string{
					e2eLMTPBackendAID: fakeLMTPA.Address(),
					e2eLMTPBackendBID: fakeLMTPB.Address(),
				},
				SieveBackends: map[string]string{
					e2eSieveBackendAID: fakeSieveA.Address(),
					e2eSieveBackendBID: fakeSieveB.Address(),
				},
				POP3BackendTLSMode:   "starttls",
				POP3BackendTLSCAFile: backendCertPath,
				UserHoldMaxWait:      175 * time.Millisecond,
				UserHoldPollInterval: 25 * time.Millisecond,
				POP3Greeting:         testCase.policy,
			})
			process := startDirectorProcess(t, binary, configPath)

			got := readProcessGreetingLine(t, pop3Address, process, "+OK ")
			if got != testCase.want {
				t.Fatalf("POP3 greeting = %q, want %q", got, testCase.want)
			}
			stopDirectorProcess(t, process)
			assertPOP3ProcessOutputSafe(t, process.output.String())
			assertOutputOmits(t, process.output.String(), e2eGreetingUnsafeSentinel)
		})
	}
}

// TestServerBinaryRejectsInvalidGreetingDisplayNameBeforeListenersBind proves process-level fail-closed validation.
func TestServerBinaryRejectsInvalidGreetingDisplayNameBeforeListenersBind(t *testing.T) {
	binary := e2eServerBinaryWithVersion(t, e2eGreetingProcessVersion)
	imapAddress := loopbackAddress(t)
	lmtpAddress := loopbackAddress(t)
	sieveAddress := loopbackAddress(t)
	pop3Address := loopbackAddress(t)
	configPath := writePOP3ProductionProcessConfig(t, pop3ProductionProcessConfigOptions{
		RedisAddress:   "127.0.0.1:1",
		AuthorityURL:   "http://127.0.0.1:1/api/v1/auth/json",
		POP3Address:    pop3Address,
		POP3SAddress:   loopbackAddress(t),
		IMAPAddress:    imapAddress,
		LMTPAddress:    lmtpAddress,
		SieveAddress:   sieveAddress,
		ControlAddress: loopbackAddress(t),
		POP3Backends: map[string]string{
			e2ePOP3BackendAID: "127.0.0.1:1",
			e2ePOP3BackendBID: "127.0.0.1:1",
		},
		IMAPBackends: map[string]string{
			e2eBackendAID: "127.0.0.1:1",
			e2eBackendBID: "127.0.0.1:1",
		},
		LMTPBackends: map[string]string{
			e2eLMTPBackendAID: "127.0.0.1:1",
			e2eLMTPBackendBID: "127.0.0.1:1",
		},
		SieveBackends: map[string]string{
			e2eSieveBackendAID: "127.0.0.1:1",
			e2eSieveBackendBID: "127.0.0.1:1",
		},
		UserHoldMaxWait:      175 * time.Millisecond,
		UserHoldPollInterval: 25 * time.Millisecond,
		POP3Greeting: greetingPolicyFixture{
			DisplayName:     e2eGreetingUnsafeSentinel + "\nInjected",
			SoftwareVersion: "default",
		},
	})

	output := runDirectorProcessExpectFailure(t, binary, configPath)
	if !strings.Contains(output, "display_name contains unsupported characters or response-shaped text") {
		t.Fatalf("director output = %q, want display_name validation failure", output)
	}
	assertOutputOmits(t, output, e2eGreetingUnsafeSentinel)
	for _, address := range []string{imapAddress, lmtpAddress, sieveAddress, pop3Address} {
		assertTCPAddressClosed(t, address)
	}
}

// exercisePOP3StartTLSAuthProxyAndRouteLookup proves frontend TLS, auth, proxying and diagnostics.
func exercisePOP3StartTLSAuthProxyAndRouteLookup(
	t *testing.T,
	address string,
	controlURL string,
	ctl string,
	authority *fakeHTTPAuthority,
	fakePOP3A *pop3backend.Server,
	process *directorProcess,
) {
	t.Helper()

	beforeAuth := authority.RequestCount()
	client := dialPOP3(t, address)
	defer client.Close()
	client.ExpectStatusPrefix("+OK")
	client.WriteLine(pop3CommandCapa)
	capability := client.ReadMultiline()
	assertPOP3HasCapability(t, capability, "STLS")
	assertPOP3NoCapability(t, capability, "USER")
	assertPOP3NoCapability(t, capability, "SASL")
	client.WriteLine(pop3CommandUser + " " + e2ePOP3Account)
	client.ExpectStatusPrefix("-ERR")
	if authority.RequestCount() != beforeAuth {
		t.Fatal("plaintext POP3 USER reached Nauthilus before STLS")
	}

	client.WriteLine(pop3CommandSTLS)
	client.ExpectStatusPrefix("+OK")
	client.UpgradeTLS(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	client.WriteLine(pop3CommandCapa)
	capability = client.ReadMultiline()
	assertPOP3NoCapability(t, capability, "STLS")
	assertPOP3HasCapability(t, capability, "USER")
	assertPOP3SASLValue(t, capability, "XOAUTH2 OAUTHBEARER")

	routeOutput := runDirectorctl(t, ctl, controlURL,
		"route", "lookup",
		"--protocol", e2ePOP3Protocol,
		"--user", e2ePOP3Account,
		"--listener", e2ePOP3Listener,
		"--include-affinity",
	)
	assertCLIOutputFields(t, routeOutput, "selected_backend="+e2ePOP3BackendAID, "source=initial_placement")
	assertOutputOmits(
		t,
		routeOutput,
		e2ePOP3UIDLSentinel,
		e2ePOP3SubjectSentinel,
		e2ePOP3BodySentinel,
		e2ePassword,
		e2eToken,
		e2ePOP3XOAuth2Token,
		e2ePOP3OAuthBearerToken,
	)

	client.WriteLine(pop3CommandUser + " " + e2ePOP3Account)
	client.ExpectStatusPrefix("+OK")
	client.WriteLine(pop3CommandPass + " " + e2ePassword)
	client.ExpectStatusPrefix("+OK")
	provePOP3ProxyCommands(t, client)
	client.Close()

	observation := fakePOP3A.ExpectObservation(t)
	assertPOP3Observation(t, observation, "userpass", true)
	sessionsOutput := runDirectorctl(t, ctl, controlURL, "sessions", "list", "--protocol", e2ePOP3Protocol)
	assertOutputOmits(t, sessionsOutput, e2ePOP3UIDLSentinel, e2ePOP3SubjectSentinel, e2ePOP3BodySentinel)
	assertOutputOmits(t, process.output.String(), e2ePOP3UIDLSentinel, e2ePOP3SubjectSentinel, e2ePOP3BodySentinel)
	expectAuthorityRequest(t, authority, e2ePOP3Protocol, "userpass", e2ePOP3Account)
}

// exercisePOP3ImplicitBearerAuth proves POP3S and bearer SASL over public sockets.
func exercisePOP3ImplicitBearerAuth(t *testing.T, address string, authority *fakeHTTPAuthority, fakePOP3B *pop3backend.Server) {
	t.Helper()

	xoauth2 := dialPOP3TLS(t, address)
	defer xoauth2.Close()
	xoauth2.ExpectStatusPrefix("+OK")
	beforeAuth := authority.SASLBearerIntrospectionCount()
	xoauth2.WriteLine(pop3CommandAuth + " XOAUTH2 " + pop3XOAUTH2Payload(e2ePOP3ShardBAccount, e2ePOP3XOAuth2Token))
	xoauth2.ExpectStatusPrefix("+OK")
	xoauth2.WriteLine(pop3CommandQuit)
	xoauth2.ExpectStatusPrefix("+OK")
	xoauth2.Close()
	authority.ExpectSASLBearerIntrospection(t, beforeAuth, 1)
	assertPOP3Observation(t, fakePOP3B.ExpectObservation(t), "xoauth2", false)

	oauthbearer := dialPOP3TLS(t, address)
	defer oauthbearer.Close()
	oauthbearer.ExpectStatusPrefix("+OK")
	beforeAuth = authority.SASLBearerIntrospectionCount()
	oauthbearer.WriteLine(pop3CommandAuth + " OAUTHBEARER " + pop3OAuthBearerPayload(e2ePOP3BearerAccount, e2ePOP3OAuthBearerToken))
	oauthbearer.ExpectStatusPrefix("+OK")
	oauthbearer.WriteLine(pop3CommandQuit)
	oauthbearer.ExpectStatusPrefix("+OK")
	oauthbearer.Close()
	authority.ExpectSASLBearerIntrospection(t, beforeAuth, 1)
	assertPOP3Observation(t, fakePOP3B.ExpectObservation(t), "oauthbearer", false)
}

// exerciseIMAPSieveAndLMTPAffinityInfluencePOP3 proves existing state selects the POP3 backend node.
func exerciseIMAPSieveAndLMTPAffinityInfluencePOP3(
	t *testing.T,
	pop3Address string,
	imapAddress string,
	sieveAddress string,
	lmtpAddress string,
	controlURL string,
	fakeIMAPA *fakeIMAPBackend,
	fakeSieveA *managesievebackend.Server,
	fakeLMTPA *lmtpbackend.Server,
	fakePOP3A *pop3backend.Server,
) {
	t.Helper()

	imapClient, imapReader := loginProcessIMAP(t, imapAddress, e2ePOP3CrossAccount)
	expectBackendProxy(t, imapClient, imapReader, fakeIMAPA, "PIA002")
	activePOP3 := authenticatedPOP3Client(t, pop3Address, e2ePOP3CrossAccount)
	activePOP3.WriteLine(pop3CommandQuit)
	activePOP3.ExpectStatusPrefix("+OK")
	activePOP3.Close()
	assertPOP3Observation(t, fakePOP3A.ExpectObservation(t), "userpass", false)
	_ = imapClient.Close()
	waitForRESTSessionCount(t, controlURL, 0)

	sieveClient := authenticatedSieveClient(t, sieveAddress, e2ePOP3SieveAccount)
	retainedPOP3 := authenticatedPOP3Client(t, pop3Address, e2ePOP3SieveAccount)
	retainedPOP3.WriteLine(pop3CommandQuit)
	retainedPOP3.ExpectStatusPrefix("+OK")
	retainedPOP3.Close()
	assertPOP3Observation(t, fakePOP3A.ExpectObservation(t), "userpass", false)
	sieveClient.Close()
	assertSieveObservation(t, fakeSieveA.ExpectObservation(t), "plain", false)
	waitForRESTSessionCount(t, controlURL, 0)

	lmtpClient := dialLMTP(t, lmtpAddress)
	defer lmtpClient.Close()
	lmtpClient.ExpectLine("220 2.0.0 nauthilus-director LMTP ready\r\n")
	lmtpClient.WriteLine("LHLO pop3-affinity.example")
	lmtpClient.ReadResponse()
	lmtpClient.WriteLine("MAIL FROM:<sender@example.test>")
	lmtpClient.ExpectLine("250 2.0.0 Sender accepted\r\n")
	lmtpClient.WriteLine("RCPT TO:<" + e2eLMTPRecipientA + ">")
	lmtpClient.ExpectLine("250 2.0.0 Recipient accepted\r\n")

	duringDelivery := authenticatedPOP3Client(t, pop3Address, e2eLMTPRecipientA)
	duringDelivery.WriteLine(pop3CommandQuit)
	duringDelivery.ExpectStatusPrefix("+OK")
	duringDelivery.Close()
	assertPOP3Observation(t, fakePOP3A.ExpectObservation(t), "userpass", false)

	lmtpClient.WriteLine("DATA")
	lmtpClient.ExpectLine("354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	lmtpClient.WriteRaw("pop3-affinity-body\r\n.\r\n")
	lmtpClient.ExpectLine("250 2.1.5 Message accepted\r\n")
	assertLMTPBackendObservation(t, fakeLMTPA.ExpectObservation(t), []string{lmtpPath(e2eLMTPRecipientA)}, false)

	retainedDelivery := authenticatedPOP3Client(t, pop3Address, e2eLMTPRecipientA)
	retainedDelivery.WriteLine(pop3CommandQuit)
	retainedDelivery.ExpectStatusPrefix("+OK")
	retainedDelivery.Close()
	assertPOP3Observation(t, fakePOP3A.ExpectObservation(t), "userpass", false)
}

// exercisePOP3AffinityInfluencesIMAPAndSieve proves POP3 active and retained binding feeds later placement.
func exercisePOP3AffinityInfluencesIMAPAndSieve(
	t *testing.T,
	pop3Address string,
	imapAddress string,
	sieveAddress string,
	controlURL string,
	ctl string,
	fakePOP3A *pop3backend.Server,
	fakeIMAPA *fakeIMAPBackend,
	fakeSieveA *managesievebackend.Server,
) {
	t.Helper()

	activePOP3 := authenticatedPOP3Client(t, pop3Address, e2ePOP3RuntimeAccount)
	imapClient, imapReader := loginProcessIMAP(t, imapAddress, e2ePOP3RuntimeAccount)
	expectBackendProxy(t, imapClient, imapReader, fakeIMAPA, "PIP002")
	_ = imapClient.Close()
	activePOP3.WriteLine(pop3CommandQuit)
	activePOP3.ExpectStatusPrefix("+OK")
	activePOP3.Close()
	assertPOP3Observation(t, fakePOP3A.ExpectObservation(t), "userpass", false)
	waitForRESTSessionCount(t, controlURL, 0)

	retainedPOP3 := authenticatedPOP3Client(t, pop3Address, e2ePOP3RetainedAccount)
	retainedPOP3.WriteLine(pop3CommandQuit)
	retainedPOP3.ExpectStatusPrefix("+OK")
	retainedPOP3.Close()
	assertPOP3Observation(t, fakePOP3A.ExpectObservation(t), "userpass", false)
	waitForRESTSessionCount(t, controlURL, 0)

	retainedRoute := runDirectorctl(t, ctl, controlURL,
		"route", "lookup",
		"--protocol", e2eSieveProtocol,
		"--user", e2ePOP3RetainedAccount,
		"--listener", e2eSieveListener,
		"--include-affinity",
	)
	assertCLIOutputFields(t, retainedRoute, "selected_backend="+e2eSieveBackendAID, "source=retained_backend_binding")
	sieveClient := authenticatedSieveClient(t, sieveAddress, e2ePOP3RetainedAccount)
	sieveClient.Close()
	assertSieveObservation(t, fakeSieveA.ExpectObservation(t), "plain", false)
}

// exercisePOP3RuntimeControls proves hold, pin, runtime out and maintenance through public APIs.
func exercisePOP3RuntimeControls(
	t *testing.T,
	address string,
	controlURL string,
	ctl string,
	fakePOP3A *pop3backend.Server,
	fakePOP3B *pop3backend.Server,
	process *directorProcess,
) {
	t.Helper()

	runDirectorctl(t, ctl, controlURL, "users", "hold", "set", e2ePOP3HoldAccount, "--duration", "5s", "--reason", "pop3 hold timeout")
	beforeConnections := fakePOP3A.ConnectionCount() + fakePOP3B.ConnectionCount()
	held := authenticatedPOP3ClientExpectFailure(t, address, e2ePOP3HoldAccount)
	held.Close()
	afterConnections := fakePOP3A.ConnectionCount() + fakePOP3B.ConnectionCount()
	if beforeConnections != afterConnections {
		t.Fatalf("hold timeout opened POP3 backend connections before=%d after=%d", beforeConnections, afterConnections)
	}
	heldRoute := runDirectorctl(t, ctl, controlURL,
		"route", "lookup",
		"--protocol", e2ePOP3Protocol,
		"--user", e2ePOP3HoldAccount,
		"--listener", e2ePOP3Listener,
		"--include-affinity",
	)
	assertCLIOutputFields(t, heldRoute, "user_hold_present=true", "user_hold_reason=user_hold_active")
	assertOutputOmits(t, heldRoute, "pop3 hold timeout")
	runDirectorctl(t, ctl, controlURL, "users", "hold", "clear", e2ePOP3HoldAccount, "--reason", "pop3 hold cleanup")

	runDirectorctl(t, ctl, controlURL, "users", "backend-pin", "set", e2ePOP3PinnedAccount,
		"--backend", e2eBackendAID,
		"--strategy", "kick_existing",
		"--reason", "imap pin mismatch")
	mismatched := runDirectorctl(t, ctl, controlURL,
		"route", "lookup",
		"--protocol", e2ePOP3Protocol,
		"--user", e2ePOP3PinnedAccount,
		"--listener", e2ePOP3Listener,
		"--attribute", "mailShard="+e2eShardTag,
		"--include-affinity",
	)
	assertCLIOutputFields(t, mismatched,
		"backend_pin_present=false",
		"backend_pin_applied=false",
		"backend_pin_scope_count=1",
		"backend_pin_current_scope_unpinned=true",
		"backend_pin_other_scope_count=1",
		"backend_pin_other_scopes=imap/imap-default",
		"backend_pin_reason=backend_pin_other_scopes",
	)
	runDirectorctl(t, ctl, controlURL, "users", "backend-pin", "clear", e2ePOP3PinnedAccount, "--reason", "clear imap mismatch")

	runDirectorctl(t, ctl, controlURL, "users", "backend-pin", "set", e2ePOP3PinnedAccount,
		"--backend", e2ePOP3BackendAID,
		"--strategy", "kick_existing",
		"--reason", "pop3 pin match")
	matched := runDirectorctl(t, ctl, controlURL,
		"route", "lookup",
		"--protocol", e2ePOP3Protocol,
		"--user", e2ePOP3PinnedAccount,
		"--listener", e2ePOP3Listener,
		"--attribute", "mailShard="+e2eShardTag,
		"--include-affinity",
	)
	assertCLIOutputFields(t, matched, "selected_backend="+e2ePOP3BackendAID, "backend_pin_applied=true")

	runDirectorctl(t, ctl, controlURL, "backends", "out", e2ePOP3BackendAID, "--reason", "pop3 out proof")
	outClient := authenticatedPOP3ClientExpectFailure(t, address, e2ePOP3PinnedAccount)
	outClient.Close()
	runDirectorctl(t, ctl, controlURL, "backends", "in", e2ePOP3BackendAID, "--reason", "pop3 out cleanup")
	runDirectorctl(t, ctl, controlURL, "users", "backend-pin", "clear", e2ePOP3PinnedAccount, "--reason", "clear pop3 pin")
	runDirectorctl(t, ctl, controlURL, "users", "affinity", "clear", e2ePOP3PinnedAccount, "--reason", "clear pop3 affinity")

	active := authenticatedPOP3Client(t, address, e2ePOP3MaintenanceUser)
	runDirectorctl(t, ctl, controlURL, "backends", "maintenance", "enable", e2ePOP3BackendAID, "--mode", "soft", "--reason", "pop3 soft maintenance")
	active.WriteLine(pop3CommandStat)
	active.ExpectStatusPrefix("+OK")
	rejected := authenticatedPOP3ClientExpectFailure(t, address, e2ePOP3HoldAccount)
	rejected.Close()
	runDirectorctl(t, ctl, controlURL, "backends", "maintenance", "disable", e2ePOP3BackendAID, "--reason", "pop3 maintenance cleanup")
	active.WriteLine(pop3CommandQuit)
	active.ExpectStatusPrefix("+OK")
	active.Close()
	assertPOP3Observation(t, fakePOP3A.ExpectObservation(t), "userpass", false)
	assertOutputOmits(t, process.output.String(), "pop3 hold timeout", "pop3 pin match", "pop3 soft maintenance")
}

type pop3ProductionProcessConfigOptions struct {
	RedisAddress         string
	AuthorityURL         string
	AuthorityBearer      processAuthorityBearerOptions
	POP3Address          string
	POP3SAddress         string
	IMAPAddress          string
	LMTPAddress          string
	SieveAddress         string
	ControlAddress       string
	IMAPGreeting         greetingPolicyFixture
	LMTPGreeting         greetingPolicyFixture
	SieveGreeting        greetingPolicyFixture
	POP3Greeting         greetingPolicyFixture
	POP3SGreeting        greetingPolicyFixture
	POP3Backends         map[string]string
	POP3BackendTLSMode   string
	POP3BackendTLSCAFile string
	IMAPBackends         map[string]string
	LMTPBackends         map[string]string
	SieveBackends        map[string]string
	UserHoldMaxWait      time.Duration
	UserHoldPollInterval time.Duration
}

// writePOP3ProductionProcessConfig writes a production-style multiprotocol POP3 fixture.
func writePOP3ProductionProcessConfig(t *testing.T, options pop3ProductionProcessConfigOptions) string {
	t.Helper()

	certPath, keyPath, _ := writeTestCertificate(t)
	authorityPasswordPath := writeProcessSecretFile(t, "unused")
	backendPasswordPath := writeProcessSecretFile(t, e2ePassword)
	content := fmt.Sprintf(`patch:
  - op: remove
    path: director.listeners
    value: [imaps, lmtps, sieves]
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
          password_file: %q
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
    user_holds:
      enabled: true
      max_duration: 30m
      max_wait: %q
      poll_interval: %q
      max_local_waiters: 1024
      max_local_waiters_per_user: 16
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
%s
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
%s
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
        min_tls_version: TLS1.2
      sieve:
        auth_mechanisms: [plain]
        capabilities:
          script_extensions: [fileinto, reject]
          language: en
%s
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
        auth_mechanisms: [userpass, xoauth2, oauthbearer]
        capabilities: [STLS, USER, SASL, UIDL, TOP, RESP-CODES]
%s
    pop3s:
      protocol: pop3
      service_name: pop3s
      network: tcp
      address: %q
      authority: default
      backend_pool: pop3-default
      tls:
        mode: implicit
        cert: %q
        key: %q
        min_tls_version: TLS1.2
      pop3:
        auth_mechanisms: [userpass, xoauth2, oauthbearer]
        capabilities: [USER, SASL, UIDL, TOP, RESP-CODES]
%s
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
    pop3-default:
      protocol: pop3
      selector: rendezvous_hash
      backends: [mailstore-a-pop3, mailstore-b-pop3]
  backends:
%s`, options.ControlAddress,
		processControlAuthYAML(t),
		e2eProcessKeyPrefix,
		options.RedisAddress,
		processAuthorityYAML(t, processAuthorityOIDCOptions{}, options.AuthorityBearer),
		options.AuthorityURL,
		authorityPasswordPath,
		options.UserHoldMaxWait.String(),
		options.UserHoldPollInterval.String(),
		e2eShardTag,
		options.IMAPAddress,
		certPath,
		keyPath,
		greetingPolicyYAML("        ", options.IMAPGreeting),
		options.LMTPAddress,
		certPath,
		keyPath,
		greetingPolicyYAML("        ", options.LMTPGreeting),
		options.SieveAddress,
		certPath,
		keyPath,
		greetingPolicyYAML("        ", options.SieveGreeting),
		options.POP3Address,
		certPath,
		keyPath,
		greetingPolicyYAML("        ", options.POP3Greeting),
		options.POP3SAddress,
		certPath,
		keyPath,
		greetingPolicyYAML("        ", options.POP3SGreeting),
		pop3ProductionBackendsYAML(options, backendPasswordPath),
	)
	content = strings.ReplaceAll(content, "\t", "")

	path := filepath.Join(t.TempDir(), "nauthilus-director-pop3-production.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write POP3 production process config: %v", err)
	}

	return path
}

// pop3ProductionBackendsYAML renders matching backend-node entries across protocols.
func pop3ProductionBackendsYAML(options pop3ProductionProcessConfigOptions, backendPasswordPath string) string {
	pop3BackendTLSMode := strings.TrimSpace(options.POP3BackendTLSMode)
	if pop3BackendTLSMode == "" {
		pop3BackendTLSMode = "plaintext"
	}

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
          password_file: %q
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
          password_file: %q
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
        mode: plaintext
        min_tls_version: TLS1.2
      auth:
        mode: master_user
        master_user:
          username: director-master
          password_file: %q
          user_format: "{user}*{master_user}"
          mechanism: plain
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
        mode: %q
        ca_file: %q
        cert: ""
        key: ""
        server_name: "127.0.0.1"
        min_tls_version: TLS1.2
        insecure_skip_verify: false
      auth:
        mode: master_user
        master_user:
          username: director-master
          password_file: %q
          user_format: "{user}*{master_user}"
          mechanism: plain
        credential_replay:
          require_backend_tls: true
          preserve_mechanism: true
          allowed_mechanisms: [userpass, xoauth2, oauthbearer]
      health_check:
        enabled: false
    mailstore-b-pop3:
      protocol: pop3
      shard_tag: %q
      backend_node: mailstore-b-node
      address: %q
      weight: 100
      max_connections: 100
      maintenance: disabled
      tls:
        mode: %q
        ca_file: %q
        cert: ""
        key: ""
        server_name: "127.0.0.1"
        min_tls_version: TLS1.2
        insecure_skip_verify: false
      auth:
        mode: master_user
        master_user:
          username: director-master
          password_file: %q
          user_format: "{user}*{master_user}"
          mechanism: plain
        credential_replay:
          require_backend_tls: true
          preserve_mechanism: true
          allowed_mechanisms: [userpass, xoauth2, oauthbearer]
      health_check:
        enabled: false
`, e2eShardTag,
		options.IMAPBackends[e2eBackendAID],
		backendPasswordPath,
		e2eShardTagB,
		options.IMAPBackends[e2eBackendBID],
		backendPasswordPath,
		e2eShardTag,
		options.LMTPBackends[e2eLMTPBackendAID],
		e2eShardTagB,
		options.LMTPBackends[e2eLMTPBackendBID],
		e2eShardTag,
		options.SieveBackends[e2eSieveBackendAID],
		backendPasswordPath,
		e2eShardTagB,
		options.SieveBackends[e2eSieveBackendBID],
		backendPasswordPath,
		e2eShardTag,
		options.POP3Backends[e2ePOP3BackendAID],
		pop3BackendTLSMode,
		options.POP3BackendTLSCAFile,
		backendPasswordPath,
		e2eShardTagB,
		options.POP3Backends[e2ePOP3BackendBID],
		pop3BackendTLSMode,
		options.POP3BackendTLSCAFile,
		backendPasswordPath,
	)
}

type pop3Client struct {
	conn   net.Conn
	reader *bufio.Reader
}

// dialPOP3 connects to a public plaintext POP3 listener.
func dialPOP3(t *testing.T, address string) *pop3Client {
	t.Helper()

	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatalf("dial POP3 %s: %v", address, err)
	}

	return &pop3Client{conn: conn, reader: bufio.NewReader(conn)}
}

// dialPOP3TLS connects to a public implicit-TLS POP3 listener.
func dialPOP3TLS(t *testing.T, address string) *pop3Client {
	t.Helper()

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: time.Second},
		"tcp",
		address,
		&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
	)
	if err != nil {
		t.Fatalf("dial POP3 TLS %s: %v", address, err)
	}

	return &pop3Client{conn: conn, reader: bufio.NewReader(conn)}
}

// authenticatedPOP3Client returns a STARTTLS-authenticated public POP3 client.
func authenticatedPOP3Client(t *testing.T, address string, username string) *pop3Client {
	t.Helper()

	client := dialPOP3StartedTLS(t, address)
	client.WriteLine(pop3CommandUser + " " + username)
	client.ExpectStatusPrefix("+OK")
	client.WriteLine(pop3CommandPass + " " + e2ePassword)
	client.ExpectStatusPrefix("+OK")

	return client
}

// authenticatedPOP3ClientExpectFailure authenticates until backend readiness fails.
func authenticatedPOP3ClientExpectFailure(t *testing.T, address string, username string) *pop3Client {
	t.Helper()

	client := dialPOP3StartedTLS(t, address)
	client.WriteLine(pop3CommandUser + " " + username)
	client.ExpectStatusPrefix("+OK")
	client.WriteLine(pop3CommandPass + " " + e2ePassword)
	client.ExpectStatusPrefix("-ERR")

	return client
}

// dialPOP3StartedTLS connects and negotiates STLS.
func dialPOP3StartedTLS(t *testing.T, address string) *pop3Client {
	t.Helper()

	client := dialPOP3(t, address)
	client.ExpectStatusPrefix("+OK")
	client.WriteLine(pop3CommandSTLS)
	client.ExpectStatusPrefix("+OK")
	client.UpgradeTLS(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})

	return client
}

// Close closes the public POP3 connection.
func (c *pop3Client) Close() {
	if c != nil && c.conn != nil {
		_ = c.conn.Close()
	}
}

// WriteLine writes one CRLF-terminated POP3 command.
func (c *pop3Client) WriteLine(line string) {
	_, _ = io.WriteString(c.conn, line+"\r\n")
}

// UpgradeTLS performs an STLS handshake on the existing connection.
func (c *pop3Client) UpgradeTLS(config *tls.Config) {
	tlsConn := tls.Client(c.conn, config.Clone())
	if err := tlsConn.Handshake(); err != nil {
		panic(fmt.Sprintf("POP3 STLS handshake failed: %v", err))
	}
	c.conn = tlsConn
	c.reader = bufio.NewReader(tlsConn)
}

// ReadMultiline reads a POP3 multiline response through the terminator.
func (c *pop3Client) ReadMultiline() []string {
	var lines []string
	for {
		line := c.readLine()
		lines = append(lines, strings.TrimRight(line, "\r\n"))
		if strings.TrimSpace(line) == "." {
			return lines
		}
	}
}

// ExpectStatusPrefix verifies the next response status prefix.
func (c *pop3Client) ExpectStatusPrefix(want string) string {
	line := c.readLine()
	if !strings.HasPrefix(line, want) {
		panic(fmt.Sprintf("POP3 response = %q, want status prefix %q", line, want))
	}

	return line
}

// readLine reads one POP3 line with a bounded deadline.
func (c *pop3Client) readLine() string {
	_ = c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := c.reader.ReadString('\n')
	if err != nil {
		panic(fmt.Sprintf("read POP3 line: %v", err))
	}

	return line
}

// waitForPOP3Greeting waits until the process exposes its public POP3 socket.
func waitForPOP3Greeting(t *testing.T, address string, process *directorProcess) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			line, readErr := bufio.NewReader(conn).ReadString('\n')
			_ = conn.Close()
			if readErr == nil && strings.HasPrefix(line, "+OK") {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("director process did not expose POP3 at %s:\n%s", address, process.output.String())
}

// provePOP3ProxyCommands verifies opaque post-auth POP3 command proxying.
func provePOP3ProxyCommands(t *testing.T, client *pop3Client) {
	t.Helper()

	client.WriteLine(pop3CommandStat)
	client.ExpectStatusPrefix("+OK")
	client.WriteLine(pop3CommandList)
	listResponse := client.ReadMultiline()
	assertPOP3ResponseContains(t, listResponse, "1 ")
	client.WriteLine(pop3CommandUIDL)
	uidlResponse := client.ReadMultiline()
	assertPOP3ResponseContains(t, uidlResponse, e2ePOP3UIDLSentinel)
	client.WriteLine(pop3CommandRetr + " 1")
	retrResponse := client.ReadMultiline()
	assertPOP3ResponseContains(t, retrResponse, e2ePOP3SubjectSentinel)
	assertPOP3ResponseContains(t, retrResponse, e2ePOP3BodySentinel)
	client.WriteLine(pop3CommandDele + " 1")
	client.ExpectStatusPrefix("+OK")
	client.WriteLine(pop3CommandRset)
	client.ExpectStatusPrefix("+OK")
	client.WriteLine(pop3CommandQuit)
	client.ExpectStatusPrefix("+OK")
}

// assertPOP3HasCapability verifies one CAPA token is present.
func assertPOP3HasCapability(t *testing.T, lines []string, capability string) {
	t.Helper()

	if !pop3CapabilityPresent(lines, capability) {
		t.Fatalf("POP3 capabilities = %v, want %q", lines, capability)
	}
}

// assertPOP3NoCapability verifies one CAPA token is absent.
func assertPOP3NoCapability(t *testing.T, lines []string, capability string) {
	t.Helper()

	if pop3CapabilityPresent(lines, capability) {
		t.Fatalf("POP3 capabilities = %v, did not want %q", lines, capability)
	}
}

// assertPOP3SASLValue verifies the effective SASL CAPA value.
func assertPOP3SASLValue(t *testing.T, lines []string, want string) {
	t.Helper()

	for _, line := range lines {
		if strings.HasPrefix(strings.ToUpper(line), "SASL ") {
			if !strings.Contains(line, want) {
				t.Fatalf("SASL capability line = %q, want value %q", line, want)
			}

			return
		}
	}

	t.Fatalf("POP3 capabilities = %v, missing SASL line", lines)
}

// pop3CapabilityPresent reports whether a CAPA token is present.
func pop3CapabilityPresent(lines []string, capability string) bool {
	want := strings.ToUpper(strings.TrimSpace(capability))
	for _, line := range lines {
		fields := strings.Fields(strings.ToUpper(line))
		if len(fields) > 0 && fields[0] == want {
			return true
		}
	}

	return false
}

// assertPOP3ResponseContains verifies a client-visible response contains backend bytes.
func assertPOP3ResponseContains(t *testing.T, lines []string, want string) {
	t.Helper()

	if !strings.Contains(strings.Join(lines, "\n"), want) {
		t.Fatalf("POP3 response = %v, want %q", lines, want)
	}
}

// assertPOP3Observation verifies redacted fake backend observation facts.
func assertPOP3Observation(t *testing.T, observation pop3backend.Observation, mechanism string, wantMailboxMatch bool) {
	t.Helper()

	if len(observation.AuthMechanisms) == 0 || observation.AuthMechanisms[0] != mechanism {
		t.Fatalf("POP3 auth mechanisms = %v, want first %q", observation.AuthMechanisms, mechanism)
	}
	if wantMailboxMatch && (!observation.MessageNumberMatched || !observation.UIDLMatched || !observation.ContentMatched) {
		t.Fatalf("POP3 observation = %#v, missing redacted mailbox sentinel match", observation)
	}
	dump := fmt.Sprintf("%#v", observation)
	assertOutputOmits(
		t,
		dump,
		e2ePOP3UIDLSentinel,
		e2ePOP3SubjectSentinel,
		e2ePOP3BodySentinel,
		e2ePassword,
		e2eToken,
		e2ePOP3XOAuth2Token,
		e2ePOP3OAuthBearerToken,
	)
}

// expectAuthorityRequestAtLeast verifies one matching auth request exists among several.
func expectAuthorityRequestAtLeast(t *testing.T, authority *fakeHTTPAuthority, protocol string, method string, username string) {
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

// pop3XOAUTH2Payload renders a POP3 AUTH XOAUTH2 initial response.
func pop3XOAUTH2Payload(username string, token string) string {
	payload := "user=" + username + "\x01auth=Bearer " + token + "\x01\x01"

	return base64.StdEncoding.EncodeToString([]byte(payload))
}

// pop3OAuthBearerPayload renders a POP3 AUTH OAUTHBEARER initial response.
func pop3OAuthBearerPayload(username string, token string) string {
	payload := "n,a=" + username + ",\x01auth=Bearer " + token + "\x01\x01"

	return base64.StdEncoding.EncodeToString([]byte(payload))
}

// pop3SentinelMessages returns deterministic fake mailbox data.
func pop3SentinelMessages() []pop3backend.Message {
	return []pop3backend.Message{{Number: 1, UIDL: e2ePOP3UIDLSentinel, Content: e2ePOP3MessageSentinel}}
}

// pop3AuthorityIdentities returns deterministic Nauthilus auth and lookup facts.
func pop3AuthorityIdentities() map[string]map[string][]string {
	shardA := func(account string) map[string][]string {
		return map[string][]string{"account": {account}, "tenant": {e2eTenant}, "mailShard": {e2eShardTag}}
	}
	shardB := func(account string) map[string][]string {
		return map[string][]string{"account": {account}, "tenant": {e2eTenant}, "mailShard": {e2eShardTagB}}
	}

	return map[string]map[string][]string{
		e2ePOP3Account:         shardA(e2ePOP3Account),
		e2ePOP3BearerAccount:   shardB(e2ePOP3BearerAccount),
		e2ePOP3CrossAccount:    shardA(e2ePOP3CrossAccount),
		e2ePOP3HoldAccount:     shardA(e2ePOP3HoldAccount),
		e2ePOP3PinnedAccount:   shardA(e2ePOP3PinnedAccount),
		e2ePOP3RuntimeAccount:  shardA(e2ePOP3RuntimeAccount),
		e2ePOP3RetainedAccount: shardA(e2ePOP3RetainedAccount),
		e2ePOP3ShardBAccount:   shardB(e2ePOP3ShardBAccount),
		e2ePOP3SieveAccount:    shardA(e2ePOP3SieveAccount),
		e2ePOP3MaintenanceUser: shardA(e2ePOP3MaintenanceUser),
		e2eLMTPRecipientA:      shardA(e2eLMTPRecipientA),
		e2eLMTPRecipientB:      shardB(e2eLMTPRecipientB),
	}
}

// assertPOP3ProcessOutputSafe verifies process diagnostics did not leak mailbox or identity material.
func assertPOP3ProcessOutputSafe(t *testing.T, output string) {
	t.Helper()

	assertNoSecretText(t, output)
	for _, forbidden := range []string{
		e2ePOP3UIDLSentinel,
		e2ePOP3MessageSentinel,
		e2ePOP3HoldAccount,
		e2ePOP3PinnedAccount,
		e2ePOP3RuntimeAccount,
		e2ePOP3BearerAccount,
		e2ePOP3ShardBAccount,
		e2ePOP3XOAuth2Token,
		e2ePOP3OAuthBearerToken,
	} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("process output leaked POP3 value %q: %s", forbidden, output)
		}
	}
}
