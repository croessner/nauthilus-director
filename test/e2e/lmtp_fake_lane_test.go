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
	"slices"
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
	e2eLMTPRecipientMaint   = "maintenance-a@example.test"
	e2eLMTPRecipientMixed   = "temp-a@example.test"
	e2eLMTPMessageSecret    = "top-secret-message-body"
	e2eLMTPXOAuth2Token     = "e2e-lmtp-xoauth2-token-sentinel"
	e2eLMTPOAuthBearerToken = "e2e-lmtp-oauthbearer-token-sentinel"
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
		RedisAddress:        redisFixture.addr,
		AuthorityURL:        authority.URL(),
		LMTPAddress:         lmtpAddress,
		LMTPSAddress:        lmtpsAddress,
		IMAPAddress:         imapAddress,
		ControlAddress:      controlAddress,
		BackendRetentionTTL: "2s",
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

// TestServerBinaryPublicLMTPGreetingDisclosurePolicy proves LMTP greeting identity through public sockets.
func TestServerBinaryPublicLMTPGreetingDisclosurePolicy(t *testing.T) {
	binary := e2eServerBinaryWithVersion(t, e2eGreetingProcessVersion)
	testCases := []struct {
		name     string
		policy   greetingPolicyFixture
		greeting string
		lhlo     string
	}{
		{
			name:     "default",
			greeting: "220 2.0.0 nauthilus-director LMTP ready\r\n",
			lhlo:     "250-nauthilus-director",
		},
		{
			name: "include",
			policy: greetingPolicyFixture{
				DisplayName:     "nauthilus-director",
				SoftwareVersion: "include",
			},
			greeting: "220 2.0.0 nauthilus-director " + e2eGreetingProcessVersion + " LMTP ready\r\n",
			lhlo:     "250-nauthilus-director " + e2eGreetingProcessVersion,
		},
		{
			name: "suppress",
			policy: greetingPolicyFixture{
				DisplayName:     "nauthilus-director",
				SoftwareVersion: "suppress",
			},
			greeting: "220 2.0.0 nauthilus-director LMTP ready\r\n",
			lhlo:     "250-nauthilus-director",
		},
		{
			name: "display name",
			policy: greetingPolicyFixture{
				DisplayName:     "Norbert",
				SoftwareVersion: "default",
			},
			greeting: "220 2.0.0 Norbert LMTP ready\r\n",
			lhlo:     "250-Norbert",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			redisFixture := startValkeySessionStore(t)
			authority := startLMTPAuthority(t, lmtpAuthorityIdentities())
			tlsBundle := writeLMTPPeerTLSBundle(t)
			fakeLMTPA := lmtpbackend.Start(t, lmtpbackend.Options{})
			fakeLMTPB := lmtpbackend.Start(t, lmtpbackend.Options{})
			fakeIMAPA := startFakeIMAPBackend(t, fakeBackendOptions{})
			fakeIMAPB := startFakeIMAPBackend(t, fakeBackendOptions{})
			lmtpAddress := loopbackAddress(t)
			configPath := writeLMTPProcessConfig(t, lmtpProcessConfigOptions{
				RedisAddress:   redisFixture.addr,
				AuthorityURL:   authority.URL(),
				LMTPAddress:    lmtpAddress,
				LMTPSAddress:   loopbackAddress(t),
				IMAPAddress:    loopbackAddress(t),
				ControlAddress: loopbackAddress(t),
				LMTPBackends: map[string]string{
					e2eLMTPBackendAID: fakeLMTPA.Address(),
					e2eLMTPBackendBID: fakeLMTPB.Address(),
				},
				IMAPBackends: map[string]string{
					e2eBackendAID: fakeIMAPA.Address(),
					e2eBackendBID: fakeIMAPB.Address(),
				},
				TLS:          tlsBundle,
				LMTPGreeting: testCase.policy,
			})
			process := startDirectorProcess(t, binary, configPath)

			got := readProcessGreetingLine(t, lmtpAddress, process, "220 ")
			if got != testCase.greeting {
				t.Fatalf("LMTP greeting = %q, want %q", got, testCase.greeting)
			}
			client := dialLMTP(t, lmtpAddress)
			defer client.Close()
			client.ExpectLine(testCase.greeting)
			client.WriteLine("LHLO greeting-policy.example")
			lhlo := client.ReadResponse()
			if len(lhlo) == 0 || lhlo[0] != testCase.lhlo {
				t.Fatalf("LMTP LHLO = %v, want first line %q", lhlo, testCase.lhlo)
			}
			client.Close()
			stopDirectorProcess(t, process)
			assertLMTPProcessOutputSafe(t, process.output.String())
			assertOutputOmits(t, process.output.String(), e2eGreetingUnsafeSentinel)
		})
	}
}

// TestServerBinaryPublicLMTPBearerPeerIntrospectionFlow proves LMTP peer bearer auth uses OIDC introspection.
func TestServerBinaryPublicLMTPBearerPeerIntrospectionFlow(t *testing.T) {
	binary := e2eServerBinary(t)
	ctl := buildDirectorctl(t)
	redisFixture := startValkeySessionStore(t)
	authority := startMappedFakeOIDCHTTPAuthority(t, lmtpMappedAuthorityIdentities(), nil, fakeOIDCAuthorityOptions{
		SASLBearerTokens: map[string]fakeSASLBearerToken{
			e2eLMTPXOAuth2Token:     activeFakeSASLBearerToken(e2eLMTPSubmitter, e2eShardTag),
			e2eLMTPOAuthBearerToken: activeFakeSASLBearerToken(e2eLMTPSSubmitter, e2eShardTag),
		},
		SkipBackchannelAuth: true,
	})
	tlsBundle := writeLMTPPeerTLSBundle(t)
	fakeLMTPA := lmtpbackend.Start(t, lmtpbackend.Options{Capabilities: []string{"CHUNKING"}})
	fakeLMTPB := lmtpbackend.Start(t, lmtpbackend.Options{Capabilities: []string{"CHUNKING"}})
	fakeIMAPA := startFakeIMAPBackend(t, fakeBackendOptions{})
	fakeIMAPB := startFakeIMAPBackend(t, fakeBackendOptions{})
	lmtpAddress := loopbackAddress(t)
	lmtpsAddress := loopbackAddress(t)
	imapAddress := loopbackAddress(t)
	controlAddress := loopbackAddress(t)
	publishHealthyLMTPBackends(t, redisFixture, []string{e2eLMTPBackendAID, e2eLMTPBackendBID}, "CHUNKING")
	configPath := writeLMTPProcessConfig(t, lmtpProcessConfigOptions{
		RedisAddress:           redisFixture.addr,
		AuthorityURL:           authority.URL(),
		AuthorityBearer:        processAuthorityBearerForFake(authority),
		LMTPAddress:            lmtpAddress,
		LMTPSAddress:           lmtpsAddress,
		IMAPAddress:            imapAddress,
		ControlAddress:         controlAddress,
		LMTPPeerAuthMechanisms: []string{"xoauth2", "oauthbearer"},
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

	beforeRouteLookup := authority.SASLBearerIntrospectionCount()
	beforeRouteLookupRequests := authority.RequestCount()
	routeOutput := runDirectorctl(t, ctl, controlURL, "route", "lookup", "--protocol", e2eLMTPProtocol, "--recipient", e2eLMTPRecipientA, "--listener", e2eLMTPListenerName, "--include-affinity")
	assertCLIOutputFields(t, routeOutput, "source=fail_closed", "reason=account_unresolved", "identity_source=director_state_unresolved", "identity_nauthilus=false")
	assertOutputOmits(t, routeOutput, e2eLMTPXOAuth2Token, e2eLMTPOAuthBearerToken)
	if authority.SASLBearerIntrospectionCount() != beforeRouteLookup {
		t.Fatal("LMTP route lookup called bearer introspection")
	}
	if authority.RequestCount() != beforeRouteLookupRequests {
		t.Fatal("LMTP route lookup called Nauthilus identity lookup")
	}

	backchannelBeforeAuth := authority.RequestCount()
	beforeAuth := authority.SASLBearerIntrospectionCount()
	xoauth2 := authenticatedLMTPBearerClient(t, lmtpAddress, "XOAUTH2", e2eLMTPSubmitter, e2eLMTPXOAuth2Token)
	authority.ExpectSASLBearerIntrospection(t, beforeAuth, 1)
	if authority.RequestCount() != backchannelBeforeAuth {
		t.Fatal("LMTP XOAUTH2 peer auth used the password backchannel")
	}
	deliverLMTPMessage(t, xoauth2, e2eLMTPRecipientA, "lmtp-xoauth2-delivery-body")
	xoauth2.Close()
	assertLMTPBackendObservation(t, fakeLMTPA.ExpectObservation(t), []string{lmtpPath(e2eLMTPRecipientA)}, true)

	backchannelBeforeAuth = authority.RequestCount()
	beforeAuth = authority.SASLBearerIntrospectionCount()
	oauthbearer := authenticatedLMTPBearerClient(t, lmtpAddress, "OAUTHBEARER", e2eLMTPSSubmitter, e2eLMTPOAuthBearerToken)
	authority.ExpectSASLBearerIntrospection(t, beforeAuth, 1)
	if authority.RequestCount() != backchannelBeforeAuth {
		t.Fatal("LMTP OAUTHBEARER peer auth used the password backchannel")
	}
	deliverLMTPMessage(t, oauthbearer, e2eLMTPRecipientASecond, "lmtp-oauthbearer-delivery-body")
	oauthbearer.Close()
	assertLMTPBackendObservation(t, fakeLMTPA.ExpectObservation(t), []string{lmtpPath(e2eLMTPRecipientASecond)}, true)
	expectNoAuthorityRequestMethod(t, authority, e2eLMTPProtocol, "xoauth2")
	expectNoAuthorityRequestMethod(t, authority, e2eLMTPProtocol, "oauthbearer")
	assertLMTPProcessOutputSafe(t, process.output.String())
}

// TestServerBinaryPublicLMTPChunkingSuppression proves configured CHUNKING is hidden without backend proof.
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

// TestServerBinaryPublicLMTPBackendDATAFallbackTranscript proves non-CHUNKING backends receive DATA.
func TestServerBinaryPublicLMTPBackendDATAFallbackTranscript(t *testing.T) {
	fixture := startLMTPBackendChunkingFixture(t, lmtpBackendChunkingFixtureOptions{})
	client := authenticatedLMTPClient(t, fixture.address)
	defer client.Close()

	body := "fallback-one\r\n..fallback-dot\r\n..\r\n"
	deliverLMTPDATA(t, client, []string{e2eLMTPRecipientA}, body)

	observation := fixture.fakeLMTPA.ExpectObservation(t)
	assertLMTPBackendObservation(t, observation, []string{lmtpPath(e2eLMTPRecipientA)}, false)
	assertBackendDATAWire(t, observation, body)
	assertNoBackendBDATWire(t, observation)
	assertLMTPProcessOutputSafe(t, fixture.process.output.String())
}

// TestServerBinaryPublicLMTPBackendBDATWithoutFrontendChunking proves backend transport independence.
func TestServerBinaryPublicLMTPBackendBDATWithoutFrontendChunking(t *testing.T) {
	fixture := startLMTPBackendChunkingFixture(t, lmtpBackendChunkingFixtureOptions{
		BackendCapabilities:     []string{"CHUNKING"},
		HealthCapabilities:      []string{"CHUNKING"},
		DisableFrontendChunking: true,
	})
	client := authenticatedLMTPClientWithoutFrontendChunking(t, fixture.address)
	defer client.Close()

	body := "chunk-proof-one\r\n..chunk-proof-dot\r\n..\r\n"
	deliverLMTPDATA(t, client, []string{e2eLMTPRecipientA}, body)

	observation := fixture.fakeLMTPA.ExpectObservation(t)
	assertLMTPBackendObservation(t, observation, []string{lmtpPath(e2eLMTPRecipientA)}, true)
	assertBackendBDATWire(t, observation, "chunk-proof-one\r\n.chunk-proof-dot\r\n.\r\n")
	assertLMTPProcessOutputSafe(t, fixture.process.output.String())
}

// TestServerBinaryPublicLMTPBackendBDATConversionEdges proves empty and multi-chunk DATA conversion.
func TestServerBinaryPublicLMTPBackendBDATConversionEdges(t *testing.T) {
	fixture := startLMTPBackendChunkingFixture(t, lmtpBackendChunkingFixtureOptions{
		BackendCapabilities: []string{"CHUNKING"},
		HealthCapabilities:  []string{"CHUNKING"},
	})

	emptyClient := authenticatedLMTPClient(t, fixture.address)
	deliverLMTPDATA(t, emptyClient, []string{e2eLMTPRecipientA}, "")
	emptyClient.Close()

	emptyObservation := fixture.fakeLMTPA.ExpectObservation(t)
	assertLMTPBackendObservation(t, emptyObservation, []string{lmtpPath(e2eLMTPRecipientA)}, true)
	assertBackendBDATChunks(t, emptyObservation, []lmtpbackend.BDATChunk{
		{Command: "BDAT 0 LAST", Last: true},
	})

	largeBody := largeLMTPBody()
	largeClient := authenticatedLMTPClient(t, fixture.address)
	deliverLMTPDATA(t, largeClient, []string{e2eLMTPRecipientA}, largeBody)
	largeClient.Close()

	largeObservation := fixture.fakeLMTPA.ExpectObservation(t)
	assertLMTPBackendObservation(t, largeObservation, []string{lmtpPath(e2eLMTPRecipientA)}, true)
	assertBackendBDATBody(t, largeObservation, largeBody)
	if len(largeObservation.BDATChunks) < 2 {
		t.Fatalf("large DATA backend chunks = %d, want multiple BDAT chunks", len(largeObservation.BDATChunks))
	}
	if largeObservation.BDATChunks[0].Size != 65536 || largeObservation.BDATChunks[0].Last {
		t.Fatalf("first large BDAT chunk = %#v, want non-final 64 KiB chunk", largeObservation.BDATChunks[0])
	}
	if !largeObservation.BDATChunks[len(largeObservation.BDATChunks)-1].Last {
		t.Fatalf("last large BDAT chunk = %#v, want LAST", largeObservation.BDATChunks[len(largeObservation.BDATChunks)-1])
	}
	assertLMTPProcessOutputSafe(t, fixture.process.output.String())
}

// TestServerBinaryPublicLMTPBackendBDATNonFinalRejectionFailsClosed proves rejected chunks stop delivery.
func TestServerBinaryPublicLMTPBackendBDATNonFinalRejectionFailsClosed(t *testing.T) {
	fixture := startLMTPBackendChunkingFixture(t, lmtpBackendChunkingFixtureOptions{
		BackendCapabilities:  []string{"CHUNKING"},
		HealthCapabilities:   []string{"CHUNKING"},
		NonFinalBDATStatuses: []lmtpbackend.Status{{Code: "451", Enhanced: "4.3.0", Text: "chunk rejected"}},
	})
	client := authenticatedLMTPClient(t, fixture.address)
	defer client.Close()

	client.WriteLine("MAIL FROM:<sender@example.test>")
	client.ExpectLine("250 2.0.0 Sender accepted\r\n")
	client.WriteLine("RCPT TO:<" + e2eLMTPRecipientA + ">")
	client.ExpectLine("250 2.0.0 Recipient accepted\r\n")
	client.WriteLine("DATA")
	client.ExpectLine("354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	client.WriteRaw(largeLMTPBody() + ".\r\n")
	client.ExpectLine("451 4.3.0 Message delivery temporarily failed\r\n")

	observation := fixture.fakeLMTPA.ExpectObservation(t)
	assertLMTPBackendObservation(t, observation, []string{lmtpPath(e2eLMTPRecipientA)}, true)
	if observation.FinalComplete {
		t.Fatal("backend observation completed after rejected non-final BDAT")
	}
	if len(observation.BDATChunks) != 1 || observation.BDATChunks[0].Last {
		t.Fatalf("BDAT chunks after rejection = %#v, want one non-final chunk", observation.BDATChunks)
	}
	assertLMTPProcessOutputSafe(t, fixture.process.output.String())
}

// TestServerBinaryPublicLMTPBackendBDATFinalStatusOrdering proves recipient outcomes stay ordered.
func TestServerBinaryPublicLMTPBackendBDATFinalStatusOrdering(t *testing.T) {
	fixture := startLMTPBackendChunkingFixture(t, lmtpBackendChunkingFixtureOptions{
		BackendCapabilities: []string{"CHUNKING"},
		HealthCapabilities:  []string{"CHUNKING"},
		FinalStatus: map[string]lmtpbackend.Status{
			lmtpPath(e2eLMTPRecipientASecond): {Code: "451", Enhanced: "4.2.0", Text: "temporary policy"},
		},
	})
	client := authenticatedLMTPClient(t, fixture.address)
	defer client.Close()

	body := "status-order-proof\r\n"
	client.WriteLine("MAIL FROM:<sender@example.test>")
	client.ExpectLine("250 2.0.0 Sender accepted\r\n")
	client.WriteLine("RCPT TO:<" + e2eLMTPRecipientA + ">")
	client.ExpectLine("250 2.0.0 Recipient accepted\r\n")
	client.WriteLine("RCPT TO:<" + e2eLMTPRecipientASecond + ">")
	client.ExpectLine("250 2.0.0 Recipient accepted\r\n")
	client.WriteLine("DATA")
	client.ExpectLine("354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	client.WriteRaw(body + ".\r\n")
	client.ExpectLine("250 2.1.5 Message accepted\r\n")
	client.ExpectLine("451 4.2.0 Message delivery temporarily failed\r\n")

	observation := fixture.fakeLMTPA.ExpectObservation(t)
	assertLMTPBackendObservation(t, observation, []string{lmtpPath(e2eLMTPRecipientA), lmtpPath(e2eLMTPRecipientASecond)}, true)
	assertBackendBDATWire(t, observation, body)
	if !observation.FinalComplete {
		t.Fatal("backend observation did not complete final status ordering proof")
	}
	assertLMTPProcessOutputSafe(t, fixture.process.output.String())
}

// TestServerBinaryPublicLMTPBackendBDATIncompleteStatusesFailClosed proves missing outcomes become temporary.
func TestServerBinaryPublicLMTPBackendBDATIncompleteStatusesFailClosed(t *testing.T) {
	fixture := startLMTPBackendChunkingFixture(t, lmtpBackendChunkingFixtureOptions{
		BackendCapabilities: []string{"CHUNKING"},
		HealthCapabilities:  []string{"CHUNKING"},
		FinalStatusLimit:    1,
	})
	client := authenticatedLMTPClient(t, fixture.address)
	defer client.Close()

	body := "incomplete-status-proof\r\n"
	client.WriteLine("MAIL FROM:<sender@example.test>")
	client.ExpectLine("250 2.0.0 Sender accepted\r\n")
	client.WriteLine("RCPT TO:<" + e2eLMTPRecipientA + ">")
	client.ExpectLine("250 2.0.0 Recipient accepted\r\n")
	client.WriteLine("RCPT TO:<" + e2eLMTPRecipientASecond + ">")
	client.ExpectLine("250 2.0.0 Recipient accepted\r\n")
	client.WriteLine("DATA")
	client.ExpectLine("354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	client.WriteRaw(body + ".\r\n")
	client.ExpectLine("250 2.1.5 Message accepted\r\n")
	client.ExpectLine("451 4.3.0 Message delivery temporarily failed\r\n")

	observation := fixture.fakeLMTPA.ExpectObservation(t)
	assertLMTPBackendObservation(t, observation, []string{lmtpPath(e2eLMTPRecipientA), lmtpPath(e2eLMTPRecipientASecond)}, true)
	if observation.FinalComplete {
		t.Fatal("backend observation completed despite intentionally missing final statuses")
	}
	assertLMTPProcessOutputSafe(t, fixture.process.output.String())
}

// TestServerBinaryPublicLMTPBackendBDATGateForFrontendBDAT proves unsupported backend CHUNKING blocks BDAT writes.
func TestServerBinaryPublicLMTPBackendBDATGateForFrontendBDAT(t *testing.T) {
	fixture := startLMTPBackendChunkingFixture(t, lmtpBackendChunkingFixtureOptions{
		HealthCapabilities: []string{"CHUNKING"},
	})
	client := authenticatedLMTPClient(t, fixture.address)
	defer client.Close()

	client.WriteLine("MAIL FROM:<sender@example.test>")
	client.ExpectLine("250 2.0.0 Sender accepted\r\n")
	client.WriteLine("RCPT TO:<" + e2eLMTPRecipientA + ">")
	client.ExpectLine("250 2.0.0 Recipient accepted\r\n")
	client.WriteRaw("BDAT 5 LAST\r\nhello")
	client.ExpectLine("451 4.3.0 Message delivery temporarily failed\r\n")
	client.WriteLine("NOOP")
	client.ExpectLine("250 2.0.0 OK\r\n")

	observation := fixture.fakeLMTPA.ExpectObservation(t)
	assertLMTPBackendObservation(t, observation, []string{lmtpPath(e2eLMTPRecipientA)}, false)
	assertNoBackendBDATWire(t, observation)
	assertLMTPProcessOutputSafe(t, fixture.process.output.String())
}

// TestServerBinaryPublicPlaintextLMTPNoAuthFlow proves auth-free plaintext LMTP through public sockets.
func TestServerBinaryPublicPlaintextLMTPNoAuthFlow(t *testing.T) {
	binary := e2eServerBinary(t)
	redisFixture := startValkeySessionStore(t)
	authority := startLMTPAuthority(t, lmtpAuthorityIdentities())
	tlsBundle := writeLMTPPeerTLSBundle(t)
	fakeLMTPA := lmtpbackend.Start(t, lmtpbackend.Options{Capabilities: []string{"CHUNKING"}})
	fakeLMTPB := lmtpbackend.Start(t, lmtpbackend.Options{Capabilities: []string{"CHUNKING"}})
	fakeIMAPA := startFakeIMAPBackend(t, fakeBackendOptions{})
	fakeIMAPB := startFakeIMAPBackend(t, fakeBackendOptions{})
	lmtpAddress := loopbackAddress(t)
	lmtpsAddress := loopbackAddress(t)
	imapAddress := loopbackAddress(t)
	controlAddress := loopbackAddress(t)
	publishHealthyLMTPBackends(t, redisFixture, []string{e2eLMTPBackendAID, e2eLMTPBackendBID}, "CHUNKING")
	configPath := writeLMTPProcessConfig(t, lmtpProcessConfigOptions{
		RedisAddress:           redisFixture.addr,
		AuthorityURL:           authority.URL(),
		LMTPAddress:            lmtpAddress,
		LMTPSAddress:           lmtpsAddress,
		IMAPAddress:            imapAddress,
		ControlAddress:         controlAddress,
		LMTPListenerTLSMode:    "plaintext",
		DisableLMTPPeerAuth:    true,
		LMTPPeerAuthMechanisms: nil,
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
	client := dialLMTP(t, lmtpAddress)
	defer client.Close()
	client.ExpectLine("220 2.0.0 nauthilus-director LMTP ready\r\n")
	client.WriteLine("LHLO plaintext.example")
	capabilities := client.ReadResponse()
	assertLMTPHasCapability(t, capabilities, "ENHANCEDSTATUSCODES")
	assertLMTPHasCapability(t, capabilities, "CHUNKING")
	assertLMTPNoCapability(t, capabilities, "STARTTLS")
	assertLMTPNoCapability(t, capabilities, "AUTH")
	client.WriteLine("STARTTLS")
	client.ExpectLine("503 5.5.1 STARTTLS is not available\r\n")
	beforeAuth := authority.RequestCount()
	client.WriteLine("AUTH PLAIN " + plainLMTPPayload(e2eLMTPSubmitter, e2ePassword))
	client.ExpectLine("530 5.7.0 Must issue STARTTLS first\r\n")
	if authority.RequestCount() != beforeAuth {
		t.Fatal("plaintext LMTP AUTH reached Nauthilus")
	}
	client.WriteLine("MAIL FROM:<sender@example.test>")
	client.ExpectLine("250 2.0.0 Sender accepted\r\n")
	client.WriteLine("RCPT TO:<" + e2eLMTPRecipientA + ">")
	client.ExpectLine("250 2.0.0 Recipient accepted\r\n")
	authority.ExpectLookupMode(t, e2eLMTPRecipientA, "no-auth")
	client.WriteLine("DATA")
	client.ExpectLine("354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	client.WriteRaw("plaintext-body\r\n.\r\n")
	client.ExpectLine("250 2.1.5 Message accepted\r\n")
	assertLMTPBackendObservation(t, fakeLMTPA.ExpectObservation(t), []string{lmtpPath(e2eLMTPRecipientA)}, true)
	assertLMTPProcessOutputSafe(t, process.output.String())
}

// TestServerBinaryPublicLMTP8BITMIMEFlow proves BODY=8BITMIME through public and backend sockets.
func TestServerBinaryPublicLMTP8BITMIMEFlow(t *testing.T) {
	binary := e2eServerBinary(t)
	redisFixture := startValkeySessionStore(t)
	authority := startLMTPAuthority(t, lmtpAuthorityIdentities())
	tlsBundle := writeLMTPPeerTLSBundle(t)
	fakeLMTPA := lmtpbackend.Start(t, lmtpbackend.Options{Capabilities: []string{"8BITMIME"}})
	fakeLMTPB := lmtpbackend.Start(t, lmtpbackend.Options{Capabilities: []string{"8BITMIME"}})
	fakeIMAPA := startFakeIMAPBackend(t, fakeBackendOptions{})
	fakeIMAPB := startFakeIMAPBackend(t, fakeBackendOptions{})
	lmtpAddress := loopbackAddress(t)
	lmtpsAddress := loopbackAddress(t)
	imapAddress := loopbackAddress(t)
	controlAddress := loopbackAddress(t)
	publishHealthyLMTPBackends(t, redisFixture, []string{e2eLMTPBackendAID, e2eLMTPBackendBID}, "8BITMIME")
	configPath := writeLMTPProcessConfig(t, lmtpProcessConfigOptions{
		RedisAddress:          redisFixture.addr,
		AuthorityURL:          authority.URL(),
		LMTPAddress:           lmtpAddress,
		LMTPSAddress:          lmtpsAddress,
		IMAPAddress:           imapAddress,
		ControlAddress:        controlAddress,
		LMTPExtraCapabilities: []string{"8BITMIME"},
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
	client := dialLMTP(t, lmtpAddress)
	defer client.Close()
	client.ExpectLine("220 2.0.0 nauthilus-director LMTP ready\r\n")
	client.WriteLine("LHLO eightbit.example")
	capabilities := client.ReadResponse()
	assertLMTPHasCapability(t, capabilities, "STARTTLS")
	assertLMTPHasCapability(t, capabilities, "8BITMIME")
	assertLMTPNoCapability(t, capabilities, "CHUNKING")
	client.WriteLine("STARTTLS")
	client.ExpectLine("220 2.0.0 Ready to start TLS\r\n")
	client.UpgradeTLS(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	client.WriteLine("LHLO eightbit.example")
	capabilities = client.ReadResponse()
	assertLMTPHasCapability(t, capabilities, "AUTH PLAIN")
	assertLMTPHasCapability(t, capabilities, "8BITMIME")
	assertLMTPNoCapability(t, capabilities, "CHUNKING")
	client.WriteLine("AUTH PLAIN " + plainLMTPPayload(e2eLMTPSubmitter, e2ePassword))
	client.ExpectLine("235 2.7.0 Authentication successful\r\n")
	client.WriteLine("MAIL FROM:<sender@example.test> BODY=8BITMIME")
	client.ExpectLine("250 2.0.0 Sender accepted\r\n")
	client.WriteLine("RCPT TO:<" + e2eLMTPRecipientA + ">")
	client.ExpectLine("250 2.0.0 Recipient accepted\r\n")
	client.WriteLine("DATA")
	client.ExpectLine("354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	client.WriteRaw("eight-bit-body\r\n.\r\n")
	client.ExpectLine("250 2.1.5 Message accepted\r\n")
	authority.ExpectPeerAuth(t, e2eLMTPSubmitter)

	observation := fakeLMTPA.ExpectObservation(t)
	assertLMTPBackendObservation(t, observation, []string{lmtpPath(e2eLMTPRecipientA)}, false)
	if !slices.Contains(observation.Commands, "MAIL FROM:<sender@example.test> BODY=8BITMIME") {
		t.Fatalf("backend commands = %v, want forwarded BODY=8BITMIME", observation.Commands)
	}
	assertLMTPProcessOutputSafe(t, process.output.String())
}

// TestServerBinaryPublicLMTPSIZEForwardingTranscript proves accepted SIZE reaches only capable backends.
func TestServerBinaryPublicLMTPSIZEForwardingTranscript(t *testing.T) {
	fixture := startLMTPBackendChunkingFixture(t, lmtpBackendChunkingFixtureOptions{
		BackendCapabilities:     []string{"8BITMIME", "SIZE 100"},
		HealthCapabilities:      []string{"8BITMIME", "SIZE 100"},
		ExtraCapabilities:       []string{"8BITMIME", "SIZE"},
		MaxMessageBytes:         50,
		DisableFrontendChunking: true,
	})

	client, capabilities := authenticatedLMTPClientWithCapabilities(t, fixture.address, "size-forward.example")
	defer client.Close()
	assertLMTPHasCapability(t, capabilities, "8BITMIME")
	assertLMTPHasCapability(t, capabilities, "SIZE 50")
	client.WriteLine("MAIL FROM:<sender@example.test> SIZE=42 BODY=8BITMIME")
	client.ExpectLine("250 2.0.0 Sender accepted\r\n")
	client.WriteLine("RCPT TO:<" + e2eLMTPRecipientA + ">")
	client.ExpectLine("250 2.0.0 Recipient accepted\r\n")
	client.WriteLine("DATA")
	client.ExpectLine("354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	client.WriteRaw("size-forward-body\r\n.\r\n")
	client.ExpectLine("250 2.1.5 Message accepted\r\n")

	observation := fixture.fakeLMTPA.ExpectObservation(t)
	assertBackendMAILCommand(t, observation, "MAIL FROM:<sender@example.test> BODY=8BITMIME SIZE=42")
	assertLMTPBackendObservation(t, observation, []string{lmtpPath(e2eLMTPRecipientA)}, false)

	omittedClient, omittedCapabilities := authenticatedLMTPClientWithCapabilities(t, fixture.address, "size-omitted.example")
	defer omittedClient.Close()
	assertLMTPHasCapability(t, omittedCapabilities, "SIZE 50")
	deliverLMTPMessage(t, omittedClient, e2eLMTPRecipientASecond, "size-omitted-body")

	omittedObservation := fixture.fakeLMTPA.ExpectObservation(t)
	assertBackendMAILCommand(t, omittedObservation, "MAIL FROM:<sender@example.test>")
	assertNoBackendMAILParameter(t, omittedObservation, "SIZE=")
	assertLMTPProcessOutputSafe(t, fixture.process.output.String())
}

// TestServerBinaryPublicLMTPSIZESuppressedByMixedHealth proves pool proof is fail-closed.
func TestServerBinaryPublicLMTPSIZESuppressedByMixedHealth(t *testing.T) {
	fixture := startLMTPBackendChunkingFixture(t, lmtpBackendChunkingFixtureOptions{
		BackendCapabilities: []string{"SIZE 100"},
		HealthCapabilitiesByBackend: map[string][]string{
			e2eLMTPBackendAID: {"SIZE 100"},
			e2eLMTPBackendBID: {},
		},
		ExtraCapabilities:       []string{"SIZE"},
		MaxMessageBytes:         50,
		DisableFrontendChunking: true,
	})

	client, capabilities := authenticatedLMTPClientWithCapabilities(t, fixture.address, "size-suppressed.example")
	defer client.Close()
	assertLMTPNoCapability(t, capabilities, "SIZE")
	client.WriteLine("MAIL FROM:<sender@example.test> SIZE=42")
	client.ExpectLine("501 5.5.4 Invalid MAIL command\r\n")
	fixture.fakeLMTPA.AssertNoObservation(t, 300*time.Millisecond)
	assertLMTPProcessOutputSafe(t, fixture.process.output.String())
}

// TestServerBinaryPublicLMTPSIZEOversizeRejectsBeforeBackend proves declared oversize is local.
func TestServerBinaryPublicLMTPSIZEOversizeRejectsBeforeBackend(t *testing.T) {
	fixture := startLMTPBackendChunkingFixture(t, lmtpBackendChunkingFixtureOptions{
		BackendCapabilities:     []string{"SIZE 100"},
		HealthCapabilities:      []string{"SIZE 100"},
		ExtraCapabilities:       []string{"SIZE"},
		MaxMessageBytes:         5,
		DisableFrontendChunking: true,
	})

	client, capabilities := authenticatedLMTPClientWithCapabilities(t, fixture.address, "size-oversize.example")
	defer client.Close()
	assertLMTPHasCapability(t, capabilities, "SIZE 5")
	client.WriteLine("MAIL FROM:<sender@example.test> SIZE=6")
	client.ExpectLine("552 5.3.4 Message size exceeds fixed maximum message size\r\n")
	fixture.fakeLMTPA.AssertNoObservation(t, 300*time.Millisecond)
	assertLMTPProcessOutputSafe(t, fixture.process.output.String())
}

// TestServerBinaryPublicLMTPSIZESelectedBackendRaceFailsClosed proves selected proof is enforced.
func TestServerBinaryPublicLMTPSIZESelectedBackendRaceFailsClosed(t *testing.T) {
	fixture := startLMTPBackendChunkingFixture(t, lmtpBackendChunkingFixtureOptions{
		HealthCapabilities:      []string{"SIZE 100"},
		ExtraCapabilities:       []string{"SIZE"},
		MaxMessageBytes:         50,
		DisableFrontendChunking: true,
	})

	client, capabilities := authenticatedLMTPClientWithCapabilities(t, fixture.address, "size-race.example")
	defer client.Close()
	assertLMTPHasCapability(t, capabilities, "SIZE 50")
	client.WriteLine("MAIL FROM:<sender@example.test> SIZE=42")
	client.ExpectLine("250 2.0.0 Sender accepted\r\n")
	client.WriteLine("RCPT TO:<" + e2eLMTPRecipientA + ">")
	client.ExpectLine("451 4.3.0 Message delivery temporarily failed\r\n")
	fixture.fakeLMTPA.AssertNoObservation(t, 300*time.Millisecond)
	assertLMTPProcessOutputSafe(t, fixture.process.output.String())
}

// TestServerBinaryPublicLMTPPipeliningDoesNotBatchBackend proves frontend grouping stays local.
func TestServerBinaryPublicLMTPPipeliningDoesNotBatchBackend(t *testing.T) {
	fixture := startLMTPBackendChunkingFixture(t, lmtpBackendChunkingFixtureOptions{
		ExtraCapabilities:       []string{"PIPELINING"},
		DisableFrontendChunking: true,
		DetectCommandBatching:   true,
	})

	client, capabilities := authenticatedLMTPClientWithCapabilities(t, fixture.address, "pipelining.example")
	defer client.Close()
	assertLMTPHasCapability(t, capabilities, "PIPELINING")
	client.WriteRaw(strings.Join([]string{
		"MAIL FROM:<sender@example.test>",
		"RCPT TO:<" + e2eLMTPRecipientA + ">",
		"DATA",
		"",
	}, "\r\n"))
	client.ExpectLine("250 2.0.0 Sender accepted\r\n")
	client.ExpectLine("250 2.0.0 Recipient accepted\r\n")
	client.ExpectLine("354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	client.WriteRaw("pipelined-body\r\n.\r\n")
	client.ExpectLine("250 2.1.5 Message accepted\r\n")

	observation := fixture.fakeLMTPA.ExpectObservation(t)
	if observation.CommandBatched {
		t.Fatalf("backend observation = %#v, want sequential backend commands", observation)
	}
	assertBackendMAILCommand(t, observation, "MAIL FROM:<sender@example.test>")
	assertLMTPProcessOutputSafe(t, fixture.process.output.String())
}

// TestServerBinaryPublicLMTPBackendProxyProtocolFlow proves LMTP delivery and health through outbound PROXY.
func TestServerBinaryPublicLMTPBackendProxyProtocolFlow(t *testing.T) {
	binary := e2eServerBinary(t)
	redisFixture := startValkeySessionStore(t)
	authority := startLMTPAuthority(t, lmtpAuthorityIdentities())
	tlsBundle := writeLMTPPeerTLSBundle(t)
	fakeLMTPA := lmtpbackend.Start(t, lmtpbackend.Options{
		Capabilities:         []string{"CHUNKING"},
		RequireProxyProtocol: true,
	})
	fakeLMTPB := lmtpbackend.Start(t, lmtpbackend.Options{Capabilities: []string{"CHUNKING"}})
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
		LMTPBackendHAProxy: map[string]bool{
			e2eLMTPBackendAID: true,
		},
		LMTPBackendHealth: map[string]bool{
			e2eLMTPBackendAID: true,
		},
		LMTPBackendDeepHealth: map[string]bool{
			e2eLMTPBackendAID: true,
		},
		TLS: tlsBundle,
	})
	process := startDirectorProcess(t, binary, configPath)

	waitForLMTPGreeting(t, lmtpAddress, process)
	waitForControlReady(t, "http://"+controlAddress, process)
	waitForProcessHealthStatus(t, redisFixture.store, e2eLMTPBackendAID, backend.HealthStatusHealthy)
	assertProxyProtocolHeader(t, fakeLMTPA.ExpectProxyProtocolHeader(t))

	client := authenticatedLMTPClient(t, lmtpAddress)
	defer client.Close()
	client.WriteLine("MAIL FROM:<sender@example.test>")
	client.ExpectLine("250 2.0.0 Sender accepted\r\n")
	client.WriteLine("RCPT TO:<" + e2eLMTPRecipientA + ">")
	client.ExpectLine("250 2.0.0 Recipient accepted\r\n")
	client.WriteLine("DATA")
	client.ExpectLine("354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	client.WriteRaw(e2eLMTPMessageSecret + "\r\n.\r\n")
	client.ExpectLine("250 2.1.5 Message accepted\r\n")
	assertLMTPBackendObservation(t, fakeLMTPA.ExpectObservation(t), []string{lmtpPath(e2eLMTPRecipientA)}, true)
	assertProxyProtocolHeader(t, fakeLMTPA.ExpectProxyProtocolHeader(t))
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
	imapClient, imapReader := loginProcessIMAP(t, imapAddress, e2eLMTPRecipientA)
	expectBackendProxy(t, imapClient, imapReader, fakeIMAPA, "A002")
	_ = imapClient.Close()
	waitForRESTSessionCount(t, controlURL, 0)
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
	assertLMTPBackendObservation(t, observation, []string{lmtpPath(e2eLMTPRecipientA), lmtpPath(e2eLMTPRecipientASecond)}, true)
	if !strings.Contains(observation.Body, e2eLMTPMessageSecret) {
		t.Fatalf("fake backend did not receive DATA body")
	}
	retainedRouteOutput := waitForLMTPRouteSource(t, ctl, controlURL, e2eLMTPRecipientA, "retained_backend_binding")
	if !strings.Contains(retainedRouteOutput, "selected_backend="+e2eLMTPBackendAID) ||
		!strings.Contains(retainedRouteOutput, "affinity_binding_source=retained_backend_binding") {
		t.Fatalf("retained LMTP route lookup output = %q, want retained backend-node binding", retainedRouteOutput)
	}
	retainedClient, retainedReader := loginProcessIMAP(t, imapAddress, e2eLMTPRecipientA)
	expectBackendProxy(t, retainedClient, retainedReader, fakeIMAPA, "R002")
	_ = retainedClient.Close()
	waitForRESTSessionCount(t, controlURL, 0)
	time.Sleep(3 * time.Second)
	expiredRouteOutput := waitForLMTPRouteSource(t, ctl, controlURL, e2eLMTPRecipientA, "fail_closed")
	if strings.Contains(expiredRouteOutput, "affinity_binding_source=retained_backend_binding") {
		t.Fatalf("expired LMTP route lookup output = %q, want no retained backend-node binding", expiredRouteOutput)
	}
	if !strings.Contains(expiredRouteOutput, "reason=account_unresolved") || !strings.Contains(expiredRouteOutput, "identity_nauthilus=false") {
		t.Fatalf("expired LMTP route lookup output = %q, want bounded unresolved identity diagnostic", expiredRouteOutput)
	}
	authority.ExpectLookupMode(t, e2eLMTPRecipientA, "no-auth")
	authority.ExpectLookupMode(t, e2eLMTPRecipientASecond, "no-auth")
	beforeMixedRouteLookup := authority.RequestCount()
	routeOutput := runDirectorctl(t, ctl, controlURL, "route", "lookup", "--protocol", e2eLMTPProtocol, "--recipient", e2eLMTPRecipientMixed, "--listener", e2eLMTPListenerName, "--include-affinity")
	if !strings.Contains(routeOutput, "source=fail_closed") || !strings.Contains(routeOutput, "reason=account_unresolved") || !strings.Contains(routeOutput, "identity_source=director_state_unresolved") {
		t.Fatalf("route lookup output = %q, want bounded unresolved identity diagnostic", routeOutput)
	}
	if authority.RequestCount() != beforeMixedRouteLookup {
		t.Fatal("LMTP route lookup called Nauthilus identity lookup")
	}
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
	assertLMTPBackendObservation(t, observation, []string{lmtpPath(e2eLMTPRecipientA)}, true)
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
	assertLMTPBackendObservation(t, fakeLMTPA.ExpectObservation(t), []string{lmtpPath(e2eLMTPRecipientA)}, true)

	rejected := authenticatedLMTPClient(t, address)
	defer rejected.Close()
	rejected.WriteLine("MAIL FROM:<sender@example.test>")
	rejected.ExpectLine("250 2.0.0 Sender accepted\r\n")
	rejected.WriteLine("RCPT TO:<" + e2eLMTPRecipientMaint + ">")
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

// authenticatedLMTPClientWithCapabilities authenticates and returns the post-TLS LHLO capabilities.
func authenticatedLMTPClientWithCapabilities(t *testing.T, address string, lhloName string) (*lmtpClient, []string) {
	t.Helper()

	client := dialLMTP(t, address)
	client.ExpectLine("220 2.0.0 nauthilus-director LMTP ready\r\n")
	client.WriteLine("LHLO " + lhloName)
	capabilities := client.ReadResponse()
	assertLMTPHasCapability(t, capabilities, "STARTTLS")
	client.WriteLine("STARTTLS")
	client.ExpectLine("220 2.0.0 Ready to start TLS\r\n")
	client.UpgradeTLS(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	client.WriteLine("LHLO " + lhloName)
	capabilities = client.ReadResponse()
	client.WriteLine("AUTH PLAIN " + plainLMTPPayload(e2eLMTPSubmitter, e2ePassword))
	client.ExpectLine("235 2.7.0 Authentication successful\r\n")

	return client, capabilities
}

// authenticatedLMTPBearerClient returns a STARTTLS and bearer-authenticated LMTP client.
func authenticatedLMTPBearerClient(t *testing.T, address string, mechanism string, username string, token string) *lmtpClient {
	t.Helper()

	client := dialLMTP(t, address)
	client.ExpectLine("220 2.0.0 nauthilus-director LMTP ready\r\n")
	client.WriteLine("LHLO bearer-peer.example")
	capabilities := client.ReadResponse()
	assertLMTPHasCapability(t, capabilities, "STARTTLS")
	client.WriteLine("STARTTLS")
	client.ExpectLine("220 2.0.0 Ready to start TLS\r\n")
	client.UpgradeTLS(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	client.WriteLine("LHLO bearer-peer.example")
	capabilities = client.ReadResponse()
	assertLMTPAuthMechanism(t, capabilities, mechanism)
	client.WriteLine("AUTH " + mechanism + " " + lmtpBearerPayload(mechanism, username, token))
	client.ExpectLine("235 2.7.0 Authentication successful\r\n")

	return client
}

// deliverLMTPMessage sends one message through an already-authenticated public LMTP connection.
func deliverLMTPMessage(t *testing.T, client *lmtpClient, recipient string, body string) {
	t.Helper()

	client.WriteLine("MAIL FROM:<sender@example.test>")
	client.ExpectLine("250 2.0.0 Sender accepted\r\n")
	client.WriteLine("RCPT TO:<" + recipient + ">")
	client.ExpectLine("250 2.0.0 Recipient accepted\r\n")
	client.WriteLine("DATA")
	client.ExpectLine("354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	client.WriteRaw(body + "\r\n.\r\n")
	client.ExpectLine("250 2.1.5 Message accepted\r\n")
}

type lmtpProcessConfigOptions struct {
	RedisAddress                string
	AuthorityURL                string
	AuthorityOIDC               processAuthorityOIDCOptions
	AuthorityBearer             processAuthorityBearerOptions
	LMTPAddress                 string
	LMTPSAddress                string
	IMAPAddress                 string
	ControlAddress              string
	IMAPGreeting                greetingPolicyFixture
	LMTPGreeting                greetingPolicyFixture
	LMTPSGreeting               greetingPolicyFixture
	BackendRetentionTTL         string
	LMTPBackends                map[string]string
	IMAPBackends                map[string]string
	LMTPBackendHAProxy          map[string]bool
	LMTPBackendHealth           map[string]bool
	LMTPBackendDeepHealth       map[string]bool
	LMTPListenerTLSMode         string
	LMTPExtraCapabilities       []string
	LMTPCapabilityFilterDeny    []string
	LMTPMaxMessageBytes         int64
	LMTPDisableChunking         bool
	LMTPPeerAuthMechanisms      []string
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
	lmtpListenerTLSMode := strings.ToLower(strings.TrimSpace(options.LMTPListenerTLSMode))
	if lmtpListenerTLSMode == "" {
		lmtpListenerTLSMode = "starttls"
	}
	lmtpPeerAuthRequired := !options.DisableLMTPPeerAuth
	lmtpPeerAuthMechanisms := configuredLMTPPeerAuthMechanisms(options)
	lmtpCapabilities := lmtpListenerCapabilities(lmtpListenerTLSMode, lmtpPeerAuthMechanisms, options.LMTPExtraCapabilities, !options.LMTPDisableChunking)
	lmtpsCapabilities := lmtpListenerCapabilities("implicit", lmtpPeerAuthMechanisms, options.LMTPExtraCapabilities, !options.LMTPDisableChunking)
	lmtpCapabilityDeny := quotedYAMLStrings(options.LMTPCapabilityFilterDeny)
	backendRetentionTTL := strings.TrimSpace(options.BackendRetentionTTL)
	if backendRetentionTTL == "" {
		backendRetentionTTL = "15m"
	}
	authorityPasswordPath := writeProcessSecretFile(t, "unused")
	backendPasswordPath := writeProcessSecretFile(t, e2ePassword)
	healthPasswordPath := writeProcessSecretFile(t, e2ePassword)

	content := fmt.Sprintf(`patch:
  - op: remove
    path: director.listeners
    value: [imaps, sieve, sieves, pop3, pop3s]
  - op: remove
    path: director.backend_pools
    value: [sieve-default, pop3-default]
  - op: remove
    path: director.backends
    value: [mailstore-a-sieve, mailstore-b-sieve, mailstore-a-pop3, mailstore-b-pop3]
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
      default_ttl: %q
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
%s
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
        mode: %q
        cert: %q
        key: %q
        client_ca: ""
        require_client_cert: false
        min_tls_version: TLS1.2
      lmtp:
        client_auth:
          required: %t
          authority: default
          mechanisms: [%s]
          mtls:
            satisfies_required: false
            identity_source: subject_common_name
        capabilities: [%s]
        capability_filter:
          deny: [%s]
        size:
          max_message_bytes: %d
%s
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
        client_auth:
          required: true
          authority: default
          mechanisms: [%s]
          mtls:
            satisfies_required: true
            identity_source: subject_common_name
        capabilities: [%s]
        capability_filter:
          deny: [%s]
        size:
          max_message_bytes: %d
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
          password_file: %q
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
        mode: %q
        master_user:
          username: director-master
          password_file: %q
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
      backend_node: mailstore-a-node
      address: %q
      weight: 100
      max_connections: 100
      maintenance: disabled
      haproxy:
        enabled: %t
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
        enabled: %t
        deep_check: %t
        username: healthcheck@example.test
        password_file: %q
    mailstore-b-lmtp:
      protocol: lmtp
      shard_tag: %q
      backend_node: mailstore-b-node
      address: %q
      weight: 100
      max_connections: 100
      maintenance: disabled
      haproxy:
        enabled: %t
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
        enabled: %t
        deep_check: %t
        username: healthcheck@example.test
        password_file: %q
	`, options.ControlAddress,
		processControlAuthYAML(t),
		options.RedisAddress,
		processAuthorityYAML(t, options.AuthorityOIDC, options.AuthorityBearer),
		options.AuthorityURL,
		authorityPasswordPath,
		backendRetentionTTL,
		e2eShardTag,
		options.IMAPAddress,
		options.TLS.ServerCertPath,
		options.TLS.ServerKeyPath,
		greetingPolicyYAML("        ", options.IMAPGreeting),
		options.LMTPAddress,
		lmtpListenerTLSMode,
		options.TLS.ServerCertPath,
		options.TLS.ServerKeyPath,
		lmtpPeerAuthRequired,
		quotedYAMLStrings(lmtpPeerAuthMechanisms),
		quotedYAMLStrings(lmtpCapabilities),
		lmtpCapabilityDeny,
		options.LMTPMaxMessageBytes,
		greetingPolicyYAML("        ", options.LMTPGreeting),
		options.LMTPSAddress,
		options.TLS.ServerCertPath,
		options.TLS.ServerKeyPath,
		options.TLS.CAPath,
		quotedYAMLStrings(lmtpPeerAuthMechanisms),
		quotedYAMLStrings(lmtpsCapabilities),
		lmtpCapabilityDeny,
		options.LMTPMaxMessageBytes,
		greetingPolicyYAML("        ", options.LMTPSGreeting),
		e2eShardTag,
		options.IMAPBackends[e2eBackendAID],
		imapBackendTLSMode,
		options.IMAPBackendTLSInsecure,
		imapBackendAuthMode,
		backendPasswordPath,
		e2eShardTagB,
		options.IMAPBackends[e2eBackendBID],
		imapBackendTLSMode,
		options.IMAPBackendTLSInsecure,
		imapBackendAuthMode,
		backendPasswordPath,
		e2eShardTag,
		options.LMTPBackends[e2eLMTPBackendAID],
		options.LMTPBackendHAProxy[e2eLMTPBackendAID],
		lmtpBackendTLSMode,
		options.LMTPBackendTLSInsecure,
		options.LMTPBackendHealth[e2eLMTPBackendAID],
		options.LMTPBackendDeepHealth[e2eLMTPBackendAID],
		healthPasswordPath,
		e2eShardTagB,
		options.LMTPBackends[e2eLMTPBackendBID],
		options.LMTPBackendHAProxy[e2eLMTPBackendBID],
		lmtpBackendTLSMode,
		options.LMTPBackendTLSInsecure,
		options.LMTPBackendHealth[e2eLMTPBackendBID],
		options.LMTPBackendDeepHealth[e2eLMTPBackendBID],
		healthPasswordPath,
	)
	content = strings.ReplaceAll(content, "\t", "")

	path := filepath.Join(t.TempDir(), "nauthilus-director-lmtp.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write LMTP process config: %v", err)
	}

	return path
}

// normalizedLMTPPeerAuthMechanisms returns lower-case configured LMTP peer mechanisms.
func normalizedLMTPPeerAuthMechanisms(mechanisms []string) []string {
	if len(mechanisms) == 0 {
		return []string{"plain"}
	}

	normalized := make([]string, 0, len(mechanisms))
	for _, mechanism := range mechanisms {
		mechanism = strings.ToLower(strings.TrimSpace(mechanism))
		if mechanism != "" {
			normalized = append(normalized, mechanism)
		}
	}
	if len(normalized) == 0 {
		return []string{"plain"}
	}

	return normalized
}

// configuredLMTPPeerAuthMechanisms returns configured peer-auth mechanisms or an empty auth-free set.
func configuredLMTPPeerAuthMechanisms(options lmtpProcessConfigOptions) []string {
	if options.DisableLMTPPeerAuth && len(options.LMTPPeerAuthMechanisms) == 0 {
		return nil
	}

	return normalizedLMTPPeerAuthMechanisms(options.LMTPPeerAuthMechanisms)
}

// lmtpListenerCapabilities renders desired frontend capabilities for one LMTP listener.
func lmtpListenerCapabilities(tlsMode string, mechanisms []string, extra []string, enableChunking bool) []string {
	capabilities := []string{"SMTPUTF8", "ENHANCEDSTATUSCODES"}
	if strings.EqualFold(tlsMode, "starttls") {
		capabilities = append(capabilities, "STARTTLS")
	}
	if len(mechanisms) > 0 {
		capabilities = append(capabilities, "AUTH "+strings.ToUpper(strings.Join(mechanisms, " ")))
	}
	if enableChunking {
		capabilities = append(capabilities, "CHUNKING")
	}

	return append(capabilities, extra...)
}

// publishHealthyLMTPBackends seeds backend capability proof before process startup.
func publishHealthyLMTPBackends(t *testing.T, fixture redisSessionFixture, backendIDs []string, capabilities ...string) {
	t.Helper()

	capabilitySet, capabilityFacts := lmtpHealthCapabilityFacts(capabilities)

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
				Enabled:         true,
				Status:          backend.HealthStatusHealthy,
				ReasonClass:     "ok",
				Capabilities:    capabilitySet,
				CapabilityFacts: capabilityFacts,
			},
			TTL: time.Minute,
		})
		if err != nil {
			t.Fatalf("PublishHealthState %s: %v", backendID, err)
		}
	}
}

// lmtpHealthCapabilityFacts converts test LHLO strings into backend health proof.
func lmtpHealthCapabilityFacts(capabilities []string) (backend.CapabilitySet, backend.CapabilityFacts) {
	var (
		capabilitySet   backend.CapabilitySet
		capabilityFacts backend.CapabilityFacts
	)

	for _, capability := range capabilities {
		fields := strings.Fields(strings.ToUpper(strings.TrimSpace(capability)))
		if len(fields) == 0 {
			continue
		}

		if fields[0] == "SIZE" {
			size, ok := backend.ParseSizeCapabilityFact(fields[1:])
			if ok {
				capabilitySet.Add("SIZE")
				capabilityFacts.SetSize(size)
			}

			continue
		}

		capabilitySet.Add(strings.Join(fields, " "))
	}

	return capabilitySet, capabilityFacts
}

type lmtpBackendChunkingFixtureOptions struct {
	BackendCapabilities         []string
	HealthCapabilities          []string
	HealthCapabilitiesByBackend map[string][]string
	ExtraCapabilities           []string
	CapabilityFilterDeny        []string
	MaxMessageBytes             int64
	DisableFrontendChunking     bool
	DetectCommandBatching       bool
	FinalStatus                 map[string]lmtpbackend.Status
	FinalStatusLimit            int
	NonFinalBDATStatuses        []lmtpbackend.Status
}

type lmtpBackendChunkingFixture struct {
	address   string
	process   *directorProcess
	fakeLMTPA *lmtpbackend.Server
}

// startLMTPBackendChunkingFixture starts a real Director binary with fake LMTP backends.
func startLMTPBackendChunkingFixture(t *testing.T, options lmtpBackendChunkingFixtureOptions) lmtpBackendChunkingFixture {
	t.Helper()

	binary := e2eServerBinary(t)
	redisFixture := startValkeySessionStore(t)
	authority := startLMTPAuthority(t, lmtpAuthorityIdentities())
	tlsBundle := writeLMTPPeerTLSBundle(t)
	fakeLMTPA := lmtpbackend.Start(t, lmtpbackend.Options{
		Capabilities:          options.BackendCapabilities,
		FinalStatus:           options.FinalStatus,
		FinalStatusLimit:      options.FinalStatusLimit,
		NonFinalBDATStatus:    options.NonFinalBDATStatuses,
		DetectCommandBatching: options.DetectCommandBatching,
	})
	fakeLMTPB := lmtpbackend.Start(t, lmtpbackend.Options{
		Capabilities:          options.BackendCapabilities,
		DetectCommandBatching: options.DetectCommandBatching,
	})
	fakeIMAPA := startFakeIMAPBackend(t, fakeBackendOptions{})
	fakeIMAPB := startFakeIMAPBackend(t, fakeBackendOptions{})
	lmtpAddress := loopbackAddress(t)
	lmtpsAddress := loopbackAddress(t)
	imapAddress := loopbackAddress(t)
	controlAddress := loopbackAddress(t)
	if len(options.HealthCapabilitiesByBackend) > 0 {
		publishHealthyLMTPBackends(t, redisFixture, []string{e2eLMTPBackendAID}, options.HealthCapabilitiesByBackend[e2eLMTPBackendAID]...)
		publishHealthyLMTPBackends(t, redisFixture, []string{e2eLMTPBackendBID}, options.HealthCapabilitiesByBackend[e2eLMTPBackendBID]...)
	} else {
		publishHealthyLMTPBackends(t, redisFixture, []string{e2eLMTPBackendAID, e2eLMTPBackendBID}, options.HealthCapabilities...)
	}
	configPath := writeLMTPProcessConfig(t, lmtpProcessConfigOptions{
		RedisAddress:             redisFixture.addr,
		AuthorityURL:             authority.URL(),
		LMTPAddress:              lmtpAddress,
		LMTPSAddress:             lmtpsAddress,
		IMAPAddress:              imapAddress,
		ControlAddress:           controlAddress,
		LMTPExtraCapabilities:    options.ExtraCapabilities,
		LMTPCapabilityFilterDeny: options.CapabilityFilterDeny,
		LMTPMaxMessageBytes:      options.MaxMessageBytes,
		LMTPDisableChunking:      options.DisableFrontendChunking,
		LMTPBackends:             map[string]string{e2eLMTPBackendAID: fakeLMTPA.Address(), e2eLMTPBackendBID: fakeLMTPB.Address()},
		IMAPBackends:             map[string]string{e2eBackendAID: fakeIMAPA.Address(), e2eBackendBID: fakeIMAPB.Address()},
		TLS:                      tlsBundle,
	})
	process := startDirectorProcess(t, binary, configPath)
	waitForLMTPGreeting(t, lmtpAddress, process)

	return lmtpBackendChunkingFixture{
		address:   lmtpAddress,
		process:   process,
		fakeLMTPA: fakeLMTPA,
	}
}

// authenticatedLMTPClientWithoutFrontendChunking verifies CHUNKING is absent before AUTH.
func authenticatedLMTPClientWithoutFrontendChunking(t *testing.T, address string) *lmtpClient {
	t.Helper()

	client := dialLMTP(t, address)
	client.ExpectLine("220 2.0.0 nauthilus-director LMTP ready\r\n")
	client.WriteLine("LHLO no-frontend-chunking.example")
	capabilities := client.ReadResponse()
	assertLMTPHasCapability(t, capabilities, "STARTTLS")
	assertLMTPNoCapability(t, capabilities, "CHUNKING")
	client.WriteLine("STARTTLS")
	client.ExpectLine("220 2.0.0 Ready to start TLS\r\n")
	client.UpgradeTLS(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	client.WriteLine("LHLO no-frontend-chunking.example")
	capabilities = client.ReadResponse()
	assertLMTPHasCapability(t, capabilities, "AUTH PLAIN")
	assertLMTPNoCapability(t, capabilities, "CHUNKING")
	client.WriteLine("AUTH PLAIN " + plainLMTPPayload(e2eLMTPSubmitter, e2ePassword))
	client.ExpectLine("235 2.7.0 Authentication successful\r\n")

	return client
}

// deliverLMTPDATA sends a DATA transaction through an authenticated public LMTP client.
func deliverLMTPDATA(t *testing.T, client *lmtpClient, recipients []string, body string) {
	t.Helper()

	client.WriteLine("MAIL FROM:<sender@example.test>")
	client.ExpectLine("250 2.0.0 Sender accepted\r\n")
	for _, recipient := range recipients {
		client.WriteLine("RCPT TO:<" + recipient + ">")
		client.ExpectLine("250 2.0.0 Recipient accepted\r\n")
	}
	client.WriteLine("DATA")
	client.ExpectLine("354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	client.WriteRaw(body + ".\r\n")
	for range recipients {
		client.ExpectLine("250 2.1.5 Message accepted\r\n")
	}
}

// largeLMTPBody returns a deterministic body that crosses the backend BDAT chunk boundary.
func largeLMTPBody() string {
	return strings.Repeat(strings.Repeat("a", 1022)+"\r\n", 65) + "large-proof-tail\r\n"
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

// RequestCount returns how many public authority calls reached the fake.
func (a *lmtpAuthority) RequestCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()

	return len(a.requests)
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
		"account_field": "account",
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
		e2eLMTPRecipientMaint:   {Account: e2eLMTPRecipientMaint, Tenant: e2eTenant, Shard: e2eShardTag},
		e2eLMTPRecipientMixed:   {Account: e2eLMTPRecipientMixed, Tenant: e2eTenant, Shard: e2eShardTag},
		e2eLMTPRecipientB:       {Account: e2eLMTPRecipientB, Tenant: e2eTenant, Shard: e2eShardTagB},
	}
}

// lmtpMappedAuthorityIdentities adapts LMTP identity fixtures to the shared HTTP authority.
func lmtpMappedAuthorityIdentities() map[string]map[string][]string {
	return mappedAttributesFromLMTPIdentities(lmtpAuthorityIdentities())
}

// mappedAttributesFromLMTPIdentities adapts caller-provided LMTP fixtures to the shared HTTP authority.
func mappedAttributesFromLMTPIdentities(identities map[string]lmtpAuthorityIdentity) map[string]map[string][]string {
	mapped := make(map[string]map[string][]string, len(identities))
	for username, identity := range identities {
		mapped[username] = map[string][]string{
			"account":   {identity.Account},
			"tenant":    {identity.Tenant},
			"mailShard": {identity.Shard},
		}
	}

	return mapped
}

// expectNoAuthorityRequestMethod verifies bearer peer auth did not use password auth JSON.
func expectNoAuthorityRequestMethod(t *testing.T, authority *fakeHTTPAuthority, protocol string, method string) {
	t.Helper()

	authority.requestsLock.Lock()
	defer authority.requestsLock.Unlock()

	for _, request := range authority.requests {
		if request["protocol"] == protocol && request["method"] == method {
			t.Fatalf("authority saw forbidden protocol=%s method=%s request", protocol, method)
		}
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

// assertLMTPAuthMechanism verifies an advertised AUTH list contains one mechanism.
func assertLMTPAuthMechanism(t *testing.T, lines []string, mechanism string) {
	t.Helper()

	want := strings.ToUpper(strings.TrimSpace(mechanism))
	for _, line := range lines {
		if len(line) < 4 {
			continue
		}
		fields := strings.Fields(strings.ToUpper(strings.TrimSpace(line[4:])))
		if len(fields) == 0 || fields[0] != "AUTH" {
			continue
		}
		if slices.Contains(fields[1:], want) {
			return
		}
	}

	t.Fatalf("capabilities = %v, want AUTH mechanism %q", lines, mechanism)
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

// assertBackendMAILCommand verifies the exact backend MAIL command transcript.
func assertBackendMAILCommand(t *testing.T, observation lmtpbackend.Observation, want string) {
	t.Helper()

	if !slices.Contains(observation.Commands, want) {
		t.Fatalf("backend commands = %v, want %q", observation.Commands, want)
	}
}

// assertNoBackendMAILParameter verifies no backend MAIL command contains one parameter token.
func assertNoBackendMAILParameter(t *testing.T, observation lmtpbackend.Observation, parameter string) {
	t.Helper()

	for _, command := range observation.Commands {
		if strings.HasPrefix(command, "MAIL FROM:") && strings.Contains(command, parameter) {
			t.Fatalf("backend MAIL command = %q, did not want parameter %q", command, parameter)
		}
	}
}

// assertBackendDATAWire verifies backend DATA was the only body transport.
func assertBackendDATAWire(t *testing.T, observation lmtpbackend.Observation, wantBody string) {
	t.Helper()

	if !observation.UsedDATA {
		t.Fatalf("backend did not receive DATA: %#v", observation)
	}
	if observation.Body != wantBody {
		t.Fatalf("backend DATA body length = %d, want %d", len(observation.Body), len(wantBody))
	}
	if !slices.Contains(observation.Commands, "DATA") {
		t.Fatalf("backend commands = %v, want DATA", observation.Commands)
	}
}

// assertBackendBDATWire verifies backend BDAT was the only body transport and bytes match.
func assertBackendBDATWire(t *testing.T, observation lmtpbackend.Observation, wantBody string) {
	t.Helper()

	if observation.UsedDATA {
		t.Fatalf("backend received DATA during BDAT proof: %#v", observation)
	}
	assertBackendBDATBody(t, observation, wantBody)
	if len(observation.BDATChunks) == 0 {
		t.Fatal("backend BDAT transcript has no chunks")
	}
	if !observation.BDATChunks[len(observation.BDATChunks)-1].Last {
		t.Fatalf("backend BDAT chunks = %#v, want final LAST chunk", observation.BDATChunks)
	}
}

// assertBackendBDATBody verifies converted payload bytes without printing the body.
func assertBackendBDATBody(t *testing.T, observation lmtpbackend.Observation, wantBody string) {
	t.Helper()

	if !observation.UsedBDAT {
		t.Fatalf("backend did not receive BDAT: %#v", observation)
	}
	if observation.Body != wantBody {
		t.Fatalf("backend BDAT body length = %d, want %d", len(observation.Body), len(wantBody))
	}
}

// assertBackendBDATChunks verifies exact backend BDAT chunk metadata.
func assertBackendBDATChunks(t *testing.T, observation lmtpbackend.Observation, want []lmtpbackend.BDATChunk) {
	t.Helper()

	if len(observation.BDATChunks) != len(want) {
		t.Fatalf("backend BDAT chunks = %#v, want %#v", observation.BDATChunks, want)
	}
	for index := range want {
		got := observation.BDATChunks[index]
		if got.Command != want[index].Command || got.Size != want[index].Size || got.Last != want[index].Last || got.Payload != want[index].Payload {
			t.Fatalf("backend BDAT chunk %d = %#v, want %#v", index, got, want[index])
		}
	}
}

// assertNoBackendBDATWire verifies no backend BDAT command or payload was observed.
func assertNoBackendBDATWire(t *testing.T, observation lmtpbackend.Observation) {
	t.Helper()

	if observation.UsedBDAT || len(observation.BDATChunks) > 0 {
		t.Fatalf("backend unexpectedly received BDAT chunks: %#v", observation.BDATChunks)
	}
	for _, command := range observation.Commands {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(command)), "BDAT") {
			t.Fatalf("backend unexpectedly received BDAT command %q", command)
		}
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

// waitForLMTPRouteSource polls the public CLI route lookup until the expected source is visible.
func waitForLMTPRouteSource(t *testing.T, ctl string, controlURL string, recipient string, source string) string {
	t.Helper()

	var output string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		output = runDirectorctl(t, ctl, controlURL, "route", "lookup", "--protocol", e2eLMTPProtocol, "--recipient", recipient, "--listener", e2eLMTPListenerName, "--include-affinity")
		if strings.Contains(output, "source="+source) {
			return output
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("LMTP route lookup output = %q, want source=%s", output, source)

	return output
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

// lmtpBearerPayload renders a bearer SASL initial response for LMTP AUTH.
func lmtpBearerPayload(mechanism string, username string, token string) string {
	switch strings.ToLower(strings.TrimSpace(mechanism)) {
	case "oauthbearer":
		return base64.StdEncoding.EncodeToString([]byte("n,a=" + username + ",\x01auth=Bearer " + token + "\x01\x01"))
	default:
		return base64.StdEncoding.EncodeToString([]byte("user=" + username + "\x01auth=Bearer " + token + "\x01\x01"))
	}
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
		e2eLMTPRecipientMaint,
		e2eLMTPRecipientMixed,
		e2eLMTPSubmitter,
		e2eLMTPSSubmitter,
		e2eLMTPMessageSecret,
		e2eLMTPXOAuth2Token,
		e2eLMTPOAuthBearerToken,
		"sender@example.test",
		"plaintext-body",
		"eight-bit-body",
		"lmtp-xoauth2-delivery-body",
		"lmtp-oauthbearer-delivery-body",
		"maintenance-body",
		"mtls-body",
		"fallback-one",
		"chunk-proof-one",
		"large-proof-tail",
		"status-order-proof",
		"incomplete-status-proof",
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
