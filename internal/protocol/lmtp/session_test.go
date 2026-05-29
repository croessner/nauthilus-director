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

package lmtp

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/routing"
	"github.com/croessner/nauthilus-director/internal/state"
)

const (
	testAllAuthCapability   = "AUTH PLAIN LOGIN XOAUTH2 OAUTHBEARER"
	testDataBody            = "line-one\r\n.line-two\r\n"
	testMTLSPeerIdentity    = "technical-peer"
	testPeerPassword        = "submitter-secret"
	testPeerToken           = "submitter-token"
	testPlainAuthCapability = "AUTH PLAIN"
	testPlacementAccount    = "canonical@example.test"
	testPlacementListener   = "inbound-lmtp"
	testPlacementPool       = "lmtp-default"
	testPlacementService    = "delivery"
	testPlacementShardA     = "mailstore-a"
	testPlacementShardB     = "mailstore-b"
	testPlacementTenant     = "blue"
	testRecipientFirst      = "first@example.test"
	testRecipientLookup     = "Local@example.com"
	testRecipientSecond     = "second@example.test"
	testRecipientSingle     = "recipient@example.test"
	testRecipientThird      = "third@example.test"
	testRoutingShardAttr    = "mailShard"
	testTenantAttribute     = "tenant"
	testTemporaryDelivery   = "451 4.3.0 Message delivery temporarily failed\r\n"
	testSubmitterIdentity   = "technical-submit@example.test"
	testUnicodeRecipient    = "M\xc3\xbcller@example.test"
	testUnicodeSender       = "sender-\xc3\xbc@example.test"
)

// TestGreetingAndLHLOCapabilitiesAreDeterministic verifies safe capability filtering before and after STARTTLS.
func TestGreetingAndLHLOCapabilitiesAreDeterministic(t *testing.T) {
	harness := startLMTPHarness(t, testSessionConfig())
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")

	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250-SMTPUTF8\r\n")
	harness.expectLine(t, "250 STARTTLS\r\n")

	harness.write(t, "STARTTLS\r\n")
	harness.expectLine(t, "220 2.0.0 Ready to start TLS\r\n")

	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250-SMTPUTF8\r\n")
	harness.expectLine(t, "250 AUTH PLAIN LOGIN XOAUTH2 OAUTHBEARER\r\n")
}

// TestCommandsBeforeLHLOFailWithStableBadSequence verifies transaction commands do not run before LHLO.
func TestCommandsBeforeLHLOFailWithStableBadSequence(t *testing.T) {
	harness := startLMTPHarness(t, testSessionConfig())
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")

	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "503 5.5.1 Send LHLO first\r\n")
}

// TestSTARTTLSSequencingAndStateReset verifies STARTTLS only runs before auth and transaction state.
func TestSTARTTLSSequencingAndStateReset(t *testing.T) {
	harness := startLMTPHarness(t, testSessionConfig())
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")

	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250-SMTPUTF8\r\n")
	harness.expectLine(t, "250 STARTTLS\r\n")

	harness.write(t, "STARTTLS\r\n")
	harness.expectLine(t, "220 2.0.0 Ready to start TLS\r\n")

	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "503 5.5.1 Send LHLO first\r\n")

	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250-SMTPUTF8\r\n")
	harness.expectLine(t, "250 AUTH PLAIN LOGIN XOAUTH2 OAUTHBEARER\r\n")

	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "STARTTLS\r\n")
	harness.expectLine(t, "503 5.5.1 STARTTLS is not available\r\n")
}

// TestOmittedSTARTTLSCapabilityDisablesUpgrade verifies transport mode alone does not expose STARTTLS.
func TestOmittedSTARTTLSCapabilityDisablesUpgrade(t *testing.T) {
	config := testSessionConfig()
	config.Capabilities = []string{capabilitySMTPUTF8, testAllAuthCapability}

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 SMTPUTF8\r\n")

	harness.write(t, "STARTTLS\r\n")
	harness.expectLine(t, "503 5.5.1 STARTTLS is not available\r\n")
}

// TestOmittedAUTHCapabilityDisablesPeerAuth verifies AUTH is bounded by LHLO output.
func TestOmittedAUTHCapabilityDisablesPeerAuth(t *testing.T) {
	config := testSessionConfig()
	config.TLSMode = TLSModeImplicit
	config.Capabilities = []string{capabilitySMTPUTF8}

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 SMTPUTF8\r\n")

	harness.write(t, "AUTH PLAIN "+plainPayload(testSubmitterIdentity, testPeerPassword)+"\r\n")
	harness.expectLine(t, "502 5.5.1 AUTH is not available\r\n")
}

// TestOmittedAUTHMechanismCapabilityDisablesMechanism verifies individual AUTH mechanisms are not inferred.
func TestOmittedAUTHMechanismCapabilityDisablesMechanism(t *testing.T) {
	config := testSessionConfig()
	config.TLSMode = TLSModeImplicit
	config.Capabilities = []string{testPlainAuthCapability}

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 AUTH PLAIN\r\n")

	harness.write(t, "AUTH LOGIN\r\n")
	harness.expectLine(t, "535 5.7.8 Unsupported authentication mechanism\r\n")
}

// TestSMTPUTF8CapabilityGatesEnvelopeSyntax verifies Unicode paths require explicit transaction opt-in.
func TestSMTPUTF8CapabilityGatesEnvelopeSyntax(t *testing.T) {
	t.Run("parameter without capability", testSMTPUTF8ParameterWithoutCapability)
	t.Run("unsupported mail parameter", testSMTPUTF8UnsupportedMailParameter)
	t.Run("unicode without mail parameter", testSMTPUTF8UnicodeWithoutMailParameter)
	t.Run("advertised transaction opt-in", testSMTPUTF8AdvertisedTransactionOptIn)
}

// testSMTPUTF8ParameterWithoutCapability verifies explicit opt-in needs advertisement.
func testSMTPUTF8ParameterWithoutCapability(t *testing.T) {
	config := testSessionConfig()
	config.TLSMode = TLSModeImplicit
	config.Capabilities = nil

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250 nauthilus-director\r\n")
	harness.write(t, "MAIL FROM:<sender@example.test> SMTPUTF8\r\n")
	harness.expectLine(t, "501 5.5.4 Invalid MAIL command\r\n")
}

// testSMTPUTF8UnsupportedMailParameter verifies unsupported MAIL parameters fail closed.
func testSMTPUTF8UnsupportedMailParameter(t *testing.T) {
	config := testSessionConfig()
	config.TLSMode = TLSModeImplicit

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.drainLHLO(t)
	harness.write(t, "MAIL FROM:<sender@example.test> BODY=8BITMIME\r\n")
	harness.expectLine(t, "501 5.5.4 Invalid MAIL command\r\n")
	harness.write(t, "MAIL FROM:<sender@example.test>SMTPUTF8\r\n")
	harness.expectLine(t, "501 5.5.4 Invalid MAIL command\r\n")
}

// testSMTPUTF8UnicodeWithoutMailParameter verifies transaction opt-in gates recipients.
func testSMTPUTF8UnicodeWithoutMailParameter(t *testing.T) {
	config := testSessionConfig()
	config.TLSMode = TLSModeImplicit
	config.Capabilities = []string{capabilitySMTPUTF8}

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 SMTPUTF8\r\n")
	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<"+testUnicodeRecipient+">\r\n")
	harness.expectLine(t, "501 5.5.4 Invalid RCPT command\r\n")
}

// testSMTPUTF8AdvertisedTransactionOptIn verifies advertised SMTPUTF8 enables Unicode paths.
func testSMTPUTF8AdvertisedTransactionOptIn(t *testing.T) {
	config := testSessionConfig()
	config.TLSMode = TLSModeImplicit
	config.Capabilities = []string{capabilitySMTPUTF8}

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 SMTPUTF8\r\n")
	harness.write(t, "MAIL FROM:<"+testUnicodeSender+"> SMTPUTF8\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<"+testUnicodeRecipient+">\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
}

// TestRequiredPeerAuthBlocksTransactionCommands verifies submitter auth gates envelope and body commands.
func TestRequiredPeerAuthBlocksTransactionCommands(t *testing.T) {
	for _, command := range []string{
		"MAIL FROM:<sender@example.test>\r\n",
		"RCPT TO:<recipient@example.test>\r\n",
		"DATA\r\n",
		"BDAT 0 LAST\r\n",
	} {
		t.Run(strings.Fields(command)[0], func(t *testing.T) {
			config := testSessionConfig()
			config.TLSMode = TLSModeImplicit
			config.RequirePeerAuth = true
			config.BackendChunkingAllowed = true
			config.Capabilities = []string{testAllAuthCapability, capabilityCHUNKING}

			harness := startLMTPHarness(t, config)
			harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
			harness.write(t, "LHLO submitter.example\r\n")
			harness.drainLHLO(t)
			harness.write(t, command)
			harness.expectLine(t, "530 5.7.0 Authentication required\r\n")
		})
	}
}

// TestSASLPeerAuthUsesSubmitterIdentity verifies recipient values never become credential-auth usernames.
func TestSASLPeerAuthUsesSubmitterIdentity(t *testing.T) {
	authenticator := &recordingAuthenticator{}
	config := testSessionConfig()
	config.TLSMode = TLSModeImplicit
	config.RequirePeerAuth = true
	config.Authenticator = authenticator
	config.Capabilities = []string{testAllAuthCapability}

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 AUTH PLAIN LOGIN XOAUTH2 OAUTHBEARER\r\n")
	harness.write(t, "AUTH PLAIN "+plainPayload(testSubmitterIdentity, testPeerPassword)+"\r\n")
	harness.expectLine(t, "235 2.7.0 Authentication successful\r\n")
	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<mailbox-user@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")

	request := authenticator.singleRequest(t)
	if request.Context.Protocol != protocolLMTP {
		t.Fatalf("protocol = %q, want lmtp", request.Context.Protocol)
	}

	if request.Context.Method != mechanismPlain {
		t.Fatalf("method = %q, want plain", request.Context.Method)
	}

	if request.Context.Username != testSubmitterIdentity {
		t.Fatalf("username = %q, want submitter identity", request.Context.Username)
	}

	if request.Context.Username == "mailbox-user@example.test" {
		t.Fatal("recipient identity was used as peer-auth username")
	}
}

// TestHTTPSASLPeerAuthDoesNotUseNoAuth verifies HTTP credential auth stays separate from lookup mode.
func TestHTTPSASLPeerAuthDoesNotUseNoAuth(t *testing.T) {
	var seenMode string

	var seenUsername string

	authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenMode = r.URL.Query().Get("mode")

		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}

		seenUsername, _ = body["username"].(string)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"account_field":"uid","attributes":{"uid":["` + testSubmitterIdentity + `"]}}`))
	}))
	defer authority.Close()

	client, err := nauthilus.NewHTTPClient(nauthilus.HTTPClientConfig{
		Endpoint: authority.URL,
		Client:   authority.Client(),
	})
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}

	config := testSessionConfig()
	config.TLSMode = TLSModeImplicit
	config.RequirePeerAuth = true
	config.Authenticator = client
	config.Capabilities = []string{"AUTH PLAIN"}
	config.PeerAuthMechanisms = []string{mechanismPlain}

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 AUTH PLAIN\r\n")
	harness.write(t, "AUTH PLAIN "+plainPayload(testSubmitterIdentity, testPeerPassword)+"\r\n")
	harness.expectLine(t, "235 2.7.0 Authentication successful\r\n")

	if seenMode == "no-auth" {
		t.Fatal("HTTP SASL peer auth used mode=no-auth")
	}

	if seenUsername != testSubmitterIdentity {
		t.Fatalf("HTTP username = %q, want submitter identity", seenUsername)
	}
}

// TestVerifiedClientCertRequiresExplicitMTLSPolicy verifies transport certificates are not implicit auth.
func TestVerifiedClientCertRequiresExplicitMTLSPolicy(t *testing.T) {
	config := testMTLSConfig(false)
	harness := startLMTPHarnessWithState(t, config, verifiedTLSState(testMTLSPeerIdentity))
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.drainLHLO(t)
	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "530 5.7.0 Authentication required\r\n")
}

// TestVerifiedClientCertSatisfiesExplicitMTLSPeerAuth verifies verified mTLS can satisfy required peer auth.
func TestVerifiedClientCertSatisfiesExplicitMTLSPeerAuth(t *testing.T) {
	config := testMTLSConfig(true)
	harness := startLMTPHarnessWithState(t, config, verifiedTLSState(testMTLSPeerIdentity))
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.drainLHLO(t)
	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")

	if !harness.session.PeerAuthenticated() {
		t.Fatal("verified explicit mTLS did not satisfy peer auth")
	}

	if harness.session.PeerIdentity() != testMTLSPeerIdentity {
		t.Fatalf("peer identity = %q, want bounded certificate identity", harness.session.PeerIdentity())
	}
}

// TestMTLSPeerIdentityIsBounded verifies certificate-derived identities stay safe and bounded.
func TestMTLSPeerIdentityIsBounded(t *testing.T) {
	rawIdentity := strings.Repeat("a", maxSafePeerIdentityBytes+32) + "\r\nsecret"
	config := testMTLSConfig(true)
	harness := startLMTPHarnessWithState(t, config, verifiedTLSState(rawIdentity))
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")

	identity := harness.session.PeerIdentity()
	if len(identity) > maxSafePeerIdentityBytes {
		t.Fatalf("identity length = %d, want <= %d", len(identity), maxSafePeerIdentityBytes)
	}

	if strings.ContainsAny(identity, "\r\n") {
		t.Fatalf("identity contains controls: %q", identity)
	}
}

// TestAUTHRejectsMalformedOrOversizedInputsWithoutLeakingSecrets verifies parser failures stay secret-safe.
func TestAUTHRejectsMalformedOrOversizedInputsWithoutLeakingSecrets(t *testing.T) {
	mechanism, err := newMechanismIdentity(mechanismXOAUTH2)
	if err != nil {
		t.Fatalf("newMechanismIdentity: %v", err)
	}

	_, err = parseSASLCredentials(mechanism, xoauth2Payload(testSubmitterIdentity, testPeerToken), 256, 8)
	if !errors.Is(err, ErrCredentialTooLarge) {
		t.Fatalf("error = %v, want credential too large", err)
	}

	assertNoSecretLeak(t, err.Error(), testPeerToken)

	_, err = parseSASLCredentials(mechanism, "not-base64!", 256, 8)
	if !errors.Is(err, ErrCredentialRejected) {
		t.Fatalf("error = %v, want credential rejected", err)
	}

	assertNoSecretLeak(t, err.Error(), "not-base64!")
}

// TestBDATRejectsInvalidStateAndMalformedSizes verifies BDAT fails closed before streaming.
func TestBDATRejectsInvalidStateAndMalformedSizes(t *testing.T) {
	t.Run("not advertised", func(t *testing.T) {
		harness := startLMTPHarness(t, testSessionConfig())
		harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
		harness.write(t, "LHLO submitter.example\r\n")
		harness.drainLHLO(t)
		harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
		harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
		harness.write(t, "RCPT TO:<recipient@example.test>\r\n")
		harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
		harness.write(t, "BDAT 0 LAST\r\n")
		harness.expectLine(t, "502 5.5.1 BDAT is not available\r\n")
	})

	t.Run("missing recipient", func(t *testing.T) {
		config := testChunkingConfig()
		harness := startLMTPHarness(t, config)
		harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
		harness.write(t, "LHLO submitter.example\r\n")
		harness.expectLine(t, "250-nauthilus-director\r\n")
		harness.expectLine(t, "250 CHUNKING\r\n")
		harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
		harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
		harness.write(t, "BDAT 0 LAST\r\n")
		harness.expectLine(t, "503 5.5.1 Need recipient before message body\r\n")
	})

	t.Run("malformed size", func(t *testing.T) {
		config := testChunkingConfig()
		harness := startLMTPHarness(t, config)
		harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
		harness.write(t, "LHLO submitter.example\r\n")
		harness.expectLine(t, "250-nauthilus-director\r\n")
		harness.expectLine(t, "250 CHUNKING\r\n")
		harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
		harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
		harness.write(t, "RCPT TO:<recipient@example.test>\r\n")
		harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
		harness.write(t, "BDAT nope LAST\r\n")
		harness.expectLine(t, "501 5.5.4 Invalid BDAT command\r\n")
	})
}

// TestBDATStreamsExactChunkSizesAndHonorsLAST verifies byte-counted chunks are not parsed as commands.
func TestBDATStreamsExactChunkSizesAndHonorsLAST(t *testing.T) {
	sink := &recordingMessageSink{}
	config := testChunkingConfig()
	config.MessageSink = sink

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 CHUNKING\r\n")
	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<recipient@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "BDAT 5\r\nhelloNOOP\r\n")
	harness.expectLine(t, "250 2.0.0 BDAT chunk accepted\r\n")
	harness.expectLine(t, "250 2.0.0 OK\r\n")
	harness.write(t, "BDAT 0 LAST\r\n")
	harness.expectLine(t, "250 2.0.0 Message accepted\r\n")

	if got := sink.bodyString(); got != "hello" {
		t.Fatalf("BDAT body = %q, want exact chunk", got)
	}

	if sink.finishCount() != 1 {
		t.Fatalf("finish count = %d, want 1", sink.finishCount())
	}
}

// TestDATATerminatorStreamsIncrementally verifies DATA handling avoids whole-message buffering.
func TestDATATerminatorStreamsIncrementally(t *testing.T) {
	sink := &recordingMessageSink{}
	config := testSessionConfig()
	config.MessageSink = sink

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.drainLHLO(t)
	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<recipient@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "DATA\r\n")
	harness.expectLine(t, "354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	harness.write(t, "line-one\r\n..line-two\r\n.\r\n")
	harness.expectLine(t, "250 2.0.0 Message accepted\r\n")

	if got := sink.bodyString(); got != testDataBody {
		t.Fatalf("DATA body = %q, want dot-unescaped lines", got)
	}

	if sink.maxWriteBytes() >= len(testDataBody) {
		t.Fatalf("max write size = %d, DATA appears whole-buffered", sink.maxWriteBytes())
	}
}

// TestRecipientPlacementUsesIdentityRoutingAndPreservesWirePath verifies recipient placement facts.
func TestRecipientPlacementUsesIdentityRoutingAndPreservesWirePath(t *testing.T) {
	identity := &recordingIdentityLookuper{results: map[string]nauthilus.AuthResult{
		testRecipientLookup: {
			Decision: nauthilus.DecisionAuthenticated,
			Account:  "Canonical@EXAMPLE.TEST",
			Attributes: map[string][]string{
				testRoutingShardAttr: {testPlacementShardA},
				testTenantAttribute:  {testPlacementTenant},
			},
		},
	}}
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{}
	sink := &recordingMessageSink{}
	config := placementSessionConfig(identity, resolver, store, selector)
	config.MessageSink = sink

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.drainLHLO(t)
	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<Local@EXAMPLE.com>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "DATA\r\n")
	harness.expectLine(t, "354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	harness.write(t, "line-one\r\n.\r\n")
	harness.expectLine(t, "250 2.0.0 Message accepted\r\n")

	assertRecipientLookupContext(t, identity.singleLookup(t))

	assertRecipientRoutingRequest(t, resolver.singleRequest(t))
	assertRecipientHoldOpen(t, store.singleOpen(t))
	assertRecipientSelection(t, selector.firstRequest(t))
	assertSingleWireRecipient(t, sink.singleSnapshot(t))

	store.assertClosed(t, 1)
}

// TestRecipientPlacementDifferentBackendTempfailsBeforeData verifies same-backend-only acceptance.
func TestRecipientPlacementDifferentBackendTempfailsBeforeData(t *testing.T) {
	identity := &recordingIdentityLookuper{results: map[string]nauthilus.AuthResult{
		testRecipientFirst: {
			Decision:   nauthilus.DecisionAuthenticated,
			Account:    testRecipientFirst,
			Attributes: map[string][]string{testRoutingShardAttr: {testPlacementShardA}, testTenantAttribute: {testPlacementTenant}},
		},
		testRecipientSecond: {
			Decision:   nauthilus.DecisionAuthenticated,
			Account:    testRecipientSecond,
			Attributes: map[string][]string{testRoutingShardAttr: {testPlacementShardB}, testTenantAttribute: {testPlacementTenant}},
		},
	}}
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{backendForShard: map[string]string{testPlacementShardB: "mailstore-b-lmtp"}}
	config := placementSessionConfig(identity, resolver, store, selector)

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.drainLHLO(t)
	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<first@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "RCPT TO:<second@example.test>\r\n")
	harness.expectLine(t, "451 4.3.2 Recipient must be retried separately\r\n")
	harness.write(t, "DATA\r\n")
	harness.expectLine(t, "354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	harness.write(t, "line-one\r\n.\r\n")
	harness.expectLine(t, "250 2.0.0 Message accepted\r\n")

	store.assertOpened(t, 2)
	store.assertAttached(t, 1)
	store.assertClosed(t, 2)
}

// TestRecipientBackendAccountingCountsOneBackendTransaction verifies multi-recipient delivery uses one backend count.
func TestRecipientBackendAccountingCountsOneBackendTransaction(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{
		testRecipientFirst:  testPlacementShardA,
		testRecipientSecond: testPlacementShardA,
	})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{}
	config := placementSessionConfig(identity, resolver, store, selector)

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.drainLHLO(t)
	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<first@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "RCPT TO:<second@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "DATA\r\n")
	harness.expectLine(t, "354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	harness.write(t, "line-one\r\n.\r\n")
	harness.expectLine(t, "250 2.0.0 Message accepted\r\n")

	store.assertOpened(t, 2)
	store.assertAttached(t, 1)
	store.assertClosed(t, 2)
}

// TestRecipientDeliveryHoldHeartbeatsAndClosesOnReset verifies hold lifecycle boundaries.
func TestRecipientDeliveryHoldHeartbeatsAndClosesOnReset(t *testing.T) {
	identity := &recordingIdentityLookuper{results: map[string]nauthilus.AuthResult{
		testRecipientSingle: {
			Decision:   nauthilus.DecisionAuthenticated,
			Account:    testRecipientSingle,
			Attributes: map[string][]string{testRoutingShardAttr: {testPlacementShardA}, testTenantAttribute: {testPlacementTenant}},
		},
	}}
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{}
	config := placementSessionConfig(identity, resolver, store, selector)
	config.SessionLeaseTTL = 20 * time.Millisecond

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.drainLHLO(t)
	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<recipient@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")

	store.waitForHeartbeat(t)

	harness.write(t, "RSET\r\n")
	harness.expectLine(t, "250 2.0.0 Transaction reset\r\n")
	store.assertClosed(t, 1)
}

// TestBackendTransactionForwardsEnvelopeAndDATAStatuses verifies DATA forwarding and ordered final replies.
func TestBackendTransactionForwardsEnvelopeAndDATAStatuses(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{
		testRecipientFirst:  testPlacementShardA,
		testRecipientSecond: testPlacementShardA,
		testRecipientThird:  testPlacementShardA,
	})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{}
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := greetTransactionBackend(t, conn)
		expectLMTPBackendLine(t, reader, "MAIL FROM:<sender@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.0 sender ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<first@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.5 first ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<second@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.5 second ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<"+testRecipientThird+">")
		writeLMTPBackendLine(t, conn, "250 2.1.5 third ok")
		expectLMTPBackendLine(t, reader, "DATA")
		writeLMTPBackendLine(t, conn, "354 2.0.0 send data")
		expectLMTPBackendLine(t, reader, "line-one")
		expectLMTPBackendLine(t, reader, "..line-two")
		expectLMTPBackendLine(t, reader, ".")
		writeLMTPBackendLine(t, conn, "250 2.1.5 delivered")
		writeLMTPBackendLine(t, conn, "451 4.2.0 temporary policy detail first@example.test")
		writeLMTPBackendLine(t, conn, "552 5.2.2 quota detail second@example.test")
	})
	config := backendForwardingSessionConfig(identity, resolver, store, selector, dialer)

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.drainLHLO(t)
	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<first@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "RCPT TO:<second@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "RCPT TO:<"+testRecipientThird+">\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "DATA\r\n")
	harness.expectLine(t, "354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	harness.write(t, "line-one\r\n..line-two\r\n.\r\n")
	harness.expectLine(t, "250 2.1.5 Message accepted\r\n")
	harness.expectLine(t, "451 4.2.0 Message delivery temporarily failed\r\n")
	harness.expectLine(t, "552 5.2.2 Message delivery permanently failed\r\n")

	store.assertClosed(t, 3)
	dialer.Wait(t)
}

// TestBackendRCPTRejectionIsNotTrackedForFinalStatuses verifies rejected RCPTs do not receive DATA replies.
func TestBackendRCPTRejectionIsNotTrackedForFinalStatuses(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{
		testRecipientFirst:  testPlacementShardA,
		testRecipientSecond: testPlacementShardA,
	})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{}
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := greetTransactionBackend(t, conn)
		expectLMTPBackendLine(t, reader, "MAIL FROM:<sender@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.0 sender ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<first@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.5 first ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<second@example.test>")
		writeLMTPBackendLine(t, conn, "550 5.1.1 rejected second@example.test")
		expectLMTPBackendLine(t, reader, "DATA")
		writeLMTPBackendLine(t, conn, "354 2.0.0 send data")
		expectLMTPBackendLine(t, reader, "body")
		expectLMTPBackendLine(t, reader, ".")
		writeLMTPBackendLine(t, conn, "250 2.1.5 delivered")
	})
	config := backendForwardingSessionConfig(identity, resolver, store, selector, dialer)

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.drainLHLO(t)
	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<first@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "RCPT TO:<second@example.test>\r\n")
	harness.expectLine(t, "550 5.1.1 Recipient rejected by backend\r\n")
	harness.write(t, "DATA\r\n")
	harness.expectLine(t, "354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	harness.write(t, "body\r\n.\r\n")
	harness.expectLine(t, "250 2.1.5 Message accepted\r\n")
	harness.write(t, "NOOP\r\n")
	harness.expectLine(t, "250 2.0.0 OK\r\n")

	store.assertClosed(t, 2)
	dialer.Wait(t)
}

// TestDifferentBackendRecipientIsNotForwardedBeforeBDAT verifies same-backend-only enforcement for BDAT.
func TestDifferentBackendRecipientIsNotForwardedBeforeBDAT(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{
		testRecipientFirst:  testPlacementShardA,
		testRecipientSecond: testPlacementShardB,
	})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{backendForShard: map[string]string{testPlacementShardB: "mailstore-b-lmtp"}}
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := greetTransactionBackend(t, conn)
		expectLMTPBackendLine(t, reader, "MAIL FROM:<sender@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.0 sender ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<first@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.5 first ok")
		expectLMTPBackendLine(t, reader, "BDAT 0 LAST")
		writeLMTPBackendLine(t, conn, "250 2.1.5 delivered")
	})
	config := backendForwardingSessionConfig(identity, resolver, store, selector, dialer)
	config.Capabilities = []string{capabilityCHUNKING}
	config.BackendChunkingAllowed = true

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 CHUNKING\r\n")
	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<first@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "RCPT TO:<second@example.test>\r\n")
	harness.expectLine(t, "451 4.3.2 Recipient must be retried separately\r\n")
	harness.write(t, "BDAT 0 LAST\r\n")
	harness.expectLine(t, "250 2.1.5 Message accepted\r\n")

	store.assertClosed(t, 2)
	dialer.Wait(t)
}

// TestBackendBDATFinalRepliesMatchRecipientOrder verifies BDAT chunks and mixed final replies.
func TestBackendBDATFinalRepliesMatchRecipientOrder(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{
		testRecipientFirst:  testPlacementShardA,
		testRecipientSecond: testPlacementShardA,
		testRecipientThird:  testPlacementShardA,
	})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{}
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := greetTransactionBackend(t, conn)
		expectLMTPBackendLine(t, reader, "MAIL FROM:<sender@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.0 sender ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<first@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.5 first ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<second@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.5 second ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<"+testRecipientThird+">")
		writeLMTPBackendLine(t, conn, "250 2.1.5 third ok")
		expectLMTPBackendLine(t, reader, "BDAT 5")
		expectLMTPBackendBytes(t, reader, "hello")
		writeLMTPBackendLine(t, conn, "250 2.0.0 chunk ok")
		expectLMTPBackendLine(t, reader, "BDAT 0 LAST")
		writeLMTPBackendLine(t, conn, "250 2.1.5 delivered")
		writeLMTPBackendLine(t, conn, "451 4.2.0 temporary policy detail")
		writeLMTPBackendLine(t, conn, "552 5.2.2 quota detail")
	})
	config := backendForwardingSessionConfig(identity, resolver, store, selector, dialer)
	config.Capabilities = []string{capabilityCHUNKING}
	config.BackendChunkingAllowed = true

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 CHUNKING\r\n")
	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<first@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "RCPT TO:<second@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "RCPT TO:<"+testRecipientThird+">\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "BDAT 5\r\nhello")
	harness.expectLine(t, "250 2.0.0 Message accepted\r\n")
	harness.write(t, "BDAT 0 LAST\r\n")
	harness.expectLine(t, "250 2.1.5 Message accepted\r\n")
	harness.expectLine(t, "451 4.2.0 Message delivery temporarily failed\r\n")
	harness.expectLine(t, "552 5.2.2 Message delivery permanently failed\r\n")

	store.assertClosed(t, 3)
	dialer.Wait(t)
}

// TestMidDATAFailureMapsUnknownRecipientsToTemporaryFailure verifies opaque stream failure handling.
func TestMidDATAFailureMapsUnknownRecipientsToTemporaryFailure(t *testing.T) {
	secretBody := "opaque-secret-body"
	identity := identityLookuperForRecipients(map[string]string{
		testRecipientFirst:  testPlacementShardA,
		testRecipientSecond: testPlacementShardA,
	})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{}
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := greetTransactionBackend(t, conn)
		expectLMTPBackendLine(t, reader, "MAIL FROM:<sender@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.0 sender ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<first@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.5 first ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<second@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.5 second ok")
		expectLMTPBackendLine(t, reader, "DATA")
		writeLMTPBackendLine(t, conn, "354 2.0.0 send data")
		expectLMTPBackendLine(t, reader, secretBody)
		expectLMTPBackendLine(t, reader, ".")
	})
	config := backendForwardingSessionConfig(identity, resolver, store, selector, dialer)

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.drainLHLO(t)
	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<first@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "RCPT TO:<second@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "DATA\r\n")
	harness.expectLine(t, "354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	harness.write(t, secretBody+"\r\n.\r\n")
	first := harness.readLine(t)
	second := harness.readLine(t)
	assertNoSecretLeak(t, first+second, secretBody)

	if first != testTemporaryDelivery || second != testTemporaryDelivery {
		t.Fatalf("failure statuses = %q %q, want two temporary failures", first, second)
	}

	store.assertClosed(t, 2)
	dialer.Wait(t)
}

// TestMidBDATFailureMapsUnknownRecipientsToTemporaryFailure verifies unknown BDAT LAST outcomes tempfail.
func TestMidBDATFailureMapsUnknownRecipientsToTemporaryFailure(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{
		testRecipientFirst:  testPlacementShardA,
		testRecipientSecond: testPlacementShardA,
	})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{}
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := greetTransactionBackend(t, conn)
		expectLMTPBackendLine(t, reader, "MAIL FROM:<sender@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.0 sender ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<first@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.5 first ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<second@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.5 second ok")
		expectLMTPBackendLine(t, reader, "BDAT 6 LAST")
		expectLMTPBackendBytes(t, reader, "secret")
	})
	config := backendForwardingSessionConfig(identity, resolver, store, selector, dialer)
	config.Capabilities = []string{capabilityCHUNKING}
	config.BackendChunkingAllowed = true

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 CHUNKING\r\n")
	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<first@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "RCPT TO:<second@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "BDAT 6 LAST\r\nsecret")
	harness.expectLine(t, testTemporaryDelivery)
	harness.expectLine(t, testTemporaryDelivery)

	store.assertClosed(t, 2)
	dialer.Wait(t)
}

// TestRSETClearsBackendTransactionState verifies frontend reset propagates to backend envelope state.
func TestRSETClearsBackendTransactionState(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{testRecipientSingle: testPlacementShardA})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{}
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := greetTransactionBackend(t, conn)
		expectLMTPBackendLine(t, reader, "MAIL FROM:<sender@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.0 sender ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<recipient@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.5 recipient ok")
		expectLMTPBackendLine(t, reader, "RSET")
		writeLMTPBackendLine(t, conn, "250 2.0.0 reset")
	})
	config := backendForwardingSessionConfig(identity, resolver, store, selector, dialer)

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.drainLHLO(t)
	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<recipient@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "RSET\r\n")
	harness.expectLine(t, "250 2.0.0 Transaction reset\r\n")

	store.assertClosed(t, 1)
	dialer.Wait(t)
}

// assertRecipientLookupContext verifies recipient lookup uses the normalized envelope value.
func assertRecipientLookupContext(t *testing.T, lookup nauthilus.IdentityLookupRequest) {
	t.Helper()

	if lookup.Context.Username != testRecipientLookup || lookup.Context.Protocol != protocolLMTP || lookup.Context.Method != recipientLookupMethod {
		t.Fatalf("lookup context = %#v, want normalized recipient lookup", lookup.Context)
	}
}

// assertRecipientRoutingRequest verifies routing receives canonical account facts.
func assertRecipientRoutingRequest(t *testing.T, route routing.RoutingRequest) {
	t.Helper()

	if route.Protocol != protocolLMTP || route.ListenerName != testPlacementListener || route.ServiceName != testPlacementService || route.BackendPool != testPlacementPool {
		t.Fatalf("routing request = %#v, want LMTP listener context", route)
	}

	if route.NormalizedAccount != testPlacementAccount || route.LoginName != testRecipientLookup {
		t.Fatalf("routing request = %#v, want canonical account and lookup identity split", route)
	}
}

// assertRecipientHoldOpen verifies the delivery hold is keyed by canonical identity.
func assertRecipientHoldOpen(t *testing.T, open state.SessionRecord) {
	t.Helper()

	if open.HolderKind != state.HolderKindDelivery || open.Protocol != protocolLMTP || open.Key.AccountKey != testPlacementAccount || open.Key.Tenant != testPlacementTenant {
		t.Fatalf("opened hold = %#v, want delivery hold for canonical account", open)
	}
}

// assertRecipientSelection verifies backend selection uses canonical account input.
func assertRecipientSelection(t *testing.T, selection backend.SelectionRequest) {
	t.Helper()

	if selection.Protocol != protocolLMTP || selection.BackendPool != testPlacementPool || selection.AccountKey != testPlacementAccount {
		t.Fatalf("selection request = %#v, want LMTP canonical account", selection)
	}
}

// assertSingleWireRecipient verifies backend-facing state keeps the original path.
func assertSingleWireRecipient(t *testing.T, snapshot TransactionSnapshot) {
	t.Helper()

	if len(snapshot.Recipients) != 1 || snapshot.Recipients[0].WirePath != "<Local@EXAMPLE.com>" {
		t.Fatalf("message snapshot = %#v, want original wire recipient", snapshot)
	}
}

// testSessionConfig returns a minimal LMTP session configuration.
func testSessionConfig() SessionConfig {
	return SessionConfig{
		ListenerName:        protocolLMTP,
		AuthorityName:       "default",
		AuthorityTransport:  "http",
		ServiceName:         protocolLMTP,
		Network:             "tcp",
		BackendPool:         testPlacementPool,
		TLSMode:             TLSModeStartTLS,
		Capabilities:        []string{"SMTPUTF8", "STARTTLS", testAllAuthCapability},
		PreauthTimeout:      time.Second,
		AuthTimeout:         time.Second,
		MaxLineBytes:        8192,
		MaxBearerTokenBytes: 64,
		PeerAuthMechanisms:  []string{mechanismPlain, mechanismLogin, mechanismXOAUTH2, mechanismOAuthBearer},
	}
}

// testChunkingConfig returns a session config where CHUNKING is safe to advertise for tests.
func testChunkingConfig() SessionConfig {
	config := testSessionConfig()
	config.TLSMode = TLSModeImplicit
	config.Capabilities = []string{"CHUNKING"}
	config.BackendChunkingAllowed = true

	return config
}

// testMTLSConfig returns a required-peer-auth config for certificate-auth tests.
func testMTLSConfig(satisfiesRequired bool) SessionConfig {
	config := testSessionConfig()
	config.TLSMode = TLSModeImplicit
	config.RequirePeerAuth = true
	config.RequireTLSClientCert = true
	config.MTLSPeerAuth = MTLSPeerAuthConfig{
		SatisfiesRequired: satisfiesRequired,
		IdentitySource:    identitySourceSubjectCommonName,
	}

	return config
}

// placementSessionConfig returns an LMTP config with production placement collaborators.
func placementSessionConfig(
	identity nauthilus.IdentityLookuper,
	resolver routing.RoutingResolver,
	store state.SessionStore,
	selector backend.Selector,
) SessionConfig {
	config := testSessionConfig()
	config.TLSMode = TLSModeImplicit
	config.Capabilities = []string{"SMTPUTF8"}
	config.ListenerName = testPlacementListener
	config.ServiceName = testPlacementService
	config.BackendPool = testPlacementPool
	config.DirectorInstanceID = "director-test"
	config.DefaultTenant = "default"
	config.DefaultShard = "mailstore-a"
	config.SessionLeaseTTL = time.Second
	config.SessionIdleGrace = time.Second
	config.RecipientLookupRequired = true
	config.IdentityLookuper = identity
	config.RoutingResolver = resolver
	config.SessionStore = store
	config.BackendSelector = selector

	return config
}

// backendForwardingSessionConfig returns placement config with a real backend connector seam.
func backendForwardingSessionConfig(
	identity nauthilus.IdentityLookuper,
	resolver routing.RoutingResolver,
	store state.SessionStore,
	selector backend.Selector,
	dialer BackendDialer,
) SessionConfig {
	config := placementSessionConfig(identity, resolver, store, selector)
	config.BackendConnector = NewTCPBackendConnector(dialer)
	config.BackendConnectTimeout = time.Second

	return config
}

// identityLookuperForRecipients creates deterministic successful recipient identity results.
func identityLookuperForRecipients(shards map[string]string) *recordingIdentityLookuper {
	results := make(map[string]nauthilus.AuthResult, len(shards))
	for recipient, shard := range shards {
		results[recipient] = nauthilus.AuthResult{
			Decision: nauthilus.DecisionAuthenticated,
			Account:  recipient,
			Attributes: map[string][]string{
				testRoutingShardAttr: {shard},
				testTenantAttribute:  {testPlacementTenant},
			},
		}
	}

	return &recordingIdentityLookuper{results: results}
}

// greetTransactionBackend runs the common backend greeting and LHLO handshake.
func greetTransactionBackend(t *testing.T, conn net.Conn) *bufio.Reader {
	t.Helper()

	reader := bufio.NewReader(conn)
	writeLMTPBackendLine(t, conn, "220 backend ready")
	expectLMTPBackendLine(t, reader, "LHLO "+backendLHLOName)
	writeLMTPBackendLine(t, conn, "250 mailstore")

	return reader
}

// expectLMTPBackendBytes reads exact opaque backend payload bytes.
func expectLMTPBackendBytes(t *testing.T, reader *bufio.Reader, want string) {
	t.Helper()

	payload := make([]byte, len(want))
	if _, err := io.ReadFull(reader, payload); err != nil {
		t.Fatalf("read backend payload: %v", err)
	}

	if string(payload) != want {
		t.Fatalf("backend payload = %q, want %q", string(payload), want)
	}
}

type lmtpHarness struct {
	session *Session
	client  net.Conn
	reader  *bufio.Reader
	cancel  context.CancelFunc
	done    chan error
}

// startLMTPHarness starts a session over an in-memory connection.
func startLMTPHarness(t *testing.T, config SessionConfig) *lmtpHarness {
	t.Helper()

	return startLMTPHarnessWithServerConn(t, config, nil)
}

// startLMTPHarnessWithState starts a session over a connection exposing TLS state.
func startLMTPHarnessWithState(t *testing.T, config SessionConfig, state tls.ConnectionState) *lmtpHarness {
	t.Helper()

	return startLMTPHarnessWithServerConn(t, config, func(conn net.Conn) net.Conn {
		return stateConn{Conn: conn, state: state}
	})
}

// startLMTPHarnessWithServerConn starts a session with an optional server-side connection wrapper.
func startLMTPHarnessWithServerConn(
	t *testing.T,
	config SessionConfig,
	wrap func(net.Conn) net.Conn,
) *lmtpHarness {
	t.Helper()

	server, client := net.Pipe()
	if wrap != nil {
		server = wrap(server)
	}

	session, err := NewSession(config, server)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)

	go func() {
		done <- session.Serve(ctx)
	}()

	harness := &lmtpHarness{
		session: session,
		client:  client,
		reader:  bufio.NewReader(client),
		cancel:  cancel,
		done:    done,
	}

	t.Cleanup(func() {
		cancel()

		_ = client.Close()

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("LMTP session did not exit")
		}
	})

	return harness
}

// write sends raw frontend bytes to the session.
func (h *lmtpHarness) write(t *testing.T, value string) {
	t.Helper()

	if _, err := h.client.Write([]byte(value)); err != nil {
		t.Fatalf("write %q: %v", value, err)
	}
}

// expectLine reads one response line and compares it exactly.
func (h *lmtpHarness) expectLine(t *testing.T, expected string) {
	t.Helper()

	line := h.readLine(t)

	if line != expected {
		t.Fatalf("line = %q, want %q", line, expected)
	}
}

// readLine reads one response line from the frontend side.
func (h *lmtpHarness) readLine(t *testing.T) string {
	t.Helper()

	line, err := h.reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	return line
}

// drainLHLO reads a complete LHLO response with one or more lines.
func (h *lmtpHarness) drainLHLO(t *testing.T) {
	t.Helper()

	for {
		line, err := h.reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read LHLO line: %v", err)
		}

		if len(line) >= 4 && line[3] == ' ' {
			return
		}
	}
}

type stateConn struct {
	net.Conn
	state tls.ConnectionState
}

// ConnectionState returns fixed TLS metadata for mTLS unit tests.
func (c stateConn) ConnectionState() tls.ConnectionState {
	return c.state
}

// verifiedTLSState returns a verified TLS state carrying one peer certificate.
func verifiedTLSState(commonName string) tls.ConnectionState {
	cert := &x509.Certificate{
		Subject: pkix.Name{CommonName: commonName},
	}

	return tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   [][]*x509.Certificate{{cert}},
	}
}

type recordingIdentityLookuper struct {
	mu       sync.Mutex
	requests []nauthilus.IdentityLookupRequest
	results  map[string]nauthilus.AuthResult
	err      error
}

// LookupIdentity records recipient identity lookup input and returns a configured result.
func (l *recordingIdentityLookuper) LookupIdentity(_ context.Context, request nauthilus.IdentityLookupRequest) (nauthilus.AuthResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.requests = append(l.requests, request)
	if l.err != nil {
		return nauthilus.AuthResult{Decision: nauthilus.DecisionTemporaryFailure}, l.err
	}

	if result, ok := l.results[request.Context.Username]; ok {
		return result, nil
	}

	return nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: request.Context.Username}, nil
}

// singleLookup returns the only recorded identity lookup request.
func (l *recordingIdentityLookuper) singleLookup(t *testing.T) nauthilus.IdentityLookupRequest {
	t.Helper()

	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.requests) != 1 {
		t.Fatalf("lookup requests = %d, want 1", len(l.requests))
	}

	return l.requests[0]
}

type recordingRoutingResolver struct {
	mu       sync.Mutex
	requests []routing.RoutingRequest
}

// Resolve records routing input and returns identity-derived logical facts.
func (r *recordingRoutingResolver) Resolve(_ context.Context, request routing.RoutingRequest) (routing.RoutingResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.requests = append(r.requests, request)

	tenant := firstAttribute(request.AuthAttributes, testTenantAttribute)
	if tenant == "" {
		tenant = request.Tenant
	}

	shard := firstAttribute(request.AuthAttributes, testRoutingShardAttr)
	if shard == "" {
		shard = testPlacementShardA
	}

	return routing.RoutingResult{
		AccountKey:    normalizedAccount(request.NormalizedAccount),
		Tenant:        tenant,
		ShardTag:      shard,
		RoutingSource: routing.SourceAuthAttribute,
		Sticky:        true,
		Attributes:    cloneStringSlices(request.AuthAttributes),
	}, nil
}

// singleRequest returns the only recorded routing request.
func (r *recordingRoutingResolver) singleRequest(t *testing.T) routing.RoutingRequest {
	t.Helper()

	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.requests) != 1 {
		t.Fatalf("routing requests = %d, want 1", len(r.requests))
	}

	return r.requests[0]
}

type recordingDeliveryStore struct {
	mu           sync.Mutex
	opens        []state.SessionRecord
	reservations []state.BackendReservationRequest
	attachments  []state.SessionBackendAttachment
	heartbeats   int
	closes       []string
}

// OpenSession records a delivery hold and returns an active affinity record.
func (s *recordingDeliveryStore) OpenSession(_ context.Context, record state.SessionRecord) (state.AffinityRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.opens = append(s.opens, record)

	return state.AffinityRecord{
		Key:                record.Key,
		ShardTag:           record.ShardTag,
		Status:             deliveryStatusCreated,
		Present:            true,
		ActiveSessionCount: 1,
	}, nil
}

// ReserveBackendCapacity records backend reservation for a delivery hold.
func (s *recordingDeliveryStore) ReserveBackendCapacity(
	_ context.Context,
	request state.BackendReservationRequest,
) (state.BackendReservationRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.reservations = append(s.reservations, request)

	return state.BackendReservationRecord{
		Status:             "reserved",
		BackendIdentifier:  request.BackendIdentifier,
		ReservationID:      request.ReservationID,
		BackendActiveCount: 1,
		LeaseExpiresAt:     time.Now().Add(request.LeaseTTL),
	}, nil
}

// ReleaseBackendReservation records reservation rollback for a delivery hold.
func (s *recordingDeliveryStore) ReleaseBackendReservation(
	context.Context,
	state.BackendReservationReleaseRequest,
) (state.BackendReservationRecord, error) {
	return state.BackendReservationRecord{Status: "released", RepairedCount: 1}, nil
}

// ReapBackendReservations is unused by LMTP placement tests.
func (s *recordingDeliveryStore) ReapBackendReservations(
	context.Context,
	state.BackendReservationReapRequest,
) (state.BackendReservationRecord, error) {
	return state.BackendReservationRecord{}, nil
}

// AttachSelectedBackend records selected backend attachment.
func (s *recordingDeliveryStore) AttachSelectedBackend(_ context.Context, attachment state.SessionBackendAttachment) (state.SessionBackendRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.attachments = append(s.attachments, attachment)

	return state.SessionBackendRecord{
		Status:             "attached",
		BackendIdentifier:  attachment.BackendIdentifier,
		ReservationID:      attachment.ReservationID,
		BackendActiveCount: 1,
	}, nil
}

// HeartbeatSession records delivery lease refreshes.
func (s *recordingDeliveryStore) HeartbeatSession(_ context.Context, _ state.AffinityKey, _ string, _ time.Duration) (state.AffinityRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.heartbeats++

	return state.AffinityRecord{Present: true, Status: "heartbeat"}, nil
}

// CloseSession records delivery hold release.
func (s *recordingDeliveryStore) CloseSession(_ context.Context, _ state.AffinityKey, sessionID string) (state.AffinityRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.closes = append(s.closes, sessionID)

	return state.AffinityRecord{Present: true, Status: "closed"}, nil
}

// singleOpen returns the only recorded session-open call.
func (s *recordingDeliveryStore) singleOpen(t *testing.T) state.SessionRecord {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.opens) != 1 {
		t.Fatalf("open calls = %d, want 1", len(s.opens))
	}

	return s.opens[0]
}

// assertOpened verifies the number of opened delivery holds.
func (s *recordingDeliveryStore) assertOpened(t *testing.T, want int) {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.opens) != want {
		t.Fatalf("open calls = %d, want %d", len(s.opens), want)
	}
}

// assertAttached verifies the number of backend active-use accounting attachments.
func (s *recordingDeliveryStore) assertAttached(t *testing.T, want int) {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.attachments) != want {
		t.Fatalf("attachment calls = %d, want %d", len(s.attachments), want)
	}
}

// assertClosed verifies the number of closed delivery holds.
func (s *recordingDeliveryStore) assertClosed(t *testing.T, want int) {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.closes) != want {
		t.Fatalf("close calls = %d, want %d", len(s.closes), want)
	}
}

// waitForHeartbeat waits until the delivery hold heartbeat loop refreshes once.
func (s *recordingDeliveryStore) waitForHeartbeat(t *testing.T) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		heartbeats := s.heartbeats
		s.mu.Unlock()

		if heartbeats > 0 {
			return
		}

		time.Sleep(5 * time.Millisecond)
	}

	t.Fatal("delivery hold heartbeat did not run")
}

type recordingBackendSelector struct {
	mu              sync.Mutex
	requests        []backend.SelectionRequest
	backendForShard map[string]string
}

// Select records backend selection and returns a deterministic LMTP backend.
func (s *recordingBackendSelector) Select(_ context.Context, request backend.SelectionRequest) (backend.SelectionResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.requests = append(s.requests, request)

	identifier := "mailstore-a-lmtp"
	if request.PinnedBackendIdentifier != "" {
		identifier = request.PinnedBackendIdentifier
	} else if s.backendForShard != nil && s.backendForShard[request.ShardTag] != "" {
		identifier = s.backendForShard[request.ShardTag]
	}

	selected := backend.Backend{
		Identifier:     identifier,
		Protocol:       request.Protocol,
		BackendPool:    request.BackendPool,
		ShardTag:       request.ShardTag,
		Address:        testBackendTLSHostTarget,
		TLS:            backend.TLSConfig{Mode: backendTLSPlaintext, MinTLSVersion: backendTLSMinDefault},
		Auth:           backend.AuthConfig{Mode: backendAuthModeNone},
		MaxConnections: 100,
	}

	return backend.SelectionResult{
		Backend: selected,
		EffectiveBackend: backend.EffectiveBackendState{
			Backend:           selected,
			Identifier:        identifier,
			Protocol:          request.Protocol,
			BackendPool:       request.BackendPool,
			EffectiveShardTag: request.ShardTag,
			MaxConnections:    100,
			AllowsNewSessions: true,
			AllowsActivePins:  true,
		},
		Reason:         "test",
		ActiveAffinity: request.ActiveAffinity,
	}, nil
}

// firstRequest returns the first selector request.
func (s *recordingBackendSelector) firstRequest(t *testing.T) backend.SelectionRequest {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.requests) == 0 {
		t.Fatal("selector was not called")
	}

	return s.requests[0]
}

type recordingAuthenticator struct {
	mu       sync.Mutex
	requests []nauthilus.AuthRequest
	result   nauthilus.AuthResult
	err      error
}

// Authenticate records the request and returns a deterministic success by default.
func (a *recordingAuthenticator) Authenticate(_ context.Context, request nauthilus.AuthRequest) (nauthilus.AuthResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.requests = append(a.requests, request)
	if a.err != nil {
		return nauthilus.AuthResult{Decision: nauthilus.DecisionTemporaryFailure}, a.err
	}

	if a.result.Decision != "" {
		return a.result, nil
	}

	return nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: request.Context.Username}, nil
}

// singleRequest returns the only recorded auth request.
func (a *recordingAuthenticator) singleRequest(t *testing.T) nauthilus.AuthRequest {
	t.Helper()

	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.requests) != 1 {
		t.Fatalf("recorded requests = %d, want 1", len(a.requests))
	}

	return a.requests[0]
}

type recordingMessageSink struct {
	mu        sync.Mutex
	body      strings.Builder
	max       int
	finish    int
	snapshots []TransactionSnapshot
}

// OpenMessage returns the sink itself as the streaming body.
func (s *recordingMessageSink) OpenMessage(_ context.Context, snapshot TransactionSnapshot) (MessageBody, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.snapshots = append(s.snapshots, snapshot)

	return s, nil
}

// Write records one streamed body chunk and tracks the largest write size.
func (s *recordingMessageSink) Write(payload []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(payload) > s.max {
		s.max = len(payload)
	}

	s.body.Write(payload)

	return len(payload), nil
}

// Finish records message completion.
func (s *recordingMessageSink) Finish(context.Context) (MessageResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.finish++

	return MessageResult{Status: responseStatusOK, Text: dataQueuedText}, nil
}

// Abort records no payload and allows the session to close cleanly.
func (s *recordingMessageSink) Abort(context.Context, string) error {
	return nil
}

// bodyString returns all streamed bytes for assertions.
func (s *recordingMessageSink) bodyString() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.body.String()
}

// maxWriteBytes returns the largest chunk passed to Write.
func (s *recordingMessageSink) maxWriteBytes() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.max
}

// finishCount returns the number of completed messages.
func (s *recordingMessageSink) finishCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.finish
}

// singleSnapshot returns the only recorded transaction snapshot.
func (s *recordingMessageSink) singleSnapshot(t *testing.T) TransactionSnapshot {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.snapshots) != 1 {
		t.Fatalf("snapshots = %d, want 1", len(s.snapshots))
	}

	return s.snapshots[0]
}

// firstAttribute returns the first configured attribute value.
func firstAttribute(attributes map[string][]string, name string) string {
	if len(attributes[name]) == 0 {
		return ""
	}

	return strings.TrimSpace(attributes[name][0])
}

// plainPayload builds a base64 SASL PLAIN initial response.
func plainPayload(username string, password string) string {
	return base64.StdEncoding.EncodeToString([]byte("\x00" + username + "\x00" + password))
}

// xoauth2Payload builds a base64 XOAUTH2 envelope.
func xoauth2Payload(username string, token string) string {
	payload := "user=" + username + "\x01auth=Bearer " + token + "\x01\x01"

	return base64.StdEncoding.EncodeToString([]byte(payload))
}

// assertNoSecretLeak fails if an error string contains raw secret material.
func assertNoSecretLeak(t *testing.T, value string, secret string) {
	t.Helper()

	if strings.Contains(value, secret) {
		t.Fatalf("value %q leaked secret %q", value, secret)
	}
}
