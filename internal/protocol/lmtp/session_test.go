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

//nolint:dupl,goconst // Protocol fixtures repeat stable public wire and backend-node values.
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
	"github.com/croessner/nauthilus-director/internal/placement"
	"github.com/croessner/nauthilus-director/internal/routing"
	runtimectl "github.com/croessner/nauthilus-director/internal/runtime"
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
	testPlacementBackendB   = "mailstore-b-lmtp"
	testPlacementBackendA2  = "mailstore-a-other-lmtp"
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
	testTLSActive           = "true"
	testTLSInactive         = "false"
	testTLSClientVerifyNone = "NONE"
	testTLSClientVerifyOK   = "SUCCESS"
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

// TestLHLOAdvertisesEnhancedStatusCodesOnlyWhenConfigured verifies frontend-owned capability filtering.
func TestLHLOAdvertisesEnhancedStatusCodesOnlyWhenConfigured(t *testing.T) {
	t.Run("omitted", func(t *testing.T) {
		config := testSessionConfig()
		config.TLSMode = TLSModeImplicit
		config.Capabilities = []string{capabilitySMTPUTF8}

		harness := startLMTPHarness(t, config)
		harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
		harness.write(t, "LHLO submitter.example\r\n")
		harness.expectLine(t, "250-nauthilus-director\r\n")
		harness.expectLine(t, "250 SMTPUTF8\r\n")
	})

	t.Run("configured duplicate", func(t *testing.T) {
		config := testSessionConfig()
		config.TLSMode = TLSModeImplicit
		config.Capabilities = []string{capabilityEnhancedStatusCodes, "enhancedstatuscodes", capabilitySMTPUTF8}

		harness := startLMTPHarness(t, config)
		harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
		harness.write(t, "LHLO submitter.example\r\n")
		harness.expectLine(t, "250-nauthilus-director\r\n")
		harness.expectLine(t, "250-ENHANCEDSTATUSCODES\r\n")
		harness.expectLine(t, "250 SMTPUTF8\r\n")
	})
}

// TestEnhancedStatusResponsesRemainStable verifies capability advertisement does not alter replies.
func TestEnhancedStatusResponsesRemainStable(t *testing.T) {
	config := testSessionConfig()
	config.TLSMode = TLSModeImplicit
	config.Capabilities = []string{capabilityEnhancedStatusCodes}

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 ENHANCEDSTATUSCODES\r\n")
	harness.write(t, "NOOP\r\n")
	harness.expectLine(t, "250 2.0.0 OK\r\n")
	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
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

// Test8BITMIMECapabilityGatesMailBodyParameter verifies BODY=8BITMIME follows LHLO advertisement.
func Test8BITMIMECapabilityGatesMailBodyParameter(t *testing.T) {
	t.Run("configured without backend proof", test8BITMIMEConfiguredWithoutBackendProof)
	t.Run("advertised transaction opt-in", test8BITMIMEAdvertisedTransactionOptIn)
	t.Run("duplicate body parameter", test8BITMIMEDuplicateBodyParameter)
	t.Run("unsupported body values", test8BITMIMEUnsupportedBodyValues)
	t.Run("coexists with smtputf8", test8BITMIMECoexistsWithSMTPUTF8)
}

// TestLHLOUsesCapabilitiesAsPositiveAllowlist verifies backend proof cannot advertise omitted entries.
func TestLHLOUsesCapabilitiesAsPositiveAllowlist(t *testing.T) {
	config := testSessionConfig()
	config.TLSMode = TLSModeImplicit
	config.Capabilities = []string{capabilitySMTPUTF8}
	config.BackendCapabilities = []string{capability8BITMIME, capabilityCHUNKING}

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 SMTPUTF8\r\n")
}

// TestCapabilityDenyFilterSuppressesLHLO verifies listener policy wins over backend proof.
func TestCapabilityDenyFilterSuppressesLHLO(t *testing.T) {
	config := testSessionConfig()
	config.TLSMode = TLSModeImplicit
	config.Capabilities = []string{capabilitySMTPUTF8, capability8BITMIME, capabilityCHUNKING, capabilityEnhancedStatusCodes}
	config.BackendCapabilities = []string{capability8BITMIME, capabilityCHUNKING}
	config.CapabilityFilterDeny = []string{capabilitySMTPUTF8, capability8BITMIME, capabilityCHUNKING}

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 ENHANCEDSTATUSCODES\r\n")
}

// TestCapabilityDenyFilterRejectsSMTPUTF8EnvelopeUse verifies denied UTF-8 paths fail closed.
func TestCapabilityDenyFilterRejectsSMTPUTF8EnvelopeUse(t *testing.T) {
	t.Run("mail parameter", func(t *testing.T) {
		config := testSessionConfig()
		config.TLSMode = TLSModeImplicit
		config.Capabilities = []string{capabilitySMTPUTF8}
		config.CapabilityFilterDeny = []string{capabilitySMTPUTF8}

		harness := startLMTPHarness(t, config)
		harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
		harness.write(t, "LHLO submitter.example\r\n")
		harness.expectLine(t, "250 nauthilus-director\r\n")
		harness.write(t, "MAIL FROM:<sender@example.test> SMTPUTF8\r\n")
		harness.expectLine(t, "501 5.5.4 Invalid MAIL command\r\n")
	})

	t.Run("unicode path", func(t *testing.T) {
		config := testSessionConfig()
		config.TLSMode = TLSModeImplicit
		config.Capabilities = []string{capabilitySMTPUTF8}
		config.CapabilityFilterDeny = []string{capabilitySMTPUTF8}

		harness := startLMTPHarness(t, config)
		harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
		harness.write(t, "LHLO submitter.example\r\n")
		harness.expectLine(t, "250 nauthilus-director\r\n")
		harness.write(t, "MAIL FROM:<"+testUnicodeSender+">\r\n")
		harness.expectLine(t, "501 5.5.4 Invalid MAIL command\r\n")
	})
}

// TestCapabilityDenyFilterRejects8BITMIMEUse verifies denied BODY=8BITMIME cannot start delivery.
func TestCapabilityDenyFilterRejects8BITMIMEUse(t *testing.T) {
	config := test8BITMIMEConfig()
	config.CapabilityFilterDeny = []string{capability8BITMIME}

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250 nauthilus-director\r\n")
	harness.write(t, "MAIL FROM:<sender@example.test> BODY=8BITMIME\r\n")
	harness.expectLine(t, "501 5.5.4 Invalid MAIL command\r\n")
}

// TestCapabilityDenyFilterRejectsFrontendBDAT verifies CHUNKING denial disables frontend BDAT.
func TestCapabilityDenyFilterRejectsFrontendBDAT(t *testing.T) {
	config := testChunkingConfig()
	config.CapabilityFilterDeny = []string{capabilityCHUNKING}

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250 nauthilus-director\r\n")
	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<recipient@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "BDAT 0 LAST\r\n")
	harness.expectLine(t, "502 5.5.1 BDAT is not available\r\n")
}

// TestCapabilityDenyFilterRemovesBackendCapabilityInput verifies backend proof is listener-filtered.
func TestCapabilityDenyFilterRemovesBackendCapabilityInput(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	config := testSessionConfig()
	config.Capabilities = []string{capability8BITMIME, capabilityCHUNKING}
	config.BackendCapabilities = []string{capability8BITMIME, capabilityCHUNKING}
	config.CapabilityFilterDeny = []string{capability8BITMIME}

	session, err := NewSession(config, server)
	if err != nil {
		t.Fatalf("NewSession returned error: %v", err)
	}

	if containsCapability(session.backendSafeCapabilities, capability8BITMIME) {
		t.Fatalf("backend-safe capabilities = %v, want denied 8BITMIME removed", session.backendSafeCapabilities)
	}

	if !containsCapability(session.backendSafeCapabilities, capabilityCHUNKING) {
		t.Fatalf("backend-safe capabilities = %v, want CHUNKING preserved", session.backendSafeCapabilities)
	}
}

// TestSIZECapabilityAdvertisesEffectiveMaximum verifies LHLO renders the current fixed limit.
func TestSIZECapabilityAdvertisesEffectiveMaximum(t *testing.T) {
	tests := map[string]struct {
		listenerMaximum int64
		proof           backend.PoolSizeProof
		want            string
	}{
		"listener maximum": {
			listenerMaximum: 52_428_800,
			proof:           backend.PoolSizeProof{Supported: true},
			want:            "250 SIZE 52428800\r\n",
		},
		"backend lower maximum": {
			listenerMaximum: 52_428_800,
			proof:           backend.PoolSizeProof{Supported: true, HasMaximum: true, MaximumBytes: 10_485_760},
			want:            "250 SIZE 10485760\r\n",
		},
		"backend higher maximum": {
			listenerMaximum: 1024,
			proof:           backend.PoolSizeProof{Supported: true, HasMaximum: true, MaximumBytes: 4096},
			want:            "250 SIZE 1024\r\n",
		},
		"backend zero maximum means no fixed backend lowering": {
			listenerMaximum: 2048,
			proof:           backend.PoolSizeProof{Supported: true, HasMaximum: true, MaximumBytes: 0},
			want:            "250 SIZE 2048\r\n",
		},
	}

	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			config := testSIZEConfig(testCase.listenerMaximum, testCase.proof)

			harness := startLMTPHarness(t, config)
			harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
			harness.write(t, "LHLO submitter.example\r\n")
			harness.expectLine(t, "250-nauthilus-director\r\n")
			harness.expectLine(t, testCase.want)
		})
	}
}

// TestSIZECapabilityOmittedWithoutSafeProof verifies config alone never advertises SIZE.
func TestSIZECapabilityOmittedWithoutSafeProof(t *testing.T) {
	tests := map[string]func() SessionConfig{
		"missing proof reader": func() SessionConfig {
			config := testSessionConfig()
			config.TLSMode = TLSModeImplicit
			config.Capabilities = []string{capabilitySIZE}
			config.MaxMessageBytes = 1024

			return config
		},
		"unsupported proof": func() SessionConfig {
			return testSIZEConfig(1024, backend.PoolSizeProof{})
		},
		"unavailable proof": func() SessionConfig {
			config := testSIZEConfig(1024, backend.PoolSizeProof{Supported: true})
			config.BackendSizeProof = &fakeBackendSizeProofReader{err: errors.New("redis unavailable")}

			return config
		},
		"denied": func() SessionConfig {
			config := testSIZEConfig(1024, backend.PoolSizeProof{Supported: true})
			config.CapabilityFilterDeny = []string{capabilitySIZE}

			return config
		},
	}

	for name, makeConfig := range tests {
		t.Run(name, func(t *testing.T) {
			harness := startLMTPHarness(t, makeConfig())
			harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
			harness.write(t, "LHLO submitter.example\r\n")
			harness.expectLine(t, "250 nauthilus-director\r\n")
			harness.write(t, "MAIL FROM:<sender@example.test> SIZE=42\r\n")
			harness.expectLine(t, "501 5.5.4 Invalid MAIL command\r\n")
		})
	}
}

// TestMAILSIZERequiresCurrentSessionAdvertisement verifies SIZE is a negotiated MAIL parameter.
func TestMAILSIZERequiresCurrentSessionAdvertisement(t *testing.T) {
	t.Run("before lhlo", func(t *testing.T) {
		config := testSIZEConfig(1024, backend.PoolSizeProof{Supported: true})

		harness := startLMTPHarness(t, config)
		harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
		harness.write(t, "MAIL FROM:<sender@example.test> SIZE=42\r\n")
		harness.expectLine(t, "503 5.5.1 Send LHLO first\r\n")
	})

	t.Run("after lhlo without size", func(t *testing.T) {
		config := testSessionConfig()
		config.TLSMode = TLSModeImplicit
		config.Capabilities = []string{capabilitySMTPUTF8}

		harness := startLMTPHarness(t, config)
		harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
		harness.write(t, "LHLO submitter.example\r\n")
		harness.expectLine(t, "250-nauthilus-director\r\n")
		harness.expectLine(t, "250 SMTPUTF8\r\n")
		harness.write(t, "MAIL FROM:<sender@example.test> SIZE=42\r\n")
		harness.expectLine(t, "501 5.5.4 Invalid MAIL command\r\n")
	})
}

// TestMAILSIZEAcceptedWhenAdvertisedAndWithinMaximum verifies accepted declared size state.
func TestMAILSIZEAcceptedWhenAdvertisedAndWithinMaximum(t *testing.T) {
	config := testSIZEConfig(1024, backend.PoolSizeProof{Supported: true})

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 SIZE 1024\r\n")
	harness.write(t, "MAIL FROM:<sender@example.test> SIZE=42\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")

	if !harness.session.transaction.declaredSizePresent || harness.session.transaction.declaredSizeBytes != 42 {
		t.Fatalf("transaction declared size = %d present=%v, want 42 true", harness.session.transaction.declaredSizeBytes, harness.session.transaction.declaredSizePresent)
	}
}

// TestMAILSIZEZeroIsAccepted verifies RFC 1870 empty-message declarations are valid.
func TestMAILSIZEZeroIsAccepted(t *testing.T) {
	config := testSIZEConfig(1024, backend.PoolSizeProof{Supported: true})

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 SIZE 1024\r\n")
	harness.write(t, "MAIL FROM:<sender@example.test> SIZE=0\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")

	if !harness.session.transaction.declaredSizePresent || harness.session.transaction.declaredSizeBytes != 0 {
		t.Fatalf("transaction declared size = %d present=%v, want 0 true", harness.session.transaction.declaredSizeBytes, harness.session.transaction.declaredSizePresent)
	}
}

// TestMAILSIZERejectsMalformedParameters verifies parser failures stay deterministic.
func TestMAILSIZERejectsMalformedParameters(t *testing.T) {
	for _, parameter := range []string{
		"SIZE=42 SIZE=43",
		"SIZE=",
		"SIZE=-1",
		"SIZE=1.5",
		"SIZE=18446744073709551616",
	} {
		t.Run(parameter, func(t *testing.T) {
			config := testSIZEConfig(1024, backend.PoolSizeProof{Supported: true})

			harness := startLMTPHarness(t, config)
			harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
			harness.write(t, "LHLO submitter.example\r\n")
			harness.drainLHLO(t)
			harness.write(t, "MAIL FROM:<sender@example.test> "+parameter+"\r\n")
			harness.expectLine(t, "501 5.5.4 Invalid MAIL command\r\n")
		})
	}
}

// TestMAILSIZERejectsOversizeBeforePlacement verifies declared oversize has no backend side effects.
func TestMAILSIZERejectsOversizeBeforePlacement(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{testRecipientSingle: testPlacementShardA})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{}
	connector := &recordingLMTPBackendConnector{}
	config := placementSessionConfig(identity, resolver, store, selector)
	config.Capabilities = []string{capabilitySIZE}
	config.MaxMessageBytes = 1024
	config.BackendSizeProof = &fakeBackendSizeProofReader{proof: backend.PoolSizeProof{Supported: true}}
	config.BackendConnector = connector

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 SIZE 1024\r\n")
	harness.write(t, "MAIL FROM:<sender@example.test> SIZE=1025\r\n")
	harness.expectLine(t, "552 5.3.4 Message size exceeds fixed maximum message size\r\n")

	store.assertOpened(t, 0)
	store.assertReserved(t, 0)
	store.assertAttached(t, 0)

	if selector.requestCount() != 0 {
		t.Fatalf("selector calls = %d, want none", selector.requestCount())
	}

	if connector.requestCount() != 0 {
		t.Fatalf("backend connect requests = %d, want none", connector.requestCount())
	}
}

// TestMAILSIZECoexistsWithSMTPUTF8And8BITMIME verifies parameter order is deterministic.
func TestMAILSIZECoexistsWithSMTPUTF8And8BITMIME(t *testing.T) {
	parameters := []string{
		"SMTPUTF8 BODY=8BITMIME SIZE=42",
		"SIZE=42 SMTPUTF8 BODY=8BITMIME",
		"BODY=8BITMIME SIZE=42 SMTPUTF8",
	}

	for _, parameter := range parameters {
		t.Run(parameter, func(t *testing.T) {
			config := testSIZEConfig(1024, backend.PoolSizeProof{Supported: true})
			config.Capabilities = []string{capabilitySMTPUTF8, capability8BITMIME, capabilitySIZE}
			config.BackendCapabilities = []string{capability8BITMIME}

			harness := startLMTPHarness(t, config)
			harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
			harness.write(t, "LHLO submitter.example\r\n")
			harness.expectLine(t, "250-nauthilus-director\r\n")
			harness.expectLine(t, "250-SMTPUTF8\r\n")
			harness.expectLine(t, "250-8BITMIME\r\n")
			harness.expectLine(t, "250 SIZE 1024\r\n")
			harness.write(t, "MAIL FROM:<"+testUnicodeSender+"> "+parameter+"\r\n")
			harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")

			if !harness.session.transaction.smtpUTF8 || !harness.session.transaction.body8BitMIME ||
				!harness.session.transaction.declaredSizePresent || harness.session.transaction.declaredSizeBytes != 42 {
				t.Fatalf("transaction state = %#v, want SMTPUTF8, BODY=8BITMIME and SIZE=42", harness.session.transaction)
			}
		})
	}
}

// TestPIPELININGCapabilityAdvertisesOnlyWhenConfiguredAndNotDenied verifies the frontend policy gate.
func TestPIPELININGCapabilityAdvertisesOnlyWhenConfiguredAndNotDenied(t *testing.T) {
	t.Run("configured", func(t *testing.T) {
		config := testPipeliningConfig()

		harness := startLMTPHarness(t, config)
		harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
		harness.write(t, "LHLO submitter.example\r\n")
		harness.expectLine(t, "250-nauthilus-director\r\n")
		harness.expectLine(t, "250 PIPELINING\r\n")
	})

	t.Run("omitted", func(t *testing.T) {
		config := testSessionConfig()
		config.TLSMode = TLSModeImplicit
		config.Capabilities = nil

		harness := startLMTPHarness(t, config)
		harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
		harness.write(t, "LHLO submitter.example\r\n")
		harness.expectLine(t, "250 nauthilus-director\r\n")
	})

	t.Run("denied", func(t *testing.T) {
		config := testPipeliningConfig()
		config.CapabilityFilterDeny = []string{capabilityPIPELINING}

		harness := startLMTPHarness(t, config)
		harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
		harness.write(t, "LHLO submitter.example\r\n")
		harness.expectLine(t, "250 nauthilus-director\r\n")
	})
}

// TestPipelinedMAILRCPTDATARepliesInOrder proves grouped transaction commands keep reply order.
func TestPipelinedMAILRCPTDATARepliesInOrder(t *testing.T) {
	sink := &recordingMessageSink{}
	config := testPipeliningConfig()
	config.MessageSink = sink

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 PIPELINING\r\n")
	harness.write(t, strings.Join([]string{
		"MAIL FROM:<sender@example.test>",
		"RCPT TO:<first@example.test>",
		"RCPT TO:<second@example.test>",
		"DATA",
		"",
	}, "\r\n"))
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.expectLine(t, "354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	harness.write(t, "body\r\n.\r\n")
	harness.expectLine(t, "250 2.0.0 Message accepted\r\n")

	snapshot := sink.singleSnapshot(t)
	if len(snapshot.Recipients) != 2 {
		t.Fatalf("recipient count = %d, want two accepted pipelined recipients", len(snapshot.Recipients))
	}
}

// TestPipelinedRCPTFailureKeepsFollowingCommands proves same-backend failures do not drop queued input.
func TestPipelinedRCPTFailureKeepsFollowingCommands(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{
		testRecipientFirst:  testPlacementShardA,
		testRecipientSecond: testPlacementShardB,
	})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{backendForShard: map[string]string{testPlacementShardB: testPlacementBackendB}}
	sink := &recordingMessageSink{}
	config := placementSessionConfig(identity, resolver, store, selector)
	config.Capabilities = []string{capabilityPIPELINING}
	config.MessageSink = sink

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 PIPELINING\r\n")
	harness.write(t, strings.Join([]string{
		"MAIL FROM:<sender@example.test>",
		"RCPT TO:<first@example.test>",
		"RCPT TO:<second@example.test>",
		"DATA",
		"",
	}, "\r\n"))
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.expectLine(t, "451 4.3.2 Recipient must be retried separately\r\n")
	harness.expectLine(t, "354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	harness.write(t, "body\r\n.\r\n")
	harness.expectLine(t, "250 2.0.0 Message accepted\r\n")

	snapshot := sink.singleSnapshot(t)
	if len(snapshot.Recipients) != 1 || snapshot.Recipients[0].WirePath != "<first@example.test>" {
		t.Fatalf("accepted recipients = %#v, want only first recipient after pipelined failure", snapshot.Recipients)
	}

	store.assertClosed(t, 2)
}

// TestPipelinedDATAWithNoAcceptedRecipientsStaysInCommandMode proves DATA failure consumes no body.
func TestPipelinedDATAWithNoAcceptedRecipientsStaysInCommandMode(t *testing.T) {
	identity := &recordingIdentityLookuper{results: map[string]nauthilus.AuthResult{
		testRecipientSingle: {Decision: nauthilus.DecisionRejected},
	}}
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{}
	sink := &recordingMessageSink{}
	config := placementSessionConfig(identity, resolver, store, selector)
	config.Capabilities = []string{capabilityPIPELINING}
	config.MessageSink = sink

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 PIPELINING\r\n")
	harness.write(t, strings.Join([]string{
		"MAIL FROM:<sender@example.test>",
		"RCPT TO:<recipient@example.test>",
		"DATA",
		"",
	}, "\r\n"))
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.expectLine(t, "451 4.3.0 Recipient lookup temporarily unavailable\r\n")
	harness.expectLine(t, "503 5.5.1 Need recipient before message body\r\n")
	harness.write(t, "NOOP\r\n")
	harness.expectLine(t, "250 2.0.0 OK\r\n")

	if sink.finishCount() != 0 || sink.bodyString() != "" {
		t.Fatalf("sink finish/body = %d/%q, want no body accepted", sink.finishCount(), sink.bodyString())
	}
}

// TestPipelinedRSETMAILRCPTPreservesResetSemantics verifies reset boundaries inside a command group.
func TestPipelinedRSETMAILRCPTPreservesResetSemantics(t *testing.T) {
	sink := &recordingMessageSink{}
	config := testPipeliningConfig()
	config.MessageSink = sink

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 PIPELINING\r\n")
	harness.write(t, strings.Join([]string{
		"MAIL FROM:<first-sender@example.test>",
		"RCPT TO:<first@example.test>",
		"RSET",
		"MAIL FROM:<second-sender@example.test>",
		"RCPT TO:<second@example.test>",
		"DATA",
		"",
	}, "\r\n"))
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.expectLine(t, "250 2.0.0 Transaction reset\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.expectLine(t, "354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	harness.write(t, "body\r\n.\r\n")
	harness.expectLine(t, "250 2.0.0 Message accepted\r\n")

	snapshot := sink.singleSnapshot(t)
	if len(snapshot.Recipients) != 1 || snapshot.Recipients[0].WirePath != "<second@example.test>" {
		t.Fatalf("accepted recipients = %#v, want reset transaction recipient", snapshot.Recipients)
	}
}

// TestQueuedPlaintextCommandsAfterSTARTTLSFailClosed verifies queued plaintext cannot continue delivery.
func TestQueuedPlaintextCommandsAfterSTARTTLSFailClosed(t *testing.T) {
	harness := startLMTPHarness(t, testSessionConfig())
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250-SMTPUTF8\r\n")
	harness.expectLine(t, "250 STARTTLS\r\n")
	harness.write(t, "STARTTLS\r\nMAIL FROM:<sender@example.test>\r\nNOOP\r\n")
	harness.expectLine(t, "220 2.0.0 Ready to start TLS\r\n")
	harness.expectLine(t, "503 5.5.1 Send LHLO first\r\n")
	harness.expectLine(t, "503 5.5.1 Send LHLO first\r\n")
}

// TestQueuedCommandsAfterFailedAUTHDoNotBypassPeerAuth verifies failed AUTH gates queued transactions.
func TestQueuedCommandsAfterFailedAUTHDoNotBypassPeerAuth(t *testing.T) {
	config := testPipeliningConfig()
	config.RequirePeerAuth = true
	config.Authenticator = &recordingAuthenticator{result: nauthilus.AuthResult{Decision: nauthilus.DecisionRejected}}
	config.Capabilities = []string{capabilityPIPELINING, testPlainAuthCapability}
	config.PeerAuthMechanisms = []string{mechanismPlain}

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250-PIPELINING\r\n")
	harness.expectLine(t, "250 AUTH PLAIN\r\n")
	harness.write(t, strings.Join([]string{
		"AUTH PLAIN " + plainPayload(testSubmitterIdentity, testPeerPassword),
		"MAIL FROM:<sender@example.test>",
		"DATA",
		"",
	}, "\r\n"))
	harness.expectLine(t, "535 5.7.8 Authentication credentials invalid\r\n")
	harness.expectLine(t, "530 5.7.0 Authentication required\r\n")
	harness.expectLine(t, "530 5.7.0 Authentication required\r\n")
	harness.write(t, "NOOP\r\n")
	harness.expectLine(t, "250 2.0.0 OK\r\n")
}

// TestCHUNKINGAndPIPELININGAdvertiseTogether verifies independent capability policy.
func TestCHUNKINGAndPIPELININGAdvertiseTogether(t *testing.T) {
	config := testChunkingConfig()
	config.Capabilities = []string{capabilityCHUNKING, capabilityPIPELINING}

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250-CHUNKING\r\n")
	harness.expectLine(t, "250 PIPELINING\r\n")
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
	harness.write(t, "MAIL FROM:<sender@example.test> SIZE=42\r\n")
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

// test8BITMIMEConfiguredWithoutBackendProof verifies config alone cannot enable BODY=8BITMIME.
func test8BITMIMEConfiguredWithoutBackendProof(t *testing.T) {
	config := testSessionConfig()
	config.TLSMode = TLSModeImplicit
	config.Capabilities = []string{capability8BITMIME}

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250 nauthilus-director\r\n")
	harness.write(t, "MAIL FROM:<sender@example.test> BODY=8BITMIME\r\n")
	harness.expectLine(t, "501 5.5.4 Invalid MAIL command\r\n")
}

// test8BITMIMEAdvertisedTransactionOptIn verifies advertised BODY=8BITMIME is accepted.
func test8BITMIMEAdvertisedTransactionOptIn(t *testing.T) {
	config := test8BITMIMEConfig()

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 8BITMIME\r\n")
	harness.write(t, "MAIL FROM:<sender@example.test> BODY=8BITMIME\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
}

// test8BITMIMEDuplicateBodyParameter verifies only one BODY parameter is accepted.
func test8BITMIMEDuplicateBodyParameter(t *testing.T) {
	config := test8BITMIMEConfig()

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.drainLHLO(t)
	harness.write(t, "MAIL FROM:<sender@example.test> BODY=8BITMIME BODY=8BITMIME\r\n")
	harness.expectLine(t, "501 5.5.4 Invalid MAIL command\r\n")
}

// test8BITMIMEUnsupportedBodyValues verifies unsupported BODY modes remain fail-closed.
func test8BITMIMEUnsupportedBodyValues(t *testing.T) {
	for _, parameter := range []string{"BODY=BINARYMIME", "BODY=7BIT", "BODY=8BITMIME=YES"} {
		t.Run(parameter, func(t *testing.T) {
			config := test8BITMIMEConfig()

			harness := startLMTPHarness(t, config)
			harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
			harness.write(t, "LHLO submitter.example\r\n")
			harness.drainLHLO(t)
			harness.write(t, "MAIL FROM:<sender@example.test> "+parameter+"\r\n")
			harness.expectLine(t, "501 5.5.4 Invalid MAIL command\r\n")
		})
	}
}

// test8BITMIMECoexistsWithSMTPUTF8 verifies both MAIL opt-ins can share one transaction.
func test8BITMIMECoexistsWithSMTPUTF8(t *testing.T) {
	config := test8BITMIMEConfig()
	config.Capabilities = []string{capabilitySMTPUTF8, capability8BITMIME}

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250-SMTPUTF8\r\n")
	harness.expectLine(t, "250 8BITMIME\r\n")
	harness.write(t, "MAIL FROM:<"+testUnicodeSender+"> SMTPUTF8 BODY=8BITMIME\r\n")
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
			config.BackendCapabilities = []string{capabilityCHUNKING}
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

	if request.Context.TLS != testTLSActive || request.Context.TLSClientVerify != testTLSClientVerifyNone {
		t.Fatalf("TLS context = %#v, want implicit TLS without client cert", request.Context)
	}
}

// TestSASLPeerBearerAuthUsesIntrospection proves peer bearer auth avoids password auth.
func TestSASLPeerBearerAuthUsesIntrospection(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		method   string
		username string
		token    string
	}{
		{
			name:     "xoauth2",
			command:  "AUTH XOAUTH2 " + xoauth2Payload("xoauth-submit@example.test", "xoauth-submit-token") + "\r\n",
			method:   mechanismXOAUTH2,
			username: "xoauth-submit@example.test",
			token:    "xoauth-submit-token",
		},
		{
			name:     "oauthbearer",
			command:  "AUTH OAUTHBEARER " + oauthBearerPayload("oauth-submit@example.test", "oauth-submit-token") + "\r\n",
			method:   mechanismOAuthBearer,
			username: "oauth-submit@example.test",
			token:    "oauth-submit-token",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			authenticator := &recordingAuthenticator{}
			introspector := &recordingBearerIntrospector{
				result: nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: testCase.username},
			}
			config := testSessionConfig()
			config.TLSMode = TLSModeImplicit
			config.RequirePeerAuth = true
			config.Authenticator = authenticator
			config.BearerIntrospector = introspector
			config.Capabilities = []string{testAllAuthCapability}

			harness := startLMTPHarness(t, config)
			harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
			harness.write(t, "LHLO submitter.example\r\n")
			harness.expectLine(t, "250-nauthilus-director\r\n")
			harness.expectLine(t, "250 AUTH PLAIN LOGIN XOAUTH2 OAUTHBEARER\r\n")
			harness.write(t, testCase.command)
			harness.expectLine(t, "235 2.7.0 Authentication successful\r\n")

			if authenticator.callCount() != 0 {
				t.Fatalf("password auth calls = %d, want 0", authenticator.callCount())
			}

			request := introspector.singleRequest(t)
			if request.Context.Protocol != protocolLMTP || request.Context.Method != testCase.method {
				t.Fatalf("request context protocol/method = %q/%q, want lmtp/%s", request.Context.Protocol, request.Context.Method, testCase.method)
			}

			if request.Context.Username != testCase.username || request.BearerToken.Value() != testCase.token {
				t.Fatalf("request username/token = %q/%q, want introspected bearer material", request.Context.Username, request.BearerToken.String())
			}
		})
	}
}

// TestSASLPeerPasswordAuthStillUsesAuthenticator proves PLAIN remains on password auth.
func TestSASLPeerPasswordAuthStillUsesAuthenticator(t *testing.T) {
	authenticator := &recordingAuthenticator{}
	introspector := &recordingBearerIntrospector{}
	config := testSessionConfig()
	config.TLSMode = TLSModeImplicit
	config.RequirePeerAuth = true
	config.Authenticator = authenticator
	config.BearerIntrospector = introspector
	config.Capabilities = []string{testAllAuthCapability}

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 AUTH PLAIN LOGIN XOAUTH2 OAUTHBEARER\r\n")
	harness.write(t, "AUTH PLAIN "+plainPayload(testSubmitterIdentity, testPeerPassword)+"\r\n")
	harness.expectLine(t, "235 2.7.0 Authentication successful\r\n")

	if authenticator.callCount() != 1 {
		t.Fatalf("password auth calls = %d, want 1", authenticator.callCount())
	}

	if introspector.callCount() != 0 {
		t.Fatalf("introspection calls = %d, want 0", introspector.callCount())
	}
}

// TestSASLPeerBearerBeforeTLSDoesNotIntrospect verifies plaintext AUTH stays fail-closed.
func TestSASLPeerBearerBeforeTLSDoesNotIntrospect(t *testing.T) {
	authenticator := &recordingAuthenticator{}
	introspector := &recordingBearerIntrospector{}
	config := testSessionConfig()
	config.TLSMode = TLSModeStartTLS
	config.RequirePeerAuth = true
	config.Authenticator = authenticator
	config.BearerIntrospector = introspector
	config.Capabilities = []string{testAllAuthCapability, capabilitySTARTTLS}

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 STARTTLS\r\n")
	harness.write(t, "AUTH XOAUTH2 "+xoauth2Payload("alice@example.test", "token-before-tls")+"\r\n")
	harness.expectLine(t, "530 5.7.0 Must issue STARTTLS first\r\n")

	if authenticator.callCount() != 0 {
		t.Fatalf("password auth calls = %d, want 0", authenticator.callCount())
	}

	if introspector.callCount() != 0 {
		t.Fatalf("introspection calls = %d, want 0", introspector.callCount())
	}
}

// TestPlaintextLMTPAUTHFailsLocally verifies miswired plaintext auth never reaches Nauthilus.
func TestPlaintextLMTPAUTHFailsLocally(t *testing.T) {
	authenticator := &recordingAuthenticator{}
	introspector := &recordingBearerIntrospector{}
	config := testSessionConfig()
	config.TLSMode = TLSModePlaintext
	config.RequirePeerAuth = false
	config.Authenticator = authenticator
	config.BearerIntrospector = introspector
	config.Capabilities = []string{capabilitySMTPUTF8, capabilitySTARTTLS, testAllAuthCapability}

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 SMTPUTF8\r\n")
	harness.write(t, "STARTTLS\r\n")
	harness.expectLine(t, "503 5.5.1 STARTTLS is not available\r\n")
	harness.write(t, "AUTH XOAUTH2 "+xoauth2Payload("alice@example.test", "token-before-tls")+"\r\n")
	harness.expectLine(t, "530 5.7.0 Must issue STARTTLS first\r\n")

	if authenticator.callCount() != 0 {
		t.Fatalf("password auth calls = %d, want 0", authenticator.callCount())
	}

	if introspector.callCount() != 0 {
		t.Fatalf("introspection calls = %d, want 0", introspector.callCount())
	}
}

// TestPlaintextLMTPAllowsUnauthenticatedTransaction verifies auth-free plaintext delivery commands work.
func TestPlaintextLMTPAllowsUnauthenticatedTransaction(t *testing.T) {
	sink := &recordingMessageSink{}
	config := testSessionConfig()
	config.TLSMode = TLSModePlaintext
	config.Capabilities = []string{capabilitySMTPUTF8}
	config.PeerAuthMechanisms = nil
	config.MessageSink = sink

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 SMTPUTF8\r\n")
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
}

// TestPlaintextLMTPRecipientLookupReportsInactiveTLS verifies no-auth lookup context stays truthful.
func TestPlaintextLMTPRecipientLookupReportsInactiveTLS(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{
		testRecipientSingle: testPlacementShardA,
	})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{}
	config := placementSessionConfig(identity, resolver, store, selector)
	config.TLSMode = TLSModePlaintext
	config.Capabilities = []string{capabilitySMTPUTF8}

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 SMTPUTF8\r\n")
	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<recipient@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")

	lookup := identity.singleLookup(t)
	if lookup.Context.TLS != testTLSInactive {
		t.Fatalf("lookup TLS = %q, want plaintext ssl=false", lookup.Context.TLS)
	}

	if lookup.Context.TLSProtocol != "" || lookup.Context.TLSCipher != "" || lookup.Context.TLSClientVerify != "" {
		t.Fatalf("lookup TLS metadata = %#v, want no invented TLS fields", lookup.Context)
	}
}

// TestSASLPeerBearerTemporaryFailureMapsTo454 verifies transport errors stay temporary.
func TestSASLPeerBearerTemporaryFailureMapsTo454(t *testing.T) {
	config := testSessionConfig()
	config.TLSMode = TLSModeImplicit
	config.RequirePeerAuth = true
	config.Authenticator = &recordingAuthenticator{}
	config.BearerIntrospector = &recordingBearerIntrospector{err: errors.New("temporary introspection failure")}
	config.Capabilities = []string{testAllAuthCapability}

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 AUTH PLAIN LOGIN XOAUTH2 OAUTHBEARER\r\n")
	harness.write(t, "AUTH XOAUTH2 "+xoauth2Payload("alice@example.test", "xoauth-token")+"\r\n")
	harness.expectLine(t, "454 4.7.0 Authentication service temporarily unavailable\r\n")
}

// TestSASLPeerBearerRejectionMapsTo535 verifies inactive tokens reject authentication.
func TestSASLPeerBearerRejectionMapsTo535(t *testing.T) {
	config := testSessionConfig()
	config.TLSMode = TLSModeImplicit
	config.RequirePeerAuth = true
	config.Authenticator = &recordingAuthenticator{}
	config.BearerIntrospector = &recordingBearerIntrospector{
		result: nauthilus.AuthResult{Decision: nauthilus.DecisionRejected},
	}
	config.Capabilities = []string{testAllAuthCapability}

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 AUTH PLAIN LOGIN XOAUTH2 OAUTHBEARER\r\n")
	harness.write(t, "AUTH OAUTHBEARER "+oauthBearerPayload("alice@example.test", "oauth-token")+"\r\n")
	harness.expectLine(t, "535 5.7.8 Authentication credentials invalid\r\n")
}

// TestSASLPeerAuthPassesVerifiedTLSFacts verifies client certificate metadata reaches Nauthilus.
func TestSASLPeerAuthPassesVerifiedTLSFacts(t *testing.T) {
	authenticator := &recordingAuthenticator{}
	config := testSessionConfig()
	config.TLSMode = TLSModeImplicit
	config.RequirePeerAuth = true
	config.Authenticator = authenticator
	config.Capabilities = []string{testPlainAuthCapability}
	config.PeerAuthMechanisms = []string{mechanismPlain}

	harness := startLMTPHarnessWithState(t, config, verifiedTLSState(testMTLSPeerIdentity))
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 AUTH PLAIN\r\n")
	harness.write(t, "AUTH PLAIN "+plainPayload(testSubmitterIdentity, testPeerPassword)+"\r\n")
	harness.expectLine(t, "235 2.7.0 Authentication successful\r\n")

	request := authenticator.singleRequest(t)
	if request.Context.TLS != testTLSActive || request.Context.TLSClientVerify != testTLSClientVerifyOK {
		t.Fatalf("TLS context = %#v, want verified TLS", request.Context)
	}

	if request.Context.TLSClientCN != testMTLSPeerIdentity {
		t.Fatalf("TLS client CN = %q, want %q", request.Context.TLSClientCN, testMTLSPeerIdentity)
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

	t.Run("configured without backend proof", func(t *testing.T) {
		config := testSessionConfig()
		config.TLSMode = TLSModeImplicit
		config.Capabilities = []string{capabilitySMTPUTF8, capabilityCHUNKING}
		config.BackendCapabilities = nil

		harness := startLMTPHarness(t, config)
		harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
		harness.write(t, "LHLO submitter.example\r\n")
		harness.expectLine(t, "250-nauthilus-director\r\n")
		harness.expectLine(t, "250 SMTPUTF8\r\n")
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
	config.Capabilities = []string{capabilityCHUNKING, capability8BITMIME}
	config.BackendCapabilities = []string{capabilityCHUNKING, capability8BITMIME}
	config.MessageSink = sink

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250-CHUNKING\r\n")
	harness.expectLine(t, "250 8BITMIME\r\n")
	harness.write(t, "MAIL FROM:<sender@example.test> BODY=8BITMIME\r\n")
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
	config := test8BITMIMEConfig()
	config.MessageSink = sink

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 8BITMIME\r\n")
	harness.write(t, "MAIL FROM:<sender@example.test> BODY=8BITMIME\r\n")
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

// TestDATAExactSizeLimitSucceeds verifies decoded DATA bytes can match the fixed limit.
func TestDATAExactSizeLimitSucceeds(t *testing.T) {
	sink := &recordingMessageSink{}
	config := testSIZEConfig(5, backend.PoolSizeProof{Supported: true})
	config.MessageSink = sink

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 SIZE 5\r\n")
	harness.write(t, "MAIL FROM:<sender@example.test> SIZE=1\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<recipient@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "DATA\r\n")
	harness.expectLine(t, "354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	harness.write(t, "abc\r\n.\r\n")
	harness.expectLine(t, "250 2.0.0 Message accepted\r\n")

	if got := sink.bodyString(); got != "abc\r\n" {
		t.Fatalf("DATA body = %q, want CRLF-preserved content", got)
	}
}

// TestDATACRLFBytesCountTowardSizeLimit verifies line endings are message bytes.
func TestDATACRLFBytesCountTowardSizeLimit(t *testing.T) {
	sink := &recordingMessageSink{}
	config := testSIZEConfig(3, backend.PoolSizeProof{Supported: true})
	config.MessageSink = sink

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 SIZE 3\r\n")
	harness.write(t, "MAIL FROM:<sender@example.test> SIZE=3\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<recipient@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "DATA\r\n")
	harness.expectLine(t, "354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	harness.write(t, "abc\r\n.\r\n")
	harness.expectLine(t, "552 5.3.4 Message size exceeds fixed maximum message size\r\n")
	harness.write(t, "NOOP\r\n")
	harness.expectLine(t, "250 2.0.0 OK\r\n")

	if sink.finishCount() != 0 || sink.abortCount() != 1 {
		t.Fatalf("sink finish/abort = %d/%d, want 0/1", sink.finishCount(), sink.abortCount())
	}
}

// TestDATADotStuffedBytesCountAfterUnstuffing verifies DATA dot transparency.
func TestDATADotStuffedBytesCountAfterUnstuffing(t *testing.T) {
	sink := &recordingMessageSink{}
	config := testSIZEConfig(3, backend.PoolSizeProof{Supported: true})
	config.MessageSink = sink

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 SIZE 3\r\n")
	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<recipient@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "DATA\r\n")
	harness.expectLine(t, "354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	harness.write(t, "..\r\n.\r\n")
	harness.expectLine(t, "250 2.0.0 Message accepted\r\n")

	if got := sink.bodyString(); got != ".\r\n" {
		t.Fatalf("DATA body = %q, want dot-unstuffed content", got)
	}
}

// TestDATATerminatorDoesNotCountTowardSizeLimit verifies DATA framing is separate.
func TestDATATerminatorDoesNotCountTowardSizeLimit(t *testing.T) {
	sink := &recordingMessageSink{}
	config := testSIZEConfig(1, backend.PoolSizeProof{Supported: true})
	config.MessageSink = sink

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 SIZE 1\r\n")
	harness.write(t, "MAIL FROM:<sender@example.test> SIZE=0\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<recipient@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "DATA\r\n")
	harness.expectLine(t, "354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	harness.write(t, ".\r\n")
	harness.expectLine(t, "250 2.0.0 Message accepted\r\n")
}

// TestBDATActualSizeEnforcesEffectiveMaximum verifies exact chunk-size accounting and drains.
func TestBDATActualSizeEnforcesEffectiveMaximum(t *testing.T) {
	t.Run("exact maximum succeeds", func(t *testing.T) {
		sink := &recordingMessageSink{}
		config := testSIZEConfig(5, backend.PoolSizeProof{Supported: true})
		config.Capabilities = []string{capabilityCHUNKING, capabilitySIZE}
		config.BackendCapabilities = []string{capabilityCHUNKING}
		config.MessageSink = sink

		harness := startLMTPHarness(t, config)
		harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
		harness.write(t, "LHLO submitter.example\r\n")
		harness.expectLine(t, "250-nauthilus-director\r\n")
		harness.expectLine(t, "250-CHUNKING\r\n")
		harness.expectLine(t, "250 SIZE 5\r\n")
		harness.write(t, "MAIL FROM:<sender@example.test> SIZE=1\r\n")
		harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
		harness.write(t, "RCPT TO:<recipient@example.test>\r\n")
		harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
		harness.write(t, "BDAT 5 LAST\r\nhello")
		harness.expectLine(t, "250 2.0.0 Message accepted\r\n")

		if got := sink.bodyString(); got != "hello" {
			t.Fatalf("BDAT body = %q, want exact payload", got)
		}
	})

	t.Run("oversize drains failed payload and keeps command mode", func(t *testing.T) {
		sink := &recordingMessageSink{}
		config := testSIZEConfig(5, backend.PoolSizeProof{Supported: true})
		config.Capabilities = []string{capabilityCHUNKING, capabilitySIZE}
		config.BackendCapabilities = []string{capabilityCHUNKING}
		config.MessageSink = sink

		harness := startLMTPHarness(t, config)
		harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
		harness.write(t, "LHLO submitter.example\r\n")
		harness.expectLine(t, "250-nauthilus-director\r\n")
		harness.expectLine(t, "250-CHUNKING\r\n")
		harness.expectLine(t, "250 SIZE 5\r\n")
		harness.write(t, "MAIL FROM:<sender@example.test> SIZE=1\r\n")
		harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
		harness.write(t, "RCPT TO:<recipient@example.test>\r\n")
		harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
		harness.write(t, "BDAT 6 LAST\r\nsecretNOOP\r\n")
		harness.expectLine(t, "552 5.3.4 Message size exceeds fixed maximum message size\r\n")
		harness.expectLine(t, "250 2.0.0 OK\r\n")

		if sink.bodyString() != "" || sink.finishCount() != 0 {
			t.Fatalf("sink body/finish = %q/%d, want empty/0", sink.bodyString(), sink.finishCount())
		}
	})
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

// TestRecipientPlacementGateTemporaryFailureStopsPlacement verifies held recipients do not route.
func TestRecipientPlacementGateTemporaryFailureStopsPlacement(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{
		testRecipientSingle: testPlacementShardA,
	})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{}
	gate := &recordingRecipientPlacementGate{
		err: &runtimectl.Error{Kind: runtimectl.ErrorKindUnavailable, Operation: "user_hold_check", Message: "user hold wait timeout"},
	}
	config := placementSessionConfig(identity, resolver, store, selector)
	config.PlacementGate = gate

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.drainLHLO(t)
	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<recipient@example.test>\r\n")
	harness.expectLine(t, "451 4.3.0 Recipient lookup temporarily unavailable\r\n")

	if gate.calls != 1 {
		t.Fatalf("placement gate calls = %d, want 1", gate.calls)
	}

	if gate.request.Protocol != protocolLMTP || gate.request.ListenerName != testPlacementListener || gate.request.ServiceName != testPlacementService {
		t.Fatalf("placement gate request = %#v, want LMTP listener context", gate.request)
	}

	store.assertOpened(t, 0)
	store.assertAttached(t, 0)
	store.assertReserved(t, 0)

	if store.backendPinReads() != 0 {
		t.Fatalf("backend-pin reads = %d, want none before gate release", store.backendPinReads())
	}

	if selector.requestCount() != 0 {
		t.Fatalf("selector calls = %d, want no backend selection", selector.requestCount())
	}
}

// TestRecipientPlacementGateReleaseReReadsRuntimeState verifies release resumes fresh placement.
func TestRecipientPlacementGateReleaseReReadsRuntimeState(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{
		testRecipientSingle: testPlacementShardB,
	})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{}
	gate := recipientPlacementReleaseGate(t, store, selector)
	config := placementSessionConfig(identity, resolver, store, selector)
	config.PlacementGate = gate

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
	harness.write(t, "line-one\r\n.\r\n")
	harness.expectLine(t, "250 2.0.0 Message accepted\r\n")

	if gate.calls != 1 {
		t.Fatalf("placement gate calls = %d, want 1", gate.calls)
	}

	request := selector.firstRequest(t)
	if request.OperatorBackendIdentifier != testPlacementBackendB || request.ShardTag != testPlacementShardB {
		t.Fatalf("selection request after gate release = %#v, want re-read backend pin", request)
	}

	if open := store.singleOpen(t); open.ShardTag != testPlacementShardB {
		t.Fatalf("delivery hold shard = %q, want routed shard after re-read", open.ShardTag)
	}

	store.assertReserved(t, 1)
	store.assertAttached(t, 1)
	store.assertClosed(t, 1)
}

// recipientPlacementReleaseGate builds a gate that proves release happens before placement side effects.
func recipientPlacementReleaseGate(
	t *testing.T,
	store *recordingDeliveryStore,
	selector *recordingBackendSelector,
) *recordingRecipientPlacementGate {
	t.Helper()

	return &recordingRecipientPlacementGate{
		wait: func(_ context.Context, request runtimectl.PlacementGateRequest) (runtimectl.PlacementGateResult, error) {
			if request.Protocol != protocolLMTP || request.ListenerName != testPlacementListener || request.ServiceName != testPlacementService {
				t.Fatalf("placement gate request = %#v, want LMTP listener context", request)
			}

			store.assertOpened(t, 0)
			store.assertReserved(t, 0)
			store.assertAttached(t, 0)

			if store.backendPinReads() != 0 || selector.requestCount() != 0 {
				t.Fatalf("runtime side effects before gate release = pin:%d selector:%d", store.backendPinReads(), selector.requestCount())
			}

			store.setBackendPin(state.UserBackendPinRecord{
				Present:           true,
				BackendIdentifier: testPlacementBackendB,
				Protocol:          protocolLMTP,
				BackendPool:       testPlacementPool,
				ShardTag:          testPlacementShardB,
			})

			return runtimectl.PlacementGateResult{
				Outcome:                     runtimectl.PlacementGateOutcomeReleased,
				RuntimeStateRecheckRequired: true,
			}, nil
		},
	}
}

// TestAcceptedRecipientIgnoresLaterPlacementHold verifies active transactions are not retroactive.
func TestAcceptedRecipientIgnoresLaterPlacementHold(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{
		testRecipientSingle: testPlacementShardA,
	})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{}
	gate := &recordingRecipientPlacementGate{}
	config := placementSessionConfig(identity, resolver, store, selector)
	config.PlacementGate = gate

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.drainLHLO(t)
	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<recipient@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")

	gate.err = &runtimectl.Error{Kind: runtimectl.ErrorKindUnavailable, Operation: "user_hold_check", Message: "user hold wait timeout"}

	harness.write(t, "DATA\r\n")
	harness.expectLine(t, "354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	harness.write(t, "line-one\r\n.\r\n")
	harness.expectLine(t, "250 2.0.0 Message accepted\r\n")

	if gate.calls != 1 {
		t.Fatalf("placement gate calls after accepted recipient = %d, want initial RCPT only", gate.calls)
	}

	store.assertClosed(t, 1)
}

// TestRecipientPlacementUsesScopedLMTPBackendPin verifies LMTP pins are pool scoped.
func TestRecipientPlacementUsesScopedLMTPBackendPin(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{
		testRecipientSingle: testPlacementShardB,
	})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{
		backendPin: state.UserBackendPinRecord{
			Present:           true,
			BackendIdentifier: testPlacementBackendB,
			Protocol:          protocolLMTP,
			BackendPool:       testPlacementPool,
			ShardTag:          testPlacementShardB,
		},
	}
	selector := &recordingBackendSelector{}
	config := placementSessionConfig(identity, resolver, store, selector)

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
	harness.write(t, "line-one\r\n.\r\n")
	harness.expectLine(t, "250 2.0.0 Message accepted\r\n")

	request := selector.firstRequest(t)
	if request.OperatorBackendIdentifier != testPlacementBackendB || request.ShardTag != testPlacementShardB {
		t.Fatalf("selection request = %#v, want scoped LMTP backend pin", request)
	}

	if open := store.singleOpen(t); open.ShardTag != testPlacementShardB {
		t.Fatalf("delivery hold shard = %q, want matching routed shard", open.ShardTag)
	}

	store.assertAttached(t, 1)
	store.assertClosed(t, 1)
}

// TestRecipientPlacementIgnoresCrossShardBackendPin verifies LMTP pins cannot move shards.
func TestRecipientPlacementIgnoresCrossShardBackendPin(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{
		testRecipientSingle: testPlacementShardA,
	})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{
		backendPin: state.UserBackendPinRecord{
			Present:           true,
			BackendIdentifier: testPlacementBackendB,
			Protocol:          protocolLMTP,
			BackendPool:       testPlacementPool,
			ShardTag:          testPlacementShardB,
		},
	}
	selector := &recordingBackendSelector{}
	config := placementSessionConfig(identity, resolver, store, selector)

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
	harness.write(t, "line-one\r\n.\r\n")
	harness.expectLine(t, "250 2.0.0 Message accepted\r\n")

	request := selector.firstRequest(t)
	if request.OperatorBackendIdentifier != "" || request.ShardTag != testPlacementShardA {
		t.Fatalf("selection request = %#v, want routed shard without cross-shard pin", request)
	}

	if open := store.singleOpen(t); open.ShardTag != testPlacementShardA {
		t.Fatalf("delivery hold shard = %q, want routing shard", open.ShardTag)
	}
}

// TestRecipientPlacementIgnoresIMAPBackendPin verifies cross-protocol pins do not leak.
func TestRecipientPlacementIgnoresIMAPBackendPin(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{
		testRecipientSingle: testPlacementShardA,
	})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{
		backendPin: state.UserBackendPinRecord{
			Present:           true,
			BackendIdentifier: "mailstore-c-imap",
			Protocol:          "imap",
			BackendPool:       "imap-default",
			ShardTag:          "mailstore-c",
		},
	}
	selector := &recordingBackendSelector{}
	config := placementSessionConfig(identity, resolver, store, selector)

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
	harness.write(t, "line-one\r\n.\r\n")
	harness.expectLine(t, "250 2.0.0 Message accepted\r\n")

	request := selector.firstRequest(t)
	if request.OperatorBackendIdentifier != "" || request.ShardTag != testPlacementShardA {
		t.Fatalf("selection request = %#v, want normal LMTP placement", request)
	}

	if open := store.singleOpen(t); open.ShardTag != testPlacementShardA {
		t.Fatalf("delivery hold shard = %q, want routing shard", open.ShardTag)
	}
}

// TestActiveIMAPBindingMakesLMTPSelectMatchingBackendNode verifies active login bindings constrain LMTP.
func TestActiveIMAPBindingMakesLMTPSelectMatchingBackendNode(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{
		testRecipientSingle: testPlacementShardA,
	})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{
		affinity: state.AffinityRecord{
			Key:                state.AffinityKey{Tenant: testPlacementTenant, AccountKey: testRecipientSingle},
			ShardTag:           testPlacementShardB,
			BackendNode:        "mailstore-b-node-1",
			Status:             "found",
			Present:            true,
			BindingStatus:      state.BindingStatusActive,
			ActiveSessionCount: 1,
			ActiveHolderCount:  1,
		},
	}
	selector := &recordingBackendSelector{}
	config := placementSessionConfig(identity, resolver, store, selector)

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
	harness.write(t, "line-one\r\n.\r\n")
	harness.expectLine(t, "250 2.0.0 Message accepted\r\n")

	nodeRequest := selector.firstNodeRequest(t)
	if nodeRequest.BackendNode != "mailstore-b-node-1" || nodeRequest.ShardTag != testPlacementShardB {
		t.Fatalf("node request = %#v, want active IMAP backend node", nodeRequest)
	}

	open := store.singleOpen(t)
	if open.BackendNode != "mailstore-b-node-1" || open.ShardTag != testPlacementShardB {
		t.Fatalf("delivery hold = %#v, want active IMAP node binding", open)
	}

	store.assertClosed(t, 1)
}

// TestRetainedIMAPBindingMakesLMTPSelectMatchingBackendNode verifies idle login retention constrains LMTP.
func TestRetainedIMAPBindingMakesLMTPSelectMatchingBackendNode(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{
		testRecipientSingle: testPlacementShardA,
	})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{
		affinity: state.AffinityRecord{
			Key:                state.AffinityKey{Tenant: testPlacementTenant, AccountKey: testRecipientSingle},
			ShardTag:           testPlacementShardB,
			BackendNode:        "mailstore-b-node-1",
			Status:             "retained",
			Present:            true,
			BindingStatus:      state.BindingStatusRetained,
			RetentionExpiresAt: time.Now().Add(time.Minute),
		},
	}
	selector := &recordingBackendSelector{}
	config := placementSessionConfig(identity, resolver, store, selector)

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
	harness.write(t, "line-one\r\n.\r\n")
	harness.expectLine(t, "250 2.0.0 Message accepted\r\n")

	nodeRequest := selector.firstNodeRequest(t)
	if nodeRequest.BackendNode != "mailstore-b-node-1" || nodeRequest.ShardTag != testPlacementShardB {
		t.Fatalf("node request = %#v, want retained IMAP backend node", nodeRequest)
	}

	open := store.singleOpen(t)
	if open.BackendNode != "mailstore-b-node-1" || open.ShardTag != testPlacementShardB {
		t.Fatalf("delivery hold = %#v, want retained IMAP node binding", open)
	}

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
	selector := &recordingBackendSelector{backendForShard: map[string]string{testPlacementShardB: testPlacementBackendB}}
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

// TestRecipientPlacementSameShardDifferentBackendNodeTempfailsBeforeData verifies node drift is rejected.
func TestRecipientPlacementSameShardDifferentBackendNodeTempfailsBeforeData(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{
		testRecipientFirst:  testPlacementShardA,
		testRecipientSecond: testPlacementShardA,
	})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{
		backendForAccount: map[string]string{testRecipientSecond: testPlacementBackendA2},
	}
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

	secondOpen := store.openAt(t, 1)
	if secondOpen.ShardTag != testPlacementShardA || secondOpen.BackendNode != "mailstore-a-node-2" {
		t.Fatalf("second hold = %#v, want same shard but different backend node", secondOpen)
	}

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

// TestRecipientBackendReservationRollbackClosesHoldOnAttachFailure verifies failed accounting cleanup.
func TestRecipientBackendReservationRollbackClosesHoldOnAttachFailure(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{
		testRecipientSingle: testPlacementShardA,
	})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{attachErr: errors.New("attach failed")}
	selector := &recordingBackendSelector{}
	config := placementSessionConfig(identity, resolver, store, selector)

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.drainLHLO(t)
	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<recipient@example.test>\r\n")
	harness.expectLine(t, "451 4.3.0 Recipient lookup temporarily unavailable\r\n")

	store.assertOpened(t, 1)
	store.assertReserved(t, 1)
	store.assertAttached(t, 1)
	store.assertReleased(t, 1)
	store.assertClosed(t, 1)
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

// TestBackendSessionConnectRequestCarriesEffectiveFrontendTuple verifies trusted listener addresses flow out.
func TestBackendSessionConnectRequestCarriesEffectiveFrontendTuple(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{testRecipientSingle: testPlacementShardA})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{}
	connector := &recordingLMTPBackendConnector{}
	config := placementSessionConfig(identity, resolver, store, selector)
	config.BackendConnector = connector
	config.BackendConnectTimeout = time.Second

	harness := startLMTPHarnessWithServerConn(t, config, func(conn net.Conn) net.Conn {
		return backendAddressConn{
			Conn:   conn,
			local:  tcpAddr("198.51.100.20", 24),
			remote: tcpAddr("203.0.113.10", 42500),
		}
	})
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.drainLHLO(t)
	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<recipient@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")

	request := connector.singleRequest(t)
	if request.Purpose != backend.ConnectPurposeSession {
		t.Fatalf("connect purpose = %q, want session", request.Purpose)
	}

	if request.Target.Identifier != "mailstore-a-lmtp" {
		t.Fatalf("connect target = %q, want selected LMTP backend", request.Target.Identifier)
	}

	if request.Target.BackendNode != "mailstore-a-node-1" || request.Target.ShardTag != testPlacementShardA {
		t.Fatalf("placement facts changed across connector boundary: %#v", request.Target)
	}

	if request.ProxyAddresses == nil {
		t.Fatal("connect request did not carry frontend proxy addresses")
	}

	if got := request.ProxyAddresses.Source.String(); got != "203.0.113.10:42500" {
		t.Fatalf("proxy source = %q, want effective frontend remote", got)
	}

	if got := request.ProxyAddresses.Destination.String(); got != "198.51.100.20:24" {
		t.Fatalf("proxy destination = %q, want effective frontend local", got)
	}

	store.assertOpened(t, 1)
	store.assertAttached(t, 1)
}

// TestBackendProxyUnsafeFrontendAddressFailsBeforeBackendCommands verifies fail-closed metadata validation.
func TestBackendProxyUnsafeFrontendAddressFailsBeforeBackendCommands(t *testing.T) {
	testCases := []struct {
		name   string
		remote net.Addr
	}{
		{
			name: "missing",
		},
		{
			name:   "non_tcp",
			remote: &net.UnixAddr{Name: "/run/client.sock", Net: "unix"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			identity := identityLookuperForRecipients(map[string]string{testRecipientSingle: testPlacementShardA})
			resolver := &recordingRoutingResolver{}
			store := &recordingDeliveryStore{}
			selector := &recordingBackendSelector{configureBackend: enableBackendProxy}
			dialer := &recordingLMTPFailureDialer{
				conn: &recordingLMTPFailureConn{
					local:  tcpAddr("10.0.0.1", 5024),
					remote: tcpAddr("10.0.0.2", 24),
				},
			}
			config := backendForwardingSessionConfig(identity, resolver, store, selector, dialer)

			harness := startLMTPHarnessWithServerConn(t, config, func(conn net.Conn) net.Conn {
				return backendAddressConn{
					Conn:   conn,
					local:  tcpAddr("198.51.100.20", 24),
					remote: testCase.remote,
				}
			})
			harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
			harness.write(t, "LHLO submitter.example\r\n")
			harness.drainLHLO(t)
			harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
			harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
			harness.write(t, "RCPT TO:<recipient@example.test>\r\n")
			harness.expectLine(t, testTemporaryDelivery)

			if !dialer.conn.closed {
				t.Fatal("unsafe frontend metadata did not close backend connection")
			}

			if dialer.conn.writes != 0 {
				t.Fatalf("backend writes = %d, want none before valid PROXY metadata", dialer.conn.writes)
			}

			store.assertClosed(t, 1)
		})
	}
}

// TestBackendProxyWriteFailurePreventsMessageBodyForwarding verifies body bytes cannot stream afterward.
func TestBackendProxyWriteFailurePreventsMessageBodyForwarding(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{testRecipientSingle: testPlacementShardA})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{configureBackend: enableBackendProxy}
	dialer := &recordingLMTPFailureDialer{
		conn: &recordingLMTPFailureConn{
			local:    tcpAddr("10.0.0.1", 5024),
			remote:   tcpAddr("10.0.0.2", 24),
			writeErr: errors.New("proxy write failed for secret backend"),
		},
	}
	config := backendForwardingSessionConfig(identity, resolver, store, selector, dialer)

	harness := startLMTPHarnessWithServerConn(t, config, func(conn net.Conn) net.Conn {
		return backendAddressConn{
			Conn:   conn,
			local:  tcpAddr("198.51.100.20", 24),
			remote: tcpAddr("203.0.113.10", 42500),
		}
	})
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.drainLHLO(t)
	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<recipient@example.test>\r\n")
	harness.expectLine(t, testTemporaryDelivery)
	harness.write(t, "DATA\r\n")
	harness.expectLine(t, "503 5.5.1 Need recipient before message body\r\n")

	if !dialer.conn.closed {
		t.Fatal("failed PROXY write did not close backend connection")
	}

	if dialer.conn.writes != 1 {
		t.Fatalf("backend writes = %d, want exactly one failed PROXY write", dialer.conn.writes)
	}

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

// TestBackendDATAUsesBDATWhenBackendAdvertisesChunking verifies DATA-to-BDAT conversion.
func TestBackendDATAUsesBDATWhenBackendAdvertisesChunking(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{
		testRecipientSingle: testPlacementShardA,
	})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{}
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := greetChunkingSizedTransactionBackend(t, conn, "5")
		expectLMTPBackendLine(t, reader, "MAIL FROM:<sender@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.0 sender ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<recipient@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.5 recipient ok")
		expectLMTPBackendLine(t, reader, "BDAT 21 LAST")
		expectLMTPBackendBytes(t, reader, "line-one\r\n.line-two\r\n")
		writeLMTPBackendLine(t, conn, "250 2.1.5 delivered")
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
	harness.write(t, "DATA\r\n")
	harness.expectLine(t, "354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	harness.write(t, "line-one\r\n..line-two\r\n.\r\n")
	harness.expectLine(t, "250 2.1.5 Message accepted\r\n")

	store.assertClosed(t, 1)
	dialer.Wait(t)
}

// TestBackendDATAOversizeThroughBDATClosesBackend verifies size failure stops DATA-to-BDAT forwarding.
func TestBackendDATAOversizeThroughBDATClosesBackend(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{
		testRecipientSingle: testPlacementShardA,
	})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{}
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := greetChunkingSizedTransactionBackend(t, conn, "5")
		expectLMTPBackendLine(t, reader, "MAIL FROM:<sender@example.test> SIZE=1")
		writeLMTPBackendLine(t, conn, "250 2.1.0 sender ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<recipient@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.5 recipient ok")

		if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatalf("set backend read deadline: %v", err)
		}

		line, err := reader.ReadString('\n')
		if err == nil {
			t.Fatalf("backend received unexpected command after DATA size failure: %q", strings.TrimRight(line, "\r\n"))
		}

		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			t.Fatal("backend stream was not closed after DATA size failure")
		}
	})
	config := backendForwardingSessionConfig(identity, resolver, store, selector, dialer)
	config.Capabilities = []string{capabilitySIZE}
	config.MaxMessageBytes = 5
	config.BackendSizeProof = &fakeBackendSizeProofReader{proof: backend.PoolSizeProof{Supported: true}}

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 SIZE 5\r\n")
	harness.write(t, "MAIL FROM:<sender@example.test> SIZE=1\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<recipient@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "DATA\r\n")
	harness.expectLine(t, "354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	harness.write(t, "abc\r\nz\r\n.\r\n")
	harness.expectLine(t, "552 5.3.4 Message size exceeds fixed maximum message size\r\n")
	harness.write(t, "NOOP\r\n")
	harness.expectLine(t, "250 2.0.0 OK\r\n")

	store.assertClosed(t, 1)
	dialer.Wait(t)
}

// TestBackendDATAOversizeFallbackClosesBackend verifies backend DATA is aborted on size failure.
func TestBackendDATAOversizeFallbackClosesBackend(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{
		testRecipientSingle: testPlacementShardA,
	})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{}
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := greetSizedTransactionBackend(t, conn, "5")
		expectLMTPBackendLine(t, reader, "MAIL FROM:<sender@example.test> SIZE=1")
		writeLMTPBackendLine(t, conn, "250 2.1.0 sender ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<recipient@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.5 recipient ok")
		expectLMTPBackendLine(t, reader, "DATA")
		writeLMTPBackendLine(t, conn, "354 2.0.0 send data")

		if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatalf("set backend read deadline: %v", err)
		}

		line, err := reader.ReadString('\n')
		if err == nil {
			t.Fatalf("backend received unexpected DATA after size failure: %q", strings.TrimRight(line, "\r\n"))
		}

		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			t.Fatal("backend DATA stream was not closed after size failure")
		}
	})
	config := backendForwardingSessionConfig(identity, resolver, store, selector, dialer)
	config.Capabilities = []string{capabilitySIZE}
	config.MaxMessageBytes = 5
	config.BackendSizeProof = &fakeBackendSizeProofReader{proof: backend.PoolSizeProof{Supported: true}}

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 SIZE 5\r\n")
	harness.write(t, "MAIL FROM:<sender@example.test> SIZE=1\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<recipient@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "DATA\r\n")
	harness.expectLine(t, "354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	harness.write(t, "abc\r\nz\r\n.\r\n")
	harness.expectLine(t, "552 5.3.4 Message size exceeds fixed maximum message size\r\n")

	store.assertClosed(t, 1)
	dialer.Wait(t)
}

// TestBackendDATADeniedChunkingFallsBackToDATA verifies listener policy disables backend BDAT optimization.
func TestBackendDATADeniedChunkingFallsBackToDATA(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{
		testRecipientSingle: testPlacementShardA,
	})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{}
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := greetChunkingSizedTransactionBackend(t, conn, "5")
		expectLMTPBackendLine(t, reader, "MAIL FROM:<sender@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.0 sender ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<recipient@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.5 recipient ok")
		expectLMTPBackendLine(t, reader, "DATA")
		writeLMTPBackendLine(t, conn, "354 2.0.0 send data")
		expectLMTPBackendLine(t, reader, "line-one")
		expectLMTPBackendLine(t, reader, "..line-two")
		expectLMTPBackendLine(t, reader, ".")
		writeLMTPBackendLine(t, conn, "250 2.1.5 delivered")
	})
	config := backendForwardingSessionConfig(identity, resolver, store, selector, dialer)
	config.CapabilityFilterDeny = []string{capabilityCHUNKING}

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
	harness.expectLine(t, "250 2.1.5 Message accepted\r\n")

	store.assertClosed(t, 1)
	dialer.Wait(t)
}

// TestBackendDATAEmptyBodyUsesBDATZeroLast verifies empty DATA converts to a final empty BDAT.
func TestBackendDATAEmptyBodyUsesBDATZeroLast(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{
		testRecipientSingle: testPlacementShardA,
	})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{}
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := greetChunkingSizedTransactionBackend(t, conn, "5")
		expectLMTPBackendLine(t, reader, "MAIL FROM:<sender@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.0 sender ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<recipient@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.5 recipient ok")
		expectLMTPBackendLine(t, reader, "BDAT 0 LAST")
		writeLMTPBackendLine(t, conn, "250 2.1.5 delivered")
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
	harness.write(t, "DATA\r\n")
	harness.expectLine(t, "354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	harness.write(t, ".\r\n")
	harness.expectLine(t, "250 2.1.5 Message accepted\r\n")

	store.assertClosed(t, 1)
	dialer.Wait(t)
}

// TestBackendDATALargeBodySplitsBDATPayloads verifies DATA-to-BDAT uses bounded chunks.
func TestBackendDATALargeBodySplitsBDATPayloads(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{
		testRecipientSingle: testPlacementShardA,
	})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{}
	fullChunk := strings.Repeat(strings.Repeat("a", 1022)+"\r\n", 64)
	finalChunk := "tail\r\n"
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := greetChunkingTransactionBackend(t, conn)
		expectLMTPBackendLine(t, reader, "MAIL FROM:<sender@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.0 sender ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<recipient@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.5 recipient ok")
		expectLMTPBackendLine(t, reader, "BDAT 65536")
		expectLMTPBackendBytes(t, reader, fullChunk)
		writeLMTPBackendLine(t, conn, "250 2.0.0 chunk ok")
		expectLMTPBackendLine(t, reader, "BDAT 6 LAST")
		expectLMTPBackendBytes(t, reader, finalChunk)
		writeLMTPBackendLine(t, conn, "250 2.1.5 delivered")
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
	harness.write(t, "DATA\r\n")
	harness.expectLine(t, "354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	harness.write(t, fullChunk+finalChunk+".\r\n")
	harness.expectLine(t, "250 2.1.5 Message accepted\r\n")

	store.assertClosed(t, 1)
	dialer.Wait(t)
}

// TestBackendDATAtoBDATNonFinalRejectionTempfailsAndClosesBackend verifies fail-closed chunk rejection.
func TestBackendDATAtoBDATNonFinalRejectionTempfailsAndClosesBackend(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{
		testRecipientSingle: testPlacementShardA,
	})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{}
	fullChunk := strings.Repeat(strings.Repeat("a", 1022)+"\r\n", 64)
	finalChunk := "tail\r\n"
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := greetChunkingTransactionBackend(t, conn)
		expectLMTPBackendLine(t, reader, "MAIL FROM:<sender@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.0 sender ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<recipient@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.5 recipient ok")
		expectLMTPBackendLine(t, reader, "BDAT 65536")
		expectLMTPBackendBytes(t, reader, fullChunk)
		writeLMTPBackendLine(t, conn, "451 4.3.0 chunk rejected")

		if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			return
		}

		line, err := reader.ReadString('\n')
		if err == nil {
			t.Fatalf("backend received unexpected command after rejected BDAT chunk: %q", strings.TrimRight(line, "\r\n"))
		}

		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			t.Fatal("backend stream was not closed after rejected BDAT chunk")
		}
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
	harness.write(t, "DATA\r\n")
	harness.expectLine(t, "354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	harness.write(t, fullChunk+finalChunk+".\r\n")
	harness.expectLine(t, testTemporaryDelivery)

	store.assertClosed(t, 1)
	dialer.Wait(t)
}

// TestBackendDATAtoBDATFinalRepliesMatchRecipientOrder verifies converted DATA preserves LMTP statuses.
func TestBackendDATAtoBDATFinalRepliesMatchRecipientOrder(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{
		testRecipientFirst:  testPlacementShardA,
		testRecipientSecond: testPlacementShardA,
		testRecipientThird:  testPlacementShardA,
	})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{}
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := greetChunkingTransactionBackend(t, conn)
		expectLMTPBackendLine(t, reader, "MAIL FROM:<sender@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.0 sender ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<first@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.5 first ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<second@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.5 second ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<"+testRecipientThird+">")
		writeLMTPBackendLine(t, conn, "250 2.1.5 third ok")
		expectLMTPBackendLine(t, reader, "BDAT 6 LAST")
		expectLMTPBackendBytes(t, reader, "body\r\n")
		writeLMTPBackendLine(t, conn, "250 2.1.5 delivered")
		writeLMTPBackendLine(t, conn, "451 4.2.0 temporary policy detail")
		writeLMTPBackendLine(t, conn, "552 5.2.2 quota detail")
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
	harness.write(t, "body\r\n.\r\n")
	harness.expectLine(t, "250 2.1.5 Message accepted\r\n")
	harness.expectLine(t, "451 4.2.0 Message delivery temporarily failed\r\n")
	harness.expectLine(t, "552 5.2.2 Message delivery permanently failed\r\n")

	store.assertClosed(t, 3)
	dialer.Wait(t)
}

// TestBackendDATAtoBDATBackendWriteFailureTempfailsAndClosesHold verifies unknown write outcomes fail closed.
func TestBackendDATAtoBDATBackendWriteFailureTempfailsAndClosesHold(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{
		testRecipientSingle: testPlacementShardA,
	})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{}
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := greetChunkingTransactionBackend(t, conn)
		expectLMTPBackendLine(t, reader, "MAIL FROM:<sender@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.0 sender ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<recipient@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.5 recipient ok")
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
	harness.write(t, "DATA\r\n")
	harness.expectLine(t, "354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	harness.write(t, "body\r\n.\r\n")
	harness.expectLine(t, testTemporaryDelivery)

	store.assertClosed(t, 1)
	dialer.Wait(t)
}

// TestBackendDATAtoBDATIncompleteFinalRepliesSynthesizeTemporaryStatuses verifies missing outcomes.
func TestBackendDATAtoBDATIncompleteFinalRepliesSynthesizeTemporaryStatuses(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{
		testRecipientFirst:  testPlacementShardA,
		testRecipientSecond: testPlacementShardA,
	})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{}
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := greetChunkingTransactionBackend(t, conn)
		expectLMTPBackendLine(t, reader, "MAIL FROM:<sender@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.0 sender ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<first@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.5 first ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<second@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.5 second ok")
		expectLMTPBackendLine(t, reader, "BDAT 6 LAST")
		expectLMTPBackendBytes(t, reader, "body\r\n")
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
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "DATA\r\n")
	harness.expectLine(t, "354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	harness.write(t, "body\r\n.\r\n")
	harness.expectLine(t, "250 2.1.5 Message accepted\r\n")
	harness.expectLine(t, testTemporaryDelivery)

	store.assertClosed(t, 2)
	dialer.Wait(t)
}

// TestFrontendDATAReadFailureAfterBackendBDATBeginsClosesBackend verifies partial body abort cleanup.
func TestFrontendDATAReadFailureAfterBackendBDATBeginsClosesBackend(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{
		testRecipientSingle: testPlacementShardA,
	})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{}
	fullChunk := strings.Repeat(strings.Repeat("a", 1022)+"\r\n", 64)
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := greetChunkingTransactionBackend(t, conn)
		expectLMTPBackendLine(t, reader, "MAIL FROM:<sender@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.0 sender ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<recipient@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.5 recipient ok")
		expectLMTPBackendLine(t, reader, "BDAT 65536")
		expectLMTPBackendBytes(t, reader, fullChunk)
		writeLMTPBackendLine(t, conn, "250 2.0.0 chunk ok")

		if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			return
		}

		line, err := reader.ReadString('\n')
		if err == nil {
			t.Fatalf("backend received unexpected command after frontend DATA read failure: %q", strings.TrimRight(line, "\r\n"))
		}

		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			t.Fatal("backend stream was not closed after frontend DATA read failure")
		}
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
	harness.write(t, "DATA\r\n")
	harness.expectLine(t, "354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	harness.write(t, fullChunk)
	_ = harness.client.Close()

	dialer.Wait(t)
	store.waitClosed(t, 1)
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
	selector := &recordingBackendSelector{backendForShard: map[string]string{testPlacementShardB: testPlacementBackendB}}
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := greetChunkingTransactionBackend(t, conn)
		expectLMTPBackendLine(t, reader, "MAIL FROM:<sender@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.0 sender ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<first@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.5 first ok")
		expectLMTPBackendLine(t, reader, "BDAT 0 LAST")
		writeLMTPBackendLine(t, conn, "250 2.1.5 delivered")
	})
	config := backendForwardingSessionConfig(identity, resolver, store, selector, dialer)
	config.Capabilities = []string{capabilityCHUNKING}
	config.BackendCapabilities = []string{capabilityCHUNKING}

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
		reader := greetChunkingTransactionBackend(t, conn)
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
	config.BackendCapabilities = []string{capabilityCHUNKING}

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

// TestBackendBDATWithoutSelectedChunkingTempfailsAndClosesBackend verifies fail-closed gating.
func TestBackendBDATWithoutSelectedChunkingTempfailsAndClosesBackend(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{
		testRecipientSingle: testPlacementShardA,
	})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{}
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := greetTransactionBackend(t, conn)
		expectLMTPBackendLine(t, reader, "MAIL FROM:<sender@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.0 sender ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<recipient@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.5 recipient ok")

		if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatalf("set backend read deadline: %v", err)
		}

		line, err := reader.ReadString('\n')
		if err == nil {
			command := strings.TrimRight(line, "\r\n")
			if strings.HasPrefix(strings.ToUpper(command), commandBDAT) {
				t.Fatalf("backend received BDAT without selected CHUNKING support")
			}

			t.Fatalf("backend received unexpected command %q after unsupported BDAT", command)
		}

		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			t.Fatal("backend stream was not closed after unsupported BDAT")
		}
	})
	config := backendForwardingSessionConfig(identity, resolver, store, selector, dialer)
	config.Capabilities = []string{capabilityCHUNKING}
	config.BackendCapabilities = []string{capabilityCHUNKING}

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 CHUNKING\r\n")
	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<recipient@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "BDAT 5 LAST\r\nhello")
	harness.expectLine(t, testTemporaryDelivery)
	harness.write(t, "NOOP\r\n")
	harness.expectLine(t, "250 2.0.0 OK\r\n")

	store.assertClosed(t, 1)
	dialer.Wait(t)
}

// TestBackendBDATOversizeDrainsAndStopsForwarding verifies oversized frontend BDAT never reaches backend.
func TestBackendBDATOversizeDrainsAndStopsForwarding(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{
		testRecipientSingle: testPlacementShardA,
	})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{}
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := greetChunkingSizedTransactionBackend(t, conn, "5")
		expectLMTPBackendLine(t, reader, "MAIL FROM:<sender@example.test> SIZE=1")
		writeLMTPBackendLine(t, conn, "250 2.1.0 sender ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<recipient@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.5 recipient ok")

		if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatalf("set backend read deadline: %v", err)
		}

		line, err := reader.ReadString('\n')
		if err == nil {
			t.Fatalf("backend received unexpected command after BDAT size failure: %q", strings.TrimRight(line, "\r\n"))
		}

		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			t.Fatal("backend stream was not closed after BDAT size failure")
		}
	})
	config := backendForwardingSessionConfig(identity, resolver, store, selector, dialer)
	config.Capabilities = []string{capabilityCHUNKING, capabilitySIZE}
	config.BackendCapabilities = []string{capabilityCHUNKING}
	config.MaxMessageBytes = 5
	config.BackendSizeProof = &fakeBackendSizeProofReader{proof: backend.PoolSizeProof{Supported: true}}

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250-CHUNKING\r\n")
	harness.expectLine(t, "250 SIZE 5\r\n")
	harness.write(t, "MAIL FROM:<sender@example.test> SIZE=1\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<recipient@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "BDAT 6 LAST\r\nsecretNOOP\r\n")
	harness.expectLine(t, "552 5.3.4 Message size exceeds fixed maximum message size\r\n")
	harness.expectLine(t, "250 2.0.0 OK\r\n")

	store.assertClosed(t, 1)
	dialer.Wait(t)
}

// TestPipelinedBDATChunksKeepFramingAndFinalOrdering verifies adjacent chunks remain byte-exact.
func TestPipelinedBDATChunksKeepFramingAndFinalOrdering(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{
		testRecipientFirst:  testPlacementShardA,
		testRecipientSecond: testPlacementShardA,
	})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{}
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := greetChunkingTransactionBackend(t, conn)
		expectLMTPBackendLine(t, reader, "MAIL FROM:<sender@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.0 sender ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<first@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.5 first ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<second@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.5 second ok")
		expectLMTPBackendLine(t, reader, "BDAT 5")
		expectLMTPBackendBytes(t, reader, "hello")
		writeLMTPBackendLine(t, conn, "250 2.0.0 chunk ok")
		expectLMTPBackendLine(t, reader, "BDAT 5 LAST")
		expectLMTPBackendBytes(t, reader, "world")
		writeLMTPBackendLine(t, conn, "250 2.1.5 delivered")
		writeLMTPBackendLine(t, conn, "451 4.2.0 temporary policy detail")
	})
	config := backendForwardingSessionConfig(identity, resolver, store, selector, dialer)
	config.Capabilities = []string{capabilityCHUNKING, capabilityPIPELINING}
	config.BackendCapabilities = []string{capabilityCHUNKING}

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250-CHUNKING\r\n")
	harness.expectLine(t, "250 PIPELINING\r\n")
	harness.write(t, strings.Join([]string{
		"MAIL FROM:<sender@example.test>",
		"RCPT TO:<first@example.test>",
		"RCPT TO:<second@example.test>",
		"",
	}, "\r\n"))
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "BDAT 5\r\nhelloBDAT 5 LAST\r\nworld")
	harness.expectLine(t, "250 2.0.0 Message accepted\r\n")
	harness.expectLine(t, "250 2.1.5 Message accepted\r\n")
	harness.expectLine(t, "451 4.2.0 Message delivery temporarily failed\r\n")

	store.assertClosed(t, 2)
	dialer.Wait(t)
}

// TestPipelinedFailedBDATDrainsQueuedChunksAndStopsBackend verifies failed chunks cannot desynchronize.
func TestPipelinedFailedBDATDrainsQueuedChunksAndStopsBackend(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{
		testRecipientSingle: testPlacementShardA,
	})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{}
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := greetChunkingSizedTransactionBackend(t, conn, "5")
		expectLMTPBackendLine(t, reader, "MAIL FROM:<sender@example.test> SIZE=1")
		writeLMTPBackendLine(t, conn, "250 2.1.0 sender ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<recipient@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.5 recipient ok")

		if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatalf("set backend read deadline: %v", err)
		}

		line, err := reader.ReadString('\n')
		if err == nil {
			t.Fatalf("backend received unexpected command after failed frontend BDAT: %q", strings.TrimRight(line, "\r\n"))
		}

		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			t.Fatal("backend stream was not closed after failed frontend BDAT")
		}
	})
	config := backendForwardingSessionConfig(identity, resolver, store, selector, dialer)
	config.Capabilities = []string{capabilityCHUNKING, capabilitySIZE, capabilityPIPELINING}
	config.BackendCapabilities = []string{capabilityCHUNKING}
	config.MaxMessageBytes = 5
	config.BackendSizeProof = &fakeBackendSizeProofReader{proof: backend.PoolSizeProof{Supported: true}}

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250-CHUNKING\r\n")
	harness.expectLine(t, "250-SIZE 5\r\n")
	harness.expectLine(t, "250 PIPELINING\r\n")
	harness.write(t, strings.Join([]string{
		"MAIL FROM:<sender@example.test> SIZE=1",
		"RCPT TO:<recipient@example.test>",
		"",
	}, "\r\n"))
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "BDAT 6\r\nsecretBDAT 5 LAST\r\nlaterNOOP\r\n")
	harness.expectLine(t, "552 5.3.4 Message size exceeds fixed maximum message size\r\n")
	harness.expectLine(t, "503 5.5.1 Send MAIL first\r\n")
	harness.expectLine(t, "250 2.0.0 OK\r\n")

	store.assertClosed(t, 1)
	dialer.Wait(t)
}

// TestPipelinedBDATAfterLASTDrainsPayloadAndReturnsToCommandMode verifies extra body chunks fail safely.
func TestPipelinedBDATAfterLASTDrainsPayloadAndReturnsToCommandMode(t *testing.T) {
	sink := &recordingMessageSink{}
	config := testChunkingConfig()
	config.Capabilities = []string{capabilityCHUNKING, capabilityPIPELINING}
	config.MessageSink = sink

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250-CHUNKING\r\n")
	harness.expectLine(t, "250 PIPELINING\r\n")
	harness.write(t, strings.Join([]string{
		"MAIL FROM:<sender@example.test>",
		"RCPT TO:<recipient@example.test>",
		"",
	}, "\r\n"))
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "BDAT 0 LAST\r\nBDAT 4 LAST\r\njunkNOOP\r\n")
	harness.expectLine(t, "250 2.0.0 Message accepted\r\n")
	harness.expectLine(t, "503 5.5.1 Send MAIL first\r\n")
	harness.expectLine(t, "250 2.0.0 OK\r\n")

	if sink.finishCount() != 1 {
		t.Fatalf("finish count = %d, want one completed message", sink.finishCount())
	}
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
		reader := greetChunkingTransactionBackend(t, conn)
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
	config.BackendCapabilities = []string{capabilityCHUNKING}

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

// TestBackendMAILForwardsAccepted8BITMIMEParameter verifies deterministic backend MAIL parameters.
func TestBackendMAILForwardsAccepted8BITMIMEParameter(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{testRecipientSingle: testPlacementShardA})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{}
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := greetTransactionBackend(t, conn)
		expectLMTPBackendLine(t, reader, "MAIL FROM:<sender@example.test> SMTPUTF8 BODY=8BITMIME")
		writeLMTPBackendLine(t, conn, "250 2.1.0 sender ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<recipient@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.5 recipient ok")
		expectLMTPBackendLine(t, reader, "DATA")
		writeLMTPBackendLine(t, conn, "354 2.0.0 data")
		expectLMTPBackendLine(t, reader, "body")
		expectLMTPBackendLine(t, reader, ".")
		writeLMTPBackendLine(t, conn, "250 2.1.5 delivered")
	})
	config := backendForwardingSessionConfig(identity, resolver, store, selector, dialer)
	config.Capabilities = []string{capabilitySMTPUTF8, capability8BITMIME}
	config.BackendCapabilities = []string{capability8BITMIME}

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250-SMTPUTF8\r\n")
	harness.expectLine(t, "250 8BITMIME\r\n")
	harness.write(t, "MAIL FROM:<sender@example.test> BODY=8BITMIME SMTPUTF8\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<recipient@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "DATA\r\n")
	harness.expectLine(t, "354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	harness.write(t, "body\r\n.\r\n")
	harness.expectLine(t, "250 2.1.5 Message accepted\r\n")

	store.assertClosed(t, 1)
	dialer.Wait(t)
}

// TestBackendMAILForwardsAcceptedSIZEParameter verifies selected-backend SIZE proof and ordering.
func TestBackendMAILForwardsAcceptedSIZEParameter(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{testRecipientSingle: testPlacementShardA})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{}
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := greetSizedTransactionBackend(t, conn, "100")
		expectLMTPBackendLine(t, reader, "MAIL FROM:<"+testUnicodeSender+"> SMTPUTF8 BODY=8BITMIME SIZE=42")
		writeLMTPBackendLine(t, conn, "250 2.1.0 sender ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<recipient@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.5 recipient ok")
		expectLMTPBackendLine(t, reader, "DATA")
		writeLMTPBackendLine(t, conn, "354 2.0.0 data")
		expectLMTPBackendLine(t, reader, "body")
		expectLMTPBackendLine(t, reader, ".")
		writeLMTPBackendLine(t, conn, "250 2.1.5 delivered")
	})
	config := backendForwardingSessionConfig(identity, resolver, store, selector, dialer)
	config.Capabilities = []string{capabilitySMTPUTF8, capability8BITMIME, capabilitySIZE}
	config.BackendCapabilities = []string{capability8BITMIME}
	config.MaxMessageBytes = 100
	config.BackendSizeProof = &fakeBackendSizeProofReader{proof: backend.PoolSizeProof{Supported: true}}

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250-SMTPUTF8\r\n")
	harness.expectLine(t, "250-8BITMIME\r\n")
	harness.expectLine(t, "250 SIZE 100\r\n")
	harness.write(t, "MAIL FROM:<"+testUnicodeSender+"> SIZE=42 BODY=8BITMIME SMTPUTF8\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<recipient@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "DATA\r\n")
	harness.expectLine(t, "354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	harness.write(t, "body\r\n.\r\n")
	harness.expectLine(t, "250 2.1.5 Message accepted\r\n")

	store.assertClosed(t, 1)
	dialer.Wait(t)
}

// TestBackendMAILDoesNotSynthesizeSIZEWhenFrontendOmitted keeps backend MAIL declarative only.
func TestBackendMAILDoesNotSynthesizeSIZEWhenFrontendOmitted(t *testing.T) {
	identity := identityLookuperForRecipients(map[string]string{testRecipientSingle: testPlacementShardA})
	resolver := &recordingRoutingResolver{}
	store := &recordingDeliveryStore{}
	selector := &recordingBackendSelector{}
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := greetSizedTransactionBackend(t, conn, "100")
		expectLMTPBackendLine(t, reader, "MAIL FROM:<sender@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.0 sender ok")
		expectLMTPBackendLine(t, reader, "RCPT TO:<recipient@example.test>")
		writeLMTPBackendLine(t, conn, "250 2.1.5 recipient ok")
		expectLMTPBackendLine(t, reader, "DATA")
		writeLMTPBackendLine(t, conn, "354 2.0.0 data")
		expectLMTPBackendLine(t, reader, "body")
		expectLMTPBackendLine(t, reader, ".")
		writeLMTPBackendLine(t, conn, "250 2.1.5 delivered")
	})
	config := backendForwardingSessionConfig(identity, resolver, store, selector, dialer)
	config.Capabilities = []string{capabilitySIZE}
	config.MaxMessageBytes = 100
	config.BackendSizeProof = &fakeBackendSizeProofReader{proof: backend.PoolSizeProof{Supported: true}}

	harness := startLMTPHarness(t, config)
	harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
	harness.write(t, "LHLO submitter.example\r\n")
	harness.expectLine(t, "250-nauthilus-director\r\n")
	harness.expectLine(t, "250 SIZE 100\r\n")
	harness.write(t, "MAIL FROM:<sender@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
	harness.write(t, "RCPT TO:<recipient@example.test>\r\n")
	harness.expectLine(t, "250 2.0.0 Recipient accepted\r\n")
	harness.write(t, "DATA\r\n")
	harness.expectLine(t, "354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
	harness.write(t, "body\r\n.\r\n")
	harness.expectLine(t, "250 2.1.5 Message accepted\r\n")

	store.assertClosed(t, 1)
	dialer.Wait(t)
}

// TestSelectedBackendMissingSIZEFailsBeforeBackendMAIL protects stale pool-proof races.
func TestSelectedBackendMissingSIZEFailsBeforeBackendMAIL(t *testing.T) {
	testSelectedBackendSIZEFailure(t, "missing", func(t *testing.T, conn net.Conn) *bufio.Reader {
		return greetTransactionBackend(t, conn)
	})
}

// TestSelectedBackendLowerSIZEFailsBeforeBackendMAIL protects selected-backend limit races.
func TestSelectedBackendLowerSIZEFailsBeforeBackendMAIL(t *testing.T) {
	testSelectedBackendSIZEFailure(t, "lower maximum", func(t *testing.T, conn net.Conn) *bufio.Reader {
		return greetSizedTransactionBackend(t, conn, "5")
	})
}

// testSelectedBackendSIZEFailure exercises selected-backend SIZE proof mismatches.
func testSelectedBackendSIZEFailure(t *testing.T, name string, greet func(*testing.T, net.Conn) *bufio.Reader) {
	t.Helper()

	t.Run(name, func(t *testing.T) {
		identity := identityLookuperForRecipients(map[string]string{testRecipientSingle: testPlacementShardA})
		resolver := &recordingRoutingResolver{}
		store := &recordingDeliveryStore{}
		selector := &recordingBackendSelector{}
		dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
			reader := greet(t, conn)
			assertNoBackendMAILBeforeClose(t, conn, reader)
		})
		config := backendForwardingSessionConfig(identity, resolver, store, selector, dialer)
		config.Capabilities = []string{capabilitySIZE}
		config.MaxMessageBytes = 10
		config.BackendSizeProof = &fakeBackendSizeProofReader{proof: backend.PoolSizeProof{Supported: true}}

		harness := startLMTPHarness(t, config)
		harness.expectLine(t, "220 2.0.0 nauthilus-director LMTP ready\r\n")
		harness.write(t, "LHLO submitter.example\r\n")
		harness.expectLine(t, "250-nauthilus-director\r\n")
		harness.expectLine(t, "250 SIZE 10\r\n")
		harness.write(t, "MAIL FROM:<sender@example.test> SIZE=6\r\n")
		harness.expectLine(t, "250 2.0.0 Sender accepted\r\n")
		harness.write(t, "RCPT TO:<recipient@example.test>\r\n")
		harness.expectLine(t, testTemporaryDelivery)

		store.assertClosed(t, 1)
		dialer.Wait(t)
	})
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
	config.BackendCapabilities = []string{capabilityCHUNKING}

	return config
}

// test8BITMIMEConfig returns a session config where BODY=8BITMIME is safe to advertise.
func test8BITMIMEConfig() SessionConfig {
	config := testSessionConfig()
	config.TLSMode = TLSModeImplicit
	config.Capabilities = []string{capability8BITMIME}
	config.BackendCapabilities = []string{capability8BITMIME}

	return config
}

// testPipeliningConfig returns a session config where PIPELINING is advertised.
func testPipeliningConfig() SessionConfig {
	config := testSessionConfig()
	config.TLSMode = TLSModeImplicit
	config.Capabilities = []string{capabilityPIPELINING}

	return config
}

// testSIZEConfig returns a session config where SIZE can be proven safe.
func testSIZEConfig(maxMessageBytes int64, proof backend.PoolSizeProof) SessionConfig {
	config := testSessionConfig()
	config.TLSMode = TLSModeImplicit
	config.Capabilities = []string{capabilitySIZE}
	config.MaxMessageBytes = maxMessageBytes
	config.BackendSizeProof = &fakeBackendSizeProofReader{proof: proof}

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
	if recordingStore, ok := store.(*recordingDeliveryStore); ok {
		if recordingSelector, ok := selector.(*recordingBackendSelector); ok {
			config.PlacementService = mustLMTPPlacementService(recordingStore, recordingSelector)
		}
	}

	return config
}

// mustLMTPPlacementService creates the shared placement service used by LMTP tests.
func mustLMTPPlacementService(store *recordingDeliveryStore, selector *recordingBackendSelector) placement.DeliveryPlacer {
	service, err := placement.NewService(lmtpBackendRegistry{}, selector, store)
	if err != nil {
		panic(err)
	}

	return service
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

// greetChunkingTransactionBackend runs the common backend handshake with CHUNKING proof.
func greetChunkingTransactionBackend(t *testing.T, conn net.Conn) *bufio.Reader {
	t.Helper()

	reader := bufio.NewReader(conn)
	writeLMTPBackendLine(t, conn, "220 backend ready")
	expectLMTPBackendLine(t, reader, "LHLO "+backendLHLOName)
	writeLMTPBackendLine(t, conn, "250-mailstore")
	writeLMTPBackendLine(t, conn, "250 CHUNKING")

	return reader
}

// greetSizedTransactionBackend runs the common backend handshake with SIZE proof.
func greetSizedTransactionBackend(t *testing.T, conn net.Conn, maximum string) *bufio.Reader {
	t.Helper()

	reader := bufio.NewReader(conn)
	writeLMTPBackendLine(t, conn, "220 backend ready")
	expectLMTPBackendLine(t, reader, "LHLO "+backendLHLOName)
	writeLMTPBackendLine(t, conn, "250-mailstore")
	writeLMTPBackendLine(t, conn, "250 SIZE "+maximum)

	return reader
}

// greetChunkingSizedTransactionBackend runs the common backend handshake with CHUNKING and SIZE proof.
func greetChunkingSizedTransactionBackend(t *testing.T, conn net.Conn, maximum string) *bufio.Reader {
	t.Helper()

	reader := bufio.NewReader(conn)
	writeLMTPBackendLine(t, conn, "220 backend ready")
	expectLMTPBackendLine(t, reader, "LHLO "+backendLHLOName)
	writeLMTPBackendLine(t, conn, "250-mailstore")
	writeLMTPBackendLine(t, conn, "250-"+capabilityCHUNKING)
	writeLMTPBackendLine(t, conn, "250 SIZE "+maximum)

	return reader
}

// assertNoBackendMAILBeforeClose proves selected-backend SIZE failure happened pre-envelope.
func assertNoBackendMAILBeforeClose(t *testing.T, conn net.Conn, reader *bufio.Reader) {
	t.Helper()

	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set backend read deadline: %v", err)
	}

	line, err := reader.ReadString('\n')
	if err == nil {
		t.Fatalf("backend received unexpected command before SIZE failure: %q", strings.TrimRight(line, "\r\n"))
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatal("backend stream was not closed after selected-backend SIZE failure")
	}
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

type fakeBackendSizeProofReader struct {
	proof backend.PoolSizeProof
	err   error
	calls int
}

// PoolSupportsSize returns fixed backend-pool SIZE proof for frontend tests.
func (r *fakeBackendSizeProofReader) PoolSupportsSize(context.Context, string) (backend.PoolSizeProof, error) {
	r.calls++

	return r.proof, r.err
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

// enableBackendProxy marks a selected test backend as PROXY-enabled.
func enableBackendProxy(target *backend.Backend) {
	target.HAProxy.Enabled = true
}

type recordingLMTPBackendConnector struct {
	mu       sync.Mutex
	requests []backend.ConnectRequest
	err      error
}

// Connect records backend request metadata and returns a minimal envelope-capable stream.
func (c *recordingLMTPBackendConnector) Connect(_ context.Context, request backend.ConnectRequest) (*BackendConnection, error) {
	c.mu.Lock()
	c.requests = append(c.requests, request)
	c.mu.Unlock()

	if c.err != nil {
		return nil, c.err
	}

	client, server := net.Pipe()
	connection := newBackendConnection(client)
	connection.capabilities = backend.NewCapabilitySet(capabilityCHUNKING)

	go serveMinimalLMTPEnvelopeBackend(server)

	return connection, nil
}

// singleRequest returns the only recorded backend connect request.
func (c *recordingLMTPBackendConnector) singleRequest(t *testing.T) backend.ConnectRequest {
	t.Helper()

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.requests) != 1 {
		t.Fatalf("backend connect requests = %d, want 1", len(c.requests))
	}

	return c.requests[0]
}

// requestCount returns how often backend connection setup was attempted.
func (c *recordingLMTPBackendConnector) requestCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.requests)
}

// serveMinimalLMTPEnvelopeBackend accepts MAIL and RCPT before waiting for close.
func serveMinimalLMTPEnvelopeBackend(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}

		upper := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(upper, "MAIL FROM:"):
			_, _ = io.WriteString(conn, "250 2.1.0 sender ok\r\n")
		case strings.HasPrefix(upper, "RCPT TO:"):
			_, _ = io.WriteString(conn, "250 2.1.5 recipient ok\r\n")
			_, _ = io.Copy(io.Discard, reader)

			return
		}
	}
}

type recordingLMTPFailureDialer struct {
	conn *recordingLMTPFailureConn
}

// DialContext returns the configured backend connection for fail-closed tests.
func (d *recordingLMTPFailureDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return d.conn, nil
}

type recordingLMTPFailureConn struct {
	local    net.Addr
	remote   net.Addr
	writeErr error
	closed   bool
	writes   int
}

// Read returns EOF if protocol negotiation accidentally continues.
func (c *recordingLMTPFailureConn) Read([]byte) (int, error) {
	return 0, io.EOF
}

// Write records backend writes and can fail the PROXY preface.
func (c *recordingLMTPFailureConn) Write([]byte) (int, error) {
	c.writes++
	if c.writeErr != nil {
		return 0, c.writeErr
	}

	return 0, io.ErrClosedPipe
}

// Close records backend stream closure.
func (c *recordingLMTPFailureConn) Close() error {
	c.closed = true

	return nil
}

// LocalAddr returns the configured Director-side backend socket address.
func (c *recordingLMTPFailureConn) LocalAddr() net.Addr {
	return c.local
}

// RemoteAddr returns the configured backend-side socket address.
func (c *recordingLMTPFailureConn) RemoteAddr() net.Addr {
	return c.remote
}

// SetDeadline accepts connector deadline calls.
func (c *recordingLMTPFailureConn) SetDeadline(time.Time) error {
	return nil
}

// SetReadDeadline accepts connector read deadline calls.
func (c *recordingLMTPFailureConn) SetReadDeadline(time.Time) error {
	return nil
}

// SetWriteDeadline accepts connector write deadline calls.
func (c *recordingLMTPFailureConn) SetWriteDeadline(time.Time) error {
	return nil
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
	releaseCalls int
	affinity     state.AffinityRecord
	backendPin   state.UserBackendPinRecord
	pinReads     int
	pinErr       error
	attachErr    error
}

// OpenSession records a delivery hold and returns an active affinity record.
func (s *recordingDeliveryStore) OpenSession(_ context.Context, record state.SessionRecord) (state.AffinityRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.opens = append(s.opens, record)

	if s.affinity.Present && strings.TrimSpace(s.affinity.BackendNode) != "" && strings.TrimSpace(s.affinity.BackendNode) != strings.TrimSpace(record.BackendNode) {
		affinity := s.affinity
		affinity.Key = record.Key
		affinity.Status = "backend_node_mismatch"
		affinity.BindingStatus = state.BindingStatusBackendNodeMismatch

		return affinity, nil
	}

	status := deliveryStatusCreated
	if s.affinity.Present {
		status = "reused"
		if s.affinity.Status == "retained" || s.affinity.BindingStatus == state.BindingStatusRetained {
			status = "retained"
		}
	}

	activeSessionCount := 0
	if record.HolderKind == state.HolderKindSession {
		activeSessionCount = 1
	}

	return state.AffinityRecord{
		Key:                record.Key,
		ShardTag:           record.ShardTag,
		BackendNode:        record.BackendNode,
		Status:             status,
		Present:            true,
		ActiveSessionCount: activeSessionCount,
		ActiveHolderCount:  1,
		BindingStatus:      state.BindingStatusActive,
	}, nil
}

// LookupAffinity records a read-only affinity lookup for recipient placement.
func (s *recordingDeliveryStore) LookupAffinity(_ context.Context, key state.AffinityKey) (state.AffinityRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.affinity.Present {
		affinity := s.affinity
		affinity.Key = key

		return affinity, nil
	}

	return state.AffinityRecord{Key: key, BindingStatus: state.BindingStatusNone}, nil
}

// GetUserBackendPin records a read-only backend-pin lookup for placement tests.
func (s *recordingDeliveryStore) GetUserBackendPin(
	_ context.Context,
	request state.UserBackendPinGetRequest,
) (state.UserBackendPinRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.pinReads++
	if s.backendPin.Key == (state.AffinityKey{}) {
		s.backendPin.Key = request.Key
	}

	return s.backendPin, s.pinErr
}

// setBackendPin changes the fake backend-pin read model during gate-release tests.
func (s *recordingDeliveryStore) setBackendPin(record state.UserBackendPinRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.backendPin = record
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
	s.mu.Lock()
	defer s.mu.Unlock()

	s.releaseCalls++

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
	if s.attachErr != nil {
		return state.SessionBackendRecord{}, s.attachErr
	}

	return state.SessionBackendRecord{
		Status:             "attached",
		BackendIdentifier:  attachment.BackendIdentifier,
		BackendNode:        attachment.BackendNode,
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

// openAt returns a recorded open call by zero-based index.
func (s *recordingDeliveryStore) openAt(t *testing.T, index int) state.SessionRecord {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	if index < 0 || index >= len(s.opens) {
		t.Fatalf("open index %d outside %d recorded calls", index, len(s.opens))
	}

	return s.opens[index]
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

// assertReserved verifies the number of backend capacity reservations.
func (s *recordingDeliveryStore) assertReserved(t *testing.T, want int) {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.reservations) != want {
		t.Fatalf("reservation calls = %d, want %d", len(s.reservations), want)
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

// assertReleased verifies the number of backend reservation rollback releases.
func (s *recordingDeliveryStore) assertReleased(t *testing.T, want int) {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.releaseCalls != want {
		t.Fatalf("reservation release calls = %d, want %d", s.releaseCalls, want)
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

// waitClosed waits for asynchronous disconnect cleanup to close delivery holds.
func (s *recordingDeliveryStore) waitClosed(t *testing.T, want int) {
	t.Helper()

	deadline := time.Now().Add(time.Second)

	for {
		s.mu.Lock()
		got := len(s.closes)
		s.mu.Unlock()

		if got == want {
			return
		}

		if time.Now().After(deadline) {
			t.Fatalf("close calls = %d, want %d", got, want)
		}

		time.Sleep(10 * time.Millisecond)
	}
}

// backendPinReads returns the number of backend-pin read attempts.
func (s *recordingDeliveryStore) backendPinReads() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.pinReads
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
	mu                sync.Mutex
	requests          []backend.SelectionRequest
	nodeRequests      []backend.NodeSelectionRequest
	backendForShard   map[string]string
	backendForAccount map[string]string
	configureBackend  func(*backend.Backend)
}

type recordingRecipientPlacementGate struct {
	calls   int
	request runtimectl.PlacementGateRequest
	result  runtimectl.PlacementGateResult
	err     error
	wait    func(context.Context, runtimectl.PlacementGateRequest) (runtimectl.PlacementGateResult, error)
}

// Select records backend selection and returns a deterministic LMTP backend.
func (s *recordingBackendSelector) Select(_ context.Context, request backend.SelectionRequest) (backend.SelectionResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.requests = append(s.requests, request)

	identifier := "mailstore-a-lmtp"
	if request.PinnedBackendIdentifier != "" {
		identifier = request.PinnedBackendIdentifier
	} else if s.backendForAccount != nil && s.backendForAccount[request.AccountKey] != "" {
		identifier = s.backendForAccount[request.AccountKey]
	} else if s.backendForShard != nil && s.backendForShard[request.ShardTag] != "" {
		identifier = s.backendForShard[request.ShardTag]
	}

	selected := backend.Backend{
		Identifier:     identifier,
		Protocol:       request.Protocol,
		BackendPool:    request.BackendPool,
		ShardTag:       request.ShardTag,
		BackendNode:    lmtpBackendNode(identifier, request.ShardTag),
		Address:        testBackendTLSHostTarget,
		TLS:            backend.TLSConfig{Mode: backendTLSPlaintext, MinTLSVersion: backendTLSMinDefault},
		Auth:           backend.AuthConfig{Mode: backendAuthModeNone},
		MaxConnections: 100,
	}
	if s.configureBackend != nil {
		s.configureBackend(&selected)
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

// SelectInBackendNode records backend-node constrained selection input.
func (s *recordingBackendSelector) SelectInBackendNode(_ context.Context, request backend.NodeSelectionRequest) (backend.SelectionResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.nodeRequests = append(s.nodeRequests, request)

	identifier := request.OperatorBackendIdentifier
	if identifier == "" {
		identifier = lmtpBackendForNode(request.BackendNode)
	}

	s.requests = append(s.requests, backend.SelectionRequest{
		AccountKey:                request.AccountKey,
		Tenant:                    request.Tenant,
		ShardTag:                  request.ShardTag,
		Protocol:                  request.Protocol,
		BackendPool:               request.BackendPool,
		ActiveAffinity:            true,
		PinnedBackendIdentifier:   identifier,
		OperatorBackendIdentifier: request.OperatorBackendIdentifier,
	})

	selected := backend.Backend{
		Identifier:     identifier,
		Protocol:       request.Protocol,
		BackendPool:    request.BackendPool,
		ShardTag:       request.ShardTag,
		BackendNode:    request.BackendNode,
		Address:        testBackendTLSHostTarget,
		TLS:            backend.TLSConfig{Mode: backendTLSPlaintext, MinTLSVersion: backendTLSMinDefault},
		Auth:           backend.AuthConfig{Mode: backendAuthModeNone},
		MaxConnections: 100,
	}
	if s.configureBackend != nil {
		s.configureBackend(&selected)
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
		Reason:         backend.SelectionReasonBackendBinding,
		ActiveAffinity: true,
	}, nil
}

// WaitForPlacement records the shared recipient hold gate request.
func (g *recordingRecipientPlacementGate) WaitForPlacement(
	ctx context.Context,
	request runtimectl.PlacementGateRequest,
) (runtimectl.PlacementGateResult, error) {
	g.calls++
	g.request = request
	if g.wait != nil {
		return g.wait(ctx, request)
	}

	return g.result, g.err
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

// firstNodeRequest returns the first backend-node constrained selector request.
func (s *recordingBackendSelector) firstNodeRequest(t *testing.T) backend.NodeSelectionRequest {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.nodeRequests) == 0 {
		t.Fatal("backend-node selector was not called")
	}

	return s.nodeRequests[0]
}

// requestCount returns how often the selector was called.
func (s *recordingBackendSelector) requestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.requests)
}

// lmtpBackendNode returns the deterministic backend-node fixture for one backend.
func lmtpBackendNode(identifier string, shardTag string) string {
	if identifier == testPlacementBackendA2 {
		return "mailstore-a-node-2"
	}

	if strings.Contains(identifier, "mailstore-b") || strings.TrimSpace(shardTag) == testPlacementShardB {
		return "mailstore-b-node-1"
	}

	return "mailstore-a-node-1"
}

// lmtpBackendForNode returns the LMTP backend fixture inside one backend node.
func lmtpBackendForNode(backendNode string) string {
	if backendNode == "mailstore-a-node-2" {
		return testPlacementBackendA2
	}

	if backendNode == "mailstore-b-node-1" {
		return testPlacementBackendB
	}

	return "mailstore-a-lmtp"
}

// lmtpBackendRegistry supplies backend lookup facts for placement tests.
type lmtpBackendRegistry struct{}

// AllBackends returns the configured fake backend inventory.
func (lmtpBackendRegistry) AllBackends(context.Context) ([]backend.Backend, error) {
	return []backend.Backend{
		lmtpRegistryBackend("mailstore-a-lmtp", testPlacementShardA),
		lmtpRegistryBackend(testPlacementBackendA2, testPlacementShardA),
		lmtpRegistryBackend(testPlacementBackendB, testPlacementShardB),
	}, nil
}

// BackendsForShard returns fake backends matching one shard.
func (lmtpBackendRegistry) BackendsForShard(_ context.Context, request backend.RegistryRequest) ([]backend.Backend, error) {
	backends := []backend.Backend{}

	for _, candidate := range []backend.Backend{
		lmtpRegistryBackend("mailstore-a-lmtp", testPlacementShardA),
		lmtpRegistryBackend(testPlacementBackendA2, testPlacementShardA),
		lmtpRegistryBackend(testPlacementBackendB, testPlacementShardB),
	} {
		if candidate.Protocol == request.Protocol && candidate.BackendPool == request.BackendPool && candidate.ShardTag == request.ShardTag {
			backends = append(backends, candidate)
		}
	}

	if len(backends) == 0 {
		return nil, &backend.Error{Kind: backend.ErrorKindNoBackend, Operation: "test_registry", Message: "no shard backend"}
	}

	return backends, nil
}

// Lookup returns one fake backend by identifier.
func (lmtpBackendRegistry) Lookup(_ context.Context, identifier string) (backend.Backend, error) {
	if identifier == testPlacementBackendB {
		return lmtpRegistryBackend(identifier, testPlacementShardB), nil
	}

	if identifier == testPlacementBackendA2 {
		return lmtpRegistryBackend(identifier, testPlacementShardA), nil
	}

	return lmtpRegistryBackend(identifier, testPlacementShardA), nil
}

// LookupInBackendNode resolves the fake LMTP endpoint inside a backend node.
func (lmtpBackendRegistry) LookupInBackendNode(_ context.Context, request backend.NodeLookupRequest) (backend.Backend, error) {
	if request.BackendNode == "mailstore-b-node-1" {
		return lmtpRegistryBackend(testPlacementBackendB, testPlacementShardB), nil
	}

	return lmtpRegistryBackend("mailstore-a-lmtp", testPlacementShardA), nil
}

// Pool returns the fake LMTP backend pool.
func (lmtpBackendRegistry) Pool(_ context.Context, name string) (backend.Pool, error) {
	return backend.Pool{Name: name, Protocol: protocolLMTP, Selector: "recipient_hash", Backends: []string{"mailstore-a-lmtp", testPlacementBackendA2, testPlacementBackendB}}, nil
}

// lmtpRegistryBackend creates a fake registry backend with node metadata.
func lmtpRegistryBackend(identifier string, shardTag string) backend.Backend {
	return backend.Backend{
		Identifier:     identifier,
		Protocol:       protocolLMTP,
		BackendPool:    testPlacementPool,
		ShardTag:       shardTag,
		BackendNode:    lmtpBackendNode(identifier, shardTag),
		Address:        testBackendTLSHostTarget,
		MaxConnections: 100,
	}
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

// callCount returns how many password auth requests were recorded.
func (a *recordingAuthenticator) callCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()

	return len(a.requests)
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

type recordingBearerIntrospector struct {
	mu       sync.Mutex
	requests []nauthilus.BearerIntrospectionRequest
	result   nauthilus.AuthResult
	err      error
}

// Introspect records the request and returns a deterministic success by default.
func (i *recordingBearerIntrospector) Introspect(_ context.Context, request nauthilus.BearerIntrospectionRequest) (nauthilus.AuthResult, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	i.requests = append(i.requests, request)
	if i.err != nil {
		return nauthilus.AuthResult{Decision: nauthilus.DecisionTemporaryFailure}, i.err
	}

	if i.result.Decision != "" {
		return i.result, nil
	}

	return nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: request.Context.Username}, nil
}

// callCount returns how many introspection requests were recorded.
func (i *recordingBearerIntrospector) callCount() int {
	i.mu.Lock()
	defer i.mu.Unlock()

	return len(i.requests)
}

// singleRequest returns the only recorded introspection request.
func (i *recordingBearerIntrospector) singleRequest(t *testing.T) nauthilus.BearerIntrospectionRequest {
	t.Helper()

	i.mu.Lock()
	defer i.mu.Unlock()

	if len(i.requests) != 1 {
		t.Fatalf("introspection requests = %d, want 1", len(i.requests))
	}

	return i.requests[0]
}

type recordingMessageSink struct {
	mu        sync.Mutex
	body      strings.Builder
	max       int
	finish    int
	abort     int
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
	s.mu.Lock()
	defer s.mu.Unlock()

	s.abort++

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

// abortCount returns the number of aborted messages.
func (s *recordingMessageSink) abortCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.abort
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

// oauthBearerPayload builds a base64 OAUTHBEARER envelope.
func oauthBearerPayload(username string, token string) string {
	payload := "n,a=" + username + ",\x01auth=Bearer " + token + "\x01\x01"

	return base64.StdEncoding.EncodeToString([]byte(payload))
}

// assertNoSecretLeak fails if an error string contains raw secret material.
func assertNoSecretLeak(t *testing.T, value string, secret string) {
	t.Helper()

	if strings.Contains(value, secret) {
		t.Fatalf("value %q leaked secret %q", value, secret)
	}
}
