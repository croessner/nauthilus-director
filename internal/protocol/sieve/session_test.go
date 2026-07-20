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

//nolint:dupl,funlen,goconst,gocyclo,wsl_v5 // ManageSieve wire tests keep transcripts inline for review.
package sieve

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/placement"
	"github.com/croessner/nauthilus-director/internal/protocol/certauth"
	"github.com/croessner/nauthilus-director/internal/protocol/greeting"
	"github.com/croessner/nauthilus-director/internal/protocol/saslcred"
	"github.com/croessner/nauthilus-director/internal/proxy"
	"github.com/croessner/nauthilus-director/internal/routing"
	runtimectl "github.com/croessner/nauthilus-director/internal/runtime"
	"github.com/croessner/nauthilus-director/internal/state"
)

// TestExternalCapabilityRequiresVerifiedClientCertificate proves ManageSieve advertises EXTERNAL truthfully.
func TestExternalCapabilityRequiresVerifiedClientCertificate(t *testing.T) {
	config := testSessionConfig(TLSModeImplicit, nil)
	config.AuthMechanisms = append(config.AuthMechanisms, saslcred.MechanismExternal)
	leaf := &x509.Certificate{EmailAddresses: []string{"cert@example.test"}}
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	session, err := NewSession(config, stateConn{Conn: server, state: tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf}},
	}})
	if err != nil {
		t.Fatalf("NewSession returned error: %v", err)
	}

	if !slices.Contains(session.effectiveSASLMechanisms(), "EXTERNAL") {
		t.Fatalf("SASL mechanisms = %v, want EXTERNAL", session.effectiveSASLMechanisms())
	}

	session.conn = stateConn{Conn: server, state: tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}}
	if slices.Contains(session.effectiveSASLMechanisms(), "EXTERNAL") {
		t.Fatalf("SASL mechanisms = %v, EXTERNAL must require verification", session.effectiveSASLMechanisms())
	}
}

const (
	testGreetingImplementation = "\"IMPLEMENTATION\" \"nauthilus-director test\"\r\n"
	testGreetingVersion        = "\"VERSION\" \"1.0\"\r\n"
	testGreetingSieve          = "\"SIEVE\" \"fileinto reject\"\r\n"
	testGreetingLanguage       = "\"LANGUAGE\" \"en\"\r\n"
	testGreetingStartTLS       = "\"STARTTLS\"\r\n"
	testGreetingSASLClear      = "\"SASL\" \"\"\r\n"
	testGreetingSASLTLS        = "\"SASL\" \"PLAIN XOAUTH2 OAUTHBEARER\"\r\n"
	testGreetingOK             = "OK\r\n"
)

// TestImplementationCapabilityUsesProcessVersion verifies RFC 5804 IMPLEMENTATION facts stay internal.
func TestImplementationCapabilityUsesProcessVersion(t *testing.T) {
	if got := ImplementationCapability("  v1.2.3\nbuild "); got != "nauthilus-director v1.2.3 build" {
		t.Fatalf("implementation = %q, want product name plus normalized version", got)
	}

	if got := ImplementationCapability(" "); got != ImplementationName {
		t.Fatalf("implementation fallback = %q, want product name", got)
	}
}

// TestGreetingPolicyControlsImplementationDisclosure verifies Sieve identity policy rendering.
func TestGreetingPolicyControlsImplementationDisclosure(t *testing.T) {
	tests := []struct {
		name           string
		displayName    string
		disclosure     greeting.SoftwareVersionDisclosure
		implementation string
	}{
		{
			name:           "default",
			displayName:    ImplementationName,
			disclosure:     greeting.DisclosureDefault,
			implementation: "\"IMPLEMENTATION\" \"nauthilus-director test\"\r\n",
		},
		{
			name:           "suppress",
			displayName:    ImplementationName,
			disclosure:     greeting.DisclosureSuppress,
			implementation: "\"IMPLEMENTATION\" \"nauthilus-director\"\r\n",
		},
		{
			name:           "include",
			displayName:    ImplementationName,
			disclosure:     greeting.DisclosureInclude,
			implementation: "\"IMPLEMENTATION\" \"nauthilus-director test\"\r\n",
		},
		{
			name:           "custom default",
			displayName:    "Norbert",
			disclosure:     greeting.DisclosureDefault,
			implementation: "\"IMPLEMENTATION\" \"Norbert test\"\r\n",
		},
		{
			name:           "custom suppress",
			displayName:    "Norbert",
			disclosure:     greeting.DisclosureSuppress,
			implementation: "\"IMPLEMENTATION\" \"Norbert\"\r\n",
		},
		{
			name:           "custom include",
			displayName:    "Norbert",
			disclosure:     greeting.DisclosureInclude,
			implementation: "\"IMPLEMENTATION\" \"Norbert test\"\r\n",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			config := testSessionConfig(TLSModeImplicit, nil)
			config.GreetingPolicy = testGreetingPolicy(t, testCase.displayName, "test", testCase.disclosure)
			harness := startSieveHarness(t, config)
			harness.expectGreeting(t,
				testCase.implementation,
				testGreetingVersion,
				testGreetingSieve,
				testGreetingLanguage,
				testGreetingSASLTLS,
				testGreetingOK,
			)
		})
	}
}

// TestGreetingPolicyWithoutVersionKeepsProtocolVersion verifies include cannot publish an empty process version.
func TestGreetingPolicyWithoutVersionKeepsProtocolVersion(t *testing.T) {
	config := testSessionConfig(TLSModeImplicit, nil)
	config.GreetingPolicy = testGreetingPolicy(t, "Norbert", " \n\t ", greeting.DisclosureInclude)
	harness := startSieveHarness(t, config)
	harness.expectGreeting(t,
		"\"IMPLEMENTATION\" \"Norbert\"\r\n",
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		testGreetingSASLTLS,
		testGreetingOK,
	)
}

// TestCapabilitiesReturnsDetachedFacts verifies callers cannot mutate handler capability state.
func TestCapabilitiesReturnsDetachedFacts(t *testing.T) {
	handler := NewHandler(testSessionConfig(TLSModeStartTLS, nil))

	capabilities := handler.Capabilities()
	capabilities.ScriptExtensions[0] = "mutated"

	if got := handler.Capabilities().ScriptExtensions[0]; got != "fileinto" {
		t.Fatalf("handler capability extension = %q, want detached immutable value", got)
	}
}

// TestGreetingRendersRequiredCapabilities verifies the initial greeting is truthful and bounded.
func TestGreetingRendersRequiredCapabilities(t *testing.T) {
	cleartext := startSieveHarness(t, testSessionConfig(TLSModeStartTLS, nil))
	cleartext.expectGreeting(t,
		testGreetingImplementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		testGreetingStartTLS,
		testGreetingSASLClear,
		testGreetingOK,
	)

	implicit := startSieveHarness(t, testSessionConfig(TLSModeImplicit, nil))
	implicit.expectGreeting(t,
		testGreetingImplementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		testGreetingSASLTLS,
		testGreetingOK,
	)
}

// TestCapabilityChangesAfterStartTLS verifies STARTTLS is removed and SASL is exposed after TLS.
func TestCapabilityChangesAfterStartTLS(t *testing.T) {
	harness := startSieveHarness(t, testSessionConfig(TLSModeStartTLS, nil))
	harness.expectGreeting(t,
		testGreetingImplementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		testGreetingStartTLS,
		testGreetingSASLClear,
		testGreetingOK,
	)

	harness.write(t, "CAPABILITY\r\n")
	harness.expectLines(t,
		testGreetingImplementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		testGreetingStartTLS,
		testGreetingSASLClear,
		"OK \"Capability completed\"\r\n",
	)

	harness.write(t, "STARTTLS\r\n")
	harness.expectLine(t, "OK \"Begin TLS negotiation now\"\r\n")
	harness.expectLines(t,
		testGreetingImplementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		testGreetingSASLTLS,
		testGreetingOK,
	)

	if !harness.session.TLSActive() {
		t.Fatal("STARTTLS did not mark the session TLS-active")
	}

	harness.write(t, "CAPABILITY\r\n")
	harness.expectLines(t,
		testGreetingImplementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		testGreetingSASLTLS,
		"OK \"Capability completed\"\r\n",
	)
}

// TestCapabilityRefreshAfterStartTLSKeepsGreetingPolicy verifies STARTTLS does not reset identity policy.
func TestCapabilityRefreshAfterStartTLSKeepsGreetingPolicy(t *testing.T) {
	implementation := "\"IMPLEMENTATION\" \"Norbert\"\r\n"
	config := testSessionConfig(TLSModeStartTLS, nil)
	config.GreetingPolicy = testGreetingPolicy(t, "Norbert", "test", greeting.DisclosureSuppress)
	harness := startSieveHarness(t, config)
	harness.expectGreeting(t,
		implementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		testGreetingStartTLS,
		testGreetingSASLClear,
		testGreetingOK,
	)

	harness.write(t, "STARTTLS\r\n")
	harness.expectLine(t, "OK \"Begin TLS negotiation now\"\r\n")
	harness.expectLines(t,
		implementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		testGreetingSASLTLS,
		testGreetingOK,
	)

	harness.write(t, "CAPABILITY\r\n")
	harness.expectLines(t,
		implementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		testGreetingSASLTLS,
		"OK \"Capability completed\"\r\n",
	)
}

// TestStartTLSRejectsUnavailableAndPipelinedBytes verifies STARTTLS sequencing is fail-closed.
func TestStartTLSRejectsUnavailableAndPipelinedBytes(t *testing.T) {
	implicit := startSieveHarness(t, testSessionConfig(TLSModeImplicit, nil))
	implicit.expectGreeting(t,
		testGreetingImplementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		testGreetingSASLTLS,
		testGreetingOK,
	)
	implicit.write(t, "STARTTLS\r\n")
	implicit.expectLine(t, "NO (CLIENT-BUG) \"STARTTLS is not available\"\r\n")

	pipelined := startSieveHarness(t, testSessionConfig(TLSModeStartTLS, nil))
	pipelined.expectGreeting(t,
		testGreetingImplementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		testGreetingStartTLS,
		testGreetingSASLClear,
		testGreetingOK,
	)
	pipelined.write(t, "STARTTLS\r\nNOOP\r\n")
	pipelined.expectLine(t, "NO (CLIENT-BUG) \""+startTLSInjectionMessage+"\"\r\n")
	pipelined.expectDone(t)

	if pipelined.session.TLSActive() {
		t.Fatal("pipelined STARTTLS marked the session TLS-active")
	}
}

// TestCredentialAuthRequiresTLSBeforeNauthilus verifies plaintext credentials fail closed locally.
func TestCredentialAuthRequiresTLSBeforeNauthilus(t *testing.T) {
	authenticator := &recordingAuthenticator{}
	introspector := &recordingBearerIntrospector{}
	config := testSessionConfig(TLSModeStartTLS, authenticator)
	config.BearerIntrospector = introspector
	harness := startSieveHarness(t, config)
	harness.expectGreeting(t,
		testGreetingImplementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		testGreetingStartTLS,
		testGreetingSASLClear,
		testGreetingOK,
	)

	harness.write(t, "AUTHENTICATE \"PLAIN\" \""+plainPayload("alice@example.test", "plain-secret")+"\"\r\n")
	harness.expectLine(t, "NO (ENCRYPT-NEEDED) \"TLS is required before authentication\"\r\n")
	harness.write(t, "AUTHENTICATE \"XOAUTH2\" \""+xoauth2Payload("alice@example.test", "token-before-tls")+"\"\r\n")
	harness.expectLine(t, "NO (ENCRYPT-NEEDED) \"TLS is required before authentication\"\r\n")

	if got := authenticator.callCount(); got != 0 {
		t.Fatalf("Nauthilus calls = %d, want 0 before TLS", got)
	}
	if got := introspector.callCount(); got != 0 {
		t.Fatalf("introspection calls = %d, want 0 before TLS", got)
	}
}

// TestAuthenticateMechanismShapes verifies supported SASL mechanisms and initial responses parse.
func TestAuthenticateMechanismShapes(t *testing.T) {
	tests := []struct {
		command  string
		method   string
		username string
		secret   string
		bearer   bool
	}{
		{
			command:  "AUTHENTICATE \"PLAIN\" \"" + plainPayload("plain-user@example.test", "plain-passphrase") + "\"\r\n",
			method:   "plain",
			username: "plain-user@example.test",
			secret:   "plain-passphrase",
		},
		{
			command:  "AUTHENTICATE \"XOAUTH2\" \"" + xoauth2Payload("xoauth2-user@example.test", "xoauth2-token") + "\"\r\n",
			method:   "xoauth2",
			username: "xoauth2-user@example.test",
			secret:   "xoauth2-token",
			bearer:   true,
		},
		{
			command:  "AUTHENTICATE \"OAUTHBEARER\" \"" + oauthBearerPayload("oauth-user@example.test", "oauth-token") + "\"\r\n",
			method:   "oauthbearer",
			username: "oauth-user@example.test",
			secret:   "oauth-token",
			bearer:   true,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.method, func(t *testing.T) {
			authenticator := &recordingAuthenticator{
				result: nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: "alice@example.test"},
			}
			introspector := &recordingBearerIntrospector{
				result: nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: "alice@example.test"},
			}
			placer := &recordingSessionPlacer{}
			config := testPlacementSessionConfig(TLSModeImplicit, authenticator, nil, placer)
			config.BearerIntrospector = introspector
			harness := startSieveHarness(t, config)
			harness.expectGreeting(t,
				testGreetingImplementation,
				testGreetingVersion,
				testGreetingSieve,
				testGreetingLanguage,
				testGreetingSASLTLS,
				testGreetingOK,
			)

			harness.write(t, testCase.command)
			harness.expectAuthenticatedCapability(t, "alice@example.test")
			harness.expectDone(t)

			if testCase.bearer {
				if authenticator.callCount() != 0 {
					t.Fatalf("password auth calls = %d, want 0", authenticator.callCount())
				}

				request := introspector.singleRequest(t)
				if request.Context.Protocol != protocolSieve || request.Context.Method != testCase.method {
					t.Fatalf("introspection context protocol/method mismatch: got %q/%q, want sieve/%s", request.Context.Protocol, request.Context.Method, testCase.method)
				}

				if request.Context.Username != testCase.username || request.BearerToken.Value() != testCase.secret {
					t.Fatal("introspection credential did not match parsed username and secret")
				}
			} else {
				if introspector.callCount() != 0 {
					t.Fatalf("introspection calls = %d, want 0", introspector.callCount())
				}

				request := authenticator.singleRequest(t)
				if request.Context.Protocol != protocolSieve || request.Context.Method != testCase.method {
					t.Fatalf("request context protocol/method mismatch: got %q/%q, want sieve/%s", request.Context.Protocol, request.Context.Method, testCase.method)
				}

				if request.Context.Username != testCase.username || request.Credential.Value() != testCase.secret {
					t.Fatal("request credential did not match parsed username and secret")
				}
			}

			if got := placer.callCount(); got != 1 {
				t.Fatalf("placement calls = %d, want 1", got)
			}
		})
	}
}

// TestAuthenticateContinuationCancellationAndLiteral verifies bounded SASL exchange shapes.
func TestAuthenticateContinuationCancellationAndLiteral(t *testing.T) {
	t.Run("cancel", func(t *testing.T) {
		authenticator := &recordingAuthenticator{}
		harness := startSieveHarness(t, testSessionConfig(TLSModeImplicit, authenticator))
		harness.expectGreeting(t,
			testGreetingImplementation,
			testGreetingVersion,
			testGreetingSieve,
			testGreetingLanguage,
			testGreetingSASLTLS,
			testGreetingOK,
		)

		harness.write(t, "AUTHENTICATE \"PLAIN\"\r\n")
		harness.expectLine(t, "\"\"\r\n")
		harness.write(t, "*\r\n")
		harness.expectLine(t, "NO (AUTHENTICATIONFAILED) \"Authentication cancelled\"\r\n")

		if got := authenticator.callCount(); got != 0 {
			t.Fatalf("Nauthilus calls = %d, want 0 after SASL cancellation", got)
		}
	})

	t.Run("literal", func(t *testing.T) {
		authenticator := &recordingAuthenticator{
			result: nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: "literal@example.test"},
		}
		placer := &recordingSessionPlacer{}
		payload := plainPayload("literal@example.test", "literal-secret")
		harness := startSieveHarness(t, testPlacementSessionConfig(TLSModeImplicit, authenticator, nil, placer))
		harness.expectGreeting(t,
			testGreetingImplementation,
			testGreetingVersion,
			testGreetingSieve,
			testGreetingLanguage,
			testGreetingSASLTLS,
			testGreetingOK,
		)

		harness.write(t, "AUTHENTICATE \"PLAIN\" {"+strconvItoa(len(payload))+"}\r\n"+payload+"\r\n")
		harness.expectAuthenticatedCapability(t, "literal@example.test")
		harness.expectDone(t)

		request := authenticator.singleRequest(t)
		if request.Context.Username != "literal@example.test" || request.Credential.Value() != "literal-secret" {
			t.Fatal("literal request did not match parsed PLAIN credentials")
		}
	})
}

// TestBearerIntrospectionTemporaryFailureMapsToTryLater verifies transport failures stay temporary.
func TestBearerIntrospectionTemporaryFailureMapsToTryLater(t *testing.T) {
	config := testSessionConfig(TLSModeImplicit, &recordingAuthenticator{})
	config.BearerIntrospector = &recordingBearerIntrospector{err: errors.New("temporary introspection failure")}

	harness := startSieveHarness(t, config)
	harness.expectGreeting(t,
		testGreetingImplementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		testGreetingSASLTLS,
		testGreetingOK,
	)
	harness.write(t, "AUTHENTICATE \"XOAUTH2\" \""+xoauth2Payload("alice@example.test", "xoauth-token")+"\"\r\n")
	harness.expectLine(t, "NO (TRYLATER) \"Authentication service temporarily unavailable\"\r\n")
}

// TestBearerIntrospectionRejectionMapsToAuthFailure verifies inactive tokens reject auth.
func TestBearerIntrospectionRejectionMapsToAuthFailure(t *testing.T) {
	config := testSessionConfig(TLSModeImplicit, &recordingAuthenticator{})
	config.BearerIntrospector = &recordingBearerIntrospector{
		result: nauthilus.AuthResult{Decision: nauthilus.DecisionRejected},
	}

	harness := startSieveHarness(t, config)
	harness.expectGreeting(t,
		testGreetingImplementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		testGreetingSASLTLS,
		testGreetingOK,
	)
	harness.write(t, "AUTHENTICATE \"OAUTHBEARER\" \""+oauthBearerPayload("alice@example.test", "oauth-token")+"\"\r\n")
	harness.expectLine(t, "NO (AUTHENTICATIONFAILED) \"Authentication failed\"\r\n")
}

// TestMalformedUnsupportedAndOversizedSASLInputIsSafe verifies bad SASL never leaks payload text.
func TestMalformedUnsupportedAndOversizedSASLInputIsSafe(t *testing.T) {
	authenticator := &recordingAuthenticator{}
	config := testSessionConfig(TLSModeImplicit, authenticator)
	config.MaxBearerTokenBytes = 4
	harness := startSieveHarness(t, config)
	harness.expectGreeting(t,
		testGreetingImplementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		testGreetingSASLTLS,
		testGreetingOK,
	)

	for _, command := range []string{
		"AUTHENTICATE \"SCRAM-SHA-256\" \"not-a-secret\"\r\n",
		"AUTHENTICATE \"PLAIN\" \"not-base64-secret-material\"\r\n",
		"AUTHENTICATE \"XOAUTH2\" \"" + xoauth2Payload("oversized@example.test", "very-secret-token") + "\"\r\n",
	} {
		harness.write(t, command)
		line := harness.readLine(t)

		if strings.Contains(line, "secret") || strings.Contains(line, "token") {
			t.Fatal("response leaked payload material")
		}

		if !strings.HasPrefix(line, "NO ") {
			t.Fatalf("response class mismatch: got prefix %.2q, want NO", line)
		}
	}

	if got := authenticator.callCount(); got != 0 {
		t.Fatalf("Nauthilus calls = %d, want 0 for invalid SASL", got)
	}
}

// TestUnsupportedPreauthCommandDoesNotAuthenticate verifies post-auth script verbs stay out of Director logic.
func TestUnsupportedPreauthCommandDoesNotAuthenticate(t *testing.T) {
	authenticator := &recordingAuthenticator{}
	harness := startSieveHarness(t, testSessionConfig(TLSModeImplicit, authenticator))
	harness.expectGreeting(t,
		testGreetingImplementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		testGreetingSASLTLS,
		testGreetingOK,
	)

	harness.write(t, "PUTSCRIPT \"active\" \"require [\\\"fileinto\\\"];\"\r\n")
	harness.expectLine(t, "NO (UNSUPPORTED) \"Unsupported command before authentication\"\r\n")

	if got := authenticator.callCount(); got != 0 {
		t.Fatalf("Nauthilus calls = %d, want 0 for unsupported pre-auth command", got)
	}
}

// TestAuthenticatePipelinedPostAuthBytesReachProxyHandoff verifies safe read-ahead enters proxy mode.
func TestAuthenticatePipelinedPostAuthBytesReachProxyHandoff(t *testing.T) {
	authenticator := &recordingAuthenticator{
		result: nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: "alice@example.test"},
	}
	runner := &recordingSieveProxyRunner{}
	config := testPlacementSessionConfig(TLSModeImplicit, authenticator, nil, nil)
	config.ProxyRunner = runner
	harness := startSieveHarness(t, config)
	harness.expectGreeting(t,
		testGreetingImplementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		testGreetingSASLTLS,
		testGreetingOK,
	)

	scriptPayload := "require [\"fileinto\"];\n# sentinel-script-content"
	postAuth := "PUTSCRIPT \"sentinel-script-name\" {" + strconvItoa(len(scriptPayload)) + "}\r\n" + scriptPayload + "\r\n"
	harness.write(t, "AUTHENTICATE \"PLAIN\" \""+plainPayload("alice@example.test", "plain-secret")+"\"\r\n"+postAuth)
	harness.expectAuthenticatedCapability(t, "alice@example.test")
	harness.expectDone(t)

	if got := authenticator.callCount(); got != 1 {
		t.Fatalf("Nauthilus calls = %d, want 1 before proxy handoff", got)
	}

	configured := runner.singleConfig(t)
	if got := string(configured.BufferedToBackend); got != postAuth {
		t.Fatalf("buffered post-auth byte mismatch: got %d bytes, want %d bytes", len(got), len(postAuth))
	}
}

// TestScriptMaterialNotRecordedByProxyObservability verifies proxied bytes stay out of events.
func TestScriptMaterialNotRecordedByProxyObservability(t *testing.T) {
	frontendClient, frontendProxy := net.Pipe()
	backendProxy, backendServer := net.Pipe()
	defer func() { _ = frontendClient.Close() }()
	defer func() { _ = backendServer.Close() }()

	recorder := &recordingSieveObservability{}
	scriptName := "sentinel-script-name"
	scriptContent := "require [\"fileinto\"];\n# sentinel-script-content"
	postAuth := "PUTSCRIPT \"" + scriptName + "\" {" + strconvItoa(len(scriptContent)) + "}\r\n" + scriptContent + "\r\n"

	resultCh := make(chan error, 1)
	go func() {
		_, err := proxy.NewPipe().Run(context.Background(), proxy.PipeConfig{
			Frontend:          frontendProxy,
			Backend:           backendProxy,
			BufferedToBackend: []byte(postAuth),
			IdleTimeout:       time.Second,
			Observability:     recorder,
		})
		resultCh <- err
	}()

	buffer := make([]byte, len(postAuth))
	if _, err := io.ReadFull(backendServer, buffer); err != nil {
		t.Fatalf("read proxied script bytes: %v", err)
	}

	if string(buffer) != postAuth {
		t.Fatalf("proxied script byte mismatch: got %d bytes, want %d bytes", len(buffer), len(postAuth))
	}

	_ = frontendClient.Close()
	select {
	case <-resultCh:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for proxy result")
	}

	if recorder.contains(scriptName) || recorder.contains("sentinel-script-content") {
		t.Fatal("proxy observability leaked script material")
	}
}

// TestNauthilusContextReportsFrontendTLS verifies SSL facts reach the auth request context.
func TestNauthilusContextReportsFrontendTLS(t *testing.T) {
	cleartext := startSieveHarness(t, testSessionConfig(TLSModeStartTLS, nil))
	cleartext.expectGreeting(t,
		testGreetingImplementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		testGreetingStartTLS,
		testGreetingSASLClear,
		testGreetingOK,
	)

	clearContext := cleartext.session.NauthilusRequestContext("plain")
	if clearContext.TLS != "false" {
		t.Fatalf("cleartext TLS = %q, want false", clearContext.TLS)
	}

	authenticator := &recordingAuthenticator{
		result: nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: "tls@example.test"},
	}
	implicit := startSieveHarnessWithState(t, testPlacementSessionConfig(TLSModeImplicit, authenticator, nil, nil), tls.ConnectionState{
		Version:     tls.VersionTLS13,
		CipherSuite: tls.TLS_AES_128_GCM_SHA256,
	})
	implicit.expectGreeting(t,
		testGreetingImplementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		testGreetingSASLTLS,
		testGreetingOK,
	)
	implicit.write(t, "AUTHENTICATE \"PLAIN\" \""+plainPayload("tls@example.test", "tls-secret")+"\"\r\n")
	implicit.expectAuthenticatedCapability(t, "tls@example.test")
	implicit.expectDone(t)

	request := authenticator.singleRequest(t)
	if request.Context.TLS != "true" || request.Context.TLSProtocol != "TLS1.3" ||
		request.Context.TLSCipher != "TLS_AES_128_GCM_SHA256" || request.Context.TLSClientVerify != "NONE" {
		t.Fatal("TLS context did not include the expected active TLS1.3 fields")
	}
}

// TestAuthenticatedSieveFeedsSharedRoutingAndPlacement verifies canonical auth facts drive placement.
func TestAuthenticatedSieveFeedsSharedRoutingAndPlacement(t *testing.T) {
	authenticator := &recordingAuthenticator{
		result: nauthilus.AuthResult{
			Decision: nauthilus.DecisionAuthenticated,
			Account:  "Canonical@Example.Test",
			Attributes: map[string][]string{
				"tenant": {"blue"},
				"shard":  {"mailstore-b"},
			},
		},
	}
	resolver := &recordingRoutingResolver{
		result: routing.RoutingResult{
			AccountKey: "Canonical@Example.Test",
			Tenant:     "blue",
			ShardTag:   "mailstore-b",
		},
	}
	placer := &recordingSessionPlacer{}
	harness := startSieveHarness(t, testPlacementSessionConfig(TLSModeImplicit, authenticator, resolver, placer))
	harness.expectGreeting(t,
		testGreetingImplementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		testGreetingSASLTLS,
		testGreetingOK,
	)

	harness.write(t, "AUTHENTICATE \"PLAIN\" \""+plainPayload("RawUser@Example.Test", "routing-secret")+"\"\r\n")
	harness.expectAuthenticatedCapability(t, "Canonical@Example.Test")
	harness.expectDone(t)

	routingRequest := resolver.singleRequest(t)
	if routingRequest.Protocol != protocolSieve || routingRequest.BackendPool != "sieve-default" {
		t.Fatalf("routing protocol/pool = %q/%q, want sieve/sieve-default", routingRequest.Protocol, routingRequest.BackendPool)
	}

	if routingRequest.LoginName != "RawUser@Example.Test" || routingRequest.NormalizedAccount != "canonical@example.test" {
		t.Fatal("routing identity did not preserve login name and canonical account as expected")
	}

	placementRequest := placer.singleRequest(t)
	if placementRequest.Protocol != protocolSieve || placementRequest.Key.AccountKey != "canonical@example.test" {
		t.Fatal("placement request did not use the canonical sieve affinity key")
	}

	if placementRequest.ListenerName != "sieve" || placementRequest.ServiceName != "sieve" ||
		placementRequest.BackendPool != "sieve-default" || placementRequest.DirectorInstanceID != "director-a" {
		t.Fatal("placement request did not include the configured Sieve listener context")
	}

	if placer.closeCount() != 1 {
		t.Fatalf("placement close calls = %d, want controlled close after backend readiness", placer.closeCount())
	}

	if _, ok := harness.session.Placement(); ok {
		t.Fatal("session retained placement after controlled close")
	}
}

// TestAuthenticatedSieveBackendAuthBindsToAuthenticatedAccount verifies backend auth ignores frontend aliases.
func TestAuthenticatedSieveBackendAuthBindsToAuthenticatedAccount(t *testing.T) {
	authenticator := &recordingAuthenticator{
		result: nauthilus.AuthResult{
			Decision: nauthilus.DecisionAuthenticated,
			Account:  "canonical@example.test",
		},
	}
	resolver := &recordingRoutingResolver{
		result: routing.RoutingResult{
			AccountKey: "canonical@example.test",
			Tenant:     "default",
			ShardTag:   "mailstore-a",
		},
	}
	placer := &recordingSessionPlacer{}
	authCommands := make(chan string, 1)
	config := testPlacementSessionConfig(TLSModeImplicit, authenticator, resolver, placer)
	config.BackendConnector = &recordingSieveBackendConnector{authCommands: authCommands}
	harness := startSieveHarness(t, config)
	harness.expectGreeting(t,
		testGreetingImplementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		testGreetingSASLTLS,
		testGreetingOK,
	)

	frontendPayload := base64.StdEncoding.EncodeToString([]byte("delegate@example.test\x00frontend@example.test\x00routing-secret"))
	harness.write(t, "AUTHENTICATE \"PLAIN\" \""+frontendPayload+"\"\r\n")
	harness.expectAuthenticatedCapability(t, "canonical@example.test")
	harness.expectDone(t)

	payload := decodeSieveInitialResponse(t, receiveSieveBackendAuthCommand(t, authCommands), mechanismPlain)
	if payload != "\x00canonical@example.test*director-master\x00backend-master-secret" {
		t.Fatalf("backend auth payload = %q, want canonical account binding", payload)
	}
	for _, forbidden := range []string{"frontend@example.test", "delegate@example.test"} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("backend auth replayed frontend identity %q instead of canonical account", forbidden)
		}
	}
}

// TestExternalSieveUsesCanonicalMasterUserBackend proves certificate auth reaches backend without replay.
func TestExternalSieveUsesCanonicalMasterUserBackend(t *testing.T) {
	resolver := &recordingRoutingResolver{
		result: routing.RoutingResult{
			AccountKey: "canonical@example.test",
			Tenant:     "default",
			ShardTag:   "mailstore-a",
		},
	}
	authCommands := make(chan string, 1)
	config := testPlacementSessionConfig(TLSModeImplicit, nil, resolver, nil)
	config.AuthMechanisms = append(config.AuthMechanisms, saslcred.MechanismExternal)
	config.CertificateAuthenticator = certauth.NewService(staticSieveIdentityLookuper{})
	config.BackendConnector = &recordingSieveBackendConnector{authCommands: authCommands}
	leaf := &x509.Certificate{EmailAddresses: []string{"external@example.test"}}
	harness := startSieveHarnessWithState(t, config, tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf}},
	})
	harness.expectGreeting(t,
		testGreetingImplementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		"\"SASL\" \"PLAIN XOAUTH2 OAUTHBEARER EXTERNAL\"\r\n",
		testGreetingOK,
	)

	harness.write(t, "AUTHENTICATE \"EXTERNAL\" \"=\"\r\n")
	harness.expectLines(t,
		testGreetingImplementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		"\"OWNER\" \"canonical@example.test\"\r\n",
		"\"SASL\" \"PLAIN XOAUTH2 OAUTHBEARER EXTERNAL\"\r\n",
		"OK \"Authentication successful\"\r\n",
	)
	harness.expectDone(t)

	payload := decodeSieveInitialResponse(t, receiveSieveBackendAuthCommand(t, authCommands), mechanismPlain)
	if payload != "\x00canonical@example.test*director-master\x00backend-master-secret" {
		t.Fatalf("backend auth payload = %q, want canonical master-user binding", payload)
	}
}

type staticSieveIdentityLookuper struct{}

// LookupIdentity returns one canonical account for the ManageSieve EXTERNAL fixture.
func (staticSieveIdentityLookuper) LookupIdentity(_ context.Context, request nauthilus.IdentityLookupRequest) (nauthilus.AuthResult, error) {
	if request.Context.Username != "external@example.test" {
		return nauthilus.AuthResult{Decision: nauthilus.DecisionRejected}, nil
	}

	return nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: "canonical@example.test"}, nil
}

// TestAuthenticatedSieveConnectsSelectedBackendBeforeSuccess verifies the backend request boundary.
func TestAuthenticatedSieveConnectsSelectedBackendBeforeSuccess(t *testing.T) {
	authenticator := &recordingAuthenticator{
		result: nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: "alice@example.test"},
	}
	connector := &recordingSieveBackendConnector{}
	config := testPlacementSessionConfig(TLSModeImplicit, authenticator, nil, nil)
	config.BackendConnector = connector

	harness := startSieveHarness(t, config)
	harness.expectGreeting(t,
		testGreetingImplementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		testGreetingSASLTLS,
		testGreetingOK,
	)

	harness.write(t, "AUTHENTICATE \"PLAIN\" \""+plainPayload("alice@example.test", "backend-secret")+"\"\r\n")
	harness.expectAuthenticatedCapability(t, "alice@example.test")
	harness.expectDone(t)

	request := connector.singleRequest(t)
	if request.Purpose != backend.ConnectPurposeSession {
		t.Fatalf("connect purpose = %q, want session", request.Purpose)
	}

	if request.Target.Identifier != "mailstore-a-sieve" || request.Target.Protocol != protocolSieve {
		t.Fatal("connect target did not match the selected Sieve backend")
	}

	if request.ProxyAddresses == nil || request.ProxyAddresses.Source != harness.server.RemoteAddr() ||
		request.ProxyAddresses.Destination != harness.server.LocalAddr() {
		t.Fatal("proxy addresses did not use the effective frontend tuple")
	}
}

// TestBufferedPostAuthBytesReachBackendExactlyOnce verifies pre-auth read-ahead is not replayed or dropped.
func TestBufferedPostAuthBytesReachBackendExactlyOnce(t *testing.T) {
	authenticator := &recordingAuthenticator{
		result: nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: "alice@example.test"},
	}
	connector := &observingProxyBackendConnector{observed: make(chan observedProxyBytes, 1)}
	config := testPlacementSessionConfig(TLSModeImplicit, authenticator, nil, nil)
	config.BackendConnector = connector
	config.ProxyRunner = proxy.NewPipe()
	config.ProxyIdleTimeout = time.Second

	harness := startSieveHarness(t, config)
	harness.expectGreeting(t,
		testGreetingImplementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		testGreetingSASLTLS,
		testGreetingOK,
	)

	postAuth := "LISTSCRIPTS\r\n"
	harness.write(t, "AUTHENTICATE \"PLAIN\" \""+plainPayload("alice@example.test", "backend-secret")+"\"\r\n"+postAuth)
	harness.expectAuthenticatedCapability(t, "alice@example.test")

	observed := connector.singleObservation(t)
	if observed.first != postAuth {
		t.Fatalf("proxied post-auth byte mismatch: got %d bytes, want %d bytes", len(observed.first), len(postAuth))
	}

	if observed.extra != "" {
		t.Fatalf("extra proxied bytes = %d, want none", len(observed.extra))
	}

	harness.expectDone(t)
}

// TestBackendPostAuthCapabilitiesAreDiscardedBeforeProxyHandoff verifies
// backend capability updates cannot be misread as client command output.
func TestBackendPostAuthCapabilitiesAreDiscardedBeforeProxyHandoff(t *testing.T) {
	authenticator := &recordingAuthenticator{
		result: nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: "alice@example.test"},
	}
	backendBuffered := "\"IMPLEMENTATION\" \"Dovecot Pigeonhole\"\r\n\"SASL\" \"PLAIN XOAUTH2\"\r\nOK \"post-auth capability\"\r\n"
	connector := &recordingSieveBackendConnector{backendBuffered: backendBuffered}
	runner := &recordingSieveProxyRunner{}
	config := testPlacementSessionConfig(TLSModeImplicit, authenticator, nil, nil)
	config.BackendConnector = connector
	config.ProxyRunner = runner

	harness := startSieveHarness(t, config)
	harness.expectGreeting(t,
		testGreetingImplementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		testGreetingSASLTLS,
		testGreetingOK,
	)

	harness.write(t, "AUTHENTICATE \"PLAIN\" \""+plainPayload("alice@example.test", "backend-secret")+"\"\r\n")
	harness.expectAuthenticatedCapability(t, "alice@example.test")
	harness.expectDone(t)

	configured := runner.singleConfig(t)
	if got := string(configured.BufferedToClient); got != "" {
		t.Fatalf("backend buffered bytes = %q, want none", got)
	}
}

// TestBackendPostAuthOKIsDiscardedBeforeProxyHandoff verifies a standalone
// backend login success cannot be misread as the post-auth CAPABILITY result.
func TestBackendPostAuthOKIsDiscardedBeforeProxyHandoff(t *testing.T) {
	authenticator := &recordingAuthenticator{
		result: nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: "alice@example.test"},
	}
	connector := &recordingSieveBackendConnector{backendBuffered: "OK \"Logged in.\"\r\n"}
	runner := &recordingSieveProxyRunner{}
	config := testPlacementSessionConfig(TLSModeImplicit, authenticator, nil, nil)
	config.BackendConnector = connector
	config.ProxyRunner = runner

	harness := startSieveHarness(t, config)
	harness.expectGreeting(t,
		testGreetingImplementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		testGreetingSASLTLS,
		testGreetingOK,
	)

	postAuth := "CAPABILITY\r\nLISTSCRIPTS\r\n"
	harness.write(t, "AUTHENTICATE \"PLAIN\" \""+plainPayload("alice@example.test", "backend-secret")+"\"\r\n"+postAuth)
	harness.expectAuthenticatedCapability(t, "alice@example.test")
	harness.expectDone(t)

	configured := runner.singleConfig(t)
	if got := string(configured.BufferedToClient); got != "" {
		t.Fatalf("backend buffered bytes = %q, want none", got)
	}

	if got := string(configured.BufferedToBackend); got != postAuth {
		t.Fatalf("proxied post-auth bytes = %q, want %q", got, postAuth)
	}
}

// TestBackendPostAuthCapabilityDiscardPreservesRoundcubeCommands verifies
// Roundcube-style post-auth CAPABILITY and LISTSCRIPTS commands still reach the
// backend after a backend capability block is discarded.
func TestBackendPostAuthCapabilityDiscardPreservesRoundcubeCommands(t *testing.T) {
	authenticator := &recordingAuthenticator{
		result: nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: "alice@example.test"},
	}
	backendBuffered := "\"IMPLEMENTATION\" \"Dovecot Pigeonhole\"\r\n" +
		"\"SIEVE\" \"fileinto reject vacation relational date vacation-seconds\"\r\n" +
		"\"SASL\" \"PLAIN XOAUTH2\"\r\n" +
		"OK \"post-auth capability\"\r\n"
	connector := &recordingSieveBackendConnector{backendBuffered: backendBuffered}
	runner := &recordingSieveProxyRunner{}
	config := testPlacementSessionConfig(TLSModeImplicit, authenticator, nil, nil)
	config.BackendConnector = connector
	config.ProxyRunner = runner

	harness := startSieveHarness(t, config)
	harness.expectGreeting(t,
		testGreetingImplementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		testGreetingSASLTLS,
		testGreetingOK,
	)

	postAuth := "CAPABILITY\r\nLISTSCRIPTS\r\n"
	harness.write(t, "AUTHENTICATE \"PLAIN\" \""+plainPayload("alice@example.test", "backend-secret")+"\"\r\n"+postAuth)
	harness.expectAuthenticatedCapability(t, "alice@example.test")
	harness.expectDone(t)

	configured := runner.singleConfig(t)
	if got := string(configured.BufferedToClient); got != "" {
		t.Fatalf("backend buffered bytes = %q, want none", got)
	}

	if got := string(configured.BufferedToBackend); got != postAuth {
		t.Fatalf("proxied post-auth bytes = %q, want %q", got, postAuth)
	}
}

// TestFrontendSuccessWriteFailureRollsBackBackendAndPlacement verifies post-backend-auth rollback.
func TestFrontendSuccessWriteFailureRollsBackBackendAndPlacement(t *testing.T) {
	authenticator := &recordingAuthenticator{
		result: nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: "alice@example.test"},
	}
	placer := &recordingSessionPlacer{}
	connector := &recordingSieveBackendConnector{}
	runner := &recordingSieveProxyRunner{}
	config := testPlacementSessionConfig(TLSModeImplicit, authenticator, nil, placer)
	config.BackendConnector = connector
	config.ProxyRunner = runner

	client, server := net.Pipe()
	harness := startSieveHarnessOnConn(t, config, client, &writeFailAfterConn{Conn: server, failAfter: 1})
	harness.expectGreeting(t,
		testGreetingImplementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		testGreetingSASLTLS,
		testGreetingOK,
	)

	harness.write(t, "AUTHENTICATE \"PLAIN\" \""+plainPayload("alice@example.test", "backend-secret")+"\"\r\n")
	if err := harness.expectError(t); err == nil {
		t.Fatal("Serve returned nil, want frontend success write failure")
	}

	if connector.backendCloseCount() != 1 {
		t.Fatalf("backend close calls = %d, want 1", connector.backendCloseCount())
	}

	if placer.closeCount() != 1 {
		t.Fatalf("placement close calls = %d, want 1", placer.closeCount())
	}

	if runner.callCount() != 0 {
		t.Fatalf("proxy handoffs = %d, want none after frontend success failure", runner.callCount())
	}
}

// TestSieveProxyLeaseLifecycleClosesAndHeartbeatsLease verifies proxy cleanup is idempotent.
func TestSieveProxyLeaseLifecycleClosesAndHeartbeatsLease(t *testing.T) {
	request := placement.SessionRequest{
		Key:         state.AffinityKey{Tenant: "default", AccountKey: "alice@example.test"},
		SessionID:   "sieve-session",
		Protocol:    protocolSieve,
		BackendPool: "sieve-default",
		ShardTag:    "mailstore-a",
		LeaseTTL:    time.Minute,
	}
	lease := newRecordingPlacementLease(request)
	lifecycle := &placementLeaseLifecycle{lease: lease, ttl: time.Minute}

	if err := lifecycle.Heartbeat(context.Background()); err != nil {
		t.Fatalf("Heartbeat returned error: %v", err)
	}

	if lease.heartbeatCount() != 1 {
		t.Fatalf("heartbeat calls = %d, want 1", lease.heartbeatCount())
	}

	if err := lifecycle.Close(context.Background()); err != nil {
		t.Fatalf("first Close returned error: %v", err)
	}

	if err := lifecycle.Close(context.Background()); err != nil {
		t.Fatalf("second Close returned error: %v", err)
	}

	if lease.closeCount() != 1 {
		t.Fatalf("lease close calls = %d, want 1", lease.closeCount())
	}
}

// TestBackendAuthFailureMapsToTemporaryFrontendFailure verifies backend status text stays hidden.
func TestBackendAuthFailureMapsToTemporaryFrontendFailure(t *testing.T) {
	authenticator := &recordingAuthenticator{
		result: nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: "alice@example.test"},
	}
	connector := &recordingSieveBackendConnector{
		authResponse: "NO (AUTHENTICATIONFAILED) \"backend-secret says no\"",
	}
	config := testPlacementSessionConfig(TLSModeImplicit, authenticator, nil, nil)
	config.BackendConnector = connector
	harness := startSieveHarness(t, config)
	harness.expectGreeting(t,
		testGreetingImplementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		testGreetingSASLTLS,
		testGreetingOK,
	)

	harness.write(t, "AUTHENTICATE \"PLAIN\" \""+plainPayload("alice@example.test", "frontend-secret")+"\"\r\n")
	line := harness.readLine(t)
	if line != "NO (TRYLATER) \"Backend service temporarily unavailable\"\r\n" {
		t.Fatalf("backend auth failure response = %q, want safe temporary failure", line)
	}

	if strings.Contains(line, "backend-secret") || strings.Contains(line, "frontend-secret") {
		t.Fatalf("backend auth failure leaked secret material: %q", line)
	}
}

// TestAuthenticatedSievePlacementGateRunsBeforePlacement verifies holds block runtime side effects.
func TestAuthenticatedSievePlacementGateRunsBeforePlacement(t *testing.T) {
	authenticator := &recordingAuthenticator{
		result: nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: "alice@example.test"},
	}
	resolver := &recordingRoutingResolver{}
	placer := &recordingSessionPlacer{}
	gate := &recordingPlacementGate{
		wait: func(_ context.Context, request runtimectl.PlacementGateRequest) (runtimectl.PlacementGateResult, error) {
			if request.Protocol != protocolSieve || request.ListenerName != "sieve" || request.ServiceName != "sieve" {
				t.Fatal("placement gate request did not include the Sieve listener context")
			}

			if placer.callCount() != 0 {
				t.Fatalf("placement calls before hold release = %d, want 0", placer.callCount())
			}

			return runtimectl.PlacementGateResult{
				Outcome:                     runtimectl.PlacementGateOutcomeReleased,
				RuntimeStateRecheckRequired: true,
			}, nil
		},
	}
	config := testPlacementSessionConfig(TLSModeImplicit, authenticator, resolver, placer)
	config.PlacementGate = gate
	harness := startSieveHarness(t, config)
	harness.expectGreeting(t,
		testGreetingImplementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		testGreetingSASLTLS,
		testGreetingOK,
	)

	harness.write(t, "AUTHENTICATE \"PLAIN\" \""+plainPayload("alice@example.test", "hold-secret")+"\"\r\n")
	harness.expectAuthenticatedCapability(t, "alice@example.test")
	harness.expectDone(t)

	if gate.callCount() != 1 || placer.callCount() != 1 {
		t.Fatalf("gate/placement calls = %d/%d, want 1/1", gate.callCount(), placer.callCount())
	}
}

// TestAuthenticatedSievePlacementGateTimeoutStopsPlacement verifies held users do not open sessions.
func TestAuthenticatedSievePlacementGateTimeoutStopsPlacement(t *testing.T) {
	authenticator := &recordingAuthenticator{
		result: nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: "alice@example.test"},
	}
	placer := &recordingSessionPlacer{}
	gate := &recordingPlacementGate{
		err: &runtimectl.Error{Kind: runtimectl.ErrorKindUnavailable, Operation: "user_hold_check", Message: "user hold wait timeout"},
	}
	config := testPlacementSessionConfig(TLSModeImplicit, authenticator, nil, placer)
	config.PlacementGate = gate
	harness := startSieveHarness(t, config)
	harness.expectGreeting(t,
		testGreetingImplementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		testGreetingSASLTLS,
		testGreetingOK,
	)

	harness.write(t, "AUTHENTICATE \"PLAIN\" \""+plainPayload("alice@example.test", "hold-secret")+"\"\r\n")
	harness.expectLine(t, "NO (TRYLATER) \"Authentication service temporarily unavailable\"\r\n")

	if gate.callCount() != 1 {
		t.Fatalf("placement gate calls = %d, want 1", gate.callCount())
	}

	if placer.callCount() != 0 || placer.closeCount() != 0 {
		t.Fatalf("placement calls close=%d place=%d, want none", placer.closeCount(), placer.callCount())
	}
}

// testSessionConfig builds a conservative Sieve pre-auth fixture.
func testSessionConfig(tlsMode string, authenticator nauthilus.Authenticator) SessionConfig {
	return SessionConfig{
		ListenerName:        "sieve",
		AuthorityName:       "default",
		AuthorityTransport:  "http",
		ServiceName:         "sieve",
		Network:             "tcp",
		BackendPool:         "sieve-default",
		TLSMode:             tlsMode,
		AuthMechanisms:      []string{"plain", "xoauth2", "oauthbearer"},
		MaxBearerTokenBytes: defaultMaxBearerBytes,
		GreetingPolicy:      testGreetingPolicyForHelper(ImplementationName, "test", greeting.DisclosureDefault),
		Capabilities: CapabilitiesConfig{
			ProtocolVersion:  ProtocolVersionRFC5804,
			ScriptExtensions: []string{"fileinto", "reject"},
			Language:         "en",
		},
		MaxPreauthLineBytes:    defaultMaxLineBytes,
		MaxPreauthLiteralBytes: defaultMaxLiteralBytes,
		Authenticator:          authenticator,
	}
}

// testPlacementSessionConfig builds a Sieve fixture with shared placement collaborators.
func testPlacementSessionConfig(
	tlsMode string,
	authenticator nauthilus.Authenticator,
	resolver routing.RoutingResolver,
	placer placement.SessionPlacer,
) SessionConfig {
	config := testSessionConfig(tlsMode, authenticator)
	if resolver == nil {
		resolver = &recordingRoutingResolver{}
	}

	if placer == nil {
		placer = &recordingSessionPlacer{}
	}

	config.DirectorInstanceID = "director-a"
	config.DefaultTenant = "default"
	config.DefaultShard = "mailstore-a"
	config.SessionLeaseTTL = time.Minute
	config.SessionIdleGrace = time.Minute
	config.BackendRetentionTTL = 15 * time.Minute
	config.RoutingResolver = resolver
	config.PlacementService = placer
	config.BackendConnectTimeout = time.Second
	config.ProxyIdleTimeout = time.Minute
	config.BackendConnector = &recordingSieveBackendConnector{}
	config.ProxyRunner = &recordingSieveProxyRunner{}

	return config
}

// testGreetingPolicy builds a public identity policy and fails the test on invalid fixtures.
func testGreetingPolicy(
	t *testing.T,
	displayNameValue string,
	processVersion string,
	disclosure greeting.SoftwareVersionDisclosure,
) greeting.Policy {
	t.Helper()

	policy, err := newTestGreetingPolicy(displayNameValue, processVersion, disclosure)
	if err != nil {
		t.Fatalf("newTestGreetingPolicy rejected fixture: %v", err)
	}

	return policy
}

// testGreetingPolicyForHelper builds a public identity policy where no testing handle is available.
func testGreetingPolicyForHelper(
	displayNameValue string,
	processVersion string,
	disclosure greeting.SoftwareVersionDisclosure,
) greeting.Policy {
	policy, _ := newTestGreetingPolicy(displayNameValue, processVersion, disclosure)

	return policy
}

// newTestGreetingPolicy constructs a shared policy for ManageSieve wire tests.
func newTestGreetingPolicy(
	displayNameValue string,
	processVersion string,
	disclosure greeting.SoftwareVersionDisclosure,
) (greeting.Policy, error) {
	displayName, err := greeting.NewDisplayName(displayNameValue)
	if err != nil {
		return greeting.Policy{}, err
	}

	return greeting.NewPolicy(displayName, processVersion, disclosure)
}

type sieveHarness struct {
	client  net.Conn
	server  net.Conn
	reader  *bufio.Reader
	session *Session
	done    chan error
}

// startSieveHarness starts one session over net.Pipe.
func startSieveHarness(t *testing.T, config SessionConfig) *sieveHarness {
	t.Helper()

	client, server := net.Pipe()

	return startSieveHarnessOnConn(t, config, client, server)
}

// startSieveHarnessWithState starts one session with synthetic TLS state metadata.
func startSieveHarnessWithState(t *testing.T, config SessionConfig, state tls.ConnectionState) *sieveHarness {
	t.Helper()

	client, server := net.Pipe()

	return startSieveHarnessOnConn(t, config, client, stateConn{Conn: server, state: state})
}

// startSieveHarnessOnConn starts one session on the supplied client/server pipe.
func startSieveHarnessOnConn(t *testing.T, config SessionConfig, client net.Conn, server net.Conn) *sieveHarness {
	t.Helper()

	session, err := NewSession(config, server)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	harness := &sieveHarness{
		client:  client,
		server:  server,
		reader:  bufio.NewReader(client),
		session: session,
		done:    make(chan error, 1),
	}
	go func() {
		harness.done <- session.Serve(context.Background())
	}()

	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()

		if harness.done == nil {
			return
		}

		select {
		case err := <-harness.done:
			if err != nil && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("Serve returned error: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("Serve did not stop")
		}
	})

	return harness
}

// expectGreeting consumes the expected greeting transcript.
func (h *sieveHarness) expectGreeting(t *testing.T, lines ...string) {
	t.Helper()
	h.expectLines(t, lines...)
}

// expectAuthenticatedCapability consumes the RFC 5804 capability update after AUTHENTICATE.
func (h *sieveHarness) expectAuthenticatedCapability(t *testing.T, owner string) {
	t.Helper()
	h.expectLines(t,
		testGreetingImplementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		"\"OWNER\" \""+owner+"\"\r\n",
		testGreetingSASLTLS,
		"OK \"Authentication successful\"\r\n",
	)
}

// expectLines consumes the expected response lines.
func (h *sieveHarness) expectLines(t *testing.T, lines ...string) {
	t.Helper()

	for _, line := range lines {
		h.expectLine(t, line)
	}
}

// expectLine consumes one expected response line.
func (h *sieveHarness) expectLine(t *testing.T, want string) {
	t.Helper()

	got := h.readLine(t)
	if got != want {
		t.Fatalf("line = %q, want %q", got, want)
	}
}

// readLine reads one response line with a test deadline.
func (h *sieveHarness) readLine(t *testing.T) string {
	t.Helper()

	_ = h.client.SetReadDeadline(time.Now().Add(time.Second))

	line, err := h.reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read line: %v", err)
	}

	_ = h.client.SetReadDeadline(time.Time{})

	return line
}

// write sends raw client bytes with a test deadline.
func (h *sieveHarness) write(t *testing.T, value string) {
	t.Helper()

	_ = h.client.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := io.WriteString(h.client, value); err != nil {
		t.Fatalf("write %q: %v", value, err)
	}

	_ = h.client.SetWriteDeadline(time.Time{})
}

// expectDone verifies the session finished after a fail-closed close decision.
func (h *sieveHarness) expectDone(t *testing.T) {
	t.Helper()

	select {
	case err := <-h.done:
		if err != nil {
			t.Fatalf("Serve returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not finish")
	}

	h.done = nil
}

// expectError verifies the session finished with a terminal error.
func (h *sieveHarness) expectError(t *testing.T) error {
	t.Helper()

	select {
	case err := <-h.done:
		if err == nil {
			t.Fatal("Serve returned nil, want error")
		}

		h.done = nil

		return err
	case <-time.After(time.Second):
		t.Fatal("Serve did not finish")
	}

	return nil
}

type recordingAuthenticator struct {
	mu       sync.Mutex
	requests []nauthilus.AuthRequest
	result   nauthilus.AuthResult
	err      error
}

// Authenticate records the authority request and returns the configured outcome.
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

// callCount returns the number of recorded authority requests.
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

// Introspect records one bearer request and returns a deterministic success by default.
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

// callCount returns the number of recorded introspection requests.
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
		t.Fatalf("recorded introspection requests = %d, want 1", len(i.requests))
	}

	return i.requests[0]
}

type recordingRoutingResolver struct {
	mu       sync.Mutex
	requests []routing.RoutingRequest
	result   routing.RoutingResult
	err      error
}

// Resolve records the routing input and returns a complete default route when none is configured.
func (r *recordingRoutingResolver) Resolve(_ context.Context, request routing.RoutingRequest) (routing.RoutingResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.requests = append(r.requests, request)
	if r.err != nil {
		return routing.RoutingResult{}, r.err
	}

	if r.result.Complete() {
		return r.result, nil
	}

	return routing.RoutingResult{
		AccountKey:    request.NormalizedAccount,
		Tenant:        request.Tenant,
		ShardTag:      "mailstore-a",
		RoutingSource: routing.SourceHash,
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

type recordingSessionPlacer struct {
	mu       sync.Mutex
	requests []placement.SessionRequest
	lease    *recordingPlacementLease
	err      error
}

// PlaceSession records the placement input and returns a closeable lease fixture.
func (p *recordingSessionPlacer) PlaceSession(_ context.Context, request placement.SessionRequest) (placement.LeaseHandle, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.requests = append(p.requests, request)
	if p.err != nil {
		return nil, p.err
	}

	lease := p.lease
	if lease == nil {
		lease = newRecordingPlacementLease(request)
	}

	p.lease = lease

	return lease, nil
}

// callCount returns the number of placement attempts.
func (p *recordingSessionPlacer) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return len(p.requests)
}

// closeCount returns how often the current fixture lease was closed.
func (p *recordingSessionPlacer) closeCount() int {
	p.mu.Lock()
	lease := p.lease
	p.mu.Unlock()

	if lease == nil {
		return 0
	}

	return lease.closeCount()
}

// singleRequest returns the only recorded placement request.
func (p *recordingSessionPlacer) singleRequest(t *testing.T) placement.SessionRequest {
	t.Helper()

	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.requests) != 1 {
		t.Fatalf("placement requests = %d, want 1", len(p.requests))
	}

	return p.requests[0]
}

type recordingPlacementLease struct {
	mu         sync.Mutex
	request    placement.SessionRequest
	affinity   state.AffinityRecord
	backend    backend.SelectionResult
	binding    placement.BackendBinding
	closed     int
	heartbeats int
}

// newRecordingPlacementLease creates a lease fixture from one placement request.
func newRecordingPlacementLease(request placement.SessionRequest) *recordingPlacementLease {
	backendNode := "mailstore-a-node"
	backendID := "mailstore-a-sieve"

	return &recordingPlacementLease{
		request: request,
		affinity: state.AffinityRecord{
			Key:                request.Key,
			ShardTag:           request.ShardTag,
			BackendNode:        backendNode,
			Present:            true,
			BindingStatus:      state.BindingStatusActive,
			ActiveSessionCount: 1,
			ActiveHolderCount:  1,
		},
		backend: backend.SelectionResult{
			Backend: backend.Backend{
				Identifier:  backendID,
				Protocol:    protocolSieve,
				BackendPool: request.BackendPool,
				ShardTag:    request.ShardTag,
				BackendNode: backendNode,
				Address:     "127.0.0.1:4190",
				TLS: backend.TLSConfig{
					Mode:          backendTLSImplicit,
					ServerName:    "localhost",
					MinTLSVersion: backendTLSMinDefault,
				},
				Auth: backend.AuthConfig{
					Mode: backendAuthModeMasterUser,
					MasterUser: backend.MasterUserConfig{
						Username:   "director-master",
						Password:   config.Secret("backend-master-secret"),
						UserFormat: "{user}*{master_user}",
						Mechanism:  mechanismPlain,
					},
					CredentialReplay: backend.CredentialReplayConfig{
						RequireBackendTLS: true,
						PreserveMechanism: true,
						AllowedMechanisms: []string{mechanismPlain, mechanismXOAUTH2, mechanismOAuthBearer},
					},
				},
			},
		},
		binding: placement.BackendBinding{
			Key:               request.Key,
			ShardTag:          request.ShardTag,
			BackendNode:       backendNode,
			BackendIdentifier: backendID,
			Source:            placement.BindingSourceInitialPlacement,
			ActiveHolderCount: 1,
		},
	}
}

// Affinity returns the lease affinity record.
func (l *recordingPlacementLease) Affinity() state.AffinityRecord {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.affinity
}

// AttachBackend satisfies the placement lease interface for tests.
func (l *recordingPlacementLease) AttachBackend(context.Context) error {
	return nil
}

// Backend returns the selected backend fixture.
func (l *recordingPlacementLease) Backend() backend.SelectionResult {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.backend
}

// Binding returns the backend-node binding fixture.
func (l *recordingPlacementLease) Binding() placement.BackendBinding {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.binding
}

// Close records lease rollback or session cleanup.
func (l *recordingPlacementLease) Close(context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.closed++

	return nil
}

// Heartbeat returns the current affinity fixture.
func (l *recordingPlacementLease) Heartbeat(context.Context, time.Duration) (state.AffinityRecord, error) {
	l.mu.Lock()
	l.heartbeats++
	l.mu.Unlock()

	return l.Affinity(), nil
}

// SessionID returns the placement session ID.
func (l *recordingPlacementLease) SessionID() string {
	return l.request.SessionID
}

// closeCount reports how many times Close was called.
func (l *recordingPlacementLease) closeCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.closed
}

// heartbeatCount reports how many times Heartbeat was called.
func (l *recordingPlacementLease) heartbeatCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.heartbeats
}

type recordingPlacementGate struct {
	mu      sync.Mutex
	request runtimectl.PlacementGateRequest
	result  runtimectl.PlacementGateResult
	err     error
	calls   int
	wait    func(context.Context, runtimectl.PlacementGateRequest) (runtimectl.PlacementGateResult, error)
}

// WaitForPlacement records the gate request and returns the configured wait outcome.
func (g *recordingPlacementGate) WaitForPlacement(
	ctx context.Context,
	request runtimectl.PlacementGateRequest,
) (runtimectl.PlacementGateResult, error) {
	g.mu.Lock()
	g.calls++
	g.request = request
	g.mu.Unlock()

	if g.wait != nil {
		return g.wait(ctx, request)
	}

	if g.err != nil {
		return runtimectl.PlacementGateResult{}, g.err
	}

	if g.result.Outcome != "" {
		return g.result, nil
	}

	return runtimectl.PlacementGateResult{Outcome: runtimectl.PlacementGateOutcomeAllowed}, nil
}

// callCount returns how many times the gate was evaluated.
func (g *recordingPlacementGate) callCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()

	return g.calls
}

type recordingSieveBackendConnector struct {
	mu              sync.Mutex
	requests        []backend.ConnectRequest
	err             error
	authResponse    string
	backendBuffered string
	backendCloses   int
	authCommands    chan<- string
}

// Connect records backend connect facts and returns a prepared auth-capable stream.
func (c *recordingSieveBackendConnector) Connect(_ context.Context, request backend.ConnectRequest) (*BackendConnection, error) {
	c.mu.Lock()
	c.requests = append(c.requests, request)
	c.mu.Unlock()

	if c.err != nil {
		return nil, c.err
	}

	client, server := net.Pipe()
	clientConn := &recordingCloseConn{
		Conn:    client,
		onClose: c.recordBackendClose,
	}
	response := c.authResponse
	if response == "" {
		response = "OK \"backend auth completed\""
	}

	go func() {
		defer func() { _ = server.Close() }()

		reader := bufio.NewReader(server)
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		if c.authCommands != nil {
			c.authCommands <- strings.TrimRight(line, "\r\n")
		}

		_, _ = io.WriteString(server, response+"\r\n"+c.backendBuffered)
	}()

	connection := newBackendConnection(clientConn)
	connection.capabilities = backend.NewCapabilitySet("SASL=PLAIN", "SASL=XOAUTH2", "SASL=OAUTHBEARER")
	connection.tlsActive = true
	connection.tlsVerified = true

	return connection, nil
}

// singleRequest returns the only recorded backend connect request.
func (c *recordingSieveBackendConnector) singleRequest(t *testing.T) backend.ConnectRequest {
	t.Helper()

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.requests) != 1 {
		t.Fatalf("backend connect requests = %d, want 1", len(c.requests))
	}

	return c.requests[0]
}

type observedProxyBytes struct {
	first string
	extra string
}

type observingProxyBackendConnector struct {
	observed chan observedProxyBytes
}

// Connect returns a backend stream that authenticates and observes proxied bytes opaquely.
func (c *observingProxyBackendConnector) Connect(_ context.Context, _ backend.ConnectRequest) (*BackendConnection, error) {
	client, server := net.Pipe()

	go func() {
		defer func() { _ = server.Close() }()

		reader := bufio.NewReader(server)
		if _, err := reader.ReadString('\n'); err != nil {
			return
		}

		if _, err := io.WriteString(server, "OK \"backend auth completed\"\r\n"); err != nil {
			return
		}

		first, err := reader.ReadString('\n')
		if err != nil {
			c.observed <- observedProxyBytes{}

			return
		}

		_ = server.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		extra, err := reader.ReadString('\n')
		if err != nil {
			extra = ""
		}
		_ = server.SetReadDeadline(time.Time{})

		c.observed <- observedProxyBytes{first: first, extra: extra}
	}()

	connection := newBackendConnection(client)
	connection.capabilities = backend.NewCapabilitySet("SASL=PLAIN")
	connection.tlsActive = true
	connection.tlsVerified = true

	return connection, nil
}

// receiveSieveBackendAuthCommand returns the observed backend AUTHENTICATE command.
func receiveSieveBackendAuthCommand(t *testing.T, commands <-chan string) string {
	t.Helper()

	select {
	case command := <-commands:
		return command
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Sieve backend auth command")
	}

	return ""
}

// singleObservation returns the only opaque byte observation from the fake backend.
func (c *observingProxyBackendConnector) singleObservation(t *testing.T) observedProxyBytes {
	t.Helper()

	select {
	case observed := <-c.observed:
		return observed
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for proxied backend bytes")
	}

	return observedProxyBytes{}
}

// backendCloseCount returns how many times the backend handoff stream was closed.
func (c *recordingSieveBackendConnector) backendCloseCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.backendCloses
}

// recordBackendClose records a backend connection close without logging stream data.
func (c *recordingSieveBackendConnector) recordBackendClose() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.backendCloses++
}

type recordingCloseConn struct {
	net.Conn
	onClose func()
	once    sync.Once
}

// Close records local close ownership before closing the wrapped stream.
func (c *recordingCloseConn) Close() error {
	c.once.Do(func() {
		if c.onClose != nil {
			c.onClose()
		}
	})

	return c.Conn.Close()
}

type writeFailAfterConn struct {
	net.Conn
	mu        sync.Mutex
	writes    int
	failAfter int
}

// Write delegates until the configured successful write count has elapsed.
func (c *writeFailAfterConn) Write(data []byte) (int, error) {
	c.mu.Lock()
	if c.writes >= c.failAfter {
		c.mu.Unlock()

		return 0, errors.New("frontend write failed")
	}

	c.writes++
	c.mu.Unlock()

	return c.Conn.Write(data)
}

type recordingSieveProxyRunner struct {
	mu      sync.Mutex
	configs []proxy.PipeConfig
	err     error
	check   func(proxy.PipeConfig)
}

// Run records proxy handoff facts and closes the supplied lease and streams.
func (r *recordingSieveProxyRunner) Run(ctx context.Context, config proxy.PipeConfig) (proxy.Result, error) {
	r.mu.Lock()
	r.configs = append(r.configs, config)
	r.mu.Unlock()

	if r.check != nil {
		r.check(config)
	}

	if config.Lease != nil {
		_ = config.Lease.Close(ctx)
	}

	if config.Frontend != nil {
		_ = config.Frontend.Close()
	}

	if config.Backend != nil {
		_ = config.Backend.Close()
	}

	return proxy.Result{Class: proxy.ResultClientClosed}, r.err
}

// callCount returns how many transparent proxy handoffs were started.
func (r *recordingSieveProxyRunner) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	return len(r.configs)
}

// singleConfig returns the only recorded proxy handoff configuration.
func (r *recordingSieveProxyRunner) singleConfig(t *testing.T) proxy.PipeConfig {
	t.Helper()

	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.configs) != 1 {
		t.Fatalf("proxy handoffs = %d, want 1", len(r.configs))
	}

	return r.configs[0]
}

type recordingSieveObservability struct {
	mu     sync.Mutex
	events []observability.Event
}

// Record stores a sanitized observability event for later inspection.
func (r *recordingSieveObservability) Record(_ context.Context, event observability.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.events = append(r.events, event)
}

// contains reports whether any event field or label contains forbidden material.
func (r *recordingSieveObservability) contains(value string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, event := range r.events {
		if eventContains(event.LogFields, value) || eventContains(event.MetricLabels, value) {
			return true
		}
	}

	return false
}

// eventContains checks one string map for a forbidden value.
func eventContains(values map[string]string, forbidden string) bool {
	for key, value := range values {
		if strings.Contains(key, forbidden) || strings.Contains(value, forbidden) {
			return true
		}
	}

	return false
}

type stateConn struct {
	net.Conn
	state tls.ConnectionState
}

// ConnectionState returns fixed TLS metadata for auth-context tests.
func (c stateConn) ConnectionState() tls.ConnectionState {
	return c.state
}

// plainPayload returns a base64 SASL PLAIN envelope.
func plainPayload(username string, password string) string {
	return base64.StdEncoding.EncodeToString([]byte("\x00" + username + "\x00" + password))
}

// xoauth2Payload returns a base64 XOAUTH2 bearer envelope.
func xoauth2Payload(username string, token string) string {
	return base64.StdEncoding.EncodeToString([]byte("user=" + username + "\x01auth=Bearer " + token + "\x01\x01"))
}

// oauthBearerPayload returns a base64 OAUTHBEARER envelope.
func oauthBearerPayload(username string, token string) string {
	return base64.StdEncoding.EncodeToString([]byte("n,a=" + username + ",\x01auth=Bearer " + token + "\x01\x01"))
}

// strconvItoa avoids pulling response formatting into the test body.
func strconvItoa(value int) string {
	return strconv.FormatInt(int64(value), 10)
}
