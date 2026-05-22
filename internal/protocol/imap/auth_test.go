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

//nolint:funlen,goconst,wsl_v5 // Credential fixtures are explicit to prove leak-safe handling.
package imap

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/croessner/nauthilus-director/internal/nauthilus"
)

const (
	testBearerToken = "ya29.ValidBearerToken"
	testPassword    = "secret-passphrase"
)

// TestLoginParsingWithQuotedStringsAndInvalidForms verifies LOGIN accepts only simple strings.
func TestLoginParsingWithQuotedStringsAndInvalidForms(t *testing.T) {
	command := parseTestCommand(t, `A001 LOGIN "alice@example.test" "secret-passphrase"`)

	credentials, err := parseLoginCredentials(command)
	if err != nil {
		t.Fatalf("parseLoginCredentials returned error: %v", err)
	}
	defer credentials.Clear()

	if credentials.Username() != "alice@example.test" {
		t.Fatalf("username = %q, want alice@example.test", credentials.Username())
	}
	if credentials.Mechanism().Normalized() != mechanismLogin || credentials.Mechanism().Original() != mechanismLogin {
		t.Fatalf("mechanism = %#v, want LOGIN identity", credentials.Mechanism())
	}
	if credentials.Kind() != credentialKindPassword {
		t.Fatalf("kind = %q, want password", credentials.Kind())
	}
	if credentials.Secret().Value() != testPassword {
		t.Fatal("LOGIN password was not preserved for short-lived auth use")
	}

	for _, input := range []string{
		`A001 LOGIN "alice@example.test"`,
		`A001 LOGIN () "secret-passphrase"`,
		`A001 LOGIN "" "secret-passphrase"`,
		`A001 LOGIN "alice@example.test" ""`,
	} {
		t.Run(input, func(t *testing.T) {
			_, err := parseLoginCredentials(parseTestCommand(t, input))
			if !errors.Is(err, ErrCredentialRejected) {
				t.Fatalf("error = %v, want credential rejection", err)
			}
			assertNoCredentialLeak(t, err.Error())
		})
	}
}

// TestPlainSASLParsing verifies PLAIN valid, malformed, missing-field and oversized cases.
func TestPlainSASLParsing(t *testing.T) {
	mechanism := testMechanism(t, "PLAIN")
	credentials, err := parseSASLCredentials(mechanism, encodeSASL("\x00alice@example.test\x00"+testPassword), 256, 64)
	if err != nil {
		t.Fatalf("parseSASLCredentials returned error: %v", err)
	}
	defer credentials.Clear()

	if credentials.Username() != "alice@example.test" {
		t.Fatalf("username = %q, want alice@example.test", credentials.Username())
	}
	if credentials.AuthorizationID() != "" {
		t.Fatalf("authzid = %q, want empty", credentials.AuthorizationID())
	}
	if credentials.Secret().Value() != testPassword {
		t.Fatal("PLAIN password was not preserved for short-lived auth use")
	}

	testCases := map[string]string{
		"invalid_base64": "not-base64!",
		"missing_field":  encodeSASL("\x00alice@example.test"),
		"empty_authcid":  encodeSASL("\x00\x00secret-passphrase"),
		"empty_password": encodeSASL("\x00alice@example.test\x00"),
	}
	for name, encoded := range testCases {
		t.Run(name, func(t *testing.T) {
			_, err := parseSASLCredentials(mechanism, encoded, 256, 64)
			if !errors.Is(err, ErrCredentialRejected) {
				t.Fatalf("error = %v, want credential rejection", err)
			}
			assertNoCredentialLeak(t, err.Error())
		})
	}

	_, err = parseSASLCredentials(mechanism, encodeSASL("\x00alice@example.test\x00"+strings.Repeat("x", 32)), 8, 64)
	if !errors.Is(err, ErrCredentialTooLarge) {
		t.Fatalf("oversized error = %v, want credential too large", err)
	}
	assertNoCredentialLeak(t, err.Error())
}

// TestXOAUTH2SASLParsing verifies XOAUTH2 valid, malformed, missing-token and oversized-token cases.
func TestXOAUTH2SASLParsing(t *testing.T) {
	mechanism := testMechanism(t, "xOAuth2")
	credentials, err := parseSASLCredentials(mechanism, xoauth2Payload("alice@example.test", testBearerToken), 256, 64)
	if err != nil {
		t.Fatalf("parseSASLCredentials returned error: %v", err)
	}
	defer credentials.Clear()

	if credentials.Username() != "alice@example.test" {
		t.Fatalf("username = %q, want alice@example.test", credentials.Username())
	}
	if credentials.Mechanism().Original() != "xOAuth2" || credentials.Mechanism().Normalized() != mechanismXOAUTH2 {
		t.Fatalf("mechanism = %#v, want preserved XOAUTH2 identity", credentials.Mechanism())
	}
	if credentials.Kind() != credentialKindBearer {
		t.Fatalf("kind = %q, want bearer", credentials.Kind())
	}
	if credentials.Secret().Value() != testBearerToken {
		t.Fatal("XOAUTH2 bearer token was not preserved for short-lived auth use")
	}

	testCases := map[string]string{
		"malformed":     encodeSASL("user=alice@example.test\x01auth=Bearer " + testBearerToken),
		"missing_user":  encodeSASL("auth=Bearer " + testBearerToken + "\x01\x01"),
		"missing_token": encodeSASL("user=alice@example.test\x01auth=Bearer \x01\x01"),
	}
	for name, encoded := range testCases {
		t.Run(name, func(t *testing.T) {
			_, err := parseSASLCredentials(mechanism, encoded, 256, 64)
			if !errors.Is(err, ErrCredentialRejected) {
				t.Fatalf("error = %v, want credential rejection", err)
			}
			assertNoCredentialLeak(t, err.Error())
		})
	}

	_, err = parseSASLCredentials(mechanism, xoauth2Payload("alice@example.test", strings.Repeat("t", 9)), 256, 8)
	if !errors.Is(err, ErrCredentialTooLarge) {
		t.Fatalf("oversized error = %v, want credential too large", err)
	}
	assertNoCredentialLeak(t, err.Error())
}

// TestOAuthBearerSASLParsing verifies OAUTHBEARER valid, malformed and oversized cases.
func TestOAuthBearerSASLParsing(t *testing.T) {
	mechanism := testMechanism(t, "OAUTHBEARER")
	credentials, err := parseSASLCredentials(
		mechanism,
		oauthBearerPayload("alice=example@example.test", testBearerToken),
		256,
		64,
	)
	if err != nil {
		t.Fatalf("parseSASLCredentials returned error: %v", err)
	}
	defer credentials.Clear()

	if credentials.Username() != "alice=example@example.test" {
		t.Fatalf("username = %q, want decoded auth identity", credentials.Username())
	}
	if credentials.AuthorizationID() != credentials.Username() {
		t.Fatalf("authzid = %q, want username", credentials.AuthorizationID())
	}
	if credentials.Mechanism().IMAPName() != "OAUTHBEARER" {
		t.Fatalf("IMAP mechanism = %q, want OAUTHBEARER", credentials.Mechanism().IMAPName())
	}
	if credentials.Secret().Value() != testBearerToken {
		t.Fatal("OAUTHBEARER bearer token was not preserved for short-lived auth use")
	}

	testCases := map[string]string{
		"malformed":        encodeSASL("n,a=alice@example.test,\x01auth=Bearer " + testBearerToken),
		"missing_identity": encodeSASL("n,,\x01auth=Bearer " + testBearerToken + "\x01\x01"),
		"missing_token":    encodeSASL("n,a=alice@example.test,\x01auth=Bearer \x01\x01"),
	}
	for name, encoded := range testCases {
		t.Run(name, func(t *testing.T) {
			_, err := parseSASLCredentials(mechanism, encoded, 256, 64)
			if !errors.Is(err, ErrCredentialRejected) {
				t.Fatalf("error = %v, want credential rejection", err)
			}
			assertNoCredentialLeak(t, err.Error())
		})
	}

	_, err = parseSASLCredentials(mechanism, oauthBearerPayload("alice@example.test", strings.Repeat("t", 9)), 256, 8)
	if !errors.Is(err, ErrCredentialTooLarge) {
		t.Fatalf("oversized error = %v, want credential too large", err)
	}
	assertNoCredentialLeak(t, err.Error())
}

// TestAuthenticateSASLIRAndContinuationFlows verifies both supported AUTHENTICATE input modes.
func TestAuthenticateSASLIRAndContinuationFlows(t *testing.T) {
	testCases := []struct {
		name      string
		mechanism string
		encoded   string
	}{
		{name: "plain", mechanism: "PLAIN", encoded: plainPayload("plain-user@example.test", "plain-passphrase")},
		{name: "xoauth2", mechanism: "XOAUTH2", encoded: xoauth2Payload("xoauth2-user@example.test", "xoauth2-token")},
		{name: "oauthbearer", mechanism: "OAUTHBEARER", encoded: oauthBearerPayload("oauth-user@example.test", "oauth-token")},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name+"_sasl_ir", func(t *testing.T) {
			harness := startTestSession(t, testPreauthConfig(TLSModeStartTLS, false))
			harness.expectLine(t, greetingLine)
			harness.write(t, fmt.Sprintf("A001 AUTHENTICATE %s %s\r\n", testCase.mechanism, testCase.encoded))
			harness.expectLine(t, "A001 NO [UNAVAILABLE] Authentication handler unavailable\r\n")
		})

		t.Run(testCase.name+"_continuation", func(t *testing.T) {
			harness := startTestSession(t, testPreauthConfig(TLSModeStartTLS, false))
			harness.expectLine(t, greetingLine)
			harness.write(t, fmt.Sprintf("A001 AUTHENTICATE %s\r\n", testCase.mechanism))
			harness.expectLine(t, "+ \r\n")
			harness.write(t, testCase.encoded+"\r\n")
			harness.expectLine(t, "A001 NO [UNAVAILABLE] Authentication handler unavailable\r\n")
		})
	}
}

// TestBearerTokenLimitUsesSessionConfig verifies authority-derived bearer limits fail closed.
func TestBearerTokenLimitUsesSessionConfig(t *testing.T) {
	config := testPreauthConfig(TLSModeStartTLS, false)
	config.MaxBearerTokenBytes = 8

	harness := startTestSession(t, config)
	harness.expectLine(t, greetingLine)
	harness.write(t, "A001 AUTHENTICATE XOAUTH2 "+xoauth2Payload("alice@example.test", "123456789")+"\r\n")
	harness.expectLine(t, "A001 BAD Invalid AUTHENTICATE response\r\n")
}

// TestMalformedContinuationResponseIsTagged verifies continuation failures stay generic.
func TestMalformedContinuationResponseIsTagged(t *testing.T) {
	harness := startTestSession(t, testPreauthConfig(TLSModeStartTLS, false))
	harness.expectLine(t, greetingLine)
	harness.write(t, "A001 AUTHENTICATE PLAIN\r\n")
	harness.expectLine(t, "+ \r\n")
	harness.write(t, "not-base64!\r\n")
	harness.expectLine(t, "A001 BAD Invalid AUTHENTICATE response\r\n")
}

// TestCredentialFormattingRedactsMaterial verifies String and GoString do not expose secrets.
func TestCredentialFormattingRedactsMaterial(t *testing.T) {
	secret := newCredentialSecret(testPassword)
	if secret.Len() != len(testPassword) {
		t.Fatalf("secret length = %d, want %d", secret.Len(), len(testPassword))
	}

	text := fmt.Sprintf("%s %v %#v %q", secret, secret, secret, secret)
	assertDoesNotContain(t, text, testPassword)
	if !strings.Contains(text, redactedCredential) {
		t.Fatalf("formatted secret = %q, want redacted marker", text)
	}

	credentials, err := parseSASLCredentials(testMechanism(t, "PLAIN"), plainPayload("alice@example.test", testPassword), 256, 64)
	if err != nil {
		t.Fatalf("parseSASLCredentials returned error: %v", err)
	}
	defer credentials.Clear()

	text = fmt.Sprintf("%s %#v", credentials, credentials)
	assertDoesNotContain(t, text, testPassword)
	if !strings.Contains(text, redactedCredential) {
		t.Fatalf("formatted credentials = %q, want redacted marker", text)
	}
}

// TestCredentialsBuildNauthilusRequest verifies mechanism metadata reaches the auth boundary.
func TestCredentialsBuildNauthilusRequest(t *testing.T) {
	credentials, err := parseSASLCredentials(testMechanism(t, "PLAIN"), plainPayload("alice@example.test", testPassword), 256, 64)
	if err != nil {
		t.Fatalf("parseSASLCredentials returned error: %v", err)
	}
	defer credentials.Clear()

	request := credentials.NauthilusAuthRequest(nauthilus.RequestContext{Protocol: "imap", ClientID: "test-client"})
	if request.Context.Username != "alice@example.test" {
		t.Fatalf("request username = %q, want alice@example.test", request.Context.Username)
	}
	if request.Context.Method != mechanismPlain {
		t.Fatalf("request method = %q, want plain", request.Context.Method)
	}
	if request.Context.ClientID != "test-client" {
		t.Fatalf("request client ID = %q, want test-client", request.Context.ClientID)
	}
	if request.Credential.Value() != testPassword {
		t.Fatal("Nauthilus request did not carry the wrapped credential")
	}

	text := fmt.Sprintf("%v", request.Credential)
	assertDoesNotContain(t, text, testPassword)
}

// parseTestCommand parses one test command line with the package parser.
func parseTestCommand(t *testing.T, line string) preauthCommand {
	t.Helper()

	command, err := parsePreauthCommand([]byte(line+"\r\n"), 8192)
	if err != nil {
		t.Fatalf("parsePreauthCommand(%q): %v", line, err)
	}

	return command
}

// testMechanism returns a normalized mechanism identity for tests.
func testMechanism(t *testing.T, value string) mechanismIdentity {
	t.Helper()

	mechanism, err := newMechanismIdentity(value)
	if err != nil {
		t.Fatalf("newMechanismIdentity(%q): %v", value, err)
	}

	return mechanism
}

// plainPayload encodes a minimal SASL PLAIN payload.
func plainPayload(username string, password string) string {
	return encodeSASL("\x00" + username + "\x00" + password)
}

// xoauth2Payload encodes a minimal XOAUTH2 payload.
func xoauth2Payload(username string, token string) string {
	return encodeSASL("user=" + username + "\x01auth=Bearer " + token + "\x01\x01")
}

// oauthBearerPayload encodes a minimal OAUTHBEARER payload.
func oauthBearerPayload(identity string, token string) string {
	return encodeSASL("n,a=" + encodeGS2AuthzID(identity) + ",\x01auth=Bearer " + token + "\x01\x01")
}

// encodeSASL returns standard base64 text for SASL response payloads.
func encodeSASL(payload string) string {
	return base64.StdEncoding.EncodeToString([]byte(payload))
}

// encodeGS2AuthzID encodes the two special bytes in a GS2 authzid.
func encodeGS2AuthzID(value string) string {
	value = strings.ReplaceAll(value, "=", "=3D")
	value = strings.ReplaceAll(value, ",", "=2C")

	return value
}

// assertNoCredentialLeak checks representative secret fixtures against text output.
func assertNoCredentialLeak(t *testing.T, text string) {
	t.Helper()

	for _, secret := range []string{testPassword, testBearerToken, "123456789", "secret-passphrase"} {
		assertDoesNotContain(t, text, secret)
	}
}

// assertDoesNotContain fails when sensitive text appears in diagnostic output.
func assertDoesNotContain(t *testing.T, text string, secret string) {
	t.Helper()

	if strings.Contains(text, secret) {
		t.Fatalf("text %q leaked secret %q", text, secret)
	}
}
