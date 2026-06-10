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

//nolint:funlen,goconst,wsl_v5 // Backend auth tests keep mechanism fixtures explicit.
package imap

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/config"
)

// TestMasterUserAuthCommandGeneration verifies configured user formatting and redaction-safe errors.
func TestMasterUserAuthCommandGeneration(t *testing.T) {
	credentials := loginCredentialsForBackendTest(t)
	defer credentials.Clear()

	command, err := masterUserAuthCommand(testMasterUserConfig(), testBackendCapabilities(), credentials)
	if err != nil {
		t.Fatalf("masterUserAuthCommand returned error: %v", err)
	}

	payload := decodeInitialResponse(t, command, "AUTHENTICATE PLAIN ")
	if payload != "\x00alice@example.test*director-master\x00master-secret" {
		t.Fatalf("PLAIN payload = %q, want formatted master-user payload", payload)
	}

	_, err = masterUserAuthCommand(testMasterUserConfig(), newBackendCapabilities("IMAP4rev1"), credentials)
	if !errors.Is(err, ErrBackendAuthPolicy) {
		t.Fatalf("masterUserAuthCommand error = %v, want policy rejection", err)
	}
	assertDoesNotContain(t, err.Error(), "master-secret")
	assertDoesNotContain(t, err.Error(), "alice@example.test")
}

// TestCredentialReplayCommandsCoverSupportedMechanisms verifies PLAIN, LOGIN and bearer replay shapes.
func TestCredentialReplayCommandsCoverSupportedMechanisms(t *testing.T) {
	testCases := []struct {
		name       string
		mechanism  string
		credential *frontendCredentials
		wantPrefix string
		wantRaw    string
	}{
		{
			name:       "plain",
			mechanism:  mechanismPlain,
			credential: plainCredentialsForBackendTest(t),
			wantPrefix: "AUTHENTICATE PLAIN ",
			wantRaw:    "\x00alice@example.test\x00" + testPassword,
		},
		{
			name:       "login",
			mechanism:  mechanismLogin,
			credential: loginCredentialsForBackendTest(t),
			wantPrefix: `LOGIN "alice@example.test" "`,
			wantRaw:    `LOGIN "alice@example.test" "secret-passphrase"`,
		},
		{
			name:       "xoauth2",
			mechanism:  mechanismXOAUTH2,
			credential: xoauth2CredentialsForBackendTest(t),
			wantPrefix: "AUTHENTICATE XOAUTH2 ",
			wantRaw:    "user=alice@example.test\x01auth=Bearer " + testBearerToken + "\x01\x01",
		},
		{
			name:       "oauthbearer",
			mechanism:  mechanismOAuthBearer,
			credential: oauthBearerCredentialsForBackendTest(t),
			wantPrefix: "AUTHENTICATE OAUTHBEARER ",
			wantRaw:    "n,a=alice=3Dexample@example.test,\x01auth=Bearer " + testBearerToken + "\x01\x01",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			defer testCase.credential.Clear()

			command, err := replayCommandForMechanism(testCase.mechanism, testCase.credential)
			if err != nil {
				t.Fatalf("replayCommandForMechanism returned error: %v", err)
			}

			if testCase.mechanism == mechanismLogin {
				if command != testCase.wantRaw {
					t.Fatalf("LOGIN command = %q, want %q", command, testCase.wantRaw)
				}

				return
			}

			if !strings.HasPrefix(command, testCase.wantPrefix) {
				t.Fatalf("command = %q, want prefix %q", command, testCase.wantPrefix)
			}
			if got := decodeInitialResponse(t, command, testCase.wantPrefix); got != testCase.wantRaw {
				t.Fatalf("decoded payload = %q, want %q", got, testCase.wantRaw)
			}
		})
	}
}

// TestMasterUserModeBranchesByCredentialKind verifies bearer credentials are policy-replayed.
func TestMasterUserModeBranchesByCredentialKind(t *testing.T) {
	t.Run("password uses master user", func(t *testing.T) {
		credentials := loginCredentialsForBackendTest(t)
		defer credentials.Clear()

		command, err := backendAuthCommand(testMasterUserBackend(), testVerifiedBackendConnection(testBackendCapabilities()), credentials)
		if err != nil {
			t.Fatalf("backendAuthCommand returned error: %v", err)
		}

		payload := decodeInitialResponse(t, command, "AUTHENTICATE PLAIN ")
		if payload != "\x00alice@example.test*director-master\x00master-secret" {
			t.Fatalf("PLAIN payload = %q, want master-user payload", payload)
		}
		if strings.Contains(payload, testPassword) {
			t.Fatal("master-user branch replayed the frontend password")
		}
	})

	t.Run("bearer uses credential replay", func(t *testing.T) {
		credentials := xoauth2CredentialsForBackendTest(t)
		defer credentials.Clear()

		command, err := backendAuthCommand(testMasterUserBackend(), testVerifiedBackendConnection(testBackendCapabilities()), credentials)
		if err != nil {
			t.Fatalf("backendAuthCommand returned error: %v", err)
		}

		payload := decodeInitialResponse(t, command, "AUTHENTICATE XOAUTH2 ")
		if payload != "user=alice@example.test\x01auth=Bearer "+testBearerToken+"\x01\x01" {
			t.Fatalf("XOAUTH2 payload = %q, want bearer replay payload", payload)
		}
		for _, forbidden := range []string{"director-master", "master-secret", "*director-master"} {
			if strings.Contains(payload, forbidden) {
				t.Fatalf("bearer replay payload used master-user material %q", forbidden)
			}
		}
	})
}

// TestMasterUserBearerReplayFailsClosedBeforeCommand verifies unsafe hybrid policy writes nothing.
func TestMasterUserBearerReplayFailsClosedBeforeCommand(t *testing.T) {
	testCases := map[string]struct {
		target       backend.Backend
		connection   *BackendConnection
		wantContains string
	}{
		"missing allowlist": {
			target: func() backend.Backend {
				target := testMasterUserBackend()
				target.Auth.CredentialReplay.AllowedMechanisms = []string{mechanismOAuthBearer}

				return target
			}(),
			connection:   testVerifiedBackendConnection(testBackendCapabilities()),
			wantContains: "bearer replay mechanism unavailable",
		},
		"missing capability": {
			target:       testMasterUserBackend(),
			connection:   testVerifiedBackendConnection(newBackendCapabilities("IMAP4rev1", "AUTH=PLAIN")),
			wantContains: "bearer replay mechanism unavailable",
		},
		"tls required": {
			target: testMasterUserBackend(),
			connection: &BackendConnection{
				capabilities: testBackendCapabilities(),
				tlsActive:    true,
				tlsVerified:  false,
			},
			wantContains: "credential replay requires verified backend TLS",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			credentials := xoauth2CredentialsForBackendTest(t)
			defer credentials.Clear()

			command, err := backendAuthCommand(testCase.target, testCase.connection, credentials)
			if !errors.Is(err, ErrBackendAuthPolicy) {
				t.Fatalf("backendAuthCommand error = %v, want policy rejection", err)
			}
			if command != "" {
				t.Fatalf("backendAuthCommand returned command before policy rejection: %q", command)
			}
			if !strings.Contains(err.Error(), testCase.wantContains) {
				t.Fatalf("error = %q, want %q", err.Error(), testCase.wantContains)
			}
			assertDoesNotContain(t, err.Error(), testBearerToken)
			assertDoesNotContain(t, err.Error(), "alice@example.test")
		})
	}
}

// TestCredentialReplayTLSEnforcement verifies replay fails before secrets cross plaintext.
func TestCredentialReplayTLSEnforcement(t *testing.T) {
	credentials := plainCredentialsForBackendTest(t)
	defer credentials.Clear()

	connection := &BackendConnection{
		capabilities: testBackendCapabilities(),
		tlsActive:    true,
		tlsVerified:  false,
	}
	target := testReplayBackend()
	target.Auth.CredentialReplay.RequireBackendTLS = true

	_, err := credentialReplayCommand(target.Auth.CredentialReplay, connection, credentials)
	if !errors.Is(err, ErrBackendAuthPolicy) {
		t.Fatalf("credentialReplayCommand error = %v, want policy rejection", err)
	}
	assertDoesNotContain(t, err.Error(), testPassword)
}

// TestCredentialReplayAllowlistAndPreserveRules verifies strict bearer and password normalization behavior.
func TestCredentialReplayAllowlistAndPreserveRules(t *testing.T) {
	plainCredentials := plainCredentialsForBackendTest(t)
	defer plainCredentials.Clear()

	xoauthCredentials := xoauth2CredentialsForBackendTest(t)
	defer xoauthCredentials.Clear()

	capabilities := testBackendCapabilities()
	config := backend.CredentialReplayConfig{
		RequireBackendTLS: true,
		PreserveMechanism: true,
		AllowedMechanisms: []string{mechanismLogin, mechanismXOAUTH2},
	}

	_, err := selectReplayMechanism(config, capabilities, plainCredentials)
	if !errors.Is(err, ErrBackendAuthPolicy) {
		t.Fatalf("preserve PLAIN error = %v, want policy rejection", err)
	}

	config.PreserveMechanism = false
	mechanism, err := selectReplayMechanism(config, capabilities, plainCredentials)
	if err != nil {
		t.Fatalf("normalized password replay returned error: %v", err)
	}
	if mechanism != mechanismLogin {
		t.Fatalf("normalized mechanism = %q, want login", mechanism)
	}

	config.AllowedMechanisms = []string{mechanismOAuthBearer}
	_, err = selectReplayMechanism(config, capabilities, xoauthCredentials)
	if !errors.Is(err, ErrBackendAuthPolicy) {
		t.Fatalf("XOAUTH2 to OAUTHBEARER error = %v, want policy rejection", err)
	}
}

// decodeInitialResponse decodes the base64 suffix from an AUTHENTICATE command.
func decodeInitialResponse(t *testing.T, command string, prefix string) string {
	t.Helper()

	if !strings.HasPrefix(command, prefix) {
		t.Fatalf("command = %q, want prefix %q", command, prefix)
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(command, prefix))
	if err != nil {
		t.Fatalf("decode initial response: %v", err)
	}

	return string(raw)
}

// testMasterUserConfig returns an explicit master-user fixture.
func testMasterUserConfig() backend.MasterUserConfig {
	return backend.MasterUserConfig{
		Username:   "director-master",
		Password:   config.Secret("master-secret"),
		UserFormat: "{user}*{master_user}",
		Mechanism:  mechanismPlain,
	}
}

// testReplayBackend returns a backend fixture using credential replay.
func testReplayBackend() backend.Backend {
	return backend.Backend{
		Protocol: backendProtocol,
		Address:  "127.0.0.1:1143",
		Auth: backend.AuthConfig{
			Mode: backendAuthModeCredentialReplay,
			CredentialReplay: backend.CredentialReplayConfig{
				RequireBackendTLS: true,
				PreserveMechanism: true,
				AllowedMechanisms: []string{mechanismPlain, mechanismLogin, mechanismXOAUTH2, mechanismOAuthBearer},
			},
		},
	}
}

// testMasterUserBackend returns a hybrid master-user backend fixture.
func testMasterUserBackend() backend.Backend {
	target := testReplayBackend()
	target.Auth.Mode = backendAuthModeMasterUser
	target.Auth.MasterUser = testMasterUserConfig()

	return target
}

// testVerifiedBackendConnection returns a prepared backend connection fixture.
func testVerifiedBackendConnection(capabilities backendCapabilities) *BackendConnection {
	return &BackendConnection{
		capabilities: capabilities,
		tlsActive:    true,
		tlsVerified:  true,
	}
}

// testBackendCapabilities returns all mechanisms used by backend replay tests.
func testBackendCapabilities() backendCapabilities {
	return newBackendCapabilities("IMAP4rev1", "AUTH=PLAIN", "AUTH=LOGIN", "AUTH=XOAUTH2", "AUTH=OAUTHBEARER")
}

// loginCredentialsForBackendTest creates LOGIN credentials for backend auth tests.
func loginCredentialsForBackendTest(t *testing.T) *frontendCredentials {
	t.Helper()

	credentials, err := parseLoginCredentials(parseTestCommand(t, fmt.Sprintf(`A001 LOGIN "alice@example.test" "%s"`, testPassword)))
	if err != nil {
		t.Fatalf("parseLoginCredentials: %v", err)
	}

	return credentials
}

// plainCredentialsForBackendTest creates PLAIN credentials for backend auth tests.
func plainCredentialsForBackendTest(t *testing.T) *frontendCredentials {
	t.Helper()

	credentials, err := parseSASLCredentials(testMechanism(t, "PLAIN"), plainPayload("alice@example.test", testPassword), 256, 64)
	if err != nil {
		t.Fatalf("parse PLAIN credentials: %v", err)
	}

	return credentials
}

// xoauth2CredentialsForBackendTest creates XOAUTH2 credentials for backend auth tests.
func xoauth2CredentialsForBackendTest(t *testing.T) *frontendCredentials {
	t.Helper()

	credentials, err := parseSASLCredentials(testMechanism(t, "XOAUTH2"), xoauth2Payload("alice@example.test", testBearerToken), 256, 64)
	if err != nil {
		t.Fatalf("parse XOAUTH2 credentials: %v", err)
	}

	return credentials
}

// oauthBearerCredentialsForBackendTest creates OAUTHBEARER credentials for backend auth tests.
func oauthBearerCredentialsForBackendTest(t *testing.T) *frontendCredentials {
	t.Helper()

	credentials, err := parseSASLCredentials(
		testMechanism(t, "OAUTHBEARER"),
		oauthBearerPayload("alice=example@example.test", testBearerToken),
		256,
		64,
	)
	if err != nil {
		t.Fatalf("parse OAUTHBEARER credentials: %v", err)
	}

	return credentials
}
