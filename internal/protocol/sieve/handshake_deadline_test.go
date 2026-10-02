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
//nolint:goconst // Handshake fixtures repeat the stable public wire values of the shared session fixtures.
package sieve

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
)

const (
	testHandshakeTimeout = 200 * time.Millisecond
	testHandshakeWithin  = 10 * testHandshakeTimeout
)

// TestBackendConnectorBoundsSilentBackendHandshake fails session connects to backends that never answer.
func TestBackendConnectorBoundsSilentBackendHandshake(t *testing.T) {
	for name, script := range map[string]func(*testing.T, net.Conn){
		"no_greeting": func(_ *testing.T, conn net.Conn) {
			_, _ = io.Copy(io.Discard, conn)
		},
		"partial_greeting": func(_ *testing.T, conn net.Conn) {
			_, _ = io.WriteString(conn, "\"IMPLEMENTATION\" \"backend\"\r\n")
			_, _ = io.Copy(io.Discard, conn)
		},
	} {
		t.Run(name, func(t *testing.T) {
			dialer := scriptedSieveBackendDialer(t, script)
			request := testSieveBackendConnectRequest(testSieveBackendTarget(backendTLSPlaintext))
			request.Timeout = testHandshakeTimeout

			done := make(chan error, 1)

			go func() {
				connection, err := NewTCPBackendConnector(dialer).Connect(context.Background(), request)
				if connection != nil {
					_ = connection.Conn().Close()
				}

				done <- err
			}()

			select {
			case err := <-done:
				if err == nil {
					t.Fatal("Connect succeeded against a silent backend")
				}
			case <-time.After(testHandshakeWithin):
				t.Fatalf("Connect to a silent backend did not fail within %s", testHandshakeWithin)
			}

			dialer.Wait(t)
		})
	}
}

// TestSilentBackendAuthFailsSessionWithinConnectTimeout bounds the backend login before proxy mode.
func TestSilentBackendAuthFailsSessionWithinConnectTimeout(t *testing.T) {
	authenticator := &recordingAuthenticator{
		result: nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: "alice@example.test"},
	}
	sessionConfig := testPlacementSessionConfig(TLSModeImplicit, authenticator, nil, nil)
	sessionConfig.BackendConnector = silentAuthSieveBackendConnector{}
	sessionConfig.BackendConnectTimeout = testHandshakeTimeout
	harness := startSieveHarness(t, sessionConfig)
	harness.expectGreeting(t,
		testGreetingImplementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		testGreetingSASLTLS,
		testGreetingOK,
	)

	started := time.Now()

	harness.write(t, "AUTHENTICATE \"PLAIN\" \""+plainPayload("alice@example.test", "frontend-secret")+"\"\r\n")

	line := harness.readLine(t)
	if line != "NO (TRYLATER) \"Backend service temporarily unavailable\"\r\n" {
		t.Fatalf("silent backend auth response = %q, want safe temporary failure", line)
	}

	if elapsed := time.Since(started); elapsed > testHandshakeWithin {
		t.Fatalf("silent backend auth failed after %s, want within %s", elapsed, testHandshakeWithin)
	}
}

type silentAuthSieveBackendConnector struct{}

// Connect returns a prepared backend stream whose peer never answers the login.
func (silentAuthSieveBackendConnector) Connect(context.Context, backend.ConnectRequest) (*BackendConnection, error) {
	client, server := net.Pipe()
	connection := newBackendConnection(client)
	connection.capabilities = backend.NewCapabilitySet("SASL=PLAIN")
	connection.tlsActive = true
	connection.tlsVerified = true

	go func() {
		defer func() { _ = server.Close() }()

		_, _ = io.Copy(io.Discard, server)
	}()

	return connection, nil
}
