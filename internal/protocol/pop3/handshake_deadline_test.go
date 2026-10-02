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
package pop3

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/placement"
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
		"no_capability_reply": func(_ *testing.T, conn net.Conn) {
			_, _ = io.WriteString(conn, "+OK backend ready\r\n")
			_, _ = io.Copy(io.Discard, conn)
		},
	} {
		t.Run(name, func(t *testing.T) {
			dialer := scriptedPOP3BackendDialer(t, script)
			request := testPOP3BackendConnectRequest(testPOP3BackendTarget(backendTLSPlaintext))
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
		result: nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: "canonical@example.test"},
	}
	placer := &recordingSessionPlacer{}
	lease := newRecordingPlacementLease(placement.SessionRequest{
		BackendPool: "pop3-default",
		ShardTag:    "mailstore-a",
	})
	lease.backend.Backend.TLS = backend.TLSConfig{Mode: backendTLSNone}
	lease.backend.Backend.Auth = backend.AuthConfig{
		Mode: backendAuthModeMasterUser,
		MasterUser: backend.MasterUserConfig{
			Username:   testPOP3BackendMasterUser,
			Password:   config.Secret(testPOP3BackendMasterPass),
			UserFormat: "{user}*{master_user}",
			Mechanism:  "plain",
		},
	}
	placer.lease = lease

	sessionConfig := testPlacementPOP3Config(TLSModeImplicit, authenticator, nil, placer)
	sessionConfig.BackendConnector = silentAuthPOP3BackendConnector{}
	sessionConfig.BackendConnectTimeout = testHandshakeTimeout
	harness := startPOP3Harness(t, sessionConfig)
	harness.expectOK(t)

	harness.write(t, "USER frontend@example.test\r\n")
	harness.expectOK(t)

	started := time.Now()

	harness.write(t, "PASS "+testPOP3FrontendPassword+"\r\n")

	line := harness.expectERR(t)
	if !strings.Contains(line, "Mailbox temporarily unavailable") {
		t.Fatalf("silent backend auth response = %q, want safe temporary failure", line)
	}

	if elapsed := time.Since(started); elapsed > testHandshakeWithin {
		t.Fatalf("silent backend auth failed after %s, want within %s", elapsed, testHandshakeWithin)
	}
}

type silentAuthPOP3BackendConnector struct{}

// Connect returns a prepared backend stream whose peer never answers the login.
func (silentAuthPOP3BackendConnector) Connect(context.Context, backend.ConnectRequest) (*BackendConnection, error) {
	client, server := net.Pipe()
	connection := newBackendConnection(client)
	connection.capabilities = backend.NewCapabilitySet(capabilityUser, capabilitySASL+"=PLAIN")
	connection.tlsActive = true
	connection.tlsVerified = true

	go func() {
		defer func() { _ = server.Close() }()

		_, _ = io.Copy(io.Discard, server)
	}()

	return connection, nil
}
