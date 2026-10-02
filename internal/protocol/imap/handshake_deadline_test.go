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

package imap

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
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
			_, _ = io.WriteString(conn, "* OK backend ready\r\n")
			_, _ = io.Copy(io.Discard, conn)
		},
	} {
		t.Run(name, func(t *testing.T) {
			dialer := scriptedBackendDialer(t, script)
			request := testSessionBackendConnectRequest(testBackendTarget(backendTLSPlaintext))
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
	credentials := plainCredentialsForBackendTest(t)
	defer credentials.Clear()

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	go func() { _, _ = io.Copy(io.Discard, client) }()

	store := &recordingSessionStore{}
	session := newPlacedTransitionSession(t, server, store)
	session.context.BackendConnectTimeout = testHandshakeTimeout
	session.backendConnector = silentAuthBackendConnector{}

	done := make(chan error, 1)

	go func() {
		_, err := session.transitionAuthenticatedSession(context.Background(), "A001", credentials)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("transitionAuthenticatedSession returned transport error: %v", err)
		}
	case <-time.After(testHandshakeWithin):
		t.Fatalf("silent backend auth did not fail within %s", testHandshakeWithin)
	}

	if store.closeCalls != 1 {
		t.Fatalf("close calls after silent backend auth = %d, want 1", store.closeCalls)
	}
}

type silentAuthBackendConnector struct{}

// Connect returns a prepared backend stream whose peer never answers the login.
func (silentAuthBackendConnector) Connect(context.Context, backend.ConnectRequest) (*BackendConnection, error) {
	client, server := net.Pipe()
	connection := newBackendConnection(client)
	connection.capabilities = testBackendCapabilities()
	connection.tlsActive = true
	connection.tlsVerified = true

	go func() {
		defer func() { _ = server.Close() }()

		_, _ = io.Copy(io.Discard, server)
	}()

	return connection, nil
}
