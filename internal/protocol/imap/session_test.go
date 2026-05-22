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
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

const (
	testIMAPService  = "imap"
	testIMAPSService = "imaps"
	testNetworkTCP   = "tcp"
)

// TestSessionContextUsesStableOpaqueID verifies each session receives internal correlation metadata.
func TestSessionContextUsesStableOpaqueID(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	session, err := NewSession(testSessionConfig(), server)
	if err != nil {
		t.Fatalf("NewSession returned error: %v", err)
	}

	if session.Context().ID == "" {
		t.Fatal("session ID is empty")
	}

	if session.Context().StartTLSAvailable() {
		t.Fatal("implicit TLS test session reported STARTTLS")
	}
}

// TestSessionRejectsOversizedPreauthLine verifies line limits are enforced before parsing.
func TestSessionRejectsOversizedPreauthLine(t *testing.T) {
	err := runSessionInput(t, SessionConfig{
		ListenerName:           testIMAPService,
		ServiceName:            testIMAPService,
		Network:                testNetworkTCP,
		TLSMode:                TLSModeStartTLS,
		PreauthTimeout:         time.Second,
		MaxPreauthLineBytes:    8,
		MaxPreauthLiteralBytes: 16,
	}, "12345678\n")

	if !errors.Is(err, ErrPreauthLineTooLarge) {
		t.Fatalf("session error = %v, want %v", err, ErrPreauthLineTooLarge)
	}
}

// TestSessionRejectsOversizedPreauthLiteral verifies literal limits are enforced at the boundary.
func TestSessionRejectsOversizedPreauthLiteral(t *testing.T) {
	err := runSessionInput(t, SessionConfig{
		ListenerName:           testIMAPService,
		ServiceName:            testIMAPService,
		Network:                testNetworkTCP,
		TLSMode:                TLSModeStartTLS,
		PreauthTimeout:         time.Second,
		MaxPreauthLineBytes:    64,
		MaxPreauthLiteralBytes: 4,
	}, "A001 APPEND mailbox {5}\r\n")

	if !errors.Is(err, ErrPreauthLiteralTooLarge) {
		t.Fatalf("session error = %v, want %v", err, ErrPreauthLiteralTooLarge)
	}
}

// testSessionConfig returns a minimal valid IMAP session configuration.
func testSessionConfig() SessionConfig {
	return SessionConfig{
		ListenerName:           testIMAPSService,
		ServiceName:            testIMAPSService,
		Network:                testNetworkTCP,
		TLSMode:                TLSModeImplicit,
		PreauthTimeout:         time.Second,
		MaxPreauthLineBytes:    64,
		MaxPreauthLiteralBytes: 16,
	}
}

// runSessionInput serves one net.Pipe session and returns its terminal error.
func runSessionInput(t *testing.T, cfg SessionConfig, input string) error {
	t.Helper()

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	handler := NewHandler(cfg)
	done := make(chan error, 1)

	go func() {
		defer func() { _ = server.Close() }()

		done <- handler.Serve(context.Background(), server)
	}()

	buffer := make([]byte, 128)
	if _, err := client.Read(buffer); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	if _, err := io.WriteString(client, input); err != nil {
		t.Fatalf("write input: %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	_, _ = client.Read(buffer)
	_ = client.SetReadDeadline(time.Time{})

	select {
	case err := <-done:
		return err
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for session error")
	}

	return nil
}
