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

//nolint:wsl_v5 // Fake POP3 backend tests keep wire transcript steps adjacent.
package pop3backend

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

const (
	testMessageContent = "Subject: fake POP3 proof\r\n\r\nsentinel body"
	testMessageUIDL    = "sentinel-uidl"
)

// TestFakePOP3BackendObservesRedactedMailboxFacts proves safe deterministic observations.
func TestFakePOP3BackendObservesRedactedMailboxFacts(t *testing.T) {
	server := Start(t, Options{
		Messages: []Message{{Number: 1, UIDL: testMessageUIDL, Content: testMessageContent}},
	})

	conn, reader := dialTestPOP3Backend(t, server.Address())
	defer func() { _ = conn.Close() }()

	expectBackendLine(t, reader, "+OK")
	writeBackendLine(t, conn, "USER alice@example.test")
	expectBackendLine(t, reader, "+OK")
	writeBackendLine(t, conn, "PASS secret")
	expectBackendLine(t, reader, "+OK")
	writeBackendLine(t, conn, "UIDL 1")
	expectBackendLine(t, reader, "+OK 1 "+testMessageUIDL)
	writeBackendLine(t, conn, "RETR 1")
	expectBackendLine(t, reader, "+OK")
	readUntilDot(t, reader)
	writeBackendLine(t, conn, "QUIT")
	expectBackendLine(t, reader, "+OK")
	_ = conn.Close()

	observation := server.ExpectObservation(t)
	if strings.Join(observation.AuthMechanisms, ",") != "userpass" {
		t.Fatalf("auth mechanisms = %v, want userpass", observation.AuthMechanisms)
	}
	if !observation.MessageNumberMatched || !observation.UIDLMatched || !observation.ContentMatched {
		t.Fatalf("observation = %#v, want redacted mailbox sentinel matches", observation)
	}
	dump := fmt.Sprintf("%#v", observation)
	if strings.Contains(dump, testMessageUIDL) || strings.Contains(dump, testMessageContent) {
		t.Fatalf("observation leaked mailbox data: %#v", observation)
	}
}

// TestFakePOP3BackendScriptedStatus proves deterministic status overrides.
func TestFakePOP3BackendScriptedStatus(t *testing.T) {
	server := Start(t, Options{
		CommandStatus: map[string]Status{
			commandStat: {Code: responseErr, Text: "maildrop locked"},
		},
	})

	conn, reader := dialTestPOP3Backend(t, server.Address())
	defer func() { _ = conn.Close() }()

	expectBackendLine(t, reader, "+OK")
	writeBackendLine(t, conn, "USER alice@example.test")
	expectBackendLine(t, reader, "+OK")
	writeBackendLine(t, conn, "PASS secret")
	expectBackendLine(t, reader, "+OK")
	writeBackendLine(t, conn, "STAT")
	expectBackendLine(t, reader, "-ERR maildrop locked")
	writeBackendLine(t, conn, "QUIT")
	expectBackendLine(t, reader, "+OK")
}

// dialTestPOP3Backend opens one fake backend test client.
func dialTestPOP3Backend(t *testing.T, address string) (net.Conn, *bufio.Reader) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatalf("dial fake POP3 backend: %v", err)
	}

	return conn, bufio.NewReader(conn)
}

// writeBackendLine writes one CRLF-terminated backend test command.
func writeBackendLine(t *testing.T, conn net.Conn, line string) {
	t.Helper()

	if _, err := fmt.Fprintf(conn, "%s\r\n", line); err != nil {
		t.Fatalf("write POP3 backend line: %v", err)
	}
}

// expectBackendLine verifies a POP3 backend response prefix.
func expectBackendLine(t *testing.T, reader *bufio.Reader, prefix string) {
	t.Helper()

	line := readBackendLine(t, reader)
	if !strings.HasPrefix(line, prefix) {
		t.Fatalf("backend line = %q, want prefix %q", line, prefix)
	}
}

// readUntilDot consumes a POP3 multiline response body.
func readUntilDot(t *testing.T, reader *bufio.Reader) {
	t.Helper()

	for {
		line := readBackendLine(t, reader)
		if line == ".\r\n" {
			return
		}
	}
}

// readBackendLine reads one bounded backend response line.
func readBackendLine(t *testing.T, reader *bufio.Reader) string {
	t.Helper()

	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read POP3 backend line: %v", err)
	}

	return line
}
