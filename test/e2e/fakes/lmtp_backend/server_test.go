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

//nolint:goconst,wsl_v5 // Scripted status tables repeat wire recipients for readability.
package lmtpbackend

import (
	"bufio"
	"net"
	"testing"
	"time"
)

// TestScriptedFinalStatusesAreDeterministic proves recipient status scripting is stable.
func TestScriptedFinalStatusesAreDeterministic(t *testing.T) {
	server := Start(t, Options{
		FinalStatus: map[string]Status{
			"<temp@example.test>": {Code: "451", Enhanced: "4.2.0", Text: "temporary policy"},
			"<perm@example.test>": {Code: "552", Enhanced: "5.2.2", Text: "mailbox full"},
		},
	})

	conn, err := net.DialTimeout("tcp", server.Address(), time.Second)
	if err != nil {
		t.Fatalf("dial fake LMTP backend: %v", err)
	}
	defer func() { _ = conn.Close() }()

	reader := bufio.NewReader(conn)
	expectBackendTestLine(t, reader, "220 fake LMTP backend ready\r\n")
	writeBackendTestLine(t, conn, "LHLO client")
	expectBackendTestLine(t, reader, "250 fake-lmtp-backend\r\n")
	writeBackendTestLine(t, conn, "MAIL FROM:<sender@example.test>")
	expectBackendTestLine(t, reader, "250 2.1.0 sender ok\r\n")
	writeBackendTestLine(t, conn, "RCPT TO:<temp@example.test>")
	expectBackendTestLine(t, reader, "250 2.1.5 recipient ok\r\n")
	writeBackendTestLine(t, conn, "RCPT TO:<perm@example.test>")
	expectBackendTestLine(t, reader, "250 2.1.5 recipient ok\r\n")
	writeBackendTestLine(t, conn, "DATA")
	expectBackendTestLine(t, reader, "354 2.0.0 send data\r\n")
	writeBackendTestLine(t, conn, "body")
	writeBackendTestLine(t, conn, ".")
	expectBackendTestLine(t, reader, "451 4.2.0 temporary policy\r\n")
	expectBackendTestLine(t, reader, "552 5.2.2 mailbox full\r\n")

	observation := server.ExpectObservation(t)
	if len(observation.Recipients) != 2 || observation.Recipients[0] != "<temp@example.test>" || observation.Recipients[1] != "<perm@example.test>" {
		t.Fatalf("recipients = %#v", observation.Recipients)
	}
}

// expectBackendTestLine reads one exact backend test line.
func expectBackendTestLine(t *testing.T, reader *bufio.Reader, want string) {
	t.Helper()

	got, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read backend line: %v", err)
	}
	if got != want {
		t.Fatalf("line = %q, want %q", got, want)
	}
}

// writeBackendTestLine writes one CRLF-terminated backend test command.
func writeBackendTestLine(t *testing.T, conn net.Conn, line string) {
	t.Helper()

	if _, err := conn.Write([]byte(line + "\r\n")); err != nil {
		t.Fatalf("write backend line %q: %v", line, err)
	}
}
