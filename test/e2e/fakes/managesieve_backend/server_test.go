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

//nolint:goconst,wsl_v5 // Fake backend tests repeat protocol command names intentionally.
package managesievebackend

import (
	"bufio"
	"encoding/base64"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestScriptedCommandStatusesAreDeterministic proves fake backend status overrides are stable.
func TestScriptedCommandStatusesAreDeterministic(t *testing.T) {
	server := Start(t, Options{
		CommandStatus: map[string]Status{
			commandListScripts: {Condition: responseNo, Code: "TRYLATER", Text: "scripted temporary failure"},
		},
	})

	conn := dialBackendTest(t, server.Address())
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	readBackendResponse(t, reader)

	writeBackendLine(t, conn, `AUTHENTICATE "PLAIN" "`+base64.StdEncoding.EncodeToString([]byte("\x00user\x00secret"))+`"`)
	expectBackendLine(t, reader, "OK \"authenticated\"\r\n")
	writeBackendLine(t, conn, "LISTSCRIPTS")
	expectBackendLine(t, reader, "NO (TRYLATER) \"scripted temporary failure\"\r\n")
}

// TestObservationsHideScriptAndCredentialMaterial proves observations are redacted.
func TestObservationsHideScriptAndCredentialMaterial(t *testing.T) {
	scriptName := "sentinel-script-name"
	scriptContent := "require [\"fileinto\"];\n# sentinel-script-content"
	server := Start(t, Options{ExpectedScripts: map[string]string{scriptName: scriptContent}})

	conn := dialBackendTest(t, server.Address())
	reader := bufio.NewReader(conn)
	readBackendResponse(t, reader)
	writeBackendLine(t, conn, `AUTHENTICATE "PLAIN" "`+base64.StdEncoding.EncodeToString([]byte("\x00user\x00secret"))+`"`)
	expectBackendLine(t, reader, "OK \"authenticated\"\r\n")
	writeBackendLine(t, conn, `PUTSCRIPT "`+scriptName+`" {`+strconvItoa(len(scriptContent))+`}`)
	writeBackendRaw(t, conn, scriptContent+"\r\n")
	expectBackendLine(t, reader, "OK \"putscript completed\"\r\n")
	_ = conn.Close()

	observation := server.ExpectObservation(t)
	text := strings.Join(observation.AuthMechanisms, ",") + strings.Join(commandNames(observation.Commands), ",")
	for _, forbidden := range []string{scriptName, scriptContent, "secret"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("observation leaked %q: %#v", forbidden, observation)
		}
	}
	if len(observation.Commands) != 1 || !observation.Commands[0].ScriptNameMatched || !observation.Commands[0].ScriptContentMatched {
		t.Fatalf("redacted command observation = %#v, want matched sentinel facts", observation.Commands)
	}
}

// dialBackendTest opens one backend test connection.
func dialBackendTest(t *testing.T, address string) net.Conn {
	t.Helper()

	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatalf("dial fake ManageSieve backend: %v", err)
	}

	return conn
}

// readBackendResponse consumes one ManageSieve response block.
func readBackendResponse(t *testing.T, reader *bufio.Reader) []string {
	t.Helper()

	var lines []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read backend response: %v", err)
		}
		lines = append(lines, line)
		if strings.HasPrefix(line, "OK") || strings.HasPrefix(line, "NO") || strings.HasPrefix(line, "BYE") {
			return lines
		}
	}
}

// expectBackendLine reads and compares one backend test line.
func expectBackendLine(t *testing.T, reader *bufio.Reader, want string) {
	t.Helper()

	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read backend line: %v", err)
	}
	if line != want {
		t.Fatalf("backend line = %q, want %q", line, want)
	}
}

// writeBackendLine writes one CRLF-terminated backend command.
func writeBackendLine(t *testing.T, conn net.Conn, line string) {
	t.Helper()

	writeBackendRaw(t, conn, line+"\r\n")
}

// writeBackendRaw writes raw backend bytes.
func writeBackendRaw(t *testing.T, conn net.Conn, payload string) {
	t.Helper()

	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write backend bytes: %v", err)
	}
}

// commandNames returns only redacted command names for assertion text.
func commandNames(commands []CommandObservation) []string {
	names := make([]string, 0, len(commands))
	for _, command := range commands {
		names = append(names, command.Command)
	}

	return names
}

// strconvItoa keeps tests readable without pulling conversion into assertions.
func strconvItoa(value int) string {
	return strconv.Itoa(value)
}
