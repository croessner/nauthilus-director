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

//go:build interop

package e2e

import (
	"bufio"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
)

const interopBackendAddressEnv = "NAUTHILUS_DIRECTOR_INTEROP_BACKEND_ADDR"

// TestDovecotCredentialReplayInterop proves public director login and proxy handoff to real Dovecot.
func TestDovecotCredentialReplayInterop(t *testing.T) {
	backendAddress := os.Getenv(interopBackendAddressEnv)
	if backendAddress == "" {
		t.Skipf("%s is required for real IMAP interop", interopBackendAddressEnv)
	}

	director := startDirector(t, directorOptions{
		Authenticator:  staticInteropAuthenticator{},
		BackendAuth:    credentialReplayBackendAuth(false),
		BackendAddress: backendAddress,
		BackendTLS: config.BackendTLSConfig{
			Mode:               "starttls",
			MinTLSVersion:      "TLS1.2",
			InsecureSkipVerify: true,
		},
		Recorder: newCapturedRecorder(),
		TLSMode:  "starttls",
	})
	defer director.Stop(t)

	client := dialPlain(t, director.Address())
	defer func() { _ = client.Close() }()

	reader := bufio.NewReader(client)
	expectLine(t, reader, "* OK nauthilus-director IMAP session ready\r\n")
	writeLine(t, client, `A001 LOGIN "`+e2eAccount+`" "`+e2ePassword+`"`)
	expectLine(t, reader, "A001 OK Authentication completed\r\n")
	writeLine(t, client, "A002 NOOP")

	response := readLine(t, reader)
	if !strings.HasPrefix(response, "A002 OK") {
		t.Fatalf("Dovecot post-auth response = %q, want tagged OK", response)
	}
}

type staticInteropAuthenticator struct{}

// Authenticate returns an accepted account for real-backend interop.
func (staticInteropAuthenticator) Authenticate(context.Context, nauthilus.AuthRequest) (nauthilus.AuthResult, error) {
	return nauthilus.AuthResult{
		Decision: nauthilus.DecisionAuthenticated,
		Account:  e2eAccount,
		Attributes: map[string][]string{
			"account":   {e2eAccount},
			"tenant":    {e2eTenant},
			"mailShard": {e2eShardTag},
		},
	}, nil
}
