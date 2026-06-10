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

package listener

import (
	"net"
	"testing"

	"github.com/croessner/nauthilus-director/internal/config"
)

// TestPlaintextListenerAliasesSkipTLSMaterialRequirements verifies non-TLS modes bind without certificates.
func TestPlaintextListenerAliasesSkipTLSMaterialRequirements(t *testing.T) {
	for _, mode := range []string{tlsModePlaintext, tlsModeDisabled, tlsModeNone} {
		t.Run(mode, func(t *testing.T) {
			cfg := plaintextLMTPListenerConfig(t, mode)
			recorder := newRecordingHandler()
			manager, address := startManager(t, cfg, testLMTPListener, WithSessionHandlerFactory(recorder.factory))

			snapshot := waitForListenerSnapshot(t, manager, testLMTPListener, func(snapshot Snapshot) bool {
				return snapshot.BoundAddress != ""
			})

			if snapshot.ImplicitTLS {
				t.Fatal("plaintext listener was marked as implicit TLS")
			}

			if snapshot.TLSMode != tlsModePlaintext {
				t.Fatalf("snapshot TLS mode = %q, want %q", snapshot.TLSMode, tlsModePlaintext)
			}

			conn, err := net.Dial(networkTCP, address)
			if err != nil {
				t.Fatalf("dial plaintext listener: %v", err)
			}
			defer func() { _ = conn.Close() }()

			if line := readLine(t, conn); line != testGreeting {
				t.Fatalf("greeting = %q, want %q", line, testGreeting)
			}
		})
	}
}

// plaintextLMTPListenerConfig returns one LMTP listener without TLS certificate material.
func plaintextLMTPListenerConfig(t *testing.T, mode string) config.Config {
	t.Helper()

	cfg := singleListenerConfig(t, testLMTPListener, mode)
	entry := cfg.Director.Listeners[testLMTPListener]
	entry.TLS.Cert = ""
	entry.TLS.Key = config.Secret("")
	entry.TLS.ClientCA = ""
	entry.TLS.RequireClientCert = false

	if entry.LMTP != nil {
		entry.LMTP.ClientAuth.Required = false
		entry.LMTP.ClientAuth.Mechanisms = nil
		entry.LMTP.Capabilities = []string{"SMTPUTF8"}
	}

	cfg.Director.Listeners[testLMTPListener] = entry

	return cfg
}
