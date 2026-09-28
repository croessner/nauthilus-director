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

//nolint:goconst // PROXY fixtures repeat documentation address ranges intentionally.
package listener

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/observability"
)

// localProxyConfig returns a trusted PROXY listener that accepts LOCAL headers.
func localProxyConfig(t *testing.T, trustedCIDRs []string) config.Config {
	t.Helper()

	cfg := proxyListenerConfig(t, trustedCIDRs)
	entry := cfg.Director.Listeners[testIMAPListener]
	entry.ProxyProtocol.AcceptLocal = true
	cfg.Director.Listeners[testIMAPListener] = entry

	return cfg
}

// TestProxyProtocolAcceptLocalKeepsRealEndpoints proves LOCAL and UNKNOWN keep the TCP peer.
func TestProxyProtocolAcceptLocalKeepsRealEndpoints(t *testing.T) {
	for name, header := range map[string][]byte{
		"v2 local":   proxyLocalHeader(),
		"v1 unknown": []byte("PROXY UNKNOWN\r\n"),
	} {
		t.Run(name, func(t *testing.T) {
			recorder := newRecordingHandler()
			events := &recordingListenerObservability{}
			_, address := startManager(t, localProxyConfig(t, []string{trustedLocalhostCIDR}), testIMAPListener,
				WithSessionHandlerFactory(recorder.factory), WithObservabilityRecorder(events))

			conn, err := net.Dial(networkTCP, address)
			if err != nil {
				t.Fatalf("dial listener: %v", err)
			}
			defer func() { _ = conn.Close() }()

			if _, err := conn.Write(header); err != nil {
				t.Fatalf("write header: %v", err)
			}

			recorder.expectRemote(t, conn.LocalAddr().String())

			event, ok := events.lastWithResult(observability.EventProxyProtocol, listenerResultLocal)
			if !ok || event.MetricLabels["reason_class"] != listenerResultOK {
				t.Fatalf("proxy protocol event = %+v, want result local", event.MetricLabels)
			}
		})
	}
}

// TestProxyProtocolAcceptLocalStillRequiresTrustedPeer refuses untrusted peers before reading.
func TestProxyProtocolAcceptLocalStillRequiresTrustedPeer(t *testing.T) {
	expectProxyRejection(t, localProxyConfig(t, []string{"192.0.2.0/24"}), func(t *testing.T, conn net.Conn) {
		t.Helper()

		_, _ = conn.Write(proxyLocalHeader())
	})
}

// TestProxyProtocolLocalRejectedWithoutFlag keeps the fail-closed default.
func TestProxyProtocolLocalRejectedWithoutFlag(t *testing.T) {
	expectProxyRejection(t, proxyListenerConfig(t, []string{trustedLocalhostCIDR}), func(t *testing.T, conn net.Conn) {
		t.Helper()

		_, _ = io.WriteString(conn, "PROXY UNKNOWN\r\n")
	})
}

// TestProxyProtocolAcceptLocalKeepsProxiedClients still adopts client addresses from PROXY headers.
func TestProxyProtocolAcceptLocalKeepsProxiedClients(t *testing.T) {
	recorder := newRecordingHandler()
	_, address := startManager(t, localProxyConfig(t, []string{trustedLocalhostCIDR}), testIMAPListener, WithSessionHandlerFactory(recorder.factory))

	conn, err := net.Dial(networkTCP, address)
	if err != nil {
		t.Fatalf("dial listener: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.WriteString(conn, "PROXY TCP4 198.51.100.30 203.0.113.30 34567 143\r\n")

	recorder.expectRemote(t, "198.51.100.30:34567")
}
