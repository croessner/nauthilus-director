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

package backend

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

const (
	testClientTLSServerName = "backend.test"
	testClientTLSMode       = "starttls"
	testClientTLSBackend    = "imap-a"
)

// TestClientTLSConfigCacheResumesBackendSessions verifies that the second connection to a backend resumes the
// first TLS session instead of a full handshake, and that the configuration is built once.
func TestClientTLSConfigCacheResumesBackendSessions(t *testing.T) {
	serverConfig, roots := resumableTLSServerConfig(t)
	address := startResumableTLSServer(t, serverConfig)
	target := Backend{Identifier: testClientTLSBackend, TLS: TLSConfig{Mode: testClientTLSMode, ServerName: testClientTLSServerName}}
	cache := NewClientTLSConfigCache()
	builds := 0

	build := func() (*tls.Config, error) {
		builds++

		return &tls.Config{MinVersion: tls.VersionTLS13, ServerName: testClientTLSServerName, RootCAs: roots}, nil
	}

	resumed := make([]bool, 0, 2)

	for range 2 {
		config, err := cache.Config(target, build)
		if err != nil {
			t.Fatalf("Config returned error: %v", err)
		}

		resumed = append(resumed, resumableHandshake(t, address, config))
	}

	if builds != 1 {
		t.Fatalf("configuration builds = %d, want 1", builds)
	}

	if resumed[0] || !resumed[1] {
		t.Fatalf("resumed = %v, want a full first handshake and a resumed second one", resumed)
	}
}

// TestClientTLSConfigCacheRebuildsOnChangedSettings verifies reloads and the TTL replace the configuration.
func TestClientTLSConfigCacheRebuildsOnChangedSettings(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cache := NewClientTLSConfigCache()
	cache.now = func() time.Time { return now }
	builds := 0
	build := func() (*tls.Config, error) {
		builds++

		return &tls.Config{MinVersion: tls.VersionTLS12}, nil
	}

	target := Backend{Identifier: testClientTLSBackend, TLS: TLSConfig{Mode: testClientTLSMode, ServerName: "a.test"}}
	first, _ := cache.Config(target, build)

	target.TLS.ServerName = "b.test"
	second, _ := cache.Config(target, build)

	now = now.Add(clientTLSConfigTTL)
	third, _ := cache.Config(target, build)

	if builds != 3 || first == second || second == third {
		t.Fatalf("builds = %d, distinct configs %v/%v, want a rebuild per settings change and per TTL",
			builds, first != second, second != third)
	}

	if second.ClientSessionCache != third.ClientSessionCache || first.ClientSessionCache == second.ClientSessionCache {
		t.Fatal("session cache must survive a TTL rebuild and restart with changed settings")
	}

	var uncachedCache *ClientTLSConfigCache

	uncached, err := uncachedCache.Config(target, build)
	if err != nil || uncached.ClientSessionCache != nil {
		t.Fatal("a nil cache must build a fresh configuration without session resumption")
	}
}

// resumableTLSServerConfig creates a TLS 1.3 server with a fixed ticket key, like a long-running backend process.
func resumableTLSServerConfig(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: testClientTLSServerName},
		DNSNames:     []string{testClientTLSServerName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,

		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(certificate)

	config := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: certificate}},
	}
	config.SetSessionTicketKeys([][32]byte{{1, 2, 3}})

	return config, roots
}

// startResumableTLSServer answers every connection with one byte after the handshake, so the client reads the
// session ticket that follows the handshake.
func startResumableTLSServer(t *testing.T, config *tls.Config) string {
	t.Helper()

	listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}

			go func() {
				defer func() { _ = conn.Close() }()

				_, _ = conn.Write([]byte{'+'})
			}()
		}
	}()

	return listener.Addr().String()
}

// resumableHandshake connects once, reads the greeting byte and reports whether the session was resumed.
func resumableHandshake(t *testing.T, address string, config *tls.Config) bool {
	t.Helper()

	raw, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	conn := tls.Client(raw, config)
	defer func() { _ = conn.Close() }()

	buffer := make([]byte, 1)
	if _, err := conn.Read(buffer); err != nil {
		t.Fatalf("Read: %v", err)
	}

	return conn.ConnectionState().DidResume
}
