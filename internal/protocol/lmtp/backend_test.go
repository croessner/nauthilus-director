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

//nolint:funlen // Scripted protocol tests keep the wire transcript visible.
package lmtp

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/config"
)

const (
	testBackendAddress       = "127.0.0.1:2424"
	testBackendLHLODomain    = "mailstore"
	testBackendPassword      = "backend-secret"
	testBackendServerName    = "mailstore.example.test"
	testBackendServiceUser   = "director-lmtp"
	testBackendTLSHost       = "localhost"
	testBackendTLSHostTarget = "localhost:2424"
	testBackendToken         = "backend-token"
	testBackendCommandMail   = "MAIL FROM"
	testBackendCommandRCPT   = "RCPT TO"
	testLMTPProxyHeaderV4    = "PROXY TCP4 203.0.113.10 198.51.100.20 42500 24"
	testLMTPHealthProxyV4    = "PROXY TCP4 10.10.0.1 10.10.0.2 5024 24"
	testLHLOSizeProse        = testBackendLHLODomain + " says SIZE 10485760"
)

// TestBackendConnectorHandlesPlaintextModes verifies cleartext LMTP capability discovery.
func TestBackendConnectorHandlesPlaintextModes(t *testing.T) {
	for _, mode := range []string{backendTLSPlaintext, backendTLSDisabled, backendTLSNone} {
		t.Run(mode, func(t *testing.T) {
			dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
				reader := bufio.NewReader(conn)
				writeLMTPBackendLine(t, conn, "220 backend ready")
				expectLMTPBackendLine(t, reader, "LHLO "+backendLHLOName)
				writeLMTPBackendLine(t, conn, "250-mailstore")
				writeLMTPBackendLine(t, conn, "250 "+capabilityCHUNKING)
			})

			connection, err := NewTCPBackendConnector(dialer).Connect(
				context.Background(),
				testLMTPBackendConnectRequest(testLMTPBackendTarget(mode)),
			)
			if err != nil {
				t.Fatalf("Connect returned error: %v", err)
			}
			defer func() { _ = connection.Conn().Close() }()

			if connection.TLSActive() || connection.TLSVerified() {
				t.Fatalf("TLS state active=%v verified=%v, want plaintext", connection.TLSActive(), connection.TLSVerified())
			}

			if !connection.CapabilitySet().Has(capabilityCHUNKING) {
				t.Fatalf("capabilities = %v, want CHUNKING", connection.Capabilities())
			}

			dialer.Wait(t)
		})
	}
}

// TestBackendConnectorWritesProxyBeforePlaintextGreeting verifies PROXY precedes greeting reads.
func TestBackendConnectorWritesProxyBeforePlaintextGreeting(t *testing.T) {
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := bufio.NewReader(conn)
		expectLMTPBackendLine(t, reader, testLMTPProxyHeaderV4)
		writeLMTPBackendLine(t, conn, "220 backend ready")
		expectLMTPBackendLine(t, reader, "LHLO "+backendLHLOName)
		writeLMTPBackendLine(t, conn, "250 mailstore")
	})

	connection, err := NewTCPBackendConnector(dialer).Connect(
		context.Background(),
		testProxyLMTPBackendConnectRequest(testLMTPBackendTarget(backendTLSPlaintext)),
	)
	if err != nil {
		t.Fatalf("Connect returned error: %v", err)
	}
	defer func() { _ = connection.Conn().Close() }()

	if connection.TLSActive() {
		t.Fatal("plaintext backend unexpectedly enabled TLS")
	}

	dialer.Wait(t)
}

// TestBackendConnectorWritesProxyBeforeStartTLSGreeting verifies PROXY precedes STARTTLS setup.
func TestBackendConnectorWritesProxyBeforeStartTLSGreeting(t *testing.T) {
	certPath, certificate := writeLMTPBackendTestCertificate(t)
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := bufio.NewReader(conn)
		expectLMTPBackendLine(t, reader, testLMTPProxyHeaderV4)
		writeLMTPBackendLine(t, conn, "220 backend ready")
		expectLMTPBackendLine(t, reader, "LHLO "+backendLHLOName)
		writeLMTPBackendLine(t, conn, "250-mailstore")
		writeLMTPBackendLine(t, conn, "250 STARTTLS")
		expectLMTPBackendLine(t, reader, "STARTTLS")
		writeLMTPBackendLine(t, conn, "220 ready for tls")

		tlsConn := tls.Server(conn, lmtpBackendTestTLSConfig(t, certificate))
		if err := tlsConn.Handshake(); err != nil {
			t.Errorf("server handshake: %v", err)
			return
		}

		tlsReader := bufio.NewReader(tlsConn)
		expectLMTPBackendLine(t, tlsReader, "LHLO "+backendLHLOName)
		writeLMTPBackendLine(t, tlsConn, "250 mailstore")
	})

	connection, err := NewTCPBackendConnector(dialer).Connect(
		context.Background(),
		testProxyLMTPBackendConnectRequest(testLMTPBackendTargetWithCA(backendTLSStartTLS, certPath)),
	)
	if err != nil {
		t.Fatalf("Connect returned error: %v", err)
	}
	defer func() { _ = connection.Conn().Close() }()

	if !connection.TLSActive() || !connection.TLSVerified() {
		t.Fatalf("TLS state active=%v verified=%v", connection.TLSActive(), connection.TLSVerified())
	}

	dialer.Wait(t)
}

// TestBackendConnectorWritesProxyBeforeImplicitTLS verifies PROXY precedes the TLS handshake.
func TestBackendConnectorWritesProxyBeforeImplicitTLS(t *testing.T) {
	certPath, certificate := writeLMTPBackendTestCertificate(t)
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := bufio.NewReader(conn)
		expectLMTPBackendLine(t, reader, testLMTPProxyHeaderV4)

		tlsConn := tls.Server(conn, lmtpBackendTestTLSConfig(t, certificate))
		if err := tlsConn.Handshake(); err != nil {
			t.Errorf("server handshake: %v", err)
			return
		}

		tlsReader := bufio.NewReader(tlsConn)
		writeLMTPBackendLine(t, tlsConn, "220 backend ready")
		expectLMTPBackendLine(t, tlsReader, "LHLO "+backendLHLOName)
		writeLMTPBackendLine(t, tlsConn, "250 mailstore")
	})

	connection, err := NewTCPBackendConnector(dialer).Connect(
		context.Background(),
		testProxyLMTPBackendConnectRequest(testLMTPBackendTargetWithCA(backendTLSImplicit, certPath)),
	)
	if err != nil {
		t.Fatalf("Connect returned error: %v", err)
	}
	defer func() { _ = connection.Conn().Close() }()

	if !connection.TLSActive() || !connection.TLSVerified() {
		t.Fatalf("TLS state active=%v verified=%v", connection.TLSActive(), connection.TLSVerified())
	}

	dialer.Wait(t)
}

// TestBackendConnectorWritesProxyBeforeBackendAuth verifies auth follows PROXY and LHLO.
func TestBackendConnectorWritesProxyBeforeBackendAuth(t *testing.T) {
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := bufio.NewReader(conn)
		expectLMTPBackendLine(t, reader, testLMTPProxyHeaderV4)
		writeLMTPBackendLine(t, conn, "220 backend ready")
		expectLMTPBackendLine(t, reader, "LHLO "+backendLHLOName)
		writeLMTPBackendLine(t, conn, "250-mailstore")
		writeLMTPBackendLine(t, conn, "250 AUTH PLAIN")
		expectLMTPBackendLine(t, reader, expectedPlainAuthCommand())
		writeLMTPBackendLine(t, conn, "235 2.7.0 ok")
	})

	target := testLMTPBackendTarget(backendTLSPlaintext)
	target.Auth = backend.AuthConfig{
		Mode: backendAuthModeSASL,
		SASL: backend.SASLConfig{
			Mechanism: mechanismPlain,
			Username:  testBackendServiceUser,
			Password:  config.Secret(testBackendPassword),
		},
	}

	connection, err := NewTCPBackendConnector(dialer).Connect(
		context.Background(),
		testProxyLMTPBackendConnectRequest(target),
	)
	if err != nil {
		t.Fatalf("Connect returned error: %v", err)
	}
	defer func() { _ = connection.Conn().Close() }()

	if err := AuthenticateBackend(connection, target); err != nil {
		t.Fatalf("AuthenticateBackend returned error: %v", err)
	}

	dialer.Wait(t)
}

// TestBackendConnectorHandlesStartTLS verifies STARTTLS before final LHLO state.
func TestBackendConnectorHandlesStartTLS(t *testing.T) {
	certPath, certificate := writeLMTPBackendTestCertificate(t)
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := bufio.NewReader(conn)
		writeLMTPBackendLine(t, conn, "220 backend ready")
		expectLMTPBackendLine(t, reader, "LHLO "+backendLHLOName)
		writeLMTPBackendLine(t, conn, "250-mailstore")
		writeLMTPBackendLine(t, conn, "250 STARTTLS")
		expectLMTPBackendLine(t, reader, "STARTTLS")
		writeLMTPBackendLine(t, conn, "220 ready for tls")

		tlsConn := tls.Server(conn, lmtpBackendTestTLSConfig(t, certificate))
		if err := tlsConn.Handshake(); err != nil {
			t.Errorf("server handshake: %v", err)
			return
		}

		tlsReader := bufio.NewReader(tlsConn)
		expectLMTPBackendLine(t, tlsReader, "LHLO "+backendLHLOName)
		writeLMTPBackendLine(t, tlsConn, "250-mailstore")
		writeLMTPBackendLine(t, tlsConn, "250-"+capabilityCHUNKING)
		writeLMTPBackendLine(t, tlsConn, "250 AUTH PLAIN")
	})

	connection, err := NewTCPBackendConnector(dialer).Connect(
		context.Background(),
		testLMTPBackendConnectRequest(testLMTPBackendTargetWithCA(backendTLSStartTLS, certPath)),
	)
	if err != nil {
		t.Fatalf("Connect returned error: %v", err)
	}
	defer func() { _ = connection.Conn().Close() }()

	if !connection.TLSActive() || !connection.TLSVerified() {
		t.Fatalf("TLS state active=%v verified=%v", connection.TLSActive(), connection.TLSVerified())
	}

	if !connection.CapabilitySet().Has(capabilityAUTH + "=" + strings.ToUpper(mechanismPlain)) {
		t.Fatalf("capabilities = %v, want AUTH PLAIN", connection.Capabilities())
	}

	dialer.Wait(t)
}

// TestBackendConnectorHandlesImplicitTLS verifies TLS wraps before the greeting.
func TestBackendConnectorHandlesImplicitTLS(t *testing.T) {
	certPath, certificate := writeLMTPBackendTestCertificate(t)
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		tlsConn := tls.Server(conn, lmtpBackendTestTLSConfig(t, certificate))
		if err := tlsConn.Handshake(); err != nil {
			t.Errorf("server handshake: %v", err)
			return
		}

		reader := bufio.NewReader(tlsConn)
		writeLMTPBackendLine(t, tlsConn, "220 backend ready")
		expectLMTPBackendLine(t, reader, "LHLO "+backendLHLOName)
		writeLMTPBackendLine(t, tlsConn, "250-mailstore")
		writeLMTPBackendLine(t, tlsConn, "250 "+capabilityCHUNKING)
	})

	connection, err := NewTCPBackendConnector(dialer).Connect(
		context.Background(),
		testLMTPBackendConnectRequest(testLMTPBackendTargetWithCA(backendTLSImplicit, certPath)),
	)
	if err != nil {
		t.Fatalf("Connect returned error: %v", err)
	}
	defer func() { _ = connection.Conn().Close() }()

	if !connection.TLSActive() || !connection.TLSVerified() {
		t.Fatalf("TLS state active=%v verified=%v", connection.TLSActive(), connection.TLSVerified())
	}

	dialer.Wait(t)
}

// TestBackendTLSRequiresServerNameForIPAddress verifies verified TLS fails closed without SNI.
func TestBackendTLSRequiresServerNameForIPAddress(t *testing.T) {
	target := testLMTPBackendTarget(backendTLSImplicit)
	target.Address = "127.0.0.1:2424"
	target.TLS.ServerName = ""

	_, _, _, err := backendTLSConfig(target)
	if !errors.Is(err, ErrBackendTLS) {
		t.Fatalf("backendTLSConfig error = %v, want TLS server_name rejection", err)
	}

	target.Address = testBackendServerName + ":2424"

	tlsConfig, verified, _, err := backendTLSConfig(target)
	if err != nil {
		t.Fatalf("backendTLSConfig returned error for hostname address: %v", err)
	}

	if tlsConfig.ServerName != testBackendServerName || !verified {
		t.Fatalf("TLS config server name = %q verified=%v", tlsConfig.ServerName, verified)
	}
}

// TestLHLOCapabilitiesAreParsedWithoutBannerText verifies prose does not create CHUNKING proof.
func TestLHLOCapabilitiesAreParsedWithoutBannerText(t *testing.T) {
	response := backendStatusResponse{
		code: responseStatusOK,
		lines: []string{
			"mailstore says CHUNKING, 8BITMIME and SIZE are words in prose",
			testPlainAuthCapability + " LOGIN",
			capabilityCHUNKING,
			capability8BITMIME,
		},
	}

	capabilities := lmtpCapabilitiesFromLHLO(response)
	if !capabilities.Has(capabilityCHUNKING) || !capabilities.Has(capability8BITMIME) ||
		!capabilities.Has(capabilityAUTH+"=PLAIN") || !capabilities.Has(capabilityAUTH+"=LOGIN") {
		t.Fatalf("capabilities = %v, want CHUNKING, 8BITMIME and AUTH mechanisms", capabilities.List())
	}

	bannerOnly := lmtpCapabilitiesFromLHLO(backendStatusResponse{
		code:  responseStatusOK,
		lines: []string{"mailstore says CHUNKING, 8BITMIME and SIZE"},
	})
	if bannerOnly.Has(capabilityCHUNKING) || bannerOnly.Has(capability8BITMIME) || bannerOnly.Has(capabilitySIZE) {
		t.Fatalf("banner-only capabilities = %v, want no CHUNKING, 8BITMIME or SIZE", bannerOnly.List())
	}
}

// TestLHLOSizeCapabilityFacts verifies RFC 1870 backend SIZE advertisement parsing.
func TestLHLOSizeCapabilityFacts(t *testing.T) {
	tests := []struct {
		name          string
		lines         []string
		wantSupport   bool
		wantMaximum   bool
		maximum       uint64
		wantChunking  bool
		want8BitMIME  bool
		wantAuthPlain bool
	}{
		{
			name:        "size without maximum",
			lines:       []string{capabilitySIZE},
			wantSupport: true,
		},
		{
			name:        "size zero has no fixed maximum",
			lines:       []string{capabilitySIZE + " 0"},
			wantSupport: true,
		},
		{
			name:        "size positive maximum",
			lines:       []string{capabilitySIZE + " 10485760"},
			wantSupport: true,
			wantMaximum: true,
			maximum:     10485760,
		},
		{
			name:  "negative size is unsafe",
			lines: []string{capabilitySIZE + " -1"},
		},
		{
			name:  "malformed size is unsafe",
			lines: []string{capabilitySIZE + " no"},
		},
		{
			name:  "overflowing size is unsafe",
			lines: []string{capabilitySIZE + " 18446744073709551616"},
		},
		{
			name:  "extra size parameter is unsafe",
			lines: []string{capabilitySIZE + " 10 20"},
		},
		{
			name:  "banner prose is ignored",
			lines: []string{testLHLOSizeProse},
		},
		{
			name:  "non-capability prose is not size support",
			lines: []string{testBackendLHLODomain, testLHLOSizeProse},
		},
		{
			name:          "token checks continue to work",
			lines:         []string{testBackendLHLODomain, testPlainAuthCapability, capabilityCHUNKING, capability8BITMIME},
			wantChunking:  true,
			want8BitMIME:  true,
			wantAuthPlain: true,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			capabilities, facts := lmtpBackendCapabilityFactsFromLHLO(backendStatusResponse{
				code:  responseStatusOK,
				lines: testCase.lines,
			})
			size := facts.Size()

			if capabilities.Has(capabilitySIZE) != testCase.wantSupport {
				t.Fatalf("SIZE token support = %v, want %v; capabilities=%v", capabilities.Has(capabilitySIZE), testCase.wantSupport, capabilities.List())
			}

			if size.Supported != testCase.wantSupport {
				t.Fatalf("SIZE fact support = %v, want %v", size.Supported, testCase.wantSupport)
			}

			maximum, ok := size.Maximum()
			if ok != testCase.wantMaximum || maximum != testCase.maximum {
				t.Fatalf("SIZE maximum = %d ok=%v, want %d ok=%v", maximum, ok, testCase.maximum, testCase.wantMaximum)
			}

			if capabilities.Has(capabilityCHUNKING) != testCase.wantChunking {
				t.Fatalf("CHUNKING support = %v, want %v", capabilities.Has(capabilityCHUNKING), testCase.wantChunking)
			}

			if capabilities.Has(capability8BITMIME) != testCase.want8BitMIME {
				t.Fatalf("8BITMIME support = %v, want %v", capabilities.Has(capability8BITMIME), testCase.want8BitMIME)
			}

			if capabilities.Has(capabilityAUTH+"=PLAIN") != testCase.wantAuthPlain {
				t.Fatalf("AUTH PLAIN support = %v, want %v", capabilities.Has(capabilityAUTH+"=PLAIN"), testCase.wantAuthPlain)
			}
		})
	}
}

// TestBackendConnectionSupportsChunkingFromSelectedLHLOCapabilities verifies the selected backend gate.
func TestBackendConnectionSupportsChunkingFromSelectedLHLOCapabilities(t *testing.T) {
	tests := []struct {
		name         string
		lhloLine     string
		wantChunking bool
	}{
		{
			name:         "advertised",
			lhloLine:     "250 chunking",
			wantChunking: true,
		},
		{
			name:     "not advertised",
			lhloLine: "250 8BITMIME",
		},
		{
			name:     "banner prose",
			lhloLine: "250 mailstore mentions CHUNKING",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
				reader := bufio.NewReader(conn)
				writeLMTPBackendLine(t, conn, "220 backend ready")
				expectLMTPBackendLine(t, reader, "LHLO "+backendLHLOName)
				writeLMTPBackendLine(t, conn, testCase.lhloLine)
			})

			connection, err := NewTCPBackendConnector(dialer).Connect(
				context.Background(),
				testLMTPBackendConnectRequest(testLMTPBackendTarget(backendTLSPlaintext)),
			)
			if err != nil {
				t.Fatalf("Connect returned error: %v", err)
			}
			defer func() { _ = connection.Conn().Close() }()

			if got := connection.supportsChunking(); got != testCase.wantChunking {
				t.Fatalf("connection supportsChunking = %v, want %v", got, testCase.wantChunking)
			}

			transaction := &backendTransaction{connection: connection}
			if got := transaction.supportsChunking(); got != testCase.wantChunking {
				t.Fatalf("transaction supportsChunking = %v, want %v", got, testCase.wantChunking)
			}

			dialer.Wait(t)
		})
	}
}

// TestFrontendDATABodyTransportSelectionUsesSelectedBackendCapabilities verifies DATA transport intent.
func TestFrontendDATABodyTransportSelectionUsesSelectedBackendCapabilities(t *testing.T) {
	tests := []struct {
		name         string
		capabilities []string
		denied       []string
		want         backendBodyTransport
	}{
		{
			name:         "backend can chunk",
			capabilities: []string{capabilityCHUNKING},
			want:         backendBodyTransportBDAT,
		},
		{
			name:         "listener denied chunking",
			capabilities: []string{capabilityCHUNKING},
			denied:       []string{capabilityCHUNKING},
			want:         backendBodyTransportDATA,
		},
		{
			name: "data fallback",
			want: backendBodyTransportDATA,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			transaction := &backendTransaction{
				connection:       &BackendConnection{capabilities: backend.NewCapabilitySet(testCase.capabilities...)},
				capabilityPolicy: NewCapabilityPolicy(nil, testCase.denied),
			}

			if got := transaction.frontendDATABodyTransport(); got != testCase.want {
				t.Fatalf("frontend DATA transport = %q, want %q", got, testCase.want)
			}
		})
	}
}

// TestBackendTransactionSendBDATPayloadWritesExactWireAndStatuses verifies payload helper semantics.
func TestBackendTransactionSendBDATPayloadWritesExactWireAndStatuses(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	transaction := &backendTransaction{connection: newBackendConnection(client)}
	done := make(chan struct{})

	go func() {
		defer close(done)

		reader := bufio.NewReader(server)
		expectLMTPBackendLine(t, reader, "BDAT 4")
		expectLMTPBackendBytes(t, reader, "body")
		writeLMTPBackendLine(t, server, "250 2.0.0 chunk ok")
		expectLMTPBackendLine(t, reader, "BDAT 0 LAST")
		writeLMTPBackendLine(t, server, "250 2.1.5 delivered")
		writeLMTPBackendLine(t, server, "451 4.2.0 delayed")
	}()

	chunkResult, err := transaction.sendBDATPayload([]byte("body"), false, 2)
	if err != nil {
		t.Fatalf("sendBDATPayload non-final returned error: %v", err)
	}

	if len(chunkResult.Statuses) != 1 || chunkResult.Statuses[0].Status != responseStatusOK {
		t.Fatalf("non-final result = %#v, want accepted chunk", chunkResult)
	}

	finalResult, err := transaction.sendBDATPayload(nil, true, 2)
	if err != nil {
		t.Fatalf("sendBDATPayload final returned error: %v", err)
	}

	if len(finalResult.Statuses) != 2 {
		t.Fatalf("final statuses = %d, want 2", len(finalResult.Statuses))
	}

	if finalResult.Statuses[0].Status != responseStatusOK || finalResult.Statuses[1].Status != responseStatusTemporary {
		t.Fatalf("final result = %#v, want accepted then temporary", finalResult)
	}

	waitForBackendAuthScript(t, done)
}

// TestSASLBackendAuthRequiresCredentialsAndVerifiedTLS checks fail-closed SASL policy.
func TestSASLBackendAuthRequiresCredentialsAndVerifiedTLS(t *testing.T) {
	connection := &BackendConnection{capabilities: backend.NewCapabilitySet(capabilityAUTH + "=PLAIN")}
	target := testLMTPBackendTarget(backendTLSPlaintext)
	target.Auth = backend.AuthConfig{
		Mode: backendAuthModeSASL,
		SASL: backend.SASLConfig{
			Mechanism:  mechanismPlain,
			Username:   testBackendServiceUser,
			Password:   config.Secret(testBackendPassword),
			RequireTLS: true,
		},
	}

	if err := AuthenticateBackend(connection, target); !errors.Is(err, ErrBackendAuthPolicy) {
		t.Fatalf("AuthenticateBackend without verified TLS error = %v, want policy", err)
	}

	connection.tlsActive = true
	connection.tlsVerified = true
	target.Auth.SASL.Password = config.Secret("")

	if err := AuthenticateBackend(connection, target); !errors.Is(err, ErrBackendAuthPolicy) {
		t.Fatalf("AuthenticateBackend without credentials error = %v, want policy", err)
	}
}

// TestOAuthBearerBackendAuthRequiresTokenAndVerifiedTLS checks fail-closed bearer policy.
func TestOAuthBearerBackendAuthRequiresTokenAndVerifiedTLS(t *testing.T) {
	connection := &BackendConnection{capabilities: backend.NewCapabilitySet(capabilityAUTH + "=OAUTHBEARER")}
	target := testLMTPBackendTarget(backendTLSPlaintext)
	target.Auth = backend.AuthConfig{
		Mode: backendAuthModeOAuthBearer,
		OAuthBearer: backend.OAuthBearerConfig{
			Token:      config.Secret(testBackendToken),
			RequireTLS: true,
		},
	}

	if err := AuthenticateBackend(connection, target); !errors.Is(err, ErrBackendAuthPolicy) {
		t.Fatalf("AuthenticateBackend without verified TLS error = %v, want policy", err)
	}

	connection.tlsActive = true
	connection.tlsVerified = true
	target.Auth.OAuthBearer.Token = config.Secret("")

	if err := AuthenticateBackend(connection, target); !errors.Is(err, ErrBackendAuthPolicy) {
		t.Fatalf("AuthenticateBackend without token error = %v, want policy", err)
	}
}

// TestNoAuthBackendDoesNotSendCredentials verifies plaintext no-auth is credential-free.
func TestNoAuthBackendDoesNotSendCredentials(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	connection := newBackendConnection(client)
	connection.capabilities = backend.NewCapabilitySet(capabilityAUTH+"=PLAIN", capabilityAUTH+"=OAUTHBEARER")

	target := testLMTPBackendTarget(backendTLSPlaintext)
	target.Auth.Mode = backendAuthModeNone

	if err := AuthenticateBackend(connection, target); err != nil {
		t.Fatalf("AuthenticateBackend returned error: %v", err)
	}

	_ = server.SetReadDeadline(time.Now().Add(25 * time.Millisecond))

	line, err := bufio.NewReader(server).ReadString('\n')
	if err == nil {
		t.Fatalf("no-auth backend auth wrote unexpected command %q", line)
	}
}

// TestSASLBackendAuthAllowsExplicitPlaintextPolicy documents the weaker opt-in path.
func TestSASLBackendAuthAllowsExplicitPlaintextPolicy(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)

		reader := bufio.NewReader(server)
		expectLMTPBackendLine(t, reader, expectedPlainAuthCommand())
		writeLMTPBackendLine(t, server, "235 2.7.0 ok")
	}()

	connection := newBackendConnection(client)
	connection.capabilities = backend.NewCapabilitySet(capabilityAUTH + "=PLAIN")

	target := testLMTPBackendTarget(backendTLSPlaintext)
	target.Auth = backend.AuthConfig{
		Mode: backendAuthModeSASL,
		SASL: backend.SASLConfig{
			Mechanism:  mechanismPlain,
			Username:   testBackendServiceUser,
			Password:   config.Secret(testBackendPassword),
			RequireTLS: false,
		},
	}

	if err := AuthenticateBackend(connection, target); err != nil {
		t.Fatalf("AuthenticateBackend returned error: %v", err)
	}

	waitForBackendAuthScript(t, done)
}

// TestOAuthBearerBackendAuthAllowsExplicitPlaintextPolicy documents the weaker opt-in path.
func TestOAuthBearerBackendAuthAllowsExplicitPlaintextPolicy(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)

		reader := bufio.NewReader(server)
		expectLMTPBackendLine(t, reader, expectedOAuthBearerAuthCommand())
		writeLMTPBackendLine(t, server, "235 2.7.0 ok")
	}()

	connection := newBackendConnection(client)
	connection.capabilities = backend.NewCapabilitySet(capabilityAUTH + "=OAUTHBEARER")

	target := testLMTPBackendTarget(backendTLSPlaintext)
	target.Auth = backend.AuthConfig{
		Mode: backendAuthModeOAuthBearer,
		OAuthBearer: backend.OAuthBearerConfig{
			Token:      config.Secret(testBackendToken),
			RequireTLS: false,
		},
	}

	if err := AuthenticateBackend(connection, target); err != nil {
		t.Fatalf("AuthenticateBackend returned error: %v", err)
	}

	waitForBackendAuthScript(t, done)
}

// TestBackendMTLSAuthDoesNotSendSASL verifies certificate auth never emits AUTH commands.
func TestBackendMTLSAuthDoesNotSendSASL(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	connection := newBackendConnection(client)
	connection.tlsActive = true
	connection.tlsVerified = true
	connection.clientCertificateConfigured = true

	target := testLMTPBackendTarget(backendTLSImplicit)
	target.Auth.Mode = backendAuthModeMTLS
	target.TLS.Cert = "/configured/client.crt"
	target.TLS.Key = config.Secret("/configured/client.key")

	if err := AuthenticateBackend(connection, target); err != nil {
		t.Fatalf("AuthenticateBackend returned error: %v", err)
	}

	_ = server.SetReadDeadline(time.Now().Add(25 * time.Millisecond))

	line, err := bufio.NewReader(server).ReadString('\n')
	if err == nil {
		t.Fatalf("mtls backend auth wrote unexpected command %q", line)
	}
}

// TestLightHealthWritesProxyBeforeGreeting verifies health checks exercise the same transport preface.
func TestLightHealthWritesProxyBeforeGreeting(t *testing.T) {
	dialer := scriptedLMTPBackendDialerWithAddrs(
		t,
		tcpAddr("10.10.0.1", 5024),
		tcpAddr("10.10.0.2", 24),
		func(t *testing.T, conn net.Conn) {
			reader := bufio.NewReader(conn)
			expectLMTPBackendLine(t, reader, testLMTPHealthProxyV4)
			writeLMTPBackendLine(t, conn, "220 backend ready")
			expectLMTPBackendLine(t, reader, "LHLO "+backendLHLOName)
			writeLMTPBackendLine(t, conn, "250 "+capabilityCHUNKING)
			expectLMTPBackendLine(t, reader, "QUIT")
			writeLMTPBackendLine(t, conn, "221 2.0.0 bye")
		},
	)
	target := testLMTPBackendTarget(backendTLSPlaintext)
	target.HAProxy.Enabled = true

	result := NewHealthChecker(NewTCPBackendConnector(dialer)).CheckBackend(context.Background(), target, backend.HealthCheckRequest{
		Timeout: time.Second,
	})
	if !result.Healthy || !result.Capabilities.Has(capabilityCHUNKING) {
		t.Fatalf("health result = %#v, want healthy with CHUNKING", result)
	}

	dialer.Wait(t)
}

// TestLightHealthPreservesStructuredSizeFacts verifies health carries SIZE details.
func TestLightHealthPreservesStructuredSizeFacts(t *testing.T) {
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := bufio.NewReader(conn)
		writeLMTPBackendLine(t, conn, "220 backend ready")
		expectLMTPBackendLine(t, reader, "LHLO "+backendLHLOName)
		writeLMTPBackendLine(t, conn, "250-SIZE 10485760")
		writeLMTPBackendLine(t, conn, "250 "+capabilityCHUNKING)
		expectLMTPBackendLine(t, reader, "QUIT")
		writeLMTPBackendLine(t, conn, "221 2.0.0 bye")
	})

	result := NewHealthChecker(NewTCPBackendConnector(dialer)).CheckBackend(context.Background(), testLMTPBackendTarget(backendTLSPlaintext), backend.HealthCheckRequest{
		Timeout: time.Second,
	})
	if !result.Healthy || !result.Capabilities.Has(capabilitySIZE) || !result.Capabilities.Has(capabilityCHUNKING) {
		t.Fatalf("health result = %#v, want healthy SIZE and CHUNKING", result)
	}

	maximum, ok := result.CapabilityFacts.Size().Maximum()
	if !ok || maximum != 10485760 {
		t.Fatalf("health SIZE maximum = %d ok=%v, want 10485760 true", maximum, ok)
	}

	dialer.Wait(t)
}

// TestLightHealthPreservesDovecotCapabilities verifies Dovecot LMTP proofs keep every mediated extension.
func TestLightHealthPreservesDovecotCapabilities(t *testing.T) {
	dialer := scriptedLMTPBackendDialer(t, func(t *testing.T, conn net.Conn) {
		reader := bufio.NewReader(conn)
		writeLMTPBackendLine(t, conn, "220 mail.example Dovecot ready")
		expectLMTPBackendLine(t, reader, "LHLO "+backendLHLOName)
		writeLMTPBackendLine(t, conn, "250-mail.example")
		writeLMTPBackendLine(t, conn, "250-"+capability8BITMIME)
		writeLMTPBackendLine(t, conn, "250-"+capabilityCHUNKING)
		writeLMTPBackendLine(t, conn, "250-"+capabilityEnhancedStatusCodes)
		writeLMTPBackendLine(t, conn, "250-"+capabilityPIPELINING)
		writeLMTPBackendLine(t, conn, "250-"+capabilitySIZE)
		writeLMTPBackendLine(t, conn, "250 "+capabilitySMTPUTF8)
		expectLMTPBackendLine(t, reader, "QUIT")
		writeLMTPBackendLine(t, conn, "221 2.0.0 bye")
	})

	result := NewHealthChecker(NewTCPBackendConnector(dialer)).CheckBackend(context.Background(), testLMTPBackendTarget(backendTLSPlaintext), backend.HealthCheckRequest{
		Timeout: time.Second,
	})
	if !result.Healthy {
		t.Fatalf("health result = %#v, want healthy", result)
	}

	for _, capability := range []string{capability8BITMIME, capabilityCHUNKING, capabilitySIZE} {
		if !result.Capabilities.Has(capability) {
			t.Fatalf("health capabilities = %v, want %s", result.Capabilities.List(), capability)
		}
	}

	dialer.Wait(t)
}

// TestDeepHealthNoAuthDoesNotSendCredentials verifies health honors auth.mode none.
func TestDeepHealthNoAuthDoesNotSendCredentials(t *testing.T) {
	commands := make(chan string, 8)
	dialer := scriptedLMTPBackendDialerWithAddrs(
		t,
		tcpAddr("10.10.0.1", 5024),
		tcpAddr("10.10.0.2", 24),
		func(t *testing.T, conn net.Conn) {
			reader := bufio.NewReader(conn)
			expectLMTPBackendLine(t, reader, testLMTPHealthProxyV4)
			writeLMTPBackendLine(t, conn, "220 backend ready")
			recordAndExpectLMTPBackendLine(t, reader, commands, "LHLO "+backendLHLOName)
			writeLMTPBackendLine(t, conn, "250-mailstore")
			writeLMTPBackendLine(t, conn, "250-AUTH PLAIN")
			writeLMTPBackendLine(t, conn, "250 CHUNKING")
			recordAndExpectLMTPBackendLine(t, reader, commands, "NOOP")
			writeLMTPBackendLine(t, conn, "250 2.0.0 ok")
			recordAndExpectLMTPBackendLine(t, reader, commands, "RSET")
			writeLMTPBackendLine(t, conn, "250 2.0.0 ok")
			recordAndExpectLMTPBackendLine(t, reader, commands, "QUIT")
			writeLMTPBackendLine(t, conn, "221 2.0.0 bye")
		},
	)

	target := testLMTPBackendTarget(backendTLSPlaintext)
	target.HAProxy.Enabled = true
	target.Auth = backend.AuthConfig{Mode: backendAuthModeNone}

	result := NewHealthChecker(NewTCPBackendConnector(dialer)).CheckBackend(context.Background(), target, backend.HealthCheckRequest{
		Deep:    true,
		Timeout: time.Second,
	})
	if !result.Healthy || !result.Capabilities.Has(capabilityCHUNKING) {
		t.Fatalf("health result = %#v, want healthy with CHUNKING", result)
	}

	dialer.Wait(t)
	close(commands)

	for command := range commands {
		upper := strings.ToUpper(command)
		for _, forbidden := range []string{commandAuth, testBackendCommandMail, testBackendCommandRCPT, commandDATA, commandBDAT} {
			if strings.HasPrefix(upper, forbidden) {
				t.Fatalf("no-auth deep health sent forbidden command %q", command)
			}
		}
	}
}

// TestDeepHealthUsesSafeCommandSequence verifies health stops before envelope state.
func TestDeepHealthUsesSafeCommandSequence(t *testing.T) {
	commands := make(chan string, 8)
	dialer := scriptedLMTPBackendDialerWithAddrs(
		t,
		tcpAddr("10.10.0.1", 5024),
		tcpAddr("10.10.0.2", 24),
		func(t *testing.T, conn net.Conn) {
			reader := bufio.NewReader(conn)
			expectLMTPBackendLine(t, reader, testLMTPHealthProxyV4)
			writeLMTPBackendLine(t, conn, "220 backend ready")
			recordAndExpectLMTPBackendLine(t, reader, commands, "LHLO "+backendLHLOName)
			writeLMTPBackendLine(t, conn, "250-mailstore")
			writeLMTPBackendLine(t, conn, "250-AUTH PLAIN")
			writeLMTPBackendLine(t, conn, "250 CHUNKING")
			recordAndExpectLMTPBackendLine(t, reader, commands, expectedPlainAuthCommand())
			writeLMTPBackendLine(t, conn, "235 2.7.0 ok")
			recordAndExpectLMTPBackendLine(t, reader, commands, "NOOP")
			writeLMTPBackendLine(t, conn, "250 2.0.0 ok")
			recordAndExpectLMTPBackendLine(t, reader, commands, "RSET")
			writeLMTPBackendLine(t, conn, "250 2.0.0 ok")
			recordAndExpectLMTPBackendLine(t, reader, commands, "QUIT")
			writeLMTPBackendLine(t, conn, "221 2.0.0 bye")
		},
	)

	target := testLMTPBackendTarget(backendTLSPlaintext)
	target.HAProxy.Enabled = true
	target.Auth = backend.AuthConfig{
		Mode: backendAuthModeSASL,
		SASL: backend.SASLConfig{
			Mechanism: mechanismPlain,
			Username:  testBackendServiceUser,
			Password:  config.Secret(testBackendPassword),
		},
	}

	result := NewHealthChecker(NewTCPBackendConnector(dialer)).CheckBackend(context.Background(), target, backend.HealthCheckRequest{
		Deep:    true,
		Timeout: time.Second,
	})
	if !result.Healthy || !result.Capabilities.Has(capabilityCHUNKING) {
		t.Fatalf("health result = %#v, want healthy with CHUNKING", result)
	}

	dialer.Wait(t)
	close(commands)

	for command := range commands {
		upper := strings.ToUpper(command)
		for _, forbidden := range []string{testBackendCommandMail, testBackendCommandRCPT, commandDATA, commandBDAT} {
			if strings.HasPrefix(upper, forbidden) {
				t.Fatalf("deep health sent forbidden command %q", command)
			}
		}
	}
}

// TestBackendHealthReasonClassesAreBounded verifies secret-safe classification.
func TestBackendHealthReasonClassesAreBounded(t *testing.T) {
	for _, reason := range []string{
		backendHealthReason(ErrBackendConnect),
		backendHealthReason(ErrBackendTLS),
		backendHealthReason(ErrBackendProtocol),
		backendHealthReason(ErrBackendAuth),
		backendHealthReason(context.DeadlineExceeded),
		backendHealthReason(&backend.TransportError{Reason: backend.TransportReasonWriteFailed, Purpose: backend.ConnectPurposeHealth}),
		backendHealthReason(&backend.TransportError{Reason: backend.TransportReasonMissingAddress, Purpose: backend.ConnectPurposeHealth}),
		backendHealthReason(&backend.TransportError{Reason: backend.TransportReasonUnsupportedFamily, Purpose: backend.ConnectPurposeHealth}),
		backendHealthReason(errors.New(testBackendPassword)),
	} {
		switch reason {
		case healthReasonConnect, healthReasonTLS, healthReasonProtocol, healthReasonAuth, healthReasonProxyConfig,
			healthReasonProxyMissing, healthReasonProxyFamily, healthReasonProxyWrite, healthReasonTimeout, healthReasonUnknown:
		default:
			t.Fatalf("reason class %q is not bounded", reason)
		}

		if strings.Contains(reason, testBackendPassword) {
			t.Fatalf("reason class leaked secret: %q", reason)
		}
	}
}

// scriptedLMTPBackendDialer creates a dialer backed by net.Pipe and one scripted server.
func scriptedLMTPBackendDialer(t *testing.T, script func(*testing.T, net.Conn)) *lmtpBackendScriptedDialer {
	t.Helper()

	return &lmtpBackendScriptedDialer{t: t, script: script, done: make(chan struct{})}
}

// scriptedLMTPBackendDialerWithAddrs creates a dialer with fixed backend socket addresses.
func scriptedLMTPBackendDialerWithAddrs(
	t *testing.T,
	local net.Addr,
	remote net.Addr,
	script func(*testing.T, net.Conn),
) *lmtpBackendScriptedDialer {
	t.Helper()

	return &lmtpBackendScriptedDialer{
		t:      t,
		local:  local,
		remote: remote,
		script: script,
		done:   make(chan struct{}),
	}
}

type lmtpBackendScriptedDialer struct {
	t      *testing.T
	local  net.Addr
	remote net.Addr
	script func(*testing.T, net.Conn)
	done   chan struct{}
}

// DialContext returns one side of a net.Pipe and runs the fake backend on the other.
func (d *lmtpBackendScriptedDialer) DialContext(_ context.Context, _ string, _ string) (net.Conn, error) {
	client, server := net.Pipe()
	clientConn := client

	if d.local != nil || d.remote != nil {
		clientConn = backendAddressConn{Conn: client, local: d.local, remote: d.remote}
	}

	go func() {
		defer close(d.done)
		defer func() { _ = server.Close() }()

		d.script(d.t, server)
	}()

	return clientConn, nil
}

// Wait asserts that the fake backend script finished.
func (d *lmtpBackendScriptedDialer) Wait(t *testing.T) {
	t.Helper()

	select {
	case <-d.done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for scripted backend")
	}
}

// testLMTPBackendConnectRequest creates a disabled-PROXY request with stable metadata.
func testLMTPBackendConnectRequest(target backend.Backend) backend.ConnectRequest {
	return backend.ConnectRequest{
		Target:  target,
		Timeout: time.Second,
		Purpose: backend.ConnectPurposeSession,
		ProxyAddresses: &backend.ProxyAddresses{
			Source:      tcpAddr("203.0.113.10", 42500),
			Destination: tcpAddr("198.51.100.20", 24),
		},
	}
}

// testProxyLMTPBackendConnectRequest enables outbound PROXY for connector tests.
func testProxyLMTPBackendConnectRequest(target backend.Backend) backend.ConnectRequest {
	request := testLMTPBackendConnectRequest(target)
	request.Target.HAProxy.Enabled = true

	return request
}

// testLMTPBackendTarget returns a minimal backend target for connector tests.
func testLMTPBackendTarget(mode string) backend.Backend {
	return backend.Backend{
		Protocol: protocolLMTP,
		Address:  testBackendTLSHostTarget,
		TLS: backend.TLSConfig{
			Mode:          mode,
			ServerName:    testBackendTLSHost,
			MinTLSVersion: backendTLSMinDefault,
		},
		Auth: backend.AuthConfig{Mode: backendAuthModeNone},
	}
}

// testLMTPBackendTargetWithCA returns a backend target using the generated test CA.
func testLMTPBackendTargetWithCA(mode string, caFile string) backend.Backend {
	target := testLMTPBackendTarget(mode)
	target.TLS.CAFile = caFile

	return target
}

// tcpAddr creates a TCP address fixture for outbound PROXY metadata.
func tcpAddr(ip string, port int) *net.TCPAddr {
	return &net.TCPAddr{IP: net.ParseIP(ip), Port: port}
}

// backendAddressConn overlays stable socket addresses onto an in-memory connection.
type backendAddressConn struct {
	net.Conn
	local  net.Addr
	remote net.Addr
}

// LocalAddr returns the configured Director-side backend socket address.
func (c backendAddressConn) LocalAddr() net.Addr {
	return c.local
}

// RemoteAddr returns the configured backend-side socket address.
func (c backendAddressConn) RemoteAddr() net.Addr {
	return c.remote
}

// lmtpBackendTestTLSConfig creates a server-side TLS config for backend tests.
func lmtpBackendTestTLSConfig(t *testing.T, certificate tls.Certificate) *tls.Config {
	t.Helper()

	return &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
}

// writeLMTPBackendTestCertificate writes a localhost server certificate and returns its PEM path.
func writeLMTPBackendTestCertificate(t *testing.T) (string, tls.Certificate) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: testBackendTLSHost},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{testBackendTLSHost},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	certPath := writeLMTPBackendTempFile(t, "backend-*.crt", certPEM)
	keyPath := writeLMTPBackendTempFile(t, "backend-*.key", keyPEM)

	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}

	return certPath, certificate
}

// writeLMTPBackendTempFile writes bytes to a temporary file for TLS tests.
func writeLMTPBackendTempFile(t *testing.T, pattern string, contents []byte) string {
	t.Helper()

	file, err := os.CreateTemp(t.TempDir(), pattern)
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer func() { _ = file.Close() }()

	if _, err := file.Write(contents); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	return file.Name()
}

// writeLMTPBackendLine writes one CRLF-terminated LMTP backend line.
func writeLMTPBackendLine(t *testing.T, writer io.Writer, line string) {
	t.Helper()

	if _, err := io.WriteString(writer, line+"\r\n"); err != nil {
		t.Fatalf("write backend line %q: %v", line, err)
	}
}

// expectLMTPBackendLine reads and compares one CRLF-terminated backend command.
func expectLMTPBackendLine(t *testing.T, reader *bufio.Reader, want string) {
	t.Helper()

	line := readLMTPBackendLine(t, reader)
	if line != want {
		t.Fatalf("backend line = %q, want %q", line, want)
	}
}

// recordAndExpectLMTPBackendLine records a command before comparing it.
func recordAndExpectLMTPBackendLine(t *testing.T, reader *bufio.Reader, commands chan<- string, want string) {
	t.Helper()

	line := readLMTPBackendLine(t, reader)
	commands <- line

	if line != want {
		t.Fatalf("backend line = %q, want %q", line, want)
	}
}

// readLMTPBackendLine reads one command line from the scripted fake backend.
func readLMTPBackendLine(t *testing.T, reader *bufio.Reader) string {
	t.Helper()

	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read backend line: %v", err)
	}

	return strings.TrimRight(line, "\r\n")
}

// expectedPlainAuthCommand returns the service-credential AUTH PLAIN command.
func expectedPlainAuthCommand() string {
	payload := "\x00" + testBackendServiceUser + "\x00" + testBackendPassword

	return "AUTH PLAIN " + base64.StdEncoding.EncodeToString([]byte(payload))
}

// expectedOAuthBearerAuthCommand returns the service-token AUTH OAUTHBEARER command.
func expectedOAuthBearerAuthCommand() string {
	return "AUTH OAUTHBEARER " + base64.StdEncoding.EncodeToString([]byte(oauthBearerBackendPayload(testBackendToken)))
}

// waitForBackendAuthScript asserts that an inline backend auth script finished.
func waitForBackendAuthScript(t *testing.T, done <-chan struct{}) {
	t.Helper()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for backend auth script")
	}
}
