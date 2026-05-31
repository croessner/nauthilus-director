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

package tlscontext

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/nauthilus"
)

const (
	testProtocolIMAP = "imap"
	testProtocolLMTP = "lmtp"
	testPeerCN       = "submitter.example.test"
	testIssuerCN     = "issuer.example.test"
)

// TestApplyReportsInactiveTLS verifies plaintext auth attempts remain explicit.
func TestApplyReportsInactiveTLS(t *testing.T) {
	requestContext := Apply(nauthilus.RequestContext{Protocol: testProtocolIMAP}, false, tls.ConnectionState{}, false)
	if requestContext.TLS != tlsBoolFalse {
		t.Fatalf("TLS = %q, want false", requestContext.TLS)
	}

	if requestContext.TLSClientVerify != "" {
		t.Fatalf("TLS client verify = %q, want empty for inactive TLS", requestContext.TLSClientVerify)
	}
}

// TestApplyReportsActiveTLSWithoutState verifies tests and synthetic streams still mark TLS truthfully.
func TestApplyReportsActiveTLSWithoutState(t *testing.T) {
	requestContext := Apply(nauthilus.RequestContext{Protocol: testProtocolIMAP}, true, tls.ConnectionState{}, false)
	if requestContext.TLS != tlsBoolTrue {
		t.Fatalf("TLS = %q, want true", requestContext.TLS)
	}

	if requestContext.TLSClientVerify != tlsClientVerifyNone {
		t.Fatalf("TLS client verify = %q, want NONE", requestContext.TLSClientVerify)
	}
}

// TestApplyCopiesPeerCertificateMetadata verifies Nauthilus receives bounded TLS facts.
func TestApplyCopiesPeerCertificateMetadata(t *testing.T) {
	notBefore := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	notAfter := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	certificate := &x509.Certificate{
		Raw:          []byte("certificate-bytes"),
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: testPeerCN, Organization: []string{"Submitters"}},
		Issuer:       pkix.Name{CommonName: testIssuerCN, Organization: []string{"Issuers"}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}

	requestContext := Apply(
		nauthilus.RequestContext{Protocol: testProtocolLMTP},
		true,
		tls.ConnectionState{
			Version:          tls.VersionTLS13,
			CipherSuite:      tls.TLS_AES_128_GCM_SHA256,
			PeerCertificates: []*x509.Certificate{certificate},
			VerifiedChains:   [][]*x509.Certificate{{certificate}},
		},
		true,
	)

	if requestContext.TLS != tlsBoolTrue || requestContext.TLSClientVerify != tlsClientVerifyOK {
		t.Fatalf("TLS fields = %q/%q, want true/SUCCESS", requestContext.TLS, requestContext.TLSClientVerify)
	}

	if requestContext.TLSProtocol != tlsVersion13Name || requestContext.TLSCipher != "TLS_AES_128_GCM_SHA256" {
		t.Fatalf("TLS version/cipher = %q/%q", requestContext.TLSProtocol, requestContext.TLSCipher)
	}

	if requestContext.TLSClientCN != testPeerCN || requestContext.TLSIssuer != testIssuerCN {
		t.Fatalf("TLS client CN/issuer = %q/%q", requestContext.TLSClientCN, requestContext.TLSIssuer)
	}

	if requestContext.TLSSerial != "42" || requestContext.TLSFingerprint == "" {
		t.Fatalf("TLS serial/fingerprint = %q/%q", requestContext.TLSSerial, requestContext.TLSFingerprint)
	}
}

// TestConnectionStateReadsProvider verifies protocol sessions can pass wrapped connections.
func TestConnectionStateReadsProvider(t *testing.T) {
	state := tls.ConnectionState{Version: tls.VersionTLS12}

	got, ok := ConnectionState(testStateProvider{state: state})
	if !ok || got.Version != tls.VersionTLS12 {
		t.Fatalf("ConnectionState = %#v/%v, want TLS1.2 provider state", got, ok)
	}
}

type testStateProvider struct {
	state tls.ConnectionState
}

// ConnectionState returns fixed TLS metadata for tests.
func (p testStateProvider) ConnectionState() tls.ConnectionState {
	return p.state
}
