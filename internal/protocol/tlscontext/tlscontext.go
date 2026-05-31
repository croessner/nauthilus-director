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

// Package tlscontext maps frontend TLS state into Nauthilus auth context fields.
package tlscontext

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"time"

	"github.com/croessner/nauthilus-director/internal/nauthilus"
)

const (
	tlsBoolTrue         = "true"
	tlsBoolFalse        = "false"
	tlsClientVerifyNone = "NONE"
	tlsClientVerifyOK   = "SUCCESS"
	tlsClientVerifyFail = "FAILED"
	tlsVersion10Name    = "TLS1.0"
	tlsVersion11Name    = "TLS1.1"
	tlsVersion12Name    = "TLS1.2"
	tlsVersion13Name    = "TLS1.3"
)

// StateProvider exposes TLS metadata from connections that completed a handshake.
type StateProvider interface {
	ConnectionState() tls.ConnectionState
}

// ConnectionState returns TLS metadata when the connection exposes it.
func ConnectionState(conn any) (tls.ConnectionState, bool) {
	provider, ok := conn.(StateProvider)
	if !ok {
		return tls.ConnectionState{}, false
	}

	return provider.ConnectionState(), true
}

// Apply copies frontend TLS facts into the Nauthilus request context.
func Apply(requestContext nauthilus.RequestContext, active bool, state tls.ConnectionState, stateAvailable bool) nauthilus.RequestContext {
	requestContext.TLS = boolString(active)
	if !active {
		return requestContext
	}

	if !stateAvailable {
		requestContext.TLSClientVerify = tlsClientVerifyNone

		return requestContext
	}

	requestContext.TLSProtocol = tlsVersionName(state.Version)
	requestContext.TLSCipher = tls.CipherSuiteName(state.CipherSuite)
	requestContext.TLSClientVerify = clientVerifyState(state)

	if len(state.PeerCertificates) > 0 {
		applyPeerCertificate(&requestContext, state.PeerCertificates[0])
	}

	return requestContext
}

// applyPeerCertificate copies bounded client certificate facts into the auth context.
func applyPeerCertificate(requestContext *nauthilus.RequestContext, certificate *x509.Certificate) {
	if certificate == nil {
		return
	}

	subject := certificate.Subject.String()
	issuer := certificate.Issuer.String()

	requestContext.TLSClientDN = subject
	requestContext.TLSClientCN = certificate.Subject.CommonName
	requestContext.TLSIssuer = certificate.Issuer.CommonName
	requestContext.TLSClientNotBefore = formatTime(certificate.NotBefore)
	requestContext.TLSClientNotAfter = formatTime(certificate.NotAfter)
	requestContext.TLSSubjectDN = subject
	requestContext.TLSIssuerDN = issuer
	requestContext.TLSClientSubjectDN = subject
	requestContext.TLSClientIssuerDN = issuer
	requestContext.TLSSerial = serialString(certificate.SerialNumber)
	requestContext.TLSFingerprint = fingerprint(certificate.Raw)
}

// boolString returns Nauthilus-compatible string booleans for TLS state.
func boolString(value bool) string {
	if value {
		return tlsBoolTrue
	}

	return tlsBoolFalse
}

// clientVerifyState maps Go TLS verification facts to stable request metadata.
func clientVerifyState(state tls.ConnectionState) string {
	if len(state.PeerCertificates) == 0 {
		return tlsClientVerifyNone
	}

	if len(state.VerifiedChains) > 0 {
		return tlsClientVerifyOK
	}

	return tlsClientVerifyFail
}

// fingerprint returns a SHA-256 certificate fingerprint.
func fingerprint(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}

	sum := sha256.Sum256(raw)

	return hex.EncodeToString(sum[:])
}

// formatTime returns an empty value for missing certificate timestamps.
func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}

	return value.UTC().Format(time.RFC3339)
}

// serialString formats nil-safe certificate serial numbers.
func serialString(serial *big.Int) string {
	if serial == nil {
		return ""
	}

	return serial.String()
}

// tlsVersionName converts Go TLS version constants into policy-friendly text.
func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return tlsVersion10Name
	case tls.VersionTLS11:
		return tlsVersion11Name
	case tls.VersionTLS12:
		return tlsVersion12Name
	case tls.VersionTLS13:
		return tlsVersion13Name
	default:
		return ""
	}
}
