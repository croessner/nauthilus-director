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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/croessner/nauthilus-director/internal/config"
)

// buildListenerTLSConfig loads implicit TLS settings while keeping STARTTLS lazy for later phases.
func buildListenerTLSConfig(listener config.ListenerConfig) (*tls.Config, error) {
	minVersion, err := tlsMinVersion(listener.TLS.MinTLSVersion)
	if err != nil {
		return nil, err
	}

	if listener.TLS.Mode != tlsModeImplicit {
		return &tls.Config{MinVersion: minVersion}, nil
	}

	if strings.TrimSpace(listener.TLS.Cert) == "" {
		return nil, fmt.Errorf("listener tls.cert is required for implicit TLS")
	}

	if listener.TLS.Key.IsZero() {
		return nil, fmt.Errorf("listener tls.key is required for implicit TLS")
	}

	certificate, err := tls.LoadX509KeyPair(listener.TLS.Cert, listener.TLS.Key.Value())
	if err != nil {
		return nil, fmt.Errorf("load listener TLS certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   minVersion,
	}
	if err := applyClientCA(tlsConfig, listener); err != nil {
		return nil, err
	}

	return tlsConfig, nil
}

// tlsMinVersion converts config vocabulary into Go TLS constants.
func tlsMinVersion(version string) (uint16, error) {
	switch strings.ToUpper(strings.TrimSpace(version)) {
	case "", defaultTLSMinName, "TLS12", "TLS1_2":
		return tls.VersionTLS12, nil
	case "TLS1.3", "TLS13", "TLS1_3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported listener TLS minimum version %q", version)
	}
}

// applyClientCA configures optional or required frontend client certificate verification.
func applyClientCA(tlsConfig *tls.Config, listener config.ListenerConfig) error {
	if strings.TrimSpace(listener.TLS.ClientCA) == "" {
		if listener.TLS.RequireClientCert {
			tlsConfig.ClientAuth = tls.RequireAnyClientCert
		}

		return nil
	}

	pemBytes, err := os.ReadFile(listener.TLS.ClientCA)
	if err != nil {
		return fmt.Errorf("load listener client CA: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return fmt.Errorf("listener client CA did not contain PEM certificates")
	}

	tlsConfig.ClientCAs = pool
	if listener.TLS.RequireClientCert {
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	} else {
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
	}

	return nil
}
