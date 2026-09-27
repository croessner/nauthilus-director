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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
)

// ErrClientTLSConfig reports an unusable backend client TLS policy without exposing file contents.
var ErrClientTLSConfig = errors.New("backend client tls configuration invalid")

// NewClientTLSConfig builds the verified client TLS configuration for one backend.
//
// The certificate name is tls.server_name or the host part of the backend address; a literal IP
// address without server_name is refused unless verification is explicitly disabled, so a backend
// never becomes reachable through an unverified connection by accident.
func NewClientTLSConfig(target Backend) (*tls.Config, error) {
	minVersion, err := clientTLSMinVersion(target.TLS.MinTLSVersion)
	if err != nil {
		return nil, err
	}

	serverName, err := clientTLSServerName(target)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		MinVersion:         minVersion,
		ServerName:         serverName,
		InsecureSkipVerify: target.TLS.InsecureSkipVerify,
	}

	if strings.TrimSpace(target.TLS.CAFile) != "" {
		roots, err := clientTLSRootCAs(target.TLS.CAFile)
		if err != nil {
			return nil, err
		}

		config.RootCAs = roots
	}

	if strings.TrimSpace(target.TLS.Cert) != "" || !target.TLS.Key.IsZero() {
		if strings.TrimSpace(target.TLS.Cert) == "" || target.TLS.Key.IsZero() {
			return nil, errors.Join(ErrClientTLSConfig, errors.New("client certificate and key must be configured together"))
		}

		certificate, err := tls.LoadX509KeyPair(target.TLS.Cert, target.TLS.Key.Value())
		if err != nil {
			return nil, errors.Join(ErrClientTLSConfig, errors.New("load client certificate"))
		}

		config.Certificates = []tls.Certificate{certificate}
	}

	return config, nil
}

// clientTLSServerName returns the SNI and verification hostname for the backend.
func clientTLSServerName(target Backend) (string, error) {
	if name := strings.TrimSpace(target.TLS.ServerName); name != "" {
		return name, nil
	}

	host, _, err := net.SplitHostPort(strings.TrimSpace(target.Address))
	if err != nil {
		return "", errors.Join(ErrClientTLSConfig, errors.New("backend address must be host:port"))
	}

	if _, err := netip.ParseAddr(host); err == nil {
		if target.TLS.InsecureSkipVerify {
			return "", nil
		}

		return "", errors.Join(ErrClientTLSConfig, errors.New("tls.server_name is required for IP backend addresses"))
	}

	return host, nil
}

// clientTLSMinVersion converts config vocabulary into Go TLS constants.
func clientTLSMinVersion(version string) (uint16, error) {
	switch strings.ToUpper(strings.TrimSpace(version)) {
	case "", "TLS1.2", "TLS12", "TLS1_2":
		return tls.VersionTLS12, nil
	case "TLS1.3", "TLS13", "TLS1_3":
		return tls.VersionTLS13, nil
	default:
		return 0, errors.Join(ErrClientTLSConfig, errors.New("unsupported minimum tls version"))
	}
}

// clientTLSRootCAs loads a PEM CA bundle for backend certificate verification.
func clientTLSRootCAs(path string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.Join(ErrClientTLSConfig, errors.New("load backend ca"))
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, errors.Join(ErrClientTLSConfig, errors.New("backend ca contains no PEM certificates"))
	}

	return pool, nil
}
