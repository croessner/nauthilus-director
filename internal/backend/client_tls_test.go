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

//nolint:goconst // TLS fixtures repeat backend names to show each policy input.
package backend

import (
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestNewClientTLSConfigUsesServerNameAndVerification keeps backend TLS verified by default.
func TestNewClientTLSConfigUsesServerNameAndVerification(t *testing.T) {
	config, err := NewClientTLSConfig(Backend{
		Address: "10.0.0.5:9443",
		TLS:     TLSConfig{ServerName: "mailstore.example.org", MinTLSVersion: "TLS1.3"},
	})
	if err != nil {
		t.Fatalf("NewClientTLSConfig returned error: %v", err)
	}

	if config.ServerName != "mailstore.example.org" || config.InsecureSkipVerify || config.MinVersion != tls.VersionTLS13 {
		t.Fatalf("config = server %q insecure %v min %x", config.ServerName, config.InsecureSkipVerify, config.MinVersion)
	}
}

// TestNewClientTLSConfigDerivesHostName uses the DNS host of the backend address.
func TestNewClientTLSConfigDerivesHostName(t *testing.T) {
	config, err := NewClientTLSConfig(Backend{Address: "mailstore.example.org:9443"})
	if err != nil {
		t.Fatalf("NewClientTLSConfig returned error: %v", err)
	}

	if config.ServerName != "mailstore.example.org" || config.MinVersion != tls.VersionTLS12 {
		t.Fatalf("config = server %q min %x", config.ServerName, config.MinVersion)
	}
}

// TestNewClientTLSConfigRejectsUnsafeInputs keeps configuration failures classified.
func TestNewClientTLSConfigRejectsUnsafeInputs(t *testing.T) {
	invalidCA := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(invalidCA, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}

	for name, target := range map[string]Backend{
		"ip without server name": {Address: "10.0.0.5:9443"},
		"unknown min version":    {Address: "mailstore.example.org:9443", TLS: TLSConfig{MinTLSVersion: "SSL3"}},
		"missing ca file":        {Address: "mailstore.example.org:9443", TLS: TLSConfig{CAFile: filepath.Join(t.TempDir(), "missing.pem")}},
		"invalid ca file":        {Address: "mailstore.example.org:9443", TLS: TLSConfig{CAFile: invalidCA}},
		"cert without key":       {Address: "mailstore.example.org:9443", TLS: TLSConfig{Cert: "/tmp/client.pem"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewClientTLSConfig(target); !errors.Is(err, ErrClientTLSConfig) {
				t.Fatalf("NewClientTLSConfig error = %v, want ErrClientTLSConfig", err)
			}
		})
	}
}
