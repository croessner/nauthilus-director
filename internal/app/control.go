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

package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/rest"
)

// controlServer owns the in-process REST control listener.
type controlServer struct {
	config          config.ControlServerConfig
	handler         *rest.Server
	httpServer      *http.Server
	listener        net.Listener
	shutdownTimeout time.Duration
}

// newControlServer prepares the configured control API listener.
func newControlServer(cfg config.Config, handler *rest.Server) (*controlServer, error) {
	control := cfg.Runtime.Servers.Control
	if strings.TrimSpace(control.Address) == "" {
		return nil, fmt.Errorf("control address is required")
	}

	return &controlServer{
		config:          control,
		handler:         handler,
		shutdownTimeout: cfg.Runtime.Process.ShutdownTimeout.Std(),
	}, nil
}

// Start binds the control listener and starts serving generated REST routes.
func (s *controlServer) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.config.Address)
	if err != nil {
		return fmt.Errorf("start control listener: %w", err)
	}

	if s.config.TLS.Enabled {
		tlsConfig, err := controlTLSConfig(s.config)
		if err != nil {
			_ = ln.Close()

			return err
		}

		ln = tls.NewListener(ln, tlsConfig)
	}

	s.listener = ln
	s.httpServer = &http.Server{
		Handler:           serverHandler(s.handler),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.httpServer.Serve(ln)
	}()

	select {
	case err := <-errCh:
		if err != nil && !errorsIsServerClosed(err) {
			return fmt.Errorf("serve control listener: %w", err)
		}
	case <-time.After(10 * time.Millisecond):
	case <-ctx.Done():
		_ = s.Stop(context.Background())

		return ctx.Err()
	}

	return nil
}

// Stop gracefully shuts down the control listener.
func (s *controlServer) Stop(ctx context.Context) error {
	if s == nil || s.httpServer == nil {
		return nil
	}

	stopCtx, cancel := contextWithTimeout(ctx, s.shutdownTimeout)
	defer cancel()

	err := s.httpServer.Shutdown(stopCtx)
	if err != nil && s.listener != nil {
		_ = s.listener.Close()
	}

	s.httpServer = nil
	s.listener = nil

	return err
}

// controlTLSConfig loads the optional control API TLS identity.
func controlTLSConfig(control config.ControlServerConfig) (*tls.Config, error) {
	minVersion, err := controlTLSMinVersion(control.TLS.MinTLSVersion)
	if err != nil {
		return nil, err
	}

	certificate, err := tls.LoadX509KeyPair(control.TLS.Cert, control.TLS.Key.Value())
	if err != nil {
		return nil, fmt.Errorf("load control TLS certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   minVersion,
	}
	if err := applyControlClientCA(tlsConfig, control); err != nil {
		return nil, err
	}

	return tlsConfig, nil
}

// controlTLSMinVersion converts control TLS config into Go constants.
func controlTLSMinVersion(version string) (uint16, error) {
	switch strings.ToUpper(strings.TrimSpace(version)) {
	case "", tlsVersion12Name, tlsVersion12Compact, tlsVersion12Symbol:
		return tls.VersionTLS12, nil
	case tlsVersion13Name, tlsVersion13Compact, tlsVersion13Symbol:
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported control TLS minimum version %q", version)
	}
}

// applyControlClientCA configures optional mTLS verification for the control API.
func applyControlClientCA(tlsConfig *tls.Config, control config.ControlServerConfig) error {
	if strings.TrimSpace(control.TLS.ClientCA) == "" {
		if control.TLS.RequireClientCert {
			tlsConfig.ClientAuth = tls.RequireAnyClientCert
		}

		return nil
	}

	pemBytes, err := os.ReadFile(control.TLS.ClientCA)
	if err != nil {
		return fmt.Errorf("load control client CA: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return fmt.Errorf("control client CA did not contain PEM certificates")
	}

	tlsConfig.ClientCAs = pool
	if control.TLS.RequireClientCert {
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	} else {
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
	}

	return nil
}

// errorsIsServerClosed reports expected http.Server shutdown completion.
func errorsIsServerClosed(err error) bool {
	return err == http.ErrServerClosed
}
