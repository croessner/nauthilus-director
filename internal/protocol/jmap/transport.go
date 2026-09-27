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

package jmap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/observability"
)

const (
	backendExpectContinueTimeout = time.Second
	backendMaxIdlePerHost        = 1
)

var (
	// ErrBackendConnect reports a failed backend TCP connection.
	ErrBackendConnect = errors.New("jmap: backend connect failed")
	// ErrBackendTLS reports a failed backend TLS handshake or unusable TLS policy.
	ErrBackendTLS = errors.New("jmap: backend tls failed")
)

// transportFactory builds backend HTTP transports whose connections carry one fixed client tuple.
type transportFactory struct {
	dialer         BackendDialer
	tlsConfigs     *backend.ClientTLSConfigCache
	connectTimeout time.Duration
	idleTimeout    time.Duration
	headerTimeout  time.Duration
	recorder       observability.Recorder
}

// newTransportFactory captures backend transport policy from the listener config.
func newTransportFactory(cfg Config) *transportFactory {
	dialer := cfg.BackendDialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}

	return &transportFactory{
		dialer:         dialer,
		tlsConfigs:     backend.NewClientTLSConfigCache(),
		connectTimeout: cfg.BackendConnectTimeout,
		idleTimeout:    cfg.Settings.Timeouts.Idle.Std(),
		headerTimeout:  cfg.Settings.Timeouts.BackendResponseHeader.Std(),
		recorder:       observability.NormalizeRecorder(cfg.Observability),
	}
}

// forDownstream returns the transport that serves one frontend connection towards one backend.
func (f *transportFactory) forDownstream(downstream *downstreamConn, target backend.Backend) (*http.Transport, bool) {
	return downstream.transport(target.Identifier, func() *http.Transport {
		return f.newTransport(target, &backend.ProxyAddresses{
			Source:      downstream.source,
			Destination: downstream.destination,
		})
	})
}

// newTransport creates an HTTP/1.1 transport whose every connection writes the client's PROXY header.
func (f *transportFactory) newTransport(target backend.Backend, addresses *backend.ProxyAddresses) *http.Transport {
	return &http.Transport{
		Proxy: nil,
		DialTLSContext: func(ctx context.Context, _ string, _ string) (net.Conn, error) {
			return f.dialBackend(ctx, target, backend.ConnectRequest{
				Target:         target,
				Timeout:        f.connectTimeout,
				Purpose:        backend.ConnectPurposeSession,
				ProxyAddresses: addresses,
				ProxyVersion:   backend.ProxyProtocolV2,
				Observability:  f.recorder,
			})
		},
		// An empty map disables HTTP/2 so connections stay one-to-one with backend PROXY tuples.
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
		ForceAttemptHTTP2:     false,
		DisableCompression:    true,
		MaxIdleConnsPerHost:   backendMaxIdlePerHost,
		IdleConnTimeout:       f.idleTimeout,
		ResponseHeaderTimeout: f.headerTimeout,
		ExpectContinueTimeout: backendExpectContinueTimeout,
	}
}

// dialBackend opens TCP, writes the configured PROXY preface and completes verified TLS.
func (f *transportFactory) dialBackend(ctx context.Context, target backend.Backend, request backend.ConnectRequest) (net.Conn, error) {
	dialCtx := ctx

	if request.Timeout > 0 {
		var cancel context.CancelFunc

		dialCtx, cancel = context.WithTimeout(ctx, request.Timeout)
		defer cancel()
	}

	raw, err := f.dialer.DialContext(dialCtx, "tcp", target.Address)
	if err != nil {
		return nil, fmt.Errorf("%w: tcp dial", ErrBackendConnect)
	}

	if err := backend.SetHealthCheckDeadline(dialCtx, raw, request); err != nil {
		_ = raw.Close()

		return nil, fmt.Errorf("%w: health deadline", ErrBackendConnect)
	}

	if _, err := backend.NewTransport().WriteProxyProtocolPreface(dialCtx, raw, request); err != nil {
		_ = raw.Close()

		return nil, fmt.Errorf("%w: proxy preface: %w", ErrBackendConnect, err)
	}

	tlsConfig, err := f.tlsConfigs.Config(target, func() (*tls.Config, error) {
		return backend.NewClientTLSConfig(target)
	})
	if err != nil {
		_ = raw.Close()

		return nil, fmt.Errorf("%w: %w", ErrBackendTLS, err)
	}

	tlsConn := tls.Client(raw, tlsConfig)
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		_ = raw.Close()

		return nil, fmt.Errorf("%w: handshake", ErrBackendTLS)
	}

	return tlsConn, nil
}
