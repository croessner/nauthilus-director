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
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/croessner/nauthilus-director/internal/backend"
)

const (
	// BackendHealthPath is the unauthenticated, side-effect-free backend readiness path.
	BackendHealthPath = "/jmap/healthz"

	maxHealthBodyBytes     = 4096
	healthReasonConnect    = "connect"
	healthReasonTLS        = "tls"
	healthReasonTimeout    = "timeout"
	healthReasonProtocol   = "protocol"
	healthReasonUnhealthy  = "unhealthy"
	healthReasonProxyWrite = "proxy_write_failed"
	healthReasonProxyAddr  = "proxy_missing_address"
	healthReasonProxyFam   = "proxy_unsupported_family"
	healthReasonProxyCfg   = "proxy_config"
	healthReasonUnknown    = "unknown"
	connectionClose        = "close"
)

// HealthChecker probes JMAP backends with one HTTPS GET of BackendHealthPath.
type HealthChecker struct {
	transports *transportFactory
}

// NewHealthChecker creates a checker that reuses the production backend TLS and PROXY rules.
func NewHealthChecker(dialer BackendDialer) *HealthChecker {
	return &HealthChecker{transports: newTransportFactory(Config{BackendDialer: dialer})}
}

// CheckBackend performs one bounded readiness request; it never authenticates or mutates state.
func (c *HealthChecker) CheckBackend(ctx context.Context, target backend.Backend, request backend.HealthCheckRequest) backend.HealthCheckResult {
	checkCtx := ctx

	if request.Timeout > 0 {
		var cancel context.CancelFunc

		checkCtx, cancel = context.WithTimeout(ctx, request.Timeout)
		defer cancel()
	}

	conn, err := c.transports.dialBackend(checkCtx, target, backend.ConnectRequest{
		Target:        target,
		Timeout:       request.Timeout,
		Purpose:       backend.ConnectPurposeHealth,
		ProxyVersion:  backend.ProxyProtocolV2,
		Observability: request.Observability,
	})
	if err != nil {
		return backend.HealthCheckResult{ReasonClass: healthReason(err)}
	}
	defer func() { _ = conn.Close() }()

	if err := backend.SetHealthCheckDeadline(checkCtx, conn, backend.ConnectRequest{Purpose: backend.ConnectPurposeHealth, Timeout: request.Timeout}); err != nil {
		return backend.HealthCheckResult{ReasonClass: healthReasonConnect}
	}

	status, err := requestBackendHealth(checkCtx, conn, target)
	if err != nil {
		return backend.HealthCheckResult{ReasonClass: healthReason(err)}
	}

	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return backend.HealthCheckResult{ReasonClass: healthReasonUnhealthy}
	}

	return backend.HealthCheckResult{Healthy: true}
}

// requestBackendHealth writes one GET over the prepared connection and returns the status code.
func requestBackendHealth(ctx context.Context, conn net.Conn, target backend.Backend) (int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, schemeHTTPS+"://"+healthHost(target)+BackendHealthPath, nil)
	if err != nil {
		return 0, errHealthProtocol
	}

	request.Header.Set(headerConnection, connectionClose)
	request.Close = true

	if err := request.Write(conn); err != nil {
		return 0, errors.Join(errHealthProtocol, err)
	}

	response, err := http.ReadResponse(bufio.NewReader(conn), request)
	if err != nil {
		return 0, errors.Join(errHealthProtocol, err)
	}
	defer func() { _ = response.Body.Close() }()

	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxHealthBodyBytes))

	return response.StatusCode, nil
}

// errHealthProtocol reports an unusable HTTP exchange with the backend.
var errHealthProtocol = errors.New("jmap: backend health protocol failed")

// healthHost returns the Host header for health probes: the TLS name or the address host.
func healthHost(target backend.Backend) string {
	if name := strings.TrimSpace(target.TLS.ServerName); name != "" {
		return name
	}

	return strings.TrimSpace(target.Address)
}

// healthReason maps backend check failures to low-cardinality reason classes.
func healthReason(err error) string {
	switch {
	case backend.IsTransportReason(err, backend.TransportReasonWriteFailed):
		return healthReasonProxyWrite
	case backend.IsTransportReason(err, backend.TransportReasonMissingAddress):
		return healthReasonProxyAddr
	case backend.IsTransportReason(err, backend.TransportReasonUnsupportedFamily):
		return healthReasonProxyFam
	case backend.IsTransportReason(err, backend.TransportReasonConfig):
		return healthReasonProxyCfg
	case isTimeout(err):
		return healthReasonTimeout
	case errors.Is(err, ErrBackendTLS):
		return healthReasonTLS
	case errors.Is(err, ErrBackendConnect):
		return healthReasonConnect
	case errors.Is(err, errHealthProtocol):
		return healthReasonProtocol
	default:
		return healthReasonUnknown
	}
}
