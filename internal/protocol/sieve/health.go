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

package sieve

import (
	"context"

	"github.com/croessner/nauthilus-director/internal/backend"
)

// HealthChecker performs protocol-aware ManageSieve backend readiness checks.
type HealthChecker struct {
	connector BackendConnector
}

// NewHealthChecker creates a health checker that reuses production backend TLS rules.
func NewHealthChecker(connector BackendConnector) *HealthChecker {
	if connector == nil {
		connector = NewTCPBackendConnector(nil)
	}

	return &HealthChecker{connector: connector}
}

// CheckBackend performs a bounded ManageSieve backend check without script commands.
func (c *HealthChecker) CheckBackend(ctx context.Context, target backend.Backend, request backend.HealthCheckRequest) backend.HealthCheckResult {
	connector := c.connector
	if connector == nil {
		connector = NewTCPBackendConnector(nil)
	}

	connection, err := connector.Connect(ctx, backend.ConnectRequest{
		Target:        target,
		Timeout:       request.Timeout,
		Purpose:       backend.ConnectPurposeHealth,
		Observability: request.Observability,
	})
	if err != nil {
		return backend.HealthCheckResult{ReasonClass: backendHealthReason(err)}
	}
	defer func() { _ = connection.Conn().Close() }()

	if !request.Deep {
		_ = connection.logout()

		return backend.HealthCheckResult{Healthy: true, Capabilities: connection.CapabilitySet()}
	}

	if err := AuthenticateHealthBackend(connection, target); err != nil {
		_ = connection.logout()

		return backend.HealthCheckResult{ReasonClass: backendHealthReason(err)}
	}

	if err := connection.noop(); err != nil {
		_ = connection.logout()

		return backend.HealthCheckResult{ReasonClass: backendHealthReason(err)}
	}

	if err := connection.logout(); err != nil {
		return backend.HealthCheckResult{ReasonClass: backendHealthReason(err)}
	}

	return backend.HealthCheckResult{Healthy: true, Capabilities: connection.CapabilitySet()}
}

// noop verifies a non-mutating backend command after health authentication.
func (c *BackendConnection) noop() error {
	return c.expectOK(commandNoop)
}

// logout closes the ManageSieve conversation politely.
func (c *BackendConnection) logout() error {
	return c.expectOK(commandLogout)
}

// expectOK sends one command and requires a safe OK response.
func (c *BackendConnection) expectOK(command string) error {
	if err := c.writeCommand(command); err != nil {
		return err
	}

	response, err := c.readResponse()
	if err != nil {
		return err
	}

	if response.condition != backendResponseOK {
		return ErrBackendProtocol
	}

	return nil
}
