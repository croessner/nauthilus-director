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
	"context"

	"github.com/croessner/nauthilus-director/internal/observability"
)

const (
	listenerOperation = "listener"
	listenerResultOK  = "ok"

	listenerFieldBackendPool = "backend_pool"
	listenerFieldListener    = "listener"
	listenerFieldNetwork     = "network"
	listenerFieldOperation   = "operation"
	listenerFieldProtocol    = "protocol"
	listenerFieldReasonClass = "reason_class"
	listenerFieldRemoteAddr  = "remote_addr"
	listenerFieldResult      = "result"
	listenerFieldService     = "service"
	listenerFieldTLSMode     = "tls_mode"
)

// recordListenerEvent emits listener lifecycle state with low-cardinality labels.
func (l *managedListener) recordListenerEvent(ctx context.Context, name string, result string, reason string) {
	recorder := observability.NormalizeRecorder(l.observability)
	fields := map[string]string{
		listenerFieldBackendPool: l.config.listener.BackendPool,
		listenerFieldListener:    l.name,
		listenerFieldNetwork:     l.config.listener.Network,
		listenerFieldOperation:   listenerOperation,
		listenerFieldProtocol:    l.config.listener.Protocol,
		listenerFieldRemoteAddr:  l.boundAddress(),
		listenerFieldResult:      result,
		listenerFieldService:     l.config.listener.ServiceName,
		listenerFieldTLSMode:     l.config.listener.TLS.Mode,
	}
	labels := map[string]string{
		listenerFieldBackendPool: l.config.listener.BackendPool,
		listenerFieldListener:    l.name,
		listenerFieldOperation:   listenerOperation,
		listenerFieldProtocol:    l.config.listener.Protocol,
		listenerFieldResult:      result,
		listenerFieldService:     l.config.listener.ServiceName,
		listenerFieldTLSMode:     l.config.listener.TLS.Mode,
	}

	if reason != "" {
		fields[listenerFieldReasonClass] = reason
		labels[listenerFieldReasonClass] = reason
	}

	event, err := observability.NewEvent(name, observability.TraceBoundarySession, fields, labels)
	if err != nil {
		return
	}

	recorder.Record(ctx, event)
}
