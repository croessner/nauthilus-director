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
	"errors"
	"net"

	"github.com/croessner/nauthilus-director/internal/observability"
	proxyproto "github.com/pires/go-proxyproto"
)

const (
	listenerOperation           = "listener"
	listenerOperationAcceptLoop = "accept_loop"
	listenerOperationProxyProto = "proxy_protocol"
	listenerResultAccepted      = "accepted"
	listenerResultOK            = "ok"
	listenerResultRejected      = "rejected"
	listenerReasonMalformed     = "malformed"

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
	l.recordListenerOperation(ctx, name, listenerOperation, result, reason)
}

// recordAcceptLoopStop emits the accept-loop terminal state separately from shutdown drain.
func (l *managedListener) recordAcceptLoopStop(result string, reason string) {
	l.recordListenerOperation(context.Background(), observability.EventListenerStop, listenerOperationAcceptLoop, result, reason)
}

// recordProxyProtocol emits PROXY protocol handling without exposing endpoint addresses.
func (l *managedListener) recordProxyProtocol(result string, reason string) {
	l.recordListenerOperation(context.Background(), observability.EventProxyProtocol, listenerOperationProxyProto, result, reason)
}

// recordListenerOperation emits listener observations with reviewed label names.
func (l *managedListener) recordListenerOperation(ctx context.Context, name string, operation string, result string, reason string) {
	recorder := observability.NormalizeRecorder(l.observability)
	fields := map[string]string{
		listenerFieldBackendPool: l.config.listener.BackendPool,
		listenerFieldListener:    l.name,
		listenerFieldNetwork:     l.config.listener.Network,
		listenerFieldOperation:   operation,
		listenerFieldProtocol:    l.config.listener.Protocol,
		listenerFieldRemoteAddr:  l.boundAddress(),
		listenerFieldResult:      result,
		listenerFieldService:     l.config.listener.ServiceName,
		listenerFieldTLSMode:     l.config.listener.TLS.Mode,
	}
	labels := map[string]string{
		listenerFieldBackendPool: l.config.listener.BackendPool,
		listenerFieldListener:    l.name,
		listenerFieldOperation:   operation,
		listenerFieldProtocol:    l.config.listener.Protocol,
		listenerFieldResult:      result,
		listenerFieldService:     l.config.listener.ServiceName,
		listenerFieldTLSMode:     l.config.listener.TLS.Mode,
	}

	if reason != "" {
		fields[listenerFieldReasonClass] = reason
		labels[listenerFieldReasonClass] = reason
	}

	event, err := observability.NewEvent(name, "", fields, labels)
	if err != nil {
		return
	}

	recorder.Record(ctx, event)
}

// proxyProtocolReasonClass maps transport setup failures into bounded classes.
func proxyProtocolReasonClass(err error) string {
	var netErr net.Error

	switch {
	case err == nil:
		return listenerResultOK
	case errors.Is(err, ErrProxyProtocolUntrustedPeer):
		return "untrusted"
	case errors.Is(err, ErrProxyProtocolUnsupportedCommand), errors.Is(err, ErrProxyProtocolUnsupportedFamily):
		return "unsupported"
	case errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	case errors.Is(err, proxyproto.ErrNoProxyProtocol):
		return listenerReasonMalformed
	default:
		return listenerReasonMalformed
	}
}
