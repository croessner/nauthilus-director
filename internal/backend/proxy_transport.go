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
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/observability"
	proxyproto "github.com/pires/go-proxyproto"
)

// ConnectPurpose classifies why one backend TCP connection is opened.
type ConnectPurpose string

const (
	backendProxyObservationFieldBackendNode = "backend_node"
	backendProxyObservationFieldBackendPool = "backend_pool"
	backendProxyObservationFieldOperation   = "operation"
	backendProxyObservationFieldProtocol    = "protocol"
	backendProxyObservationFieldPurpose     = "purpose"
	backendProxyObservationFieldReasonClass = "reason_class"
	backendProxyObservationFieldResult      = "result"
	backendProxyObservationOperation        = "backend_proxy_protocol"
	backendProxyObservationResultFailure    = "failure"
	backendProxyObservationResultOK         = "ok"

	// ConnectPurposeSession identifies a user-facing protocol session.
	ConnectPurposeSession ConnectPurpose = "session"
	// ConnectPurposeHealth identifies a backend health-check connection.
	ConnectPurposeHealth ConnectPurpose = "health"
)

// TransportReason classifies outbound backend transport preface outcomes.
type TransportReason string

const (
	// TransportReasonOK reports that a configured preface was written.
	TransportReasonOK TransportReason = "ok"
	// TransportReasonDisabled reports that outbound PROXY protocol is disabled.
	TransportReasonDisabled TransportReason = "disabled"
	// TransportReasonWriteFailed reports a failed preface write or flush.
	TransportReasonWriteFailed TransportReason = "write_failed"
	// TransportReasonMissingAddress reports absent TCP address data.
	TransportReasonMissingAddress TransportReason = "missing_address"
	// TransportReasonUnsupportedFamily reports non-TCP or mixed address families.
	TransportReasonUnsupportedFamily TransportReason = "unsupported_family"
	// TransportReasonConfig reports an unsupported bounded transport setting.
	TransportReasonConfig TransportReason = "config"
)

// ProxyAddresses carries the frontend tuple for a real backend session.
type ProxyAddresses struct {
	Source      net.Addr
	Destination net.Addr
}

// ConnectRequest describes the transport preface facts for one backend connection.
type ConnectRequest struct {
	Target         Backend
	Timeout        time.Duration
	Purpose        ConnectPurpose
	ProxyAddresses *ProxyAddresses
	Observability  observability.Recorder
}

// TransportResult reports the bounded outcome of backend transport preparation.
type TransportResult struct {
	Written bool
	Reason  TransportReason
	Purpose ConnectPurpose
}

// TransportError is a secret-safe outbound backend transport failure.
type TransportError struct {
	Reason  TransportReason
	Purpose ConnectPurpose
	cause   error
}

// Error returns only bounded transport facts and never raw socket addresses.
func (e *TransportError) Error() string {
	if e == nil {
		return ""
	}

	message := "backend transport failed: proxy_protocol reason=" + string(e.Reason)
	if e.Purpose != "" {
		message += " purpose=" + string(e.Purpose)
	}

	return message
}

// Unwrap exposes the original transport failure without adding it to Error.
func (e *TransportError) Unwrap() error {
	if e == nil {
		return nil
	}

	return e.cause
}

// IsTransportReason reports whether err wraps a bounded transport reason.
func IsTransportReason(err error, reason TransportReason) bool {
	var transportErr *TransportError
	if !errors.As(err, &transportErr) {
		return false
	}

	return transportErr.Reason == reason
}

// Transport writes backend transport metadata before protocol negotiation.
type Transport struct{}

// NewTransport creates the shared backend transport preface helper.
func NewTransport() Transport {
	return Transport{}
}

// WriteProxyProtocolPreface emits the configured outbound PROXY header before protocol bytes.
func (Transport) WriteProxyProtocolPreface(ctx context.Context, conn net.Conn, request ConnectRequest) (TransportResult, error) {
	result := TransportResult{Purpose: boundedBackendConnectPurpose(request.Purpose)}
	if !request.Target.HAProxy.Enabled {
		result.Reason = TransportReasonDisabled
		recordBackendProxyProtocol(ctx, request, result)

		return result, nil
	}

	if conn == nil {
		result, err := failBackendTransport(conn, TransportReasonMissingAddress, result.Purpose, nil)
		recordBackendProxyProtocol(ctx, request, result)

		return result, err
	}

	purpose, err := normalizeBackendConnectPurpose(request.Purpose)
	if err != nil {
		result, transportErr := failBackendTransport(conn, TransportReasonConfig, "", err)
		recordBackendProxyProtocol(ctx, request, result)

		return result, transportErr
	}

	source, destination, reason := backendProxyAddresses(conn, request, purpose)
	if reason != "" {
		result, err := failBackendTransport(conn, reason, purpose, nil)
		recordBackendProxyProtocol(ctx, request, result)

		return result, err
	}

	header, reason := newBackendProxyHeader(source, destination)
	if reason != "" {
		result, err := failBackendTransport(conn, reason, purpose, nil)
		recordBackendProxyProtocol(ctx, request, result)

		return result, err
	}

	if err := writeBackendProxyHeader(conn, header); err != nil {
		result, transportErr := failBackendTransport(conn, TransportReasonWriteFailed, purpose, err)
		recordBackendProxyProtocol(ctx, request, result)

		return result, transportErr
	}

	result = TransportResult{
		Written: true,
		Reason:  TransportReasonOK,
		Purpose: purpose,
	}
	recordBackendProxyProtocol(ctx, request, result)

	return result, nil
}

// backendProxyAddresses selects the tuple source for session or health connections.
func backendProxyAddresses(conn net.Conn, request ConnectRequest, purpose ConnectPurpose) (net.Addr, net.Addr, TransportReason) {
	switch purpose {
	case ConnectPurposeSession:
		if request.ProxyAddresses == nil {
			return nil, nil, TransportReasonMissingAddress
		}

		return request.ProxyAddresses.Source, request.ProxyAddresses.Destination, ""
	case ConnectPurposeHealth:
		return conn.LocalAddr(), conn.RemoteAddr(), ""
	default:
		return nil, nil, TransportReasonConfig
	}
}

// newBackendProxyHeader validates TCP address data before delegating wire rendering.
func newBackendProxyHeader(source net.Addr, destination net.Addr) (*proxyproto.Header, TransportReason) {
	sourceTCP, sourceFamily, reason := normalizeBackendProxyAddr(source)
	if reason != "" {
		return nil, reason
	}

	destinationTCP, destinationFamily, reason := normalizeBackendProxyAddr(destination)
	if reason != "" {
		return nil, reason
	}

	if sourceFamily != destinationFamily {
		return nil, TransportReasonUnsupportedFamily
	}

	header := proxyproto.HeaderProxyFromAddrs(1, sourceTCP, destinationTCP)
	if !header.Command.IsProxy() {
		return nil, TransportReasonUnsupportedFamily
	}

	if header.TransportProtocol != proxyproto.TCPv4 && header.TransportProtocol != proxyproto.TCPv6 {
		return nil, TransportReasonUnsupportedFamily
	}

	return header, ""
}

// normalizeBackendProxyAddr converts one net.Addr into the supported TCP subset.
func normalizeBackendProxyAddr(addr net.Addr) (*net.TCPAddr, string, TransportReason) {
	if addr == nil {
		return nil, "", TransportReasonMissingAddress
	}

	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		return nil, "", TransportReasonUnsupportedFamily
	}

	if tcpAddr.IP == nil {
		return nil, "", TransportReasonMissingAddress
	}

	if tcpAddr.Port < 0 || tcpAddr.Port > 65535 {
		return nil, "", TransportReasonMissingAddress
	}

	if ip := tcpAddr.IP.To4(); ip != nil {
		return &net.TCPAddr{IP: append(net.IP(nil), ip...), Port: tcpAddr.Port}, "tcp4", ""
	}

	if ip := tcpAddr.IP.To16(); ip != nil {
		return &net.TCPAddr{IP: append(net.IP(nil), ip...), Port: tcpAddr.Port}, "tcp6", ""
	}

	return nil, "", TransportReasonUnsupportedFamily
}

// writeBackendProxyHeader writes and flushes one complete PROXY preface.
func writeBackendProxyHeader(conn net.Conn, header *proxyproto.Header) error {
	if header == nil {
		return errors.New("missing proxy protocol header")
	}

	if _, err := header.WriteTo(conn); err != nil {
		return err
	}

	return flushBackendProxyWriter(conn)
}

// flushBackendProxyWriter flushes buffered fake or future writer boundaries.
func flushBackendProxyWriter(conn net.Conn) error {
	flusher, ok := conn.(interface{ Flush() error })
	if !ok {
		return nil
	}

	return flusher.Flush()
}

// normalizeBackendConnectPurpose accepts only the transport purposes in the public boundary.
func normalizeBackendConnectPurpose(purpose ConnectPurpose) (ConnectPurpose, error) {
	switch purpose {
	case ConnectPurposeSession, ConnectPurposeHealth:
		return purpose, nil
	default:
		return "", errors.New("unsupported backend connect purpose")
	}
}

// boundedBackendConnectPurpose keeps result metadata in the documented purpose set.
func boundedBackendConnectPurpose(purpose ConnectPurpose) ConnectPurpose {
	switch purpose {
	case ConnectPurposeSession, ConnectPurposeHealth:
		return purpose
	default:
		return ""
	}
}

// failBackendTransport closes unusable backend streams before returning a bounded error.
func failBackendTransport(conn net.Conn, reason TransportReason, purpose ConnectPurpose, cause error) (TransportResult, error) {
	if conn != nil {
		_ = conn.Close()
	}

	return TransportResult{Reason: reason, Purpose: purpose}, &TransportError{
		Reason:  reason,
		Purpose: purpose,
		cause:   cause,
	}
}

// recordBackendProxyProtocol emits one bounded observation for the shared preface step.
func recordBackendProxyProtocol(ctx context.Context, request ConnectRequest, result TransportResult) {
	reason := strings.TrimSpace(string(result.Reason))
	if reason == "" {
		reason = string(TransportReasonConfig)
	}

	fields := backendProxyObservationFields(request, result, reason)
	labels := backendProxyObservationLabels(request, result, reason)

	event, err := observability.NewEvent(observability.EventBackendProxyProtocol, observability.TraceBoundaryBackendConnect, fields, labels)
	if err != nil {
		return
	}

	observability.NormalizeRecorder(request.Observability).Record(ctx, event)
}

// backendProxyObservationFields returns log and trace fields without raw socket data.
func backendProxyObservationFields(request ConnectRequest, result TransportResult, reason string) map[string]string {
	fields := map[string]string{
		backendProxyObservationFieldBackendPool: strings.TrimSpace(request.Target.BackendPool),
		backendProxyObservationFieldOperation:   backendProxyObservationOperation,
		backendProxyObservationFieldProtocol:    normalizeProtocol(request.Target.Protocol),
		backendProxyObservationFieldReasonClass: reason,
		backendProxyObservationFieldResult:      backendProxyObservationResult(result),
	}

	if purpose := strings.TrimSpace(string(result.Purpose)); purpose != "" {
		fields[backendProxyObservationFieldPurpose] = purpose
	}

	if backendNode := strings.TrimSpace(request.Target.BackendNode); backendNode != "" {
		fields[backendProxyObservationFieldBackendNode] = backendNode
	}

	return fields
}

// backendProxyObservationLabels returns only low-cardinality Prometheus labels.
func backendProxyObservationLabels(request ConnectRequest, result TransportResult, reason string) map[string]string {
	return map[string]string{
		backendProxyObservationFieldBackendPool: strings.TrimSpace(request.Target.BackendPool),
		backendProxyObservationFieldOperation:   backendProxyObservationOperation,
		backendProxyObservationFieldProtocol:    normalizeProtocol(request.Target.Protocol),
		backendProxyObservationFieldReasonClass: reason,
		backendProxyObservationFieldResult:      backendProxyObservationResult(result),
	}
}

// backendProxyObservationResult maps disabled and successful writes to ok.
func backendProxyObservationResult(result TransportResult) string {
	switch result.Reason {
	case TransportReasonOK, TransportReasonDisabled:
		return backendProxyObservationResultOK
	default:
		return backendProxyObservationResultFailure
	}
}
