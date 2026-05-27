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

package imap

import (
	"context"
	"errors"
	"maps"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/observability"
)

const (
	observationOperationBackendAuth    = "backend_auth"
	observationOperationBackendConnect = "backend_connect"
	observationOperationBackendSelect  = "backend_select"
	observationOperationPreAuth        = "pre_auth"
	observationOperationProxy          = "proxy"
	observationOperationRouting        = "routing"
	observationOperationSessionAttach  = "session_attach"
	observationOperationSessionClose   = "session_close"
	observationOperationSession        = "session"

	observationResultFailure = "failure"
	observationResultOK      = "ok"
	observationResultStart   = "start"

	reasonBackendAuth     = "backend_auth_failed"
	reasonBackendConnect  = "backend_connect_failed"
	reasonCanceled        = "canceled"
	reasonCredentialInput = "credential_input"
	reasonLiteral         = "literal"
	reasonProtocol        = "protocol"
	reasonState           = "state_failed"
	reasonUnsupported     = "unsupported"

	obsFieldAffinitySource    = "affinity_source"
	obsFieldBackendIdentifier = "backend_identifier"
	obsFieldBackendPool       = "backend_pool"
	obsFieldCommand           = "command"
	obsFieldListener          = "listener"
	obsFieldMechanism         = "mechanism"
	obsFieldOperation         = "operation"
	obsFieldProtocol          = "protocol"
	obsFieldReasonClass       = "reason_class"
	obsFieldRemoteAddr        = "remote_addr"
	obsFieldResult            = "result"
	obsFieldRoutingSource     = "routing_source"
	obsFieldService           = "service"
	obsFieldSessionID         = "session_id"
	obsFieldShardTag          = "shard_tag"
	obsFieldTLSMode           = "tls_mode"
	obsFieldTransport         = "transport"
)

// recordSessionStart emits the first accepted-session observation.
func (s *Session) recordSessionStart(ctx context.Context) {
	s.recordObservation(ctx, observability.EventSessionStart, observability.TraceBoundarySession, observationOperationSession, observationResultStart, "", nil)
}

// recordSessionEnd emits the terminal accepted-session observation.
func (s *Session) recordSessionEnd(ctx context.Context, err error) {
	s.recordObservation(ctx, observability.EventSessionEnd, observability.TraceBoundarySession, observationOperationSession, resultLabel(err), reasonClass(err), nil)
}

// recordPreAuth emits one IMAP pre-auth parser or command observation.
func (s *Session) recordPreAuth(ctx context.Context, command string, result string, reason string) {
	s.recordObservation(ctx, observability.EventIMAPPreAuth, observability.TraceBoundaryIMAPPreAuth, observationOperationPreAuth, result, reason, map[string]string{
		obsFieldCommand: strings.ToLower(strings.TrimSpace(command)),
	})
}

// recordRoutingResolve emits one director-owned routing observation.
func (s *Session) recordRoutingResolve(ctx context.Context, result string, reason string, source string, duration time.Duration) {
	s.recordObservation(ctx, observability.EventRoutingResolve, observability.TraceBoundaryRoutingResolve, observationOperationRouting, result, reason, map[string]string{
		obsFieldRoutingSource: source,
	}, duration)
}

// recordAffinityOpen emits the Redis-backed session-open observation.
func (s *Session) recordAffinityOpen(ctx context.Context, result string, reason string, source string, shardTag string) {
	s.recordObservation(ctx, observability.EventAffinityOpen, observability.TraceBoundaryRoutingResolve, "affinity_open", result, reason, map[string]string{
		obsFieldAffinitySource: source,
		obsFieldShardTag:       shardTag,
	})
}

// recordSessionAttach emits selected-backend attachment observations.
func (s *Session) recordSessionAttach(ctx context.Context, result string, reason string, backendID string, shardTag string) {
	s.recordObservation(ctx, observability.EventSessionAttach, observability.TraceBoundaryBackendSelect, observationOperationSessionAttach, result, reason, map[string]string{
		obsFieldBackendIdentifier: strings.TrimSpace(backendID),
		obsFieldShardTag:          strings.TrimSpace(shardTag),
	})
}

// recordSessionClose emits Redis lease closure observations.
func (s *Session) recordSessionClose(ctx context.Context, result string, reason string) {
	s.recordObservation(ctx, observability.EventSessionClose, observability.TraceBoundarySession, observationOperationSessionClose, result, reason, nil)
}

// recordBackendSelect emits one concrete backend selection observation.
func (s *Session) recordBackendSelect(ctx context.Context, result string, reason string, shardTag string, duration time.Duration) {
	s.recordObservation(ctx, observability.EventBackendSelect, observability.TraceBoundaryBackendSelect, observationOperationBackendSelect, result, reason, map[string]string{
		obsFieldShardTag: shardTag,
	}, duration)
}

// recordBackendConnect emits one backend connection observation.
func (s *Session) recordBackendConnect(ctx context.Context, result string, reason string, duration time.Duration) {
	s.recordObservation(ctx, observability.EventBackendConnect, observability.TraceBoundaryBackendConnect, observationOperationBackendConnect, result, reason, nil, duration)
}

// recordBackendAuth emits one backend authentication observation.
func (s *Session) recordBackendAuth(ctx context.Context, result string, reason string, mechanism string) {
	s.recordObservation(ctx, observability.EventBackendAuth, observability.TraceBoundaryBackendConnect, observationOperationBackendAuth, result, reason, map[string]string{
		obsFieldMechanism: strings.ToLower(strings.TrimSpace(mechanism)),
	})
}

// recordObservation builds a normalized event and drops impossible internal label mistakes.
func (s *Session) recordObservation(
	ctx context.Context,
	name string,
	boundary observability.TraceBoundary,
	operation string,
	result string,
	reason string,
	extraFields map[string]string,
	duration ...time.Duration,
) {
	event := s.newObservation(ctx, name, boundary, operation, result, reason, extraFields, duration...)
	if event.Name == "" {
		return
	}

	observability.NormalizeRecorder(s.observability).Record(ctx, event)
}

// newObservation builds a normalized event and returns zero on policy mistakes.
func (s *Session) newObservation(
	_ context.Context,
	name string,
	boundary observability.TraceBoundary,
	operation string,
	result string,
	reason string,
	extraFields map[string]string,
	duration ...time.Duration,
) observability.Event {
	fields := s.observationFields(operation, result, reason)
	maps.Copy(fields, extraFields)

	labels := s.observationLabels(operation, result, reason, extraFields)

	event, err := observability.NewEvent(name, boundary, fields, labels)
	if err != nil {
		return observability.Event{}
	}

	if len(duration) > 0 && duration[0] > 0 {
		event.Measurements = observability.NewMetricMeasurements(map[string]float64{
			observability.MetricMeasurementDurationSeconds: duration[0].Seconds(),
		})
	}

	return event
}

// startObservationSpan starts a prepared span with the same safe session fields.
func (s *Session) startObservationSpan(
	ctx context.Context,
	boundary observability.TraceBoundary,
	operation string,
	result string,
	reason string,
	extraFields map[string]string,
) (context.Context, observability.TraceSpan) {
	fields := s.observationFields(operation, result, reason)
	maps.Copy(fields, extraFields)

	return observability.StartSpan(ctx, s.observability, boundary, fields)
}

// observationFields returns structured log fields before policy normalization.
func (s *Session) observationFields(operation string, result string, reason string) map[string]string {
	fields := map[string]string{
		obsFieldBackendPool: s.context.BackendPool,
		obsFieldListener:    s.context.ListenerName,
		obsFieldOperation:   operation,
		obsFieldProtocol:    protocolIMAP,
		obsFieldRemoteAddr:  safeAddrString(s.context.RemoteAddr),
		obsFieldResult:      result,
		obsFieldService:     s.context.ServiceName,
		obsFieldSessionID:   s.context.ID,
		obsFieldTLSMode:     s.context.TLSMode,
	}

	if reason != "" {
		fields[obsFieldReasonClass] = reason
	}

	if s.placed {
		fields[obsFieldBackendIdentifier] = s.placement.Backend.Backend.Identifier
		fields[obsFieldShardTag] = s.placement.SelectedShardTag
	}

	return fields
}

// observationLabels returns low-cardinality labels that must pass the allowlist.
func (s *Session) observationLabels(operation string, result string, reason string, extraFields map[string]string) map[string]string {
	labels := map[string]string{
		obsFieldBackendPool: s.context.BackendPool,
		obsFieldListener:    s.context.ListenerName,
		obsFieldOperation:   operation,
		obsFieldProtocol:    protocolIMAP,
		obsFieldResult:      result,
		obsFieldService:     s.context.ServiceName,
		obsFieldTLSMode:     s.context.TLSMode,
	}

	if transport := strings.ToLower(strings.TrimSpace(s.context.AuthorityTransport)); transport != "" {
		labels[obsFieldTransport] = transport
	}

	if mechanism := extraFields[obsFieldMechanism]; mechanism != "" {
		labels[obsFieldMechanism] = mechanism
	}

	if reason != "" {
		labels[obsFieldReasonClass] = reason
	}

	if shardTag := extraFields[obsFieldShardTag]; shardTag != "" {
		labels[obsFieldShardTag] = shardTag
	} else if s.placed && s.placement.SelectedShardTag != "" {
		labels[obsFieldShardTag] = s.placement.SelectedShardTag
	}

	return labels
}

// resultLabel turns an error into a bounded result value.
func resultLabel(err error) string {
	if err != nil {
		return observationResultFailure
	}

	return observationResultOK
}

// reasonClass classifies errors without exposing raw error text.
func reasonClass(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return reasonCanceled
	case errors.Is(err, ErrBackendAuth), errors.Is(err, ErrBackendAuthPolicy):
		return reasonBackendAuth
	case errors.Is(err, ErrBackendConnect), errors.Is(err, ErrBackendTLS), errors.Is(err, ErrBackendProtocol):
		return reasonBackendConnect
	case errors.Is(err, ErrCredentialRejected), errors.Is(err, ErrCredentialTooLarge):
		return reasonCredentialInput
	case errors.Is(err, ErrPreauthLiteralTooLarge), errors.Is(err, ErrPreauthLiteralUnsupported):
		return reasonLiteral
	case errors.Is(err, ErrUnsupportedAuthMechanism), errors.Is(err, ErrUnsupportedCommand):
		return reasonUnsupported
	default:
		return reasonProtocol
	}
}

// safeAddrString returns address text only for sanitizer collapse into presence.
func safeAddrString(addr interface{ String() string }) string {
	if addr == nil {
		return ""
	}

	return addr.String()
}
