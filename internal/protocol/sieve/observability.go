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

//nolint:goconst,gocyclo // Reason classification keeps protocol-safe error mapping centralized.
package sieve

import (
	"context"
	"errors"
	"maps"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/placement"
	"github.com/croessner/nauthilus-director/internal/protocol/saslcred"
	"github.com/croessner/nauthilus-director/internal/proxy"
	runtimectl "github.com/croessner/nauthilus-director/internal/runtime"
	"github.com/croessner/nauthilus-director/internal/state"
)

const (
	sieveObservationOperationAuthenticate  = "authenticate"
	sieveObservationOperationBackendAuth   = "backend_auth"
	sieveObservationOperationBackendSelect = "backend_select"
	sieveObservationOperationBackendConn   = "backend_connect"
	sieveObservationOperationCapability    = "capability"
	sieveObservationOperationHoldWait      = "user_hold_wait"
	sieveObservationOperationPreAuth       = "pre_auth"
	sieveObservationOperationProxy         = "proxy"
	sieveObservationOperationRouting       = "routing"
	sieveObservationOperationSession       = "session"
	sieveObservationOperationSessionAttach = "session_attach"
	sieveObservationOperationSessionClose  = "session_close"
	sieveObservationOperationStartTLS      = "starttls"

	sieveObservationResultFailure      = "failure"
	sieveObservationResultOK           = "ok"
	sieveObservationResultRejected     = "rejected"
	sieveObservationResultStart        = "start"
	sieveObservationResultUnsupported  = "unsupported"
	sieveObservationResultWaitReleased = "wait_released"

	sieveReasonBackendAuth          = "backend_auth_failed"
	sieveReasonBackendConnect       = "backend_connect"
	sieveReasonBackendProxyConfig   = "backend_proxy_config"
	sieveReasonBackendProxyMissing  = "backend_proxy_missing_address"
	sieveReasonBackendProxyFamily   = "backend_proxy_unsupported_family"
	sieveReasonBackendProxyWrite    = "backend_proxy_write_failed"
	sieveReasonAuth                 = "auth"
	sieveReasonBindingExpired       = "binding_expired"
	sieveReasonBindingRetained      = "binding_retained"
	sieveReasonCanceled             = "canceled"
	sieveReasonControlAction        = "control_action"
	sieveReasonCredentialInput      = "credential_input"
	sieveReasonIncomplete           = "incomplete"
	sieveReasonLiteral              = "literal"
	sieveReasonOK                   = "ok"
	sieveReasonParser               = "parser"
	sieveReasonProtocol             = "protocol"
	sieveReasonRouting              = "routing"
	sieveReasonState                = "state_failed"
	sieveReasonTemporaryFailure     = "temporary_failure"
	sieveReasonUnsupported          = "unsupported"
	sieveReasonUserHoldWaitReleased = "user_hold_wait_released"
	sieveReasonUserHoldWaitTimeout  = "user_hold_wait_timeout"

	sieveObsFieldBackendIdentifier = "backend_identifier"
	sieveObsFieldBackendNode       = "backend_node"
	sieveObsFieldBackendPool       = "backend_pool"
	sieveObsFieldCommand           = "command"
	sieveObsFieldListener          = "listener"
	sieveObsFieldMechanism         = "mechanism"
	sieveObsFieldOperation         = "operation"
	sieveObsFieldProtocol          = "protocol"
	sieveObsFieldReasonClass       = "reason_class"
	sieveObsFieldRemoteAddr        = "remote_addr"
	sieveObsFieldResult            = "result"
	sieveObsFieldRoutingSource     = "routing_source"
	sieveObsFieldService           = "service"
	sieveObsFieldSessionID         = "session_id"
	sieveObsFieldShardTag          = "shard_tag"
	sieveObsFieldTLSMode           = "tls_mode"
	sieveObsFieldTransport         = "transport"
)

// recordSessionStart emits the first accepted ManageSieve session observation.
func (s *Session) recordSessionStart(ctx context.Context) {
	s.recordObservation(ctx, observability.EventSessionStart, observability.TraceBoundarySession, sieveObservationOperationSession, sieveObservationResultStart, "", nil)
}

// recordSessionEnd emits the terminal accepted ManageSieve session observation.
func (s *Session) recordSessionEnd(ctx context.Context, err error) {
	s.recordObservation(ctx, observability.EventSessionEnd, observability.TraceBoundarySession, sieveObservationOperationSession, sieveResultLabel(err), sieveReasonClass(err), nil)
}

// recordPreAuth emits one bounded pre-auth command observation.
func (s *Session) recordPreAuth(ctx context.Context, command string, result string, reason string) {
	s.recordObservation(ctx, observability.EventSievePreAuth, observability.TraceBoundarySievePreAuth, sieveObservationOperationPreAuth, result, reason, map[string]string{
		sieveObsFieldCommand: safeSieveCommand(command),
	})
}

// recordCapability emits greeting or CAPABILITY rendering results.
func (s *Session) recordCapability(ctx context.Context, result string, reason string) {
	s.recordObservation(ctx, observability.EventSievePreAuth, observability.TraceBoundarySievePreAuth, sieveObservationOperationCapability, result, reason, nil)
}

// recordStartTLS emits STARTTLS upgrade results without transcript bytes.
func (s *Session) recordStartTLS(ctx context.Context, result string, reason string) {
	s.recordObservation(ctx, observability.EventSievePreAuth, observability.TraceBoundarySievePreAuth, sieveObservationOperationStartTLS, result, reason, nil)
}

// recordAuthenticate emits frontend AUTHENTICATE command results without SASL material.
func (s *Session) recordAuthenticate(ctx context.Context, result string, reason string, mechanism string) {
	s.recordObservation(ctx, observability.EventSievePreAuth, observability.TraceBoundarySievePreAuth, sieveObservationOperationAuthenticate, result, reason, map[string]string{
		sieveObsFieldMechanism: strings.ToLower(strings.TrimSpace(mechanism)),
	})
}

// recordNauthilusAuth emits one authority-auth observation.
func (s *Session) recordNauthilusAuth(ctx context.Context, result string, reason string, mechanism string, duration time.Duration) {
	s.recordObservation(ctx, observability.EventNauthilusAuth, observability.TraceBoundaryNauthilusAuth, sieveObservationOperationAuthenticate, result, reason, map[string]string{
		sieveObsFieldMechanism: strings.ToLower(strings.TrimSpace(mechanism)),
		sieveObsFieldTransport: strings.ToLower(strings.TrimSpace(s.authorityTransport)),
	}, duration)
}

// recordRoutingResolve emits one director-owned routing observation.
func (s *Session) recordRoutingResolve(ctx context.Context, result string, reason string, source string, shardTag string, duration time.Duration) {
	s.recordObservation(ctx, observability.EventRoutingResolve, observability.TraceBoundaryRoutingResolve, sieveObservationOperationRouting, result, reason, map[string]string{
		sieveObsFieldRoutingSource: strings.TrimSpace(source),
		sieveObsFieldShardTag:      strings.TrimSpace(shardTag),
	}, duration)
}

// recordPlacementGate emits a Sieve-local hold-gate result for fakes and tests.
func (s *Session) recordPlacementGate(ctx context.Context, result string, reason string) {
	s.recordObservation(ctx, observability.EventUserHold, observability.TraceBoundaryBackendSelect, sieveObservationOperationHoldWait, result, reason, nil)
}

// recordAffinityOpen emits the Redis-backed session-open observation.
func (s *Session) recordAffinityOpen(ctx context.Context, result string, reason string, source string, shardTag string, backendNode string) {
	s.recordObservation(ctx, observability.EventAffinityOpen, observability.TraceBoundaryRoutingResolve, "affinity_open", result, reason, map[string]string{
		sieveObsFieldBackendNode: strings.TrimSpace(backendNode),
		sieveObsFieldShardTag:    strings.TrimSpace(shardTag),
		"affinity_source":        strings.TrimSpace(source),
	})
}

// recordSessionAttach emits selected-backend attachment observations.
func (s *Session) recordSessionAttach(ctx context.Context, result string, reason string, backendID string, backendNode string, shardTag string) {
	s.recordObservation(ctx, observability.EventSessionAttach, observability.TraceBoundaryBackendSelect, sieveObservationOperationSessionAttach, result, reason, map[string]string{
		sieveObsFieldBackendIdentifier: strings.TrimSpace(backendID),
		sieveObsFieldBackendNode:       strings.TrimSpace(backendNode),
		sieveObsFieldShardTag:          strings.TrimSpace(shardTag),
	})
}

// recordSessionClose emits Redis lease closure observations.
func (s *Session) recordSessionClose(ctx context.Context, result string, reason string) {
	s.recordObservation(ctx, observability.EventSessionClose, observability.TraceBoundarySession, sieveObservationOperationSessionClose, result, reason, nil)
}

// recordBackendSelect emits backend selection observations.
func (s *Session) recordBackendSelect(ctx context.Context, result string, reason string, shardTag string, backendNode string, duration time.Duration) {
	s.recordObservation(ctx, observability.EventBackendSelect, observability.TraceBoundaryBackendSelect, sieveObservationOperationBackendSelect, result, reason, map[string]string{
		sieveObsFieldBackendNode: strings.TrimSpace(backendNode),
		sieveObsFieldShardTag:    strings.TrimSpace(shardTag),
	}, duration)
}

// recordBackendConnect emits one backend connection observation.
func (s *Session) recordBackendConnect(ctx context.Context, result string, reason string, duration time.Duration) {
	s.recordObservation(ctx, observability.EventBackendConnect, observability.TraceBoundaryBackendConnect, sieveObservationOperationBackendConn, result, reason, nil, duration)
}

// recordBackendAuth emits one backend authentication observation.
func (s *Session) recordBackendAuth(ctx context.Context, result string, reason string, mechanism string) {
	s.recordObservation(ctx, observability.EventBackendAuth, observability.TraceBoundaryBackendConnect, sieveObservationOperationBackendAuth, result, reason, map[string]string{
		sieveObsFieldMechanism: strings.ToLower(strings.TrimSpace(mechanism)),
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
	event := s.newObservation(name, boundary, operation, result, reason, extraFields, duration...)
	if event.Name == "" {
		return
	}

	observability.NormalizeRecorder(s.observability).Record(ctx, event)
}

// newObservation builds a normalized event and returns zero on policy mistakes.
func (s *Session) newObservation(
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

// startObservationSpan starts a prepared span with bounded session attributes.
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
		sieveObsFieldBackendPool: s.backendPool,
		sieveObsFieldListener:    s.listenerName,
		sieveObsFieldOperation:   operation,
		sieveObsFieldProtocol:    protocolSieve,
		sieveObsFieldRemoteAddr:  safeSieveAddrString(s.conn.RemoteAddr()),
		sieveObsFieldResult:      result,
		sieveObsFieldService:     s.serviceName,
		sieveObsFieldSessionID:   s.sessionID,
		sieveObsFieldTLSMode:     s.tlsMode,
	}

	if reason != "" {
		fields[sieveObsFieldReasonClass] = reason
	}

	if s.placed {
		fields[sieveObsFieldBackendIdentifier] = s.placement.Backend.Backend.Identifier
		fields[sieveObsFieldBackendNode] = s.placement.Backend.Backend.BackendNode
		fields[sieveObsFieldShardTag] = s.placement.SelectedShardTag
	}

	return fields
}

// observationLabels returns low-cardinality labels that must pass the allowlist.
func (s *Session) observationLabels(operation string, result string, reason string, extraFields map[string]string) map[string]string {
	labels := map[string]string{
		sieveObsFieldBackendPool: s.backendPool,
		sieveObsFieldListener:    s.listenerName,
		sieveObsFieldOperation:   operation,
		sieveObsFieldProtocol:    protocolSieve,
		sieveObsFieldResult:      result,
		sieveObsFieldService:     s.serviceName,
		sieveObsFieldTLSMode:     s.tlsMode,
	}

	if transport := strings.ToLower(strings.TrimSpace(s.authorityTransport)); transport != "" {
		labels[sieveObsFieldTransport] = transport
	}

	if mechanism := strings.ToLower(strings.TrimSpace(extraFields[sieveObsFieldMechanism])); mechanism != "" {
		labels[sieveObsFieldMechanism] = mechanism
	}

	if reason != "" {
		labels[sieveObsFieldReasonClass] = reason
	}

	if shardTag := strings.TrimSpace(extraFields[sieveObsFieldShardTag]); shardTag != "" {
		labels[sieveObsFieldShardTag] = shardTag
	} else if s.placed && s.placement.SelectedShardTag != "" {
		labels[sieveObsFieldShardTag] = s.placement.SelectedShardTag
	}

	return labels
}

// sieveResultLabel turns an error into a bounded result value.
func sieveResultLabel(err error) string {
	if err != nil {
		return sieveObservationResultFailure
	}

	return sieveObservationResultOK
}

// sieveReasonClass classifies errors without exposing raw error text.
func sieveReasonClass(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return sieveReasonCanceled
	case proxy.IsControlActionError(err):
		return sieveReasonControlAction
	case errors.Is(err, ErrBackendAuth), errors.Is(err, ErrBackendAuthPolicy):
		return sieveReasonBackendAuth
	case backend.IsTransportReason(err, backend.TransportReasonWriteFailed):
		return sieveReasonBackendProxyWrite
	case backend.IsTransportReason(err, backend.TransportReasonMissingAddress):
		return sieveReasonBackendProxyMissing
	case backend.IsTransportReason(err, backend.TransportReasonUnsupportedFamily):
		return sieveReasonBackendProxyFamily
	case backend.IsTransportReason(err, backend.TransportReasonConfig):
		return sieveReasonBackendProxyConfig
	case errors.Is(err, ErrBackendConnect), errors.Is(err, ErrBackendTLS), errors.Is(err, ErrBackendProtocol):
		return sieveReasonBackendConnect
	case errors.Is(err, saslcred.ErrRejected), errors.Is(err, saslcred.ErrTooLarge):
		return sieveReasonCredentialInput
	case errors.Is(err, ErrMalformedCommand), errors.Is(err, ErrPreauthLineTooLarge), errors.Is(err, ErrPreauthPartialCommand):
		return sieveReasonParser
	case errors.Is(err, ErrPreauthLiteralTooLarge):
		return sieveReasonLiteral
	case errors.Is(err, saslcred.ErrUnsupportedMechanism), errors.Is(err, ErrUnsupportedCommand):
		return sieveReasonUnsupported
	case placement.IsErrorKind(err, placement.ErrorKindBackendNodeMissingProtocol):
		return string(placement.ErrorKindBackendNodeMissingProtocol)
	case placement.IsErrorKind(err, placement.ErrorKindBackendNodeMismatch):
		return string(placement.ErrorKindBackendNodeMismatch)
	case placement.IsErrorKind(err, placement.ErrorKindBackendNodeUnusable):
		return string(placement.ErrorKindBackendNodeUnusable)
	case runtimectl.IsErrorKind(err, runtimectl.ErrorKindUnavailable):
		return sieveReasonTemporaryFailure
	default:
		return sieveReasonProtocol
	}
}

// sieveCloseReasonClass maps successful lease close state into binding retention classes.
func sieveCloseReasonClass(err error, record state.AffinityRecord) string {
	if err != nil {
		return sieveReasonClass(err)
	}

	switch record.BindingStatus {
	case state.BindingStatusRetained:
		return sieveReasonBindingRetained
	case state.BindingStatusExpired:
		return sieveReasonBindingExpired
	default:
		if record.ActiveHolderCount == 0 && !record.RetentionExpiresAt.IsZero() {
			return sieveReasonBindingRetained
		}

		return sieveReasonOK
	}
}

// holdGateObservation maps placement-gate results into bounded observable outcomes.
func holdGateObservation(result runtimectl.PlacementGateResult, err error) (string, string) {
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "wait timeout") {
			return sieveObservationResultFailure, sieveReasonUserHoldWaitTimeout
		}

		return sieveObservationResultFailure, sieveReasonTemporaryFailure
	}

	if result.Outcome == runtimectl.PlacementGateOutcomeReleased || result.RuntimeStateRecheckRequired {
		return sieveObservationResultWaitReleased, sieveReasonUserHoldWaitReleased
	}

	return sieveObservationResultOK, sieveReasonOK
}

// safeSieveCommand returns only the known command token as observable metadata.
func safeSieveCommand(command string) string {
	switch strings.ToUpper(strings.TrimSpace(command)) {
	case commandAuthenticate:
		return strings.ToLower(commandAuthenticate)
	case commandCapability:
		return strings.ToLower(commandCapability)
	case commandLogout:
		return strings.ToLower(commandLogout)
	case commandNoop:
		return strings.ToLower(commandNoop)
	case commandStartTLS:
		return strings.ToLower(commandStartTLS)
	case "parse":
		return "parse"
	default:
		return "unknown"
	}
}

// safeSieveAddrString returns address text only for sanitizer collapse into presence.
func safeSieveAddrString(addr interface{ String() string }) string {
	if addr == nil {
		return ""
	}

	return addr.String()
}
