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

//nolint:goconst,gocyclo // POP3 reason classification keeps safe telemetry mapping centralized.
package pop3

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
	pop3ObservationOperationAuthenticate  = "authenticate"
	pop3ObservationOperationBackendAuth   = "backend_auth"
	pop3ObservationOperationBackendConn   = "backend_connect"
	pop3ObservationOperationBackendSelect = "backend_select"
	pop3ObservationOperationCapability    = "capability"
	pop3ObservationOperationGreeting      = "greeting"
	pop3ObservationOperationHoldWait      = "user_hold_wait"
	pop3ObservationOperationPreAuth       = "pre_auth"
	pop3ObservationOperationProxy         = "proxy"
	pop3ObservationOperationRouting       = "routing"
	pop3ObservationOperationSession       = "session"
	pop3ObservationOperationSessionAttach = "session_attach"
	pop3ObservationOperationSessionClose  = "session_close"
	pop3ObservationOperationSTLS          = "stls"
	pop3ObservationOperationUser          = "user"

	pop3ObservationResultFailure      = "failure"
	pop3ObservationResultOK           = "ok"
	pop3ObservationResultRejected     = "rejected"
	pop3ObservationResultStart        = "start"
	pop3ObservationResultUnsupported  = "unsupported"
	pop3ObservationResultWaitReleased = "wait_released"

	pop3ReasonAuth                 = "auth"
	pop3ReasonBackendAuth          = "backend_auth_failed"
	pop3ReasonBackendConnect       = "backend_connect"
	pop3ReasonBackendProxyConfig   = "backend_proxy_config"
	pop3ReasonBackendProxyMissing  = "backend_proxy_missing_address"
	pop3ReasonBackendProxyFamily   = "backend_proxy_unsupported_family"
	pop3ReasonBackendProxyWrite    = "backend_proxy_write_failed"
	pop3ReasonBindingExpired       = "binding_expired"
	pop3ReasonBindingRetained      = "binding_retained"
	pop3ReasonCanceled             = "canceled"
	pop3ReasonControlAction        = "control_action"
	pop3ReasonCredentialInput      = "credential_input"
	pop3ReasonIncomplete           = "incomplete"
	pop3ReasonLiteral              = "literal"
	pop3ReasonOK                   = "ok"
	pop3ReasonParser               = "parser"
	pop3ReasonProtocol             = "protocol"
	pop3ReasonRouting              = "routing"
	pop3ReasonState                = "state_failed"
	pop3ReasonTemporaryFailure     = "temporary_failure"
	pop3ReasonUnsupported          = "unsupported"
	pop3ReasonUserHoldWaitReleased = "user_hold_wait_released"
	pop3ReasonUserHoldWaitTimeout  = "user_hold_wait_timeout"

	pop3ObsFieldAffinitySource    = "affinity_source"
	pop3ObsFieldBackendIdentifier = "backend_identifier"
	pop3ObsFieldBackendNode       = "backend_node"
	pop3ObsFieldBackendPool       = "backend_pool"
	pop3ObsFieldCommand           = "command"
	pop3ObsFieldListener          = "listener"
	pop3ObsFieldMechanism         = "mechanism"
	pop3ObsFieldOperation         = "operation"
	pop3ObsFieldProtocol          = "protocol"
	pop3ObsFieldReasonClass       = "reason_class"
	pop3ObsFieldRemoteAddr        = "remote_addr"
	pop3ObsFieldResult            = "result"
	pop3ObsFieldRoutingSource     = "routing_source"
	pop3ObsFieldService           = "service"
	pop3ObsFieldSessionID         = "session_id"
	pop3ObsFieldShardTag          = "shard_tag"
	pop3ObsFieldTLSMode           = "tls_mode"
	pop3ObsFieldTransport         = "transport"
)

// recordSessionStart emits the first accepted POP3 session observation.
func (s *Session) recordSessionStart(ctx context.Context) {
	s.recordObservation(ctx, observability.EventSessionStart, observability.TraceBoundarySession, pop3ObservationOperationSession, pop3ObservationResultStart, "", nil)
}

// recordSessionEnd emits the terminal accepted POP3 session observation.
func (s *Session) recordSessionEnd(ctx context.Context, err error) {
	s.recordObservation(ctx, observability.EventSessionEnd, observability.TraceBoundarySession, pop3ObservationOperationSession, pop3ResultLabel(err), pop3ReasonClass(err), nil)
}

// recordPreAuth emits one bounded POP3 pre-auth command observation.
func (s *Session) recordPreAuth(ctx context.Context, command string, result string, reason string) {
	s.recordObservation(ctx, observability.EventPOP3PreAuth, observability.TraceBoundaryPOP3PreAuth, pop3ObservationOperationPreAuth, result, reason, map[string]string{
		pop3ObsFieldCommand: safePOP3Command(command),
	})
}

// recordGreeting emits greeting rendering results without deployment details.
func (s *Session) recordGreeting(ctx context.Context, result string, reason string) {
	s.recordObservation(ctx, observability.EventPOP3PreAuth, observability.TraceBoundaryPOP3PreAuth, pop3ObservationOperationGreeting, result, reason, nil)
}

// recordCapability emits CAPA rendering results without response body sampling.
func (s *Session) recordCapability(ctx context.Context, result string, reason string) {
	s.recordObservation(ctx, observability.EventPOP3PreAuth, observability.TraceBoundaryPOP3PreAuth, pop3ObservationOperationCapability, result, reason, nil)
}

// recordSTLS emits STLS upgrade outcomes without TLS transcript material.
func (s *Session) recordSTLS(ctx context.Context, result string, reason string) {
	s.recordObservation(ctx, observability.EventPOP3PreAuth, observability.TraceBoundaryPOP3PreAuth, pop3ObservationOperationSTLS, result, reason, nil)
}

// recordUser emits USER command outcomes without the supplied username.
func (s *Session) recordUser(ctx context.Context, result string, reason string) {
	s.recordObservation(ctx, observability.EventPOP3PreAuth, observability.TraceBoundaryPOP3PreAuth, pop3ObservationOperationUser, result, reason, nil)
}

// recordAuthenticate emits frontend auth method outcomes without credentials.
func (s *Session) recordAuthenticate(ctx context.Context, result string, reason string, mechanism string) {
	s.recordObservation(ctx, observability.EventPOP3PreAuth, observability.TraceBoundaryPOP3PreAuth, pop3ObservationOperationAuthenticate, result, reason, map[string]string{
		pop3ObsFieldMechanism: safePOP3Mechanism(mechanism),
	})
}

// recordNauthilusAuth emits one authority-auth observation.
func (s *Session) recordNauthilusAuth(ctx context.Context, result string, reason string, mechanism string, duration time.Duration) {
	s.recordObservation(ctx, observability.EventNauthilusAuth, observability.TraceBoundaryNauthilusAuth, pop3ObservationOperationAuthenticate, result, reason, map[string]string{
		pop3ObsFieldMechanism: safePOP3Mechanism(mechanism),
		pop3ObsFieldTransport: strings.ToLower(strings.TrimSpace(s.authorityTransport)),
	}, duration)
}

// recordRoutingResolve emits one director-owned routing observation.
func (s *Session) recordRoutingResolve(ctx context.Context, result string, reason string, source string, shardTag string, duration time.Duration) {
	s.recordObservation(ctx, observability.EventRoutingResolve, observability.TraceBoundaryRoutingResolve, pop3ObservationOperationRouting, result, reason, map[string]string{
		pop3ObsFieldRoutingSource: strings.TrimSpace(source),
		pop3ObsFieldShardTag:      strings.TrimSpace(shardTag),
	}, duration)
}

// recordPlacementGate emits user-hold gate results around placement.
func (s *Session) recordPlacementGate(ctx context.Context, result string, reason string) {
	s.recordObservation(ctx, observability.EventUserHold, observability.TraceBoundaryBackendSelect, pop3ObservationOperationHoldWait, result, reason, nil)
}

// recordAffinityOpen emits the Redis-backed session-open observation.
func (s *Session) recordAffinityOpen(ctx context.Context, result string, reason string, source string, shardTag string, backendNode string) {
	s.recordObservation(ctx, observability.EventAffinityOpen, observability.TraceBoundaryRoutingResolve, "affinity_open", result, reason, map[string]string{
		pop3ObsFieldAffinitySource: strings.TrimSpace(source),
		pop3ObsFieldBackendNode:    strings.TrimSpace(backendNode),
		pop3ObsFieldShardTag:       strings.TrimSpace(shardTag),
	})
}

// recordSessionAttach emits selected-backend attachment observations.
func (s *Session) recordSessionAttach(ctx context.Context, result string, reason string, backendID string, backendNode string, shardTag string) {
	s.recordObservation(ctx, observability.EventSessionAttach, observability.TraceBoundaryBackendSelect, pop3ObservationOperationSessionAttach, result, reason, map[string]string{
		pop3ObsFieldBackendIdentifier: strings.TrimSpace(backendID),
		pop3ObsFieldBackendNode:       strings.TrimSpace(backendNode),
		pop3ObsFieldShardTag:          strings.TrimSpace(shardTag),
	})
}

// recordSessionClose emits Redis lease closure observations.
func (s *Session) recordSessionClose(ctx context.Context, result string, reason string) {
	s.recordObservation(ctx, observability.EventSessionClose, observability.TraceBoundarySession, pop3ObservationOperationSessionClose, result, reason, nil)
}

// recordBackendSelect emits backend selection observations.
func (s *Session) recordBackendSelect(ctx context.Context, result string, reason string, shardTag string, backendNode string, duration time.Duration) {
	s.recordObservation(ctx, observability.EventBackendSelect, observability.TraceBoundaryBackendSelect, pop3ObservationOperationBackendSelect, result, reason, map[string]string{
		pop3ObsFieldBackendNode: strings.TrimSpace(backendNode),
		pop3ObsFieldShardTag:    strings.TrimSpace(shardTag),
	}, duration)
}

// recordBackendConnect emits one backend connection observation.
func (s *Session) recordBackendConnect(ctx context.Context, result string, reason string, duration time.Duration) {
	s.recordObservation(ctx, observability.EventBackendConnect, observability.TraceBoundaryBackendConnect, pop3ObservationOperationBackendConn, result, reason, nil, duration)
}

// recordBackendAuth emits one backend authentication observation.
func (s *Session) recordBackendAuth(ctx context.Context, result string, reason string, mechanism string) {
	s.recordObservation(ctx, observability.EventBackendAuth, observability.TraceBoundaryBackendConnect, pop3ObservationOperationBackendAuth, result, reason, map[string]string{
		pop3ObsFieldMechanism: safePOP3Mechanism(mechanism),
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
		pop3ObsFieldBackendPool: s.backendPool,
		pop3ObsFieldListener:    s.listenerName,
		pop3ObsFieldOperation:   operation,
		pop3ObsFieldProtocol:    ProtocolPOP3,
		pop3ObsFieldRemoteAddr:  safePOP3AddrString(s.conn.RemoteAddr()),
		pop3ObsFieldResult:      result,
		pop3ObsFieldService:     s.serviceName,
		pop3ObsFieldSessionID:   s.sessionID,
		pop3ObsFieldTLSMode:     s.tlsMode,
	}

	if reason != "" {
		fields[pop3ObsFieldReasonClass] = reason
	}

	if s.placed {
		fields[pop3ObsFieldBackendIdentifier] = s.placement.Backend.Backend.Identifier
		fields[pop3ObsFieldBackendNode] = s.placement.Backend.Backend.BackendNode
		fields[pop3ObsFieldShardTag] = s.placement.SelectedShardTag
	}

	return fields
}

// observationLabels returns low-cardinality labels that must pass the allowlist.
func (s *Session) observationLabels(operation string, result string, reason string, extraFields map[string]string) map[string]string {
	labels := map[string]string{
		pop3ObsFieldBackendPool: s.backendPool,
		pop3ObsFieldListener:    s.listenerName,
		pop3ObsFieldOperation:   operation,
		pop3ObsFieldProtocol:    ProtocolPOP3,
		pop3ObsFieldResult:      result,
		pop3ObsFieldService:     s.serviceName,
		pop3ObsFieldTLSMode:     s.tlsMode,
	}

	if transport := strings.ToLower(strings.TrimSpace(s.authorityTransport)); transport != "" {
		labels[pop3ObsFieldTransport] = transport
	}

	if mechanism := safePOP3Mechanism(extraFields[pop3ObsFieldMechanism]); mechanism != "" {
		labels[pop3ObsFieldMechanism] = mechanism
	}

	if reason != "" {
		labels[pop3ObsFieldReasonClass] = reason
	}

	if shardTag := strings.TrimSpace(extraFields[pop3ObsFieldShardTag]); shardTag != "" {
		labels[pop3ObsFieldShardTag] = shardTag
	} else if s.placed && s.placement.SelectedShardTag != "" {
		labels[pop3ObsFieldShardTag] = s.placement.SelectedShardTag
	}

	return labels
}

// pop3ResultLabel turns an error into a bounded result value.
func pop3ResultLabel(err error) string {
	if err != nil {
		return pop3ObservationResultFailure
	}

	return pop3ObservationResultOK
}

// pop3ReasonClass classifies errors without exposing raw error text.
func pop3ReasonClass(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded), errors.Is(err, errSASLCancelled):
		return pop3ReasonCanceled
	case proxy.IsControlActionError(err):
		return pop3ReasonControlAction
	case errors.Is(err, ErrBackendAuth), errors.Is(err, ErrBackendAuthPolicy):
		return pop3ReasonBackendAuth
	case backend.IsTransportReason(err, backend.TransportReasonWriteFailed):
		return pop3ReasonBackendProxyWrite
	case backend.IsTransportReason(err, backend.TransportReasonMissingAddress):
		return pop3ReasonBackendProxyMissing
	case backend.IsTransportReason(err, backend.TransportReasonUnsupportedFamily):
		return pop3ReasonBackendProxyFamily
	case backend.IsTransportReason(err, backend.TransportReasonConfig):
		return pop3ReasonBackendProxyConfig
	case errors.Is(err, ErrBackendConnect), errors.Is(err, ErrBackendTLS), errors.Is(err, ErrBackendProtocol):
		return pop3ReasonBackendConnect
	case errors.Is(err, ErrBackendReadinessUnavailable):
		return pop3ReasonTemporaryFailure
	case errors.Is(err, saslcred.ErrRejected), errors.Is(err, saslcred.ErrTooLarge):
		return pop3ReasonCredentialInput
	case errors.Is(err, ErrMalformedCommand), errors.Is(err, ErrPreauthLineTooLarge), errors.Is(err, ErrPreauthPartialCommand):
		return pop3ReasonParser
	case errors.Is(err, ErrPreauthLiteralTooLarge):
		return pop3ReasonLiteral
	case errors.Is(err, saslcred.ErrUnsupportedMechanism), errors.Is(err, ErrUnsupportedCommand):
		return pop3ReasonUnsupported
	case placement.IsErrorKind(err, placement.ErrorKindBackendNodeMissingProtocol):
		return string(placement.ErrorKindBackendNodeMissingProtocol)
	case placement.IsErrorKind(err, placement.ErrorKindBackendNodeMismatch):
		return string(placement.ErrorKindBackendNodeMismatch)
	case placement.IsErrorKind(err, placement.ErrorKindBackendNodeUnusable):
		return string(placement.ErrorKindBackendNodeUnusable)
	case runtimectl.IsErrorKind(err, runtimectl.ErrorKindUnavailable):
		return pop3ReasonTemporaryFailure
	default:
		return pop3ReasonProtocol
	}
}

// pop3CloseReasonClass maps successful lease close state into retention classes.
func pop3CloseReasonClass(err error, record state.AffinityRecord) string {
	if err != nil {
		return pop3ReasonClass(err)
	}

	switch record.BindingStatus {
	case state.BindingStatusRetained:
		return pop3ReasonBindingRetained
	case state.BindingStatusExpired:
		return pop3ReasonBindingExpired
	default:
		if record.ActiveHolderCount == 0 && !record.RetentionExpiresAt.IsZero() {
			return pop3ReasonBindingRetained
		}

		return pop3ReasonOK
	}
}

// pop3HoldGateObservation maps placement-gate results into bounded outcomes.
func pop3HoldGateObservation(result runtimectl.PlacementGateResult, err error) (string, string) {
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "wait timeout") {
			return pop3ObservationResultFailure, pop3ReasonUserHoldWaitTimeout
		}

		return pop3ObservationResultFailure, pop3ReasonTemporaryFailure
	}

	if result.Outcome == runtimectl.PlacementGateOutcomeReleased || result.RuntimeStateRecheckRequired {
		return pop3ObservationResultWaitReleased, pop3ReasonUserHoldWaitReleased
	}

	return pop3ObservationResultOK, pop3ReasonOK
}

// safePOP3Command returns only bounded authorization-state command tokens.
func safePOP3Command(command string) string {
	switch strings.ToUpper(strings.TrimSpace(command)) {
	case commandAuth:
		return strings.ToLower(commandAuth)
	case commandCapa:
		return strings.ToLower(commandCapa)
	case commandNoop:
		return strings.ToLower(commandNoop)
	case commandPass:
		return strings.ToLower(commandPass)
	case commandQuit:
		return strings.ToLower(commandQuit)
	case commandSTLS:
		return strings.ToLower(commandSTLS)
	case commandUser:
		return strings.ToLower(commandUser)
	case "parse":
		return "parse"
	default:
		return "unknown"
	}
}

// safePOP3Mechanism keeps auth labels bounded to implemented mechanisms.
func safePOP3Mechanism(mechanism string) string {
	switch strings.ToLower(strings.TrimSpace(mechanism)) {
	case "":
		return ""
	case authMethodUserPass:
		return authMethodUserPass
	case saslcred.MechanismXOAUTH2:
		return saslcred.MechanismXOAUTH2
	case saslcred.MechanismOAuthBearer:
		return saslcred.MechanismOAuthBearer
	default:
		return "unknown"
	}
}

// safePOP3AddrString returns address text only for sanitizer collapse into presence.
func safePOP3AddrString(addr interface{ String() string }) string {
	if addr == nil {
		return ""
	}

	return addr.String()
}
