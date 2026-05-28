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

package lmtp

import (
	"context"
	"errors"
	"maps"
	"net"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/observability"
)

const (
	lmtpObservationOperationBackendAuth      = "backend_auth"
	lmtpObservationOperationBackendConnect   = "backend_connect"
	lmtpObservationOperationBackendSelect    = "backend_select"
	lmtpObservationOperationBDATChunk        = "bdat_chunk"
	lmtpObservationOperationBDATComplete     = "bdat_complete"
	lmtpObservationOperationDATA             = "data"
	lmtpObservationOperationLHLO             = "lhlo"
	lmtpObservationOperationMAIL             = "mail"
	lmtpObservationOperationPeerAuth         = "peer_auth"
	lmtpObservationOperationRecipientRoute   = "recipient_route"
	lmtpObservationOperationRecipientStatus  = "recipient_status"
	lmtpObservationOperationRSET             = "rset"
	lmtpObservationOperationRouting          = "routing"
	lmtpObservationOperationSameBackend      = "same_backend_policy"
	lmtpObservationOperationSession          = "session"
	lmtpObservationOperationSTARTTLS         = "starttls"
	lmtpObservationOperationTransaction      = "transaction"
	lmtpObservationOperationTransactionReset = "transaction_reset"

	lmtpObservationResultAccepted = "accepted"
	lmtpObservationResultFailure  = "failure"
	lmtpObservationResultOK       = "ok"
	lmtpObservationResultRejected = "rejected"
	lmtpObservationResultStart    = "start"
	lmtpObservationResultTempfail = "tempfail"

	lmtpReasonAuth             = "auth"
	lmtpReasonBackendAuth      = "backend_auth_failed"
	lmtpReasonBackendConnect   = "backend_connect"
	lmtpReasonBackendStatus    = "backend_status"
	lmtpReasonBDAT             = "bdat"
	lmtpReasonCanceled         = "canceled"
	lmtpReasonCredentialInput  = "credential_input"
	lmtpReasonDATA             = "data"
	lmtpReasonMalformed        = "malformed"
	lmtpReasonOK               = "ok"
	lmtpReasonParser           = "parser"
	lmtpReasonProtocol         = "protocol"
	lmtpReasonRejected         = "rejected"
	lmtpReasonRouting          = "routing"
	lmtpReasonSameBackend      = "same_backend"
	lmtpReasonState            = "state_failed"
	lmtpReasonTemporaryFailure = "temporary_failure"
	lmtpReasonUnsupported      = "unsupported"

	lmtpStatusClass2xx     = "2xx"
	lmtpStatusClass4xx     = "4xx"
	lmtpStatusClass5xx     = "5xx"
	lmtpStatusClassUnknown = "unknown"
)

const (
	lmtpObsFieldBackendIdentifier = "backend_identifier"
	lmtpObsFieldBackendPool       = "backend_pool"
	lmtpObsFieldListener          = "listener"
	lmtpObsFieldMechanism         = "mechanism"
	lmtpObsFieldOperation         = "operation"
	lmtpObsFieldProtocol          = "protocol"
	lmtpObsFieldReasonClass       = "reason_class"
	lmtpObsFieldRemoteAddr        = "remote_addr"
	lmtpObsFieldResult            = "result"
	lmtpObsFieldService           = "service"
	lmtpObsFieldShardTag          = "shard_tag"
	lmtpObsFieldStatusClass       = "status_class"
	lmtpObsFieldTLSMode           = "tls_mode"
	lmtpObsFieldTransport         = "transport"
)

// recordSessionStart emits the first accepted LMTP session observation.
func (s *Session) recordSessionStart(ctx context.Context) {
	s.recordObservation(ctx, observability.EventSessionStart, observability.TraceBoundarySession, lmtpObservationOperationSession, lmtpObservationResultStart, "", nil)
}

// recordSessionEnd emits the terminal accepted LMTP session observation.
func (s *Session) recordSessionEnd(ctx context.Context, err error) {
	s.recordObservation(ctx, observability.EventSessionEnd, observability.TraceBoundarySession, lmtpObservationOperationSession, lmtpResultLabel(err), lmtpReasonClass(err), nil)
}

// recordCommand emits a command-level observation without transcript content.
func (s *Session) recordCommand(ctx context.Context, operation string, result string, reason string, extraFields map[string]string) {
	boundary := observability.TraceBoundary("")
	if s.transaction.observed {
		boundary = observability.TraceBoundaryLMTPTransaction
	}

	s.recordObservation(ctx, observability.EventLMTPCommand, boundary, operation, result, reason, extraFields)
}

// recordPeerAuth emits a bounded peer-auth command observation.
func (s *Session) recordPeerAuth(ctx context.Context, result string, reason string, mechanism string) {
	s.recordCommand(ctx, lmtpObservationOperationPeerAuth, result, reason, map[string]string{
		lmtpObsFieldMechanism: strings.ToLower(strings.TrimSpace(mechanism)),
	})
}

// recordAuthorityLookup emits a bounded Nauthilus no-auth recipient lookup observation.
func (s *Session) recordAuthorityLookup(ctx context.Context, result string, reason string, duration time.Duration) {
	s.recordObservation(ctx, observability.EventNauthilusAuth, observability.TraceBoundaryNauthilusAuth, recipientLookupMethod, result, reason, map[string]string{
		lmtpObsFieldMechanism: recipientLookupMethod,
		lmtpObsFieldTransport: strings.ToLower(strings.TrimSpace(s.authorityTransport)),
	}, duration)
}

// recordRoutingResolve emits one director-owned recipient routing observation.
func (s *Session) recordRoutingResolve(ctx context.Context, result string, reason string, shardTag string, duration time.Duration) {
	s.recordObservation(ctx, observability.EventRoutingResolve, observability.TraceBoundaryRoutingResolve, lmtpObservationOperationRouting, result, reason, map[string]string{
		lmtpObsFieldShardTag: strings.TrimSpace(shardTag),
	}, duration)
}

// recordBackendSelect emits a backend-selection observation for recipient placement.
func (s *Session) recordBackendSelect(ctx context.Context, result string, reason string, shardTag string, duration time.Duration) {
	s.recordObservation(ctx, observability.EventBackendSelect, observability.TraceBoundaryBackendSelect, lmtpObservationOperationBackendSelect, result, reason, map[string]string{
		lmtpObsFieldShardTag: strings.TrimSpace(shardTag),
	}, duration)
}

// recordRecipientRoute emits one per-recipient routing result without the raw recipient.
func (s *Session) recordRecipientRoute(ctx context.Context, result string, reason string, shardTag string) {
	s.recordObservation(ctx, observability.EventLMTPRecipientRoute, observability.TraceBoundaryRoutingResolve, lmtpObservationOperationRecipientRoute, result, reason, map[string]string{
		lmtpObsFieldShardTag: strings.TrimSpace(shardTag),
	})
}

// recordSameBackendPolicy emits a same-backend-only transaction rejection.
func (s *Session) recordSameBackendPolicy(ctx context.Context, shardTag string) {
	s.recordObservation(ctx, observability.EventLMTPSameBackendPolicy, observability.TraceBoundaryBackendSelect, lmtpObservationOperationSameBackend, lmtpObservationResultTempfail, lmtpReasonSameBackend, map[string]string{
		lmtpObsFieldShardTag: strings.TrimSpace(shardTag),
	})
}

// recordBackendConnect emits one backend connect observation.
func (s *Session) recordBackendConnect(ctx context.Context, result string, reason string, backendID string, shardTag string, duration time.Duration) {
	s.recordObservation(ctx, observability.EventBackendConnect, observability.TraceBoundaryBackendConnect, lmtpObservationOperationBackendConnect, result, reason, map[string]string{
		lmtpObsFieldBackendIdentifier: strings.TrimSpace(backendID),
		lmtpObsFieldShardTag:          strings.TrimSpace(shardTag),
	}, duration)
}

// recordBackendAuth emits one backend authentication observation.
func (s *Session) recordBackendAuth(ctx context.Context, result string, reason string, mechanism string, backendID string, shardTag string) {
	s.recordObservation(ctx, observability.EventBackendAuth, observability.TraceBoundaryBackendConnect, lmtpObservationOperationBackendAuth, result, reason, map[string]string{
		lmtpObsFieldBackendIdentifier: strings.TrimSpace(backendID),
		lmtpObsFieldMechanism:         strings.ToLower(strings.TrimSpace(mechanism)),
		lmtpObsFieldShardTag:          strings.TrimSpace(shardTag),
	})
}

// recordDATAStream emits DATA forwarding completion metrics and events.
func (s *Session) recordDATAStream(ctx context.Context, result string, reason string, statusClass string, duration time.Duration) {
	s.recordObservation(ctx, observability.EventLMTPDataStream, observability.TraceBoundaryLMTPTransaction, lmtpObservationOperationDATA, result, reason, map[string]string{
		lmtpObsFieldStatusClass: normalizeStatusClass(statusClass),
	}, duration)
}

// recordBDATStream emits BDAT chunk or completion forwarding metrics and events.
func (s *Session) recordBDATStream(ctx context.Context, operation string, result string, reason string, statusClass string, duration time.Duration) {
	s.recordObservation(ctx, observability.EventLMTPBDATStream, observability.TraceBoundaryLMTPTransaction, operation, result, reason, map[string]string{
		lmtpObsFieldStatusClass: normalizeStatusClass(statusClass),
	}, duration)
}

// recordDeliveryStatuses emits status-class observations for all frontend final replies.
func (s *Session) recordDeliveryStatuses(ctx context.Context, result MessageResult) {
	statuses := deliveryStatusesForObservation(result, s.transaction.recipientCount)
	for _, status := range statuses {
		resultLabel, reasonClass := deliveryStatusObservation(status)
		statusClass := statusClass(status.Status)

		s.recordObservation(ctx, observability.EventLMTPRecipientStatus, observability.TraceBoundaryLMTPTransaction, lmtpObservationOperationRecipientStatus, resultLabel, reasonClass, map[string]string{
			lmtpObsFieldStatusClass: statusClass,
		})
		s.recordObservation(ctx, observability.EventLMTPBackendStatus, observability.TraceBoundaryBackendConnect, lmtpObservationOperationRecipientStatus, resultLabel, reasonClass, map[string]string{
			lmtpObsFieldStatusClass: statusClass,
		})
	}
}

// beginTransactionObservation starts the LMTP transaction span after MAIL is accepted.
func (s *Session) beginTransactionObservation(ctx context.Context) context.Context {
	if s.transaction.observed {
		return s.transactionContext(ctx)
	}

	fields := s.observationFields(lmtpObservationOperationTransaction, lmtpObservationResultStart, "")
	txCtx, span := s.startObservationSpan(ctx, observability.TraceBoundaryLMTPTransaction, lmtpObservationOperationTransaction, lmtpObservationResultStart, "", nil)

	s.transaction.observed = true
	s.transaction.observationContext = txCtx
	s.transaction.observationSpan = span
	s.transaction.observationStarted = time.Now()

	observability.NormalizeRecorder(s.observability).Record(txCtx, observability.Event{
		Name:      observability.EventLMTPCommand,
		SpanName:  traceSpanName(observability.TraceBoundaryLMTPTransaction),
		LogFields: observability.SanitizeLogFields(fields),
	})

	return txCtx
}

// finishTransactionObservation records and closes the active transaction span.
func (s *Session) finishTransactionObservation(ctx context.Context, result string, reason string) {
	if !s.transaction.observed {
		return
	}

	txCtx := s.transactionContext(ctx)
	duration := time.Since(s.transaction.observationStarted)
	s.recordObservation(txCtx, observability.EventLMTPTransaction, observability.TraceBoundaryLMTPTransaction, lmtpObservationOperationTransaction, result, reason, nil, duration)
	s.transaction.observationSpan.End(result, reason)
	s.transaction.observed = false
	s.transaction.observationContext = nil
	s.transaction.observationSpan = nil
	s.transaction.observationStarted = time.Time{}
}

// transactionContext returns the active transaction span context when one exists.
func (s *Session) transactionContext(ctx context.Context) context.Context {
	if s.transaction.observed && s.transaction.observationContext != nil {
		return s.transaction.observationContext
	}

	if ctx == nil {
		return context.Background()
	}

	return ctx
}

// recordTransactionReset emits reset diagnostics and terminates a partial transaction.
func (s *Session) recordTransactionReset(ctx context.Context, reason string) {
	result, reasonClass := resetObservationOutcome(reason)
	txCtx := s.transactionContext(ctx)
	s.recordCommand(txCtx, lmtpObservationOperationTransactionReset, result, reasonClass, nil)
	s.finishTransactionObservation(txCtx, result, reasonClass)
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
		lmtpObsFieldBackendPool: s.backendPool,
		lmtpObsFieldListener:    s.listenerName,
		lmtpObsFieldOperation:   operation,
		lmtpObsFieldProtocol:    protocolLMTP,
		lmtpObsFieldRemoteAddr:  addrString(s.conn.RemoteAddr()),
		lmtpObsFieldResult:      result,
		lmtpObsFieldService:     s.serviceName,
		lmtpObsFieldTLSMode:     s.tlsMode,
	}

	if reason != "" {
		fields[lmtpObsFieldReasonClass] = reason
	}

	if backendID, shardTag := s.currentBackendDiagnostics(); backendID != "" || shardTag != "" {
		fields[lmtpObsFieldBackendIdentifier] = backendID
		fields[lmtpObsFieldShardTag] = shardTag
	}

	return fields
}

// observationLabels returns low-cardinality labels that must pass the allowlist.
func (s *Session) observationLabels(operation string, result string, reason string, extraFields map[string]string) map[string]string {
	labels := map[string]string{
		lmtpObsFieldBackendPool: s.backendPool,
		lmtpObsFieldListener:    s.listenerName,
		lmtpObsFieldOperation:   operation,
		lmtpObsFieldProtocol:    protocolLMTP,
		lmtpObsFieldResult:      result,
		lmtpObsFieldService:     s.serviceName,
		lmtpObsFieldTLSMode:     s.tlsMode,
	}

	if transport := strings.ToLower(strings.TrimSpace(s.authorityTransport)); transport != "" {
		labels[lmtpObsFieldTransport] = transport
	}

	if mechanism := strings.ToLower(strings.TrimSpace(extraFields[lmtpObsFieldMechanism])); mechanism != "" {
		labels[lmtpObsFieldMechanism] = mechanism
	}

	if reason != "" {
		labels[lmtpObsFieldReasonClass] = reason
	}

	if shardTag := strings.TrimSpace(extraFields[lmtpObsFieldShardTag]); shardTag != "" {
		labels[lmtpObsFieldShardTag] = shardTag
	} else if _, currentShard := s.currentBackendDiagnostics(); currentShard != "" {
		labels[lmtpObsFieldShardTag] = currentShard
	}

	if statusClass := normalizeStatusClass(extraFields[lmtpObsFieldStatusClass]); statusClass != "" {
		labels[lmtpObsFieldStatusClass] = statusClass
	}

	return labels
}

// currentBackendDiagnostics returns bounded backend diagnostics for logs and traces.
func (s *Session) currentBackendDiagnostics() (string, string) {
	if s.transaction.backend != nil {
		return strings.TrimSpace(s.transaction.backend.target.Identifier), strings.TrimSpace(s.transaction.backend.target.ShardTag)
	}

	for _, recipient := range s.transaction.recipients {
		return strings.TrimSpace(recipient.Backend.Backend.Identifier), strings.TrimSpace(recipient.SelectedShardTag)
	}

	return "", ""
}

// lmtpResultLabel turns an error into a bounded result value.
func lmtpResultLabel(err error) string {
	if err != nil {
		return lmtpObservationResultFailure
	}

	return lmtpObservationResultOK
}

// lmtpReasonClass classifies errors without exposing raw error text.
func lmtpReasonClass(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return lmtpReasonCanceled
	case errors.Is(err, ErrBackendAuth), errors.Is(err, ErrBackendAuthPolicy):
		return lmtpReasonBackendAuth
	case errors.Is(err, ErrBackendConnect), errors.Is(err, ErrBackendTLS), errors.Is(err, ErrBackendProtocol):
		return lmtpReasonBackendConnect
	case errors.Is(err, ErrCredentialRejected), errors.Is(err, ErrCredentialTooLarge):
		return lmtpReasonCredentialInput
	case errors.Is(err, ErrMalformedRecipient), errors.Is(err, ErrLineTooLarge), errors.Is(err, ErrPartialCommand):
		return lmtpReasonParser
	case errors.Is(err, ErrUnsupportedAuthMechanism):
		return lmtpReasonUnsupported
	case errors.Is(err, errDifferentBackendRecipient):
		return lmtpReasonSameBackend
	default:
		return lmtpReasonProtocol
	}
}

// resetObservationOutcome maps internal reset reasons into bounded transaction outcomes.
func resetObservationOutcome(reason string) (string, string) {
	switch strings.ToLower(strings.TrimSpace(reason)) {
	case "", "rset", "quit", "delivery_complete":
		return lmtpObservationResultOK, lmtpReasonOK
	case "eof", "context":
		return lmtpObservationResultFailure, lmtpReasonCanceled
	case "data_stream", "data_rejected", "unknown_delivery":
		return lmtpObservationResultFailure, lmtpReasonDATA
	case "bdat_stream", "bdat_rejected":
		return lmtpObservationResultFailure, lmtpReasonBDAT
	case "read_error", "command_error":
		return lmtpObservationResultFailure, lmtpReasonParser
	default:
		return lmtpObservationResultFailure, lmtpReasonProtocol
	}
}

// deliveryStatusesForObservation returns one status per accepted recipient.
func deliveryStatusesForObservation(result MessageResult, recipientCount int) []DeliveryStatus {
	if len(result.Statuses) > 0 {
		return append([]DeliveryStatus(nil), result.Statuses...)
	}

	status := strings.TrimSpace(result.Status)
	if status == "" {
		status = responseStatusOK
	}

	if status != responseStatusOK {
		status = responseStatusTemporary
	}

	repeat := recipientCount
	if repeat <= 0 {
		repeat = 1
	}

	statuses := make([]DeliveryStatus, 0, repeat)
	for range repeat {
		statuses = append(statuses, DeliveryStatus{Status: status})
	}

	return statuses
}

// deliveryStatusObservation maps one status into bounded result and reason classes.
func deliveryStatusObservation(status DeliveryStatus) (string, string) {
	switch statusClass(status.Status) {
	case lmtpStatusClass2xx:
		return lmtpObservationResultOK, lmtpReasonOK
	case lmtpStatusClass4xx:
		return lmtpObservationResultTempfail, lmtpReasonTemporaryFailure
	case lmtpStatusClass5xx:
		return lmtpObservationResultRejected, lmtpReasonRejected
	default:
		return lmtpObservationResultFailure, lmtpReasonBackendStatus
	}
}

// deliveryResultLabel summarizes a delivery result without backend text.
func deliveryResultLabel(result MessageResult) string {
	statuses := deliveryStatusesForObservation(result, 1)
	for _, status := range statuses {
		if statusClass(status.Status) == lmtpStatusClass4xx {
			return lmtpObservationResultTempfail
		}

		if statusClass(status.Status) == lmtpStatusClass5xx {
			return lmtpObservationResultRejected
		}

		if statusClass(status.Status) == lmtpStatusClassUnknown {
			return lmtpObservationResultFailure
		}
	}

	return lmtpObservationResultOK
}

// deliveryReasonClass summarizes delivery statuses into a bounded reason class.
func deliveryReasonClass(result MessageResult) string {
	switch deliveryResultLabel(result) {
	case lmtpObservationResultOK:
		return lmtpReasonOK
	case lmtpObservationResultTempfail:
		return lmtpReasonTemporaryFailure
	case lmtpObservationResultRejected:
		return lmtpReasonRejected
	default:
		return lmtpReasonBackendStatus
	}
}

// deliveryResultStatusClass returns the highest-severity status class in a result.
func deliveryResultStatusClass(result MessageResult) string {
	statuses := deliveryStatusesForObservation(result, 1)
	statusClassValue := lmtpStatusClass2xx

	for _, status := range statuses {
		switch statusClass(status.Status) {
		case lmtpStatusClass5xx:
			return lmtpStatusClass5xx
		case lmtpStatusClass4xx:
			statusClassValue = lmtpStatusClass4xx
		case lmtpStatusClassUnknown:
			if statusClassValue == lmtpStatusClass2xx {
				statusClassValue = lmtpStatusClassUnknown
			}
		}
	}

	return statusClassValue
}

// statusClass returns a low-cardinality SMTP status-code class.
func statusClass(status string) string {
	status = strings.TrimSpace(status)
	if len(status) != 3 {
		return lmtpStatusClassUnknown
	}

	switch status[0] {
	case '2':
		return lmtpStatusClass2xx
	case '4':
		return lmtpStatusClass4xx
	case '5':
		return lmtpStatusClass5xx
	default:
		return lmtpStatusClassUnknown
	}
}

// normalizeStatusClass applies a stable fallback to status-class labels.
func normalizeStatusClass(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return lmtpStatusClassUnknown
	}

	return value
}

// addrString returns address text only so the shared policy can collapse it.
func addrString(addr net.Addr) string {
	if addr == nil {
		return ""
	}

	return addr.String()
}

// traceSpanName resolves a prepared span name for manual start-event records.
func traceSpanName(boundary observability.TraceBoundary) string {
	name, _ := observability.SpanName(boundary)

	return name
}
