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
	"io"
	"strings"
	"time"
)

// handleCommand dispatches one parsed LMTP command in wire order.
func (s *Session) handleCommand(ctx context.Context, command frontendCommand) (commandOutcome, error) {
	if command.name == commandQUIT {
		s.resetTransaction(ctx, "quit")

		return commandOutcome{closeSession: true}, s.handleQUIT(command)
	}

	if command.name != commandLHLO && !s.lhloSeen {
		return commandOutcome{}, s.writeEnhanced(responseStatusBadSequence, enhancedBadSequence, badSequenceLHLOText)
	}

	if commandSessionScoped(command.name) {
		return s.handleSessionCommand(ctx, command)
	}

	return s.handleTransactionCommand(ctx, command)
}

// commandSessionScoped reports whether a command affects connection state rather than message state.
func commandSessionScoped(name string) bool {
	switch name {
	case commandLHLO, commandSTARTTLS, commandAuth, commandRSET, commandNOOP:
		return true
	default:
		return false
	}
}

// handleSessionCommand dispatches commands that are valid outside transaction placement.
func (s *Session) handleSessionCommand(ctx context.Context, command frontendCommand) (commandOutcome, error) {
	switch command.name {
	case commandLHLO:
		return commandOutcome{}, s.handleLHLO(ctx, command)
	case commandSTARTTLS:
		return s.handleSTARTTLS(ctx, command)
	case commandAuth:
		return commandOutcome{}, s.handleAUTH(ctx, command)
	case commandRSET:
		return commandOutcome{}, s.handleRSET(ctx, command)
	case commandNOOP:
		return commandOutcome{}, s.handleNOOP(command)
	default:
		return commandOutcome{}, s.writeEnhanced(responseStatusUnavailable, enhancedUnavailable, unsupportedText)
	}
}

// handleTransactionCommand dispatches envelope and body commands in sequence.
func (s *Session) handleTransactionCommand(ctx context.Context, command frontendCommand) (commandOutcome, error) {
	switch command.name {
	case commandMAIL:
		return commandOutcome{}, s.handleMAIL(ctx, command)
	case commandRCPT:
		return commandOutcome{}, s.handleRCPT(ctx, command)
	case commandDATA:
		return commandOutcome{}, s.handleDATA(ctx, command)
	case commandBDAT:
		return commandOutcome{}, s.handleBDAT(ctx, command)
	default:
		return commandOutcome{}, s.writeEnhanced(responseStatusUnavailable, enhancedUnavailable, unsupportedText)
	}
}

// handleLHLO records the client greeting and advertises effective capabilities.
func (s *Session) handleLHLO(ctx context.Context, command frontendCommand) error {
	if strings.TrimSpace(command.args) == "" {
		s.recordCommand(ctx, lmtpObservationOperationLHLO, lmtpObservationResultFailure, lmtpReasonParser, nil)

		return s.writeEnhanced(responseStatusParameter, enhancedParameter, "Invalid LHLO command")
	}

	if s.transaction.active() {
		s.recordCommand(ctx, lmtpObservationOperationLHLO, lmtpObservationResultFailure, lmtpReasonProtocol, nil)

		return s.writeEnhanced(responseStatusBadSequence, enhancedBadSequence, "LHLO not allowed during transaction")
	}

	s.effectiveCapabilities = s.effectiveCapabilitySet()
	s.chunkingAdvertised = containsCapability(s.effectiveCapabilities, capabilityCHUNKING)
	s.lhloSeen = true
	s.recordCommand(ctx, lmtpObservationOperationLHLO, lmtpObservationResultOK, lmtpReasonOK, nil)

	return s.writeLHLO(s.effectiveCapabilities)
}

// handleMAIL validates MAIL FROM sequencing without retaining the raw envelope sender.
func (s *Session) handleMAIL(ctx context.Context, command frontendCommand) error {
	if err := s.requirePeerAuthSatisfied(); err != nil {
		s.recordCommand(ctx, lmtpObservationOperationMAIL, lmtpObservationResultFailure, lmtpReasonAuth, nil)

		return err
	}

	mail, err := parseMailCommand(command)
	if err != nil {
		s.recordCommand(ctx, lmtpObservationOperationMAIL, lmtpObservationResultFailure, lmtpReasonParser, nil)

		return s.writeEnhanced(responseStatusParameter, enhancedParameter, malformedMailText)
	}

	if err := s.requireMAILSMTPUTF8(mail); err != nil {
		s.recordCommand(ctx, lmtpObservationOperationMAIL, lmtpObservationResultFailure, lmtpReasonParser, nil)

		return err
	}

	if s.transaction.active() {
		s.recordCommand(ctx, lmtpObservationOperationMAIL, lmtpObservationResultFailure, lmtpReasonProtocol, nil)

		return s.writeEnhanced(responseStatusBadSequence, enhancedBadSequence, "Transaction already active")
	}

	s.transaction.mailSeen = true
	s.transaction.mailFrom = mail.wirePath
	s.transaction.smtpUTF8 = mail.smtpUTF8
	ctx = s.beginTransactionObservation(ctx)
	s.recordCommand(ctx, lmtpObservationOperationMAIL, lmtpObservationResultOK, lmtpReasonOK, nil)

	return s.writeEnhanced(responseStatusOK, enhancedOK, "Sender accepted")
}

// handleRCPT resolves and places RCPT TO before accepting the recipient.
func (s *Session) handleRCPT(ctx context.Context, command frontendCommand) error {
	ctx = s.transactionContext(ctx)

	if err := s.requirePeerAuthSatisfied(); err != nil {
		s.recordRecipientRoute(ctx, lmtpObservationResultFailure, lmtpReasonAuth, "")

		return err
	}

	if !s.transaction.mailSeen {
		s.recordRecipientRoute(ctx, lmtpObservationResultFailure, lmtpReasonProtocol, "")

		return s.writeEnhanced(responseStatusBadSequence, enhancedBadSequence, badSequenceMailText)
	}

	recipient, err := ParseRecipientCommand(command)
	if err != nil {
		s.recordRecipientRoute(ctx, lmtpObservationResultFailure, lmtpReasonParser, "")

		return s.writeEnhanced(responseStatusParameter, enhancedParameter, malformedRcptText)
	}

	if err := s.requireRecipientSMTPUTF8(recipient); err != nil {
		s.recordRecipientRoute(ctx, lmtpObservationResultFailure, lmtpReasonParser, "")

		return err
	}

	placement, err := s.handleRecipientPlacement(ctx, recipient)
	if err != nil {
		if errors.Is(err, errDifferentBackendRecipient) {
			s.recordSameBackendPolicy(ctx, "")
			s.recordRecipientRoute(ctx, lmtpObservationResultTempfail, lmtpReasonSameBackend, "")

			return s.writeEnhanced(responseStatusTemporary, enhancedDifferentBackend, differentBackendText)
		}

		s.recordRecipientRoute(ctx, lmtpObservationResultTempfail, lmtpReasonRouting, "")

		return s.writeEnhanced(responseStatusTemporary, enhancedTemporary, recipientLookupText)
	}

	if s.backendForwardingEnabled() {
		status, accepted := s.forwardRecipientToBackend(ctx, placement)
		if !accepted {
			_ = s.closeRecipientPlacement(ctx, &placement)
			s.recordRecipientRoute(ctx, lmtpObservationResultTempfail, lmtpReasonBackendStatus, placement.SelectedShardTag)
			s.recordDeliveryStatuses(ctx, MessageResult{Statuses: []DeliveryStatus{status}})

			return s.writeDeliveryStatus(status)
		}
	}

	s.transaction.recipientCount++
	s.transaction.recipients = append(s.transaction.recipients, placement)
	s.recordRecipientRoute(ctx, lmtpObservationResultAccepted, lmtpReasonOK, placement.SelectedShardTag)

	return s.writeEnhanced(responseStatusOK, enhancedOK, "Recipient accepted")
}

// handleDATA streams DATA lines until the dot terminator without buffering the whole body.
func (s *Session) handleDATA(ctx context.Context, command frontendCommand) error {
	ctx = s.transactionContext(ctx)
	started := time.Now()

	if err := s.requireMessageBodyAllowed(command); err != nil {
		s.recordDATAStream(ctx, lmtpObservationResultFailure, lmtpReasonProtocol, lmtpStatusClassUnknown, time.Since(started))

		return err
	}

	s.recordCommand(ctx, lmtpObservationOperationDATA, lmtpObservationResultStart, lmtpReasonOK, nil)

	if s.backendForwardingEnabled() {
		return s.handleBackendDATA(ctx)
	}

	body, err := s.messageSink.OpenMessage(ctx, s.transaction.snapshot())
	if err != nil {
		s.recordDATAStream(ctx, lmtpObservationResultFailure, lmtpReasonDATA, statusClass(responseStatusTemporary), time.Since(started))

		return s.writeEnhanced(responseStatusTemporary, enhancedTemporary, "Message sink unavailable")
	}

	if err := s.writeEnhanced(responseStatusDataContinue, enhancedOK, dataContinueText); err != nil {
		_ = body.Abort(ctx, "write_error")

		return err
	}

	if err := s.writer.Flush(); err != nil {
		_ = body.Abort(ctx, "flush_error")
		s.recordDATAStream(ctx, lmtpObservationResultFailure, lmtpReasonDATA, lmtpStatusClassUnknown, time.Since(started))

		return err
	}

	writeFailed, err := s.streamDATA(ctx, body)
	if err != nil {
		_ = body.Abort(ctx, "data_stream")
		s.recordDATAStream(ctx, lmtpObservationResultFailure, lmtpReasonDATA, lmtpStatusClassUnknown, time.Since(started))

		return err
	}

	if writeFailed {
		_ = body.Abort(ctx, "data_stream")
		s.recordDATAStream(ctx, lmtpObservationResultFailure, lmtpReasonDATA, statusClass(responseStatusTemporary), time.Since(started))

		return s.finishUnknownDelivery(ctx)
	}

	result, err := body.Finish(ctx)
	if err != nil {
		s.recordDATAStream(ctx, lmtpObservationResultFailure, lmtpReasonDATA, statusClass(responseStatusTemporary), time.Since(started))

		return s.finishUnknownDelivery(ctx)
	}

	s.recordDATAStream(ctx, deliveryResultLabel(result), deliveryReasonClass(result), deliveryResultStatusClass(result), time.Since(started))

	return s.finishKnownDelivery(ctx, result)
}

// handleBDAT streams an exact byte-counted chunk and honors LAST as completion.
func (s *Session) handleBDAT(ctx context.Context, command frontendCommand) error {
	ctx = s.transactionContext(ctx)
	started := time.Now()

	if err := s.requireBDATAllowed(command); err != nil {
		s.recordBDATStream(ctx, lmtpObservationOperationBDATChunk, lmtpObservationResultFailure, lmtpReasonProtocol, lmtpStatusClassUnknown, time.Since(started))

		return err
	}

	bdat, err := parseBDATCommand(command)
	if err != nil {
		s.recordBDATStream(ctx, lmtpObservationOperationBDATChunk, lmtpObservationResultFailure, lmtpReasonParser, lmtpStatusClassUnknown, time.Since(started))

		return s.writeEnhanced(responseStatusParameter, enhancedParameter, malformedBDATText)
	}

	if s.backendForwardingEnabled() {
		return s.handleBackendBDAT(ctx, bdat)
	}

	if s.transaction.body == nil {
		body, err := s.messageSink.OpenMessage(ctx, s.transaction.snapshot())
		if err != nil {
			s.recordBDATStream(ctx, lmtpObservationOperationBDATChunk, lmtpObservationResultFailure, lmtpReasonBDAT, statusClass(responseStatusTemporary), time.Since(started))

			return s.writeEnhanced(responseStatusTemporary, enhancedTemporary, "Message sink unavailable")
		}

		s.transaction.body = body
	}

	if err := s.copyBDATChunk(s.transaction.body, bdat.size); err != nil {
		_ = s.abortActiveBody(ctx, "bdat_stream")
		s.recordBDATStream(ctx, lmtpObservationOperationBDATChunk, lmtpObservationResultFailure, lmtpReasonBDAT, lmtpStatusClassUnknown, time.Since(started))

		return err
	}

	if !bdat.last {
		s.recordBDATStream(ctx, lmtpObservationOperationBDATChunk, lmtpObservationResultOK, lmtpReasonOK, statusClass(responseStatusOK), time.Since(started))

		return s.writeEnhanced(responseStatusOK, enhancedOK, bdatChunkAcceptedText)
	}

	body := s.transaction.body
	s.transaction.body = nil

	result, err := body.Finish(ctx)
	if err != nil {
		s.recordBDATStream(ctx, lmtpObservationOperationBDATComplete, lmtpObservationResultFailure, lmtpReasonBDAT, statusClass(responseStatusTemporary), time.Since(started))

		return s.finishUnknownDelivery(ctx)
	}

	s.recordBDATStream(ctx, lmtpObservationOperationBDATComplete, deliveryResultLabel(result), deliveryReasonClass(result), deliveryResultStatusClass(result), time.Since(started))

	return s.finishKnownDelivery(ctx, result)
}

// handleRSET clears the active transaction and aborts any open streaming body.
func (s *Session) handleRSET(ctx context.Context, command frontendCommand) error {
	if err := validateNoArguments(command); err != nil {
		return s.writeEnhanced(responseStatusParameter, enhancedParameter, "Invalid RSET command")
	}

	s.resetTransaction(ctx, "rset")
	s.recordCommand(ctx, lmtpObservationOperationRSET, lmtpObservationResultOK, lmtpReasonOK, nil)

	return s.writeEnhanced(responseStatusOK, enhancedOK, rsetText)
}

// handleNOOP accepts NOOP without mutating transaction state.
func (s *Session) handleNOOP(command frontendCommand) error {
	if err := validateNoArguments(command); err != nil {
		return s.writeEnhanced(responseStatusParameter, enhancedParameter, "Invalid NOOP command")
	}

	return s.writeEnhanced(responseStatusOK, enhancedOK, noopText)
}

// handleQUIT emits a closing status and asks the session loop to end.
func (s *Session) handleQUIT(command frontendCommand) error {
	if err := validateNoArguments(command); err != nil {
		return s.writeEnhanced(responseStatusParameter, enhancedParameter, "Invalid QUIT command")
	}

	return s.writeEnhanced(responseStatusClosing, enhancedClosing, quitText)
}

// requirePeerAuthSatisfied enforces the configured submitter-auth policy.
func (s *Session) requirePeerAuthSatisfied() error {
	if !s.requirePeerAuth || s.peerAuthenticated {
		return nil
	}

	return s.writeEnhanced(responseStatusAuthRequired, enhancedAuthRequired, authRequiredText)
}

// requireMAILSMTPUTF8 enforces the SMTPUTF8 MAIL parameter and path policy.
func (s *Session) requireMAILSMTPUTF8(mail mailCommand) error {
	advertised := containsCapability(s.effectiveCapabilities, capabilitySMTPUTF8)
	if mail.smtpUTF8 && !advertised {
		return s.writeEnhanced(responseStatusParameter, enhancedParameter, malformedMailText)
	}

	if err := validateSMTPUTF8Path(mail.wirePath, advertised && mail.smtpUTF8); err != nil {
		return s.writeEnhanced(responseStatusParameter, enhancedParameter, malformedMailText)
	}

	return nil
}

// requireRecipientSMTPUTF8 enforces transaction-scoped SMTPUTF8 for recipient paths.
func (s *Session) requireRecipientSMTPUTF8(recipient RecipientPath) error {
	if err := validateSMTPUTF8Path(recipient.WirePath, s.transaction.smtpUTF8); err != nil {
		return s.writeEnhanced(responseStatusParameter, enhancedParameter, malformedRcptText)
	}

	return nil
}

// requireMessageBodyAllowed validates common DATA and BDAT transaction state.
func (s *Session) requireMessageBodyAllowed(command frontendCommand) error {
	if err := s.requirePeerAuthSatisfied(); err != nil {
		return err
	}

	if err := validateNoArguments(command); err != nil {
		return s.writeEnhanced(responseStatusParameter, enhancedParameter, "Invalid DATA command")
	}

	if !s.transaction.mailSeen {
		return s.writeEnhanced(responseStatusBadSequence, enhancedBadSequence, badSequenceMailText)
	}

	if s.transaction.recipientCount == 0 {
		return s.writeEnhanced(responseStatusBadSequence, enhancedBadSequence, badSequenceRecipientText)
	}

	return nil
}

// requireBDATAllowed validates BDAT-specific capability and transaction state.
func (s *Session) requireBDATAllowed(command frontendCommand) error {
	if err := s.requirePeerAuthSatisfied(); err != nil {
		return err
	}

	if !s.chunkingAdvertised {
		return s.writeEnhanced(responseStatusUnavailable, enhancedUnavailable, "BDAT is not available")
	}

	if !s.transaction.mailSeen {
		return s.writeEnhanced(responseStatusBadSequence, enhancedBadSequence, badSequenceMailText)
	}

	if s.transaction.recipientCount == 0 {
		return s.writeEnhanced(responseStatusBadSequence, enhancedBadSequence, badSequenceRecipientText)
	}

	if strings.TrimSpace(command.args) == "" {
		return s.writeEnhanced(responseStatusParameter, enhancedParameter, malformedBDATText)
	}

	return nil
}

// streamDATA copies dot-terminated DATA lines to the body sink incrementally.
func (s *Session) streamDATA(ctx context.Context, body MessageBody) (bool, error) {
	writeFailed := false

	for {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		default:
		}

		line, err := s.readLine()
		if err != nil {
			return false, err
		}

		if isDataTerminator(line) {
			return writeFailed, nil
		}

		if writeFailed {
			continue
		}

		if _, err := writeDATALine(body, line); err != nil {
			writeFailed = true
		}
	}
}

// copyBDATChunk streams exactly the announced number of bytes to the body sink.
func (s *Session) copyBDATChunk(body MessageBody, size int64) error {
	if size == 0 {
		return nil
	}

	written, err := io.CopyN(body, s.reader, size)
	if err != nil {
		return err
	}

	if written != size {
		return io.ErrUnexpectedEOF
	}

	return nil
}

// writeMessageResult maps a sink completion result to a bounded LMTP status.
func (s *Session) writeMessageResult(result MessageResult) error {
	if len(result.Statuses) > 0 {
		for _, status := range result.Statuses {
			if err := s.writeDeliveryStatus(status); err != nil {
				return err
			}
		}

		return nil
	}

	status := strings.TrimSpace(result.Status)
	if status == "" {
		status = responseStatusOK
	}

	text := strings.TrimSpace(result.Text)
	if status != responseStatusOK {
		if text == "" {
			text = backendDeliveryTemporaryText
		}

		return s.writeRepeatedDeliveryStatus(DeliveryStatus{Status: responseStatusTemporary, Enhanced: enhancedTemporary, Text: text})
	}

	if text == "" {
		text = dataQueuedText
	}

	return s.writeRepeatedDeliveryStatus(DeliveryStatus{Status: responseStatusOK, Enhanced: enhancedOK, Text: text})
}

// writeRepeatedDeliveryStatus writes a single sink result once per accepted recipient.
func (s *Session) writeRepeatedDeliveryStatus(status DeliveryStatus) error {
	repeat := s.transaction.recipientCount
	if repeat <= 0 {
		repeat = 1
	}

	for range repeat {
		if err := s.writeDeliveryStatus(status); err != nil {
			return err
		}
	}

	return nil
}

// isDataTerminator reports whether a line is the DATA completion boundary.
func isDataTerminator(line []byte) bool {
	return string(line) == ".\r\n" || string(line) == ".\n"
}

// unescapeDataLine removes DATA dot-stuffing while preserving opaque content bytes.
func unescapeDataLine(line []byte) []byte {
	if len(line) == 0 || line[0] != '.' {
		return line
	}

	return line[1:]
}

// containsCapability reports whether the advertised set contains a wire capability.
func containsCapability(capabilities []string, capability string) bool {
	for _, current := range capabilities {
		if strings.EqualFold(current, capability) {
			return true
		}
	}

	return false
}
