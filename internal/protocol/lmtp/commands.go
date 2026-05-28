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
)

// handleCommand dispatches one parsed LMTP command in wire order.
func (s *Session) handleCommand(ctx context.Context, command frontendCommand) (commandOutcome, error) {
	if command.name == commandQUIT {
		s.closeTransactionHolds(ctx)
		s.transaction.reset()

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
		return commandOutcome{}, s.handleLHLO(command)
	case commandSTARTTLS:
		return s.handleSTARTTLS(command)
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
		return commandOutcome{}, s.handleMAIL(command)
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
func (s *Session) handleLHLO(command frontendCommand) error {
	if strings.TrimSpace(command.args) == "" {
		return s.writeEnhanced(responseStatusParameter, enhancedParameter, "Invalid LHLO command")
	}

	if s.transaction.active() {
		return s.writeEnhanced(responseStatusBadSequence, enhancedBadSequence, "LHLO not allowed during transaction")
	}

	s.effectiveCapabilities = s.effectiveCapabilitySet()
	s.chunkingAdvertised = containsCapability(s.effectiveCapabilities, capabilityCHUNKING)
	s.lhloSeen = true

	return s.writeLHLO(s.effectiveCapabilities)
}

// handleMAIL validates MAIL FROM sequencing without retaining the raw envelope sender.
func (s *Session) handleMAIL(command frontendCommand) error {
	if err := s.requirePeerAuthSatisfied(); err != nil {
		return err
	}

	if err := parsePathCommand(command, "FROM:"); err != nil {
		return s.writeEnhanced(responseStatusParameter, enhancedParameter, malformedMailText)
	}

	if s.transaction.active() {
		return s.writeEnhanced(responseStatusBadSequence, enhancedBadSequence, "Transaction already active")
	}

	s.transaction.mailSeen = true

	return s.writeEnhanced(responseStatusOK, enhancedOK, "Sender accepted")
}

// handleRCPT resolves and places RCPT TO before accepting the recipient.
func (s *Session) handleRCPT(ctx context.Context, command frontendCommand) error {
	if err := s.requirePeerAuthSatisfied(); err != nil {
		return err
	}

	if !s.transaction.mailSeen {
		return s.writeEnhanced(responseStatusBadSequence, enhancedBadSequence, badSequenceMailText)
	}

	recipient, err := ParseRecipientCommand(command)
	if err != nil {
		return s.writeEnhanced(responseStatusParameter, enhancedParameter, malformedRcptText)
	}

	placement, err := s.handleRecipientPlacement(ctx, recipient)
	if err != nil {
		if errors.Is(err, errDifferentBackendRecipient) {
			return s.writeEnhanced(responseStatusTemporary, enhancedDifferentBackend, differentBackendText)
		}

		return s.writeEnhanced(responseStatusTemporary, enhancedTemporary, recipientLookupText)
	}

	s.transaction.recipientCount++
	s.transaction.recipients = append(s.transaction.recipients, placement)

	return s.writeEnhanced(responseStatusOK, enhancedOK, "Recipient accepted")
}

// handleDATA streams DATA lines until the dot terminator without buffering the whole body.
func (s *Session) handleDATA(ctx context.Context, command frontendCommand) error {
	if err := s.requireMessageBodyAllowed(command); err != nil {
		return err
	}

	body, err := s.messageSink.OpenMessage(ctx, s.transaction.snapshot())
	if err != nil {
		return s.writeEnhanced(responseStatusTemporary, enhancedTemporary, "Message sink unavailable")
	}

	if err := s.writeEnhanced(responseStatusDataContinue, enhancedOK, dataContinueText); err != nil {
		_ = body.Abort(ctx, "write_error")

		return err
	}

	if err := s.writer.Flush(); err != nil {
		_ = body.Abort(ctx, "flush_error")

		return err
	}

	if err := s.streamDATA(ctx, body); err != nil {
		_ = body.Abort(ctx, "data_stream")

		return err
	}

	result, err := body.Finish(ctx)
	if err != nil {
		s.closeTransactionHolds(ctx)
		s.transaction.reset()

		return s.writeEnhanced(responseStatusTemporary, enhancedTemporary, "Message delivery temporarily failed")
	}

	s.closeTransactionHolds(ctx)
	s.transaction.reset()

	return s.writeMessageResult(result)
}

// handleBDAT streams an exact byte-counted chunk and honors LAST as completion.
func (s *Session) handleBDAT(ctx context.Context, command frontendCommand) error {
	if err := s.requireBDATAllowed(command); err != nil {
		return err
	}

	bdat, err := parseBDATCommand(command)
	if err != nil {
		return s.writeEnhanced(responseStatusParameter, enhancedParameter, malformedBDATText)
	}

	if s.transaction.body == nil {
		body, err := s.messageSink.OpenMessage(ctx, s.transaction.snapshot())
		if err != nil {
			return s.writeEnhanced(responseStatusTemporary, enhancedTemporary, "Message sink unavailable")
		}

		s.transaction.body = body
	}

	if err := s.copyBDATChunk(s.transaction.body, bdat.size); err != nil {
		_ = s.abortActiveBody(ctx, "bdat_stream")

		return err
	}

	if !bdat.last {
		return s.writeEnhanced(responseStatusOK, enhancedOK, bdatChunkAcceptedText)
	}

	body := s.transaction.body
	s.transaction.body = nil

	result, err := body.Finish(ctx)
	if err != nil {
		s.closeTransactionHolds(ctx)
		s.transaction.reset()

		return s.writeEnhanced(responseStatusTemporary, enhancedTemporary, "Message delivery temporarily failed")
	}

	s.closeTransactionHolds(ctx)
	s.transaction.reset()

	return s.writeMessageResult(result)
}

// handleRSET clears the active transaction and aborts any open streaming body.
func (s *Session) handleRSET(ctx context.Context, command frontendCommand) error {
	if err := validateNoArguments(command); err != nil {
		return s.writeEnhanced(responseStatusParameter, enhancedParameter, "Invalid RSET command")
	}

	_ = s.abortActiveBody(ctx, "rset")
	s.closeTransactionHolds(ctx)
	s.transaction.reset()

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
func (s *Session) streamDATA(ctx context.Context, body MessageBody) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line, err := s.readLine()
		if err != nil {
			return err
		}

		if isDataTerminator(line) {
			return nil
		}

		payload := unescapeDataLine(line)
		if _, err := body.Write(payload); err != nil {
			return err
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
	status := strings.TrimSpace(result.Status)
	if status == "" {
		status = responseStatusOK
	}

	if status != responseStatusOK {
		return s.writeEnhanced(responseStatusTemporary, enhancedTemporary, "Message delivery temporarily failed")
	}

	text := strings.TrimSpace(result.Text)
	if text == "" {
		text = dataQueuedText
	}

	return s.writeEnhanced(responseStatusOK, enhancedOK, text)
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
