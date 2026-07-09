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
	"bufio"
	"context"
	"crypto/tls"
)

// handleStartTLS validates STARTTLS availability and updates the logical TLS state.
func (s *Session) handleStartTLS(ctx context.Context, command preauthCommand) (commandOutcome, error) {
	if err := validateNoArguments(command); err != nil {
		s.recordStartTLS(ctx, sieveObservationResultRejected, sieveReasonParser)

		return commandOutcome{}, s.writeNo(codeClientBug, "Invalid STARTTLS command")
	}

	if !s.startTLSAdvertised() {
		s.recordStartTLS(ctx, sieveObservationResultRejected, sieveReasonUnsupported)

		return commandOutcome{}, s.writeNo(codeClientBug, "STARTTLS is not available")
	}

	if s.reader.Buffered() > 0 {
		s.recordStartTLS(ctx, sieveObservationResultRejected, sieveReasonProtocol)

		return commandOutcome{closeSession: true}, s.writeNo(codeClientBug, startTLSInjectionMessage)
	}

	if s.frontendTLSConfig == nil {
		s.resetAfterStartTLS()
	}

	if err := s.writeOK("Begin TLS negotiation now"); err != nil {
		return commandOutcome{}, err
	}

	if err := s.writer.Flush(); err != nil {
		s.recordStartTLS(ctx, sieveObservationResultFailure, sieveReasonClass(err))

		return commandOutcome{}, err
	}

	if s.frontendTLSConfig == nil {
		s.recordStartTLS(ctx, sieveObservationResultOK, sieveReasonOK)

		return s.finishStartTLS(ctx)
	}

	tlsConn := tls.Server(s.conn, s.frontendTLSConfig.Clone())
	if err := tlsConn.Handshake(); err != nil {
		s.recordStartTLS(ctx, sieveObservationResultFailure, sieveReasonClass(err))

		return commandOutcome{flushed: true}, err
	}

	s.conn = tlsConn
	s.reader = bufio.NewReaderSize(tlsConn, s.maxPreauthLineBytes+1)
	s.writer = bufio.NewWriter(tlsConn)
	s.resetAfterStartTLS()
	s.recordStartTLS(ctx, sieveObservationResultOK, sieveReasonOK)

	return s.finishStartTLS(ctx)
}

// startTLSAdvertised reports whether STARTTLS is configured and currently usable.
func (s *Session) startTLSAdvertised() bool {
	return s.startTLSPermitted()
}

// startTLSPermitted reports whether listener transport state can still upgrade.
func (s *Session) startTLSPermitted() bool {
	return s.tlsMode == TLSModeStartTLS && !s.tlsActive
}

// resetAfterStartTLS clears pre-TLS state that must not survive the transport upgrade.
func (s *Session) resetAfterStartTLS() {
	s.tlsActive = true
}

// finishStartTLS re-issues capabilities required by RFC 5804 after STARTTLS.
func (s *Session) finishStartTLS(ctx context.Context) (commandOutcome, error) {
	if err := s.writeCapabilityGreeting(); err != nil {
		s.recordCapability(ctx, sieveObservationResultFailure, sieveReasonClass(err))

		return commandOutcome{flushed: true}, err
	}

	if err := s.writer.Flush(); err != nil {
		s.recordCapability(ctx, sieveObservationResultFailure, sieveReasonClass(err))

		return commandOutcome{flushed: true}, err
	}

	s.recordCapability(ctx, sieveObservationResultOK, sieveReasonOK)

	return commandOutcome{flushed: true}, nil
}
