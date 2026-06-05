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

package pop3

import (
	"bufio"
	"context"
	"crypto/tls"
	"strings"
)

const startTLSInjectionMessage = "STLS cannot be pipelined"

// handleSTLS validates STLS availability and updates the logical TLS state.
func (s *Session) handleSTLS(ctx context.Context, command preauthCommand) (commandOutcome, error) {
	if err := validateNoArguments(command); err != nil {
		s.recordSTLS(ctx, pop3ObservationResultRejected, pop3ReasonParser)

		return commandOutcome{}, s.writeERR("Invalid STLS command")
	}

	if !s.startTLSAdvertised() {
		s.recordSTLS(ctx, pop3ObservationResultRejected, pop3ReasonUnsupported)

		return commandOutcome{}, s.writeERR("STLS is not available")
	}

	if s.reader.Buffered() > 0 {
		s.recordSTLS(ctx, pop3ObservationResultRejected, pop3ReasonProtocol)

		return commandOutcome{closeSession: true}, s.writeERR(startTLSInjectionMessage)
	}

	if s.frontendTLSConfig == nil {
		s.resetAfterSTLS()
	}

	if err := s.writeOK("Begin TLS negotiation now"); err != nil {
		s.recordSTLS(ctx, pop3ObservationResultFailure, pop3ReasonClass(err))

		return commandOutcome{}, err
	}

	if err := s.writer.Flush(); err != nil {
		s.recordSTLS(ctx, pop3ObservationResultFailure, pop3ReasonClass(err))

		return commandOutcome{}, err
	}

	if s.frontendTLSConfig == nil {
		s.recordSTLS(ctx, pop3ObservationResultOK, pop3ReasonOK)

		return commandOutcome{flushed: true}, nil
	}

	tlsConn := tls.Server(s.conn, s.frontendTLSConfig.Clone())
	if err := tlsConn.Handshake(); err != nil {
		s.recordSTLS(ctx, pop3ObservationResultFailure, pop3ReasonClass(err))

		return commandOutcome{flushed: true}, err
	}

	s.conn = tlsConn
	s.reader = bufio.NewReaderSize(tlsConn, s.maxPreauthLineBytes+1)
	s.writer = bufio.NewWriter(tlsConn)
	s.resetAfterSTLS()
	s.recordSTLS(ctx, pop3ObservationResultOK, pop3ReasonOK)

	return commandOutcome{flushed: true}, nil
}

// startTLSAdvertised reports whether STLS is configured and currently usable.
func (s *Session) startTLSAdvertised() bool {
	return s.startTLSPermitted() && s.configuredCapability(capabilitySTLS)
}

// startTLSPermitted reports whether listener transport state can still upgrade.
func (s *Session) startTLSPermitted() bool {
	return strings.EqualFold(s.tlsMode, TLSModeStartTLS) && !s.tlsActive
}

// resetAfterSTLS clears pre-TLS state that must not survive the transport upgrade.
func (s *Session) resetAfterSTLS() {
	s.tlsActive = true
	s.provisionalUser = ""
}

// cloneTLSConfig detaches mutable frontend TLS config from session callers.
func cloneTLSConfig(config *tls.Config) *tls.Config {
	if config == nil {
		return nil
	}

	return config.Clone()
}
