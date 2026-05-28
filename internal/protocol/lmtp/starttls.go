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
	"bufio"
	"crypto/tls"
)

// handleSTARTTLS validates STARTTLS sequencing and updates the logical TLS state.
func (s *Session) handleSTARTTLS(command frontendCommand) (commandOutcome, error) {
	if err := validateNoArguments(command); err != nil {
		return commandOutcome{}, s.writeEnhanced(responseStatusParameter, enhancedParameter, "Invalid STARTTLS command")
	}

	if !s.startTLSAvailable() {
		return commandOutcome{}, s.writeEnhanced(responseStatusBadSequence, enhancedBadSequence, startTLSUnavailableText)
	}

	if err := s.writeEnhanced(responseStatusReady, enhancedOK, startTLSText); err != nil {
		return commandOutcome{}, err
	}

	if err := s.writer.Flush(); err != nil {
		return commandOutcome{}, err
	}

	if s.frontendTLSConfig != nil {
		tlsConn := tls.Server(s.conn, s.frontendTLSConfig.Clone())
		if err := tlsConn.Handshake(); err != nil {
			return commandOutcome{flushed: true}, err
		}

		s.conn = tlsConn
		s.reader = bufio.NewReaderSize(tlsConn, s.maxLineBytes+1)
		s.writer = bufio.NewWriter(tlsConn)
	}

	s.tlsActive = true
	s.resetAfterSTARTTLS()
	s.refreshMTLSPeerAuth()

	return commandOutcome{flushed: true}, nil
}

// startTLSAvailable reports whether STARTTLS was advertised and remains usable.
func (s *Session) startTLSAvailable() bool {
	return s.startTLSPermitted() && containsCapability(s.effectiveCapabilities, capabilitySTARTTLS)
}

// startTLSPermitted reports whether listener transport state can still upgrade.
func (s *Session) startTLSPermitted() bool {
	return s.tlsMode == TLSModeStartTLS &&
		!s.tlsActive &&
		!s.peerAuthenticated &&
		!s.transaction.active()
}

// resetAfterSTARTTLS clears pre-TLS protocol state that must be renegotiated.
func (s *Session) resetAfterSTARTTLS() {
	s.lhloSeen = false
	s.effectiveCapabilities = nil
	s.chunkingAdvertised = false
	s.transaction.reset()
}
