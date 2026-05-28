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
	"bufio"
	"crypto/tls"
)

// handleStartTLS validates STARTTLS availability and updates the logical TLS state.
func (s *Session) handleStartTLS(command preauthCommand) error {
	if err := validateNoArguments(command); err != nil {
		return s.writeTagged(command.tag, responseBad, "Invalid STARTTLS command")
	}

	if !s.startTLSAdvertised() {
		return s.writeTagged(command.tag, responseBad, "STARTTLS is not available")
	}

	if err := s.writeTagged(command.tag, responseOK, "Begin TLS negotiation now"); err != nil {
		return err
	}

	if s.context.FrontendTLSConfig == nil {
		s.tlsActive = true

		return nil
	}

	if err := s.writer.Flush(); err != nil {
		return err
	}

	tlsConn := tls.Server(s.conn, s.context.FrontendTLSConfig.Clone())
	if err := tlsConn.Handshake(); err != nil {
		return err
	}

	s.conn = tlsConn
	s.reader = bufio.NewReaderSize(tlsConn, s.context.MaxPreauthLineBytes+1)
	s.writer = bufio.NewWriter(tlsConn)
	s.tlsActive = true

	return nil
}

// startTLSAdvertised reports whether STARTTLS is configured and currently usable.
func (s *Session) startTLSAdvertised() bool {
	return s.startTLSPermitted() && s.configuredCapability(capabilityStartTLS)
}

// startTLSPermitted reports whether listener transport state can still upgrade.
func (s *Session) startTLSPermitted() bool {
	return s.context.StartTLSAvailable() && !s.tlsActive
}

// cloneTLSConfig detaches mutable frontend TLS config from session callers.
func cloneTLSConfig(config *tls.Config) *tls.Config {
	if config == nil {
		return nil
	}

	return config.Clone()
}
