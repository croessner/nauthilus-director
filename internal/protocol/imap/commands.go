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
	"fmt"
	"strings"
)

const (
	responseBad = "BAD"
	responseNo  = "NO"
	responseOK  = "OK"

	authUnavailableText = "[UNAVAILABLE] Authentication handler unavailable"
	genericAuthFailText = "Authentication failed"
)

type commandOutcome struct {
	closeSession bool
}

// handlePreauthCommand dispatches one parsed command in wire order.
func (s *Session) handlePreauthCommand(command preauthCommand) (commandOutcome, error) {
	switch command.name {
	case commandCapability:
		return commandOutcome{}, s.handleCapability(command)
	case commandNoop:
		return commandOutcome{}, s.handleNoop(command)
	case commandLogout:
		return commandOutcome{closeSession: true}, s.handleLogout(command)
	case commandStartTLS:
		return commandOutcome{}, s.handleStartTLS(command)
	case commandID:
		return commandOutcome{}, s.handleID(command)
	case commandLogin:
		return commandOutcome{}, s.handleLogin(command)
	case commandAuthenticate:
		return commandOutcome{}, s.handleAuthenticate(command)
	default:
		if err := s.writeTagged(command.tag, responseBad, "Unsupported command before authentication"); err != nil {
			return commandOutcome{}, err
		}

		return commandOutcome{}, ErrUnsupportedCommand
	}
}

// handleNoop implements the IMAP NOOP pre-auth command.
func (s *Session) handleNoop(command preauthCommand) error {
	if err := validateNoArguments(command); err != nil {
		return s.writeTagged(command.tag, responseBad, "Invalid NOOP command")
	}

	return s.writeTagged(command.tag, responseOK, "NOOP completed")
}

// handleLogout implements the IMAP LOGOUT command and asks the session to close.
func (s *Session) handleLogout(command preauthCommand) error {
	if err := validateNoArguments(command); err != nil {
		return s.writeTagged(command.tag, responseBad, "Invalid LOGOUT command")
	}

	if _, err := s.writer.WriteString("* BYE Logging out\r\n"); err != nil {
		return err
	}

	return s.writeTagged(command.tag, responseOK, "LOGOUT completed")
}

// handleLogin validates the LOGIN command shape without retaining credentials.
func (s *Session) handleLogin(command preauthCommand) error {
	if len(command.arguments) != 2 || !tokenIsStringLike(command.arguments[0]) || !tokenIsStringLike(command.arguments[1]) {
		return s.writeTagged(command.tag, responseBad, "Invalid LOGIN command")
	}

	if s.requiresClientID() {
		return s.writeTagged(command.tag, responseNo, genericAuthFailText)
	}

	return s.writeTagged(command.tag, responseNo, authUnavailableText)
}

// handleAuthenticate validates AUTHENTICATE mechanism and SASL-IR shape only.
func (s *Session) handleAuthenticate(command preauthCommand) error {
	if len(command.arguments) < 1 || len(command.arguments) > 2 || command.arguments[0].kind != tokenAtom {
		return s.writeTagged(command.tag, responseBad, "Invalid AUTHENTICATE command")
	}

	mechanism := strings.ToUpper(command.arguments[0].value)
	if !s.supportsAuthMechanism(mechanism) {
		return s.writeTagged(command.tag, responseNo, "Unsupported authentication mechanism")
	}

	if len(command.arguments) == 2 {
		if command.arguments[1].kind != tokenAtom {
			return s.writeTagged(command.tag, responseBad, "Invalid AUTHENTICATE initial response")
		}

		if err := validateBase64Shape(command.arguments[1].value, s.context.MaxPreauthLineBytes); err != nil {
			return s.writeTagged(command.tag, responseBad, "Invalid AUTHENTICATE initial response")
		}
	}

	if s.requiresClientID() {
		return s.writeTagged(command.tag, responseNo, genericAuthFailText)
	}

	return s.writeTagged(command.tag, responseNo, authUnavailableText)
}

// writeTagged writes a single tagged IMAP response line.
func (s *Session) writeTagged(tag string, status string, text string) error {
	if tag == "" {
		_, err := fmt.Fprintf(s.writer, "* %s %s\r\n", status, text)

		return err
	}

	_, err := fmt.Fprintf(s.writer, "%s %s %s\r\n", tag, status, text)

	return err
}

// writeCommandSyntaxError writes a tagged BAD response when the tag is usable.
func (s *Session) writeCommandSyntaxError(tag string) error {
	return s.writeTagged(tag, responseBad, "Invalid pre-auth command")
}

// tokenIsStringLike reports whether a parsed argument can stand in for an IMAP string.
func tokenIsStringLike(token argumentToken) bool {
	return token.kind == tokenAtom || token.kind == tokenQuoted
}

// requiresClientID reports whether listener policy blocks auth without usable ID context.
func (s *Session) requiresClientID() bool {
	return s.context.RequireIDBeforeAuth && s.clientID == ""
}

// supportsAuthMechanism reports whether a normalized mechanism is configured for this listener.
func (s *Session) supportsAuthMechanism(mechanism string) bool {
	for _, supported := range s.context.AuthMechanisms {
		if strings.EqualFold(supported, mechanism) {
			return true
		}
	}

	return false
}
