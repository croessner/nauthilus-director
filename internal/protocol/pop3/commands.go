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

import "context"

type commandOutcome struct {
	closeSession bool
	flushed      bool
}

// handlePreauthCommand dispatches one parsed POP3 authorization-state command.
func (s *Session) handlePreauthCommand(ctx context.Context, command preauthCommand) (commandOutcome, error) {
	switch command.name {
	case commandCapa:
		return commandOutcome{}, s.handleCapa(ctx, command)
	case commandNoop:
		return commandOutcome{}, s.handleNoop(command)
	case commandQuit:
		return commandOutcome{closeSession: true}, s.handleQuit(command)
	case commandSTLS:
		return s.handleSTLS(ctx, command)
	case commandUser:
		return commandOutcome{}, s.handleUser(ctx, command)
	case commandPass:
		return s.handlePass(ctx, command)
	case commandAuth:
		return s.handleAuth(ctx, command)
	default:
		if err := s.writeERR("Unsupported command before authentication"); err != nil {
			return commandOutcome{}, err
		}

		return commandOutcome{}, ErrUnsupportedCommand
	}
}

// handleNoop implements the POP3 NOOP authorization-state command.
func (s *Session) handleNoop(command preauthCommand) error {
	if err := validateNoArguments(command); err != nil {
		return s.writeERR("Invalid NOOP command")
	}

	return s.writeOK("NOOP completed")
}

// handleQuit implements the POP3 QUIT command and asks the session to close.
func (s *Session) handleQuit(command preauthCommand) error {
	if err := validateNoArguments(command); err != nil {
		return s.writeERR("Invalid QUIT command")
	}

	return s.writeOK("POP3 session closing")
}
