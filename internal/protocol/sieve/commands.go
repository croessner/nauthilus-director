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
	"context"
)

type commandOutcome struct {
	closeSession bool
	flushed      bool
}

// handlePreauthCommand dispatches one parsed command in wire order.
func (s *Session) handlePreauthCommand(ctx context.Context, command preauthCommand) (commandOutcome, error) {
	switch command.name {
	case commandCapability:
		if err := validateNoArguments(command); err != nil {
			s.recordCapability(ctx, sieveObservationResultRejected, sieveReasonParser)

			return commandOutcome{}, s.writeNo(codeClientBug, "Invalid CAPABILITY command")
		}

		s.recordCapability(ctx, sieveObservationResultOK, sieveReasonOK)

		return commandOutcome{}, s.handleCapability(command)
	case commandNoop:
		return commandOutcome{}, s.handleNoop(command)
	case commandLogout:
		return commandOutcome{closeSession: true}, s.handleLogout(command)
	case commandStartTLS:
		return s.handleStartTLS(ctx, command)
	case commandAuthenticate:
		return s.handleAuthenticate(ctx, command)
	default:
		if err := s.writeNo(codeUnsupported, "Unsupported command before authentication"); err != nil {
			return commandOutcome{}, err
		}

		return commandOutcome{}, ErrUnsupportedCommand
	}
}

// handleNoop implements the ManageSieve NOOP pre-auth command.
func (s *Session) handleNoop(command preauthCommand) error {
	if err := validateNoArguments(command); err != nil {
		return s.writeNo(codeClientBug, "Invalid NOOP command")
	}

	return s.writeOK("NOOP completed")
}

// handleLogout implements the ManageSieve LOGOUT command and asks the session to close.
func (s *Session) handleLogout(command preauthCommand) error {
	if err := validateNoArguments(command); err != nil {
		return s.writeNo(codeClientBug, "Invalid LOGOUT command")
	}

	return s.writeOK("Logout completed")
}
