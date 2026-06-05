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
	"errors"
	"fmt"
	"strings"

	"github.com/croessner/nauthilus-director/internal/protocol/saslcred"
)

var errSASLCancelled = errors.New("pop3: sasl authentication cancelled")

// parseSASLCredentials decodes and parses a configured bearer SASL mechanism payload.
func parseSASLCredentials(
	mechanism saslcred.Mechanism,
	encoded string,
	maxPayloadBytes int,
	maxBearerTokenBytes int,
) (*frontendCredentials, error) {
	switch mechanism.Normalized() {
	case saslcred.MechanismXOAUTH2, saslcred.MechanismOAuthBearer:
	default:
		return nil, fmt.Errorf("%w: %s", saslcred.ErrUnsupportedMechanism, mechanism.Normalized())
	}

	credentials, err := saslcred.Parse(mechanism, encoded, maxPayloadBytes, maxBearerTokenBytes)
	if err != nil {
		return nil, err
	}

	return credentialsFromSASL(credentials), nil
}

// authenticateResponsePayload returns the SASL payload from initial response or continuation.
func (s *Session) authenticateResponsePayload(command preauthCommand) (string, error) {
	if len(command.arguments) == 2 {
		return authenticateInitialResponse(command.arguments[1])
	}

	return s.readSASLContinuation()
}

// authenticateInitialResponse validates and unwraps the AUTH initial response token.
func authenticateInitialResponse(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "*" {
		return "", errSASLCancelled
	}

	if value == "" || strings.ContainsAny(value, " \t\r\n") {
		return "", fmt.Errorf("%w: invalid sasl response token", ErrMalformedCommand)
	}

	return value, nil
}

// readSASLContinuation writes an empty challenge and reads one bounded client response.
func (s *Session) readSASLContinuation() (string, error) {
	if _, err := s.writer.WriteString("+ \r\n"); err != nil {
		return "", err
	}

	if err := s.writer.Flush(); err != nil {
		return "", err
	}

	line, err := s.readPreauthLine()
	if err != nil {
		return "", err
	}

	return parseSASLResponseLine(line, s.maxPreauthLineBytes)
}

// parseSASLResponseLine parses one continuation response token or cancellation marker.
func parseSASLResponseLine(line []byte, maxLineBytes int) (string, error) {
	text, err := trimPreauthLine(line, maxLineBytes)
	if err != nil {
		return "", err
	}

	if text == "*" {
		return "", errSASLCancelled
	}

	if strings.ContainsAny(text, " \t") {
		return "", fmt.Errorf("%w: invalid sasl continuation", ErrMalformedCommand)
	}

	return authenticateInitialResponse(text)
}
