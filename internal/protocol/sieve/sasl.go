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
	"errors"
	"fmt"

	"github.com/croessner/nauthilus-director/internal/protocol/saslcred"
)

var errSASLCancelled = errors.New("sieve: sasl authentication cancelled")

// parseSASLCredentials decodes and parses a configured SASL mechanism payload.
func parseSASLCredentials(
	mechanism saslcred.Mechanism,
	encoded string,
	maxPayloadBytes int,
	maxBearerTokenBytes int,
) (*frontendCredentials, error) {
	credentials, err := saslcred.Parse(mechanism, encoded, maxPayloadBytes, maxBearerTokenBytes)
	if err != nil {
		return nil, err
	}

	return &frontendCredentials{credentials: credentials}, nil
}

// authenticateResponsePayload returns the SASL payload from initial response or continuation.
func (s *Session) authenticateResponsePayload(command preauthCommand) (string, error) {
	if len(command.arguments) == 2 {
		return authenticateInitialResponse(command.arguments[1])
	}

	return s.readSASLContinuation()
}

// authenticateInitialResponse validates and unwraps the AUTHENTICATE initial response token.
func authenticateInitialResponse(token argumentToken) (string, error) {
	value, ok := tokenStringValue(token)
	if !ok {
		return "", fmt.Errorf("%w: invalid sasl response token", ErrMalformedCommand)
	}

	if value == "*" {
		return "", errSASLCancelled
	}

	return value, nil
}

// readSASLContinuation writes an empty challenge and reads one bounded client response.
func (s *Session) readSASLContinuation() (string, error) {
	if _, err := s.writer.WriteString(quoteString("") + "\r\n"); err != nil {
		return "", err
	}

	if err := s.writer.Flush(); err != nil {
		return "", err
	}

	line, err := s.readPreauthLine()
	if err != nil {
		return "", err
	}

	response, err := parseSASLResponseLine(line, s.maxPreauthLineBytes)
	if err != nil {
		return "", err
	}

	if response.kind == tokenLiteral {
		value, literalErr := s.readLiteralValue(response.literalSize)
		if literalErr != nil {
			return "", literalErr
		}

		response = argumentToken{kind: tokenQuoted, value: value}
	}

	return authenticateInitialResponse(response)
}

// parseSASLResponseLine parses one continuation response token or cancellation marker.
func parseSASLResponseLine(line []byte, maxLineBytes int) (argumentToken, error) {
	text, err := trimPreauthLine(line, maxLineBytes)
	if err != nil {
		return argumentToken{}, err
	}

	if text == "*" {
		return argumentToken{kind: tokenAtom, value: "*"}, nil
	}

	tokens, err := tokenizeArguments(text, maxLineBytes)
	if err != nil {
		return argumentToken{}, err
	}

	if len(tokens) != 1 {
		return argumentToken{}, fmt.Errorf("%w: invalid sasl continuation", ErrMalformedCommand)
	}

	return tokens[0], nil
}
