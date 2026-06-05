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
	"strconv"
	"strings"
)

const (
	commandAuthenticate = "AUTHENTICATE"
	commandCapability   = "CAPABILITY"
	commandLogout       = "LOGOUT"
	commandNoop         = "NOOP"
	commandStartTLS     = "STARTTLS"
)

var (
	// ErrMalformedCommand reports command syntax outside the supported pre-auth subset.
	ErrMalformedCommand = errors.New("sieve: malformed command")
	// ErrUnsupportedCommand reports a command that this pre-auth state does not implement.
	ErrUnsupportedCommand = errors.New("sieve: unsupported preauth command")
)

type preauthCommand struct {
	name      string
	arguments []argumentToken
}

type tokenKind int

const (
	tokenAtom tokenKind = iota
	tokenQuoted
	tokenLiteral
)

type argumentToken struct {
	kind        tokenKind
	value       string
	literalSize int
}

// parsePreauthCommand parses one bounded ManageSieve line into a pre-auth command.
func parsePreauthCommand(line []byte, maxLineBytes int) (preauthCommand, error) {
	text, err := trimPreauthLine(line, maxLineBytes)
	if err != nil {
		return preauthCommand{}, err
	}

	name, argsText, ok := cutField(text)
	if !ok {
		name = strings.TrimSpace(text)
	}

	if !validCommandName(name) {
		return preauthCommand{}, fmt.Errorf("%w: invalid command name", ErrMalformedCommand)
	}

	arguments, err := tokenizeArguments(argsText, maxLineBytes)
	if err != nil {
		return preauthCommand{}, err
	}

	return preauthCommand{name: strings.ToUpper(name), arguments: arguments}, nil
}

// trimPreauthLine strips CRLF while rejecting embedded control-line breaks.
func trimPreauthLine(line []byte, maxLineBytes int) (string, error) {
	if maxLineBytes > 0 && len(line) > maxLineBytes {
		return "", ErrPreauthLineTooLarge
	}

	text := strings.TrimRight(string(line), "\r\n")
	if strings.TrimSpace(text) == "" {
		return "", fmt.Errorf("%w: empty line", ErrMalformedCommand)
	}

	if strings.ContainsAny(text, "\r\n") {
		return "", fmt.Errorf("%w: embedded line break", ErrMalformedCommand)
	}

	return text, nil
}

// cutField splits the next whitespace-delimited field from a command line.
func cutField(text string) (string, string, bool) {
	trimmed := strings.TrimLeft(text, " \t")
	if trimmed == "" {
		return "", "", false
	}

	for index, char := range trimmed {
		if char == ' ' || char == '\t' {
			return trimmed[:index], strings.TrimLeft(trimmed[index+1:], " \t"), true
		}
	}

	return trimmed, "", false
}

// tokenizeArguments scans atoms, quoted strings and final literal markers.
func tokenizeArguments(input string, maxTokenBytes int) ([]argumentToken, error) {
	var tokens []argumentToken

	for index := 0; index < len(input); {
		switch input[index] {
		case ' ', '\t':
			index++
			continue
		case '"':
			value, next, err := scanQuoted(input, index, maxTokenBytes)
			if err != nil {
				return nil, err
			}

			tokens = append(tokens, argumentToken{kind: tokenQuoted, value: value})
			index = next
		case '{':
			size, next, err := scanLiteralMarker(input, index)
			if err != nil {
				return nil, err
			}

			tokens = append(tokens, argumentToken{kind: tokenLiteral, literalSize: size})
			index = next
		default:
			value, next, err := scanAtom(input, index, maxTokenBytes)
			if err != nil {
				return nil, err
			}

			tokens = append(tokens, argumentToken{kind: tokenAtom, value: value})
			index = next
		}
	}

	return tokens, nil
}

// scanQuoted reads one ManageSieve quoted string with minimal escape handling.
func scanQuoted(input string, start int, maxTokenBytes int) (string, int, error) {
	var builder strings.Builder
	builder.Grow(16)

	for index := start + 1; index < len(input); index++ {
		char := input[index]
		switch char {
		case '"':
			return builder.String(), index + 1, nil
		case '\\':
			index++
			if index >= len(input) {
				return "", 0, fmt.Errorf("%w: dangling quoted escape", ErrMalformedCommand)
			}

			char = input[index]
		case '\r', '\n':
			return "", 0, fmt.Errorf("%w: line break in quoted string", ErrMalformedCommand)
		}

		if char < 0x20 || char == 0x7f {
			return "", 0, fmt.Errorf("%w: control byte in quoted string", ErrMalformedCommand)
		}

		if maxTokenBytes > 0 && builder.Len()+1 > maxTokenBytes {
			return "", 0, fmt.Errorf("%w: quoted string too large", ErrMalformedCommand)
		}

		builder.WriteByte(char)
	}

	return "", 0, fmt.Errorf("%w: unterminated quoted string", ErrMalformedCommand)
}

// scanAtom reads one command atom for the intentionally small pre-auth grammar.
func scanAtom(input string, start int, maxTokenBytes int) (string, int, error) {
	index := start
	for index < len(input) && input[index] != ' ' && input[index] != '\t' {
		if !validAtomByte(input[index]) {
			return "", 0, fmt.Errorf("%w: invalid atom", ErrMalformedCommand)
		}

		index++
	}

	if index == start {
		return "", 0, fmt.Errorf("%w: empty atom", ErrMalformedCommand)
	}

	if maxTokenBytes > 0 && index-start > maxTokenBytes {
		return "", 0, fmt.Errorf("%w: atom too large", ErrMalformedCommand)
	}

	return input[start:index], index, nil
}

// scanLiteralMarker reads a ManageSieve literal size marker.
func scanLiteralMarker(input string, start int) (int, int, error) {
	closeIndex := strings.IndexByte(input[start:], '}')
	if closeIndex < 0 {
		return 0, 0, fmt.Errorf("%w: unterminated literal marker", ErrMalformedCommand)
	}

	closeIndex += start

	sizeText := input[start+1 : closeIndex]
	if sizeText == "" {
		return 0, 0, fmt.Errorf("%w: empty literal marker", ErrMalformedCommand)
	}

	size, err := strconv.Atoi(sizeText)
	if err != nil || size < 0 {
		return 0, 0, fmt.Errorf("%w: invalid literal marker", ErrMalformedCommand)
	}

	return size, closeIndex + 1, nil
}

// validCommandName reports whether the command token can be normalized safely.
func validCommandName(value string) bool {
	if value == "" {
		return false
	}

	for index := 0; index < len(value); index++ {
		char := value[index]
		if (char < 'A' || char > 'Z') && (char < 'a' || char > 'z') {
			return false
		}
	}

	return true
}

// validAtomByte accepts printable non-special bytes for command atoms.
func validAtomByte(value byte) bool {
	switch value {
	case ' ', '\t', '\r', '\n', '{', '}', '"':
		return false
	default:
		return value >= 0x21 && value != 0x7f
	}
}

// validateNoArguments rejects unexpected arguments for simple pre-auth commands.
func validateNoArguments(command preauthCommand) error {
	if len(command.arguments) != 0 {
		return fmt.Errorf("%w: unexpected arguments", ErrMalformedCommand)
	}

	return nil
}

// tokenStringValue returns a string-like token value for command arguments.
func tokenStringValue(token argumentToken) (string, bool) {
	switch token.kind {
	case tokenAtom, tokenQuoted:
		return token.value, true
	default:
		return "", false
	}
}
