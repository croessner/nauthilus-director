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
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	commandAuthenticate = "AUTHENTICATE"
	commandCapability   = "CAPABILITY"
	commandID           = "ID"
	commandLogin        = "LOGIN"
	commandLogout       = "LOGOUT"
	commandNoop         = "NOOP"
	commandStartTLS     = "STARTTLS"
)

var (
	// ErrMalformedCommand reports command syntax outside the supported pre-auth subset.
	ErrMalformedCommand = errors.New("imap: malformed command")
	// ErrUnsupportedCommand reports a command that this pre-auth state does not implement.
	ErrUnsupportedCommand = errors.New("imap: unsupported preauth command")
	// ErrUnsupportedAuthMechanism reports an AUTHENTICATE mechanism outside the supported set.
	ErrUnsupportedAuthMechanism = errors.New("imap: unsupported authentication mechanism")
)

type preauthCommand struct {
	tag       string
	name      string
	arguments []argumentToken
}

type tokenKind int

const (
	tokenAtom tokenKind = iota
	tokenQuoted
	tokenListStart
	tokenListEnd
)

type argumentToken struct {
	kind  tokenKind
	value string
}

// parsePreauthCommand parses one bounded IMAP line into a pre-auth command.
func parsePreauthCommand(line []byte, maxLineBytes int) (preauthCommand, error) {
	text, err := trimPreauthLine(line, maxLineBytes)
	if err != nil {
		return preauthCommand{}, err
	}

	tag, rest, ok := cutField(text)
	if !ok {
		return preauthCommand{}, fmt.Errorf("%w: missing command", ErrMalformedCommand)
	}

	if !validAtom(tag) {
		return preauthCommand{}, fmt.Errorf("%w: invalid tag", ErrMalformedCommand)
	}

	name, argsText, ok := cutField(rest)
	if !ok {
		name = strings.TrimSpace(rest)
	}

	if !validCommandName(name) {
		return preauthCommand{}, fmt.Errorf("%w: invalid command name", ErrMalformedCommand)
	}

	arguments, err := tokenizeArguments(argsText, maxLineBytes)
	if err != nil {
		return preauthCommand{}, err
	}

	return preauthCommand{
		tag:       tag,
		name:      strings.ToUpper(name),
		arguments: arguments,
	}, nil
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

// cutField splits the next whitespace-delimited field from an IMAP command.
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

// tokenizeArguments scans atoms, quoted strings and list delimiters for pre-auth commands.
func tokenizeArguments(input string, maxTokenBytes int) ([]argumentToken, error) {
	var tokens []argumentToken

	for index := 0; index < len(input); {
		switch input[index] {
		case ' ', '\t':
			index++
			continue
		case '(':
			tokens = append(tokens, argumentToken{kind: tokenListStart})
			index++
		case ')':
			tokens = append(tokens, argumentToken{kind: tokenListEnd})
			index++
		case '"':
			value, next, err := scanQuoted(input, index, maxTokenBytes)
			if err != nil {
				return nil, err
			}

			tokens = append(tokens, argumentToken{kind: tokenQuoted, value: value})
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

// scanQuoted reads one IMAP quoted string with minimal escape handling.
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

// scanAtom reads one IMAP atom for the intentionally small pre-auth grammar.
func scanAtom(input string, start int, maxTokenBytes int) (string, int, error) {
	index := start
	for index < len(input) && input[index] != ' ' && input[index] != '\t' && input[index] != '(' && input[index] != ')' {
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

// validAtom reports whether a field is an acceptable IMAP atom in this subset.
func validAtom(value string) bool {
	if value == "" {
		return false
	}

	for index := 0; index < len(value); index++ {
		if !validAtomByte(value[index]) {
			return false
		}
	}

	return true
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
	case ' ', '\t', '\r', '\n', '(', ')', '{', '}', '"':
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

// preauthLiteralMarker extracts unsupported literal markers without reading continuations.
func preauthLiteralMarker(line []byte) (int, bool, error) {
	text := string(line)
	for index := 0; index < len(text); index++ {
		if text[index] != '{' {
			continue
		}

		size, ok, err := literalSizeAt(text, index)
		if ok || err != nil {
			return size, ok, err
		}
	}

	return 0, false, nil
}

// literalSizeAt parses a literal marker at the supplied opening brace offset.
func literalSizeAt(text string, openIndex int) (int, bool, error) {
	sizeStart := openIndex + 1
	sizeEnd := sizeStart

	for sizeEnd < len(text) && text[sizeEnd] >= '0' && text[sizeEnd] <= '9' {
		sizeEnd++
	}

	if sizeEnd == sizeStart {
		return 0, false, nil
	}

	if sizeEnd < len(text) && text[sizeEnd] == '+' {
		sizeEnd++
	}

	if sizeEnd >= len(text) || text[sizeEnd] != '}' {
		return 0, false, nil
	}

	value := strings.TrimSuffix(text[sizeStart:sizeEnd], "+")

	size, err := strconv.Atoi(value)
	if err != nil || size < 0 {
		return 0, true, fmt.Errorf("%w: invalid literal size", ErrPreauthLiteralUnsupported)
	}

	return size, true, nil
}

// tagHintForLine extracts a safe response tag before full command parsing.
func tagHintForLine(line []byte) string {
	text := strings.TrimLeft(strings.TrimRight(string(line), "\r\n"), " \t")

	tag, _, ok := cutField(text)
	if !ok {
		tag = text
	}

	if !validAtom(tag) {
		return ""
	}

	return tag
}
