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

//nolint:wsl_v5 // POP3 command parsing stays compact so wire-token handling is easy to audit.
package pop3

import (
	"errors"
	"fmt"
	"strings"
)

const (
	commandAuth = "AUTH"
	commandCapa = "CAPA"
	commandNoop = "NOOP"
	commandPass = "PASS"
	commandQuit = "QUIT"
	commandSTLS = "STLS"
	commandUser = "USER"
)

var (
	// ErrMalformedCommand reports command syntax outside the supported authorization subset.
	ErrMalformedCommand = errors.New("pop3: malformed command")
	// ErrUnsupportedCommand reports a command that this authorization state does not implement.
	ErrUnsupportedCommand = errors.New("pop3: unsupported preauth command")
)

type preauthCommand struct {
	name      string
	arguments []string
}

// parsePreauthCommand parses one bounded POP3 line into an authorization-state command.
func parsePreauthCommand(line []byte, maxLineBytes int) (preauthCommand, error) {
	text, err := trimPreauthLine(line, maxLineBytes)
	if err != nil {
		return preauthCommand{}, err
	}

	name, argumentsText, ok := cutField(text)
	if !ok {
		name = strings.TrimSpace(text)
	}

	if !validCommandName(name) {
		return preauthCommand{}, fmt.Errorf("%w: invalid command name", ErrMalformedCommand)
	}

	arguments, err := parseArguments(argumentsText, maxLineBytes)
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

// parseArguments splits the bounded POP3 argument tail into atom-like parameters.
func parseArguments(input string, maxTokenBytes int) ([]string, error) {
	if strings.TrimSpace(input) == "" {
		return nil, nil
	}

	fields := strings.Fields(input)
	arguments := make([]string, 0, len(fields))
	for _, field := range fields {
		if !validArgument(field) {
			return nil, fmt.Errorf("%w: invalid argument", ErrMalformedCommand)
		}

		if maxTokenBytes > 0 && len(field) > maxTokenBytes {
			return nil, fmt.Errorf("%w: argument too large", ErrMalformedCommand)
		}

		arguments = append(arguments, field)
	}

	return arguments, nil
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

// validArgument rejects control bytes and whitespace inside one parsed argument.
func validArgument(value string) bool {
	if value == "" {
		return false
	}

	for index := 0; index < len(value); index++ {
		char := value[index]
		if char <= 0x20 || char == 0x7f {
			return false
		}
	}

	return true
}

// validateNoArguments rejects unexpected arguments for simple authorization commands.
func validateNoArguments(command preauthCommand) error {
	if len(command.arguments) != 0 {
		return fmt.Errorf("%w: unexpected arguments", ErrMalformedCommand)
	}

	return nil
}

// singleArgument returns the only command argument for credential-bearing commands.
func singleArgument(command preauthCommand) (string, error) {
	if len(command.arguments) != 1 {
		return "", fmt.Errorf("%w: expected one argument", ErrMalformedCommand)
	}

	value := strings.TrimSpace(command.arguments[0])
	if value == "" {
		return "", fmt.Errorf("%w: empty argument", ErrMalformedCommand)
	}

	return value, nil
}
