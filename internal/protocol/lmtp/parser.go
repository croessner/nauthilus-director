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
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	commandAuth     = "AUTH"
	commandBDAT     = "BDAT"
	commandDATA     = "DATA"
	commandLHLO     = "LHLO"
	commandMAIL     = "MAIL"
	commandNOOP     = "NOOP"
	commandQUIT     = "QUIT"
	commandRCPT     = "RCPT"
	commandRSET     = "RSET"
	commandSTARTTLS = "STARTTLS"
)

var (
	// ErrLineTooLarge reports that a frontend command or DATA line exceeded the configured bound.
	ErrLineTooLarge = errors.New("lmtp: line exceeds configured limit")
	// ErrMalformedCommand reports command syntax outside the supported frontend subset.
	ErrMalformedCommand = errors.New("lmtp: malformed command")
	// ErrPartialCommand reports connection closure before a command line was complete.
	ErrPartialCommand = errors.New("lmtp: partial command")
	// ErrMalformedBDAT reports invalid byte-counted BDAT command arguments.
	ErrMalformedBDAT = errors.New("lmtp: malformed bdat command")
)

type frontendCommand struct {
	name string
	args string
}

type bdatCommand struct {
	size int64
	last bool
}

type mailCommand struct {
	wirePath string
	smtpUTF8 bool
}

// readLine reads one bounded line from the frontend stream.
func (s *Session) readLine() ([]byte, error) {
	line, err := s.reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) > s.maxLineBytes {
		return nil, ErrLineTooLarge
	}

	if errors.Is(err, io.EOF) && len(line) > 0 {
		return line, ErrPartialCommand
	}

	if err != nil {
		return nil, err
	}

	return line, nil
}

// parseFrontendCommand parses one LMTP command line without retaining secret-bearing arguments.
func parseFrontendCommand(line []byte, maxLineBytes int) (frontendCommand, error) {
	text, err := trimCommandLine(line, maxLineBytes)
	if err != nil {
		return frontendCommand{}, err
	}

	name, args, ok := cutCommandField(text)
	if !ok {
		return frontendCommand{}, fmt.Errorf("%w: missing command", ErrMalformedCommand)
	}

	if !validCommandName(name) {
		return frontendCommand{}, fmt.Errorf("%w: invalid command name", ErrMalformedCommand)
	}

	return frontendCommand{name: strings.ToUpper(name), args: args}, nil
}

// trimCommandLine strips CRLF while rejecting embedded command-line breaks.
func trimCommandLine(line []byte, maxLineBytes int) (string, error) {
	if maxLineBytes > 0 && len(line) > maxLineBytes {
		return "", ErrLineTooLarge
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

// cutCommandField splits the command verb from the remaining arguments.
func cutCommandField(text string) (string, string, bool) {
	trimmed := strings.TrimLeft(text, " \t")
	if trimmed == "" {
		return "", "", false
	}

	for index, current := range trimmed {
		if current == ' ' || current == '\t' {
			return trimmed[:index], strings.TrimLeft(trimmed[index+1:], " \t"), true
		}
	}

	return trimmed, "", true
}

// validCommandName reports whether a command verb can be normalized safely.
func validCommandName(value string) bool {
	if value == "" {
		return false
	}

	for index := 0; index < len(value); index++ {
		current := value[index]
		if (current < 'A' || current > 'Z') && (current < 'a' || current > 'z') {
			return false
		}
	}

	return true
}

// validateNoArguments rejects unexpected arguments on fixed-shape commands.
func validateNoArguments(command frontendCommand) error {
	if strings.TrimSpace(command.args) != "" {
		return fmt.Errorf("%w: unexpected arguments", ErrMalformedCommand)
	}

	return nil
}

// parseMailCommand validates MAIL FROM and returns supported envelope parameters.
func parseMailCommand(command frontendCommand) (mailCommand, error) {
	path, tail, err := splitCommandPath(command.args, "FROM:")
	if err != nil {
		return mailCommand{}, err
	}

	parsed := mailCommand{wirePath: path}

	for parameter := range strings.FieldsSeq(tail) {
		if !strings.EqualFold(parameter, capabilitySMTPUTF8) {
			return mailCommand{}, fmt.Errorf("%w: unsupported MAIL parameter", ErrMalformedCommand)
		}

		if parsed.smtpUTF8 {
			return mailCommand{}, fmt.Errorf("%w: duplicate SMTPUTF8 parameter", ErrMalformedCommand)
		}

		parsed.smtpUTF8 = true
	}

	return parsed, nil
}

// splitCommandPath extracts one bracketed path and returns trailing parameters.
func splitCommandPath(args string, prefix string) (string, string, error) {
	args = strings.TrimSpace(args)
	if args == "" {
		return "", "", fmt.Errorf("%w: missing path", ErrMalformedCommand)
	}

	upper := strings.ToUpper(args)

	expected := strings.ToUpper(prefix)
	if !strings.HasPrefix(upper, expected) {
		return "", "", fmt.Errorf("%w: missing path prefix", ErrMalformedCommand)
	}

	remaining := strings.TrimSpace(args[len(prefix):])
	if remaining == "" || !strings.HasPrefix(remaining, "<") {
		return "", "", fmt.Errorf("%w: invalid path", ErrMalformedCommand)
	}

	closeIndex := strings.Index(remaining, ">")
	if closeIndex < 0 {
		return "", "", fmt.Errorf("%w: invalid path", ErrMalformedCommand)
	}

	path := remaining[:closeIndex+1]

	rawTail := remaining[closeIndex+1:]
	if rawTail != "" && rawTail[0] != ' ' && rawTail[0] != '\t' {
		return "", "", fmt.Errorf("%w: invalid path parameter separator", ErrMalformedCommand)
	}

	tail := strings.TrimSpace(rawTail)

	return path, tail, nil
}

// validateSMTPUTF8Path rejects non-ASCII envelope paths unless SMTPUTF8 is active.
func validateSMTPUTF8Path(path string, smtpUTF8 bool) error {
	if isASCII(path) {
		return nil
	}

	if !smtpUTF8 {
		return fmt.Errorf("%w: SMTPUTF8 required", ErrMalformedCommand)
	}

	if !utf8.ValidString(path) {
		return fmt.Errorf("%w: invalid UTF-8 path", ErrMalformedCommand)
	}

	return nil
}

// isASCII reports whether a wire path avoids SMTPUTF8-only octets.
func isASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] > 0x7f {
			return false
		}
	}

	return true
}

// parseBDATCommand validates the BDAT size and optional LAST marker.
func parseBDATCommand(command frontendCommand) (bdatCommand, error) {
	fields := strings.Fields(command.args)
	if len(fields) < 1 || len(fields) > 2 {
		return bdatCommand{}, fmt.Errorf("%w: invalid field count", ErrMalformedBDAT)
	}

	for _, current := range fields[0] {
		if current < '0' || current > '9' {
			return bdatCommand{}, fmt.Errorf("%w: invalid size", ErrMalformedBDAT)
		}
	}

	size, err := strconv.ParseInt(fields[0], 10, 63)
	if err != nil || size < 0 {
		return bdatCommand{}, fmt.Errorf("%w: invalid size", ErrMalformedBDAT)
	}

	parsed := bdatCommand{size: size}

	if len(fields) == 2 {
		if !strings.EqualFold(fields[1], "LAST") {
			return bdatCommand{}, fmt.Errorf("%w: invalid marker", ErrMalformedBDAT)
		}

		parsed.last = true
	}

	return parsed, nil
}
