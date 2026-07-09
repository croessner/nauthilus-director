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
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/croessner/nauthilus-director/internal/protocol/greeting"
)

const (
	responseOK  = "+OK"
	responseERR = "-ERR"

	genericAuthFailedText    = "Authentication failed"
	maxSafeResponseTextBytes = 512
)

// writeGreeting sends the safe POP3 greeting for a ready frontend session.
func (s *Session) writeGreeting() error {
	return s.writeOK(pop3GreetingText(s.greetingPolicy))
}

// pop3GreetingText renders the POP3 greeting text around the shared display identity.
func pop3GreetingText(policy greeting.Policy) string {
	return sanitizeResponseText(policy.DisplayIdentity(greeting.ProtocolPOP3) + " POP3 ready")
}

// writeOK writes one successful POP3 response line.
func (s *Session) writeOK(text string) error {
	return s.writeResponse(responseOK, text)
}

// writeERR writes one bounded POP3 failure response line.
func (s *Session) writeERR(text string) error {
	return s.writeResponse(responseERR, text)
}

// writeResponse writes one POP3 status response line.
func (s *Session) writeResponse(status string, text string) error {
	line := status
	if sanitized := sanitizeResponseText(text); sanitized != "" {
		line += " " + sanitized
	}

	_, err := fmt.Fprint(s.writer, line+"\r\n")

	return err
}

// writeMultilineOK writes an RFC-shaped POP3 multiline success response.
func (s *Session) writeMultilineOK(text string, lines []string) error {
	if err := s.writeOK(text); err != nil {
		return err
	}

	for _, line := range lines {
		if _, err := fmt.Fprint(s.writer, dotStuffLine(line)+"\r\n"); err != nil {
			return err
		}
	}

	_, err := fmt.Fprint(s.writer, ".\r\n")

	return err
}

// dotStuffLine prevents multiline response terminator injection.
func dotStuffLine(value string) string {
	value = sanitizeResponseText(value)
	if strings.HasPrefix(value, ".") {
		return "." + value
	}

	return value
}

// sanitizeResponseText removes response-injection controls and bounds text length.
func sanitizeResponseText(statusMessage string) string {
	sanitized := strings.TrimSpace(replaceControlCharacters(statusMessage))
	if sanitized == "" {
		return ""
	}

	sanitized = strings.Join(strings.Fields(sanitized), " ")
	if sanitized == "" {
		return ""
	}

	return truncateResponseText(sanitized, maxSafeResponseTextBytes)
}

// replaceControlCharacters removes response-injection controls from response text.
func replaceControlCharacters(value string) string {
	var builder strings.Builder
	builder.Grow(len(value))

	for _, current := range value {
		if current < 0x20 || current == 0x7f {
			builder.WriteByte(' ')

			continue
		}

		builder.WriteRune(current)
	}

	return builder.String()
}

// truncateResponseText bounds response text without splitting UTF-8 runes.
func truncateResponseText(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return strings.TrimSpace(value)
	}

	var builder strings.Builder
	builder.Grow(limit)

	for _, current := range value {
		width := utf8.RuneLen(current)
		if width < 0 {
			width = len(string(current))
		}

		if builder.Len()+width > limit {
			break
		}

		builder.WriteRune(current)
	}

	return strings.TrimSpace(builder.String())
}
