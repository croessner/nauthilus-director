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
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	responseOK = "OK"
	responseNO = "NO"

	codeAuthFailed    = "AUTHENTICATIONFAILED"
	codeClientBug     = "CLIENT-BUG"
	codeEncryptNeeded = "ENCRYPT-NEEDED"
	codeTryLater      = "TRYLATER"
	codeUnsupported   = "UNSUPPORTED"

	genericAuthFailedText    = "Authentication failed"
	maxSafeResponseTextBytes = 512
	maxSafeCapabilityBytes   = 1024
)

// writeOK writes one successful ManageSieve response.
func (s *Session) writeOK(text string) error {
	return s.writeResponse(responseOK, "", text)
}

// writeNo writes one bounded ManageSieve failure response.
func (s *Session) writeNo(code string, text string) error {
	return s.writeResponse(responseNO, code, text)
}

// writeResponse writes a response condition with an optional response code and text.
func (s *Session) writeResponse(condition string, code string, text string) error {
	line := condition
	if code != "" {
		line += " (" + sanitizeResponseCode(code) + ")"
	}

	if sanitized := sanitizeResponseText(text); sanitized != "" {
		line += " " + quoteString(sanitized)
	}

	_, err := fmt.Fprint(s.writer, line+"\r\n")

	return err
}

// quoteString renders a bounded ManageSieve quoted string.
func quoteString(value string) string {
	value = truncateResponseText(replaceControlCharacters(value), maxSafeCapabilityBytes)

	var builder strings.Builder
	builder.Grow(len(value) + 2)
	builder.WriteByte('"')

	for _, current := range value {
		switch current {
		case '\\', '"':
			builder.WriteByte('\\')
			builder.WriteRune(current)
		default:
			builder.WriteRune(current)
		}
	}

	builder.WriteByte('"')

	return builder.String()
}

// sanitizeResponseCode restricts response codes to stable protocol reason classes.
func sanitizeResponseCode(code string) string {
	normalized := strings.ToUpper(strings.TrimSpace(code))
	switch normalized {
	case codeAuthFailed, codeClientBug, codeEncryptNeeded, codeTryLater, codeUnsupported:
		return normalized
	default:
		return codeClientBug
	}
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
