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
	"strings"
	"unicode/utf8"
)

const (
	responseBad = "BAD"
	responseNo  = "NO"
	responseOK  = "OK"

	authFailedCode                 = "[AUTHENTICATIONFAILED]"
	authUnavailableText            = "[UNAVAILABLE] Authentication service temporarily unavailable"
	genericAuthFailText            = "Authentication failed"
	authSuccessText                = "Authentication completed"
	maxRejectedStatusTextBytes     = 512
	maxRejectedStatusResponseBytes = 1024
)

// rejectedAuthResponseText builds the authority-owned rejected response text safely.
func rejectedAuthResponseText(statusMessage string) string {
	return authFailedCode + " " + sanitizeRejectedStatusText(statusMessage)
}

// sanitizeRejectedStatusText applies IMAP framing hygiene without adding local policy text.
func sanitizeRejectedStatusText(statusMessage string) string {
	sanitized := strings.TrimSpace(replaceControlCharacters(statusMessage))
	if sanitized == "" {
		return genericAuthFailText
	}

	sanitized = strings.Join(strings.Fields(sanitized), " ")
	if sanitized == "" {
		return genericAuthFailText
	}

	sanitized = truncateResponseText(sanitized, maxRejectedStatusTextBytes)
	if sanitized == "" {
		return genericAuthFailText
	}

	return sanitized
}

// replaceControlCharacters removes response-injection controls from authority text.
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
	if len(value) <= limit {
		return value
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
