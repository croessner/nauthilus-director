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
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	responseStatusOK              = "250"
	responseStatusReady           = "220"
	responseStatusClosing         = "221"
	responseStatusAuthSuccess     = "235"
	responseStatusAuthContinue    = "334"
	responseStatusDataContinue    = "354"
	responseStatusTemporary       = "451"
	responseStatusMailboxReject   = "550"
	responseStatusAuthUnavailable = "454"
	responseStatusSyntax          = "500"
	responseStatusParameter       = "501"
	responseStatusUnavailable     = "502"
	responseStatusBadSequence     = "503"
	responseStatusAuthRequired    = "530"
	responseStatusAuthRejected    = "535"

	enhancedOK               = "2.0.0"
	enhancedAuthOK           = "2.7.0"
	enhancedClosing          = "2.0.0"
	enhancedTemporary        = "4.3.0"
	enhancedDifferentBackend = "4.3.2"
	enhancedMailboxReject    = "5.1.1"
	enhancedAuthUnavailable  = "4.7.0"
	enhancedSyntax           = "5.5.2"
	enhancedParameter        = "5.5.4"
	enhancedUnavailable      = "5.5.1"
	enhancedBadSequence      = "5.5.1"
	enhancedAuthRequired     = "5.7.0"
	enhancedAuthRejected     = "5.7.8"

	maxResponseTextBytes = 256
)

const (
	greetingText             = "nauthilus-director LMTP ready"
	authContinueText         = ""
	authRejectedText         = "Authentication credentials invalid"
	authRequiredText         = "Authentication required"
	authSuccessText          = "Authentication successful"
	authUnavailableText      = "Authentication service temporarily unavailable"
	badSequenceLHLOText      = "Send LHLO first"
	badSequenceMailText      = "Send MAIL first"
	badSequenceRecipientText = "Need recipient before message body"
	bdatChunkAcceptedText    = "BDAT chunk accepted"
	commandSyntaxText        = "Command syntax error"
	dataContinueText         = "End data with <CR><LF>.<CR><LF>"
	dataQueuedText           = "Message accepted"
	differentBackendText     = "Recipient must be retried separately"
	lhloDomainText           = "nauthilus-director"
	malformedAuthText        = "Invalid AUTH command"
	malformedBDATText        = "Invalid BDAT command"
	malformedMailText        = "Invalid MAIL command"
	malformedRcptText        = "Invalid RCPT command"
	recipientLookupText      = "Recipient lookup temporarily unavailable"
	noTLSAuthText            = "Must issue STARTTLS first"
	noopText                 = "OK"
	quitText                 = "Bye"
	rsetText                 = "Transaction reset"
	startTLSText             = "Ready to start TLS"
	startTLSUnavailableText  = "STARTTLS is not available"
	unsupportedText          = "Command not implemented"
)

// writeEnhanced writes one LMTP response line with an enhanced status code.
func (s *Session) writeEnhanced(status string, enhanced string, text string) error {
	_, err := fmt.Fprintf(s.writer, "%s %s %s\r\n", status, enhanced, sanitizeResponseText(text))

	return err
}

// writePlain writes one LMTP response line without an enhanced status code.
func (s *Session) writePlain(status string, text string) error {
	if strings.TrimSpace(text) == "" {
		_, err := fmt.Fprintf(s.writer, "%s \r\n", status)

		return err
	}

	_, err := fmt.Fprintf(s.writer, "%s %s\r\n", status, sanitizeResponseText(text))

	return err
}

// writeGreeting sends the initial protocol greeting.
func (s *Session) writeGreeting() error {
	return s.writeEnhanced(responseStatusReady, enhancedOK, greetingText)
}

// writeLHLO writes a deterministic multiline capability response.
func (s *Session) writeLHLO(capabilities []string) error {
	if len(capabilities) == 0 {
		return s.writePlain(responseStatusOK, lhloDomainText)
	}

	if _, err := fmt.Fprintf(s.writer, "%s-%s\r\n", responseStatusOK, lhloDomainText); err != nil {
		return err
	}

	for index, capability := range capabilities {
		separator := "-"
		if index == len(capabilities)-1 {
			separator = " "
		}

		if _, err := fmt.Fprintf(s.writer, "%s%s%s\r\n", responseStatusOK, separator, capability); err != nil {
			return err
		}
	}

	return nil
}

// sanitizeResponseText prevents response injection and bounds locally generated status text.
func sanitizeResponseText(value string) string {
	cleaned := strings.TrimSpace(replaceResponseControls(value))
	if cleaned == "" {
		return "OK"
	}

	cleaned = strings.Join(strings.Fields(cleaned), " ")

	return truncateResponseText(cleaned, maxResponseTextBytes)
}

// replaceResponseControls maps control characters to spaces before wire output.
func replaceResponseControls(value string) string {
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

// truncateResponseText bounds a response string without splitting UTF-8.
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
