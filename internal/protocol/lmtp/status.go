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
	"fmt"
	"strconv"
	"strings"

	"github.com/croessner/nauthilus-director/internal/backend"
)

const (
	backendResponseFinalSeparator = ' '
	backendResponseMoreSeparator  = '-'
)

const (
	backendDeliveryAcceptedText  = "Message accepted"
	backendDeliveryPermanentText = "Message delivery permanently failed"
	backendDeliveryTemporaryText = "Message delivery temporarily failed"
	backendRecipientRejectText   = "Recipient rejected by backend"
	backendRecipientTempfailText = "Recipient temporarily rejected by backend"
	backendReplyContextBDAT      = "bdat"
	backendReplyContextFinal     = "final"
	backendReplyContextRecipient = "rcpt"
)

type backendStatusLine struct {
	code      string
	separator byte
	text      string
}

type backendStatusResponse struct {
	code  string
	lines []string
}

// DeliveryStatus is a sanitized frontend reply for one accepted recipient.
type DeliveryStatus struct {
	Status   string
	Enhanced string
	Text     string
}

// readBackendStatusResponse reads one bounded SMTP-style multiline response.
func readBackendStatusResponse(reader *bufio.Reader) (backendStatusResponse, error) {
	var response backendStatusResponse

	for len(response.lines) < backendResponseLineLimit {
		line, err := readBackendStatusLine(reader)
		if err != nil {
			return backendStatusResponse{}, err
		}

		if response.code == "" {
			response.code = line.code
		}

		if line.code != response.code {
			return backendStatusResponse{}, fmt.Errorf("%w: mixed response status codes", ErrBackendProtocol)
		}

		response.lines = append(response.lines, line.text)
		if line.separator == backendResponseFinalSeparator {
			return response, nil
		}
	}

	return backendStatusResponse{}, fmt.Errorf("%w: backend response line count exceeded", ErrBackendProtocol)
}

// readBackendStatusLine reads and parses one bounded SMTP-style response line.
func readBackendStatusLine(reader *bufio.Reader) (backendStatusLine, error) {
	line, err := reader.ReadString('\n')
	if len(line) > backendLineLimitBytes {
		return backendStatusLine{}, fmt.Errorf("%w: backend line too large", ErrBackendProtocol)
	}

	if err != nil {
		return backendStatusLine{}, fmt.Errorf("%w: read response", ErrBackendProtocol)
	}

	return parseBackendStatusLine(line)
}

// parseBackendStatusLine converts one status line without interpreting message text.
func parseBackendStatusLine(line string) (backendStatusLine, error) {
	line = strings.TrimRight(line, "\r\n")
	if len(line) < 4 {
		return backendStatusLine{}, fmt.Errorf("%w: short status line", ErrBackendProtocol)
	}

	code := line[:3]
	if _, err := strconv.Atoi(code); err != nil {
		return backendStatusLine{}, fmt.Errorf("%w: malformed status code", ErrBackendProtocol)
	}

	separator := line[3]
	if separator != backendResponseFinalSeparator && separator != backendResponseMoreSeparator {
		return backendStatusLine{}, fmt.Errorf("%w: malformed status separator", ErrBackendProtocol)
	}

	return backendStatusLine{
		code:      code,
		separator: separator,
		text:      strings.TrimSpace(line[4:]),
	}, nil
}

// statusOK reports whether a response has the exact expected status.
func (r backendStatusResponse) statusOK(status string) bool {
	return r.code == status
}

// deliveryStatusFromBackend maps a known backend reply to a safe frontend status.
func deliveryStatusFromBackend(response backendStatusResponse, replyContext string) DeliveryStatus {
	code := strings.TrimSpace(response.code)
	if len(code) != 3 {
		return unknownDeliveryStatus()
	}

	switch code[0] {
	case '2':
		return DeliveryStatus{
			Status:   responseStatusOK,
			Enhanced: backendEnhancedStatus(response, enhancedOK, '2'),
			Text:     backendDeliveryAcceptedText,
		}
	case '4':
		return DeliveryStatus{
			Status:   code,
			Enhanced: backendEnhancedStatus(response, enhancedTemporary, '4'),
			Text:     backendTemporaryText(replyContext),
		}
	case '5':
		return DeliveryStatus{
			Status:   code,
			Enhanced: backendEnhancedStatus(response, enhancedMailboxReject, '5'),
			Text:     backendPermanentText(replyContext),
		}
	default:
		return unknownDeliveryStatus()
	}
}

// unknownDeliveryStatus returns the director-owned result for unknown final outcomes.
func unknownDeliveryStatus() DeliveryStatus {
	return DeliveryStatus{
		Status:   responseStatusTemporary,
		Enhanced: enhancedTemporary,
		Text:     backendDeliveryTemporaryText,
	}
}

// backendTemporaryText selects safe text for backend temporary replies.
func backendTemporaryText(replyContext string) string {
	if replyContext == backendReplyContextRecipient {
		return backendRecipientTempfailText
	}

	return backendDeliveryTemporaryText
}

// backendPermanentText selects safe text for backend permanent replies.
func backendPermanentText(replyContext string) string {
	if replyContext == backendReplyContextRecipient {
		return backendRecipientRejectText
	}

	return backendDeliveryPermanentText
}

// backendEnhancedStatus preserves a safe enhanced status code when present.
func backendEnhancedStatus(response backendStatusResponse, fallback string, class byte) string {
	for _, line := range response.lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		if validEnhancedStatus(fields[0], class) {
			return fields[0]
		}
	}

	return fallback
}

// validEnhancedStatus recognizes bounded RFC-style enhanced status codes.
func validEnhancedStatus(value string, class byte) bool {
	if len(value) < 5 || value[0] != class || value[1] != '.' {
		return false
	}

	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}

	for _, part := range parts {
		if part == "" || len(part) > 3 {
			return false
		}

		for index := 0; index < len(part); index++ {
			if part[index] < '0' || part[index] > '9' {
				return false
			}
		}
	}

	return true
}

// lmtpCapabilitiesFromLHLO extracts extension keywords from a backend LHLO response.
func lmtpCapabilitiesFromLHLO(response backendStatusResponse) backend.CapabilitySet {
	var capabilities backend.CapabilitySet

	for index, line := range response.lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		keyword := strings.ToUpper(fields[0])
		if index == 0 && !knownLHLOCapability(keyword) {
			continue
		}

		switch keyword {
		case capabilityAUTH:
			capabilities.Add(capabilityAUTH)

			for _, mechanism := range fields[1:] {
				capabilities.Add(capabilityAUTH + "=" + mechanism)
			}
		default:
			capabilities.Add(keyword)
		}
	}

	return capabilities
}

// knownLHLOCapability recognizes extension keywords without trusting prose text.
func knownLHLOCapability(keyword string) bool {
	switch strings.ToUpper(strings.TrimSpace(keyword)) {
	case "8BITMIME", capabilityAUTH, capabilityCHUNKING, "ENHANCEDSTATUSCODES", "PIPELINING", "SIZE", capabilitySMTPUTF8, capabilitySTARTTLS:
		return true
	default:
		return strings.HasPrefix(keyword, capabilityAUTH+"=")
	}
}
