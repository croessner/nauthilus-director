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

import "strings"

const (
	capabilityIMAP4Rev1 = "IMAP4rev1"
	capabilityID        = "ID"
	capabilitySASLIR    = "SASL-IR"
	capabilityStartTLS  = "STARTTLS"
)

// handleCapability writes a truthful CAPABILITY response for current transport state.
func (s *Session) handleCapability(command preauthCommand) error {
	if err := validateNoArguments(command); err != nil {
		return s.writeTagged(command.tag, responseBad, "Invalid CAPABILITY command")
	}

	if _, err := s.writer.WriteString("* CAPABILITY " + strings.Join(s.capabilities(), " ") + "\r\n"); err != nil {
		return err
	}

	return s.writeTagged(command.tag, responseOK, "CAPABILITY completed")
}

// capabilities returns the implemented pre-auth capability set in stable wire order.
func (s *Session) capabilities() []string {
	capabilities := []string{capabilityIMAP4Rev1, capabilityID, capabilitySASLIR}
	if s.startTLSAdvertised() {
		capabilities = append(capabilities, capabilityStartTLS)
	}

	for _, mechanism := range s.context.AuthMechanisms {
		normalized := strings.ToUpper(strings.TrimSpace(mechanism))
		if normalized == "" {
			continue
		}

		if supportedPreauthAuthMechanism(normalized) {
			capabilities = append(capabilities, "AUTH="+normalized)
		}
	}

	return capabilities
}

// supportedPreauthAuthMechanism reports whether command handling accepts the mechanism shape.
func supportedPreauthAuthMechanism(mechanism string) bool {
	switch strings.ToUpper(strings.TrimSpace(mechanism)) {
	case "PLAIN", "XOAUTH2", "OAUTHBEARER":
		return true
	default:
		return false
	}
}
