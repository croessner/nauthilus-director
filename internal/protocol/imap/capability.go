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
	capabilities := make([]string, 0, len(s.context.Capabilities))
	seen := make(map[string]struct{}, len(s.context.Capabilities))

	for _, configured := range s.context.Capabilities {
		capability := s.effectiveCapability(configured)
		if capability == "" {
			continue
		}

		key := strings.ToUpper(capability)
		if _, exists := seen[key]; exists {
			continue
		}

		seen[key] = struct{}{}

		capabilities = append(capabilities, capability)
	}

	return capabilities
}

// effectiveCapability returns one configured capability only when safe now.
func (s *Session) effectiveCapability(configured string) string {
	normalized := strings.ToUpper(strings.TrimSpace(configured))
	switch {
	case normalized == "IMAP4REV1":
		return capabilityIMAP4Rev1
	case normalized == capabilityID:
		return capabilityID
	case normalized == capabilitySASLIR:
		return capabilitySASLIR
	case normalized == capabilityStartTLS:
		if s.startTLSPermitted() {
			return capabilityStartTLS
		}

		return ""
	case strings.HasPrefix(normalized, "AUTH="):
		mechanism := strings.TrimPrefix(normalized, "AUTH=")
		if supportedPreauthAuthMechanism(mechanism) && s.supportsAuthMechanism(mechanism) {
			return "AUTH=" + strings.ToUpper(mechanism)
		}
	}

	return ""
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

// configuredCapability reports whether the listener configured a capability token.
func (s *Session) configuredCapability(capability string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(capability))
	for _, configured := range s.context.Capabilities {
		if strings.ToUpper(strings.TrimSpace(configured)) == normalized {
			return true
		}
	}

	return false
}

// authMechanismAdvertised reports whether AUTHENTICATE may use a mechanism now.
func (s *Session) authMechanismAdvertised(mechanism string) bool {
	normalized := "AUTH=" + strings.ToUpper(strings.TrimSpace(mechanism))
	for _, capability := range s.capabilities() {
		if strings.ToUpper(capability) == normalized {
			return true
		}
	}

	return false
}

// saslIRAdvertised reports whether initial responses are enabled for AUTHENTICATE.
func (s *Session) saslIRAdvertised() bool {
	for _, capability := range s.capabilities() {
		if strings.EqualFold(capability, capabilitySASLIR) {
			return true
		}
	}

	return false
}
