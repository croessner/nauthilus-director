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
	"slices"
	"strings"

	"github.com/croessner/nauthilus-director/internal/protocol/saslcred"
)

const (
	capabilityImplementation = "IMPLEMENTATION"
	capabilityLanguage       = "LANGUAGE"
	capabilityOwner          = "OWNER"
	capabilitySASL           = "SASL"
	capabilitySieve          = "SIEVE"
	capabilityStartTLS       = "STARTTLS"
	capabilityVersion        = "VERSION"
)

type capabilityLine struct {
	name     string
	value    string
	hasValue bool
}

// writeCapabilityGreeting sends the initial RFC 5804-shaped capability greeting.
func (s *Session) writeCapabilityGreeting() error {
	if err := s.writeCapabilityLines(); err != nil {
		return err
	}

	return s.writeOK("")
}

// handleCapability writes a truthful capability response for the current transport state.
func (s *Session) handleCapability(command preauthCommand) error {
	if err := validateNoArguments(command); err != nil {
		return s.writeNo(codeClientBug, "Invalid CAPABILITY command")
	}

	if err := s.writeCapabilityLines(); err != nil {
		return err
	}

	return s.writeOK("Capability completed")
}

// writeAuthenticatedCapabilityResponse sends the RFC 5804 capability update after AUTHENTICATE.
func (s *Session) writeAuthenticatedCapabilityResponse(owner string) error {
	for _, capability := range s.authenticatedCapabilityLines(owner) {
		if _, err := s.writer.WriteString(renderCapabilityLine(capability)); err != nil {
			return err
		}
	}

	return s.writeOK("Authentication successful")
}

// writeCapabilityLines writes every effective capability line in stable order.
func (s *Session) writeCapabilityLines() error {
	for _, capability := range s.capabilityLines() {
		if _, err := s.writer.WriteString(renderCapabilityLine(capability)); err != nil {
			return err
		}
	}

	return nil
}

// capabilityLines returns the effective pre-auth capability set in stable wire order.
func (s *Session) capabilityLines() []capabilityLine {
	lines := []capabilityLine{
		{name: capabilityImplementation, value: s.implementationCapability(), hasValue: true},
		{name: capabilityVersion, value: s.protocolVersionCapability(), hasValue: true},
		{name: capabilitySieve, value: strings.Join(s.safeScriptExtensions(), " "), hasValue: true},
	}

	if language := strings.TrimSpace(s.capabilities.Language); language != "" {
		lines = append(lines, capabilityLine{name: capabilityLanguage, value: language, hasValue: true})
	}

	if s.startTLSAdvertised() {
		lines = append(lines, capabilityLine{name: capabilityStartTLS})
	}

	if s.authConfigured() {
		lines = append(lines, capabilityLine{name: capabilitySASL, value: strings.Join(s.effectiveSASLMechanisms(), " "), hasValue: true})
	}

	return lines
}

// authenticatedCapabilityLines returns capabilities that are safe after successful authentication.
func (s *Session) authenticatedCapabilityLines(owner string) []capabilityLine {
	lines := make([]capabilityLine, 0, len(s.capabilityLines())+1)
	for _, capability := range s.capabilityLines() {
		if capability.name == capabilityStartTLS {
			continue
		}

		lines = append(lines, capability)
		if capability.name == capabilityLanguage {
			if owner = strings.TrimSpace(owner); owner != "" {
				lines = append(lines, capabilityLine{name: capabilityOwner, value: owner, hasValue: true})
			}
		}
	}

	if owner = strings.TrimSpace(owner); owner != "" && !capabilityLinePresent(lines, capabilityOwner) {
		lines = append(lines, capabilityLine{name: capabilityOwner, value: owner, hasValue: true})
	}

	return lines
}

// capabilityLinePresent reports whether a capability line is already rendered.
func capabilityLinePresent(lines []capabilityLine, name string) bool {
	return slices.ContainsFunc(lines, func(line capabilityLine) bool {
		return line.name == name
	})
}

// implementationCapability returns the internal IMPLEMENTATION value with a safe fallback.
func (s *Session) implementationCapability() string {
	if value := strings.TrimSpace(s.capabilities.Implementation); value != "" {
		return value
	}

	return ImplementationName
}

// protocolVersionCapability returns the RFC 5804 VERSION value with a safe fallback.
func (s *Session) protocolVersionCapability() string {
	if value := strings.TrimSpace(s.capabilities.ProtocolVersion); value != "" {
		return value
	}

	return ProtocolVersionRFC5804
}

// safeScriptExtensions returns de-duplicated configured SIEVE extension tokens.
func (s *Session) safeScriptExtensions() []string {
	extensions := make([]string, 0, len(s.capabilities.ScriptExtensions))

	seen := make(map[string]struct{}, len(s.capabilities.ScriptExtensions))
	for _, configured := range s.capabilities.ScriptExtensions {
		extension := strings.ToLower(strings.TrimSpace(configured))
		if extension == "" {
			continue
		}

		if _, exists := seen[extension]; exists {
			continue
		}

		seen[extension] = struct{}{}
		extensions = append(extensions, extension)
	}

	return extensions
}

// authConfigured reports whether this listener has any supported auth mechanism configured.
func (s *Session) authConfigured() bool {
	return slices.ContainsFunc(s.authMechanisms, func(mechanism string) bool {
		_, err := saslcred.NewMechanism(mechanism)

		return err == nil
	})
}

// effectiveSASLMechanisms returns mechanisms that may truthfully be used now.
func (s *Session) effectiveSASLMechanisms() []string {
	if !s.tlsActive {
		return nil
	}

	mechanisms := make([]string, 0, len(s.authMechanisms))

	seen := make(map[string]struct{}, len(s.authMechanisms))
	for _, configured := range s.authMechanisms {
		mechanism, err := saslcred.NewMechanism(configured)
		if err != nil {
			continue
		}

		key := mechanism.Normalized()
		if _, exists := seen[key]; exists {
			continue
		}

		seen[key] = struct{}{}

		mechanisms = append(mechanisms, mechanism.WireName())
	}

	return mechanisms
}

// authMechanismConfigured reports whether listener config accepts the normalized mechanism.
func (s *Session) authMechanismConfigured(mechanism string) bool {
	for _, configured := range s.authMechanisms {
		if strings.EqualFold(strings.TrimSpace(configured), mechanism) {
			return true
		}
	}

	return false
}

// authMechanismAdvertised reports whether AUTHENTICATE may use a mechanism now.
func (s *Session) authMechanismAdvertised(mechanism string) bool {
	for _, advertised := range s.effectiveSASLMechanisms() {
		if strings.EqualFold(advertised, mechanism) {
			return true
		}
	}

	return false
}

// renderCapabilityLine renders one capability as quoted ManageSieve strings.
func renderCapabilityLine(capability capabilityLine) string {
	if capability.hasValue {
		return quoteString(capability.name) + " " + quoteString(capability.value) + "\r\n"
	}

	return quoteString(capability.name) + "\r\n"
}
