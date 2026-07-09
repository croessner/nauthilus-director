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

// Package greeting owns protocol-neutral public greeting identity policy.
package greeting

import (
	"errors"
	"strings"
	"unicode"
)

const (
	// DefaultDisplayName is the safe public product identity used when no explicit identity is available.
	DefaultDisplayName = "nauthilus-director"

	// ProtocolIMAP names the IMAP frontend protocol for disclosure decisions.
	ProtocolIMAP = "imap"
	// ProtocolLMTP names the LMTP frontend protocol for disclosure decisions.
	ProtocolLMTP = "lmtp"
	// ProtocolSieve names the ManageSieve frontend protocol for disclosure decisions.
	ProtocolSieve = "sieve"
	// ProtocolPOP3 names the POP3 frontend protocol for disclosure decisions.
	ProtocolPOP3 = "pop3"

	maxDisplayNameBytes = 64
)

// SoftwareVersionDisclosure describes whether a frontend identity may include the process version.
type SoftwareVersionDisclosure string

const (
	// DisclosureDefault preserves each protocol's compatible version-disclosure behavior.
	DisclosureDefault SoftwareVersionDisclosure = "default"
	// DisclosureInclude explicitly publishes the normalized process version for known frontend protocols.
	DisclosureInclude SoftwareVersionDisclosure = "include"
	// DisclosureSuppress hides the process version for every frontend protocol.
	DisclosureSuppress SoftwareVersionDisclosure = "suppress"
)

// NewSoftwareVersionDisclosure normalizes operator policy text into a bounded enum.
func NewSoftwareVersionDisclosure(value string) (SoftwareVersionDisclosure, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", string(DisclosureDefault):
		return DisclosureDefault, nil
	case string(DisclosureInclude):
		return DisclosureInclude, nil
	case string(DisclosureSuppress):
		return DisclosureSuppress, nil
	default:
		return "", errors.New("greeting software version disclosure must be default, include, or suppress")
	}
}

// DisplayName is an immutable public identity value prepared for protocol renderers.
type DisplayName struct {
	value string
}

// NewDisplayName stores a non-empty public display identity after safe whitespace normalization.
func NewDisplayName(value string) (DisplayName, error) {
	normalized := normalizeDisplayName(value)
	if normalized == "" {
		return DisplayName{}, errors.New("greeting display name is required")
	}

	if len(normalized) > maxDisplayNameBytes {
		return DisplayName{}, errors.New("greeting display name is too long")
	}

	if !validDisplayName(normalized) {
		return DisplayName{}, errors.New("greeting display name contains unsupported characters")
	}

	return DisplayName{value: normalized}, nil
}

// NewDisplayNameOrDefault stores a public identity and falls back to the safe product name when blank.
func NewDisplayNameOrDefault(value string) (DisplayName, error) {
	if normalizeDisplayName(value) == "" {
		return DisplayName{value: DefaultDisplayName}, nil
	}

	return NewDisplayName(value)
}

// String returns the normalized public identity with a safe fallback for zero values.
func (d DisplayName) String() string {
	if d.value == "" {
		return DefaultDisplayName
	}

	return d.value
}

// Policy combines display identity and version-disclosure decisions for protocol renderers.
type Policy struct {
	displayName     DisplayName
	softwareVersion string
	disclosure      SoftwareVersionDisclosure
}

// NewPolicy builds an immutable greeting policy from already decoded listener settings.
func NewPolicy(displayName DisplayName, processVersion string, disclosure SoftwareVersionDisclosure) (Policy, error) {
	normalizedDisclosure, err := NewSoftwareVersionDisclosure(string(disclosure))
	if err != nil {
		return Policy{}, err
	}

	return Policy{
		displayName:     displayName,
		softwareVersion: normalizeSoftwareVersion(processVersion),
		disclosure:      normalizedDisclosure,
	}, nil
}

// DisplayName returns the public identity without protocol wire syntax.
func (p Policy) DisplayName() string {
	return p.displayName.String()
}

// SoftwareVersion returns the normalized process version, or an empty string when no version is available.
func (p Policy) SoftwareVersion() string {
	return p.softwareVersion
}

// Disclosure returns the normalized version-disclosure mode.
func (p Policy) Disclosure() SoftwareVersionDisclosure {
	if p.disclosure == "" {
		return DisclosureDefault
	}

	return p.disclosure
}

// IncludeSoftwareVersion reports whether the known frontend protocol may publish the process version.
func (p Policy) IncludeSoftwareVersion(protocol string) bool {
	if p.softwareVersion == "" {
		return false
	}

	switch p.Disclosure() {
	case DisclosureInclude:
		return knownProtocol(protocol)
	case DisclosureSuppress:
		return false
	case DisclosureDefault:
		return defaultIncludesVersion(protocol)
	default:
		return false
	}
}

// DisplayIdentity returns the protocol-neutral display identity for protocol-local renderers.
func (p Policy) DisplayIdentity(protocol string) string {
	identity := p.DisplayName()
	if !p.IncludeSoftwareVersion(protocol) {
		return identity
	}

	return identity + " " + p.softwareVersion
}

// normalizeProtocol canonicalizes the explicit frontend protocol vocabulary.
func normalizeProtocol(protocol string) string {
	return strings.ToLower(strings.TrimSpace(protocol))
}

// knownProtocol reports whether the protocol name is one of the supported frontend protocol facts.
func knownProtocol(protocol string) bool {
	switch normalizeProtocol(protocol) {
	case ProtocolIMAP, ProtocolLMTP, ProtocolSieve, ProtocolPOP3:
		return true
	default:
		return false
	}
}

// defaultIncludesVersion captures compatible per-protocol disclosure defaults.
func defaultIncludesVersion(protocol string) bool {
	return normalizeProtocol(protocol) == ProtocolSieve
}

// normalizeDisplayName folds whitespace and removes multiline/control surfaces from display identity input.
func normalizeDisplayName(value string) string {
	return foldPublicText(value)
}

// normalizeSoftwareVersion folds whitespace and strips controls before a version reaches protocol renderers.
func normalizeSoftwareVersion(value string) string {
	return foldPublicText(value)
}

// foldPublicText converts whitespace and controls to single spaces without exposing multiline text.
func foldPublicText(value string) string {
	var builder strings.Builder
	builder.Grow(len(value))

	for _, current := range value {
		if unicode.IsSpace(current) || unicode.IsControl(current) {
			builder.WriteByte(' ')

			continue
		}

		builder.WriteRune(current)
	}

	return strings.Join(strings.Fields(builder.String()), " ")
}

// validDisplayName applies the conservative public identity grammar shared by frontend protocols.
func validDisplayName(value string) bool {
	if displayNameLooksLikeStatus(value) {
		return false
	}

	for index := 0; index < len(value); index++ {
		if !validDisplayNameByte(value[index]) {
			return false
		}
	}

	return true
}

// validDisplayNameByte reports whether one byte is safe in a public display identity.
func validDisplayNameByte(value byte) bool {
	switch {
	case value >= 'a' && value <= 'z':
		return true
	case value >= 'A' && value <= 'Z':
		return true
	case value >= '0' && value <= '9':
		return true
	case value == ' ' || value == '.' || value == '_' || value == '-':
		return true
	default:
		return false
	}
}

// displayNameLooksLikeStatus rejects leading status fragments before protocol-local rendering.
func displayNameLooksLikeStatus(value string) bool {
	if len(value) < 3 {
		return false
	}

	if value[0] < '0' ||
		value[0] > '9' ||
		value[1] < '0' ||
		value[1] > '9' ||
		value[2] < '0' ||
		value[2] > '9' {
		return false
	}

	return len(value) == 3 || value[3] == ' ' || value[3] == '-'
}
