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

import "strings"

// CapabilityPolicy owns the listener-scoped LMTP allowlist and hard-deny rules.
type CapabilityPolicy struct {
	configured []string
	denied     map[string]struct{}
}

// NewCapabilityPolicy creates a deterministic listener capability policy.
func NewCapabilityPolicy(configured []string, denied []string) CapabilityPolicy {
	policy := CapabilityPolicy{
		configured: normalizeCapabilityList(configured),
		denied:     make(map[string]struct{}, len(denied)),
	}

	for _, capability := range normalizeCapabilityList(denied) {
		name := capabilityName(capability)
		if name == "" {
			continue
		}

		policy.denied[name] = struct{}{}
	}

	return policy
}

// ConfiguredCapabilities returns the normalized frontend allowlist in first-seen order.
func (p CapabilityPolicy) ConfiguredCapabilities() []string {
	return append([]string(nil), p.configured...)
}

// Denies reports whether the hard deny filter suppresses a capability.
func (p CapabilityPolicy) Denies(capability string) bool {
	name := capabilityName(capability)
	if name == "" || len(p.denied) == 0 {
		return false
	}

	_, ok := p.denied[name]

	return ok
}

// FilterBackendCapabilities removes listener-denied capability facts from backend proof input.
func (p CapabilityPolicy) FilterBackendCapabilities(capabilities []string) []string {
	filtered := make([]string, 0, len(capabilities))
	seen := make(map[string]struct{}, len(capabilities))

	for _, capability := range capabilities {
		normalized := normalizeCapability(capability)
		if normalized == "" || p.Denies(normalized) {
			continue
		}

		if _, exists := seen[normalized]; exists {
			continue
		}

		seen[normalized] = struct{}{}
		filtered = append(filtered, normalized)
	}

	return filtered
}

// normalizeCapabilityList returns canonical capability spellings without duplicates.
func normalizeCapabilityList(capabilities []string) []string {
	normalized := make([]string, 0, len(capabilities))
	seen := make(map[string]struct{}, len(capabilities))

	for _, capability := range capabilities {
		canonical := normalizeCapability(capability)
		if canonical == "" {
			continue
		}

		if _, exists := seen[canonical]; exists {
			continue
		}

		seen[canonical] = struct{}{}
		normalized = append(normalized, canonical)
	}

	return normalized
}

// normalizeCapability returns the stable LMTP wire spelling for one capability entry.
func normalizeCapability(capability string) string {
	fields := strings.Fields(strings.ToUpper(strings.TrimSpace(capability)))
	if len(fields) == 0 {
		return ""
	}

	if fields[0] == capabilityAUTH {
		mechanisms := normalizeCapabilityMechanisms(fields[1:])
		if len(mechanisms) == 0 {
			return capabilityAUTH
		}

		return capabilityAUTH + " " + strings.Join(mechanisms, " ")
	}

	return strings.Join(fields, " ")
}

// normalizeCapabilityMechanisms returns canonical AUTH mechanism tokens.
func normalizeCapabilityMechanisms(mechanisms []string) []string {
	normalized := make([]string, 0, len(mechanisms))
	seen := make(map[string]struct{}, len(mechanisms))

	for _, mechanism := range mechanisms {
		canonical := strings.ToUpper(strings.TrimSpace(mechanism))
		if canonical == "" {
			continue
		}

		if _, exists := seen[canonical]; exists {
			continue
		}

		seen[canonical] = struct{}{}
		normalized = append(normalized, canonical)
	}

	return normalized
}

// capabilityName returns the whole LMTP extension name for policy comparison.
func capabilityName(capability string) string {
	fields := strings.Fields(strings.ToUpper(strings.TrimSpace(capability)))
	if len(fields) == 0 {
		return ""
	}

	if strings.HasPrefix(fields[0], capabilityAUTH+"=") {
		return capabilityAUTH
	}

	return fields[0]
}
