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

package config

import "strings"

const (
	fallbackDefaultShard            = "default"
	defaultRoutingTenantAttribute   = "tenant"
	defaultRoutingShardTagAttribute = "mailShard"
	lmtpCapabilityAuth              = "AUTH"
)

// Normalize returns a config snapshot with derived runtime defaults applied.
func (c Config) Normalize() Config {
	c.Director = c.Director.Normalize()

	return c
}

// Normalize returns director config with non-empty effective backend shard tags.
func (d DirectorConfig) Normalize() DirectorConfig {
	d.Routing.DefaultShard = d.Routing.EffectiveDefaultShard()
	d.Routing.AuthAttributes = d.Routing.AuthAttributes.Normalize()

	if d.Listeners != nil {
		listeners := make(map[string]ListenerConfig, len(d.Listeners))
		for name, listener := range d.Listeners {
			listener.Protocol = strings.ToLower(strings.TrimSpace(listener.Protocol))
			listener.TLS.Mode = strings.ToLower(strings.TrimSpace(listener.TLS.Mode))

			if listener.LMTP != nil {
				lmtp := *listener.LMTP
				lmtp.Capabilities = normalizeLMTPCapabilities(lmtp.Capabilities)
				lmtp.ClientAuth.Authority = strings.TrimSpace(lmtp.ClientAuth.Authority)
				lmtp.ClientAuth.Mechanisms = normalizeLowerList(lmtp.ClientAuth.Mechanisms)
				lmtp.ClientAuth.MTLS.IdentitySource = strings.ToLower(strings.TrimSpace(lmtp.ClientAuth.MTLS.IdentitySource))
				listener.LMTP = &lmtp
			}

			listeners[name] = listener
		}

		d.Listeners = listeners
	}

	if d.Backends == nil {
		return d
	}

	backends := make(map[string]BackendConfig, len(d.Backends))
	for name, backend := range d.Backends {
		backend.ShardTag = strings.TrimSpace(backend.ShardTag)
		if backend.ShardTag == "" {
			backend.ShardTag = d.Routing.DefaultShard
		}

		backends[name] = backend
	}

	d.Backends = backends

	return d
}

// Normalize returns routing auth-attribute names with stable defaults applied.
func (r RoutingAuthAttributesConfig) Normalize() RoutingAuthAttributesConfig {
	r.Tenant = strings.TrimSpace(r.Tenant)
	if r.Tenant == "" {
		r.Tenant = defaultRoutingTenantAttribute
	}

	r.ShardTag = strings.TrimSpace(r.ShardTag)
	if r.ShardTag == "" {
		r.ShardTag = defaultRoutingShardTagAttribute
	}

	return r
}

// normalizeLMTPCapabilities converts configured LMTP capability strings into stable wire forms.
func normalizeLMTPCapabilities(capabilities []string) []string {
	normalized := make([]string, 0, len(capabilities))
	seen := make(map[string]struct{}, len(capabilities))

	for _, capability := range capabilities {
		canonical := normalizeLMTPCapability(capability)
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

// normalizeLMTPCapability converts one configured LMTP capability into its wire spelling.
func normalizeLMTPCapability(capability string) string {
	fields := strings.Fields(strings.ToUpper(strings.TrimSpace(capability)))
	if len(fields) == 0 {
		return ""
	}

	if fields[0] == lmtpCapabilityAuth {
		mechanisms := normalizeUpperList(fields[1:])
		if len(mechanisms) == 0 {
			return lmtpCapabilityAuth
		}

		return lmtpCapabilityAuth + " " + strings.Join(mechanisms, " ")
	}

	return strings.Join(fields, " ")
}

// normalizeLowerList trims, lower-cases and de-duplicates configured names.
func normalizeLowerList(values []string) []string {
	return normalizeStringList(values, strings.ToLower)
}

// normalizeUpperList trims, upper-cases and de-duplicates configured names.
func normalizeUpperList(values []string) []string {
	return normalizeStringList(values, strings.ToUpper)
}

// normalizeStringList trims, canonicalizes and de-duplicates configured names.
func normalizeStringList(values []string, canonicalize func(string) string) []string {
	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))

	for _, value := range values {
		canonical := canonicalize(strings.TrimSpace(value))
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

// EffectiveDefaultShard returns the non-empty routing fallback shard.
func (r RoutingConfig) EffectiveDefaultShard() string {
	shard := strings.TrimSpace(r.DefaultShard)
	if shard == "" {
		return fallbackDefaultShard
	}

	return shard
}
