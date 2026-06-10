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

import (
	"net/http"
	"sort"
	"strings"
)

const (
	fallbackDefaultShard            = "default"
	defaultRoutingTenantAttribute   = "tenant"
	defaultRoutingShardTagAttribute = "mailShard"
	lmtpCapabilityAuth              = "AUTH"
)

// Normalize returns a config snapshot with derived runtime defaults applied.
func (c Config) Normalize() Config {
	c.Auth = c.Auth.Normalize()
	c.Director = c.Director.Normalize()

	return c
}

// Normalize returns auth config with stable authority mechanism vocabulary.
func (a AuthConfig) Normalize() AuthConfig {
	if a.Authorities == nil {
		return a
	}

	authorities := make(map[string]AuthorityConfig, len(a.Authorities))
	for name, authority := range a.Authorities {
		authority.Transport = strings.ToLower(strings.TrimSpace(authority.Transport))
		authority.Mechanisms = authority.Mechanisms.Normalize()
		authority.OIDC = authority.OIDC.Normalize()
		authorities[name] = authority
	}

	a.Authorities = authorities

	return a
}

// Normalize returns authority mechanisms with canonical mechanism names.
func (a AuthorityMechanismsConfig) Normalize() AuthorityMechanismsConfig {
	a.Password.Names = normalizeLowerList(a.Password.Names)
	a.Bearer.Names = normalizeLowerList(a.Bearer.Names)
	a.Bearer.Validation = strings.ToLower(strings.TrimSpace(a.Bearer.Validation))
	a.Bearer.Introspection = a.Bearer.Introspection.Normalize()

	return a
}

// Normalize returns SASL bearer introspection config with stable scalar values.
func (b BearerIntrospectionConfig) Normalize() BearerIntrospectionConfig {
	b.Issuer = strings.TrimSpace(b.Issuer)
	b.DiscoveryURL = strings.TrimSpace(b.DiscoveryURL)
	b.ClientID = strings.TrimSpace(b.ClientID)
	b.ClientKeyID = strings.TrimSpace(b.ClientKeyID)
	b.ClientAssertionAlg = strings.TrimSpace(b.ClientAssertionAlg)
	b.AuthMethod = strings.ToLower(strings.TrimSpace(b.AuthMethod))
	b.RequiredScope = strings.TrimSpace(b.RequiredScope)
	b.AccountClaim = strings.TrimSpace(b.AccountClaim)

	return b
}

// Normalize returns authority OIDC caller-auth config with stable method values.
func (a AuthorityOIDCConfig) Normalize() AuthorityOIDCConfig {
	a.AuthorityMode = strings.ToLower(strings.TrimSpace(a.AuthorityMode))
	a.IssuerHint = strings.TrimSpace(a.IssuerHint)
	a.Issuer = strings.TrimSpace(a.Issuer)
	a.DiscoveryURL = strings.TrimSpace(a.DiscoveryURL)
	a.AudienceHint = strings.TrimSpace(a.AudienceHint)
	a.ClientCredentials.TokenEndpointAuthMethod = normalizedOIDCConfigMethod(a.ClientCredentials.TokenEndpointAuthMethod)
	a.ClientCredentials.IntrospectionEndpointAuthMethod = normalizedOIDCConfigMethod(a.ClientCredentials.IntrospectionEndpointAuthMethod)
	a.ClientCredentials.ClientAssertionAlg = strings.TrimSpace(a.ClientCredentials.ClientAssertionAlg)

	return a
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
			listener.AuthorityContext = listener.AuthorityContext.Normalize()

			if listener.LMTP != nil {
				lmtp := *listener.LMTP
				lmtp.Capabilities = normalizeLMTPCapabilities(lmtp.Capabilities)
				lmtp.ClientAuth.Authority = strings.TrimSpace(lmtp.ClientAuth.Authority)
				lmtp.ClientAuth.Mechanisms = normalizeLowerList(lmtp.ClientAuth.Mechanisms)
				lmtp.ClientAuth.MTLS.IdentitySource = strings.ToLower(strings.TrimSpace(lmtp.ClientAuth.MTLS.IdentitySource))
				listener.LMTP = &lmtp
			}

			if listener.Sieve != nil {
				sieve := *listener.Sieve
				sieve.AuthMechanisms = normalizeLowerList(sieve.AuthMechanisms)
				sieve.Capabilities.ScriptExtensions = normalizeLowerList(sieve.Capabilities.ScriptExtensions)
				sieve.Capabilities.Language = strings.ToLower(strings.TrimSpace(sieve.Capabilities.Language))
				listener.Sieve = &sieve
			}

			if listener.POP3 != nil {
				pop3 := *listener.POP3
				pop3.AuthMechanisms = normalizeLowerList(pop3.AuthMechanisms)
				pop3.Capabilities = normalizeUpperList(pop3.Capabilities)
				listener.POP3 = &pop3
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

		backend.BackendNode = strings.TrimSpace(backend.BackendNode)

		backends[name] = backend
	}

	d.Backends = backends

	return d
}

// Normalize trims listener authority context names and values into stable transport forms.
func (a AuthorityContextConfig) Normalize() AuthorityContextConfig {
	return AuthorityContextConfig{
		HTTPHeaders:  normalizeHTTPAuthorityContext(a.HTTPHeaders),
		GRPCMetadata: normalizeGRPCAuthorityContext(a.GRPCMetadata),
	}
}

// normalizeHTTPAuthorityContext trims values and canonicalizes HTTP header names.
func normalizeHTTPAuthorityContext(headers map[string]AuthorityContextValue) map[string]AuthorityContextValue {
	if headers == nil {
		return map[string]AuthorityContextValue{}
	}

	normalized := make(map[string]AuthorityContextValue, len(headers))
	for _, name := range sortedAuthorityContextNames(headers) {
		canonical := http.CanonicalHeaderKey(strings.TrimSpace(name))
		normalized[canonical] = AuthorityContextValue(strings.TrimSpace(string(headers[name])))
	}

	return normalized
}

// normalizeGRPCAuthorityContext trims metadata keys and values without changing key case.
func normalizeGRPCAuthorityContext(metadata map[string]AuthorityContextValue) map[string]AuthorityContextValue {
	if metadata == nil {
		return map[string]AuthorityContextValue{}
	}

	normalized := make(map[string]AuthorityContextValue, len(metadata))
	for _, name := range sortedAuthorityContextNames(metadata) {
		normalized[strings.TrimSpace(name)] = AuthorityContextValue(strings.TrimSpace(string(metadata[name])))
	}

	return normalized
}

// sortedAuthorityContextNames returns deterministic map iteration order for config snapshots.
func sortedAuthorityContextNames(values map[string]AuthorityContextValue) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}

	sort.Strings(names)

	return names
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
