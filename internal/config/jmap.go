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
	"net/url"
	"strings"
	"time"
)

const (
	protocolJMAP = "jmap"

	// JMAPMissingShardForbidden answers 403 when the auth result carries no shard attribute.
	JMAPMissingShardForbidden = "forbidden"
	// JMAPMissingShardUnavailable answers 503 when the auth result carries no shard attribute.
	JMAPMissingShardUnavailable = "unavailable"
	// JMAPMissingShardHashFallback routes accounts without a shard attribute by rendezvous hash.
	JMAPMissingShardHashFallback = "hash_fallback"

	jmapDefaultRealm                 = "jmap"
	jmapDefaultCacheTTL              = 30 * time.Second
	jmapDefaultCacheMaxEntries       = 10000
	jmapDefaultMaxHeaderBytes        = 64 * 1024
	jmapDefaultMaxRequestBodyBytes   = 10 * 1024 * 1024
	jmapDefaultMaxUploadBodyBytes    = 50 * 1024 * 1024
	jmapDefaultReadHeaderTimeout     = 10 * time.Second
	jmapDefaultReadTimeout           = 10 * time.Minute
	jmapDefaultIdleTimeout           = 2 * time.Minute
	jmapDefaultBackendResponseHeader = 2 * time.Minute
	jmapDefaultRequestLeaseTTL       = 2 * time.Minute
	jmapDefaultHeartbeatInterval     = 30 * time.Second
	jmapMaxCacheTTL                  = 10 * time.Minute
	jmapPathWellKnown                = "/.well-known/jmap"
	jmapPathPrefix                   = "/jmap/"
)

// JMAPListenerConfig configures one user-facing JMAP reverse-proxy listener.
type JMAPListenerConfig struct {
	PublicBaseURL string                `mapstructure:"public_base_url" yaml:"public_base_url"`
	HealthPath    string                `mapstructure:"health_path" yaml:"health_path"`
	Auth          JMAPAuthConfig        `mapstructure:"auth" yaml:"auth"`
	Routing       JMAPRoutingConfig     `mapstructure:"routing" yaml:"routing"`
	Limits        JMAPLimitsConfig      `mapstructure:"limits" yaml:"limits"`
	Timeouts      JMAPTimeoutsConfig    `mapstructure:"timeouts" yaml:"timeouts"`
	Placement     JMAPPlacementConfig   `mapstructure:"placement" yaml:"placement"`
	EventSource   JMAPEventSourceConfig `mapstructure:"event_source" yaml:"event_source"`
}

// JMAPAuthConfig selects the HTTP authentication schemes accepted by one JMAP listener.
type JMAPAuthConfig struct {
	Realm  string               `mapstructure:"realm" yaml:"realm"`
	Basic  JMAPBasicAuthConfig  `mapstructure:"basic" yaml:"basic"`
	Bearer JMAPBearerAuthConfig `mapstructure:"bearer" yaml:"bearer"`
	Cache  JMAPAuthCacheConfig  `mapstructure:"cache" yaml:"cache"`
}

// JMAPBasicAuthConfig controls HTTP Basic authentication through the Nauthilus password path.
type JMAPBasicAuthConfig struct {
	Enabled *bool `mapstructure:"enabled" yaml:"enabled"`
}

// JMAPBearerAuthConfig is the listener-owned token binding policy for HTTP Bearer credentials.
//
// The introspection endpoint and client credentials come from the listener authority, but the
// audience, resource, scope and account-claim policy is owned by the JMAP listener and never
// inherited from the mail SASL bearer policy of the authority.
type JMAPBearerAuthConfig struct {
	Enabled          bool   `mapstructure:"enabled" yaml:"enabled"`
	RequiredAudience string `mapstructure:"required_audience" yaml:"required_audience"`
	RequiredResource string `mapstructure:"required_resource" yaml:"required_resource"`
	RequiredScope    string `mapstructure:"required_scope" yaml:"required_scope"`
	AccountClaim     string `mapstructure:"account_claim" yaml:"account_claim"`
}

// JMAPAuthCacheConfig bounds the process-local cache of successful authentication results.
type JMAPAuthCacheConfig struct {
	TTL        Duration `mapstructure:"ttl" yaml:"ttl"`
	MaxEntries int      `mapstructure:"max_entries" yaml:"max_entries"`
}

// JMAPRoutingConfig controls how JMAP reacts to missing routing facts.
type JMAPRoutingConfig struct {
	MissingShard string `mapstructure:"missing_shard" yaml:"missing_shard"`
}

// JMAPLimitsConfig bounds request headers and bodies before they reach a backend.
type JMAPLimitsConfig struct {
	MaxHeaderBytes      int   `mapstructure:"max_header_bytes" yaml:"max_header_bytes"`
	MaxRequestBodyBytes int64 `mapstructure:"max_request_body_bytes" yaml:"max_request_body_bytes"`
	MaxUploadBodyBytes  int64 `mapstructure:"max_upload_body_bytes" yaml:"max_upload_body_bytes"`
}

// JMAPTimeoutsConfig bounds frontend and backend HTTP phases without limiting event streams.
type JMAPTimeoutsConfig struct {
	ReadHeader            Duration `mapstructure:"read_header" yaml:"read_header"`
	Read                  Duration `mapstructure:"read" yaml:"read"`
	Idle                  Duration `mapstructure:"idle" yaml:"idle"`
	BackendResponseHeader Duration `mapstructure:"backend_response_header" yaml:"backend_response_header"`
}

// JMAPPlacementConfig controls the short affinity hold opened for each proxied request.
type JMAPPlacementConfig struct {
	RequestLeaseTTL Duration `mapstructure:"request_lease_ttl" yaml:"request_lease_ttl"`
}

// JMAPEventSourceConfig controls the session lease held by long-lived event streams.
type JMAPEventSourceConfig struct {
	HeartbeatInterval Duration `mapstructure:"heartbeat_interval" yaml:"heartbeat_interval"`
}

// BasicEnabled reports whether HTTP Basic authentication is accepted; it defaults to true.
func (a JMAPAuthConfig) BasicEnabled() bool {
	return a.Basic.Enabled == nil || *a.Basic.Enabled
}

// Normalize applies the documented JMAP listener defaults to zero values.
func (j JMAPListenerConfig) Normalize() JMAPListenerConfig {
	j.PublicBaseURL = strings.TrimSpace(j.PublicBaseURL)
	j.HealthPath = strings.TrimSpace(j.HealthPath)
	j.Auth = j.Auth.normalize()
	j.Routing.MissingShard = strings.ToLower(strings.TrimSpace(j.Routing.MissingShard))

	if j.Routing.MissingShard == "" {
		j.Routing.MissingShard = JMAPMissingShardForbidden
	}

	j.Limits = j.Limits.normalize()
	j.Timeouts = j.Timeouts.normalize()

	if j.Placement.RequestLeaseTTL == 0 {
		j.Placement.RequestLeaseTTL = NewDuration(jmapDefaultRequestLeaseTTL)
	}

	if j.EventSource.HeartbeatInterval == 0 {
		j.EventSource.HeartbeatInterval = NewDuration(jmapDefaultHeartbeatInterval)
	}

	return j
}

// normalize applies JMAP authentication defaults.
func (a JMAPAuthConfig) normalize() JMAPAuthConfig {
	a.Realm = strings.TrimSpace(a.Realm)
	if a.Realm == "" {
		a.Realm = jmapDefaultRealm
	}

	if a.Basic.Enabled == nil {
		enabled := true
		a.Basic.Enabled = &enabled
	}

	a.Bearer.RequiredAudience = strings.TrimSpace(a.Bearer.RequiredAudience)
	a.Bearer.RequiredResource = strings.TrimSpace(a.Bearer.RequiredResource)
	a.Bearer.RequiredScope = strings.TrimSpace(a.Bearer.RequiredScope)
	a.Bearer.AccountClaim = strings.TrimSpace(a.Bearer.AccountClaim)

	if a.Cache.TTL == 0 {
		a.Cache.TTL = NewDuration(jmapDefaultCacheTTL)
	}

	if a.Cache.MaxEntries == 0 {
		a.Cache.MaxEntries = jmapDefaultCacheMaxEntries
	}

	return a
}

// normalize applies JMAP size limit defaults.
func (l JMAPLimitsConfig) normalize() JMAPLimitsConfig {
	if l.MaxHeaderBytes == 0 {
		l.MaxHeaderBytes = jmapDefaultMaxHeaderBytes
	}

	if l.MaxRequestBodyBytes == 0 {
		l.MaxRequestBodyBytes = jmapDefaultMaxRequestBodyBytes
	}

	if l.MaxUploadBodyBytes == 0 {
		l.MaxUploadBodyBytes = jmapDefaultMaxUploadBodyBytes
	}

	return l
}

// normalize applies JMAP timeout defaults.
func (t JMAPTimeoutsConfig) normalize() JMAPTimeoutsConfig {
	if t.ReadHeader == 0 {
		t.ReadHeader = NewDuration(jmapDefaultReadHeaderTimeout)
	}

	if t.Read == 0 {
		t.Read = NewDuration(jmapDefaultReadTimeout)
	}

	if t.Idle == 0 {
		t.Idle = NewDuration(jmapDefaultIdleTimeout)
	}

	if t.BackendResponseHeader == 0 {
		t.BackendResponseHeader = NewDuration(jmapDefaultBackendResponseHeader)
	}

	return t
}

// BearerIntrospectionPolicy returns the authority introspection settings with the listener token policy applied.
func (a JMAPBearerAuthConfig) BearerIntrospectionPolicy(authority BearerIntrospectionConfig) BearerIntrospectionConfig {
	authority.RequiredAudience = a.RequiredAudience
	authority.RequiredResource = a.RequiredResource
	authority.RequiredScope = a.RequiredScope
	authority.AccountClaim = a.AccountClaim

	return authority.Normalize()
}

// validateJMAPListener checks JMAP transport, authentication, routing and limit policy.
func validateJMAPListener(path string, listener ListenerConfig, authority AuthorityConfig, authorityKnown bool, problems *[]string) {
	jmap := listener.JMAP
	if jmap == nil {
		addProblem(problems, path+" is required for jmap listeners")

		return
	}

	if normalizeListenerTLSMode(listener.TLS.Mode) != listenerTLSModeImplicit {
		addProblem(problems, path+" requires listener tls.mode implicit")
	}

	validateJMAPPublicBaseURL(path+".public_base_url", jmap.PublicBaseURL, problems)
	validateJMAPHealthPath(path+".health_path", jmap.HealthPath, problems)
	validateJMAPAuth(path+".auth", jmap.Auth, authority, authorityKnown, problems)
	validateJMAPRouting(path+".routing", jmap.Routing, problems)
	validateJMAPLimits(path+".limits", jmap.Limits, problems)
	requirePositiveDuration(path+".timeouts.read_header", jmap.Timeouts.ReadHeader, problems)
	requirePositiveDuration(path+".timeouts.read", jmap.Timeouts.Read, problems)
	requirePositiveDuration(path+".timeouts.idle", jmap.Timeouts.Idle, problems)
	requirePositiveDuration(path+".timeouts.backend_response_header", jmap.Timeouts.BackendResponseHeader, problems)
	requirePositiveDuration(path+".placement.request_lease_ttl", jmap.Placement.RequestLeaseTTL, problems)
	requirePositiveDuration(path+".event_source.heartbeat_interval", jmap.EventSource.HeartbeatInterval, problems)
}

// validateJMAPPublicBaseURL accepts only absolute HTTPS origins without query or fragment.
func validateJMAPPublicBaseURL(path string, value string, problems *[]string) {
	if value == "" {
		return
	}

	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		addProblem(problems, path+" must be an absolute https URL without credentials, query or fragment")
	}
}

// validateJMAPHealthPath keeps the optional local health path outside the proxied JMAP surface.
func validateJMAPHealthPath(path string, value string, problems *[]string) {
	if value == "" {
		return
	}

	if !strings.HasPrefix(value, "/") || strings.ContainsAny(value, "?#") {
		addProblem(problems, path+" must be an absolute path without query or fragment")

		return
	}

	if value == jmapPathWellKnown || strings.HasPrefix(value, jmapPathPrefix) || value == strings.TrimSuffix(jmapPathPrefix, "/") {
		addProblem(problems, path+" must not overlap the proxied JMAP paths")
	}
}

// validateJMAPAuth requires at least one scheme and authority support for every enabled scheme.
func validateJMAPAuth(path string, auth JMAPAuthConfig, authority AuthorityConfig, authorityKnown bool, problems *[]string) {
	if !auth.BasicEnabled() && !auth.Bearer.Enabled {
		addProblem(problems, path+" must enable basic or bearer authentication")
	}

	if strings.ContainsAny(auth.Realm, "\"\\\r\n") {
		addProblem(problems, path+".realm must not contain quotes, backslashes or line breaks")
	}

	if auth.BasicEnabled() && authorityKnown && !authority.Mechanisms.Password.Enabled {
		addProblem(problems, path+".basic requires the authority password mechanism")
	}

	if auth.Bearer.Enabled {
		validateJMAPBearer(path+".bearer", auth.Bearer, authority, authorityKnown, problems)
	}

	requirePositiveDuration(path+".cache.ttl", auth.Cache.TTL, problems)

	if auth.Cache.TTL.Std() > jmapMaxCacheTTL {
		addProblem(problems, path+".cache.ttl must not exceed 10m")
	}

	requirePositiveInt(path+".cache.max_entries", auth.Cache.MaxEntries, problems)
}

// validateJMAPBearer checks the listener-owned bearer token binding policy.
func validateJMAPBearer(path string, bearer JMAPBearerAuthConfig, authority AuthorityConfig, authorityKnown bool, problems *[]string) {
	if authorityKnown && !authority.Mechanisms.Bearer.Introspection.Enabled {
		addProblem(problems, path+" requires the authority bearer introspection endpoint")
	}

	if strings.TrimSpace(bearer.RequiredScope) == "" {
		addProblem(problems, path+".required_scope is required")
	}

	validateOIDCTokenBinding(path, bearer.RequiredAudience, bearer.RequiredResource, problems)
	validateBearerAccountClaim(path+".account_claim", bearer.AccountClaim, problems)
}

// validateJMAPRouting accepts the documented missing-shard policies.
func validateJMAPRouting(path string, routing JMAPRoutingConfig, problems *[]string) {
	switch routing.MissingShard {
	case JMAPMissingShardForbidden, JMAPMissingShardUnavailable, JMAPMissingShardHashFallback:
	default:
		addProblem(problems, path+".missing_shard must be forbidden, unavailable, or hash_fallback")
	}
}

// validateJMAPLimits requires positive header and body bounds.
func validateJMAPLimits(path string, limits JMAPLimitsConfig, problems *[]string) {
	requirePositiveInt(path+".max_header_bytes", limits.MaxHeaderBytes, problems)

	if limits.MaxRequestBodyBytes <= 0 {
		addProblem(problems, path+".max_request_body_bytes must be positive")
	}

	if limits.MaxUploadBodyBytes <= 0 {
		addProblem(problems, path+".max_upload_body_bytes must be positive")
	}
}

// validateJMAPBackend restricts JMAP backends to verified HTTPS without director-owned credentials.
func validateJMAPBackend(path string, backend BackendConfig, problems *[]string) {
	if strings.ToLower(strings.TrimSpace(backend.TLS.Mode)) != listenerTLSModeImplicit {
		addProblem(problems, path+".tls.mode for JMAP backends must be implicit")
	}

	if strings.ToLower(strings.TrimSpace(backend.Auth.Mode)) != backendAuthModeNone {
		addProblem(problems, path+".auth.mode for JMAP backends must be none; client Authorization headers pass through unchanged")
	}

	if backend.HealthCheck.DeepCheck {
		addProblem(problems, path+".health_check.deep_check is not supported for JMAP backends")
	}
}
