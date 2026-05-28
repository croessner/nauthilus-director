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

//nolint:funlen,goconst,gocyclo,wsl_v5 // Validation keeps path-specific checks close to their config roots.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

const lmtpBDATImplemented = true

// Validate checks decoded typed config with validator/v10 and domain rules.
func (l *Loader) Validate(config Config) error {
	if l == nil {
		l = NewLoader()
	}
	config = config.Normalize()

	if err := l.validate.Struct(config); err != nil {
		return fmt.Errorf("validate typed config: %w", err)
	}

	var problems []string
	validateRuntime(config.Runtime, &problems)
	validateObservability(config.Observability, &problems)
	validateRedis(config.Storage.Redis, &problems)
	validateAuthorities(config.Auth.Authorities, &problems)
	validateDirector(config.Director, config.Auth.Authorities, &problems)

	if len(problems) > 0 {
		return errors.New("validate typed config: " + strings.Join(problems, "; "))
	}

	return nil
}

// validateObservability rejects local telemetry settings the runtime cannot honor.
func validateObservability(observability ObservabilityConfig, problems *[]string) {
	if strings.TrimSpace(observability.Metrics.Path) != "/metrics" {
		addProblem(problems, "observability.metrics.path must be /metrics")
	}

	if observability.Tracing.SampleRatio < 0 || observability.Tracing.SampleRatio > 1 {
		addProblem(problems, "observability.tracing.sample_ratio must be between 0.0 and 1.0")
	}

	exporter := strings.ToLower(strings.TrimSpace(observability.Tracing.Exporter))
	switch exporter {
	case "otlp":
		if observability.Tracing.Enabled && strings.TrimSpace(observability.Tracing.Endpoint) == "" {
			addProblem(problems, "observability.tracing.endpoint is required when tracing is enabled")
		}
	case "", "none", "noop", "disabled":
		if observability.Tracing.Enabled {
			addProblem(problems, "observability.tracing.exporter must be otlp when tracing is enabled")
		}
	default:
		addProblem(problems, "observability.tracing.exporter must be otlp or disabled/noop")
	}

	if observability.Tracing.Enabled && strings.TrimSpace(observability.Tracing.ServiceName) == "" {
		addProblem(problems, "observability.tracing.service_name is required when tracing is enabled")
	}
}

// validateRuntime enforces safe listener, auth and timeout defaults for process wiring.
func validateRuntime(runtime RuntimeConfig, problems *[]string) {
	if runtime.Process.ShutdownTimeout <= 0 {
		addProblem(problems, "runtime.process.shutdown_timeout must be greater than zero")
	}
	if runtime.Servers.Control.Enabled && strings.TrimSpace(runtime.Servers.Control.Address) == "" {
		addProblem(problems, "runtime.servers.control.address is required when control server is enabled")
	}
	if runtime.Servers.Control.Auth.Bearer.Enabled && runtime.Servers.Control.Auth.Bearer.TokenFile.IsZero() {
		addProblem(problems, "runtime.servers.control.auth.bearer.token_file is required when bearer auth is enabled")
	}
	if runtime.Servers.Control.Auth.OIDC.Enabled {
		if strings.TrimSpace(runtime.Servers.Control.Auth.OIDC.Authority) == "" {
			addProblem(problems, "runtime.servers.control.auth.oidc.authority is required when OIDC auth is enabled")
		}
		if strings.TrimSpace(runtime.Servers.Control.Auth.OIDC.Validation) == "" {
			addProblem(problems, "runtime.servers.control.auth.oidc.validation is required when OIDC auth is enabled")
		}
	}
	if runtime.Servers.Control.TLS.Enabled {
		if strings.TrimSpace(runtime.Servers.Control.TLS.Cert) == "" {
			addProblem(problems, "runtime.servers.control.tls.cert is required when TLS is enabled")
		}
		if runtime.Servers.Control.TLS.Key.IsZero() {
			addProblem(problems, "runtime.servers.control.tls.key is required when TLS is enabled")
		}
	}
	requirePositiveDuration("runtime.timeouts.preauth", runtime.Timeouts.Preauth, problems)
	requirePositiveDuration("runtime.timeouts.auth", runtime.Timeouts.Auth, problems)
	requirePositiveDuration("runtime.timeouts.nauthilus", runtime.Timeouts.Nauthilus, problems)
	requirePositiveDuration("runtime.timeouts.backend_connect", runtime.Timeouts.BackendConnect, problems)
	requirePositiveDuration("runtime.timeouts.proxy_idle", runtime.Timeouts.ProxyIdle, problems)
	requirePositiveDuration("runtime.timeouts.shutdown", runtime.Timeouts.Shutdown, problems)
	requirePositiveDuration("runtime.clients.http.idle_connection_timeout", runtime.Clients.HTTP.IdleConnectionTimeout, problems)
	requirePositiveInt("runtime.clients.http.max_connections_per_host", runtime.Clients.HTTP.MaxConnectionsPerHost, problems)
	requirePositiveInt("runtime.clients.http.max_idle_connections", runtime.Clients.HTTP.MaxIdleConnections, problems)
	requirePositiveInt("runtime.clients.http.max_idle_connections_per_host", runtime.Clients.HTTP.MaxIdleConnectionsPerHost, problems)
}

// validateRedis keeps Redis centralized and checks each supported topology.
func validateRedis(redis RedisConfig, problems *[]string) {
	if !redis.Enabled {
		addProblem(problems, "storage.redis.enabled must remain true for production affinity and session state")
	}
	if redis.Protocol != 2 && redis.Protocol != 3 {
		addProblem(problems, "storage.redis.protocol must be 2 or 3")
	}
	if redis.SchemaVersion <= 0 {
		addProblem(problems, "storage.redis.schema_version must be greater than zero")
	}
	if strings.TrimSpace(redis.KeyPrefix) == "" {
		addProblem(problems, "storage.redis.key_prefix is required")
	}
	requirePositiveInt("storage.redis.pool_size", redis.PoolSize, problems)
	if redis.MinIdleConnections < 0 {
		addProblem(problems, "storage.redis.min_idle_connections must not be negative")
	}
	requirePositiveDuration("storage.redis.pool_timeout", redis.PoolTimeout, problems)
	requirePositiveDuration("storage.redis.dial_timeout", redis.DialTimeout, problems)
	requirePositiveDuration("storage.redis.read_timeout", redis.ReadTimeout, problems)
	requirePositiveDuration("storage.redis.write_timeout", redis.WriteTimeout, problems)
	requirePositiveInt("storage.redis.retries.max_attempts", redis.Retries.MaxAttempts, problems)
	requirePositiveDuration("storage.redis.retries.min_backoff", redis.Retries.MinBackoff, problems)
	requirePositiveDuration("storage.redis.retries.max_backoff", redis.Retries.MaxBackoff, problems)
	if redis.Retries.MinBackoff > redis.Retries.MaxBackoff {
		addProblem(problems, "storage.redis.retries.min_backoff must not exceed max_backoff")
	}
	if redis.Health.Enabled {
		requirePositiveDuration("storage.redis.health.interval", redis.Health.Interval, problems)
		requirePositiveDuration("storage.redis.health.timeout", redis.Health.Timeout, problems)
		requirePositiveInt("storage.redis.health.failure_threshold", redis.Health.FailureThreshold, problems)
	}
	if redis.TLS.Enabled && strings.TrimSpace(redis.TLS.MinTLSVersion) == "" {
		addProblem(problems, "storage.redis.tls.min_tls_version is required when TLS is enabled")
	}

	switch redis.Mode {
	case redisModeStandalone:
		if strings.TrimSpace(redis.Standalone.Address) == "" {
			addProblem(problems, "storage.redis.standalone.address is required in standalone mode")
		}
	case redisModeCluster:
		if len(redis.Cluster.Addresses) == 0 {
			addProblem(problems, "storage.redis.cluster.addresses is required in cluster mode")
		}
	case redisModeSentinel:
		if strings.TrimSpace(redis.Sentinel.MasterName) == "" {
			addProblem(problems, "storage.redis.sentinel.master_name is required in sentinel mode")
		}
		if len(redis.Sentinel.Addresses) == 0 {
			addProblem(problems, "storage.redis.sentinel.addresses is required in sentinel mode")
		}
	default:
		addProblem(problems, "storage.redis.mode must be standalone, sentinel, or cluster")
	}
}

// validateAuthorities checks Nauthilus transport-specific authority requirements.
func validateAuthorities(authorities map[string]AuthorityConfig, problems *[]string) {
	for name, authority := range authorities {
		path := "auth.authorities." + name
		requirePositiveDuration(path+".timeout", authority.Timeout, problems)

		switch authority.Transport {
		case transportHTTP:
			if strings.TrimSpace(authority.HTTP.Endpoint) == "" {
				addProblem(problems, path+".http.endpoint is required when transport is http")
			}
			if strings.TrimSpace(authority.HTTP.ContentType) == "" {
				addProblem(problems, path+".http.content_type is required when transport is http")
			}
			if authority.HTTP.BasicAuth.PasswordFile.IsZero() {
				addProblem(problems, path+".http.basic_auth.password_file is required when transport is http")
			}
		case transportGRPC:
			if strings.TrimSpace(authority.GRPC.Address) == "" {
				addProblem(problems, path+".grpc.address is required when transport is grpc")
			}
			if authority.GRPC.CallerAuth.Basic.Enabled && authority.GRPC.CallerAuth.Bearer.Enabled {
				addProblem(problems, path+".grpc.caller_auth must enable only one caller auth method")
			}
			if authority.GRPC.CallerAuth.Basic.Enabled && strings.TrimSpace(authority.GRPC.CallerAuth.Basic.Username) == "" {
				addProblem(problems, path+".grpc.caller_auth.basic.username is required when basic caller auth is enabled")
			}
			if authority.GRPC.CallerAuth.Basic.Enabled && authority.GRPC.CallerAuth.Basic.PasswordFile.IsZero() {
				addProblem(problems, path+".grpc.caller_auth.basic.password_file is required when basic caller auth is enabled")
			}
			if authority.GRPC.CallerAuth.Bearer.Enabled && authority.GRPC.CallerAuth.Bearer.TokenFile.IsZero() {
				addProblem(problems, path+".grpc.caller_auth.bearer.token_file is required when bearer caller auth is enabled")
			}
		default:
			addProblem(problems, path+".transport must be http or grpc")
		}

		if authority.Mechanisms.Password.Enabled && len(authority.Mechanisms.Password.Names) == 0 {
			addProblem(problems, path+".mechanisms.password.names is required when password mechanisms are enabled")
		}
		if authority.Mechanisms.Bearer.Enabled {
			if len(authority.Mechanisms.Bearer.Names) == 0 {
				addProblem(problems, path+".mechanisms.bearer.names is required when bearer mechanisms are enabled")
			}
			requirePositiveInt(path+".mechanisms.bearer.token_max_bytes", authority.Mechanisms.Bearer.TokenMaxBytes, problems)
		}
	}
}

// validateDirector checks director-owned references, runtime override safety and backend auth.
func validateDirector(director DirectorConfig, authorities map[string]AuthorityConfig, problems *[]string) {
	if !director.Security.FailClosed {
		addProblem(problems, "director.security.fail_closed must be true")
	}
	requirePositiveInt("director.security.max_preauth_line_bytes", director.Security.MaxPreauthLineBytes, problems)
	requirePositiveInt("director.security.max_preauth_literal_bytes", director.Security.MaxPreauthLiteralBytes, problems)
	if director.RuntimeOverrides.ConfigWritable {
		addProblem(problems, "director.runtime_overrides.config_writable must remain false")
	}
	if director.RuntimeOverrides.Backends.MinWeight < 0 {
		addProblem(problems, "director.runtime_overrides.backends.min_weight must not be negative")
	}
	if director.RuntimeOverrides.Backends.MaxWeight < director.RuntimeOverrides.Backends.MinWeight {
		addProblem(problems, "director.runtime_overrides.backends.max_weight must not be lower than min_weight")
	}
	validateMaintenanceMode("director.maintenance.default_mode", director.Maintenance.DefaultMode, "disabled", problems)

	for name, listener := range director.Listeners {
		path := "director.listeners." + name
		if _, ok := authorities[listener.Authority]; !ok {
			addProblem(problems, path+".authority references unknown authority "+listener.Authority)
		}
		if _, ok := director.BackendPools[listener.BackendPool]; !ok {
			addProblem(problems, path+".backend_pool references unknown pool "+listener.BackendPool)
		}
		switch listener.Protocol {
		case protocolIMAP:
		case protocolLMTP:
		default:
			addProblem(problems, path+".protocol must be imap or lmtp")
		}

		if listener.Protocol == protocolIMAP && listener.IMAP == nil {
			addProblem(problems, path+".imap is required for imap listeners")
		}
		if listener.Protocol == protocolIMAP && listener.IMAP != nil {
			validateIMAPListener(path+".imap", listener, *listener.IMAP, problems)
		}
		if listener.Protocol == protocolLMTP && listener.LMTP == nil {
			addProblem(problems, path+".lmtp is required for lmtp listeners")
		}
		if listener.Protocol == protocolLMTP && listener.LMTP != nil {
			validateLMTPListener(path+".lmtp", listener, authorities, problems)
		}
		if strings.TrimSpace(listener.TLS.Mode) == "" {
			addProblem(problems, path+".tls.mode is required")
		}
		if listener.ProxyProtocol.Enabled {
			if len(listener.ProxyProtocol.TrustedCIDRs) == 0 {
				addProblem(problems, path+".proxy_protocol.trusted_cidrs is required when proxy protocol is enabled")
			}
			for _, trustedCIDR := range listener.ProxyProtocol.TrustedCIDRs {
				if _, err := netip.ParsePrefix(strings.TrimSpace(trustedCIDR)); err != nil {
					addProblem(problems, path+".proxy_protocol.trusted_cidrs contains invalid CIDR "+trustedCIDR)
				}
			}
		}
	}

	for name, pool := range director.BackendPools {
		path := "director.backend_pools." + name
		validateBackendPool(path, pool, problems)

		for _, backendName := range pool.Backends {
			backend, ok := director.Backends[backendName]
			if !ok {
				addProblem(problems, path+".backends references unknown backend "+backendName)
				continue
			}
			if !strings.EqualFold(strings.TrimSpace(pool.Protocol), strings.TrimSpace(backend.Protocol)) {
				addProblem(problems, path+".backends references backend with different protocol "+backendName)
			}
		}
	}

	for name, backend := range director.Backends {
		path := "director.backends." + name
		validateBackendProtocol(path, backend.Protocol, problems)
		requireNonNegativeInt(path+".weight", backend.Weight, problems)
		requirePositiveInt(path+".max_connections", backend.MaxConnections, problems)
		validateMaintenanceMode(path+".maintenance", backend.Maintenance, director.Maintenance.DefaultMode, problems)
		validateBackendAddress(path+".address", backend.Address, problems)
		validateBackendTLS(path+".tls", backend.Address, backend.TLS, problems)
		validateBackendAuth(path+".auth", backend, problems)
		if backend.HealthCheck.Enabled && backend.HealthCheck.PasswordFile.IsZero() {
			addProblem(problems, path+".health_check.password_file is required when health check is enabled")
		}
	}

	requirePositiveDuration("director.affinity.active_user_pinning.idle_grace", director.Affinity.ActiveUserPinning.IdleGrace, problems)
	requirePositiveDuration("director.affinity.local_cache.ttl", director.Affinity.LocalCache.TTL, problems)
	requirePositiveInt("director.affinity.local_cache.max_entries", director.Affinity.LocalCache.MaxEntries, problems)
	requirePositiveDuration("director.health.interval", director.Health.Interval, problems)
	requirePositiveDuration("director.health.timeout", director.Health.Timeout, problems)
	requirePositiveDuration("director.maintenance.drain_timeout", director.Maintenance.DrainTimeout, problems)
	requirePositiveDuration("director.maintenance.hard_kill_grace", director.Maintenance.HardKillGrace, problems)
}

// validateMaintenanceMode rejects static backend maintenance modes that selectors cannot enforce.
func validateMaintenanceMode(path string, value string, defaultMode string, problems *[]string) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		value = strings.ToLower(strings.TrimSpace(defaultMode))
	}

	switch value {
	case "disabled", "soft", "hard":
	default:
		addProblem(problems, path+" must be disabled, soft, or hard")
	}
}

// validateBackendPool checks supported pool protocols and selector vocabulary.
func validateBackendPool(path string, pool BackendPoolConfig, problems *[]string) {
	protocol := strings.ToLower(strings.TrimSpace(pool.Protocol))
	switch protocol {
	case protocolIMAP:
		if strings.ToLower(strings.TrimSpace(pool.Selector)) != "rendezvous_hash" {
			addProblem(problems, path+".selector for IMAP pools must be rendezvous_hash")
		}
	case protocolLMTP:
		if strings.ToLower(strings.TrimSpace(pool.Selector)) != "recipient_hash" {
			addProblem(problems, path+".selector for LMTP pools must be recipient_hash")
		}
	default:
		addProblem(problems, path+".protocol must be imap or lmtp")
	}
}

// validateBackendProtocol rejects backend protocols without production support.
func validateBackendProtocol(path string, protocol string, problems *[]string) {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case protocolIMAP, protocolLMTP:
	default:
		addProblem(problems, path+".protocol must be imap or lmtp")
	}
}

// validateIMAPListener rejects unsupported pre-auth advertisements and mechanisms.
func validateIMAPListener(path string, listener ListenerConfig, imap IMAPListenerConfig, problems *[]string) {
	allowedMechanisms := make(map[string]struct{}, len(imap.AuthMechanisms))
	for _, mechanism := range imap.AuthMechanisms {
		allowedMechanisms[strings.ToUpper(strings.TrimSpace(mechanism))] = struct{}{}
	}

	for _, capability := range imap.Capabilities {
		normalized := strings.ToUpper(strings.TrimSpace(capability))
		switch {
		case normalized == "IMAP4REV1", normalized == "ID", normalized == "SASL-IR":
		case normalized == "STARTTLS":
			if listener.TLS.Mode != "starttls" {
				addProblem(problems, path+".capabilities advertises STARTTLS for non-starttls listener TLS mode")
			}
		case strings.HasPrefix(normalized, "AUTH="):
			mechanism := strings.TrimPrefix(normalized, "AUTH=")
			if !validIMAPAuthMechanism(mechanism) {
				addProblem(problems, path+".capabilities advertises unsupported mechanism "+capability)
			} else if _, ok := allowedMechanisms[strings.ToUpper(strings.TrimSpace(mechanism))]; !ok {
				addProblem(problems, path+".capabilities advertises AUTH mechanism not enabled in auth_mechanisms "+mechanism)
			}
		case normalized == "ENABLE":
			addProblem(problems, path+".capabilities must not advertise unsupported ENABLE")
		default:
			addProblem(problems, path+".capabilities contains unsupported capability "+capability)
		}
	}

	for _, mechanism := range imap.AuthMechanisms {
		if !validIMAPAuthMechanism(mechanism) {
			addProblem(problems, path+".auth_mechanisms contains unsupported mechanism "+mechanism)
		}
	}
}

// validateLMTPListener rejects false listener advertisements and unsafe peer-auth policies.
func validateLMTPListener(path string, listener ListenerConfig, authorities map[string]AuthorityConfig, problems *[]string) {
	lmtp := listener.LMTP
	if lmtp == nil {
		addProblem(problems, path+" is required for lmtp listeners")

		return
	}

	if lmtp.ClientAuth.Required {
		if _, ok := authorities[lmtp.ClientAuth.Authority]; !ok {
			addProblem(problems, path+".client_auth.authority references unknown authority "+lmtp.ClientAuth.Authority)
		}
	}

	if len(lmtp.ClientAuth.Mechanisms) == 0 && lmtp.ClientAuth.Required && !lmtp.ClientAuth.MTLS.SatisfiesRequired {
		addProblem(problems, path+".client_auth.mechanisms is required unless mTLS explicitly satisfies required peer auth")
	}

	for _, mechanism := range lmtp.ClientAuth.Mechanisms {
		if !validLMTPAuthMechanism(mechanism) {
			addProblem(problems, path+".client_auth.mechanisms contains unsupported mechanism "+mechanism)
		}
	}

	validateLMTPClientMTLS(path+".client_auth.mtls", listener, lmtp.ClientAuth, problems)
	validateLMTPCapabilities(path+".capabilities", listener, *lmtp, problems)
}

// validateLMTPClientMTLS rejects mTLS peer-auth settings that cannot verify a submitter identity.
func validateLMTPClientMTLS(path string, listener ListenerConfig, auth LMTPClientAuthConfig, problems *[]string) {
	if strings.TrimSpace(auth.MTLS.IdentitySource) != "" && !validLMTPMTLSIdentitySource(auth.MTLS.IdentitySource) {
		addProblem(problems, path+".identity_source contains unsupported source "+auth.MTLS.IdentitySource)
	}

	if !auth.MTLS.SatisfiesRequired {
		return
	}

	if !auth.Required {
		addProblem(problems, path+".satisfies_required may be true only when client_auth.required is true")
	}

	if strings.TrimSpace(auth.MTLS.IdentitySource) == "" {
		addProblem(problems, path+".identity_source is required when mTLS satisfies required peer auth")
	}

	if !listener.TLS.RequireClientCert || strings.TrimSpace(listener.TLS.ClientCA) == "" {
		addProblem(problems, path+".satisfies_required requires listener TLS to require and verify client certificates")
	}
}

// validateLMTPCapabilities rejects unsupported desired LMTP listener capabilities.
func validateLMTPCapabilities(path string, listener ListenerConfig, lmtp LMTPListenerConfig, problems *[]string) {
	for _, capability := range lmtp.Capabilities {
		switch {
		case capability == "SMTPUTF8":
			if !lmtp.SMTPUTF8 {
				addProblem(problems, path+" advertises SMTPUTF8 while smtputf8 is false")
			}
		case capability == "STARTTLS":
			if listener.TLS.Mode != "starttls" {
				addProblem(problems, path+" advertises STARTTLS for non-starttls listener TLS mode")
			}
		case capability == "CHUNKING":
			if !lmtpBDATImplemented {
				addProblem(problems, path+" advertises CHUNKING before BDAT support and backend capability mediation are implemented")
			}
		case strings.HasPrefix(capability, "AUTH "):
			validateLMTPAuthCapability(path, capability, lmtp.ClientAuth.Mechanisms, problems)
		case capability == "AUTH":
			addProblem(problems, path+" AUTH capability requires at least one mechanism")
		default:
			addProblem(problems, path+" contains unsupported capability "+capability)
		}
	}
}

// validateLMTPAuthCapability checks AUTH mechanism vocabulary and listener policy consistency.
func validateLMTPAuthCapability(path string, capability string, configuredMechanisms []string, problems *[]string) {
	fields := strings.Fields(capability)
	if len(fields) < 2 {
		addProblem(problems, path+" AUTH capability requires at least one mechanism")

		return
	}

	allowed := make(map[string]struct{}, len(configuredMechanisms))
	for _, mechanism := range configuredMechanisms {
		allowed[strings.ToUpper(strings.TrimSpace(mechanism))] = struct{}{}
	}
	if len(allowed) == 0 {
		addProblem(problems, path+" AUTH capability requires client_auth.mechanisms")

		return
	}

	for _, mechanism := range fields[1:] {
		if !validLMTPAuthMechanism(mechanism) {
			addProblem(problems, path+" advertises unsupported AUTH mechanism "+mechanism)

			continue
		}

		if _, ok := allowed[strings.ToUpper(strings.TrimSpace(mechanism))]; !ok {
			addProblem(problems, path+" advertises AUTH mechanism not enabled in client_auth.mechanisms "+mechanism)
		}
	}
}

// validIMAPAuthMechanism reports whether pre-auth command handling accepts this mechanism shape.
func validIMAPAuthMechanism(mechanism string) bool {
	switch strings.ToUpper(strings.TrimSpace(mechanism)) {
	case "PLAIN", "XOAUTH2", "OAUTHBEARER":
		return true
	default:
		return false
	}
}

// validLMTPAuthMechanism reports whether LMTP peer auth may be configured for this mechanism.
func validLMTPAuthMechanism(mechanism string) bool {
	switch strings.ToUpper(strings.TrimSpace(mechanism)) {
	case "PLAIN", "LOGIN", "XOAUTH2", "OAUTHBEARER":
		return true
	default:
		return false
	}
}

// validLMTPMTLSIdentitySource reports whether a verified client cert can provide this safe identity.
func validLMTPMTLSIdentitySource(source string) bool {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "subject_common_name", "dns_san", "uri_san":
		return true
	default:
		return false
	}
}

// validateBackendAddress keeps protocol backend transports TCP-only.
func validateBackendAddress(path string, address string, problems *[]string) {
	address = strings.TrimSpace(address)
	if address == "" {
		addProblem(problems, path+" is required")

		return
	}

	if strings.HasPrefix(strings.ToLower(address), "unix:") || strings.HasPrefix(address, "/") {
		addProblem(problems, path+" must be a TCP host:port address; Unix socket backend addresses are not supported for IMAP backend connectivity")

		return
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
		addProblem(problems, path+" must be a TCP host:port address")
	}
}

// validateBackendTLS checks TLS mode vocabulary and hostname-verification prerequisites.
func validateBackendTLS(path string, address string, tlsConfig BackendTLSConfig, problems *[]string) {
	mode := strings.ToLower(strings.TrimSpace(tlsConfig.Mode))
	switch mode {
	case "disabled", "plaintext":
		return
	case "starttls", "implicit":
	default:
		addProblem(problems, path+".mode must be disabled, plaintext, starttls, or implicit")

		return
	}

	if strings.TrimSpace(tlsConfig.MinTLSVersion) == "" {
		addProblem(problems, path+".min_tls_version is required when backend TLS is enabled")
	}

	if !tlsConfig.InsecureSkipVerify && strings.TrimSpace(tlsConfig.ServerName) == "" && backendAddressHostIsIP(address) {
		addProblem(problems, path+".server_name is required when backend address is an IP address and certificate verification is enabled")
	}
}

// backendAddressHostIsIP reports whether a backend address uses a literal IP host.
func backendAddressHostIsIP(address string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return false
	}

	_, err = netip.ParseAddr(strings.TrimSpace(host))

	return err == nil
}

// validateBackendAuth checks mode-specific backend authentication requirements.
func validateBackendAuth(path string, backend BackendConfig, problems *[]string) {
	mode := strings.ToLower(strings.TrimSpace(backend.Auth.Mode))
	protocol := strings.ToLower(strings.TrimSpace(backend.Protocol))
	if protocol == protocolIMAP {
		switch mode {
		case backendAuthModeMasterUser, backendAuthModeCredentialReplay:
		default:
			addProblem(problems, path+".mode for IMAP backends must be master_user or credential_replay")

			return
		}
	}
	if protocol == protocolLMTP {
		switch mode {
		case backendAuthModeNone, backendAuthModeMTLS, backendAuthModeSASL, backendAuthModeOAuthBearer:
		default:
			addProblem(problems, path+".mode for LMTP backends must be none, mtls, sasl, or oauthbearer")

			return
		}
	}

	switch mode {
	case backendAuthModeMasterUser:
		validateMasterUserAuth(path+".master_user", backend.Auth.MasterUser, problems)
	case backendAuthModeCredentialReplay:
		validateCredentialReplayAuth(path+".credential_replay", backend.Auth.CredentialReplay, problems)
	case backendAuthModeSASL:
		validateSASLBackendAuth(path+".sasl", backend, problems)
	case backendAuthModeOAuthBearer:
		validateOAuthBearerBackendAuth(path+".oauthbearer", backend, problems)
	case backendAuthModeMTLS:
		validateMTLSBackendAuth(path+".mtls", backend, problems)
	case backendAuthModeNone:
	default:
		addProblem(problems, path+".mode must be none, mtls, sasl, oauthbearer, master_user, or credential_replay")
	}
}

// validateSASLBackendAuth checks LMTP service credentials and optional verified TLS requirements.
func validateSASLBackendAuth(path string, backend BackendConfig, problems *[]string) {
	if !validBackendPasswordMechanism(backend.Auth.SASL.Mechanism) {
		addProblem(problems, path+".mechanism must be plain or login")
	}
	if strings.TrimSpace(backend.Auth.SASL.Username) == "" {
		addProblem(problems, path+".username is required in sasl mode")
	}
	if backend.Auth.SASL.PasswordFile.IsZero() {
		addProblem(problems, path+".password_file is required in sasl mode")
	}
	if backend.Auth.SASL.RequireTLS && !backendTLSCanVerify(backend.TLS) {
		addProblem(problems, path+".require_tls requires verified backend TLS")
	}
}

// validateOAuthBearerBackendAuth checks token material and optional verified TLS requirements.
func validateOAuthBearerBackendAuth(path string, backend BackendConfig, problems *[]string) {
	if backend.Auth.OAuthBearer.TokenFile.IsZero() {
		addProblem(problems, path+".token_file is required in oauthbearer mode")
	}
	if backend.Auth.OAuthBearer.RequireTLS && !backendTLSCanVerify(backend.TLS) {
		addProblem(problems, path+".require_tls requires verified backend TLS")
	}
}

// validateMTLSBackendAuth checks the client certificate material needed for backend mTLS auth.
func validateMTLSBackendAuth(path string, backend BackendConfig, problems *[]string) {
	if !backendTLSCanVerify(backend.TLS) {
		addProblem(problems, path+" requires verified backend TLS")
	}
	if strings.TrimSpace(backend.TLS.Cert) == "" || backend.TLS.Key.IsZero() {
		addProblem(problems, path+" requires backend tls.cert and tls.key")
	}
}

// backendTLSCanVerify reports whether backend TLS can protect credential-bearing auth.
func backendTLSCanVerify(tlsConfig BackendTLSConfig) bool {
	mode := strings.ToLower(strings.TrimSpace(tlsConfig.Mode))
	return (mode == "starttls" || mode == "implicit") && !tlsConfig.InsecureSkipVerify
}

// validateMasterUserAuth checks configured administrative IMAP login material.
func validateMasterUserAuth(path string, masterUser BackendMasterUserConfig, problems *[]string) {
	if strings.TrimSpace(masterUser.Username) == "" {
		addProblem(problems, path+".username is required in master_user mode")
	}
	if masterUser.PasswordFile.IsZero() {
		addProblem(problems, path+".password_file is required in master_user mode")
	}
	if strings.TrimSpace(masterUser.UserFormat) == "" {
		addProblem(problems, path+".user_format is required in master_user mode")
	}
	if !validBackendPasswordMechanism(masterUser.Mechanism) {
		addProblem(problems, path+".mechanism must be plain or login")
	}
}

// validateCredentialReplayAuth checks replay allowlists before runtime can use credentials.
func validateCredentialReplayAuth(path string, replay BackendCredentialReplayConfig, problems *[]string) {
	if len(replay.AllowedMechanisms) == 0 {
		addProblem(problems, path+".allowed_mechanisms is required in credential_replay mode")
	}
	for _, mechanism := range replay.AllowedMechanisms {
		if !validBackendReplayMechanism(mechanism) {
			addProblem(problems, path+".allowed_mechanisms contains unsupported mechanism "+mechanism)
		}
	}
}

// validBackendPasswordMechanism reports whether a backend password flow can use the mechanism.
func validBackendPasswordMechanism(mechanism string) bool {
	switch strings.ToLower(strings.TrimSpace(mechanism)) {
	case "plain", "login":
		return true
	default:
		return false
	}
}

// validBackendReplayMechanism reports whether credential replay can preserve this mechanism.
func validBackendReplayMechanism(mechanism string) bool {
	switch strings.ToLower(strings.TrimSpace(mechanism)) {
	case "plain", "login", "xoauth2", "oauthbearer":
		return true
	default:
		return false
	}
}

// requirePositiveDuration records a path-specific error for zero or negative durations.
func requirePositiveDuration(path string, value Duration, problems *[]string) {
	if value <= 0 {
		addProblem(problems, path+" must be greater than zero")
	}
}

// requirePositiveInt records a path-specific error for zero or negative integers.
func requirePositiveInt(path string, value int, problems *[]string) {
	if value <= 0 {
		addProblem(problems, path+" must be greater than zero")
	}
}

// requireNonNegativeInt records a path-specific error for negative integers.
func requireNonNegativeInt(path string, value int, problems *[]string) {
	if value < 0 {
		addProblem(problems, path+" must not be negative")
	}
}

// addProblem accumulates validation failures without losing path context.
func addProblem(problems *[]string, message string) {
	*problems = append(*problems, message)
}
