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
	"unicode"
)

const (
	lmtpBDATImplemented = true

	bearerMechanismOAuthBearer             = "oauthbearer"
	bearerMechanismXOAUTH2                 = "xoauth2"
	bearerValidationNauthilusIntrospection = "nauthilus_introspection"
	defaultBearerRequiredScope             = "email"
	oidcClientSecretBasic                  = "client_secret_basic"
	oidcClientSecretPost                   = "client_secret_post"
	oidcPrivateKeyJWT                      = "private_key_jwt"
	oidcValidationNauthilus                = "nauthilus"
)

const (
	oidcAssertionAlgRS256 = "RS256"
	oidcAssertionAlgEdDSA = "EdDSA"
)

const (
	authorityContextNameAuthorization      = "authorization"
	authorityContextNameProxyAuthorization = "proxy-authorization"
	authorityContextNameCookie             = "cookie"
	authorityContextNameSetCookie          = "set-cookie"
	authorityContextNameContentType        = "content-type"
	authorityContextNameAccept             = "accept"
	authorityContextNameHost               = "host"
	authorityContextNameTE                 = "te"
	authorityContextGRPCPrefix             = "grpc-"
)

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
	validateRuntime(config.Runtime, config.Auth.Authorities, &problems)
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

	if !observability.Profiles.PProf.Enabled {
		if observability.Profiles.Block.Enabled {
			addProblem(problems, "observability.profiles.block.enabled requires observability.profiles.pprof.enabled")
		}
		if observability.Profiles.Mutex.Enabled {
			addProblem(problems, "observability.profiles.mutex.enabled requires observability.profiles.pprof.enabled")
		}
		if observability.Profiles.Goroutine.Enabled {
			addProblem(problems, "observability.profiles.goroutine.enabled requires observability.profiles.pprof.enabled")
		}
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
func validateRuntime(runtime RuntimeConfig, authorities map[string]AuthorityConfig, problems *[]string) {
	if runtime.Process.ShutdownTimeout <= 0 {
		addProblem(problems, "runtime.process.shutdown_timeout must be greater than zero")
	}
	if runtime.Servers.Control.Enabled && strings.TrimSpace(runtime.Servers.Control.Address) == "" {
		addProblem(problems, "runtime.servers.control.address is required when control server is enabled")
	}
	if runtime.Servers.Control.Enabled && enabledCount(
		runtime.Servers.Control.Auth.Basic.Enabled,
		runtime.Servers.Control.Auth.Bearer.Enabled,
		runtime.Servers.Control.Auth.OIDC.Enabled,
		runtime.Servers.Control.Auth.MTLS.Enabled,
	) == 0 {
		addProblem(problems, "runtime.servers.control.auth must enable at least one authentication mode")
	}
	if runtime.Servers.Control.Auth.Basic.Enabled {
		if strings.TrimSpace(runtime.Servers.Control.Auth.Basic.Username) == "" {
			addProblem(problems, "runtime.servers.control.auth.basic.username is required when basic auth is enabled")
		}
		if runtime.Servers.Control.Auth.Basic.PasswordFile.IsZero() {
			addProblem(problems, "runtime.servers.control.auth.basic.password_file is required when basic auth is enabled")
		}
	}
	if runtime.Servers.Control.Auth.Bearer.Enabled && runtime.Servers.Control.Auth.Bearer.TokenFile.IsZero() {
		addProblem(problems, "runtime.servers.control.auth.bearer.token_file is required when bearer auth is enabled")
	}
	if runtime.Servers.Control.Auth.OIDC.Enabled {
		if strings.TrimSpace(runtime.Servers.Control.Auth.OIDC.Authority) == "" {
			addProblem(problems, "runtime.servers.control.auth.oidc.authority is required when OIDC auth is enabled")
		}
		if strings.ToLower(strings.TrimSpace(runtime.Servers.Control.Auth.OIDC.Validation)) != "nauthilus" {
			addProblem(problems, "runtime.servers.control.auth.oidc.validation must be nauthilus when OIDC auth is enabled")
		}
		if len(runtime.Servers.Control.Auth.OIDC.RequiredScopes) == 0 {
			addProblem(problems, "runtime.servers.control.auth.oidc.required_scopes is required when OIDC auth is enabled")
		}
		if len(runtime.Servers.Control.Auth.OIDC.ProtectedScopes) == 0 {
			addProblem(problems, "runtime.servers.control.auth.oidc.protected_scopes is required when OIDC auth is enabled")
		}
		if authority, ok := authorities[strings.TrimSpace(runtime.Servers.Control.Auth.OIDC.Authority)]; ok {
			if !authorityOIDCCallerAuthEnabled(authority) {
				addProblem(problems, "runtime.servers.control.auth.oidc.authority must reference an authority with OIDC client credentials enabled")
			} else {
				credentials := authority.OIDC.ClientCredentials
				method := normalizedOIDCConfigMethod(credentials.IntrospectionEndpointAuthMethod)
				if method == "" {
					method = fallbackIntrospectionAuthMethod(credentials.TokenEndpointAuthMethod)
				}
				switch method {
				case oidcClientSecretBasic, oidcClientSecretPost:
					if enabledSecretCount(credentials.ClientSecret, credentials.ClientSecretFile) != 1 {
						addProblem(problems, "runtime.servers.control.auth.oidc.authority requires exactly one client_secret or client_secret_file for introspection")
					}
				case oidcPrivateKeyJWT:
					if credentials.ClientPrivateKeyFile.IsZero() {
						addProblem(problems, "runtime.servers.control.auth.oidc.authority requires client_private_key_file for private_key_jwt introspection")
					}
				case "":
					addProblem(problems, "runtime.servers.control.auth.oidc.authority requires introspection_endpoint_auth_method when OIDC auth is enabled")
				default:
					addProblem(problems, "runtime.servers.control.auth.oidc.authority introspection_endpoint_auth_method must be client_secret_basic, client_secret_post or private_key_jwt")
				}
			}
		} else if strings.TrimSpace(runtime.Servers.Control.Auth.OIDC.Authority) != "" {
			addProblem(problems, "runtime.servers.control.auth.oidc.authority must reference a configured authority")
		}
	}
	if runtime.Servers.Control.Auth.MTLS.Enabled {
		if !runtime.Servers.Control.TLS.Enabled {
			addProblem(problems, "runtime.servers.control.auth.mtls requires runtime.servers.control.tls.enabled")
		}
		if strings.TrimSpace(runtime.Servers.Control.TLS.ClientCA) == "" {
			addProblem(problems, "runtime.servers.control.auth.mtls requires runtime.servers.control.tls.client_ca")
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
	requirePositiveDuration("runtime.state.reaper.interval", runtime.State.Reaper.Interval, problems)
	requirePositiveInt("runtime.state.reaper.batch_size", runtime.State.Reaper.BatchSize, problems)
	requirePositiveDuration("runtime.state.reaper.max_pass_duration", runtime.State.Reaper.MaxPassDuration, problems)
	requireNonNegativeDuration("runtime.state.reaper.jitter", runtime.State.Reaper.Jitter, problems)
	requirePositiveInt("runtime.state.indexes.session_shards", runtime.State.Indexes.SessionShards, problems)
	requirePositiveInt("runtime.state.indexes.user_shards", runtime.State.Indexes.UserShards, problems)
	requirePositiveInt("runtime.state.indexes.backend_shards", runtime.State.Indexes.BackendShards, problems)
	requirePositiveInt("runtime.state.indexes.page_default", runtime.State.Indexes.PageDefault, problems)
	requirePositiveInt("runtime.state.indexes.page_max", runtime.State.Indexes.PageMax, problems)
	if runtime.State.Indexes.PageDefault > runtime.State.Indexes.PageMax {
		addProblem(problems, "runtime.state.indexes.page_default must not exceed runtime.state.indexes.page_max")
	}
	requirePositiveDuration("runtime.state.backend_reservations.ttl", runtime.State.BackendReservations.TTL, problems)
	requirePositiveDuration(
		"runtime.state.backend_reservations.repair_interval",
		runtime.State.BackendReservations.RepairInterval,
		problems,
	)
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
			if !authorityOIDCCallerAuthEnabled(authority) && strings.TrimSpace(authority.HTTP.BasicAuth.Username) == "" {
				addProblem(problems, path+".http.basic_auth.username is required when HTTP basic caller auth is used")
			}
			if !authorityOIDCCallerAuthEnabled(authority) && authority.HTTP.BasicAuth.PasswordFile.IsZero() {
				addProblem(problems, path+".http.basic_auth.password_file is required when transport is http")
			}
		case transportGRPC:
			if strings.TrimSpace(authority.GRPC.Address) == "" {
				addProblem(problems, path+".grpc.address is required when transport is grpc")
			}
			grpcCallerAuthMethods := enabledCount(
				authority.GRPC.CallerAuth.Basic.Enabled,
				authority.GRPC.CallerAuth.Bearer.Enabled,
				authority.GRPC.CallerAuth.OIDC.Enabled,
			)
			if grpcCallerAuthMethods > 1 {
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
			if authority.GRPC.CallerAuth.OIDC.Enabled && !authorityOIDCCallerAuthEnabled(authority) {
				addProblem(problems, path+".grpc.caller_auth.oidc requires auth.authorities."+name+".oidc.client_credentials.enabled")
			}
		default:
			addProblem(problems, path+".transport must be http or grpc")
		}

		validateAuthorityOIDC(path+".oidc", authority.OIDC, problems)

		if authority.Mechanisms.Password.Enabled && len(authority.Mechanisms.Password.Names) == 0 {
			addProblem(problems, path+".mechanisms.password.names is required when password mechanisms are enabled")
		}
		validateBearerMechanism(path+".mechanisms.bearer", authority.Mechanisms.Bearer, problems)
	}
}

// validateBearerMechanism checks the advertised SASL bearer policy and introspection boundary.
func validateBearerMechanism(path string, bearer BearerMechanismConfig, problems *[]string) {
	if !bearer.Enabled {
		if bearer.Introspection.Enabled {
			validateBearerIntrospection(path+".introspection", bearer.Introspection, problems)
		}

		return
	}

	if len(bearer.Names) == 0 {
		addProblem(problems, path+".names is required when bearer mechanisms are enabled")
	}
	requirePositiveInt(path+".token_max_bytes", bearer.TokenMaxBytes, problems)

	if !bearerMechanismsNeedIntrospection(bearer.Names) {
		if bearer.Validation != "" && bearer.Validation != bearerValidationNauthilusIntrospection {
			addProblem(problems, path+".validation must be "+bearerValidationNauthilusIntrospection)
		}
		if bearer.Introspection.Enabled {
			validateBearerIntrospection(path+".introspection", bearer.Introspection, problems)
		}

		return
	}

	if bearer.Validation != bearerValidationNauthilusIntrospection {
		addProblem(problems, path+".validation must be "+bearerValidationNauthilusIntrospection+" when bearer names include xoauth2 or oauthbearer")
	}
	if !bearer.Introspection.Enabled {
		addProblem(problems, path+".introspection.enabled must be true when bearer names include xoauth2 or oauthbearer")

		return
	}

	validateBearerIntrospection(path+".introspection", bearer.Introspection, problems)
}

// validateBearerIntrospection rejects incomplete mail SASL bearer introspection config.
func validateBearerIntrospection(path string, introspection BearerIntrospectionConfig, problems *[]string) {
	if !introspection.Enabled {
		return
	}

	if strings.TrimSpace(introspection.Issuer) == "" && strings.TrimSpace(introspection.DiscoveryURL) == "" {
		addProblem(problems, path+".issuer or "+path+".discovery_url is required when introspection is enabled")
	}
	if strings.TrimSpace(introspection.ClientID) == "" {
		addProblem(problems, path+".client_id is required when introspection is enabled")
	}
	if strings.TrimSpace(introspection.RequiredScope) == "" {
		addProblem(problems, path+".required_scope is required when introspection is enabled")
	}
	validateBearerAccountClaim(path+".account_claim", introspection.AccountClaim, problems)
	validateBearerIntrospectionClientAuth(path, introspection, problems)

	switch strings.TrimSpace(introspection.ClientAssertionAlg) {
	case "", oidcAssertionAlgRS256, oidcAssertionAlgEdDSA:
	default:
		addProblem(problems, path+".client_assertion_alg must be RS256 or EdDSA")
	}
}

// validateBearerIntrospectionClientAuth checks endpoint client-auth material.
func validateBearerIntrospectionClientAuth(path string, introspection BearerIntrospectionConfig, problems *[]string) {
	secretCount := enabledSecretCount(introspection.ClientSecret, introspection.ClientSecretFile)
	if secretCount > 1 {
		addProblem(problems, path+" must not configure both client_secret and client_secret_file")
	}

	switch normalizedOIDCConfigMethod(introspection.AuthMethod) {
	case oidcClientSecretBasic, oidcClientSecretPost:
		if secretCount != 1 {
			addProblem(problems, path+" must configure exactly one of client_secret or client_secret_file for secret-based endpoint auth")
		}
		if !introspection.ClientPrivateKeyFile.IsZero() {
			addProblem(problems, path+".client_private_key_file must be empty for secret-based endpoint auth")
		}
	case oidcPrivateKeyJWT:
		if secretCount > 0 {
			addProblem(problems, path+" must not configure client_secret or client_secret_file when auth_method is private_key_jwt")
		}
		if introspection.ClientPrivateKeyFile.IsZero() {
			addProblem(problems, path+".client_private_key_file is required when auth_method is private_key_jwt")
		}
	case "":
		addProblem(problems, path+".auth_method is required when introspection is enabled")
	default:
		addProblem(problems, path+".auth_method must be client_secret_basic, client_secret_post or private_key_jwt")
	}
}

// validateBearerAccountClaim checks optional account-claim names without echoing values.
func validateBearerAccountClaim(path string, accountClaim string, problems *[]string) {
	accountClaim = strings.TrimSpace(accountClaim)
	if accountClaim == "" {
		return
	}

	if !printableClaimName(accountClaim) {
		addProblem(problems, path+" must be a printable non-secret claim name")

		return
	}

	if secretBearingClaimName(accountClaim) {
		addProblem(problems, path+" must not name a secret-bearing claim")
	}
}

// bearerMechanismsNeedIntrospection reports whether configured names carry end-user bearer tokens.
func bearerMechanismsNeedIntrospection(names []string) bool {
	return containsFold(names, bearerMechanismXOAUTH2) || containsFold(names, bearerMechanismOAuthBearer)
}

// printableClaimName reports whether a claim name avoids control and whitespace runes.
func printableClaimName(value string) bool {
	for _, char := range value {
		if !unicode.IsPrint(char) || unicode.IsSpace(char) {
			return false
		}
	}

	return true
}

// secretBearingClaimName reports claim names that must never become account keys.
func secretBearingClaimName(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case "access_token", "refresh_token", "id_token", "token", "client_secret", "password", "secret":
		return true
	default:
		return strings.Contains(normalized, "token") ||
			strings.Contains(normalized, "secret") ||
			strings.Contains(normalized, "password")
	}
}

// validateAuthorityOIDC checks OIDC caller-auth inputs only when the flow is enabled.
func validateAuthorityOIDC(path string, oidc AuthorityOIDCConfig, problems *[]string) {
	if !oidc.Enabled {
		return
	}

	clientCredentials := oidc.ClientCredentials
	if !clientCredentials.Enabled {
		return
	}

	if strings.TrimSpace(oidc.Issuer) == "" && strings.TrimSpace(oidc.DiscoveryURL) == "" {
		addProblem(problems, path+".issuer or "+path+".discovery_url is required when client_credentials is enabled")
	}
	if strings.TrimSpace(clientCredentials.ClientID) == "" {
		addProblem(problems, path+".client_credentials.client_id is required when client_credentials is enabled")
	}
	secretCount := enabledSecretCount(clientCredentials.ClientSecret, clientCredentials.ClientSecretFile)
	if secretCount > 1 {
		addProblem(problems, path+".client_credentials must not configure both client_secret and client_secret_file")
	}
	tokenMethod := normalizedOIDCConfigMethod(clientCredentials.TokenEndpointAuthMethod)
	switch tokenMethod {
	case oidcClientSecretBasic, oidcClientSecretPost:
		if secretCount != 1 {
			addProblem(problems, path+".client_credentials must configure exactly one of client_secret or client_secret_file for secret-based token endpoint auth")
		}
	case oidcPrivateKeyJWT:
		if clientCredentials.ClientPrivateKeyFile.IsZero() {
			addProblem(problems, path+".client_credentials.client_private_key_file is required when token_endpoint_auth_method is private_key_jwt")
		}
	case "":
		addProblem(problems, path+".client_credentials.token_endpoint_auth_method is required when client_credentials is enabled")
	default:
		addProblem(problems, path+".client_credentials.token_endpoint_auth_method must be client_secret_basic, client_secret_post or private_key_jwt")
	}
	introspectionMethod := normalizedOIDCConfigMethod(clientCredentials.IntrospectionEndpointAuthMethod)
	if introspectionMethod == "" {
		introspectionMethod = fallbackIntrospectionAuthMethod(tokenMethod)
	}
	switch introspectionMethod {
	case "":
	case oidcClientSecretBasic, oidcClientSecretPost:
		if secretCount != 1 {
			addProblem(problems, path+".client_credentials must configure exactly one of client_secret or client_secret_file for introspection endpoint auth")
		}
	case oidcPrivateKeyJWT:
		if clientCredentials.ClientPrivateKeyFile.IsZero() {
			addProblem(problems, path+".client_credentials.client_private_key_file is required when introspection_endpoint_auth_method is private_key_jwt")
		}
	default:
		addProblem(problems, path+".client_credentials.introspection_endpoint_auth_method must be client_secret_basic, client_secret_post or private_key_jwt")
	}
	switch strings.TrimSpace(clientCredentials.ClientAssertionAlg) {
	case "", oidcAssertionAlgRS256, oidcAssertionAlgEdDSA:
	default:
		addProblem(problems, path+".client_credentials.client_assertion_alg must be RS256 or EdDSA")
	}
	if len(clientCredentials.Scopes) == 0 {
		addProblem(problems, path+".client_credentials.scopes is required when client_credentials is enabled")
	}
	requirePositiveDuration(path+".client_credentials.refresh_before_expiry", clientCredentials.RefreshBeforeExpiry, problems)
}

// authorityOIDCCallerAuthEnabled reports whether OIDC caller auth can affect authority calls.
func authorityOIDCCallerAuthEnabled(authority AuthorityConfig) bool {
	return authority.OIDC.Enabled && authority.OIDC.ClientCredentials.Enabled
}

// fallbackIntrospectionAuthMethod inherits only Nauthilus-supported secret methods.
func fallbackIntrospectionAuthMethod(tokenMethod string) string {
	switch normalizedOIDCConfigMethod(tokenMethod) {
	case oidcClientSecretBasic, oidcClientSecretPost, oidcPrivateKeyJWT:
		return normalizedOIDCConfigMethod(tokenMethod)
	default:
		return ""
	}
}

// normalizedOIDCConfigMethod canonicalizes configured OIDC client auth method names.
func normalizedOIDCConfigMethod(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// enabledSecretCount counts configured protected secret scalar values.
func enabledSecretCount(values ...SecretString) int {
	count := 0
	for _, value := range values {
		if !value.IsZero() {
			count++
		}
	}

	return count
}

// enabledCount counts selected mutually exclusive boolean options.
func enabledCount(values ...bool) int {
	count := 0
	for _, value := range values {
		if value {
			count++
		}
	}

	return count
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
	if strings.TrimSpace(director.Routing.AuthAttributes.Tenant) == "" {
		addProblem(problems, "director.routing.auth_attributes.tenant is required")
	}
	if strings.TrimSpace(director.Routing.AuthAttributes.ShardTag) == "" {
		addProblem(problems, "director.routing.auth_attributes.shard_tag is required")
	}
	validateMaintenanceMode("director.maintenance.default_mode", director.Maintenance.DefaultMode, "disabled", problems)

	for name, listener := range director.Listeners {
		path := "director.listeners." + name
		authority, authorityOK := authorities[listener.Authority]
		if !authorityOK {
			addProblem(problems, path+".authority references unknown authority "+listener.Authority)
		}
		validateAuthorityContext(path+".authority_context", listener.AuthorityContext, problems)

		pool, poolOK := director.BackendPools[listener.BackendPool]
		if !poolOK {
			addProblem(problems, path+".backend_pool references unknown pool "+listener.BackendPool)
		} else if !strings.EqualFold(strings.TrimSpace(listener.Protocol), strings.TrimSpace(pool.Protocol)) {
			addProblem(problems, path+".backend_pool references pool with different protocol "+listener.BackendPool)
		}

		switch listener.Protocol {
		case protocolIMAP:
		case protocolLMTP:
		case protocolSIEVE:
		case protocolPOP3:
		default:
			addProblem(problems, path+".protocol must be imap, lmtp, pop3, or sieve")
		}

		if listenerTLSModeIsPlaintext(listener.TLS.Mode) && listener.Protocol != protocolLMTP {
			addProblem(problems, path+".tls.mode plaintext is supported only for lmtp listeners")
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
		if listener.Protocol == protocolSIEVE && listener.Sieve == nil {
			addProblem(problems, path+".sieve is required for sieve listeners")
		}
		if listener.Protocol == protocolSIEVE {
			if listener.IMAP != nil {
				addProblem(problems, path+".imap must not be set for sieve listeners")
			}
			if listener.LMTP != nil {
				addProblem(problems, path+".lmtp must not be set for sieve listeners")
			}
			if listener.Sieve != nil {
				validateSieveListener(path+".sieve", listener, authority, authorityOK, problems)
			}
		}
		if listener.Protocol == protocolPOP3 && listener.POP3 == nil {
			addProblem(problems, path+".pop3 is required for pop3 listeners")
		}
		if listener.Protocol == protocolPOP3 {
			if listener.IMAP != nil {
				addProblem(problems, path+".imap must not be set for pop3 listeners")
			}
			if listener.LMTP != nil {
				addProblem(problems, path+".lmtp must not be set for pop3 listeners")
			}
			if listener.Sieve != nil {
				addProblem(problems, path+".sieve must not be set for pop3 listeners")
			}
			if listener.POP3 != nil {
				validatePOP3Listener(path+".pop3", listener, authority, authorityOK, problems)
			}
		}
		if strings.TrimSpace(listener.TLS.Mode) == "" {
			addProblem(problems, path+".tls.mode is required")
		} else if !validListenerTLSMode(listener.TLS.Mode) {
			addProblem(problems, path+".tls.mode must be starttls, implicit, plaintext, disabled, or none")
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

	bearerReplayMechanisms := bearerReplayMechanismsByBackend(director)
	for name, backend := range director.Backends {
		path := "director.backends." + name
		validateBackendProtocol(path, backend.Protocol, problems)
		requireNonNegativeInt(path+".weight", backend.Weight, problems)
		requirePositiveInt(path+".max_connections", backend.MaxConnections, problems)
		validateMaintenanceMode(path+".maintenance", backend.Maintenance, director.Maintenance.DefaultMode, problems)
		validateBackendAddress(path+".address", backend.Address, problems)
		validateBackendTLS(path+".tls", backend.Address, backend.TLS, problems)
		validateBackendAuth(path+".auth", backend, bearerReplayMechanisms[name], problems)
		if backend.HealthCheck.Enabled && backend.HealthCheck.PasswordFile.IsZero() {
			addProblem(problems, path+".health_check.password_file is required when health check is enabled")
		}
	}

	requirePositiveDuration("director.affinity.active_user_pinning.idle_grace", director.Affinity.ActiveUserPinning.IdleGrace, problems)
	validateBackendRetention("director.affinity.backend_retention", director.Affinity.BackendRetention, problems)
	requirePositiveDuration("director.affinity.local_cache.ttl", director.Affinity.LocalCache.TTL, problems)
	requirePositiveInt("director.affinity.local_cache.max_entries", director.Affinity.LocalCache.MaxEntries, problems)
	validateUserHolds("director.affinity.user_holds", director.Affinity.UserHolds, problems)
	requirePositiveDuration("director.health.interval", director.Health.Interval, problems)
	requirePositiveDuration("director.health.timeout", director.Health.Timeout, problems)
	requirePositiveDuration("director.maintenance.drain_timeout", director.Maintenance.DrainTimeout, problems)
	requirePositiveDuration("director.maintenance.hard_kill_grace", director.Maintenance.HardKillGrace, problems)
}

// bearerReplayMechanismsByBackend maps bearer-capable login pools to concrete backend entries.
func bearerReplayMechanismsByBackend(director DirectorConfig) map[string]map[string]bool {
	mechanismsByPool := make(map[string]map[string]bool)
	for _, listener := range director.Listeners {
		mechanisms := listenerBearerReplayMechanisms(listener)
		if len(mechanisms) == 0 {
			continue
		}

		poolMechanisms := mechanismsByPool[listener.BackendPool]
		if poolMechanisms == nil {
			poolMechanisms = make(map[string]bool)
			mechanismsByPool[listener.BackendPool] = poolMechanisms
		}
		for mechanism := range mechanisms {
			poolMechanisms[mechanism] = true
		}
	}

	mechanismsByBackend := make(map[string]map[string]bool)
	for poolName, mechanisms := range mechanismsByPool {
		pool, ok := director.BackendPools[poolName]
		if !ok {
			continue
		}

		for _, backendName := range pool.Backends {
			backendMechanisms := mechanismsByBackend[backendName]
			if backendMechanisms == nil {
				backendMechanisms = make(map[string]bool)
				mechanismsByBackend[backendName] = backendMechanisms
			}
			for mechanism := range mechanisms {
				backendMechanisms[mechanism] = true
			}
		}
	}

	return mechanismsByBackend
}

// listenerBearerReplayMechanisms returns bearer mechanisms that can reach user-stateful backend auth.
func listenerBearerReplayMechanisms(listener ListenerConfig) map[string]bool {
	switch strings.ToLower(strings.TrimSpace(listener.Protocol)) {
	case protocolIMAP:
		if listener.IMAP == nil {
			return nil
		}

		return configuredBearerMechanisms(listener.IMAP.AuthMechanisms)
	case protocolSIEVE:
		if listener.Sieve == nil {
			return nil
		}

		return configuredBearerMechanisms(listener.Sieve.AuthMechanisms)
	case protocolPOP3:
		if listener.POP3 == nil {
			return nil
		}

		return configuredBearerMechanisms(listener.POP3.AuthMechanisms)
	default:
		return nil
	}
}

// configuredBearerMechanisms filters a frontend mechanism list to supported bearer names.
func configuredBearerMechanisms(values []string) map[string]bool {
	mechanisms := make(map[string]bool)
	for _, value := range values {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case bearerMechanismXOAUTH2:
			mechanisms[bearerMechanismXOAUTH2] = true
		case bearerMechanismOAuthBearer:
			mechanisms[bearerMechanismOAuthBearer] = true
		}
	}

	if len(mechanisms) == 0 {
		return nil
	}

	return mechanisms
}

// validateAuthorityContext rejects listener authority context that could override transport state.
func validateAuthorityContext(path string, context AuthorityContextConfig, problems *[]string) {
	validateAuthorityHTTPHeaders(path+".http_headers", context.HTTPHeaders, problems)
	validateAuthorityGRPCMetadata(path+".grpc_metadata", context.GRPCMetadata, problems)
}

// validateAuthorityHTTPHeaders checks safe static HTTP header names and non-empty values.
func validateAuthorityHTTPHeaders(path string, headers map[string]AuthorityContextValue, problems *[]string) {
	for name, value := range headers {
		trimmedName := strings.TrimSpace(name)
		if trimmedName == "" {
			addProblem(problems, path+" contains an empty header name")

			continue
		}

		if !validHTTPHeaderName(trimmedName) {
			addProblem(problems, path+" contains an invalid header name")

			continue
		}

		if reservedAuthorityContextName(trimmedName) {
			addProblem(problems, path+" contains a reserved header name")

			continue
		}

		if strings.TrimSpace(string(value)) == "" {
			addProblem(problems, path+" contains an empty value")
		}
	}
}

// validateAuthorityGRPCMetadata checks safe static gRPC metadata keys and non-empty values.
func validateAuthorityGRPCMetadata(path string, metadata map[string]AuthorityContextValue, problems *[]string) {
	for name, value := range metadata {
		trimmedName := strings.TrimSpace(name)
		if trimmedName == "" {
			addProblem(problems, path+" contains an empty metadata key")

			continue
		}

		if !lowercaseASCII(trimmedName) {
			addProblem(problems, path+" contains a metadata key that must be lowercase ASCII")

			continue
		}

		if !validGRPCMetadataKey(trimmedName) {
			addProblem(problems, path+" contains an invalid metadata key")

			continue
		}

		if reservedAuthorityContextName(trimmedName) {
			addProblem(problems, path+" contains a reserved metadata key")

			continue
		}

		if strings.TrimSpace(string(value)) == "" {
			addProblem(problems, path+" contains an empty value")
		}
	}
}

// reservedAuthorityContextName reports names owned by credentials, sessions or transports.
func reservedAuthorityContextName(name string) bool {
	normalized := strings.ToLower(strings.TrimSpace(name))
	if strings.HasPrefix(normalized, authorityContextGRPCPrefix) {
		return true
	}

	switch normalized {
	case authorityContextNameAuthorization,
		authorityContextNameProxyAuthorization,
		authorityContextNameCookie,
		authorityContextNameSetCookie,
		authorityContextNameContentType,
		authorityContextNameAccept,
		authorityContextNameHost,
		authorityContextNameTE:
		return true
	default:
		return false
	}
}

// validHTTPHeaderName reports whether name is an RFC token-shaped HTTP field name.
func validHTTPHeaderName(name string) bool {
	if name == "" {
		return false
	}

	for index := range len(name) {
		if !validHTTPTokenByte(name[index]) {
			return false
		}
	}

	return true
}

// validHTTPTokenByte reports whether value is allowed in an HTTP token.
func validHTTPTokenByte(value byte) bool {
	switch {
	case value >= 'a' && value <= 'z':
	case value >= 'A' && value <= 'Z':
	case value >= '0' && value <= '9':
	case value == '!' || value == '#' || value == '$' || value == '%' || value == '&' ||
		value == '\'' || value == '*' || value == '+' || value == '-' || value == '.' ||
		value == '^' || value == '_' || value == '`' || value == '|' || value == '~':
	default:
		return false
	}

	return true
}

// lowercaseASCII reports whether key contains no uppercase or non-ASCII bytes.
func lowercaseASCII(key string) bool {
	for index := range len(key) {
		value := key[index]
		if value > 0x7f || (value >= 'A' && value <= 'Z') {
			return false
		}
	}

	return true
}

// validGRPCMetadataKey reports whether key follows grpc-go metadata key grammar.
func validGRPCMetadataKey(key string) bool {
	if key == "" {
		return false
	}

	for index := range len(key) {
		value := key[index]
		switch {
		case value >= 'a' && value <= 'z':
		case value >= '0' && value <= '9':
		case value == '-' || value == '_' || value == '.':
		default:
			return false
		}
	}

	return true
}

// validateBackendRetention enforces explicit opt-out for zero retained binding TTL.
func validateBackendRetention(path string, retention BackendRetentionConfig, problems *[]string) {
	requireNonNegativeDuration(path+".default_ttl", retention.DefaultTTL, problems)
	requireNonNegativeDuration(path+".max_ttl", retention.MaxTTL, problems)

	if !retention.Enabled {
		return
	}

	requirePositiveDuration(path+".default_ttl", retention.DefaultTTL, problems)
	requirePositiveDuration(path+".max_ttl", retention.MaxTTL, problems)

	if retention.DefaultTTL > retention.MaxTTL {
		addProblem(problems, path+".default_ttl must not exceed "+path+".max_ttl")
	}
}

// validateUserHolds enforces bounded placement holds and local waiter limits.
func validateUserHolds(path string, holds UserHoldsConfig, problems *[]string) {
	requirePositiveDuration(path+".max_duration", holds.MaxDuration, problems)
	requirePositiveDuration(path+".max_wait", holds.MaxWait, problems)
	requirePositiveDuration(path+".poll_interval", holds.PollInterval, problems)

	if holds.PollInterval > holds.MaxWait {
		addProblem(problems, path+".poll_interval must not exceed "+path+".max_wait")
	}

	requirePositiveInt(path+".max_local_waiters", holds.MaxLocalWaiters, problems)
	requirePositiveInt(path+".max_local_waiters_per_user", holds.MaxLocalWaitersPerUser, problems)

	if holds.MaxLocalWaitersPerUser > holds.MaxLocalWaiters {
		addProblem(problems, path+".max_local_waiters_per_user must not exceed "+path+".max_local_waiters")
	}
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
	case protocolSIEVE:
		if strings.ToLower(strings.TrimSpace(pool.Selector)) != "rendezvous_hash" {
			addProblem(problems, path+".selector for Sieve pools must be rendezvous_hash")
		}
	case protocolPOP3:
		if strings.ToLower(strings.TrimSpace(pool.Selector)) != "rendezvous_hash" {
			addProblem(problems, path+".selector for POP3 pools must be rendezvous_hash")
		}
	default:
		addProblem(problems, path+".protocol must be imap, lmtp, pop3, or sieve")
	}
}

// validateBackendProtocol rejects backend protocols without production support.
func validateBackendProtocol(path string, protocol string, problems *[]string) {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case protocolIMAP, protocolLMTP, protocolSIEVE, protocolPOP3:
	default:
		addProblem(problems, path+".protocol must be imap, lmtp, pop3, or sieve")
	}
}

// validateIMAPListener rejects unsupported pre-auth advertisements and mechanisms.
func validateIMAPListener(path string, listener ListenerConfig, imap IMAPListenerConfig, problems *[]string) {
	if len(imap.AuthMechanisms) > 0 && !listenerTLSProtectsCredentialAuth(listener.TLS.Mode) {
		addProblem(problems, path+".auth_mechanisms requires frontend TLS mode starttls or implicit")
	}

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

	validatePlaintextLMTPListener(path, listener, *lmtp, problems)
	validateLMTPClientMTLS(path+".client_auth.mtls", listener, lmtp.ClientAuth, problems)
	validateLMTPSizePolicy(path+".size", lmtp.Size, problems)
	validateLMTPCapabilities(path+".capabilities", listener, *lmtp, problems)
	validateLMTPCapabilityFilter(path+".capability_filter.deny", *lmtp, problems)
	validateLMTPCapabilityOverlap(path, *lmtp, problems)
}

// validatePlaintextLMTPListener rejects credential-capable auth on no-TLS LMTP listeners.
func validatePlaintextLMTPListener(path string, listener ListenerConfig, lmtp LMTPListenerConfig, problems *[]string) {
	if !listenerTLSModeIsPlaintext(listener.TLS.Mode) {
		return
	}

	if lmtp.ClientAuth.Required {
		addProblem(problems, path+".client_auth.required must be false for plaintext listener")
	}

	if len(lmtp.ClientAuth.Mechanisms) > 0 {
		addProblem(problems, path+".client_auth.mechanisms must be empty for plaintext listener")
	}
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
		case capability == lmtpCapabilitySMTPUTF8:
			continue
		case capability == lmtpCapability8BITMIME:
			continue
		case capability == lmtpCapabilityEnhancedStatus:
			continue
		case capability == lmtpCapabilitySTARTTLS:
			if listenerTLSModeIsPlaintext(listener.TLS.Mode) {
				addProblem(problems, path+" must not advertise STARTTLS for plaintext listener")
			} else if listener.TLS.Mode != listenerTLSModeStartTLS {
				addProblem(problems, path+" advertises STARTTLS for non-starttls listener TLS mode")
			}
		case capability == lmtpCapabilityCHUNKING:
			if !lmtpBDATImplemented {
				addProblem(problems, path+" advertises CHUNKING before BDAT support and backend capability mediation are implemented")
			}
		case capability == lmtpCapabilityPIPELINING:
			continue
		case capability == lmtpCapabilitySIZE:
			requirePositiveLMTPSizePolicy(path, lmtp, problems)
		case strings.HasPrefix(capability, "AUTH "):
			if listenerTLSModeIsPlaintext(listener.TLS.Mode) {
				addProblem(problems, path+" must not advertise AUTH for plaintext listener")

				continue
			}

			validateLMTPAuthCapability(path, capability, lmtp.ClientAuth.Mechanisms, problems)
		case capability == "AUTH":
			if listenerTLSModeIsPlaintext(listener.TLS.Mode) {
				addProblem(problems, path+" must not advertise AUTH for plaintext listener")
			} else {
				addProblem(problems, path+" AUTH capability requires at least one mechanism")
			}
		default:
			addProblem(problems, path+" contains unsupported capability "+capability)
		}
	}
}

// validateLMTPSizePolicy rejects invalid listener-owned message-size policy values.
func validateLMTPSizePolicy(path string, size LMTPSizeConfig, problems *[]string) {
	requireNonNegativeInt64(path+".max_message_bytes", size.MaxMessageBytes, problems)
}

// requirePositiveLMTPSizePolicy enforces the future SIZE advertisement prerequisite.
func requirePositiveLMTPSizePolicy(path string, lmtp LMTPListenerConfig, problems *[]string) {
	if lmtp.Size.MaxMessageBytes <= 0 {
		addProblem(problems, path+" requires positive size.max_message_bytes when SIZE is configured")
	}
}

// validateLMTPCapabilityFilter rejects capability-filter entries that cannot be fully enforced.
func validateLMTPCapabilityFilter(path string, lmtp LMTPListenerConfig, problems *[]string) {
	for _, capability := range lmtp.CapabilityFilter.Deny {
		validateLMTPCapabilityFilterEntry(path, capability, problems)
	}
}

// validateLMTPCapabilityFilterEntry checks one whole-capability deny token.
func validateLMTPCapabilityFilterEntry(path string, capability string, problems *[]string) {
	token := strings.TrimSpace(capability)
	if token == "" {
		addProblem(problems, path+" contains empty capability")

		return
	}

	if strings.Contains(token, ",") {
		addProblem(problems, path+" contains comma-shaped capability "+token)

		return
	}

	if strings.Contains(token, "=") {
		addProblem(problems, path+" contains ambiguous parameterized capability "+token)

		return
	}

	fields := strings.Fields(token)
	if len(fields) != 1 {
		addProblem(problems, path+" contains ambiguous parameterized capability "+token)

		return
	}

	if lmtpCapabilityFilterRejectsCommand(fields[0]) {
		addProblem(problems, path+" contains LMTP command name "+fields[0])

		return
	}

	if !validLMTPCapabilityFilterToken(fields[0]) {
		addProblem(problems, path+" contains unsupported capability "+fields[0])
	}
}

// validateLMTPCapabilityOverlap rejects contradictory allowlist and deny-filter entries.
func validateLMTPCapabilityOverlap(path string, lmtp LMTPListenerConfig, problems *[]string) {
	denied := make(map[string]struct{}, len(lmtp.CapabilityFilter.Deny))
	for _, capability := range lmtp.CapabilityFilter.Deny {
		if validLMTPCapabilityFilterToken(capability) {
			denied[capability] = struct{}{}
		}
	}

	for _, capability := range lmtp.Capabilities {
		if _, ok := denied[capability]; ok {
			addProblem(problems, path+".capability_filter.deny overlaps "+path+".capabilities on "+capability)

			continue
		}

		if _, ok := denied[lmtpCapabilityAuth]; ok && lmtpCapabilityName(capability) == lmtpCapabilityAuth {
			addProblem(problems, path+".capability_filter.deny overlaps "+path+".capabilities on "+lmtpCapabilityAuth)
		}
	}
}

// lmtpCapabilityFilterRejectsCommand reports ordinary command names that are not filterable capabilities.
func lmtpCapabilityFilterRejectsCommand(value string) bool {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "BDAT", "DATA", "LHLO", "MAIL", "NOOP", "QUIT", "RCPT", "RSET":
		return true
	default:
		return false
	}
}

// validLMTPCapabilityFilterToken reports whole LMTP extension names supported by the policy surface.
func validLMTPCapabilityFilterToken(value string) bool {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case lmtpCapability8BITMIME,
		lmtpCapabilityAuth,
		lmtpCapabilityCHUNKING,
		lmtpCapabilityEnhancedStatus,
		lmtpCapabilityPIPELINING,
		lmtpCapabilitySIZE,
		lmtpCapabilitySMTPUTF8,
		lmtpCapabilitySTARTTLS:
		return true
	default:
		return false
	}
}

// lmtpCapabilityName returns the whole-capability name for overlap checks.
func lmtpCapabilityName(value string) string {
	fields := strings.Fields(strings.ToUpper(strings.TrimSpace(value)))
	if len(fields) == 0 {
		return ""
	}

	return fields[0]
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

// validateSieveListener rejects unsafe ManageSieve pre-auth and capability policy.
func validateSieveListener(path string, listener ListenerConfig, authority AuthorityConfig, authorityKnown bool, problems *[]string) {
	sieve := listener.Sieve
	if sieve == nil {
		addProblem(problems, path+" is required for sieve listeners")

		return
	}

	if len(sieve.AuthMechanisms) == 0 {
		addProblem(problems, path+".auth_mechanisms is required")
	}

	if len(sieve.AuthMechanisms) > 0 && !listenerTLSProtectsCredentialAuth(listener.TLS.Mode) {
		addProblem(problems, path+".auth_mechanisms requires frontend TLS mode starttls or implicit")
	}

	for _, mechanism := range sieve.AuthMechanisms {
		if !validSieveAuthMechanism(mechanism) {
			addProblem(problems, path+".auth_mechanisms contains unsupported mechanism "+mechanism)

			continue
		}

		if authorityKnown && !sieveMechanismSupportedByAuthority(mechanism, authority) {
			addProblem(problems, path+".auth_mechanisms contains mechanism not supported by authority "+mechanism)
		}
	}

	validateSieveCapabilities(path+".capabilities", sieve.Capabilities, problems)
}

// validateSieveCapabilities keeps ManageSieve facts typed rather than transcript-shaped.
func validateSieveCapabilities(path string, capabilities SieveCapabilitiesConfig, problems *[]string) {
	for _, extension := range capabilities.ScriptExtensions {
		if !validSieveCapabilityToken(extension) {
			addProblem(problems, path+".script_extensions contains malformed extension "+extension)
		}
	}

	if !validSieveCapabilityToken(capabilities.Language) {
		addProblem(problems, path+".language must be a non-empty safe language tag")
	}
}

// validListenerTLSMode reports whether the shared listener lifecycle can enforce this TLS mode.
func validListenerTLSMode(mode string) bool {
	switch normalizeListenerTLSMode(mode) {
	case listenerTLSModeStartTLS, listenerTLSModeImplicit, listenerTLSModePlaintext:
		return true
	default:
		return false
	}
}

// listenerTLSProtectsCredentialAuth reports whether credential-bearing SASL can be gated by TLS.
func listenerTLSProtectsCredentialAuth(mode string) bool {
	switch normalizeListenerTLSMode(mode) {
	case listenerTLSModeStartTLS, listenerTLSModeImplicit:
		return true
	default:
		return false
	}
}

// listenerTLSModeIsPlaintext reports whether the listener has no TLS upgrade surface.
func listenerTLSModeIsPlaintext(mode string) bool {
	return normalizeListenerTLSMode(mode) == listenerTLSModePlaintext
}

// validSieveAuthMechanism reports whether ManageSieve frontend auth can accept this mechanism shape.
func validSieveAuthMechanism(mechanism string) bool {
	switch strings.ToUpper(strings.TrimSpace(mechanism)) {
	case "PLAIN", "XOAUTH2", "OAUTHBEARER":
		return true
	default:
		return false
	}
}

// sieveMechanismSupportedByAuthority checks the selected authority mechanism class.
func sieveMechanismSupportedByAuthority(mechanism string, authority AuthorityConfig) bool {
	mechanism = strings.ToLower(strings.TrimSpace(mechanism))
	switch mechanism {
	case "plain":
		return authority.Mechanisms.Password.Enabled && containsFold(authority.Mechanisms.Password.Names, mechanism)
	case "xoauth2", "oauthbearer":
		return authority.Mechanisms.Bearer.Enabled && containsFold(authority.Mechanisms.Bearer.Names, mechanism)
	default:
		return false
	}
}

// validSieveCapabilityToken accepts extension and language tokens without wire syntax.
func validSieveCapabilityToken(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}

	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z':
		case char >= 'A' && char <= 'Z':
		case char >= '0' && char <= '9':
		case char == '-' || char == '_' || char == '.':
		default:
			return false
		}
	}

	return true
}

// validatePOP3Listener rejects unsafe POP3 frontend auth and CAPA policy.
func validatePOP3Listener(path string, listener ListenerConfig, authority AuthorityConfig, authorityKnown bool, problems *[]string) {
	pop3 := listener.POP3
	if pop3 == nil {
		addProblem(problems, path+" is required for pop3 listeners")

		return
	}

	if len(pop3.AuthMechanisms) == 0 {
		addProblem(problems, path+".auth_mechanisms is required")
	}

	if len(pop3.AuthMechanisms) > 0 && !listenerTLSProtectsCredentialAuth(listener.TLS.Mode) {
		addProblem(problems, path+".auth_mechanisms requires frontend TLS mode starttls or implicit")
	}

	for _, mechanism := range pop3.AuthMechanisms {
		if !validPOP3AuthMethod(mechanism) {
			addProblem(problems, path+".auth_mechanisms contains unsupported method "+mechanism)

			continue
		}

		if authorityKnown && !pop3MethodSupportedByAuthority(mechanism, authority) {
			addProblem(problems, path+".auth_mechanisms contains method not supported by authority "+mechanism)
		}
	}

	validatePOP3Capabilities(path+".capabilities", listener, pop3.Capabilities, problems)
}

// validatePOP3Capabilities keeps POP3 CAPA policy bounded and renderer-owned.
func validatePOP3Capabilities(path string, listener ListenerConfig, capabilities []string, problems *[]string) {
	for _, capability := range capabilities {
		normalized := strings.ToUpper(strings.TrimSpace(capability))
		switch normalized {
		case "USER", "SASL", "TOP", "UIDL", "RESP-CODES", "PIPELINING":
		case "STLS":
			if listener.TLS.Mode != "starttls" {
				addProblem(problems, path+" advertises STLS for non-starttls listener TLS mode")
			}
		default:
			addProblem(problems, path+" contains unsupported capability "+capability)
		}
	}
}

// validPOP3AuthMethod reports whether POP3 frontend auth can accept this method.
func validPOP3AuthMethod(mechanism string) bool {
	switch strings.ToLower(strings.TrimSpace(mechanism)) {
	case "userpass", "xoauth2", "oauthbearer":
		return true
	default:
		return false
	}
}

// pop3MethodSupportedByAuthority checks the selected authority mechanism class.
func pop3MethodSupportedByAuthority(mechanism string, authority AuthorityConfig) bool {
	mechanism = strings.ToLower(strings.TrimSpace(mechanism))
	switch mechanism {
	case "userpass":
		return authority.Mechanisms.Password.Enabled
	case "xoauth2", "oauthbearer":
		return authority.Mechanisms.Bearer.Enabled && containsFold(authority.Mechanisms.Bearer.Names, mechanism)
	default:
		return false
	}
}

// containsFold reports whether a string list contains a case-insensitive match.
func containsFold(values []string, needle string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(needle)) {
			return true
		}
	}

	return false
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
	case "disabled", "none", "plaintext":
		return
	case "starttls", "implicit":
	default:
		addProblem(problems, path+".mode must be disabled, none, plaintext, starttls, or implicit")

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
func validateBackendAuth(path string, backend BackendConfig, bearerReplayMechanisms map[string]bool, problems *[]string) {
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
	if protocol == protocolSIEVE {
		switch mode {
		case backendAuthModeMasterUser, backendAuthModeCredentialReplay:
		default:
			addProblem(problems, path+".mode for Sieve backends must be master_user or credential_replay")

			return
		}
	}
	if protocol == protocolPOP3 {
		switch mode {
		case backendAuthModeMasterUser, backendAuthModeCredentialReplay:
		default:
			addProblem(problems, path+".mode for POP3 backends must be master_user or credential_replay")

			return
		}
	}

	switch mode {
	case backendAuthModeMasterUser:
		validateMasterUserAuth(path+".master_user", backend.Auth.MasterUser, problems)
		validateMasterUserBearerReplayAuth(path+".credential_replay", backend, bearerReplayMechanisms, problems)
	case backendAuthModeCredentialReplay:
		validateCredentialReplayAuth(path+".credential_replay", backend, problems)
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

// validateMasterUserBearerReplayAuth checks the bearer replay sidecar used by hybrid master-user mode.
func validateMasterUserBearerReplayAuth(path string, backend BackendConfig, requiredMechanisms map[string]bool, problems *[]string) {
	if len(requiredMechanisms) == 0 {
		return
	}

	replay := backend.Auth.CredentialReplay
	allowed := make(map[string]bool, len(replay.AllowedMechanisms))
	if len(replay.AllowedMechanisms) == 0 {
		addProblem(problems, path+".allowed_mechanisms must include bearer mechanisms for master_user mode")
	}
	for _, mechanism := range replay.AllowedMechanisms {
		normalized := strings.ToLower(strings.TrimSpace(mechanism))
		if !validBackendReplayMechanism(normalized) {
			addProblem(problems, path+".allowed_mechanisms contains unsupported mechanism "+mechanism)

			continue
		}

		allowed[normalized] = true
	}
	for mechanism := range requiredMechanisms {
		if !allowed[mechanism] {
			addProblem(problems, path+".allowed_mechanisms must include "+mechanism+" for master_user bearer replay")
		}
	}
	if !replay.RequireBackendTLS {
		addProblem(problems, path+".require_backend_tls must be true for master_user bearer replay")
	}
	if !backendTLSCanVerify(backend.TLS) {
		addProblem(problems, path+" requires verified backend TLS for master_user bearer replay")
	}
}

// validateCredentialReplayAuth checks replay allowlists before runtime can use credentials.
func validateCredentialReplayAuth(path string, backend BackendConfig, problems *[]string) {
	replay := backend.Auth.CredentialReplay
	if len(replay.AllowedMechanisms) == 0 {
		addProblem(problems, path+".allowed_mechanisms is required in credential_replay mode")
	}
	for _, mechanism := range replay.AllowedMechanisms {
		if !validBackendReplayMechanism(mechanism) {
			addProblem(problems, path+".allowed_mechanisms contains unsupported mechanism "+mechanism)
		}
	}

	protocol := strings.ToLower(strings.TrimSpace(backend.Protocol))
	if protocol == protocolSIEVE || protocol == protocolPOP3 {
		if !replay.RequireBackendTLS {
			addProblem(problems, path+".require_backend_tls must be true for "+protocol+" credential_replay")
		}

		if !backendTLSCanVerify(backend.TLS) {
			addProblem(problems, path+" requires verified backend TLS")
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
	case "plain", "login", "userpass", "xoauth2", "oauthbearer":
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

// requireNonNegativeDuration records a path-specific error for negative durations.
func requireNonNegativeDuration(path string, value Duration, problems *[]string) {
	if value < 0 {
		addProblem(problems, path+" must not be negative")
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

// requireNonNegativeInt64 records a path-specific error for negative 64-bit integers.
func requireNonNegativeInt64(path string, value int64, problems *[]string) {
	if value < 0 {
		addProblem(problems, path+" must not be negative")
	}
}

// addProblem accumulates validation failures without losing path context.
func addProblem(problems *[]string, message string) {
	*problems = append(*problems, message)
}
