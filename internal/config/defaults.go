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

//nolint:funlen,goconst // Defaults intentionally spell out the canonical YAML surface.
package config

import "time"

// Duration is a YAML-friendly duration used by typed config.
type Duration time.Duration

// NewDuration converts a standard duration into a config duration.
func NewDuration(value time.Duration) Duration {
	return Duration(value)
}

// Std returns the standard library duration value.
func (d Duration) Std() time.Duration {
	return time.Duration(d)
}

// String returns the Go duration syntax used in YAML dumps.
func (d Duration) String() string {
	return time.Duration(d).String()
}

// MarshalYAML writes durations as stable strings such as "30s".
func (d Duration) MarshalYAML() (any, error) {
	return d.String(), nil
}

// DefaultConfig returns canonical production defaults for stable foundation paths.
func DefaultConfig() Config {
	return Config{
		Runtime: RuntimeConfig{
			InstanceName: "nauthilus-director-01",
			Process: ProcessConfig{
				ShutdownTimeout: NewDuration(30 * time.Second),
			},
			Servers: RuntimeServersConfig{
				Control: ControlServerConfig{
					Enabled: true,
					Address: "127.0.0.1:9090",
					Auth: ControlAuthConfig{
						Bearer: ControlBearerAuthConfig{
							Enabled:   true,
							TokenFile: Secret("/etc/nauthilus-director/control-token"),
						},
						OIDC: ControlOIDCAuthConfig{
							Enabled:        true,
							Authority:      "default",
							Validation:     "nauthilus",
							RequiredScopes: []string{"nauthilus-director.admin"},
						},
						MTLS: ControlMTLSAuthConfig{},
					},
					TLS: ControlTLSConfig{
						Cert:          "/etc/nauthilus-director/control.crt",
						Key:           Secret("/etc/nauthilus-director/control.key"),
						ClientCA:      "/etc/nauthilus-director/control-client-ca.pem",
						MinTLSVersion: "TLS1.2",
					},
				},
			},
			Timeouts: RuntimeTimeouts{
				Preauth:        NewDuration(30 * time.Second),
				Auth:           NewDuration(10 * time.Second),
				Nauthilus:      NewDuration(5 * time.Second),
				BackendConnect: NewDuration(5 * time.Second),
				ProxyIdle:      NewDuration(30 * time.Minute),
				Shutdown:       NewDuration(30 * time.Second),
			},
			Clients: RuntimeClients{
				HTTP: HTTPClientConfig{
					MaxConnectionsPerHost:     20,
					MaxIdleConnections:        20,
					MaxIdleConnectionsPerHost: 10,
					IdleConnectionTimeout:     NewDuration(30 * time.Second),
				},
			},
		},
		Observability: defaultObservability(),
		Storage:       StorageConfig{Redis: defaultRedis()},
		Auth:          AuthConfig{Authorities: map[string]AuthorityConfig{"default": defaultAuthority()}},
		Director:      defaultDirector(),
	}
}

// defaultObservability returns conservative logging, metrics and tracing defaults.
func defaultObservability() ObservabilityConfig {
	return ObservabilityConfig{
		Log: LogConfig{
			Level:                "info",
			JSON:                 true,
			RedactSecrets:        true,
			UsernameHashSaltFile: Secret("/etc/nauthilus-director/username-hash-salt"),
		},
		Metrics: MetricsConfig{
			Enabled:        true,
			Path:           "/metrics",
			RuntimeMetrics: true,
		},
		Tracing: TracingConfig{
			Enabled:     true,
			ServiceName: "nauthilus-director",
			Exporter:    "otlp",
			Endpoint:    "127.0.0.1:4317",
			SampleRatio: 0.1,
		},
		Profiles: ProfilesConfig{
			PProf: ProfileConfig{},
			Block: ProfileConfig{},
		},
	}
}

// defaultRedis returns the central Redis state configuration used by runtime coordination.
func defaultRedis() RedisConfig {
	return RedisConfig{
		Enabled:       true,
		Protocol:      3,
		Mode:          "standalone",
		KeyPrefix:     "nauthilus-director:",
		SchemaVersion: 1,
		Namespaces: RedisNamespaces{
			Affinity:       "affinity:",
			Sessions:       "sessions:",
			BackendRuntime: "runtime:backend:",
			UserRuntime:    "runtime:user:",
		},
		Standalone: RedisStandaloneConfig{
			Address: "127.0.0.1:6379",
		},
		Cluster: RedisClusterConfig{
			Addresses:    []string{"127.0.0.1:6379"},
			MaxRedirects: 8,
		},
		Sentinel: RedisSentinelConfig{
			Addresses:    []string{},
			PasswordFile: Secret("/etc/nauthilus-director/redis-sentinel-password"),
		},
		Auth: RedisAuthConfig{
			Username:     "nauthilus-director",
			PasswordFile: Secret("/etc/nauthilus-director/redis-password"),
		},
		TLS: RedisTLSConfig{
			Enabled:       true,
			CAFile:        "/etc/nauthilus-director/redis-ca.pem",
			Cert:          "/etc/nauthilus-director/redis-client.crt",
			Key:           Secret("/etc/nauthilus-director/redis-client.key"),
			ServerName:    "redis.example.org",
			MinTLSVersion: "TLS1.2",
		},
		PoolSize:           20,
		MinIdleConnections: 4,
		PoolTimeout:        NewDuration(5 * time.Second),
		DialTimeout:        NewDuration(5 * time.Second),
		ReadTimeout:        NewDuration(2 * time.Second),
		WriteTimeout:       NewDuration(2 * time.Second),
		Retries: RedisRetryConfig{
			MaxAttempts: 3,
			MinBackoff:  NewDuration(100 * time.Millisecond),
			MaxBackoff:  NewDuration(time.Second),
		},
		Health: RedisHealthConfig{
			Enabled:          true,
			Interval:         NewDuration(5 * time.Second),
			Timeout:          NewDuration(2 * time.Second),
			FailureThreshold: 3,
		},
	}
}

// defaultAuthority returns the default Nauthilus authority transport settings.
func defaultAuthority() AuthorityConfig {
	return AuthorityConfig{
		Transport: "http",
		Timeout:   NewDuration(5 * time.Second),
		Mechanisms: AuthorityMechanismsConfig{
			Password: PasswordMechanismConfig{
				Enabled: true,
				Names:   []string{"plain", "login"},
			},
			Bearer: BearerMechanismConfig{
				Enabled:       true,
				Names:         []string{"xoauth2", "oauthbearer"},
				Validation:    "nauthilus",
				TokenMaxBytes: 16384,
			},
		},
		OIDC: AuthorityOIDCConfig{
			Enabled:        true,
			AuthorityMode:  "nauthilus",
			IssuerHint:     "https://auth.example.org",
			AudienceHint:   "mail",
			RequiredScopes: []string{"email"},
		},
		HTTP: AuthorityHTTPTransportConfig{
			Endpoint:    "http://127.0.0.1:8080/api/v1/auth/json",
			ContentType: "application/json",
			BasicAuth: BasicAuthConfig{
				Username:     "nauthilus-director",
				PasswordFile: Secret("/etc/nauthilus-director/nauthilus-http-password"),
			},
			TLS: AuthorityTLSConfig{
				CAFile:     "/etc/nauthilus-director/nauthilus-http-ca.pem",
				ServerName: "nauthilus.example.org",
			},
		},
		GRPC: AuthorityGRPCTransportConfig{
			Address:   "127.0.0.1:50051",
			Authority: "nauthilus.example.org",
			CallerAuth: GRPCCallerAuthConfig{
				Basic: BasicCallerAuthConfig{
					Enabled:      true,
					Username:     "nauthilus-director",
					PasswordFile: Secret("/etc/nauthilus-director/nauthilus-grpc-password"),
				},
				Bearer: BearerCallerAuthConfig{
					TokenFile: Secret("/etc/nauthilus-director/nauthilus-grpc-token"),
				},
			},
			TLS: AuthorityTLSConfig{
				Enabled:    true,
				CAFile:     "/etc/nauthilus-director/nauthilus-grpc-ca.pem",
				ServerName: "nauthilus.example.org",
			},
		},
	}
}

// defaultDirector returns listener, routing, affinity and backend defaults.
func defaultDirector() DirectorConfig {
	return DirectorConfig{
		Security: DirectorSecurityConfig{
			FailClosed:             true,
			MaxPreauthLineBytes:    8192,
			MaxPreauthLiteralBytes: 65536,
		},
		Listeners: map[string]ListenerConfig{
			"imap":  defaultIMAPListener("imap", "127.0.0.1:10143", "starttls", "/etc/nauthilus-director/imap.crt", "/etc/nauthilus-director/imap.key"),
			"imaps": defaultIMAPListener("imaps", "127.0.0.1:10993", "implicit", "/etc/nauthilus-director/imaps.crt", "/etc/nauthilus-director/imaps.key"),
			"lmtp":  defaultLMTPListener("lmtp", "127.0.0.1:10024", "starttls", "/etc/nauthilus-director/lmtp.crt", "/etc/nauthilus-director/lmtp.key"),
			"lmtps": defaultLMTPListener("lmtps", "127.0.0.1:11024", "implicit", "/etc/nauthilus-director/lmtps.crt", "/etc/nauthilus-director/lmtps.key"),
		},
		Routing: RoutingConfig{
			DefaultSelector: "rendezvous_hash",
			DefaultShard:    "default",
			HashKey:         "username",
			LMTPHashKey:     "recipient",
			Failover: FailoverConfig{
				Enabled:  true,
				Strategy: "same_shard_then_any_healthy",
			},
		},
		Affinity: AffinityConfig{
			Mode:             "active_user_pin",
			InitialPlacement: "rendezvous_hash",
			ActiveUserPinning: ActiveUserPinningConfig{
				Enabled:     true,
				BindTo:      "shard_tag",
				Release:     "after_last_session_closed",
				IdleGrace:   NewDuration(5 * time.Minute),
				RequiredFor: []string{"imap", "pop3", "sieve"},
				Key: AffinityKeyConfig{
					User:   "normalized_username",
					Tenant: "default",
				},
				Failover: AffinityFailoverConfig{
					AllowOnHardDown:        true,
					AllowOnHardMaintenance: true,
					Audit:                  true,
				},
			},
			LocalCache: LocalCacheConfig{
				Enabled:    true,
				TTL:        NewDuration(15 * time.Minute),
				MaxEntries: 100000,
			},
		},
		RuntimeOverrides: RuntimeOverridesConfig{
			Enabled: true,
			Backends: BackendOverridesConfig{
				AllowWeightOverride: true,
				AllowInOut:          true,
				AllowDrain:          true,
				MaxWeight:           10000,
			},
			Users: UserOverridesConfig{
				AllowMove:          true,
				AllowKick:          true,
				AllowAffinityClear: true,
				MoveStrategies:     []string{"new_sessions_only", "kick_existing", "drain_existing"},
			},
		},
		Health: DirectorHealthConfig{
			Interval:       NewDuration(5 * time.Second),
			Timeout:        NewDuration(3 * time.Second),
			Jitter:         NewDuration(500 * time.Millisecond),
			UnhealthyAfter: 3,
			HealthyAfter:   2,
		},
		Maintenance: MaintenanceConfig{
			DefaultMode:          "disabled",
			DrainTimeout:         NewDuration(5 * time.Minute),
			HardKillGrace:        NewDuration(30 * time.Second),
			SoftAllowsActivePins: true,
			Audit:                true,
		},
		BackendPools: map[string]BackendPoolConfig{
			"imap-default": {
				Protocol: "imap",
				Selector: "rendezvous_hash",
				Backends: []string{"mailstore-a-imap", "mailstore-b-imap"},
			},
			"lmtp-default": {
				Protocol: "lmtp",
				Selector: "recipient_hash",
				Backends: []string{"mailstore-a-lmtp", "mailstore-b-lmtp"},
			},
		},
		Backends: map[string]BackendConfig{
			"mailstore-a-imap": defaultIMAPBackend("mailstore-a", "127.0.0.1:1143", "mailstore-a.example.org"),
			"mailstore-b-imap": defaultIMAPBackend("mailstore-b", "127.0.0.1:2143", "mailstore-b.example.org"),
			"mailstore-a-lmtp": defaultLMTPBackend("mailstore-a", "127.0.0.1:2424", "mailstore-a.example.org"),
			"mailstore-b-lmtp": defaultLMTPBackend("mailstore-b", "127.0.0.1:3424", "mailstore-b.example.org"),
		},
	}
}

// defaultIMAPListener builds a default IMAP-family listener for one service.
func defaultIMAPListener(serviceName string, address string, tlsMode string, cert string, key string) ListenerConfig {
	return ListenerConfig{
		Protocol:    "imap",
		ServiceName: serviceName,
		Network:     "tcp",
		Address:     address,
		Authority:   "default",
		BackendPool: "imap-default",
		ProxyProtocol: ProxyProtocolConfig{
			TrustedCIDRs: []string{},
		},
		TLS: ListenerTLSConfig{
			Mode:          tlsMode,
			Cert:          cert,
			Key:           Secret(key),
			MinTLSVersion: "TLS1.2",
		},
		IMAP: &IMAPListenerConfig{
			Capabilities:        []string{"IMAP4rev1", "ID", "SASL-IR", "AUTH=PLAIN", "AUTH=XOAUTH2", "AUTH=OAUTHBEARER"},
			AuthMechanisms:      []string{"plain", "xoauth2", "oauthbearer"},
			RequireIDBeforeAuth: false,
		},
	}
}

// defaultLMTPListener builds draft LMTP listener defaults for target-config decoding.
func defaultLMTPListener(serviceName string, address string, tlsMode string, cert string, key string) ListenerConfig {
	return ListenerConfig{
		Protocol:    "lmtp",
		ServiceName: serviceName,
		Network:     "tcp",
		Address:     address,
		Authority:   "default",
		BackendPool: "lmtp-default",
		ProxyProtocol: ProxyProtocolConfig{
			TrustedCIDRs: []string{},
		},
		TLS: ListenerTLSConfig{
			Mode:          tlsMode,
			Cert:          cert,
			Key:           Secret(key),
			ClientCA:      "/etc/nauthilus-director/lmtp-client-ca.pem",
			MinTLSVersion: "TLS1.2",
		},
		LMTP: &LMTPListenerConfig{
			SMTPUTF8: true,
			ClientAuth: LMTPClientAuthConfig{
				Required:   true,
				Authority:  "default",
				Mechanisms: []string{"plain", "login", "xoauth2", "oauthbearer"},
			},
			Capabilities: []string{"CHUNKING", "SMTPUTF8", "STARTTLS", "AUTH PLAIN LOGIN XOAUTH2 OAUTHBEARER"},
		},
	}
}

// defaultIMAPBackend builds an IMAP backend using master-user authentication.
func defaultIMAPBackend(shardTag string, address string, serverName string) BackendConfig {
	return BackendConfig{
		Protocol:       "imap",
		ShardTag:       shardTag,
		Address:        address,
		Weight:         100,
		MaxConnections: 1000,
		Maintenance:    "disabled",
		HAProxy:        HAProxyConfig{},
		TLS: BackendTLSConfig{
			Mode:               "starttls",
			CAFile:             "/etc/nauthilus-director/mailstore-ca.pem",
			ServerName:         serverName,
			MinTLSVersion:      "TLS1.2",
			InsecureSkipVerify: false,
		},
		Auth: BackendAuthConfig{
			Mode: "master_user",
			MasterUser: BackendMasterUserConfig{
				Username:     "nauthilus-director",
				PasswordFile: Secret("/etc/nauthilus-director/backend-master-password"),
				UserFormat:   "{user}*{master_user}",
				Mechanism:    "plain",
			},
			CredentialReplay: BackendCredentialReplayConfig{
				RequireBackendTLS: true,
				PreserveMechanism: true,
				AllowedMechanisms: []string{"plain", "login", "xoauth2", "oauthbearer"},
			},
		},
		HealthCheck: defaultBackendHealthCheck(),
	}
}

// defaultLMTPBackend builds an LMTP backend using SASL authentication.
func defaultLMTPBackend(shardTag string, address string, serverName string) BackendConfig {
	return BackendConfig{
		Protocol:       "lmtp",
		ShardTag:       shardTag,
		Address:        address,
		Weight:         100,
		MaxConnections: 1000,
		Maintenance:    "disabled",
		HAProxy:        HAProxyConfig{},
		TLS: BackendTLSConfig{
			Mode:          "implicit",
			CAFile:        "/etc/nauthilus-director/mailstore-ca.pem",
			Cert:          "/etc/nauthilus-director/lmtp-backend-client.crt",
			Key:           Secret("/etc/nauthilus-director/lmtp-backend-client.key"),
			ServerName:    serverName,
			MinTLSVersion: "TLS1.2",
		},
		Auth: BackendAuthConfig{
			Mode: "sasl",
			SASL: BackendSASLConfig{
				Mechanism:    "plain",
				Username:     "nauthilus-director-lmtp",
				PasswordFile: Secret("/etc/nauthilus-director/lmtp-backend-password"),
				RequireTLS:   true,
			},
			OAuthBearer: BackendOAuthBearerConfig{
				TokenFile:  Secret("/etc/nauthilus-director/lmtp-backend-token"),
				RequireTLS: true,
			},
		},
		HealthCheck: defaultBackendHealthCheck(),
	}
}

// defaultBackendHealthCheck returns a deep health check with protected credentials.
func defaultBackendHealthCheck() BackendHealthConfig {
	return BackendHealthConfig{
		Enabled:      true,
		DeepCheck:    true,
		Username:     "healthcheck@example.org",
		PasswordFile: Secret("/etc/nauthilus-director/mailstore-health-password"),
	}
}
