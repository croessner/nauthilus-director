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

//nolint:dupl,funlen,goconst // Defaults intentionally spell out the canonical YAML surface.
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
			State: RuntimeStateConfig{
				Reaper: RuntimeStateReaperConfig{
					Interval:        NewDuration(5 * time.Second),
					BatchSize:       100,
					MaxPassDuration: NewDuration(2 * time.Second),
					Jitter:          NewDuration(500 * time.Millisecond),
				},
				Indexes: RuntimeStateIndexesConfig{
					SessionShards: 64,
					UserShards:    32,
					BackendShards: 32,
					PageDefault:   100,
					PageMax:       1000,
				},
				BackendReservations: RuntimeStateBackendReservationsConfig{
					TTL:            NewDuration(30 * time.Minute),
					RepairInterval: NewDuration(5 * time.Second),
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
			"imap":   defaultIMAPListener("imap", "127.0.0.1:10143", "starttls", "/etc/nauthilus-director/imap.crt", "/etc/nauthilus-director/imap.key"),
			"imaps":  defaultIMAPListener("imaps", "127.0.0.1:10993", "implicit", "/etc/nauthilus-director/imaps.crt", "/etc/nauthilus-director/imaps.key"),
			"lmtp":   defaultLMTPListener("lmtp", "127.0.0.1:10024", "starttls", "/etc/nauthilus-director/lmtp.crt", "/etc/nauthilus-director/lmtp.key"),
			"lmtps":  defaultLMTPListener("lmtps", "127.0.0.1:11024", "implicit", "/etc/nauthilus-director/lmtps.crt", "/etc/nauthilus-director/lmtps.key"),
			"sieve":  defaultSieveListener("sieve", "127.0.0.1:14190", "starttls", "/etc/nauthilus-director/sieve.crt", "/etc/nauthilus-director/sieve.key"),
			"sieves": defaultSieveListener("sieves", "127.0.0.1:14490", "implicit", "/etc/nauthilus-director/sieves.crt", "/etc/nauthilus-director/sieves.key"),
			"pop3":   defaultPOP3Listener("pop3", "127.0.0.1:10110", "starttls", "/etc/nauthilus-director/pop3.crt", "/etc/nauthilus-director/pop3.key"),
			"pop3s":  defaultPOP3Listener("pop3s", "127.0.0.1:10995", "implicit", "/etc/nauthilus-director/pop3s.crt", "/etc/nauthilus-director/pop3s.key"),
		},
		Routing: RoutingConfig{
			DefaultSelector: "rendezvous_hash",
			DefaultShard:    "default",
			HashKey:         "username",
			LMTPHashKey:     "recipient",
			AuthAttributes: RoutingAuthAttributesConfig{
				Tenant:   defaultRoutingTenantAttribute,
				ShardTag: defaultRoutingShardTagAttribute,
			},
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
			BackendRetention: BackendRetentionConfig{
				Enabled:    true,
				DefaultTTL: NewDuration(15 * time.Minute),
				MaxTTL:     NewDuration(24 * time.Hour),
			},
			LocalCache: LocalCacheConfig{
				Enabled:    true,
				TTL:        NewDuration(15 * time.Minute),
				MaxEntries: 100000,
			},
			UserHolds: UserHoldsConfig{
				Enabled:                true,
				MaxDuration:            NewDuration(30 * time.Minute),
				MaxWait:                NewDuration(30 * time.Second),
				PollInterval:           NewDuration(250 * time.Millisecond),
				MaxLocalWaiters:        1024,
				MaxLocalWaitersPerUser: 16,
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
			"sieve-default": {
				Protocol: "sieve",
				Selector: "rendezvous_hash",
				Backends: []string{"mailstore-a-sieve", "mailstore-b-sieve"},
			},
			"pop3-default": {
				Protocol: "pop3",
				Selector: "rendezvous_hash",
				Backends: []string{"mailstore-a-pop3", "mailstore-b-pop3"},
			},
		},
		Backends: map[string]BackendConfig{
			"mailstore-a-imap":  defaultIMAPBackend("mailstore-a", "mailstore-a-node-1", "127.0.0.1:1143", "mailstore-a.example.org"),
			"mailstore-b-imap":  defaultIMAPBackend("mailstore-b", "mailstore-b-node-1", "127.0.0.1:2143", "mailstore-b.example.org"),
			"mailstore-a-lmtp":  defaultLMTPBackend("mailstore-a", "mailstore-a-node-1", "127.0.0.1:2424", "mailstore-a.example.org"),
			"mailstore-b-lmtp":  defaultLMTPBackend("mailstore-b", "mailstore-b-node-1", "127.0.0.1:3424", "mailstore-b.example.org"),
			"mailstore-a-sieve": defaultSieveBackend("mailstore-a", "mailstore-a-node-1", "127.0.0.1:4190", "mailstore-a.example.org"),
			"mailstore-b-sieve": defaultSieveBackend("mailstore-b", "mailstore-b-node-1", "127.0.0.1:5190", "mailstore-b.example.org"),
			"mailstore-a-pop3":  defaultPOP3Backend("mailstore-a", "mailstore-a-node-1", "127.0.0.1:1110", "mailstore-a.example.org"),
			"mailstore-b-pop3":  defaultPOP3Backend("mailstore-b", "mailstore-b-node-1", "127.0.0.1:2110", "mailstore-b.example.org"),
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
			Capabilities:        defaultIMAPCapabilities(tlsMode),
			AuthMechanisms:      []string{"plain", "xoauth2", "oauthbearer"},
			RequireIDBeforeAuth: false,
		},
	}
}

// defaultIMAPCapabilities returns the conservative implemented IMAP surface.
func defaultIMAPCapabilities(tlsMode string) []string {
	capabilities := []string{"IMAP4rev1", "ID", "SASL-IR"}
	if tlsMode == "starttls" {
		capabilities = append(capabilities, "STARTTLS")
	}

	return append(capabilities, "AUTH=PLAIN", "AUTH=XOAUTH2", "AUTH=OAUTHBEARER")
}

// defaultLMTPListener builds conservative LMTP listener defaults for typed config decoding.
func defaultLMTPListener(serviceName string, address string, tlsMode string, cert string, key string) ListenerConfig {
	capabilities := []string{"SMTPUTF8", "AUTH PLAIN LOGIN XOAUTH2 OAUTHBEARER"}
	if tlsMode == "starttls" {
		capabilities = append([]string{"SMTPUTF8", "STARTTLS"}, "AUTH PLAIN LOGIN XOAUTH2 OAUTHBEARER")
	}

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
			ClientAuth: LMTPClientAuthConfig{
				Required:   true,
				Authority:  "default",
				Mechanisms: []string{"plain", "login", "xoauth2", "oauthbearer"},
				MTLS: LMTPClientMTLSAuthConfig{
					IdentitySource: "subject_common_name",
				},
			},
			Capabilities: capabilities,
		},
	}
}

// defaultSieveListener builds conservative ManageSieve listener defaults.
func defaultSieveListener(serviceName string, address string, tlsMode string, cert string, key string) ListenerConfig {
	return ListenerConfig{
		Protocol:    "sieve",
		ServiceName: serviceName,
		Network:     "tcp",
		Address:     address,
		Authority:   "default",
		BackendPool: "sieve-default",
		ProxyProtocol: ProxyProtocolConfig{
			TrustedCIDRs: []string{},
		},
		TLS: ListenerTLSConfig{
			Mode:          tlsMode,
			Cert:          cert,
			Key:           Secret(key),
			MinTLSVersion: "TLS1.2",
		},
		Sieve: &SieveListenerConfig{
			AuthMechanisms: []string{"plain", "xoauth2", "oauthbearer"},
			Capabilities: SieveCapabilitiesConfig{
				ScriptExtensions: []string{},
				Language:         "en",
			},
		},
	}
}

// defaultPOP3Listener builds conservative POP3 listener defaults.
func defaultPOP3Listener(serviceName string, address string, tlsMode string, cert string, key string) ListenerConfig {
	return ListenerConfig{
		Protocol:    "pop3",
		ServiceName: serviceName,
		Network:     "tcp",
		Address:     address,
		Authority:   "default",
		BackendPool: "pop3-default",
		ProxyProtocol: ProxyProtocolConfig{
			TrustedCIDRs: []string{},
		},
		TLS: ListenerTLSConfig{
			Mode:          tlsMode,
			Cert:          cert,
			Key:           Secret(key),
			MinTLSVersion: "TLS1.2",
		},
		POP3: &POP3ListenerConfig{
			AuthMechanisms: []string{"userpass", "xoauth2", "oauthbearer"},
			Capabilities:   defaultPOP3Capabilities(tlsMode),
		},
	}
}

// defaultPOP3Capabilities returns the bounded authorization-state CAPA policy.
func defaultPOP3Capabilities(tlsMode string) []string {
	capabilities := []string{"USER", "SASL"}
	if tlsMode == "starttls" {
		capabilities = append([]string{"STLS"}, capabilities...)
	}

	return capabilities
}

// defaultIMAPBackend builds an IMAP backend using master-user authentication.
func defaultIMAPBackend(shardTag string, backendNode string, address string, serverName string) BackendConfig {
	return BackendConfig{
		Protocol:       "imap",
		ShardTag:       shardTag,
		BackendNode:    backendNode,
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
func defaultLMTPBackend(shardTag string, backendNode string, address string, serverName string) BackendConfig {
	return BackendConfig{
		Protocol:       "lmtp",
		ShardTag:       shardTag,
		BackendNode:    backendNode,
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

// defaultSieveBackend builds a ManageSieve backend using master-user authentication.
func defaultSieveBackend(shardTag string, backendNode string, address string, serverName string) BackendConfig {
	return BackendConfig{
		Protocol:       "sieve",
		ShardTag:       shardTag,
		BackendNode:    backendNode,
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
				PasswordFile: Secret("/etc/nauthilus-director/sieve-backend-master-password"),
				UserFormat:   "{user}*{master_user}",
				Mechanism:    "plain",
			},
			CredentialReplay: BackendCredentialReplayConfig{
				RequireBackendTLS: true,
				PreserveMechanism: true,
				AllowedMechanisms: []string{"plain", "xoauth2", "oauthbearer"},
			},
		},
		HealthCheck: defaultBackendHealthCheck(),
	}
}

// defaultPOP3Backend builds a POP3 backend using master-user authentication.
func defaultPOP3Backend(shardTag string, backendNode string, address string, serverName string) BackendConfig {
	return BackendConfig{
		Protocol:       "pop3",
		ShardTag:       shardTag,
		BackendNode:    backendNode,
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
				PasswordFile: Secret("/etc/nauthilus-director/pop3-backend-master-password"),
				UserFormat:   "{user}*{master_user}",
				Mechanism:    "plain",
			},
			CredentialReplay: BackendCredentialReplayConfig{
				RequireBackendTLS: true,
				PreserveMechanism: true,
				AllowedMechanisms: []string{"userpass", "xoauth2", "oauthbearer"},
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
