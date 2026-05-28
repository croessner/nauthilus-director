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

// Package config owns typed configuration models, loading, validation and redaction.
//
//nolint:revive // The exported model names intentionally mirror the public config vocabulary.
package config

import (
	"github.com/go-playground/validator/v10"
	"github.com/spf13/viper"
)

const (
	configTagName = "mapstructure"

	dumpFormatYAML = "yaml"
	dumpFormatYML  = "yml"
	dumpFormatJSON = "json"
	dumpFormatTOML = "toml"

	redisModeStandalone = "standalone"
	redisModeCluster    = "cluster"
	redisModeSentinel   = "sentinel"

	transportHTTP = "http"
	transportGRPC = "grpc"

	protocolIMAP = "imap"
	protocolLMTP = "lmtp"

	backendAuthModeMasterUser       = "master_user"
	backendAuthModeCredentialReplay = "credential_replay"
	backendAuthModeSASL             = "sasl"
	backendAuthModeOAuthBearer      = "oauthbearer"
	backendAuthModeNone             = "none"
	backendAuthModeMTLS             = "mtls"
)

// Loader is the production configuration loader boundary.
type Loader struct {
	viper         *viper.Viper
	validate      *validator.Validate
	reader        configReader
	includeLoader *includeLoader
	patchEngine   PatchEngine
	expander      ValueExpander
	merger        SettingsMerger
}

// NewLoader creates a loader with isolated Viper and validator instances.
func NewLoader() *Loader {
	validate := validator.New()
	loaderViper := viper.New()
	loaderViper.SetEnvPrefix(envPrefix)

	return &Loader{
		viper:         loaderViper,
		validate:      validate,
		reader:        viperConfigReader{},
		includeLoader: newIncludeLoader(viperConfigReader{}),
		patchEngine:   DefaultPatchEngine{},
		expander:      NewConfigValueExpander(nil),
		merger:        MapMerger{},
	}
}

// Snapshot is the immutable typed result of a config load.
type Snapshot struct {
	Config        Config
	defaultConfig Config
}

// Config contains the stable production configuration roots.
type Config struct {
	Runtime       RuntimeConfig       `mapstructure:"runtime" yaml:"runtime" validate:"required"`
	Observability ObservabilityConfig `mapstructure:"observability" yaml:"observability" validate:"required"`
	Storage       StorageConfig       `mapstructure:"storage" yaml:"storage" validate:"required"`
	Auth          AuthConfig          `mapstructure:"auth" yaml:"auth" validate:"required"`
	Director      DirectorConfig      `mapstructure:"director" yaml:"director" validate:"required"`
}

type RuntimeConfig struct {
	InstanceName string               `mapstructure:"instance_name" yaml:"instance_name" validate:"required"`
	Process      ProcessConfig        `mapstructure:"process" yaml:"process" validate:"required"`
	Servers      RuntimeServersConfig `mapstructure:"servers" yaml:"servers" validate:"required"`
	Timeouts     RuntimeTimeouts      `mapstructure:"timeouts" yaml:"timeouts" validate:"required"`
	Clients      RuntimeClients       `mapstructure:"clients" yaml:"clients" validate:"required"`
}

type ProcessConfig struct {
	ShutdownTimeout Duration `mapstructure:"shutdown_timeout" yaml:"shutdown_timeout"`
}

type RuntimeServersConfig struct {
	Control ControlServerConfig `mapstructure:"control" yaml:"control" validate:"required"`
}

type ControlServerConfig struct {
	Enabled bool              `mapstructure:"enabled" yaml:"enabled"`
	Address string            `mapstructure:"address" yaml:"address" validate:"required"`
	Auth    ControlAuthConfig `mapstructure:"auth" yaml:"auth" validate:"required"`
	TLS     ControlTLSConfig  `mapstructure:"tls" yaml:"tls" validate:"required"`
}

type ControlAuthConfig struct {
	Bearer ControlBearerAuthConfig `mapstructure:"bearer" yaml:"bearer" validate:"required"`
	OIDC   ControlOIDCAuthConfig   `mapstructure:"oidc" yaml:"oidc" validate:"required"`
	MTLS   ControlMTLSAuthConfig   `mapstructure:"mtls" yaml:"mtls" validate:"required"`
}

type ControlBearerAuthConfig struct {
	Enabled   bool         `mapstructure:"enabled" yaml:"enabled"`
	TokenFile SecretString `mapstructure:"token_file" yaml:"token_file" protected:"true"`
}

type ControlOIDCAuthConfig struct {
	Enabled        bool     `mapstructure:"enabled" yaml:"enabled"`
	Authority      string   `mapstructure:"authority" yaml:"authority"`
	Validation     string   `mapstructure:"validation" yaml:"validation"`
	RequiredScopes []string `mapstructure:"required_scopes" yaml:"required_scopes"`
}

type ControlMTLSAuthConfig struct {
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`
}

type ControlTLSConfig struct {
	Enabled           bool         `mapstructure:"enabled" yaml:"enabled"`
	Cert              string       `mapstructure:"cert" yaml:"cert"`
	Key               SecretString `mapstructure:"key" yaml:"key" protected:"true"`
	ClientCA          string       `mapstructure:"client_ca" yaml:"client_ca"`
	RequireClientCert bool         `mapstructure:"require_client_cert" yaml:"require_client_cert"`
	MinTLSVersion     string       `mapstructure:"min_tls_version" yaml:"min_tls_version"`
}

type RuntimeTimeouts struct {
	Preauth        Duration `mapstructure:"preauth" yaml:"preauth"`
	Auth           Duration `mapstructure:"auth" yaml:"auth"`
	Nauthilus      Duration `mapstructure:"nauthilus" yaml:"nauthilus"`
	BackendConnect Duration `mapstructure:"backend_connect" yaml:"backend_connect"`
	ProxyIdle      Duration `mapstructure:"proxy_idle" yaml:"proxy_idle"`
	Shutdown       Duration `mapstructure:"shutdown" yaml:"shutdown"`
}

type RuntimeClients struct {
	HTTP HTTPClientConfig `mapstructure:"http" yaml:"http" validate:"required"`
}

type HTTPClientConfig struct {
	MaxConnectionsPerHost     int      `mapstructure:"max_connections_per_host" yaml:"max_connections_per_host"`
	MaxIdleConnections        int      `mapstructure:"max_idle_connections" yaml:"max_idle_connections"`
	MaxIdleConnectionsPerHost int      `mapstructure:"max_idle_connections_per_host" yaml:"max_idle_connections_per_host"`
	IdleConnectionTimeout     Duration `mapstructure:"idle_connection_timeout" yaml:"idle_connection_timeout"`
}

type ObservabilityConfig struct {
	Log      LogConfig      `mapstructure:"log" yaml:"log" validate:"required"`
	Metrics  MetricsConfig  `mapstructure:"metrics" yaml:"metrics" validate:"required"`
	Tracing  TracingConfig  `mapstructure:"tracing" yaml:"tracing" validate:"required"`
	Profiles ProfilesConfig `mapstructure:"profiles" yaml:"profiles" validate:"required"`
}

type LogConfig struct {
	Level                string       `mapstructure:"level" yaml:"level" validate:"required"`
	JSON                 bool         `mapstructure:"json" yaml:"json"`
	AddSource            bool         `mapstructure:"add_source" yaml:"add_source"`
	RedactSecrets        bool         `mapstructure:"redact_secrets" yaml:"redact_secrets"`
	UsernameHashSaltFile SecretString `mapstructure:"username_hash_salt_file" yaml:"username_hash_salt_file" protected:"true"`
}

type MetricsConfig struct {
	Enabled        bool   `mapstructure:"enabled" yaml:"enabled"`
	Path           string `mapstructure:"path" yaml:"path"`
	RuntimeMetrics bool   `mapstructure:"runtime_metrics" yaml:"runtime_metrics"`
}

type TracingConfig struct {
	Enabled     bool    `mapstructure:"enabled" yaml:"enabled"`
	ServiceName string  `mapstructure:"service_name" yaml:"service_name"`
	Exporter    string  `mapstructure:"exporter" yaml:"exporter"`
	Endpoint    string  `mapstructure:"endpoint" yaml:"endpoint"`
	SampleRatio float64 `mapstructure:"sample_ratio" yaml:"sample_ratio"`
}

type ProfilesConfig struct {
	PProf ProfileConfig `mapstructure:"pprof" yaml:"pprof" validate:"required"`
	Block ProfileConfig `mapstructure:"block" yaml:"block" validate:"required"`
}

type ProfileConfig struct {
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`
}

type StorageConfig struct {
	Redis RedisConfig `mapstructure:"redis" yaml:"redis" validate:"required"`
}

type RedisConfig struct {
	Enabled            bool                  `mapstructure:"enabled" yaml:"enabled"`
	Protocol           int                   `mapstructure:"protocol" yaml:"protocol"`
	Mode               string                `mapstructure:"mode" yaml:"mode" validate:"required"`
	KeyPrefix          string                `mapstructure:"key_prefix" yaml:"key_prefix" validate:"required"`
	SchemaVersion      int                   `mapstructure:"schema_version" yaml:"schema_version"`
	Namespaces         RedisNamespaces       `mapstructure:"namespaces" yaml:"namespaces" validate:"required"`
	Standalone         RedisStandaloneConfig `mapstructure:"standalone" yaml:"standalone" validate:"required"`
	Cluster            RedisClusterConfig    `mapstructure:"cluster" yaml:"cluster" validate:"required"`
	Sentinel           RedisSentinelConfig   `mapstructure:"sentinel" yaml:"sentinel" validate:"required"`
	Auth               RedisAuthConfig       `mapstructure:"auth" yaml:"auth" validate:"required"`
	DatabaseNumber     int                   `mapstructure:"database_number" yaml:"database_number"`
	TLS                RedisTLSConfig        `mapstructure:"tls" yaml:"tls" validate:"required"`
	PoolSize           int                   `mapstructure:"pool_size" yaml:"pool_size"`
	MinIdleConnections int                   `mapstructure:"min_idle_connections" yaml:"min_idle_connections"`
	PoolTimeout        Duration              `mapstructure:"pool_timeout" yaml:"pool_timeout"`
	DialTimeout        Duration              `mapstructure:"dial_timeout" yaml:"dial_timeout"`
	ReadTimeout        Duration              `mapstructure:"read_timeout" yaml:"read_timeout"`
	WriteTimeout       Duration              `mapstructure:"write_timeout" yaml:"write_timeout"`
	Retries            RedisRetryConfig      `mapstructure:"retries" yaml:"retries" validate:"required"`
	Health             RedisHealthConfig     `mapstructure:"health" yaml:"health" validate:"required"`
}

type RedisNamespaces struct {
	Affinity       string `mapstructure:"affinity" yaml:"affinity" validate:"required"`
	Sessions       string `mapstructure:"sessions" yaml:"sessions" validate:"required"`
	BackendRuntime string `mapstructure:"backend_runtime" yaml:"backend_runtime" validate:"required"`
	UserRuntime    string `mapstructure:"user_runtime" yaml:"user_runtime" validate:"required"`
}

type RedisStandaloneConfig struct {
	Address string `mapstructure:"address" yaml:"address"`
}

type RedisClusterConfig struct {
	Addresses      []string `mapstructure:"addresses" yaml:"addresses"`
	MaxRedirects   int      `mapstructure:"max_redirects" yaml:"max_redirects"`
	ReadOnly       bool     `mapstructure:"read_only" yaml:"read_only"`
	RouteByLatency bool     `mapstructure:"route_by_latency" yaml:"route_by_latency"`
	RouteRandomly  bool     `mapstructure:"route_randomly" yaml:"route_randomly"`
}

type RedisSentinelConfig struct {
	MasterName   string       `mapstructure:"master_name" yaml:"master_name"`
	Addresses    []string     `mapstructure:"addresses" yaml:"addresses"`
	Username     string       `mapstructure:"username" yaml:"username"`
	PasswordFile SecretString `mapstructure:"password_file" yaml:"password_file" protected:"true"`
}

type RedisAuthConfig struct {
	Username     string       `mapstructure:"username" yaml:"username"`
	PasswordFile SecretString `mapstructure:"password_file" yaml:"password_file" protected:"true"`
}

type RedisTLSConfig struct {
	Enabled            bool         `mapstructure:"enabled" yaml:"enabled"`
	CAFile             string       `mapstructure:"ca_file" yaml:"ca_file"`
	Cert               string       `mapstructure:"cert" yaml:"cert"`
	Key                SecretString `mapstructure:"key" yaml:"key" protected:"true"`
	ServerName         string       `mapstructure:"server_name" yaml:"server_name"`
	MinTLSVersion      string       `mapstructure:"min_tls_version" yaml:"min_tls_version"`
	InsecureSkipVerify bool         `mapstructure:"insecure_skip_verify" yaml:"insecure_skip_verify"`
}

type RedisRetryConfig struct {
	MaxAttempts int      `mapstructure:"max_attempts" yaml:"max_attempts"`
	MinBackoff  Duration `mapstructure:"min_backoff" yaml:"min_backoff"`
	MaxBackoff  Duration `mapstructure:"max_backoff" yaml:"max_backoff"`
}

type RedisHealthConfig struct {
	Enabled          bool     `mapstructure:"enabled" yaml:"enabled"`
	Interval         Duration `mapstructure:"interval" yaml:"interval"`
	Timeout          Duration `mapstructure:"timeout" yaml:"timeout"`
	FailureThreshold int      `mapstructure:"failure_threshold" yaml:"failure_threshold"`
}

type DirectorConfig struct {
	Security         DirectorSecurityConfig       `mapstructure:"security" yaml:"security" validate:"required"`
	Listeners        map[string]ListenerConfig    `mapstructure:"listeners" yaml:"listeners" validate:"required,min=1,dive"`
	Routing          RoutingConfig                `mapstructure:"routing" yaml:"routing" validate:"required"`
	Affinity         AffinityConfig               `mapstructure:"affinity" yaml:"affinity" validate:"required"`
	RuntimeOverrides RuntimeOverridesConfig       `mapstructure:"runtime_overrides" yaml:"runtime_overrides" validate:"required"`
	Health           DirectorHealthConfig         `mapstructure:"health" yaml:"health" validate:"required"`
	Maintenance      MaintenanceConfig            `mapstructure:"maintenance" yaml:"maintenance" validate:"required"`
	BackendPools     map[string]BackendPoolConfig `mapstructure:"backend_pools" yaml:"backend_pools" validate:"required,min=1,dive"`
	Backends         map[string]BackendConfig     `mapstructure:"backends" yaml:"backends" validate:"required,min=1,dive"`
}

type DirectorSecurityConfig struct {
	FailClosed             bool `mapstructure:"fail_closed" yaml:"fail_closed"`
	MaxPreauthLineBytes    int  `mapstructure:"max_preauth_line_bytes" yaml:"max_preauth_line_bytes"`
	MaxPreauthLiteralBytes int  `mapstructure:"max_preauth_literal_bytes" yaml:"max_preauth_literal_bytes"`
}

type ListenerConfig struct {
	Protocol      string              `mapstructure:"protocol" yaml:"protocol" validate:"required"`
	ServiceName   string              `mapstructure:"service_name" yaml:"service_name" validate:"required"`
	Network       string              `mapstructure:"network" yaml:"network" validate:"required"`
	Address       string              `mapstructure:"address" yaml:"address" validate:"required"`
	Authority     string              `mapstructure:"authority" yaml:"authority" validate:"required"`
	BackendPool   string              `mapstructure:"backend_pool" yaml:"backend_pool" validate:"required"`
	ProxyProtocol ProxyProtocolConfig `mapstructure:"proxy_protocol" yaml:"proxy_protocol" validate:"required"`
	TLS           ListenerTLSConfig   `mapstructure:"tls" yaml:"tls" validate:"required"`
	IMAP          *IMAPListenerConfig `mapstructure:"imap" yaml:"imap,omitempty"`
	LMTP          *LMTPListenerConfig `mapstructure:"lmtp" yaml:"lmtp,omitempty"`
}

type ProxyProtocolConfig struct {
	Enabled      bool     `mapstructure:"enabled" yaml:"enabled"`
	TrustedCIDRs []string `mapstructure:"trusted_cidrs" yaml:"trusted_cidrs"`
}

type ListenerTLSConfig struct {
	Mode              string       `mapstructure:"mode" yaml:"mode" validate:"required"`
	Cert              string       `mapstructure:"cert" yaml:"cert"`
	Key               SecretString `mapstructure:"key" yaml:"key" protected:"true"`
	ClientCA          string       `mapstructure:"client_ca" yaml:"client_ca"`
	RequireClientCert bool         `mapstructure:"require_client_cert" yaml:"require_client_cert"`
	MinTLSVersion     string       `mapstructure:"min_tls_version" yaml:"min_tls_version"`
}

type IMAPListenerConfig struct {
	Capabilities        []string `mapstructure:"capabilities" yaml:"capabilities"`
	AuthMechanisms      []string `mapstructure:"auth_mechanisms" yaml:"auth_mechanisms"`
	RequireIDBeforeAuth bool     `mapstructure:"require_id_before_auth" yaml:"require_id_before_auth"`
}

type LMTPListenerConfig struct {
	SMTPUTF8     bool                 `mapstructure:"smtputf8" yaml:"smtputf8"`
	ClientAuth   LMTPClientAuthConfig `mapstructure:"client_auth" yaml:"client_auth" validate:"required"`
	Capabilities []string             `mapstructure:"capabilities" yaml:"capabilities"`
}

type LMTPClientAuthConfig struct {
	Required   bool                     `mapstructure:"required" yaml:"required"`
	Authority  string                   `mapstructure:"authority" yaml:"authority"`
	Mechanisms []string                 `mapstructure:"mechanisms" yaml:"mechanisms"`
	MTLS       LMTPClientMTLSAuthConfig `mapstructure:"mtls" yaml:"mtls" validate:"required"`
}

type LMTPClientMTLSAuthConfig struct {
	SatisfiesRequired bool   `mapstructure:"satisfies_required" yaml:"satisfies_required"`
	IdentitySource    string `mapstructure:"identity_source" yaml:"identity_source"`
}

type RoutingConfig struct {
	DefaultSelector string                      `mapstructure:"default_selector" yaml:"default_selector" validate:"required"`
	DefaultShard    string                      `mapstructure:"default_shard" yaml:"default_shard"`
	HashKey         string                      `mapstructure:"hash_key" yaml:"hash_key" validate:"required"`
	LMTPHashKey     string                      `mapstructure:"lmtp_hash_key" yaml:"lmtp_hash_key"`
	AuthAttributes  RoutingAuthAttributesConfig `mapstructure:"auth_attributes" yaml:"auth_attributes" validate:"required"`
	Failover        FailoverConfig              `mapstructure:"failover" yaml:"failover" validate:"required"`
}

// RoutingAuthAttributesConfig names Nauthilus attributes that release routing facts.
type RoutingAuthAttributesConfig struct {
	Tenant   string `mapstructure:"tenant" yaml:"tenant"`
	ShardTag string `mapstructure:"shard_tag" yaml:"shard_tag"`
}

type FailoverConfig struct {
	Enabled  bool   `mapstructure:"enabled" yaml:"enabled"`
	Strategy string `mapstructure:"strategy" yaml:"strategy"`
}

type AffinityConfig struct {
	Mode              string                  `mapstructure:"mode" yaml:"mode" validate:"required"`
	InitialPlacement  string                  `mapstructure:"initial_placement" yaml:"initial_placement" validate:"required"`
	ActiveUserPinning ActiveUserPinningConfig `mapstructure:"active_user_pinning" yaml:"active_user_pinning" validate:"required"`
	LocalCache        LocalCacheConfig        `mapstructure:"local_cache" yaml:"local_cache" validate:"required"`
}

type ActiveUserPinningConfig struct {
	Enabled     bool                   `mapstructure:"enabled" yaml:"enabled"`
	BindTo      string                 `mapstructure:"bind_to" yaml:"bind_to"`
	Release     string                 `mapstructure:"release" yaml:"release"`
	IdleGrace   Duration               `mapstructure:"idle_grace" yaml:"idle_grace"`
	RequiredFor []string               `mapstructure:"required_for" yaml:"required_for"`
	Key         AffinityKeyConfig      `mapstructure:"key" yaml:"key" validate:"required"`
	Failover    AffinityFailoverConfig `mapstructure:"failover" yaml:"failover" validate:"required"`
}

type AffinityKeyConfig struct {
	User   string `mapstructure:"user" yaml:"user"`
	Tenant string `mapstructure:"tenant" yaml:"tenant"`
}

type AffinityFailoverConfig struct {
	AllowOnHardDown        bool `mapstructure:"allow_on_hard_down" yaml:"allow_on_hard_down"`
	AllowOnHardMaintenance bool `mapstructure:"allow_on_hard_maintenance" yaml:"allow_on_hard_maintenance"`
	Audit                  bool `mapstructure:"audit" yaml:"audit"`
}

type LocalCacheConfig struct {
	Enabled    bool     `mapstructure:"enabled" yaml:"enabled"`
	TTL        Duration `mapstructure:"ttl" yaml:"ttl"`
	MaxEntries int      `mapstructure:"max_entries" yaml:"max_entries"`
}

type RuntimeOverridesConfig struct {
	Enabled        bool                   `mapstructure:"enabled" yaml:"enabled"`
	ConfigWritable bool                   `mapstructure:"config_writable" yaml:"config_writable"`
	Backends       BackendOverridesConfig `mapstructure:"backends" yaml:"backends" validate:"required"`
	Users          UserOverridesConfig    `mapstructure:"users" yaml:"users" validate:"required"`
}

type BackendOverridesConfig struct {
	AllowWeightOverride bool `mapstructure:"allow_weight_override" yaml:"allow_weight_override"`
	AllowInOut          bool `mapstructure:"allow_in_out" yaml:"allow_in_out"`
	AllowDrain          bool `mapstructure:"allow_drain" yaml:"allow_drain"`
	MinWeight           int  `mapstructure:"min_weight" yaml:"min_weight"`
	MaxWeight           int  `mapstructure:"max_weight" yaml:"max_weight"`
}

type UserOverridesConfig struct {
	AllowMove          bool     `mapstructure:"allow_move" yaml:"allow_move"`
	AllowKick          bool     `mapstructure:"allow_kick" yaml:"allow_kick"`
	AllowAffinityClear bool     `mapstructure:"allow_affinity_clear" yaml:"allow_affinity_clear"`
	MoveStrategies     []string `mapstructure:"move_strategies" yaml:"move_strategies"`
}

type DirectorHealthConfig struct {
	Interval       Duration `mapstructure:"interval" yaml:"interval"`
	Timeout        Duration `mapstructure:"timeout" yaml:"timeout"`
	Jitter         Duration `mapstructure:"jitter" yaml:"jitter"`
	UnhealthyAfter int      `mapstructure:"unhealthy_after" yaml:"unhealthy_after"`
	HealthyAfter   int      `mapstructure:"healthy_after" yaml:"healthy_after"`
}

type MaintenanceConfig struct {
	DefaultMode          string   `mapstructure:"default_mode" yaml:"default_mode" validate:"required"`
	DrainTimeout         Duration `mapstructure:"drain_timeout" yaml:"drain_timeout"`
	HardKillGrace        Duration `mapstructure:"hard_kill_grace" yaml:"hard_kill_grace"`
	SoftAllowsActivePins bool     `mapstructure:"soft_allows_active_pins" yaml:"soft_allows_active_pins"`
	Audit                bool     `mapstructure:"audit" yaml:"audit"`
}

type BackendPoolConfig struct {
	Protocol string   `mapstructure:"protocol" yaml:"protocol" validate:"required"`
	Selector string   `mapstructure:"selector" yaml:"selector" validate:"required"`
	Backends []string `mapstructure:"backends" yaml:"backends" validate:"required,min=1"`
}

type BackendConfig struct {
	Protocol       string              `mapstructure:"protocol" yaml:"protocol" validate:"required"`
	ShardTag       string              `mapstructure:"shard_tag" yaml:"shard_tag"`
	Address        string              `mapstructure:"address" yaml:"address" validate:"required"`
	Weight         int                 `mapstructure:"weight" yaml:"weight"`
	MaxConnections int                 `mapstructure:"max_connections" yaml:"max_connections"`
	Maintenance    string              `mapstructure:"maintenance" yaml:"maintenance" validate:"required"`
	HAProxy        HAProxyConfig       `mapstructure:"haproxy" yaml:"haproxy" validate:"required"`
	TLS            BackendTLSConfig    `mapstructure:"tls" yaml:"tls" validate:"required"`
	Auth           BackendAuthConfig   `mapstructure:"auth" yaml:"auth" validate:"required"`
	HealthCheck    BackendHealthConfig `mapstructure:"health_check" yaml:"health_check" validate:"required"`
}

type HAProxyConfig struct {
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`
}

type BackendTLSConfig struct {
	Mode               string       `mapstructure:"mode" yaml:"mode" validate:"required"`
	CAFile             string       `mapstructure:"ca_file" yaml:"ca_file"`
	Cert               string       `mapstructure:"cert" yaml:"cert"`
	Key                SecretString `mapstructure:"key" yaml:"key" protected:"true"`
	ServerName         string       `mapstructure:"server_name" yaml:"server_name"`
	MinTLSVersion      string       `mapstructure:"min_tls_version" yaml:"min_tls_version"`
	InsecureSkipVerify bool         `mapstructure:"insecure_skip_verify" yaml:"insecure_skip_verify"`
}

type BackendAuthConfig struct {
	Mode             string                        `mapstructure:"mode" yaml:"mode" validate:"required"`
	MasterUser       BackendMasterUserConfig       `mapstructure:"master_user" yaml:"master_user" validate:"required"`
	CredentialReplay BackendCredentialReplayConfig `mapstructure:"credential_replay" yaml:"credential_replay" validate:"required"`
	SASL             BackendSASLConfig             `mapstructure:"sasl" yaml:"sasl" validate:"required"`
	OAuthBearer      BackendOAuthBearerConfig      `mapstructure:"oauthbearer" yaml:"oauthbearer" validate:"required"`
}

type BackendMasterUserConfig struct {
	Username     string       `mapstructure:"username" yaml:"username"`
	PasswordFile SecretString `mapstructure:"password_file" yaml:"password_file" protected:"true"`
	UserFormat   string       `mapstructure:"user_format" yaml:"user_format"`
	Mechanism    string       `mapstructure:"mechanism" yaml:"mechanism"`
}

type BackendCredentialReplayConfig struct {
	RequireBackendTLS bool     `mapstructure:"require_backend_tls" yaml:"require_backend_tls"`
	PreserveMechanism bool     `mapstructure:"preserve_mechanism" yaml:"preserve_mechanism"`
	AllowedMechanisms []string `mapstructure:"allowed_mechanisms" yaml:"allowed_mechanisms"`
}

type BackendSASLConfig struct {
	Mechanism    string       `mapstructure:"mechanism" yaml:"mechanism"`
	Username     string       `mapstructure:"username" yaml:"username"`
	PasswordFile SecretString `mapstructure:"password_file" yaml:"password_file" protected:"true"`
	RequireTLS   bool         `mapstructure:"require_tls" yaml:"require_tls"`
}

type BackendOAuthBearerConfig struct {
	TokenFile  SecretString `mapstructure:"token_file" yaml:"token_file" protected:"true"`
	RequireTLS bool         `mapstructure:"require_tls" yaml:"require_tls"`
}

type BackendHealthConfig struct {
	Enabled      bool         `mapstructure:"enabled" yaml:"enabled"`
	DeepCheck    bool         `mapstructure:"deep_check" yaml:"deep_check"`
	Username     string       `mapstructure:"username" yaml:"username"`
	PasswordFile SecretString `mapstructure:"password_file" yaml:"password_file" protected:"true"`
}
