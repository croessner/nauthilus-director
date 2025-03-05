package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type Config struct {
	Server        Server          `mapstructure:"server" validate:"required"`
	BackendServer []BackendServer `mapstructure:"backend_server" validate:"required,dive"`
}

func (cfg *Config) String() string {
	var backendServerStrings []string

	for _, server := range cfg.BackendServer {
		backendServerStrings = append(backendServerStrings, server.String())
	}

	return strings.Join(backendServerStrings, ", ")
}

func (cfg *Config) HandleConfig() error {
	validate := validator.New()

	_ = validate.RegisterValidation("octal_mode", isValidOctalMode)

	err := viper.Unmarshal(cfg)
	if err != nil {
		return err
	}

	return validate.Struct(cfg)
}

func NewConfig() (cfg *Config, err error) {
	cfg = &Config{}

	// Define command-line flags for config file and format
	pflag.String("config", "", "Path to the configuration file")
	pflag.String("format", "yaml", "Format of the configuration file (e.g., yaml, json, toml)")
	pflag.Parse()

	// Bind flags to Viper
	err = viper.BindPFlags(pflag.CommandLine)
	if err != nil {
		return nil, err
	}

	// Read values from the flags
	configPath := viper.GetString("config")
	configFormat := viper.GetString("format")

	// Use the passed --config and --format values
	if configPath != "" {
		viper.SetConfigFile(configPath)
		viper.SetConfigType(configFormat)
	} else {
		// Default case: look up in standard paths
		viper.SetConfigName("nauthilus-director")
		viper.SetConfigType(configFormat)

		viper.AddConfigPath("/usr/local/etc/nauthilus-director/")
		viper.AddConfigPath("/etc/nauthilus-director/")
		viper.AddConfigPath("$HOME/.nauthilus-director")
		viper.AddConfigPath(".")
	}

	// Attempt to read configuration
	err = viper.ReadInConfig()
	if err != nil {
		return nil, err
	}

	// Enable reading environment variables
	viper.AutomaticEnv()
	viper.SetEnvPrefix("PFXHTTP")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Parse the configuration into the struct
	err = cfg.HandleConfig()
	if err != nil {
		return nil, err
	}

	return cfg, err
}

func isValidOctalMode(fl validator.FieldLevel) bool {
	mode := fl.Field().String()

	if !strings.HasPrefix(mode, "0") {
		return false
	}

	_, err := strconv.ParseUint(mode, 8, 32)

	return err == nil
}

type Server struct {
	InstanceID string     `mapstructure:"instance_id" validate:"required"`
	Listen     []Listen   `mapstructure:"listen" validate:"required,dive"`
	HTTPClient HTTPClient `mapstructure:"http_client"`
	Logging    Logging    `mapstructure:"logging"`
}

type Listen struct {
	Port            int      `mapstructure:"port" validate:"required,min=1,max=65535"`
	TLS             TLS      `mapstructure:"tls"`
	HAProxy         bool     `mapstructure:"haproxy"`
	AuthMechs       []string `mapstructure:"auth_mechanisms" validate:"omitempty,dive,oneof=plain login"`
	Capability      []string `mapstructure:"capability"`
	MatchIdentifier []string `mapstructure:"match_identifier" validate:"required,dive,min=1"`
	Kind            string   `mapstructure:"kind" validate:"required,oneof=imap lmtp"`
	ServiceName     string   `mapstructure:"service_name" validate:"required"`
	Type            string   `mapstructure:"type" validate:"required"`
	Address         string   `mapstructure:"address" validate:"required"`
	Mode            string   `mapstructure:"mode" validate:"omitempty,octal_mode"`
}

func (l *Listen) String() string {
	return fmt.Sprintf("{ ServiceName: '%s' Kind: '%s' Type: '%s' Address:Port: '%s:%d' Mode: '%s' Capability: '%v' AuthMechs: '%v' TLS: '%s' MatchIdentifier: '%v' }",
		l.ServiceName, l.Kind, l.Type, l.Address, l.Port, l.Mode, l.Capability, l.AuthMechs, l.TLS.String(), l.MatchIdentifier)
}

type Logging struct {
	JSON  bool   `mapstructure:"json"`
	Level string `mapstructure:"level" validate:"omitempty,oneof=none debug info warn error"`
}

type HTTPClient struct {
	Proxy               string        `mapstructure:"proxy"`
	IdleConnTimeout     time.Duration `mapstructure:"idle_connection_timeout"`
	MaxConnsPerHost     int           `mapstructure:"max_connections_per_host"`
	MaxIdleConns        int           `mapstructure:"max_idle_connections"`
	MaxIdleConnsPerHost int           `mapstructure:"max_idle_connections_per_host"`
}

type TLS struct {
	Enabled    bool   `mapstructure:"enabled"`
	StartTLS   bool   `mapstructure:"starttls"`
	SkipVerify bool   `mapstructure:"skip_verify"`
	Cert       string `mapstructure:"cert" validate:"omitempty,file"`
	Key        string `mapstructure:"key" validate:"omitempty,file"`
}

func (t *TLS) String() string {
	return fmt.Sprintf("{ Enabled: '%v' StartTLS: '%v' SkipVerify: '%v' Cert: '%s' Key: '%s' }",
		t.Enabled, t.StartTLS, t.SkipVerify, t.Cert, t.Key)
}

type BackendServer struct {
	ShardTag       string        `mapstructure:"shard_tag"`
	Host           string        `mapstructure:"host" validate:"required,hostname|ip"`
	Identifier     string        `mapstructure:"identifier" validate:"required"`
	Protocol       string        `mapstructure:"protocol" validate:"required,oneof=imap lmtp"`
	TestUsername   string        `mapstructure:"test_username"`
	TestPassword   string        `mapstructure:"test_password"`
	TLS            TLS           `mapstructure:"tls"`
	CheckInterval  time.Duration `mapstructure:"check_interval"`
	Port           int           `mapstructure:"port" validate:"required,min=1,max=65535"`
	MaxConnections uint16        `mapstructure:"max_connections" validate:"required,min=1,max=65535"`
	Weight         uint8         `mapstructure:"weight" validate:"required,min=1,max=255"`
	DeepCheck      bool          `mapstructure:"deep_check"`
	HAProxy        bool          `mapstructure:"haproxy"`
	Maintenance    bool          `mapstructure:"maintenance"`
}

func (b *BackendServer) String() string {
	return fmt.Sprintf("{ Host: '%s' Port: '%d' Protocol: '%s' ShardTag '%s'  Maintenance: '%v' DeepCheck: '%v' HAProxy: '%v' TLS: '%s' Weight: '%d' MaxConnections: '%d' CheckInterval: '%s' TestUsername: '%s' TestPassword: '%s' Identifier: '%s' }",
		b.Host, b.Port, b.Protocol, b.ShardTag, b.Maintenance, b.DeepCheck, b.HAProxy, b.TLS.String(), b.Weight, b.MaxConnections, b.CheckInterval, b.TestUsername, b.TestPassword, b.Identifier)
}
