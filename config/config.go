package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type Config struct {
	Server        Server          `mapstructure:"server"`
	BackendServer []BackendServer `mapstructure:"backend_server"`
}

func (cfg *Config) String() string {
	var backendServerStrings []string

	for _, server := range cfg.BackendServer {
		backendServerStrings = append(backendServerStrings, server.String())
	}

	return strings.Join(backendServerStrings, ", ")
}

func (cfg *Config) HandleConfig() error {
	return viper.Unmarshal(cfg)
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

	return cfg, err
}

type Server struct {
	InstanceID string     `mapstructure:"instance_id"`
	Listen     []Listen   `mapstructure:"listen"`
	HTTPClient HTTPClient `mapstructure:"http_client"`
	Logging    Logging    `mapstructure:"logging"`
}

type Listen struct {
	Port       int      `mapstructure:"port"`
	HAProxy    bool     `mapstructure:"haproxy"`
	TLS        TLS      `mapstructure:"tls"`
	AuthMechs  []string `mapstructure:"auth_mechanisms"`
	Kind       string   `mapstructure:"kind"`
	Name       string   `mapstructure:"name"`
	Type       string   `mapstructure:"type"`
	Address    string   `mapstructure:"address"`
	Mode       string   `mapstructure:"mode"`
	Capability string   `mapstructure:"capability"`
}

func (l *Listen) String() string {
	return fmt.Sprintf("{ Name: '%s' Kind: '%s' Type: '%s' Address:Port: '%s:%d' Mode: '%s' Capability: '%s' AuthMechs: '%v' TLS: '%s' }",
		l.Name, l.Kind, l.Type, l.Address, l.Port, l.Mode, l.Capability, l.AuthMechs, l.TLS.String())
}

type Logging struct {
	JSON  bool   `mapstructure:"json"`
	Level string `mapstructure:"level"`
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
	Cert       string `mapstructure:"cert"`
	Key        string `mapstructure:"key"`
}

func (t *TLS) String() string {
	return fmt.Sprintf("{ Enabled: '%v' StartTLS: '%v' SkipVerify: '%v' Cert: '%s' Key: '%s' }",
		t.Enabled, t.StartTLS, t.SkipVerify, t.Cert, t.Key)
}

type BackendServer struct {
	Host           string        `mapstructure:"host"`
	Protocol       string        `mapstructure:"protocol"`
	TestUsername   string        `mapstructure:"test_username"`
	TestPassword   string        `mapstructure:"test_password"`
	TLS            TLS           `mapstructure:"tls"`
	CheckInterval  time.Duration `mapstructure:"check_interval"`
	Port           int           `mapstructure:"port"`
	MaxConnections uint16        `mapstructure:"max_connections"`
	Weight         uint8         `mapstructure:"weight"`
	DeepCheck      bool          `mapstructure:"deep_check"`
	HAProxy        bool          `mapstructure:"haproxy"`
	Maintenance    bool          `mapstructure:"maintenance"`
}

func (b *BackendServer) String() string {
	return fmt.Sprintf("{ Host: '%s' Port: '%d' Protocol: '%s' Maintenance: '%v' DeepCheck: '%v' HAProxy: '%v' TLS: '%s' Weight: '%d' MaxConnections: '%d' CheckInterval: '%s' TestUsername: '%s' TestPassword: '%s' }",
		b.Host, b.Port, b.Protocol, b.Maintenance, b.DeepCheck, b.HAProxy, b.TLS.String(), b.Weight, b.MaxConnections, b.CheckInterval, b.TestUsername, b.TestPassword)
}
