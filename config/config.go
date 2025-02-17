package config

import (
	"strings"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type Config struct {
	Server Server `mapstructure:"server"`
}

type Server struct {
	Listen     []Listen   `mapstructure:"listen"`
	Logging    Logging    `mapstructure:"logging"`
	HTTPClient HTTPClient `mapstructure:"http_client"`
}

type Listen struct {
	Kind       string `mapstructure:"kind"`
	Name       string `mapstructure:"name"`
	Type       string `mapstructure:"type"`
	Address    string `mapstructure:"address"`
	Port       int    `mapstructure:"port"`
	Mode       string `mapstructure:"mode"`
	TLS        TLS    `mapstructure:"tls"`
	UseHAProxy bool   `mapstructure:"use_haproxy"`
}

type Logging struct {
	JSON  bool   `mapstructure:"json"`
	Level string `mapstructure:"level"`
}

type HTTPClient struct {
	MaxConnsPerHost     int           `mapstructure:"max_connections_per_host"`
	MaxIdleConns        int           `mapstructure:"max_idle_connections"`
	MaxIdleConnsPerHost int           `mapstructure:"max_idle_connections_per_host"`
	IdleConnTimeout     time.Duration `mapstructure:"idle_connection_timeout"`
	Proxy               string        `mapstructure:"proxy"`
}

type TLS struct {
	Enabled    bool   `mapstructure:"enabled"`
	StartTLS   bool   `mapstructure:"starttls"`
	Cert       string `mapstructure:"cert"`
	Key        string `mapstructure:"key"`
	SkipVerify bool   `mapstructure:"http_client_skip_verify"`
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
