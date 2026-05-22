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

//nolint:revive // The exported model names intentionally mirror the public config vocabulary.
package config

type AuthConfig struct {
	Authorities map[string]AuthorityConfig `mapstructure:"authorities" yaml:"authorities" validate:"required,min=1,dive"`
}

type AuthorityConfig struct {
	Transport  string                       `mapstructure:"transport" yaml:"transport" validate:"required"`
	Timeout    Duration                     `mapstructure:"timeout" yaml:"timeout"`
	Mechanisms AuthorityMechanismsConfig    `mapstructure:"mechanisms" yaml:"mechanisms" validate:"required"`
	OIDC       AuthorityOIDCConfig          `mapstructure:"oidc" yaml:"oidc" validate:"required"`
	HTTP       AuthorityHTTPTransportConfig `mapstructure:"http" yaml:"http" validate:"required"`
	GRPC       AuthorityGRPCTransportConfig `mapstructure:"grpc" yaml:"grpc" validate:"required"`
}

type AuthorityMechanismsConfig struct {
	Password PasswordMechanismConfig `mapstructure:"password" yaml:"password" validate:"required"`
	Bearer   BearerMechanismConfig   `mapstructure:"bearer" yaml:"bearer" validate:"required"`
}

type PasswordMechanismConfig struct {
	Enabled bool     `mapstructure:"enabled" yaml:"enabled"`
	Names   []string `mapstructure:"names" yaml:"names"`
}

type BearerMechanismConfig struct {
	Enabled       bool     `mapstructure:"enabled" yaml:"enabled"`
	Names         []string `mapstructure:"names" yaml:"names"`
	Validation    string   `mapstructure:"validation" yaml:"validation"`
	TokenMaxBytes int      `mapstructure:"token_max_bytes" yaml:"token_max_bytes"`
}

type AuthorityOIDCConfig struct {
	Enabled        bool     `mapstructure:"enabled" yaml:"enabled"`
	AuthorityMode  string   `mapstructure:"authority_mode" yaml:"authority_mode"`
	IssuerHint     string   `mapstructure:"issuer_hint" yaml:"issuer_hint"`
	AudienceHint   string   `mapstructure:"audience_hint" yaml:"audience_hint"`
	RequiredScopes []string `mapstructure:"required_scopes" yaml:"required_scopes"`
}

type AuthorityHTTPTransportConfig struct {
	Endpoint    string             `mapstructure:"endpoint" yaml:"endpoint"`
	ContentType string             `mapstructure:"content_type" yaml:"content_type"`
	BasicAuth   BasicAuthConfig    `mapstructure:"basic_auth" yaml:"basic_auth" validate:"required"`
	TLS         AuthorityTLSConfig `mapstructure:"tls" yaml:"tls" validate:"required"`
}

type BasicAuthConfig struct {
	Username     string       `mapstructure:"username" yaml:"username"`
	PasswordFile SecretString `mapstructure:"password_file" yaml:"password_file" protected:"true"`
}

type AuthorityTLSConfig struct {
	Enabled            bool   `mapstructure:"enabled" yaml:"enabled"`
	CAFile             string `mapstructure:"ca_file" yaml:"ca_file"`
	ServerName         string `mapstructure:"server_name" yaml:"server_name"`
	InsecureSkipVerify bool   `mapstructure:"insecure_skip_verify" yaml:"insecure_skip_verify"`
}

type AuthorityGRPCTransportConfig struct {
	Address    string               `mapstructure:"address" yaml:"address"`
	Authority  string               `mapstructure:"authority" yaml:"authority"`
	CallerAuth GRPCCallerAuthConfig `mapstructure:"caller_auth" yaml:"caller_auth" validate:"required"`
	TLS        AuthorityTLSConfig   `mapstructure:"tls" yaml:"tls" validate:"required"`
}

type GRPCCallerAuthConfig struct {
	Basic  BasicCallerAuthConfig  `mapstructure:"basic" yaml:"basic" validate:"required"`
	Bearer BearerCallerAuthConfig `mapstructure:"bearer" yaml:"bearer" validate:"required"`
}

type BasicCallerAuthConfig struct {
	Enabled      bool         `mapstructure:"enabled" yaml:"enabled"`
	Username     string       `mapstructure:"username" yaml:"username"`
	PasswordFile SecretString `mapstructure:"password_file" yaml:"password_file" protected:"true"`
}

type BearerCallerAuthConfig struct {
	Enabled   bool         `mapstructure:"enabled" yaml:"enabled"`
	TokenFile SecretString `mapstructure:"token_file" yaml:"token_file" protected:"true"`
}
