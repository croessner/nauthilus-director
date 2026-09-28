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

import "strings"

const (
	// BearerTokenBindingAudienceResource accepts only tokens whose audience or resource matches the
	// configured required_audience or required_resource. It is the default.
	BearerTokenBindingAudienceResource = "audience_resource"
	// BearerTokenBindingIntrospectionAllowlist additionally accepts plain user tokens that the
	// identity provider reports active for the listener's dedicated introspection client, leaving
	// the audience binding to the provider's introspection allowlist.
	BearerTokenBindingIntrospectionAllowlist = "introspection_allowlist"

	listenerIntrospectionMaxPrivateKeyFileBytes = 64 * 1024
)

// ListenerBearerConfig is the per-listener bearer override of IMAP, POP3 and ManageSieve listeners.
//
// The authority's mail SASL bearer policy (endpoint, audience, resource, scope, account claim)
// stays in effect; a listener may only replace the introspection client and opt into the
// introspection-allowlist token binding.
type ListenerBearerConfig struct {
	TokenBinding        string                            `mapstructure:"token_binding" yaml:"token_binding"`
	IntrospectionClient ListenerIntrospectionClientConfig `mapstructure:"introspection_client" yaml:"introspection_client"`
}

// ListenerIntrospectionClientConfig optionally replaces the authority's introspection client
// credentials for one listener. An empty client_id inherits the authority client. Secrets are
// accepted only as mounted files.
type ListenerIntrospectionClientConfig struct {
	ClientID             string       `mapstructure:"client_id" yaml:"client_id"`
	AuthMethod           string       `mapstructure:"auth_method" yaml:"auth_method"`
	ClientSecretFile     SecretString `mapstructure:"client_secret_file" yaml:"client_secret_file" protected:"true"`
	ClientPrivateKeyFile SecretString `mapstructure:"client_private_key_file" yaml:"client_private_key_file" protected:"true"`
	ClientKeyID          string       `mapstructure:"client_key_id" yaml:"client_key_id"`
	ClientAssertionAlg   string       `mapstructure:"client_assertion_alg" yaml:"client_assertion_alg"`
}

// Normalize trims the override and applies the default token binding.
func (c ListenerBearerConfig) Normalize() ListenerBearerConfig {
	c.TokenBinding = normalizedTokenBinding(c.TokenBinding)
	c.IntrospectionClient = c.IntrospectionClient.normalize()

	return c
}

// IntrospectionPolicy returns the authority introspection settings with this listener's client
// and token binding applied; audience, resource, scope and account claim stay the authority's.
func (c ListenerBearerConfig) IntrospectionPolicy(authority BearerIntrospectionConfig) BearerIntrospectionConfig {
	c = c.Normalize()
	authority = c.IntrospectionClient.applyTo(authority)
	authority.TokenBinding = c.TokenBinding

	return authority.Normalize()
}

// Dedicated reports whether the listener carries its own introspection client.
func (c ListenerIntrospectionClientConfig) Dedicated() bool {
	return strings.TrimSpace(c.ClientID) != ""
}

// CheckMaterial verifies at startup that the dedicated client's secret or key file is readable,
// without returning or logging its content.
func (c ListenerIntrospectionClientConfig) CheckMaterial() error {
	if !c.Dedicated() {
		return nil
	}

	options := SecretFileOptions{Field: "listener introspection client_secret_file", Path: c.ClientSecretFile, MaxBytes: MaxSecretFileBytes}
	if normalizedOIDCConfigMethod(c.AuthMethod) == oidcPrivateKeyJWT {
		options = SecretFileOptions{
			Field:    "listener introspection client_private_key_file",
			Path:     c.ClientPrivateKeyFile,
			MaxBytes: listenerIntrospectionMaxPrivateKeyFileBytes,
		}
	}

	_, err := ReadSecretFile(options)

	return err
}

// normalize trims the dedicated client and defaults its method to client_secret_basic.
func (c ListenerIntrospectionClientConfig) normalize() ListenerIntrospectionClientConfig {
	c.ClientID = strings.TrimSpace(c.ClientID)
	c.AuthMethod = normalizedOIDCConfigMethod(c.AuthMethod)
	c.ClientKeyID = strings.TrimSpace(c.ClientKeyID)
	c.ClientAssertionAlg = strings.TrimSpace(c.ClientAssertionAlg)

	if c.ClientID != "" && c.AuthMethod == "" {
		c.AuthMethod = oidcClientSecretBasic
	}

	return c
}

// applyTo replaces every authority client credential with the dedicated client; nothing is merged.
func (c ListenerIntrospectionClientConfig) applyTo(authority BearerIntrospectionConfig) BearerIntrospectionConfig {
	client := c.normalize()
	if !client.Dedicated() {
		return authority
	}

	authority.ClientID = client.ClientID
	authority.AuthMethod = client.AuthMethod
	authority.ClientSecret = SecretString{}
	authority.ClientSecretFile = client.ClientSecretFile
	authority.ClientPrivateKeyFile = client.ClientPrivateKeyFile
	authority.ClientKeyID = client.ClientKeyID
	authority.ClientAssertionAlg = client.ClientAssertionAlg

	return authority
}

// hasMaterialWithoutClient reports credentials configured without a client id.
func (c ListenerIntrospectionClientConfig) hasMaterialWithoutClient() bool {
	return !c.Dedicated() && (!c.ClientSecretFile.IsZero() || !c.ClientPrivateKeyFile.IsZero() || c.ClientKeyID != "" ||
		c.ClientAssertionAlg != "" || c.AuthMethod != "")
}

// normalizedTokenBinding lowercases the binding mode and applies the audience/resource default.
func normalizedTokenBinding(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return BearerTokenBindingAudienceResource
	}

	return value
}

// validateListenerIntrospectionClient checks one listener's dedicated client and token binding.
//
// The introspection-allowlist binding hands the audience decision to the identity provider's
// allowlist of the introspecting client. That is only sound when the client is dedicated to this
// listener, so the binding requires introspection_client.client_id.
//
// A dedicated client must differ from the authority's mail SASL introspection client: otherwise the
// listener would share the provider allowlist of every other listener using the authority client.
// authorityClientID is empty when the authority is unknown.
func validateListenerIntrospectionClient(
	path string,
	tokenBinding string,
	client ListenerIntrospectionClientConfig,
	effective BearerIntrospectionConfig,
	authorityClientID string,
	problems *[]string,
) {
	switch tokenBinding {
	case BearerTokenBindingAudienceResource:
	case BearerTokenBindingIntrospectionAllowlist:
		if !client.Dedicated() {
			addProblem(problems, path+".token_binding "+BearerTokenBindingIntrospectionAllowlist+" requires "+path+".introspection_client.client_id")
		}
	default:
		addProblem(problems, path+".token_binding must be "+BearerTokenBindingAudienceResource+" or "+BearerTokenBindingIntrospectionAllowlist)
	}

	if client.Dedicated() {
		if authorityClientID = strings.TrimSpace(authorityClientID); authorityClientID != "" && strings.TrimSpace(client.ClientID) == authorityClientID {
			addProblem(problems, path+".introspection_client.client_id must differ from the authority bearer introspection client_id")
		}

		validateBearerIntrospectionClientAuth(path+".introspection_client", effective, problems)
	} else if client.hasMaterialWithoutClient() {
		addProblem(problems, path+".introspection_client.client_id is required when client credentials are set")
	}
}

// validateListenerBearer checks the bearer override of one IMAP, POP3 or ManageSieve listener.
func validateListenerBearer(path string, bearer ListenerBearerConfig, authority AuthorityConfig, authorityKnown bool, problems *[]string) {
	bearer = bearer.Normalize()
	effective := bearer.IntrospectionPolicy(authority.Mechanisms.Bearer.Introspection)

	if bearer.IntrospectionClient.Dedicated() && authorityKnown && !authority.Mechanisms.Bearer.Introspection.Enabled {
		addProblem(problems, path+".introspection_client requires the authority bearer introspection endpoint")
	}

	validateListenerIntrospectionClient(path, bearer.TokenBinding, bearer.IntrospectionClient, effective, knownAuthorityClientID(authority, authorityKnown), problems)
}

// knownAuthorityClientID returns the authority's mail SASL introspection client id when the authority exists.
func knownAuthorityClientID(authority AuthorityConfig, authorityKnown bool) string {
	if !authorityKnown {
		return ""
	}

	return authority.Mechanisms.Bearer.Introspection.ClientID
}
