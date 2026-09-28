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

import (
	"slices"
	"testing"
)

const (
	testRequiredScope           = "mail"
	testWebmailAudience         = "webmail"
	testMailIntrospectionClient = "mail-introspection"
	testMailIntrospectionSecret = "/run/secrets/mail-introspection"
	testJMAPResource            = "https://mail.example.org/"
)

// updateMailboxBearer replaces the bearer override of one default mailbox listener.
func updateMailboxBearer(cfg Config, name string, bearer ListenerBearerConfig) Config {
	entry := cfg.Director.Listeners[name]

	switch entry.Protocol {
	case protocolIMAP:
		imap := *entry.IMAP
		imap.Bearer = bearer
		entry.IMAP = &imap
	case protocolPOP3:
		pop3 := *entry.POP3
		pop3.Bearer = bearer
		entry.POP3 = &pop3
	case protocolSIEVE:
		sieve := *entry.Sieve
		sieve.Bearer = bearer
		entry.Sieve = &sieve
	}

	cfg.Director.Listeners[name] = entry

	return cfg
}

// defaultMailboxListenerNames returns the default IMAP, POP3 and ManageSieve listener names.
func defaultMailboxListenerNames() []string {
	names := make([]string, 0, len(DefaultConfig().Director.Listeners))
	for name, entry := range DefaultConfig().Director.Listeners {
		switch entry.Protocol {
		case protocolIMAP, protocolPOP3, protocolSIEVE:
			names = append(names, name)
		}
	}

	slices.Sort(names)

	return names
}

// dedicatedMailClient returns a complete dedicated introspection client.
func dedicatedMailClient() ListenerIntrospectionClientConfig {
	return ListenerIntrospectionClientConfig{ClientID: testMailIntrospectionClient, ClientSecretFile: Secret(testMailIntrospectionSecret)}
}

// TestMailboxListenerBearerDefaultsToAudienceResource keeps the established binding by default.
func TestMailboxListenerBearerDefaultsToAudienceResource(t *testing.T) {
	cfg := DefaultConfig().Normalize()

	for _, name := range defaultMailboxListenerNames() {
		entry := cfg.Director.Listeners[name]

		var bearer ListenerBearerConfig

		switch entry.Protocol {
		case protocolIMAP:
			bearer = entry.IMAP.Bearer
		case protocolPOP3:
			bearer = entry.POP3.Bearer
		default:
			bearer = entry.Sieve.Bearer
		}

		if bearer.TokenBinding != BearerTokenBindingAudienceResource || bearer.IntrospectionClient.Dedicated() {
			t.Fatalf("listener %s bearer = %+v, want audience_resource with the authority client", name, bearer)
		}
	}

	if (ListenerBearerConfig{}).Normalize().TokenBinding != BearerTokenBindingAudienceResource {
		t.Fatal("empty token_binding must normalize to audience_resource")
	}
}

// TestMailboxListenerBearerValidation covers the allowlist precondition and client checks.
func TestMailboxListenerBearerValidation(t *testing.T) {
	for _, name := range defaultMailboxListenerNames() {
		t.Run(name, func(t *testing.T) {
			protocolPath := "director.listeners." + name + "." + DefaultConfig().Director.Listeners[name].Protocol + ".bearer"

			withoutClient := updateMailboxBearer(DefaultConfig(), name, ListenerBearerConfig{TokenBinding: BearerTokenBindingIntrospectionAllowlist})
			expectValidationError(t, withoutClient.Normalize(), protocolPath+".token_binding introspection_allowlist requires "+protocolPath+".introspection_client.client_id")

			unknown := updateMailboxBearer(DefaultConfig(), name, ListenerBearerConfig{TokenBinding: "anything"})
			expectValidationError(t, unknown.Normalize(), protocolPath+".token_binding must be audience_resource or introspection_allowlist")

			orphan := updateMailboxBearer(DefaultConfig(), name, ListenerBearerConfig{
				IntrospectionClient: ListenerIntrospectionClientConfig{ClientSecretFile: Secret(testMailIntrospectionSecret)},
			})
			expectValidationError(t, orphan.Normalize(), protocolPath+".introspection_client.client_id is required when client credentials are set")

			incomplete := updateMailboxBearer(DefaultConfig(), name, ListenerBearerConfig{
				TokenBinding:        BearerTokenBindingIntrospectionAllowlist,
				IntrospectionClient: ListenerIntrospectionClientConfig{ClientID: testMailIntrospectionClient},
			})
			expectValidationError(t, incomplete.Normalize(), protocolPath+".introspection_client must configure exactly one of client_secret or client_secret_file")

			valid := updateMailboxBearer(DefaultConfig(), name, ListenerBearerConfig{
				TokenBinding:        BearerTokenBindingIntrospectionAllowlist,
				IntrospectionClient: dedicatedMailClient(),
			})
			if err := NewLoader().Validate(valid.Normalize()); err != nil {
				t.Fatalf("Validate rejected allowlist binding with a dedicated client: %v", err)
			}
		})
	}
}

// TestMailboxListenerBearerPolicyKeepsAuthorityTokenPolicy replaces only client and binding.
func TestMailboxListenerBearerPolicyKeepsAuthorityTokenPolicy(t *testing.T) {
	authority := DefaultConfig().Auth.Authorities["default"].Mechanisms.Bearer.Introspection
	authority.RequiredAudience = testWebmailAudience
	authority.ClientSecret = Secret("inline-authority-secret")

	inherited := ListenerBearerConfig{}.IntrospectionPolicy(authority)
	if inherited.ClientID != authority.ClientID || inherited.TokenBinding != BearerTokenBindingAudienceResource {
		t.Fatalf("inherited policy = client %q binding %q, want the authority client and audience_resource", inherited.ClientID, inherited.TokenBinding)
	}

	policy := ListenerBearerConfig{
		TokenBinding:        " Introspection_Allowlist ",
		IntrospectionClient: dedicatedMailClient(),
	}.IntrospectionPolicy(authority)

	if policy.ClientID != testMailIntrospectionClient || policy.ClientSecretFile.Value() != testMailIntrospectionSecret ||
		!policy.ClientSecret.IsZero() || policy.AuthMethod != oidcClientSecretBasic {
		t.Fatal("dedicated client must replace every authority client credential")
	}

	if policy.TokenBinding != BearerTokenBindingIntrospectionAllowlist {
		t.Fatalf("token binding = %q, want introspection_allowlist", policy.TokenBinding)
	}

	if policy.RequiredAudience != testWebmailAudience || policy.RequiredScope != authority.RequiredScope || policy.Issuer != authority.Issuer {
		t.Fatal("listener override must keep the authority audience, scope and endpoint")
	}
}

// TestJMAPBearerTokenBinding accepts the allowlist binding only with a dedicated client and makes
// the local audience or resource optional in that mode.
func TestJMAPBearerTokenBinding(t *testing.T) {
	allowlist := updateJMAPListener(jmapTestConfig(), func(entry *ListenerConfig) {
		entry.JMAP.Auth.Bearer = JMAPBearerAuthConfig{
			Enabled:             true,
			RequiredScope:       testRequiredScope,
			TokenBinding:        BearerTokenBindingIntrospectionAllowlist,
			IntrospectionClient: dedicatedMailClient(),
		}
	})
	if err := NewLoader().Validate(allowlist.Normalize()); err != nil {
		t.Fatalf("Validate rejected JMAP allowlist binding without local audience: %v", err)
	}

	withoutClient := updateJMAPListener(jmapTestConfig(), func(entry *ListenerConfig) {
		entry.JMAP.Auth.Bearer = JMAPBearerAuthConfig{
			Enabled:          true,
			RequiredResource: testJMAPResource,
			RequiredScope:    testRequiredScope,
			TokenBinding:     BearerTokenBindingIntrospectionAllowlist,
		}
	})
	expectValidationError(t, withoutClient.Normalize(), "director.listeners.jmap.jmap.auth.bearer.token_binding introspection_allowlist requires")

	withoutBinding := updateJMAPListener(jmapTestConfig(), func(entry *ListenerConfig) {
		entry.JMAP.Auth.Bearer = JMAPBearerAuthConfig{Enabled: true, RequiredScope: testRequiredScope, IntrospectionClient: dedicatedMailClient()}
	})
	expectValidationError(t, withoutBinding.Normalize(), "required_audience or director.listeners.jmap.jmap.auth.bearer.required_resource is required")

	withoutScope := updateJMAPListener(jmapTestConfig(), func(entry *ListenerConfig) {
		entry.JMAP.Auth.Bearer = JMAPBearerAuthConfig{
			Enabled:             true,
			TokenBinding:        BearerTokenBindingIntrospectionAllowlist,
			IntrospectionClient: dedicatedMailClient(),
		}
	})
	expectValidationError(t, withoutScope.Normalize(), "director.listeners.jmap.jmap.auth.bearer.required_scope is required")

	policy := JMAPBearerAuthConfig{
		RequiredResource:    testJMAPResource,
		RequiredScope:       testRequiredScope,
		TokenBinding:        BearerTokenBindingIntrospectionAllowlist,
		IntrospectionClient: dedicatedMailClient(),
	}.BearerIntrospectionPolicy(DefaultConfig().Auth.Authorities["default"].Mechanisms.Bearer.Introspection)
	if policy.TokenBinding != BearerTokenBindingIntrospectionAllowlist || policy.RequiredResource != testJMAPResource {
		t.Fatalf("JMAP policy binding = %q resource = %q", policy.TokenBinding, policy.RequiredResource)
	}
}
