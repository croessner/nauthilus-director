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

package nauthilus

import (
	"context"
	"maps"
	"testing"

	"github.com/croessner/nauthilus-director/internal/config"
)

const (
	bindingDCRClient     = "dcr-7f3a9c"
	bindingMailResource  = "https://mail.example.test/"
	bindingOtherResource = "https://files.example.test/"
	bindingScope         = "email"
	bindingAccountA      = "account-a"
	bindingProfileScope  = "profile"
)

// bindingPayload returns an active introspection response for one token shape.
func bindingPayload(audience any, extra map[string]any) map[string]any {
	payload := map[string]any{
		oidcClaimActive:    true,
		jwtClaimAudience:   audience,
		oidcClaimScope:     bindingOpenIDScope + " " + bindingScope,
		bearerClaimAccount: bindingAccountA,
	}

	maps.Copy(payload, extra)

	return payload
}

// withAllowlist switches a test policy to the introspection-allowlist binding.
func withAllowlist(cfg *config.BearerIntrospectionConfig) {
	cfg.TokenBinding = config.BearerTokenBindingIntrospectionAllowlist
}

// TestSASLBearerTokenBindingModes proves the allowlist binding accepts plain tokens of other
// clients only when enabled, keeps resource-bound tokens bound, and still enforces the scope.
func TestSASLBearerTokenBindingModes(t *testing.T) {
	for _, test := range bindingModeCases() {
		t.Run(test.name, func(t *testing.T) {
			server := newSASLBearerServer(t, oidcAuthMethodClientSecretBasic, test.payload, nil)
			defer server.Close()

			cfg := testBearerIntrospectionConfig(server.URL, oidcAuthMethodClientSecretBasic)
			if test.configure != nil {
				test.configure(&cfg)
			}

			result, err := newTestSASLBearerIntrospector(t, server, cfg).Introspect(context.Background(), testBearerRequest())
			if err != nil {
				t.Fatalf("Introspect returned error: %v", err)
			}

			if result.Decision != test.want {
				t.Fatalf("decision = %q, want %q", result.Decision, test.want)
			}
		})
	}
}

// bindingModeCase is one token shape with the policy it runs under and the expected decision.
type bindingModeCase struct {
	name      string
	payload   map[string]any
	configure func(*config.BearerIntrospectionConfig)
	want      string
}

// bindingModeCases lists the token shapes that separate the default and allowlist bindings.
func bindingModeCases() []bindingModeCase {
	return append(bindingAcceptedCases(), bindingRefusedCases()...)
}

// bindingAcceptedCases lists token shapes whose outcome depends on the binding mode.
func bindingAcceptedCases() []bindingModeCase {
	return []bindingModeCase{
		{
			name:    "foreign plain token refused by default",
			payload: bindingPayload(bindingDCRClient, map[string]any{oidcClaimAuthorizedParty: bindingDCRClient}),
			want:    DecisionRejected,
		},
		{
			name:      "foreign plain token accepted with allowlist binding",
			payload:   bindingPayload(bindingDCRClient, map[string]any{oidcClaimAuthorizedParty: bindingDCRClient}),
			configure: withAllowlist,
			want:      DecisionAuthenticated,
		},
		{
			name:      "single audience without azp is a plain token",
			payload:   bindingPayload([]any{bindingDCRClient}, nil),
			configure: withAllowlist,
			want:      DecisionAuthenticated,
		},
		{
			name:      "configured audience still accepted with allowlist binding",
			payload:   bindingPayload(testBearerClientID, nil),
			configure: withAllowlist,
			want:      DecisionAuthenticated,
		},
		{
			name:      "token bound to another resource refused",
			payload:   bindingPayload([]any{bindingDCRClient, bindingOtherResource}, map[string]any{oidcClaimAuthorizedParty: bindingDCRClient}),
			configure: withAllowlist,
			want:      DecisionRejected,
		},
		{
			name:      "resource claim refused unless configured",
			payload:   bindingPayload(bindingDCRClient, map[string]any{oidcClaimAuthorizedParty: bindingDCRClient, oidcClaimResource: bindingOtherResource}),
			configure: withAllowlist,
			want:      DecisionRejected,
		},
		{
			name:    "configured resource accepted with allowlist binding",
			payload: bindingPayload([]any{bindingDCRClient, bindingMailResource}, map[string]any{oidcClaimAuthorizedParty: bindingDCRClient, oidcClaimResource: bindingMailResource}),
			configure: func(cfg *config.BearerIntrospectionConfig) {
				withAllowlist(cfg)
				cfg.RequiredResource = bindingMailResource
			},
			want: DecisionAuthenticated,
		},
	}
}

// bindingRefusedCases lists token shapes the allowlist binding still refuses.
func bindingRefusedCases() []bindingModeCase {
	return []bindingModeCase{
		{
			name:      "multiple audiences without azp refused",
			payload:   bindingPayload([]any{bindingDCRClient, "other-client"}, nil),
			configure: withAllowlist,
			want:      DecisionRejected,
		},
		{
			name:      "service token refused",
			payload:   bindingPayload(bindingDCRClient, map[string]any{oidcFormClientID: bindingDCRClient}),
			configure: withAllowlist,
			want:      DecisionRejected,
		},
		{
			name:      "missing audience refused",
			payload:   bindingPayload(nil, nil),
			configure: withAllowlist,
			want:      DecisionRejected,
		},
		{
			name:      "scope still required with allowlist binding",
			payload:   bindingPayload(bindingDCRClient, map[string]any{oidcClaimAuthorizedParty: bindingDCRClient, oidcClaimScope: bindingOpenIDScope + " " + bindingProfileScope}),
			configure: withAllowlist,
			want:      DecisionRejected,
		},
	}
}

// TestSASLBearerAllowlistBindingNeedsNoLocalAudience allows an unbound local policy only in allowlist mode.
func TestSASLBearerAllowlistBindingNeedsNoLocalAudience(t *testing.T) {
	server := newSASLBearerServer(t, oidcAuthMethodClientSecretBasic, bindingPayload(bindingDCRClient, map[string]any{oidcClaimAuthorizedParty: bindingDCRClient}), nil)
	defer server.Close()

	cfg := testBearerIntrospectionConfig(server.URL, oidcAuthMethodClientSecretBasic)
	cfg.RequiredAudience = ""

	if _, err := NewSASLBearerIntrospector(context.Background(), cfg, server.Client()); err == nil {
		t.Fatal("audience_resource binding accepted a policy without audience or resource")
	}

	withAllowlist(&cfg)

	result, err := newTestSASLBearerIntrospector(t, server, cfg).Introspect(context.Background(), testBearerRequest())
	if err != nil || result.Decision != DecisionAuthenticated {
		t.Fatalf("Introspect = %+v, %v; want an accepted allowlisted plain token", result, err)
	}

	cfg.TokenBinding = "unknown"
	if _, err := NewSASLBearerIntrospector(context.Background(), cfg, server.Client()); err == nil {
		t.Fatal("unsupported token binding was accepted")
	}
}
