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

//nolint:goconst // MCP validation cases repeat the exact operator-facing messages they pin.
package config

import (
	"maps"
	"strings"
	"testing"
	"time"
)

// mcpEnabledConfig returns the default config with a complete, valid MCP endpoint.
func mcpEnabledConfig() Config {
	cfg := DefaultConfig()
	cfg.Runtime.Servers.MCP.Enabled = true
	cfg.Runtime.Servers.MCP.Resource = "https://director.example.org/mcp"
	cfg.Runtime.Servers.MCP.TrustedProxies = []string{"192.0.2.10/32"}
	cfg.Runtime.Servers.MCP.AllowedClients = []string{"support-cli"}
	cfg.Runtime.Servers.MCP.RequiredGroups = []string{"admin"}

	return cfg
}

// TestMCPDefaultsAreDisabledAndBounded pins the safe defaults of the MCP endpoint.
func TestMCPDefaultsAreDisabledAndBounded(t *testing.T) {
	assertMCPDefaultSettings(t, DefaultConfig().Runtime.Servers.MCP)

	if err := NewLoader().Validate(DefaultConfig()); err != nil {
		t.Fatalf("default config with disabled MCP endpoint = %v", err)
	}

	if err := NewLoader().Validate(mcpEnabledConfig()); err != nil {
		t.Fatalf("complete MCP endpoint = %v", err)
	}
}

// assertMCPDefaultSettings checks the shipped endpoint and limit defaults.
func assertMCPDefaultSettings(t *testing.T, mcp MCPServerConfig) {
	t.Helper()

	defaults := MCPServerConfig{Address: "127.0.0.1:9097", TLSTermination: MCPTLSTerminationTrustedReverseProxy,
		Authority: defaultMCPAuthorityName, GroupsClaim: defaultMCPGroupsClaim, Audit: MCPAuditConfig{Enabled: true}}
	if mcp.Enabled || mcp.Address != defaults.Address || mcp.TLSTermination != defaults.TLSTermination ||
		mcp.Authority != defaults.Authority || mcp.GroupsClaim != defaults.GroupsClaim || mcp.Audit != defaults.Audit || mcp.Resource != "" || len(mcp.AllowedClients) != 0 {
		t.Fatalf("MCP defaults = %+v", mcp)
	}

	want := MCPLimitsConfig{Timeout: NewDuration(15 * time.Second), MaxConcurrent: 8, MaxConcurrentPerPrincipal: 2,
		MaxRequestBytes: 64 << 10, MaxResponseBytes: 1 << 20, FailedAuthPerMinute: 30}
	if mcp.Limits != want {
		t.Fatalf("MCP limits = %+v", mcp.Limits)
	}
}

// TestMCPLoopbackResourceNeedsNoProxy pins that a plain-http resource is accepted only on loopback.
func TestMCPLoopbackResourceNeedsNoProxy(t *testing.T) {
	cfg := mcpEnabledConfig()
	cfg.Runtime.Servers.MCP.Resource = "http://127.0.0.1:9097/mcp"
	cfg.Runtime.Servers.MCP.TrustedProxies = nil

	if err := NewLoader().Validate(cfg); err != nil {
		t.Fatalf("loopback http resource = %v", err)
	}
}

// TestMCPValidationRejectsUnsafeSettings pins every fail-closed validation of the MCP endpoint.
func TestMCPValidationRejectsUnsafeSettings(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*Config)
		want   string
	}{
		"address":           {func(c *Config) { c.Runtime.Servers.MCP.Address = "no-port" }, "runtime.servers.mcp.address must be host:port"},
		"control collision": {func(c *Config) { c.Runtime.Servers.MCP.Address = c.Runtime.Servers.Control.Address }, "must differ from runtime.servers.control.address"},
		"tls termination":   {func(c *Config) { c.Runtime.Servers.MCP.TLSTermination = "none" }, "tls_termination must be trusted_reverse_proxy"},
		"missing resource":  {func(c *Config) { c.Runtime.Servers.MCP.Resource = "" }, "resource must be an absolute http or https URL"},
		"relative resource": {func(c *Config) { c.Runtime.Servers.MCP.Resource = "/mcp" }, "resource must be an absolute http or https URL"},
		"remote http":       {func(c *Config) { c.Runtime.Servers.MCP.Resource = "http://director.example.org/mcp" }, "must use https unless its host is loopback"},
		"resource query":    {func(c *Config) { c.Runtime.Servers.MCP.Resource = "https://director.example.org/mcp?x=1" }, "must not carry user info, a query or a fragment"},
		"resource scheme":   {func(c *Config) { c.Runtime.Servers.MCP.Resource = "ftp://director.example.org/mcp" }, "resource must be an absolute http or https URL"},
		"no proxy":          {func(c *Config) { c.Runtime.Servers.MCP.TrustedProxies = nil }, "trusted_proxies must list the TLS-terminating reverse proxy"},
		"bad proxy":         {func(c *Config) { c.Runtime.Servers.MCP.TrustedProxies = []string{"proxy.example.org"} }, "trusted_proxies[0] must be an IP address or CIDR"},
		"bad host":          {func(c *Config) { c.Runtime.Servers.MCP.AllowedHosts = []string{"https://x"} }, "allowed_hosts[0] must be a host or host:port"},
		"bad origin":        {func(c *Config) { c.Runtime.Servers.MCP.AllowedBrowserOrigins = []string{"*"} }, "allowed_browser_origins[0] must be an origin"},
		"origin path":       {func(c *Config) { c.Runtime.Servers.MCP.AllowedBrowserOrigins = []string{"https://x.example/app"} }, "allowed_browser_origins[0] must be an origin"},
		"no authority":      {func(c *Config) { c.Runtime.Servers.MCP.Authority = "" }, "runtime.servers.mcp.authority is required"},
		"unknown authority": {func(c *Config) { c.Runtime.Servers.MCP.Authority = "missing" }, "runtime.servers.mcp.authority must reference a configured authority"},
		"no introspection": {func(c *Config) {
			authority := c.Auth.Authorities["default"]
			authority.OIDC.ClientCredentials.Enabled = false
			c.Auth.Authorities["default"] = authority
			c.Runtime.Servers.Control.Auth.OIDC.Enabled = false
		}, "runtime.servers.mcp.authority must reference an authority with OIDC client credentials enabled"},
		"no issuer": {func(c *Config) {
			authority := c.Auth.Authorities["default"]
			authority.OIDC.Issuer = ""
			authority.OIDC.DiscoveryURL = "https://auth.example.org/.well-known/openid-configuration"
			c.Auth.Authorities["default"] = authority
		}, "runtime.servers.mcp.authority must reference an authority with oidc.issuer set"},
		"no clients":        {func(c *Config) { c.Runtime.Servers.MCP.AllowedClients = nil }, "allowed_clients must list at least one OAuth client id"},
		"blank client":      {func(c *Config) { c.Runtime.Servers.MCP.AllowedClients = []string{"a b"} }, "allowed_clients[0] must be a single printable OAuth client id"},
		"duplicate client":  {func(c *Config) { c.Runtime.Servers.MCP.AllowedClients = []string{"a", "a"} }, "allowed_clients[1] duplicates another OAuth client id"},
		"no groups":         {func(c *Config) { c.Runtime.Servers.MCP.RequiredGroups = nil }, "required_groups must list at least one group name"},
		"blank group":       {func(c *Config) { c.Runtime.Servers.MCP.RequiredGroups = []string{""} }, "required_groups[0] must be a single printable group name"},
		"groups claim":      {func(c *Config) { c.Runtime.Servers.MCP.GroupsClaim = "" }, "groups_claim must be a single printable claim name"},
		"zero timeout":      {func(c *Config) { c.Runtime.Servers.MCP.Limits.Timeout = 0 }, "limits.timeout must be greater than zero and at most 1m"},
		"long timeout":      {func(c *Config) { c.Runtime.Servers.MCP.Limits.Timeout = NewDuration(2 * time.Minute) }, "limits.timeout must be greater than zero and at most 1m"},
		"concurrency":       {func(c *Config) { c.Runtime.Servers.MCP.Limits.MaxConcurrent = 65 }, "limits.max_concurrent must be between 1 and 64"},
		"per principal":     {func(c *Config) { c.Runtime.Servers.MCP.Limits.MaxConcurrentPerPrincipal = 9 }, "max_concurrent_per_principal must be greater than zero and must not exceed max_concurrent"},
		"request bytes":     {func(c *Config) { c.Runtime.Servers.MCP.Limits.MaxRequestBytes = 2 << 20 }, "limits.max_request_bytes must be between 1 and 1048576"},
		"response bytes":    {func(c *Config) { c.Runtime.Servers.MCP.Limits.MaxResponseBytes = 0 }, "limits.max_response_bytes must be between 1 and 16777216"},
		"failed auth limit": {func(c *Config) { c.Runtime.Servers.MCP.Limits.FailedAuthPerMinute = 0 }, "limits.failed_auth_per_minute must be greater than zero"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := mcpEnabledConfig()
			cfg.Auth.Authorities = cloneAuthoritiesForMCPTest(cfg.Auth.Authorities)
			tc.mutate(&cfg)

			err := NewLoader().Validate(cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate = %v, want %q", err, tc.want)
			}
		})
	}
}

// TestMCPDedicatedIntrospectionClient pins that a dedicated client replaces the authority client
// for introspection, needs only an OIDC authority with issuer, and must carry its own material.
func TestMCPDedicatedIntrospectionClient(t *testing.T) {
	cfg := mcpEnabledConfig()
	cfg.Auth.Authorities = cloneAuthoritiesForMCPTest(cfg.Auth.Authorities)
	authority := cfg.Auth.Authorities["default"]
	authority.OIDC.ClientCredentials.Enabled = false
	cfg.Auth.Authorities["default"] = authority
	cfg.Runtime.Servers.Control.Auth.OIDC.Enabled = false
	cfg.Runtime.Servers.MCP.IntrospectionClient = ListenerIntrospectionClientConfig{ClientID: "director-mcp",
		ClientSecretFile: Secret("/etc/nauthilus-director/mcp/client-secret")}

	if err := NewLoader().Validate(cfg); err != nil {
		t.Fatalf("dedicated introspection client = %v", err)
	}

	assertDedicatedIntrospectionOIDC(t, cfg.Runtime.Servers.MCP.IntrospectionOIDC(authority.OIDC), authority.OIDC.Issuer)

	cfg.Runtime.Servers.MCP.IntrospectionClient.ClientSecretFile = SecretString{}

	if err := NewLoader().Validate(cfg); err == nil || !strings.Contains(err.Error(), "runtime.servers.mcp.introspection_client must configure exactly one") {
		t.Fatalf("dedicated client without secret = %v", err)
	}

	cfg.Runtime.Servers.MCP.IntrospectionClient = ListenerIntrospectionClientConfig{ClientSecretFile: Secret("/x")}

	if err := NewLoader().Validate(cfg); err == nil || !strings.Contains(err.Error(), "introspection_client.client_id is required") {
		t.Fatalf("material without client = %v", err)
	}

	if got := mcpEnabledConfig().Runtime.Servers.MCP.IntrospectionOIDC(authority.OIDC); got.ClientCredentials.Enabled {
		t.Fatal("without a dedicated client the authority settings must be returned unchanged")
	}
}

// assertDedicatedIntrospectionOIDC checks that only the dedicated client authenticates introspection.
func assertDedicatedIntrospectionOIDC(t *testing.T, oidc AuthorityOIDCConfig, issuer string) {
	t.Helper()

	credentials := oidc.ClientCredentials
	if !credentials.Enabled || credentials.ClientID != "director-mcp" || credentials.IntrospectionEndpointAuthMethod != oidcClientSecretBasic ||
		credentials.ClientSecretFile.Value() != "/etc/nauthilus-director/mcp/client-secret" || !credentials.ClientSecret.IsZero() ||
		oidc.Issuer != issuer {
		t.Fatalf("introspection OIDC = %+v", credentials)
	}
}

// TestMCPValidationSkipsDisabledEndpoint pins that a disabled endpoint never blocks a config load.
func TestMCPValidationSkipsDisabledEndpoint(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Runtime.Servers.MCP.Limits.Timeout = 0
	cfg.Runtime.Servers.MCP.Resource = "not a url"

	if err := NewLoader().Validate(cfg); err != nil {
		t.Fatalf("disabled MCP endpoint = %v", err)
	}
}

// TestMCPAdmitsClient pins exact client admission.
func TestMCPAdmitsClient(t *testing.T) {
	settings := mcpEnabledConfig().Runtime.Servers.MCP

	if !settings.AdmitsClient("support-cli") || settings.AdmitsClient("Support-CLI") || settings.AdmitsClient("") {
		t.Fatal("client admission must be exact")
	}

	if !settings.EntitlesGroups([]string{"staff", "admin"}) || settings.EntitlesGroups([]string{"Admin", ""}) || settings.EntitlesGroups(nil) {
		t.Fatal("group entitlement must be exact")
	}
}

// cloneAuthoritiesForMCPTest detaches the authority map so mutations stay local to one case.
func cloneAuthoritiesForMCPTest(authorities map[string]AuthorityConfig) map[string]AuthorityConfig {
	cloned := make(map[string]AuthorityConfig, len(authorities))
	maps.Copy(cloned, authorities)

	return cloned
}
