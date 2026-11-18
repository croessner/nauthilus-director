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

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
)

const (
	// MCPTLSTerminationTrustedReverseProxy terminates TLS at a trusted reverse proxy in front of the
	// MCP listener. It is the only supported termination mode.
	MCPTLSTerminationTrustedReverseProxy = "trusted_reverse_proxy"

	mcpServerPath = "runtime.servers.mcp"

	mcpSchemeHTTP  = "http"
	mcpSchemeHTTPS = "https"

	maxMCPTimeout          = time.Minute
	maxMCPMaxConcurrent    = 64
	maxMCPMaxRequestBytes  = int64(1 << 20)
	maxMCPMaxResponseBytes = int64(16 << 20)

	// defaultMCPAuthorityName names the authority the shipped defaults configure.
	defaultMCPAuthorityName = "default"

	// defaultMCPGroupsClaim is the introspection claim that lists the caller's groups.
	defaultMCPGroupsClaim = "groups"
)

// MCPServerConfig configures the optional read-only MCP diagnostics endpoint.
//
// The endpoint is the OAuth protected resource named by Resource. Nauthilus is its authorization
// server: incoming user access tokens are introspected through the OIDC client credentials of
// Authority, must be issued to one of AllowedClients, must carry Resource as audience and must
// name the caller as a member of one of RequiredGroups in GroupsClaim. Nauthilus does not
// evaluate group rights for resources it does not host, so the endpoint enforces them itself.
// Every setting is read at startup; changing it requires a restart.
type MCPServerConfig struct {
	Enabled               bool            `mapstructure:"enabled" yaml:"enabled"`
	Address               string          `mapstructure:"address" yaml:"address"`
	TLSTermination        string          `mapstructure:"tls_termination" yaml:"tls_termination"`
	Resource              string          `mapstructure:"resource" yaml:"resource"`
	Authority             string          `mapstructure:"authority" yaml:"authority"`
	AllowedClients        []string        `mapstructure:"allowed_clients" yaml:"allowed_clients"`
	RequiredGroups        []string        `mapstructure:"required_groups" yaml:"required_groups"`
	GroupsClaim           string          `mapstructure:"groups_claim" yaml:"groups_claim"`
	TrustedProxies        []string        `mapstructure:"trusted_proxies" yaml:"trusted_proxies"`
	AllowedHosts          []string        `mapstructure:"allowed_hosts" yaml:"allowed_hosts"`
	AllowedBrowserOrigins []string        `mapstructure:"allowed_browser_origins" yaml:"allowed_browser_origins"`
	Limits                MCPLimitsConfig `mapstructure:"limits" yaml:"limits" validate:"required"`
	Audit                 MCPAuditConfig  `mapstructure:"audit" yaml:"audit" validate:"required"`
}

// MCPLimitsConfig bounds the MCP endpoint per request, per principal and per client address.
type MCPLimitsConfig struct {
	Timeout                   Duration `mapstructure:"timeout" yaml:"timeout"`
	MaxConcurrent             int      `mapstructure:"max_concurrent" yaml:"max_concurrent"`
	MaxConcurrentPerPrincipal int      `mapstructure:"max_concurrent_per_principal" yaml:"max_concurrent_per_principal"`
	MaxRequestBytes           int64    `mapstructure:"max_request_bytes" yaml:"max_request_bytes"`
	MaxResponseBytes          int64    `mapstructure:"max_response_bytes" yaml:"max_response_bytes"`
	FailedAuthPerMinute       int      `mapstructure:"failed_auth_per_minute" yaml:"failed_auth_per_minute"`
}

// MCPAuditConfig toggles the transport audit records of the MCP endpoint.
type MCPAuditConfig struct {
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`
}

// defaultMCPServerConfig returns the disabled, loopback-only endpoint defaults.
func defaultMCPServerConfig() MCPServerConfig {
	return MCPServerConfig{
		Enabled:        false,
		Address:        "127.0.0.1:9097",
		TLSTermination: MCPTLSTerminationTrustedReverseProxy,
		Authority:      defaultMCPAuthorityName,
		GroupsClaim:    defaultMCPGroupsClaim,
		Limits: MCPLimitsConfig{
			Timeout:                   NewDuration(15 * time.Second),
			MaxConcurrent:             8,
			MaxConcurrentPerPrincipal: 2,
			MaxRequestBytes:           64 << 10,
			MaxResponseBytes:          1 << 20,
			FailedAuthPerMinute:       30,
		},
		Audit: MCPAuditConfig{Enabled: true},
	}
}

// ResourceURL parses the configured protected resource URL.
func (c MCPServerConfig) ResourceURL() (*url.URL, error) {
	return url.Parse(strings.TrimSpace(c.Resource))
}

// validateMCPServer rejects an unsafe or incomplete MCP endpoint configuration at load time.
func validateMCPServer(runtime RuntimeConfig, authorities map[string]AuthorityConfig, problems *[]string) {
	section := runtime.Servers.MCP
	if !section.Enabled {
		return
	}

	validateMCPListener(section, runtime.Servers.Control, problems)

	resource, ok := validateMCPResource(section, problems)
	if ok {
		validateMCPProxies(section, resource, problems)
	}

	validateMCPHostsAndOrigins(section, problems)
	validateMCPAuthority(section, authorities, problems)
	validateMCPClients(section, problems)
	validateMCPGroups(section, problems)
	validateMCPLimits(section.Limits, problems)
}

// validateMCPListener requires a host:port address apart from the control listener and the
// supported TLS termination.
func validateMCPListener(section MCPServerConfig, control ControlServerConfig, problems *[]string) {
	address := strings.TrimSpace(section.Address)
	if _, _, err := net.SplitHostPort(address); err != nil {
		addProblem(problems, mcpServerPath+".address must be host:port")
	} else if control.Enabled && address == strings.TrimSpace(control.Address) {
		addProblem(problems, mcpServerPath+".address must differ from runtime.servers.control.address")
	}

	if strings.TrimSpace(section.TLSTermination) != MCPTLSTerminationTrustedReverseProxy {
		addProblem(problems, mcpServerPath+".tls_termination must be "+MCPTLSTerminationTrustedReverseProxy)
	}
}

// validateMCPResource requires an absolute https resource URL, or plain http for a loopback host.
func validateMCPResource(section MCPServerConfig, problems *[]string) (*url.URL, bool) {
	path := mcpServerPath + ".resource"

	resource, err := section.ResourceURL()
	if strings.TrimSpace(section.Resource) == "" || err != nil || !resource.IsAbs() || resource.Host == "" {
		addProblem(problems, path+" must be an absolute http or https URL")

		return nil, false
	}

	switch {
	case hasMCPResourceDecoration(resource):
		addProblem(problems, path+" must not carry user info, a query or a fragment")
	case resource.Scheme == mcpSchemeHTTPS:
		return resource, true
	case resource.Scheme == mcpSchemeHTTP && isLoopbackMCPHost(resource.Hostname()):
		return resource, true
	case resource.Scheme == mcpSchemeHTTP:
		addProblem(problems, path+" must use https unless its host is loopback")
	default:
		addProblem(problems, path+" must be an absolute http or https URL")
	}

	return nil, false
}

// hasMCPResourceDecoration reports user info, a query, a fragment or an opaque part on a resource URL.
func hasMCPResourceDecoration(resource *url.URL) bool {
	return resource.User != nil || resource.RawQuery != "" || resource.Fragment != "" || resource.Opaque != ""
}

// validateMCPProxies requires trusted proxies for an https resource; plain http is accepted only
// for a loopback resource reached directly from loopback.
func validateMCPProxies(section MCPServerConfig, resource *url.URL, problems *[]string) {
	for idx, entry := range section.TrustedProxies {
		if _, err := netip.ParsePrefix(strings.TrimSpace(entry)); err == nil {
			continue
		}

		if _, err := netip.ParseAddr(strings.TrimSpace(entry)); err != nil {
			addProblem(problems, fmt.Sprintf("%s.trusted_proxies[%d] must be an IP address or CIDR", mcpServerPath, idx))
		}
	}

	if resource.Scheme == mcpSchemeHTTPS && len(section.TrustedProxies) == 0 {
		addProblem(problems, mcpServerPath+".trusted_proxies must list the TLS-terminating reverse proxy for an https resource")
	}
}

// validateMCPHostsAndOrigins requires plain host values and absolute browser origins.
func validateMCPHostsAndOrigins(section MCPServerConfig, problems *[]string) {
	for idx, host := range section.AllowedHosts {
		if strings.TrimSpace(host) == "" || strings.ContainsAny(host, "/ @") {
			addProblem(problems, fmt.Sprintf("%s.allowed_hosts[%d] must be a host or host:port", mcpServerPath, idx))
		}
	}

	for idx, origin := range section.AllowedBrowserOrigins {
		if !isMCPBrowserOrigin(origin) {
			addProblem(problems, fmt.Sprintf("%s.allowed_browser_origins[%d] must be an origin such as https://host", mcpServerPath, idx))
		}
	}
}

// isMCPBrowserOrigin reports whether value is a plain scheme://host[:port] origin.
func isMCPBrowserOrigin(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || (parsed.Path != "" && parsed.Path != "/") {
		return false
	}

	return parsed.RawQuery == "" && parsed.Fragment == "" && parsed.User == nil
}

// validateMCPAuthority requires an introspection-capable authority with a known issuer, which the
// protected resource metadata names as the authorization server.
func validateMCPAuthority(section MCPServerConfig, authorities map[string]AuthorityConfig, problems *[]string) {
	path := mcpServerPath + ".authority"

	name := strings.TrimSpace(section.Authority)
	if name == "" {
		addProblem(problems, path+" is required when the MCP endpoint is enabled")

		return
	}

	validateIntrospectionAuthority(path, name, "the MCP endpoint", authorities, problems)

	if authority, ok := authorities[name]; ok && strings.TrimSpace(authority.OIDC.Issuer) == "" {
		addProblem(problems, path+" must reference an authority with oidc.issuer set")
	}
}

// validateMCPClients requires at least one admitted OAuth client and rejects ambiguous ids.
func validateMCPClients(section MCPServerConfig, problems *[]string) {
	validateMCPNameList(mcpServerPath+".allowed_clients", "OAuth client id", section.AllowedClients, problems)
}

// validateMCPGroups requires at least one entitled group and a single-token groups claim, so a
// valid token alone never grants access to user and session diagnostics.
func validateMCPGroups(section MCPServerConfig, problems *[]string) {
	validateMCPNameList(mcpServerPath+".required_groups", "group name", section.RequiredGroups, problems)

	if !isSingleMCPToken(section.GroupsClaim) {
		addProblem(problems, mcpServerPath+".groups_claim must be a single printable claim name")
	}
}

// validateMCPNameList requires a non-empty list of unique single printable names.
func validateMCPNameList(path string, kind string, names []string, problems *[]string) {
	if len(names) == 0 {
		addProblem(problems, path+" must list at least one "+kind)

		return
	}

	seen := make(map[string]struct{}, len(names))

	for idx, name := range names {
		if !isSingleMCPToken(name) {
			addProblem(problems, fmt.Sprintf("%s[%d] must be a single printable %s", path, idx, kind))

			continue
		}

		if _, duplicate := seen[name]; duplicate {
			addProblem(problems, fmt.Sprintf("%s[%d] duplicates another %s", path, idx, kind))
		}

		seen[name] = struct{}{}
	}
}

// isSingleMCPToken reports whether value is non-empty, printable and free of whitespace.
func isSingleMCPToken(value string) bool {
	return value != "" && strings.IndexFunc(value, func(r rune) bool { return unicode.IsSpace(r) || !unicode.IsPrint(r) }) < 0
}

// validateMCPLimits keeps every limit positive and inside its ceiling.
func validateMCPLimits(limits MCPLimitsConfig, problems *[]string) {
	path := mcpServerPath + ".limits"

	if limits.Timeout <= 0 || limits.Timeout.Std() > maxMCPTimeout {
		addProblem(problems, path+".timeout must be greater than zero and at most 1m")
	}

	if limits.MaxConcurrent <= 0 || limits.MaxConcurrent > maxMCPMaxConcurrent {
		addProblem(problems, path+".max_concurrent must be between 1 and 64")
	}

	if limits.MaxConcurrentPerPrincipal <= 0 || limits.MaxConcurrentPerPrincipal > limits.MaxConcurrent {
		addProblem(problems, path+".max_concurrent_per_principal must be greater than zero and must not exceed max_concurrent")
	}

	if limits.MaxRequestBytes <= 0 || limits.MaxRequestBytes > maxMCPMaxRequestBytes {
		addProblem(problems, path+".max_request_bytes must be between 1 and 1048576")
	}

	if limits.MaxResponseBytes <= 0 || limits.MaxResponseBytes > maxMCPMaxResponseBytes {
		addProblem(problems, path+".max_response_bytes must be between 1 and 16777216")
	}

	if limits.FailedAuthPerMinute <= 0 {
		addProblem(problems, path+".failed_auth_per_minute must be greater than zero")
	}
}

// isLoopbackMCPHost reports whether a resource host is localhost or a loopback IP.
func isLoopbackMCPHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}

	addr, err := netip.ParseAddr(host)

	return err == nil && addr.IsLoopback()
}

// EntitlesGroups reports whether one of the caller's groups is a required group.
func (c MCPServerConfig) EntitlesGroups(groups []string) bool {
	return slices.ContainsFunc(groups, func(group string) bool { return group != "" && slices.Contains(c.RequiredGroups, group) })
}

// AdmitsClient reports whether user tokens issued to clientID may call the endpoint.
func (c MCPServerConfig) AdmitsClient(clientID string) bool {
	return clientID != "" && slices.Contains(c.AllowedClients, clientID)
}
