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

//nolint:funlen,goconst,wsl_v5 // JMAP config fixtures keep tables and YAML documents inline.
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// jmapTestConfig returns the default config extended with one valid JMAP listener, pool and backend.
func jmapTestConfig() Config {
	cfg := DefaultConfig()
	cfg.Director.Listeners["jmap"] = ListenerConfig{
		Protocol:    "jmap",
		ServiceName: "jmap",
		Network:     "tcp",
		Address:     "127.0.0.1:18443",
		Authority:   "default",
		BackendPool: "jmap-default",
		TLS: ListenerTLSConfig{
			Mode:          "implicit",
			Cert:          "/etc/nauthilus-director/jmap.crt",
			Key:           Secret("/etc/nauthilus-director/jmap.key"),
			MinTLSVersion: "TLS1.2",
		},
		JMAP: &JMAPListenerConfig{},
	}
	cfg.Director.BackendPools["jmap-default"] = BackendPoolConfig{
		Protocol: "jmap",
		Selector: "rendezvous_hash",
		Backends: []string{"mailstore-a-jmap"},
	}
	cfg.Director.Backends["mailstore-a-jmap"] = BackendConfig{
		Protocol:       "jmap",
		ShardTag:       "mailstore-a",
		BackendNode:    "mailstore-a-node-1",
		Address:        "127.0.0.1:9443",
		Weight:         100,
		MaxConnections: 1000,
		Maintenance:    "disabled",
		TLS: BackendTLSConfig{
			Mode:          "implicit",
			ServerName:    "mailstore-a.example.org",
			MinTLSVersion: "TLS1.2",
		},
		Auth:        BackendAuthConfig{Mode: "none"},
		HealthCheck: BackendHealthConfig{Enabled: true},
	}

	return cfg.Normalize()
}

// updateJMAPListener applies one mutation to the JMAP listener subconfig.
func updateJMAPListener(cfg Config, mutate func(*ListenerConfig)) Config {
	entry := cfg.Director.Listeners["jmap"]
	jmap := *entry.JMAP
	entry.JMAP = &jmap
	mutate(&entry)
	cfg.Director.Listeners["jmap"] = entry

	return cfg
}

// TestJMAPListenerConfigValidates accepts a minimal JMAP listener with documented defaults.
func TestJMAPListenerConfigValidates(t *testing.T) {
	cfg := jmapTestConfig()
	if err := NewLoader().Validate(cfg); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}

	jmap := cfg.Director.Listeners["jmap"].JMAP
	if !jmap.Auth.BasicEnabled() || jmap.Auth.Bearer.Enabled {
		t.Fatal("JMAP defaults must enable basic and disable bearer authentication")
	}

	if jmap.Routing.MissingShard != JMAPMissingShardForbidden {
		t.Fatalf("missing_shard = %q, want forbidden", jmap.Routing.MissingShard)
	}

	if jmap.Limits.MaxUploadBodyBytes != 50*1024*1024 || jmap.Limits.MaxRequestBodyBytes != 10*1024*1024 {
		t.Fatalf("limits = %+v, want 50 MiB uploads and 10 MiB requests", jmap.Limits)
	}

	if jmap.Auth.Cache.TTL.Std() != 30*time.Second || jmap.Auth.Cache.MaxEntries != 10000 {
		t.Fatalf("auth cache = %+v, want 30s and 10000 entries", jmap.Auth.Cache)
	}

	if jmap.Timeouts.ReadHeader.Std() <= 0 || jmap.Timeouts.Idle.Std() <= 0 {
		t.Fatalf("timeouts = %+v, want positive defaults", jmap.Timeouts)
	}
}

// TestJMAPListenerValidationRejectsUnsafePolicy keeps JMAP listeners fail-closed.
func TestJMAPListenerValidationRejectsUnsafePolicy(t *testing.T) {
	disabled := false

	testCases := []struct {
		name   string
		mutate func(*ListenerConfig)
		want   string
	}{
		{
			name:   "missing subconfig",
			mutate: func(entry *ListenerConfig) { entry.JMAP = nil },
			want:   "director.listeners.jmap.jmap is required for jmap listeners",
		},
		{
			name:   "starttls",
			mutate: func(entry *ListenerConfig) { entry.TLS.Mode = "starttls" },
			want:   "director.listeners.jmap.jmap requires listener tls.mode implicit",
		},
		{
			name:   "no scheme",
			mutate: func(entry *ListenerConfig) { entry.JMAP.Auth.Basic.Enabled = &disabled },
			want:   "director.listeners.jmap.jmap.auth must enable basic or bearer authentication",
		},
		{
			name: "bearer without binding",
			mutate: func(entry *ListenerConfig) {
				entry.JMAP.Auth.Bearer = JMAPBearerAuthConfig{Enabled: true, RequiredScope: "mail"}
			},
			want: "director.listeners.jmap.jmap.auth.bearer.required_audience or director.listeners.jmap.jmap.auth.bearer.required_resource is required",
		},
		{
			name: "bearer without scope",
			mutate: func(entry *ListenerConfig) {
				entry.JMAP.Auth.Bearer = JMAPBearerAuthConfig{Enabled: true, RequiredResource: "https://mail.example.org/"}
			},
			want: "director.listeners.jmap.jmap.auth.bearer.required_scope is required",
		},
		{
			name: "secret account claim",
			mutate: func(entry *ListenerConfig) {
				entry.JMAP.Auth.Bearer = JMAPBearerAuthConfig{
					Enabled:          true,
					RequiredResource: "https://mail.example.org/",
					RequiredScope:    "mail",
					AccountClaim:     "access_token",
				}
			},
			want: "director.listeners.jmap.jmap.auth.bearer.account_claim",
		},
		{
			name:   "unknown missing shard policy",
			mutate: func(entry *ListenerConfig) { entry.JMAP.Routing.MissingShard = "guess" },
			want:   "director.listeners.jmap.jmap.routing.missing_shard must be forbidden, unavailable, or hash_fallback",
		},
		{
			name:   "plain public base url",
			mutate: func(entry *ListenerConfig) { entry.JMAP.PublicBaseURL = "http://mail.example.org" },
			want:   "director.listeners.jmap.jmap.public_base_url must be an absolute https URL",
		},
		{
			name:   "health path overlaps jmap",
			mutate: func(entry *ListenerConfig) { entry.JMAP.HealthPath = "/jmap/healthz" },
			want:   "director.listeners.jmap.jmap.health_path must not overlap the proxied JMAP paths",
		},
		{
			name:   "negative body limit",
			mutate: func(entry *ListenerConfig) { entry.JMAP.Limits.MaxUploadBodyBytes = -1 },
			want:   "director.listeners.jmap.jmap.limits.max_upload_body_bytes must be positive",
		},
		{
			name:   "long cache ttl",
			mutate: func(entry *ListenerConfig) { entry.JMAP.Auth.Cache.TTL = NewDuration(time.Hour) },
			want:   "director.listeners.jmap.jmap.auth.cache.ttl must not exceed 10m",
		},
		{
			name:   "realm quote",
			mutate: func(entry *ListenerConfig) { entry.JMAP.Auth.Realm = "a\"b" },
			want:   "director.listeners.jmap.jmap.auth.realm must not contain quotes",
		},
		{
			name:   "foreign subconfig",
			mutate: func(entry *ListenerConfig) { entry.IMAP = &IMAPListenerConfig{} },
			want:   "director.listeners.jmap.imap must not be set for jmap listeners",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			expectValidationError(t, updateJMAPListener(jmapTestConfig(), testCase.mutate), testCase.want)
		})
	}
}

// TestJMAPSubconfigRejectedOnOtherListeners keeps JMAP policy scoped to JMAP listeners.
func TestJMAPSubconfigRejectedOnOtherListeners(t *testing.T) {
	cfg := jmapTestConfig()
	entry := cfg.Director.Listeners["imaps"]
	entry.JMAP = &JMAPListenerConfig{}
	cfg.Director.Listeners["imaps"] = entry

	expectValidationError(t, cfg, "director.listeners.imaps.jmap must not be set for imap listeners")
}

// TestJMAPBackendValidationRequiresHTTPSWithoutDirectorCredentials keeps backend auth with the client.
func TestJMAPBackendValidationRequiresHTTPSWithoutDirectorCredentials(t *testing.T) {
	testCases := []struct {
		name   string
		mutate func(*BackendConfig)
		want   string
	}{
		{
			name:   "plaintext",
			mutate: func(backend *BackendConfig) { backend.TLS.Mode = "plaintext" },
			want:   "director.backends.mailstore-a-jmap.tls.mode for JMAP backends must be implicit",
		},
		{
			name:   "master user",
			mutate: func(backend *BackendConfig) { backend.Auth.Mode = "master_user" },
			want:   "director.backends.mailstore-a-jmap.auth.mode for JMAP backends must be none",
		},
		{
			name:   "deep health",
			mutate: func(backend *BackendConfig) { backend.HealthCheck.DeepCheck = true },
			want:   "director.backends.mailstore-a-jmap.health_check.deep_check is not supported for JMAP backends",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := jmapTestConfig()
			backend := cfg.Director.Backends["mailstore-a-jmap"]
			testCase.mutate(&backend)
			cfg.Director.Backends["mailstore-a-jmap"] = backend

			expectValidationError(t, cfg, testCase.want)
		})
	}
}

// TestJMAPBearerIntrospectionPolicyReplacesAuthorityBinding keeps SASL token policy out of JMAP.
func TestJMAPBearerIntrospectionPolicyReplacesAuthorityBinding(t *testing.T) {
	authority := DefaultConfig().Auth.Authorities["default"].Mechanisms.Bearer.Introspection
	policy := JMAPBearerAuthConfig{
		Enabled:          true,
		RequiredResource: " https://mail.example.org/ ",
		RequiredScope:    "mail:jmap",
	}.BearerIntrospectionPolicy(authority)

	if policy.RequiredAudience != "" || policy.RequiredResource != "https://mail.example.org/" || policy.RequiredScope != "mail:jmap" {
		t.Fatalf("policy binding = %q/%q/%q, want listener values only", policy.RequiredAudience, policy.RequiredResource, policy.RequiredScope)
	}

	if policy.Issuer != authority.Issuer || policy.ClientID != authority.ClientID {
		t.Fatal("policy must keep the authority introspection endpoint and client")
	}
}

// TestJMAPListenerLoadsFromYAML proves the documented YAML shape decodes strictly.
func TestJMAPListenerLoadsFromYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "director.yml")
	content := `director:
  listeners:
    jmap:
      protocol: jmap
      service_name: jmap
      network: tcp
      address: "127.0.0.1:18443"
      authority: default
      backend_pool: jmap-default
      proxy_protocol:
        enabled: true
        trusted_cidrs: ["10.0.0.0/8"]
      tls:
        mode: implicit
        cert: /etc/nauthilus-director/jmap.crt
        key: /etc/nauthilus-director/jmap.key
        min_tls_version: TLS1.2
      jmap:
        public_base_url: https://mail.example.org
        health_path: /director/healthz
        auth:
          realm: mail
          basic:
            enabled: true
          bearer:
            enabled: true
            required_resource: https://mail.example.org/
            required_scope: mail:account:read
            account_claim: dovecot_account
          cache:
            ttl: 20s
            max_entries: 500
        routing:
          missing_shard: unavailable
        limits:
          max_upload_body_bytes: 1048576
  backend_pools:
    jmap-default:
      protocol: jmap
      selector: rendezvous_hash
      backends: [mailstore-a-jmap]
  backends:
    mailstore-a-jmap:
      protocol: jmap
      shard_tag: mailstore-a
      backend_node: mailstore-a-node-1
      address: "127.0.0.1:9443"
      weight: 100
      max_connections: 1000
      maintenance: disabled
      haproxy:
        enabled: true
      tls:
        mode: implicit
        server_name: mailstore-a.example.org
        min_tls_version: TLS1.2
      auth:
        mode: none
      health_check:
        enabled: true
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	snapshot, err := NewLoader().LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile returned error: %v", err)
	}

	jmap := snapshot.Config.Director.Listeners["jmap"].JMAP
	if jmap == nil || jmap.Routing.MissingShard != JMAPMissingShardUnavailable || jmap.Auth.Cache.MaxEntries != 500 {
		t.Fatalf("decoded jmap config = %+v", jmap)
	}

	if jmap.Limits.MaxRequestBodyBytes != 10*1024*1024 || jmap.Limits.MaxUploadBodyBytes != 1048576 {
		t.Fatalf("decoded limits = %+v", jmap.Limits)
	}

	if !strings.EqualFold(jmap.Auth.Bearer.AccountClaim, "dovecot_account") || !jmap.Auth.Bearer.Enabled {
		t.Fatalf("decoded bearer policy = %+v", jmap.Auth.Bearer)
	}
}

// TestTargetConfigDocumentsJMAPListener keeps the documented JMAP example loadable.
func TestTargetConfigDocumentsJMAPListener(t *testing.T) {
	snapshot, err := NewLoader().LoadFile(filepath.Join("..", "..", "docs", "config", "nauthilus-director.target.yml"))
	if err != nil {
		t.Fatalf("load target config: %v", err)
	}

	listener, ok := snapshot.Config.Director.Listeners["jmap"]
	if !ok || listener.JMAP == nil || !listener.JMAP.Auth.Bearer.Enabled || listener.JMAP.Routing.MissingShard != JMAPMissingShardForbidden {
		t.Fatalf("target jmap listener = %+v", listener.JMAP)
	}

	if snapshot.Config.Director.Backends["mailstore-a-jmap"].BackendNode != snapshot.Config.Director.Backends["mailstore-a-imap"].BackendNode {
		t.Fatal("target JMAP backend must share the backend node of the IMAP endpoint")
	}
}

// TestJMAPIntrospectionClientOverridesAuthorityCredentials replaces the client only when configured.
func TestJMAPIntrospectionClientOverridesAuthorityCredentials(t *testing.T) {
	authority := DefaultConfig().Auth.Authorities["default"].Mechanisms.Bearer.Introspection
	authority.ClientSecret = Secret("inline-authority-secret")

	inherited := JMAPBearerAuthConfig{RequiredResource: "https://mail.example.org/", RequiredScope: "mail"}.BearerIntrospectionPolicy(authority)
	if inherited.ClientID != authority.ClientID || inherited.ClientSecretFile != authority.ClientSecretFile || inherited.AuthMethod != authority.AuthMethod {
		t.Fatal("listener without introspection_client must inherit the authority client")
	}

	dedicated := JMAPBearerAuthConfig{
		RequiredResource: "https://mail.example.org/",
		RequiredScope:    "mail",
		IntrospectionClient: JMAPIntrospectionClientConfig{
			ClientID:         " jmap-introspection ",
			ClientSecretFile: Secret("/run/secrets/jmap-introspection"),
		},
	}.BearerIntrospectionPolicy(authority)

	if dedicated.ClientID != "jmap-introspection" || dedicated.AuthMethod != "client_secret_basic" ||
		dedicated.ClientSecretFile.Value() != "/run/secrets/jmap-introspection" || !dedicated.ClientSecret.IsZero() {
		t.Fatalf("dedicated policy client = %q method = %q", dedicated.ClientID, dedicated.AuthMethod)
	}

	if dedicated.Issuer != authority.Issuer {
		t.Fatal("dedicated client must keep the authority endpoint")
	}
}

// TestJMAPIntrospectionClientValidation rejects incomplete dedicated clients.
func TestJMAPIntrospectionClientValidation(t *testing.T) {
	for name, testCase := range map[string]struct {
		client JMAPIntrospectionClientConfig
		want   string
	}{
		"secret method without file": {
			client: JMAPIntrospectionClientConfig{ClientID: "jmap"},
			want:   "introspection_client must configure exactly one of client_secret or client_secret_file",
		},
		"private key without file": {
			client: JMAPIntrospectionClientConfig{ClientID: "jmap", AuthMethod: "private_key_jwt"},
			want:   "introspection_client.client_private_key_file is required",
		},
		"credentials without client id": {
			client: JMAPIntrospectionClientConfig{ClientSecretFile: Secret("/run/secrets/x")},
			want:   "introspection_client.client_id is required when client credentials are set",
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := updateJMAPListener(jmapTestConfig(), func(entry *ListenerConfig) {
				entry.JMAP.Auth.Bearer = JMAPBearerAuthConfig{
					Enabled:             true,
					RequiredResource:    "https://mail.example.org/",
					RequiredScope:       "mail",
					IntrospectionClient: testCase.client,
				}
			})
			expectValidationError(t, cfg.Normalize(), testCase.want)
		})
	}
}

// TestJMAPIntrospectionClientCheckMaterial reports unreadable files without their path.
func TestJMAPIntrospectionClientCheckMaterial(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing-secret")
	err := JMAPIntrospectionClientConfig{ClientID: "jmap", AuthMethod: "client_secret_basic", ClientSecretFile: Secret(missing)}.CheckMaterial()
	if err == nil || strings.Contains(err.Error(), missing) {
		t.Fatalf("CheckMaterial error = %v, want a path-free failure", err)
	}

	present := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(present, []byte("value\n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	if err := (JMAPIntrospectionClientConfig{ClientID: "jmap", AuthMethod: "client_secret_basic", ClientSecretFile: Secret(present)}).CheckMaterial(); err != nil {
		t.Fatalf("CheckMaterial returned error: %v", err)
	}

	if err := (JMAPIntrospectionClientConfig{}).CheckMaterial(); err != nil {
		t.Fatalf("inherited client check returned error: %v", err)
	}
}

// TestProxyProtocolAcceptLocalRequiresEnabled keeps LOCAL acceptance tied to trusted PROXY handling.
func TestProxyProtocolAcceptLocalRequiresEnabled(t *testing.T) {
	cfg := updateJMAPListener(jmapTestConfig(), func(entry *ListenerConfig) {
		entry.ProxyProtocol = ProxyProtocolConfig{AcceptLocal: true}
	})

	expectValidationError(t, cfg, "director.listeners.jmap.proxy_protocol.accept_local requires proxy_protocol.enabled")
}
