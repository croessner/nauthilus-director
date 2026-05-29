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

//nolint:funlen,goconst,wsl_v5 // Tests keep config fixtures local for readability.
package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestNewLoaderCreatesIsolatedLoader protects the loader boundary from shared global state.
func TestNewLoaderCreatesIsolatedLoader(t *testing.T) {
	loader := NewLoader()
	if loader == nil {
		t.Fatal("NewLoader returned nil")
	}
	if loader.viper == nil {
		t.Fatal("NewLoader did not initialize viper")
	}
	if loader.validate == nil {
		t.Fatal("NewLoader did not initialize validator")
	}
}

// TestDefaultsValidate ensures canonical defaults are usable without a file.
func TestDefaultsValidate(t *testing.T) {
	loader := NewLoader()
	if err := loader.Validate(DefaultConfig()); err != nil {
		t.Fatalf("default config did not validate: %v", err)
	}
}

// TestTargetConfigDecodesAndValidates keeps typed structs aligned with the documented target YAML.
func TestTargetConfigDecodesAndValidates(t *testing.T) {
	loader := NewLoader()
	snapshot, err := loader.LoadFile(filepath.Join("..", "..", "docs", "config", "nauthilus-director.target.yml"))
	if err != nil {
		t.Fatalf("load target config: %v", err)
	}
	if snapshot.Config.Storage.Redis.Mode != "standalone" {
		t.Fatalf("redis mode = %q, want standalone", snapshot.Config.Storage.Redis.Mode)
	}
	if _, ok := snapshot.Config.Director.Listeners["imap"]; !ok {
		t.Fatal("target config did not decode director.listeners.imap")
	}
	if snapshot.Config.Director.Routing.AuthAttributes.Tenant != "tenant" {
		t.Fatalf("routing auth tenant attribute = %q, want tenant", snapshot.Config.Director.Routing.AuthAttributes.Tenant)
	}
	if snapshot.Config.Director.Routing.AuthAttributes.ShardTag != "mailShard" {
		t.Fatalf("routing auth shard attribute = %q, want mailShard", snapshot.Config.Director.Routing.AuthAttributes.ShardTag)
	}
}

// TestDemoStackConfigDecodesAndValidates keeps the public demo aligned with typed config.
func TestDemoStackConfigDecodesAndValidates(t *testing.T) {
	t.Setenv("DIRECTOR_INSTANCE_NAME", "demo-director-test")

	snapshot, err := NewLoader().LoadFile(filepath.Join("..", "..", "contrib", "demo-stack", "director", "nauthilus-director.yml"))
	if err != nil {
		t.Fatalf("load demo stack config: %v", err)
	}

	if snapshot.Config.Runtime.InstanceName != "demo-director-test" {
		t.Fatalf("runtime.instance_name = %q, want env-expanded demo instance", snapshot.Config.Runtime.InstanceName)
	}

	if snapshot.Config.Storage.Redis.SchemaVersion != 1 {
		t.Fatalf("demo redis schema version = %d, want 1", snapshot.Config.Storage.Redis.SchemaVersion)
	}
}

// TestDevelopmentRuntimeStateResetGuidanceDocumented keeps dev reset behavior explicit.
func TestDevelopmentRuntimeStateResetGuidanceDocumented(t *testing.T) {
	readme := readTextFile(t, filepath.Join("..", "..", "contrib", "demo-stack", "README.md"))
	manpage := readTextFile(t, filepath.Join("..", "..", "docs", "man", "nauthilus-director.yaml.5"))

	for _, want := range []string{
		"Redis schema version `1`",
		"let the short-lived session and reservation leases expire",
		"docker compose exec valkey valkey-cli FLUSHDB",
		"Do not use these reset commands against a Redis database that carries active production sessions.",
	} {
		if !strings.Contains(readme, want) {
			t.Fatalf("demo README missing reset guidance %q", want)
		}
	}

	for _, want := range []string{
		"default schema\nversion remains\n.BR 1",
		"Clearing old runtime keys is an operator action for demo and non-production\nenvironments only.",
		"Do not silently delete active production sessions",
	} {
		if !strings.Contains(manpage, want) {
			t.Fatalf("yaml manpage missing reset guidance %q", want)
		}
	}
}

// TestRuntimeStateDefaultsValidate verifies scale-related defaults are typed and accepted.
func TestRuntimeStateDefaultsValidate(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Storage.Redis.SchemaVersion != 1 {
		t.Fatalf("default redis schema version = %d, want 1", cfg.Storage.Redis.SchemaVersion)
	}

	if cfg.Runtime.State.Indexes.SessionShards != 64 {
		t.Fatalf("session shards = %d, want 64", cfg.Runtime.State.Indexes.SessionShards)
	}

	if cfg.Runtime.State.Indexes.PageDefault != 100 || cfg.Runtime.State.Indexes.PageMax != 1000 {
		t.Fatalf("runtime page bounds = %d/%d, want 100/1000", cfg.Runtime.State.Indexes.PageDefault, cfg.Runtime.State.Indexes.PageMax)
	}

	if cfg.Runtime.State.BackendReservations.TTL != NewDuration(30*time.Minute) {
		t.Fatalf("backend reservation ttl = %s, want 30m0s", cfg.Runtime.State.BackendReservations.TTL.String())
	}

	if err := NewLoader().Validate(cfg); err != nil {
		t.Fatalf("Validate rejected runtime-state defaults: %v", err)
	}
}

// TestRuntimeStateValidationRejectsInvalidShardCounts keeps index fanout bounded.
func TestRuntimeStateValidationRejectsInvalidShardCounts(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"session": func(cfg *Config) { cfg.Runtime.State.Indexes.SessionShards = 0 },
		"user":    func(cfg *Config) { cfg.Runtime.State.Indexes.UserShards = 0 },
		"backend": func(cfg *Config) { cfg.Runtime.State.Indexes.BackendShards = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := DefaultConfig()
			mutate(&cfg)

			expectValidationError(t, cfg, "runtime.state.indexes."+name+"_shards")
		})
	}
}

// TestRuntimeStateValidationRejectsInvalidPageBounds keeps control reads bounded.
func TestRuntimeStateValidationRejectsInvalidPageBounds(t *testing.T) {
	for name, item := range map[string]struct {
		mutate func(*Config)
		want   string
	}{
		"default_zero": {
			mutate: func(cfg *Config) { cfg.Runtime.State.Indexes.PageDefault = 0 },
			want:   "runtime.state.indexes.page_default",
		},
		"max_zero": {
			mutate: func(cfg *Config) { cfg.Runtime.State.Indexes.PageMax = 0 },
			want:   "runtime.state.indexes.page_max",
		},
		"default_above_max": {
			mutate: func(cfg *Config) {
				cfg.Runtime.State.Indexes.PageDefault = 2000
				cfg.Runtime.State.Indexes.PageMax = 1000
			},
			want: "runtime.state.indexes.page_default must not exceed runtime.state.indexes.page_max",
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := DefaultConfig()
			item.mutate(&cfg)

			expectValidationError(t, cfg, item.want)
		})
	}
}

// TestRuntimeStateValidationRejectsInvalidReaperSettings keeps repair loops finite.
func TestRuntimeStateValidationRejectsInvalidReaperSettings(t *testing.T) {
	for name, item := range map[string]struct {
		mutate func(*Config)
		want   string
	}{
		"interval": {
			mutate: func(cfg *Config) { cfg.Runtime.State.Reaper.Interval = 0 },
			want:   "runtime.state.reaper.interval",
		},
		"batch_size": {
			mutate: func(cfg *Config) { cfg.Runtime.State.Reaper.BatchSize = 0 },
			want:   "runtime.state.reaper.batch_size",
		},
		"max_pass_duration": {
			mutate: func(cfg *Config) { cfg.Runtime.State.Reaper.MaxPassDuration = 0 },
			want:   "runtime.state.reaper.max_pass_duration",
		},
		"jitter": {
			mutate: func(cfg *Config) { cfg.Runtime.State.Reaper.Jitter = NewDuration(-time.Second) },
			want:   "runtime.state.reaper.jitter",
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := DefaultConfig()
			item.mutate(&cfg)

			expectValidationError(t, cfg, item.want)
		})
	}
}

// TestRuntimeStateValidationRejectsInvalidReservationSettings keeps reservation repair explicit.
func TestRuntimeStateValidationRejectsInvalidReservationSettings(t *testing.T) {
	for name, item := range map[string]struct {
		mutate func(*Config)
		want   string
	}{
		"ttl": {
			mutate: func(cfg *Config) { cfg.Runtime.State.BackendReservations.TTL = 0 },
			want:   "runtime.state.backend_reservations.ttl",
		},
		"repair_interval": {
			mutate: func(cfg *Config) { cfg.Runtime.State.BackendReservations.RepairInterval = 0 },
			want:   "runtime.state.backend_reservations.repair_interval",
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := DefaultConfig()
			item.mutate(&cfg)

			expectValidationError(t, cfg, item.want)
		})
	}
}

// TestRoutingAuthAttributeDefaults verifies tenant and shard attribute names have stable defaults.
func TestRoutingAuthAttributeDefaults(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Director.Routing.AuthAttributes.Tenant != "tenant" {
		t.Fatalf("default tenant attribute = %q, want tenant", cfg.Director.Routing.AuthAttributes.Tenant)
	}

	if cfg.Director.Routing.AuthAttributes.ShardTag != "mailShard" {
		t.Fatalf("default shard tag attribute = %q, want mailShard", cfg.Director.Routing.AuthAttributes.ShardTag)
	}
}

// TestObservabilityValidationRejectsUnknownTracingExporter keeps startup fail-closed.
func TestObservabilityValidationRejectsUnknownTracingExporter(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Observability.Tracing.Exporter = "zipkin"

	err := NewLoader().Validate(cfg)
	if err == nil {
		t.Fatal("Validate accepted an unknown tracing exporter")
	}

	if !strings.Contains(err.Error(), "observability.tracing.exporter") {
		t.Fatalf("error = %q, want tracing exporter validation", err.Error())
	}
}

// TestObservabilityValidationRejectsInvalidSampleRatio keeps sampler config bounded.
func TestObservabilityValidationRejectsInvalidSampleRatio(t *testing.T) {
	for name, ratio := range map[string]float64{
		"below": -0.01,
		"above": 1.01,
	} {
		t.Run(name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Observability.Tracing.SampleRatio = ratio

			err := NewLoader().Validate(cfg)
			if err == nil {
				t.Fatal("Validate accepted an invalid tracing sample ratio")
			}

			if !strings.Contains(err.Error(), "observability.tracing.sample_ratio") {
				t.Fatalf("error = %q, want sample ratio validation", err.Error())
			}
		})
	}
}

// TestObservabilityValidationRejectsUnsupportedMetricsPath prevents ignored routes.
func TestObservabilityValidationRejectsUnsupportedMetricsPath(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Observability.Metrics.Path = "/custom-metrics"

	err := NewLoader().Validate(cfg)
	if err == nil {
		t.Fatal("Validate accepted a non-/metrics path")
	}

	if !strings.Contains(err.Error(), "observability.metrics.path") {
		t.Fatalf("error = %q, want metrics path validation", err.Error())
	}
}

// TestGRPCCallerAuthValidationRejectsAmbiguousMethods verifies caller auth is fail-closed.
func TestGRPCCallerAuthValidationRejectsAmbiguousMethods(t *testing.T) {
	cfg := DefaultConfig()
	authority := cfg.Auth.Authorities["default"]
	authority.Transport = "grpc"
	authority.GRPC.CallerAuth.Bearer.Enabled = true
	authority.GRPC.CallerAuth.Bearer.TokenFile = Secret("bearer-token")
	cfg.Auth.Authorities["default"] = authority

	expectValidationError(t, cfg, "auth.authorities.default.grpc.caller_auth must enable only one caller auth method")
}

// TestGRPCCallerAuthValidationRequiresBasicUsername verifies basic caller auth is complete.
func TestGRPCCallerAuthValidationRequiresBasicUsername(t *testing.T) {
	cfg := DefaultConfig()
	authority := cfg.Auth.Authorities["default"]
	authority.Transport = "grpc"
	authority.GRPC.CallerAuth.Basic.Username = ""
	cfg.Auth.Authorities["default"] = authority

	expectValidationError(
		t,
		cfg,
		"auth.authorities.default.grpc.caller_auth.basic.username is required when basic caller auth is enabled",
	)
}

// TestUnknownFieldsAreRejected verifies strict decode behavior for typo safety.
func TestUnknownFieldsAreRejected(t *testing.T) {
	path := writeConfigFile(t, t.TempDir(), "unknown.yaml", `runtime:
  unexpected_field: true
`)

	_, err := NewLoader().LoadFile(path)
	if err == nil {
		t.Fatal("LoadFile returned nil error for unknown field")
	}
	if !strings.Contains(err.Error(), "unexpected_field") {
		t.Fatalf("error = %q, want unknown field name", err.Error())
	}
}

// TestLMTPConfigRejectsObsoleteSMTPUTF8Flag keeps SMTPUTF8 policy owned by capabilities.
func TestLMTPConfigRejectsObsoleteSMTPUTF8Flag(t *testing.T) {
	path := writeConfigFile(t, t.TempDir(), "obsolete-lmtp.yaml", `director:
  listeners:
    lmtp:
      lmtp:
        smtputf8: false
`)

	_, err := NewLoader().LoadFile(path)
	if err == nil {
		t.Fatal("LoadFile returned nil error for obsolete smtputf8 field")
	}
	if !strings.Contains(err.Error(), "smtputf8") {
		t.Fatalf("error = %q, want obsolete field name", err.Error())
	}
}

// TestIncludesEnvPatchesExpansionAndLoaderKeys covers the loader ordering contract.
func TestIncludesEnvPatchesExpansionAndLoaderKeys(t *testing.T) {
	t.Setenv("DIRECTOR_TEST_INSTANCE", "patched-instance")
	t.Setenv("DIRECTOR_TEST_LITERAL", "not-used")

	root := t.TempDir()
	writeConfigFile(t, root, "base.yaml", `runtime:
  instance_name: included
auth:
  authorities:
    default:
      http:
        content_type: "$5"
`)
	writeConfigFile(t, root, "dev.yaml", `runtime:
  timeouts:
    auth: 11s
patch:
  - op: add
    path: director.listeners.imap.imap.capabilities
    value: STARTTLS
`)
	mainPath := writeConfigFile(t, root, "main.yaml", `env: dev
includes:
  required:
    - base.yaml
  optional:
    - missing-optional.yaml
  env:
    dev:
      required:
        - dev.yaml
patch:
  - op: replace
    path: runtime.instance_name
    value: "${DIRECTOR_TEST_INSTANCE}"
  - op: remove
    path: director.listeners.imap.imap.auth_mechanisms
    value: oauthbearer
  - op: remove
    path: director.listeners.imap.imap.capabilities
    value: AUTH=OAUTHBEARER
  - op: replace
    path: observability.tracing.endpoint
    value: "literal-$${DIRECTOR_TEST_LITERAL}"
`)

	snapshot, err := NewLoader().LoadFile(mainPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if got := snapshot.Config.Runtime.InstanceName; got != "patched-instance" {
		t.Fatalf("instance_name = %q, want patched-instance", got)
	}
	if got := snapshot.Config.Runtime.Timeouts.Auth.String(); got != "11s" {
		t.Fatalf("runtime.timeouts.auth = %q, want 11s", got)
	}
	if got := snapshot.Config.Auth.Authorities["default"].HTTP.ContentType; got != "$5" {
		t.Fatalf("ordinary dollar value = %q, want $5", got)
	}
	if got := snapshot.Config.Observability.Tracing.Endpoint; got != "literal-${DIRECTOR_TEST_LITERAL}" {
		t.Fatalf("escaped placeholder = %q", got)
	}

	capabilities := snapshot.Config.Director.Listeners["imap"].IMAP.Capabilities
	if !containsString(capabilities, "STARTTLS") {
		t.Fatalf("capabilities = %v, want STARTTLS added", capabilities)
	}
	mechanisms := snapshot.Config.Director.Listeners["imap"].IMAP.AuthMechanisms
	if containsString(mechanisms, "oauthbearer") {
		t.Fatalf("auth_mechanisms = %v, want oauthbearer removed", mechanisms)
	}

	dump, err := snapshot.DumpNonDefault(DumpOptions{Format: "yaml"})
	if err != nil {
		t.Fatalf("dump non-default: %v", err)
	}
	text := string(dump)
	for _, loaderKey := range []string{"includes:", "patch:", "env:"} {
		if strings.Contains(text, loaderKey) {
			t.Fatalf("non-default dump contains loader key %q:\n%s", loaderKey, text)
		}
	}
}

// TestIMAPValidationRejectsUnsupportedEnableCapability keeps CAPABILITY output truthful.
func TestIMAPValidationRejectsUnsupportedEnableCapability(t *testing.T) {
	cfg := DefaultConfig()
	entry := cfg.Director.Listeners["imap"]
	entry.IMAP.Capabilities = append(entry.IMAP.Capabilities, "ENABLE")
	cfg.Director.Listeners["imap"] = entry

	expectValidationError(t, cfg, "must not advertise unsupported ENABLE")
}

// TestIMAPValidationRejectsFalseCapabilityAdvertisements keeps IMAP capabilities policy-backed.
func TestIMAPValidationRejectsFalseCapabilityAdvertisements(t *testing.T) {
	t.Run("starttls on implicit listener", func(t *testing.T) {
		cfg := DefaultConfig()
		entry := cfg.Director.Listeners["imaps"]
		entry.IMAP.Capabilities = append(entry.IMAP.Capabilities, "STARTTLS")
		cfg.Director.Listeners["imaps"] = entry

		expectValidationError(t, cfg, "STARTTLS for non-starttls listener TLS mode")
	})

	t.Run("auth mechanism not enabled", func(t *testing.T) {
		cfg := DefaultConfig()
		entry := cfg.Director.Listeners["imap"]
		entry.IMAP.AuthMechanisms = []string{"plain"}
		cfg.Director.Listeners["imap"] = entry

		expectValidationError(t, cfg, "AUTH mechanism not enabled in auth_mechanisms XOAUTH2")
	})
}

// TestLMTPValidationRejectsMissingProtocolConfig keeps LMTP listener config typed and explicit.
func TestLMTPValidationRejectsMissingProtocolConfig(t *testing.T) {
	cfg := DefaultConfig()
	entry := cfg.Director.Listeners["lmtp"]
	entry.LMTP = nil
	cfg.Director.Listeners["lmtp"] = entry

	expectValidationError(t, cfg, "director.listeners.lmtp.lmtp is required")
}

// TestListenerValidationRejectsUnsupportedProtocol keeps unknown listener protocols fail-closed.
func TestListenerValidationRejectsUnsupportedProtocol(t *testing.T) {
	cfg := DefaultConfig()
	entry := cfg.Director.Listeners["lmtp"]
	entry.Protocol = "pop3"
	cfg.Director.Listeners["lmtp"] = entry

	expectValidationError(t, cfg, "director.listeners.lmtp.protocol must be imap or lmtp")
}

// TestLMTPCapabilitiesNormalizeStableWireForms protects deterministic LHLO inputs.
func TestLMTPCapabilitiesNormalizeStableWireForms(t *testing.T) {
	cfg := DefaultConfig()
	entry := cfg.Director.Listeners["lmtp"]
	entry.LMTP.Capabilities = []string{" smtpUtf8 ", " auth   plain  xoauth2 ", "starttls", "AUTH PLAIN XOAUTH2"}
	cfg.Director.Listeners["lmtp"] = entry

	normalized := cfg.Normalize()
	got := normalized.Director.Listeners["lmtp"].LMTP.Capabilities
	want := []string{"SMTPUTF8", "AUTH PLAIN XOAUTH2", "STARTTLS"}

	if !slices.Equal(got, want) {
		t.Fatalf("LMTP capabilities = %v, want %v", got, want)
	}
}

// TestLMTPValidationRejectsUnsupportedCapabilities keeps desired listener surface bounded.
func TestLMTPValidationRejectsUnsupportedCapabilities(t *testing.T) {
	cfg := DefaultConfig()
	entry := cfg.Director.Listeners["lmtp"]
	entry.LMTP.Capabilities = append(entry.LMTP.Capabilities, "PIPELINING")
	cfg.Director.Listeners["lmtp"] = entry

	expectValidationError(t, cfg, "contains unsupported capability PIPELINING")
}

// TestLMTPValidationAcceptsConfiguredChunking verifies validation allows mediated BDAT support.
func TestLMTPValidationAcceptsConfiguredChunking(t *testing.T) {
	cfg := DefaultConfig()
	entry := cfg.Director.Listeners["lmtp"]
	entry.LMTP.Capabilities = append(entry.LMTP.Capabilities, "CHUNKING")
	cfg.Director.Listeners["lmtp"] = entry

	if err := NewLoader().Validate(cfg); err != nil {
		t.Fatalf("Validate returned error for configured CHUNKING: %v", err)
	}
}

// TestLMTPStartTLSCapabilityMatchesListenerTLSMode rejects implicit TLS STARTTLS advertisement.
func TestLMTPStartTLSCapabilityMatchesListenerTLSMode(t *testing.T) {
	cfg := DefaultConfig()
	entry := cfg.Director.Listeners["lmtps"]
	entry.LMTP.Capabilities = append(entry.LMTP.Capabilities, "STARTTLS")
	cfg.Director.Listeners["lmtps"] = entry

	expectValidationError(t, cfg, "STARTTLS for non-starttls listener TLS mode")
}

// TestLMTPMTLSPeerAuthRequiresVerifiedClientCertificates prevents unauthenticated mTLS shortcuts.
func TestLMTPMTLSPeerAuthRequiresVerifiedClientCertificates(t *testing.T) {
	cfg := DefaultConfig()
	entry := cfg.Director.Listeners["lmtp"]
	entry.LMTP.ClientAuth.MTLS.SatisfiesRequired = true
	entry.LMTP.ClientAuth.MTLS.IdentitySource = "subject_common_name"
	entry.TLS.RequireClientCert = true
	entry.TLS.ClientCA = ""
	cfg.Director.Listeners["lmtp"] = entry

	expectValidationError(t, cfg, "requires listener TLS to require and verify client certificates")
}

// TestLMTPMTLSPeerAuthRejectsUnsupportedIdentitySource keeps certificate identity mapping bounded.
func TestLMTPMTLSPeerAuthRejectsUnsupportedIdentitySource(t *testing.T) {
	cfg := DefaultConfig()
	entry := cfg.Director.Listeners["lmtp"]
	entry.LMTP.ClientAuth.MTLS.IdentitySource = "serial_number"
	cfg.Director.Listeners["lmtp"] = entry

	expectValidationError(t, cfg, "identity_source contains unsupported source serial_number")
}

// TestLMTPPoolValidationRejectsCrossProtocolBackends keeps LMTP pools internally typed.
func TestLMTPPoolValidationRejectsCrossProtocolBackends(t *testing.T) {
	cfg := DefaultConfig()
	pool := cfg.Director.BackendPools["lmtp-default"]
	pool.Backends = []string{"mailstore-a-imap"}
	cfg.Director.BackendPools["lmtp-default"] = pool

	expectValidationError(t, cfg, "backends references backend with different protocol mailstore-a-imap")
}

// TestLMTPBackendAuthValidationRejectsIncompleteSASLAndOAuth checks service credential completeness.
func TestLMTPBackendAuthValidationRejectsIncompleteSASLAndOAuth(t *testing.T) {
	t.Run("sasl", func(t *testing.T) {
		cfg := DefaultConfig()
		backend := cfg.Director.Backends["mailstore-a-lmtp"]
		backend.Auth.SASL.Username = ""
		cfg.Director.Backends["mailstore-a-lmtp"] = backend

		expectValidationError(t, cfg, "auth.sasl.username is required in sasl mode")
	})

	t.Run("oauthbearer", func(t *testing.T) {
		cfg := DefaultConfig()
		backend := cfg.Director.Backends["mailstore-a-lmtp"]
		backend.Auth.Mode = "oauthbearer"
		backend.Auth.OAuthBearer.TokenFile = Secret("")
		cfg.Director.Backends["mailstore-a-lmtp"] = backend

		expectValidationError(t, cfg, "auth.oauthbearer.token_file is required in oauthbearer mode")
	})
}

// TestConfigDumpRedactsLMTPProtectedValuesByDefault preserves protected metadata for LMTP paths.
func TestConfigDumpRedactsLMTPProtectedValuesByDefault(t *testing.T) {
	dump, err := NewLoader().DumpDefaults(DumpOptions{Format: "yaml"})
	if err != nil {
		t.Fatalf("DumpDefaults: %v", err)
	}

	text := string(dump)
	for _, secret := range []string{
		"/etc/nauthilus-director/lmtp.key",
		"/etc/nauthilus-director/lmtps.key",
		"/etc/nauthilus-director/lmtp-backend-client.key",
		"/etc/nauthilus-director/lmtp-backend-password",
		"/etc/nauthilus-director/lmtp-backend-token",
	} {
		if strings.Contains(text, secret) {
			t.Fatalf("default dump leaked protected LMTP value %q:\n%s", secret, text)
		}
	}
}

// TestBackendWeightZeroValidatesForStaticMaintenance allows selector-level initial placement exclusion.
func TestBackendWeightZeroValidatesForStaticMaintenance(t *testing.T) {
	cfg := DefaultConfig()
	backend := cfg.Director.Backends["mailstore-a-imap"]
	backend.Weight = 0
	cfg.Director.Backends["mailstore-a-imap"] = backend

	if err := NewLoader().Validate(cfg); err != nil {
		t.Fatalf("Validate rejected weight zero backend: %v", err)
	}
}

// TestBackendValidationRejectsUnixSocketAddress keeps IMAP backend connectivity TCP-only.
func TestBackendValidationRejectsUnixSocketAddress(t *testing.T) {
	cfg := DefaultConfig()
	backend := cfg.Director.Backends["mailstore-a-imap"]
	backend.Address = "/run/imap/backend.sock"
	cfg.Director.Backends["mailstore-a-imap"] = backend

	err := NewLoader().Validate(cfg)
	if err == nil {
		t.Fatal("Validate accepted Unix socket backend address")
	}
	if !strings.Contains(err.Error(), "Unix socket backend addresses are not supported for IMAP backend connectivity") {
		t.Fatalf("error = %q, want Unix socket rejection", err.Error())
	}
}

// TestIMAPBackendValidationRejectsSilentAuthSkip keeps backend auth explicit for IMAP.
func TestIMAPBackendValidationRejectsSilentAuthSkip(t *testing.T) {
	cfg := DefaultConfig()
	backend := cfg.Director.Backends["mailstore-a-imap"]
	backend.Auth.Mode = "none"
	cfg.Director.Backends["mailstore-a-imap"] = backend

	err := NewLoader().Validate(cfg)
	if err == nil {
		t.Fatal("Validate accepted IMAP backend auth mode none")
	}
	if !strings.Contains(err.Error(), "for IMAP backends must be master_user or credential_replay") {
		t.Fatalf("error = %q, want IMAP backend auth mode rejection", err.Error())
	}
}

// TestBackendValidationRejectsInvalidReplayMechanism protects runtime replay allowlists.
func TestBackendValidationRejectsInvalidReplayMechanism(t *testing.T) {
	cfg := DefaultConfig()
	backend := cfg.Director.Backends["mailstore-a-imap"]
	backend.Auth.Mode = "credential_replay"
	backend.Auth.CredentialReplay.AllowedMechanisms = []string{"plain", "xoauth2", "oauthbearer", "external"}
	cfg.Director.Backends["mailstore-a-imap"] = backend

	err := NewLoader().Validate(cfg)
	if err == nil {
		t.Fatal("Validate accepted invalid replay mechanism")
	}
	if !strings.Contains(err.Error(), "allowed_mechanisms contains unsupported mechanism external") {
		t.Fatalf("error = %q, want replay mechanism rejection", err.Error())
	}
}

// TestIncludeCycleDetected prevents recursive include loops from hanging startup.
func TestIncludeCycleDetected(t *testing.T) {
	root := t.TempDir()
	aPath := writeConfigFile(t, root, "a.yaml", `includes:
  required:
    - b.yaml
`)
	writeConfigFile(t, root, "b.yaml", `includes:
  required:
    - a.yaml
`)

	_, err := NewLoader().LoadFile(aPath)
	if err == nil {
		t.Fatal("LoadFile returned nil error for include cycle")
	}
	if !strings.Contains(err.Error(), "include cycle detected") {
		t.Fatalf("error = %q, want include cycle", err.Error())
	}
}

// TestRequiredIncludeMissingFails keeps required include errors fail-closed.
func TestRequiredIncludeMissingFails(t *testing.T) {
	path := writeConfigFile(t, t.TempDir(), "main.yaml", `includes:
  required:
    - missing.yaml
`)

	_, err := NewLoader().LoadFile(path)
	if err == nil {
		t.Fatal("LoadFile returned nil error for missing required include")
	}
	if !strings.Contains(err.Error(), "missing.yaml") {
		t.Fatalf("error = %q, want missing include path", err.Error())
	}
}

// TestPatchEngineSemanticsAndInvalidInputs locks the Nauthilus-compatible dot-path rules.
func TestPatchEngineSemanticsAndInvalidInputs(t *testing.T) {
	settings := map[string]any{
		"root": map[string]any{
			"list": []any{"a", "b"},
			"map":  map[string]any{"old": "value", "drop": true},
		},
	}
	patches := []PatchOperation{
		{Op: patchOpAdd, Path: "root.list", Value: "c"},
		{Op: patchOpAdd, Path: "root.map", Value: map[string]any{"new": "value"}},
		{Op: patchOpAdd, Path: "root.created", Value: "first"},
		{Op: patchOpReplace, Path: "root.replaced.value", Value: "ok"},
		{Op: patchOpRemove, Path: "root.list", Value: "b"},
		{Op: patchOpRemove, Path: "root.map", Value: []any{"drop"}},
	}
	if err := (DefaultPatchEngine{}).Apply(settings, patches); err != nil {
		t.Fatalf("apply patches: %v", err)
	}

	root := settings["root"].(map[string]any)
	if got := root["list"].([]any); len(got) != 2 || got[0] != "a" || got[1] != "c" {
		t.Fatalf("root.list = %v, want [a c]", got)
	}
	if got := root["created"].([]any); len(got) != 1 || got[0] != "first" {
		t.Fatalf("root.created = %v, want [first]", got)
	}
	if _, ok := root["map"].(map[string]any)["drop"]; ok {
		t.Fatal("root.map.drop was not removed")
	}
	if got := root["replaced"].(map[string]any)["value"]; got != "ok" {
		t.Fatalf("root.replaced.value = %v, want ok", got)
	}

	invalid := []PatchOperation{
		{Op: "copy", Path: "root.list", Value: "x"},
		{Op: patchOpAdd, Path: "root..list", Value: "x"},
		{Op: patchOpRemove, Path: "root.missing", Value: "x"},
		{Op: patchOpRemove, Path: "root.map", Value: []any{7}},
	}
	for _, patch := range invalid {
		t.Run(patch.Op+"_"+patch.Path, func(t *testing.T) {
			copySettings := map[string]any{
				"root": map[string]any{
					"list": []any{"a"},
					"map":  map[string]any{"a": "b"},
				},
			}
			if err := (DefaultPatchEngine{}).Apply(copySettings, []PatchOperation{patch}); err == nil {
				t.Fatalf("Apply(%+v) error = nil, want failure", patch)
			}
		})
	}
}

// TestExpansionMapKeysAndSafeMissingErrors checks scalar-only expansion and secret-safe errors.
func TestExpansionMapKeysAndSafeMissingErrors(t *testing.T) {
	t.Setenv("DIRECTOR_PRESENT_SECRET", "do-not-leak")
	t.Setenv("DIRECTOR_DYNAMIC_KEY", "expanded_key")
	t.Setenv("DIRECTOR_DYNAMIC_VALUE", "expanded_value")

	settings := map[string]any{
		"runtime": map[string]any{
			"${DIRECTOR_DYNAMIC_KEY}": "${DIRECTOR_DYNAMIC_VALUE}",
		},
	}
	if err := NewConfigValueExpander(nil).Expand(settings); err != nil {
		t.Fatalf("expand settings: %v", err)
	}
	runtimeSettings := settings["runtime"].(map[string]any)
	if _, ok := runtimeSettings["expanded_key"]; ok {
		t.Fatal("map key was expanded")
	}
	if got := runtimeSettings["${DIRECTOR_DYNAMIC_KEY}"]; got != "expanded_value" {
		t.Fatalf("dynamic key value = %v, want expanded_value", got)
	}

	path := writeConfigFile(t, t.TempDir(), "missing-env.yaml", `runtime:
  instance_name: "prefix-${DIRECTOR_PRESENT_SECRET}-${DIRECTOR_MISSING_SECRET}"
`)
	_, err := NewLoader().LoadFile(path)
	if err == nil {
		t.Fatal("LoadFile returned nil error for missing placeholder")
	}
	errText := err.Error()
	if !strings.Contains(errText, "runtime.instance_name") || !strings.Contains(errText, "DIRECTOR_MISSING_SECRET") {
		t.Fatalf("error = %q, want path and variable name", errText)
	}
	if strings.Contains(errText, "do-not-leak") || strings.Contains(errText, "prefix-") {
		t.Fatalf("error leaked raw or expanded value: %q", errText)
	}
}

// TestRedactionAndProtectedDump verifies that -P is the only path to protected dump values.
func TestRedactionAndProtectedDump(t *testing.T) {
	t.Setenv("DIRECTOR_REDIS_PASSWORD_FILE", "/run/secrets/redis-password")
	path := writeConfigFile(t, t.TempDir(), "secret.yaml", `storage:
  redis:
    auth:
      password_file: "${DIRECTOR_REDIS_PASSWORD_FILE}"
`)
	snapshot, err := NewLoader().LoadFile(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	redacted, err := snapshot.DumpNonDefault(DumpOptions{Format: "yaml"})
	if err != nil {
		t.Fatalf("redacted dump: %v", err)
	}
	if strings.Contains(string(redacted), "/run/secrets/redis-password") {
		t.Fatalf("redacted dump leaked secret path:\n%s", redacted)
	}
	if !strings.Contains(string(redacted), redactedSecret) {
		t.Fatalf("redacted dump does not contain redaction marker:\n%s", redacted)
	}

	protected, err := snapshot.DumpNonDefault(DumpOptions{Format: "yaml", IncludeProtected: true})
	if err != nil {
		t.Fatalf("protected dump: %v", err)
	}
	if !strings.Contains(string(protected), "/run/secrets/redis-password") {
		t.Fatalf("protected dump did not include secret path:\n%s", protected)
	}
	if snapshot.Config.Storage.Redis.Auth.PasswordFile.String() != redactedSecret {
		t.Fatal("SecretString.String did not remain redacted outside config dump")
	}
}

// TestRedisValidationModes exercises standalone, Sentinel and Cluster topology validation.
func TestRedisValidationModes(t *testing.T) {
	loader := NewLoader()

	sentinel := DefaultConfig()
	sentinel.Storage.Redis.Mode = "sentinel"
	sentinel.Storage.Redis.Sentinel.MasterName = "mymaster"
	sentinel.Storage.Redis.Sentinel.Addresses = []string{"127.0.0.1:26379"}
	if err := loader.Validate(sentinel); err != nil {
		t.Fatalf("sentinel redis config did not validate: %v", err)
	}

	cluster := DefaultConfig()
	cluster.Storage.Redis.Mode = "cluster"
	cluster.Storage.Redis.Cluster.Addresses = []string{"127.0.0.1:6379", "127.0.0.1:6380"}
	if err := loader.Validate(cluster); err != nil {
		t.Fatalf("cluster redis config did not validate: %v", err)
	}

	invalid := DefaultConfig()
	invalid.Storage.Redis.Mode = "sentinel"
	invalid.Storage.Redis.Sentinel.MasterName = ""
	invalid.Storage.Redis.Sentinel.Addresses = nil
	err := loader.Validate(invalid)
	if err == nil {
		t.Fatal("invalid sentinel redis config validated")
	}
	if !strings.Contains(err.Error(), "storage.redis.sentinel.master_name") {
		t.Fatalf("error = %q, want sentinel master validation", err.Error())
	}
}

// writeConfigFile creates a mode-restricted fixture file under a test temp directory.
func writeConfigFile(t *testing.T, root string, name string, content string) string {
	t.Helper()

	path := filepath.Join(root, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config %s: %v", name, err)
	}

	return path
}

// readTextFile loads a repository fixture as text for documentation guard tests.
func readTextFile(t *testing.T, path string) string {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	return string(data)
}

// expectValidationError verifies typed config validation fails with a useful diagnostic.
func expectValidationError(t *testing.T, cfg Config, want string) {
	t.Helper()

	err := NewLoader().Validate(cfg)
	if err == nil {
		t.Fatalf("Validate accepted config, want error containing %q", want)
	}

	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want %q", err.Error(), want)
	}
}

// containsString keeps slice assertions compact without pulling in another dependency.
func containsString(values []string, needle string) bool {
	return slices.Contains(values, needle)
}
