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

package backend

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/croessner/nauthilus-director/internal/config"
)

const (
	testAccountKey     = "alice@example.test"
	testBackendID      = "mailstore-a-imap"
	testBackendIDLMTP  = "mailstore-a-lmtp"
	testBackendIDBLMTP = "mailstore-b-lmtp"
	testPoolIMAP       = "imap-default"
	testPoolLMTP       = "lmtp-default"
	testProtocolLMTP   = "lmtp"
	testShardTag       = "mailstore-a"
	testTenant         = "default"
)

// TestStaticRegistryIndexesByProtocolPoolAndShard verifies config-backed backend lookup.
func TestStaticRegistryIndexesByProtocolPoolAndShard(t *testing.T) {
	registry := mustStaticRegistry(t, config.DefaultConfig())

	backends, err := registry.BackendsForShard(context.Background(), RegistryRequest{
		Protocol:    protocolIMAP,
		BackendPool: testPoolIMAP,
		ShardTag:    testShardTag,
	})
	if err != nil {
		t.Fatalf("BackendsForShard returned error: %v", err)
	}

	if len(backends) != 1 || backends[0].Identifier != testBackendID {
		t.Fatalf("backends = %#v, want %s", backends, testBackendID)
	}

	if backends[0].Protocol != protocolIMAP || backends[0].BackendPool != testPoolIMAP || backends[0].ShardTag != testShardTag {
		t.Fatalf("backend index fields = %#v", backends[0])
	}

	if backends[0].TLS.Mode != "starttls" || backends[0].TLS.ServerName != "mailstore-a.example.org" {
		t.Fatalf("backend TLS fields = %#v", backends[0].TLS)
	}

	if backends[0].Auth.Mode != "master_user" || backends[0].Auth.MasterUser.UserFormat == "" {
		t.Fatalf("backend auth fields = %#v", backends[0].Auth)
	}

	_, err = registry.BackendsForShard(context.Background(), RegistryRequest{
		Protocol:    protocolIMAP,
		BackendPool: testPoolIMAP,
		ShardTag:    "missing-shard",
	})
	if !IsErrorKind(err, ErrorKindNoBackend) {
		t.Fatalf("missing shard error = %v, want no_backend", err)
	}
}

// TestStaticRegistryRejectsUnixSocketBackendAddress keeps backend transport TCP-only.
func TestStaticRegistryRejectsUnixSocketBackendAddress(t *testing.T) {
	cfg := config.DefaultConfig()
	backendConfig := cfg.Director.Backends[testBackendID]
	backendConfig.Address = "unix:/run/mailstore/imap.sock"
	cfg.Director.Backends[testBackendID] = backendConfig

	_, err := NewStaticRegistry(cfg.Director)
	if !IsErrorKind(err, ErrorKindConfig) {
		t.Fatalf("NewStaticRegistry error = %v, want config", err)
	}
}

// TestStaticRegistryFailsClosedOnPoolProtocolMismatch rejects ambiguous config.
func TestStaticRegistryFailsClosedOnPoolProtocolMismatch(t *testing.T) {
	cfg := config.DefaultConfig()
	pool := cfg.Director.BackendPools[testPoolIMAP]
	pool.Backends = []string{testBackendIDLMTP}
	cfg.Director.BackendPools[testPoolIMAP] = pool

	_, err := NewStaticRegistry(cfg.Director)
	if !IsErrorKind(err, ErrorKindConfig) {
		t.Fatalf("NewStaticRegistry error = %v, want config", err)
	}
}

// TestBackendHealthSecretRedaction verifies health credentials stay redacted in diagnostics.
func TestBackendHealthSecretRedaction(t *testing.T) {
	registry := mustStaticRegistry(t, config.DefaultConfig())

	entry, err := registry.Lookup(context.Background(), testBackendID)
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}

	formatted := fmt.Sprintf("%#v %s", entry.Health.Password, entry.Health.Password)
	if strings.Contains(formatted, entry.Health.Password.Value()) {
		t.Fatalf("formatted health password leaked: %s", formatted)
	}

	if !strings.Contains(formatted, "<redacted>") {
		t.Fatalf("formatted health password = %s, want redaction marker", formatted)
	}
}

// TestStaticSelectorEnforcesListenerBackendPool verifies protocol and pool boundaries.
func TestStaticSelectorEnforcesListenerBackendPool(t *testing.T) {
	selector := mustStaticSelector(t, config.DefaultConfig(), SelectionPolicy{SoftAllowsActivePins: true})

	_, err := selector.Select(context.Background(), SelectionRequest{
		AccountKey:  testAccountKey,
		Tenant:      testTenant,
		ShardTag:    testShardTag,
		Protocol:    protocolIMAP,
		BackendPool: testPoolLMTP,
	})
	if !IsErrorKind(err, ErrorKindAmbiguous) {
		t.Fatalf("Select error = %v, want ambiguous", err)
	}

	result, err := selector.Select(context.Background(), SelectionRequest{
		AccountKey:  testAccountKey,
		Tenant:      testTenant,
		ShardTag:    testShardTag,
		Protocol:    testProtocolLMTP,
		BackendPool: testPoolLMTP,
	})
	if err != nil {
		t.Fatalf("LMTP Select returned error: %v", err)
	}

	if result.Backend.Identifier != testBackendIDLMTP {
		t.Fatalf("LMTP selected backend = %q, want %q", result.Backend.Identifier, testBackendIDLMTP)
	}

	if result.Backend.Auth.SASL.Username == "" || result.Backend.Auth.OAuthBearer.Token.IsZero() {
		t.Fatalf("LMTP backend auth fields were not copied: %#v", result.Backend.Auth)
	}
}

// TestStaticSelectorMaintenanceAndWeightBehavior verifies static eligibility rules.
func TestStaticSelectorMaintenanceAndWeightBehavior(t *testing.T) {
	testCases := []struct {
		name           string
		mode           string
		weight         int
		activeAffinity bool
		softPins       bool
		wantErr        ErrorKind
	}{
		{name: "disabled initial", mode: string(MaintenanceModeDisabled), weight: 100},
		{name: "soft initial excluded", mode: string(MaintenanceModeSoft), weight: 100, wantErr: ErrorKindNoBackend},
		{name: "soft active allowed", mode: string(MaintenanceModeSoft), weight: 100, activeAffinity: true, softPins: true},
		{
			name:           "soft active disallowed",
			mode:           string(MaintenanceModeSoft),
			weight:         100,
			activeAffinity: true,
			wantErr:        ErrorKindNoBackend,
		},
		{name: "hard active excluded", mode: string(MaintenanceModeHard), weight: 100, activeAffinity: true, softPins: true, wantErr: ErrorKindNoBackend},
		{name: "zero weight initial excluded", mode: string(MaintenanceModeDisabled), weight: 0, wantErr: ErrorKindNoBackend},
		{name: "zero weight active allowed", mode: string(MaintenanceModeDisabled), weight: 0, activeAffinity: true, softPins: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			selector := mustStaticSelector(t, singleBackendConfig(testCase.mode, testCase.weight), SelectionPolicy{
				SoftAllowsActivePins: testCase.softPins,
			})

			result, err := selector.Select(context.Background(), SelectionRequest{
				AccountKey:     testAccountKey,
				Tenant:         testTenant,
				ShardTag:       testShardTag,
				Protocol:       protocolIMAP,
				BackendPool:    testPoolIMAP,
				ActiveAffinity: testCase.activeAffinity,
			})
			if testCase.wantErr != "" {
				if !IsErrorKind(err, testCase.wantErr) {
					t.Fatalf("Select error = %v, want %s", err, testCase.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("Select returned error: %v", err)
			}

			if result.Backend.Identifier != testBackendID {
				t.Fatalf("selected backend = %#v", result.Backend)
			}

			if result.ActiveAffinity != testCase.activeAffinity {
				t.Fatalf("active affinity = %v, want %v", result.ActiveAffinity, testCase.activeAffinity)
			}
		})
	}
}

// singleBackendConfig creates a one-backend IMAP pool fixture.
func singleBackendConfig(mode string, weight int) config.Config {
	cfg := config.DefaultConfig()
	backend := cfg.Director.Backends[testBackendID]
	backend.Maintenance = mode
	backend.Weight = weight
	cfg.Director.Backends = map[string]config.BackendConfig{
		testBackendID: backend,
	}
	pool := cfg.Director.BackendPools[testPoolIMAP]
	pool.Backends = []string{testBackendID}
	cfg.Director.BackendPools = map[string]config.BackendPoolConfig{
		testPoolIMAP: pool,
	}

	return cfg
}

// mustStaticRegistry creates a registry fixture.
func mustStaticRegistry(t *testing.T, cfg config.Config) *StaticRegistry {
	t.Helper()

	registry, err := NewStaticRegistry(cfg.Director)
	if err != nil {
		t.Fatalf("NewStaticRegistry returned error: %v", err)
	}

	return registry
}

// mustStaticSelector creates a selector fixture.
func mustStaticSelector(t *testing.T, cfg config.Config, policy SelectionPolicy) *StaticSelector {
	t.Helper()

	selector, err := NewStaticSelector(mustStaticRegistry(t, cfg), policy)
	if err != nil {
		t.Fatalf("NewStaticSelector returned error: %v", err)
	}

	return selector
}
