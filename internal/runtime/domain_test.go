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

package runtime

import (
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/observability"
)

const (
	runtimeTestBackendIdentifier = "backend-a"
	runtimeTestTenant            = "default"
	runtimeTestUserHash          = "hash-a"
)

// runtimeValidationCase couples a validation name with the request under test.
type runtimeValidationCase struct {
	name     string
	validate func() error
}

// TestAuditMetadataDoesNotIncludeSecretBearingValues verifies audit sanitization.
func TestAuditMetadataDoesNotIncludeSecretBearingValues(t *testing.T) {
	audit, err := NewAuditMetadata(AuditInput{
		Operation:  AuditOperationBackendRuntimeSet,
		Reason:     "maintenance window",
		ServerTime: time.Unix(100, 0),
		Fields: map[string]string{
			"password": "secret-password",
			"token":    "secret-token",
			"username": "alice@example.test",
			"mode":     "hard",
		},
	})
	if err != nil {
		t.Fatalf("NewAuditMetadata returned error: %v", err)
	}

	rendered := strings.Join(mapValues(audit.SafeFields()), "\n")
	if strings.Contains(rendered, "secret-password") || strings.Contains(rendered, "secret-token") {
		t.Fatalf("audit metadata leaked secret values: %#v", audit.SafeFields())
	}

	if audit.Fields["password"] != observability.RedactedValue || audit.Fields["token"] != observability.RedactedValue {
		t.Fatalf("secret fields were not redacted: %#v", audit.Fields)
	}

	if audit.Fields["username_present"] != "true" {
		t.Fatalf("high-cardinality username was not collapsed: %#v", audit.Fields)
	}
}

// TestBackendRuntimeRequestsRejectEmptyReasons verifies backend mutation validation.
func TestBackendRuntimeRequestsRejectEmptyReasons(t *testing.T) {
	policy := backend.RuntimeOverridePolicy{
		Enabled:             true,
		AllowWeightOverride: true,
		MinWeight:           0,
		MaxWeight:           100,
	}

	assertInvalidRuntimeRequests(t, []runtimeValidationCase{
		{
			name: "backend in out",
			validate: func() error {
				return SetBackendInServiceRequest{BackendIdentifier: runtimeTestBackendIdentifier, InService: true}.Validate()
			},
		},
		{
			name: "backend weight",
			validate: func() error {
				return SetBackendWeightRequest{BackendIdentifier: runtimeTestBackendIdentifier, Weight: 10}.Validate(policy)
			},
		},
		{
			name: "backend maintenance",
			validate: func() error {
				return SetBackendMaintenanceRequest{
					BackendIdentifier: runtimeTestBackendIdentifier,
					Maintenance:       backend.MaintenanceState{Mode: backend.MaintenanceModeSoft},
				}.Validate()
			},
		},
		{
			name: "backend drain",
			validate: func() error {
				return StartBackendDrainRequest{
					BackendIdentifier: runtimeTestBackendIdentifier,
					Drain:             backend.DrainState{Enabled: true, Mode: backend.DrainModeSoft},
				}.Validate()
			},
		},
		{
			name: "backend clear",
			validate: func() error {
				return ClearBackendRuntimeRequest{BackendIdentifier: runtimeTestBackendIdentifier}.Validate()
			},
		},
	})
}

// TestUserAndSessionRuntimeRequestsRejectEmptyReasons verifies user/session mutation validation.
func TestUserAndSessionRuntimeRequestsRejectEmptyReasons(t *testing.T) {
	userKey := UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash}

	assertInvalidRuntimeRequests(t, []runtimeValidationCase{
		{
			name: "user move",
			validate: func() error {
				return MoveUserRequest{
					Key:         userKey,
					TargetShard: "shard-a",
					Strategy:    MoveStrategyNewSessionsOnly,
				}.Validate()
			},
		},
		{
			name: "user kick",
			validate: func() error {
				return KickUserRequest{Key: userKey}.Validate()
			},
		},
		{
			name: "user affinity clear",
			validate: func() error {
				return ClearUserAffinityRequest{Key: userKey}.Validate()
			},
		},
		{
			name: "session kill",
			validate: func() error {
				return KillSessionRequest{SessionID: "session-a"}.Validate()
			},
		},
	})
}

// assertInvalidRuntimeRequests checks that each mutation rejects its missing reason.
func assertInvalidRuntimeRequests(t *testing.T, testCases []runtimeValidationCase) {
	t.Helper()

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if err := testCase.validate(); !IsErrorKind(err, ErrorKindInvalidRequest) {
				t.Fatalf("Validate error = %v, want invalid_request", err)
			}
		})
	}
}

// mapValues returns map values for compact leak checks.
func mapValues(values map[string]string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}

	return out
}
