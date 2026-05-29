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

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestValidateConfigRequiresExplicitTarget keeps stress runs opt-in.
func TestValidateConfigRequiresExplicitTarget(t *testing.T) {
	err := validateConfig(scaleConfig{KeyPrefix: defaultTenant, LeaseTTL: time.Second, Timeout: time.Second})
	if err == nil || !strings.Contains(err.Error(), "explicit --redis-addr") {
		t.Fatalf("validateConfig error = %v, want explicit target requirement", err)
	}
}

// TestValidateConfigRefusesProductionLookingTarget keeps remote Redis opt-in.
func TestValidateConfigRefusesProductionLookingTarget(t *testing.T) {
	config := scaleConfig{
		RedisAddr: "redis.example.org:6379",
		KeyPrefix: defaultTenant,
		LeaseTTL:  time.Second,
		Timeout:   time.Second,
	}

	err := validateConfig(config)
	if err == nil || !strings.Contains(err.Error(), "production-looking") {
		t.Fatalf("validateConfig error = %v, want production-looking refusal", err)
	}

	config.AllowProductionTarget = true
	if err := validateConfig(config); err != nil {
		t.Fatalf("validateConfig with override returned error: %v", err)
	}
}

// TestValidateConfigAllowsLoopbackTarget accepts bounded local smoke runs.
func TestValidateConfigAllowsLoopbackTarget(t *testing.T) {
	err := validateConfig(scaleConfig{
		RedisAddr: "127.0.0.1:6379",
		KeyPrefix: defaultTenant,
		LeaseTTL:  time.Second,
		Timeout:   time.Second,
	})
	if err != nil {
		t.Fatalf("validateConfig loopback returned error: %v", err)
	}
}

// TestRedisSlotHonorsHashTags verifies Cluster slot distribution uses Redis semantics.
func TestRedisSlotHonorsHashTags(t *testing.T) {
	first := redisSlot("prefix:{aff:abc}:state")
	second := redisSlot("other:{aff:abc}:session:1")
	third := redisSlot("prefix:{aff:def}:state")

	if first != second {
		t.Fatalf("same hash tag slots = %d/%d, want equal", first, second)
	}

	if first == third {
		t.Fatalf("different hash tag slots both = %d, want distribution", first)
	}
}

// TestGuardrailsDoNotRunScaleStress keeps unbounded stress outside normal gates.
func TestGuardrailsDoNotRunScaleStress(t *testing.T) {
	makefile := readRepoFile(t, "Makefile")
	guardrailsLine := lineWithPrefix(makefile, "guardrails:")

	if strings.Contains(guardrailsLine, "scale-stress") {
		t.Fatalf("guardrails target includes scale-stress: %s", guardrailsLine)
	}
}

// readRepoFile reads a repository-root file from the test package.
func readRepoFile(t *testing.T, name string) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("..", "..", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}

	return string(data)
}

// lineWithPrefix returns one Makefile line by prefix.
func lineWithPrefix(content string, prefix string) string {
	for line := range strings.SplitSeq(content, "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}

	return ""
}
