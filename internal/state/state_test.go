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

package state

import (
	"errors"
	"strings"
	"testing"

	"github.com/redis/go-redis/v9"
)

// TestKeyBuilderCreatesClusterHashTaggedAffinityKeys verifies M0 key shape.
func TestKeyBuilderCreatesClusterHashTaggedAffinityKeys(t *testing.T) {
	builder := mustKeyBuilder(t)

	keys, err := builder.AffinityKeys("default", "user@example.org")
	if err != nil {
		t.Fatalf("AffinityKeys returned error: %v", err)
	}

	for name, key := range map[string]string{
		"state":    keys.State,
		"sessions": keys.Sessions,
		"override": keys.Override,
	} {
		if !strings.Contains(key, keys.HashTag) {
			t.Fatalf("%s key %q does not contain hash tag %q", name, key, keys.HashTag)
		}

		if !strings.HasPrefix(key, "nd:v1:{aff:") {
			t.Fatalf("%s key %q has wrong prefix", name, key)
		}
	}

	sessionKey, err := builder.SessionKey("default", "user@example.org", "session-1")
	if err != nil {
		t.Fatalf("SessionKey returned error: %v", err)
	}

	if !strings.Contains(sessionKey, keys.HashTag) || !strings.HasSuffix(sessionKey, ":session:session-1") {
		t.Fatalf("session key = %q, hash tag = %q", sessionKey, keys.HashTag)
	}
}

// TestKeyBuilderDoesNotRequireRawUsernameInKeys protects Redis key privacy.
func TestKeyBuilderDoesNotRequireRawUsernameInKeys(t *testing.T) {
	rawAccount := "User.Name+Secret@example.org"
	builder := mustKeyBuilder(t)

	keys, err := builder.AffinityKeys("default", rawAccount)
	if err != nil {
		t.Fatalf("AffinityKeys returned error: %v", err)
	}

	for _, key := range []string{keys.State, keys.Sessions, keys.Override} {
		if strings.Contains(key, rawAccount) || strings.Contains(key, strings.ToLower(rawAccount)) {
			t.Fatalf("key %q leaked raw account %q", key, rawAccount)
		}
	}
}

// TestBackendAndIndexKeysFollowM0Shape checks non-affinity runtime keys.
func TestBackendAndIndexKeysFollowM0Shape(t *testing.T) {
	builder := mustKeyBuilder(t)

	backendKey, err := builder.BackendRuntimeKey("mailstore-a-imap")
	if err != nil {
		t.Fatalf("BackendRuntimeKey returned error: %v", err)
	}

	if backendKey != "nd:v1:runtime:backend:mailstore-a-imap" {
		t.Fatalf("backend key = %q", backendKey)
	}

	if got := builder.SessionIndexKey(); got != "nd:v1:idx:sessions" {
		t.Fatalf("session index key = %q", got)
	}

	if got := builder.BackendIndexKey(); got != "nd:v1:idx:backends" {
		t.Fatalf("backend index key = %q", got)
	}
}

// TestScriptLoaderTracksSHAAndMissingScripts verifies M0 script conventions.
func TestScriptLoaderTracksSHAAndMissingScripts(t *testing.T) {
	registry, err := LoadEmbeddedScripts()
	if err != nil {
		t.Fatalf("LoadEmbeddedScripts returned error: %v", err)
	}

	script, ok := registry.Get("server_time")
	if !ok {
		t.Fatalf("server_time script missing; scripts=%v", registry.Names())
	}

	if len(script.SHA) != 40 {
		t.Fatalf("script SHA length = %d, want 40", len(script.SHA))
	}

	err = missingScriptError("server_time")

	if !IsRedisErrorKind(err, RedisErrorKindScriptMissing) {
		t.Fatalf("missing script error = %v, want script_missing", err)
	}

	if !ShouldFallbackToEval(err) {
		t.Fatal("missing script should permit controlled EVAL fallback")
	}

	if !IsFailClosedRedisError(err) {
		t.Fatal("missing script must remain fail-closed")
	}
}

// TestRedisAmbiguousStateErrorsFailClosed checks missing required state handling.
func TestRedisAmbiguousStateErrorsFailClosed(t *testing.T) {
	err := ClassifyRedisError("lookup_affinity", redis.Nil)
	if !IsRedisErrorKind(err, RedisErrorKindAmbiguousState) {
		t.Fatalf("classified error = %v, want ambiguous_state", err)
	}

	if !IsFailClosedRedisError(err) {
		t.Fatal("ambiguous Redis state must fail closed")
	}

	if classified := ClassifyRedisError("lookup_affinity", nil); classified != nil {
		t.Fatalf("nil error classified as %v", classified)
	}

	if IsFailClosedRedisError(errors.New("plain")) {
		t.Fatal("plain errors should not be treated as classified state errors")
	}
}

// mustKeyBuilder creates the standard Redis key builder fixture.
func mustKeyBuilder(t *testing.T) KeyBuilder {
	t.Helper()

	builder, err := NewKeyBuilder(KeyBuilderOptions{Prefix: "nd:", SchemaVersion: 1})
	if err != nil {
		t.Fatalf("NewKeyBuilder returned error: %v", err)
	}

	return builder
}
