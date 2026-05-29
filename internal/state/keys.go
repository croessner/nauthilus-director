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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// KeyBuilderOptions contains Redis key namespace settings.
type KeyBuilderOptions struct {
	Prefix        string
	SchemaVersion int
}

// KeyBuilder creates Redis Cluster-safe keys for affinity state.
type KeyBuilder struct {
	prefix        string
	schemaVersion int
}

// AffinityKeys contains the per-affinity Redis key group.
type AffinityKeys struct {
	HashTag  string
	State    string
	Sessions string
	Override string
}

const (
	affinityKeySessionPrefix = "session:"
	affinityKeyState         = "state"
	affinityKeySessions      = "sessions"
	affinityKeyOverride      = "override"
)

// NewKeyBuilder creates a Redis key builder with a stable namespace prefix.
func NewKeyBuilder(options KeyBuilderOptions) (KeyBuilder, error) {
	prefix := strings.Trim(strings.TrimSpace(options.Prefix), ":")
	if prefix == "" {
		return KeyBuilder{}, newStateError(RedisErrorKindConfig, "keys", "prefix required", nil)
	}

	if options.SchemaVersion <= 0 {
		return KeyBuilder{}, newStateError(RedisErrorKindConfig, "keys", "schema version required", nil)
	}

	return KeyBuilder{prefix: prefix, schemaVersion: options.SchemaVersion}, nil
}

// AffinityHash returns the hash used inside Redis Cluster hash tags.
func (b KeyBuilder) AffinityHash(tenant string, normalizedAccount string) (string, error) {
	tenant = normalizeAffinityPart(tenant)
	normalizedAccount = normalizeAffinityPart(normalizedAccount)

	if tenant == "" {
		return "", newStateError(RedisErrorKindAmbiguousState, "keys", "tenant required", nil)
	}

	if normalizedAccount == "" {
		return "", newStateError(RedisErrorKindAmbiguousState, "keys", "account key required", nil)
	}

	sum := sha256.Sum256([]byte(tenant + "\x00" + normalizedAccount))

	return hex.EncodeToString(sum[:]), nil
}

// AffinityKeys returns the Cluster hash-tagged Redis key group.
func (b KeyBuilder) AffinityKeys(tenant string, normalizedAccount string) (AffinityKeys, error) {
	hash, err := b.AffinityHash(tenant, normalizedAccount)
	if err != nil {
		return AffinityKeys{}, err
	}

	hashTag := "{aff:" + hash + "}"
	base := b.affinityBase(hashTag)

	return AffinityKeys{
		HashTag:  hashTag,
		State:    base + ":state",
		Sessions: base + ":sessions",
		Override: base + ":override",
	}, nil
}

// SessionKey returns the per-session key inside the affinity hash tag.
func (b KeyBuilder) SessionKey(tenant string, normalizedAccount string, sessionID string) (string, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return "", newStateError(RedisErrorKindAmbiguousState, "keys", "session id required", nil)
	}

	keys, err := b.AffinityKeys(tenant, normalizedAccount)
	if err != nil {
		return "", err
	}

	return b.affinityBase(keys.HashTag) + ":session:" + sessionID, nil
}

// BackendRuntimeKey returns the Redis key for mutable backend runtime state.
func (b KeyBuilder) BackendRuntimeKey(backendID string) (string, error) {
	backendID = strings.TrimSpace(backendID)
	if backendID == "" {
		return "", newStateError(RedisErrorKindAmbiguousState, "keys", "backend id required", nil)
	}

	return b.namespaceBase() + ":runtime:backend:" + backendID, nil
}

// InstanceKey returns the Redis key for one director instance heartbeat.
func (b KeyBuilder) InstanceKey(instanceID string) (string, error) {
	instanceID = strings.TrimSpace(instanceID)
	if instanceID == "" {
		return "", newStateError(RedisErrorKindAmbiguousState, "keys", "instance id required", nil)
	}

	return b.namespaceBase() + ":runtime:instance:" + instanceID, nil
}

// HealthOwnerKey returns the Redis key for one backend health ownership lease.
func (b KeyBuilder) HealthOwnerKey(backendID string) (string, error) {
	backendID = strings.TrimSpace(backendID)
	if backendID == "" {
		return "", newStateError(RedisErrorKindAmbiguousState, "keys", "backend id required", nil)
	}

	return b.namespaceBase() + ":health:backend:" + backendID + ":owner", nil
}

// HealthStateKey returns the Redis key for one backend published health result.
func (b KeyBuilder) HealthStateKey(backendID string) (string, error) {
	backendID = strings.TrimSpace(backendID)
	if backendID == "" {
		return "", newStateError(RedisErrorKindAmbiguousState, "keys", "backend id required", nil)
	}

	return b.namespaceBase() + ":health:backend:" + backendID + ":state", nil
}

// BackendSessionIndexKey returns the repairable backend-to-session index key.
func (b KeyBuilder) BackendSessionIndexKey(backendID string) (string, error) {
	backendID = strings.TrimSpace(backendID)
	if backendID == "" {
		return "", newStateError(RedisErrorKindAmbiguousState, "keys", "backend id required", nil)
	}

	return b.namespaceBase() + ":idx:backend:" + backendID + ":sessions", nil
}

// SessionIndexKey returns the repairable session index key.
func (b KeyBuilder) SessionIndexKey() string {
	return b.namespaceBase() + ":idx:sessions"
}

// BackendIndexKey returns the repairable backend index key.
func (b KeyBuilder) BackendIndexKey() string {
	return b.namespaceBase() + ":idx:backends"
}

// UserIndexKey returns the repairable user-affinity index key.
func (b KeyBuilder) UserIndexKey() string {
	return b.namespaceBase() + ":idx:users"
}

// UserSessionIndexKey returns the repairable user-to-session index key.
func (b KeyBuilder) UserSessionIndexKey(tenant string, normalizedAccount string) (string, error) {
	hash, err := b.AffinityHash(tenant, normalizedAccount)
	if err != nil {
		return "", err
	}

	return b.namespaceBase() + ":idx:user:" + hash + ":sessions", nil
}

// namespaceBase returns the versioned Redis namespace prefix.
func (b KeyBuilder) namespaceBase() string {
	return fmt.Sprintf("%s:v%d", b.prefix, b.schemaVersion)
}

// affinityBase returns the per-affinity Redis key prefix.
func (b KeyBuilder) affinityBase(hashTag string) string {
	return b.namespaceBase() + ":" + hashTag
}

// validateAffinityOwnedKeys rejects Redis script keys outside one affinity hash tag.
func (b KeyBuilder) validateAffinityOwnedKeys(operation string, keys []string) error {
	if len(keys) == 0 {
		return newStateError(RedisErrorKindConfig, operation, "affinity script keys required", nil)
	}

	hashTag := ""

	for _, key := range keys {
		keyHashTag, err := b.affinityOwnedHashTag(operation, key)
		if err != nil {
			return err
		}

		if hashTag == "" {
			hashTag = keyHashTag

			continue
		}

		if keyHashTag != hashTag {
			return newStateError(RedisErrorKindConfig, operation, "affinity script keys use multiple hash tags", nil)
		}
	}

	return nil
}

// affinityOwnedHashTag extracts and validates the one allowed affinity key family.
func (b KeyBuilder) affinityOwnedHashTag(operation string, key string) (string, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return "", newStateError(RedisErrorKindConfig, operation, "empty affinity script key", nil)
	}

	start := strings.Index(key, "{aff:")
	if start < 0 {
		return "", newStateError(RedisErrorKindConfig, operation, "missing affinity hash tag", nil)
	}

	end := strings.Index(key[start:], "}")
	if end < 0 {
		return "", newStateError(RedisErrorKindConfig, operation, "unterminated affinity hash tag", nil)
	}

	end += start

	hashTag := key[start : end+1]
	if len(hashTag) <= len("{aff:}") {
		return "", newStateError(RedisErrorKindConfig, operation, "empty affinity hash tag", nil)
	}

	prefix := b.namespaceBase() + ":" + hashTag + ":"
	if !strings.HasPrefix(key, prefix) {
		return "", newStateError(RedisErrorKindConfig, operation, "affinity key namespace mismatch", nil)
	}

	suffix := strings.TrimPrefix(key, prefix)
	if !affinityKeySuffixAllowed(suffix) {
		return "", newStateError(RedisErrorKindConfig, operation, "non-affinity key in affinity script", nil)
	}

	return hashTag, nil
}

// affinityKeySuffixAllowed reports whether a key suffix belongs to one affinity.
func affinityKeySuffixAllowed(suffix string) bool {
	switch suffix {
	case affinityKeyState, affinityKeySessions, affinityKeyOverride:
		return true
	default:
		return strings.HasPrefix(suffix, affinityKeySessionPrefix) && strings.TrimPrefix(suffix, affinityKeySessionPrefix) != ""
	}
}

// normalizeAffinityPart canonicalizes input before hashing.
func normalizeAffinityPart(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
