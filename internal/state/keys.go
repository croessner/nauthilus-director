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
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// KeyBuilderOptions contains Redis key namespace settings.
type KeyBuilderOptions struct {
	Prefix             string
	SchemaVersion      int
	SessionIndexShards int
	UserIndexShards    int
	BackendIndexShards int
}

// KeyBuilder creates Redis Cluster-safe keys for affinity state.
type KeyBuilder struct {
	prefix             string
	schemaVersion      int
	sessionIndexShards int
	userIndexShards    int
	backendIndexShards int
}

// AffinityKeys contains the per-affinity Redis key group.
type AffinityKeys struct {
	HashTag  string
	State    string
	Sessions string
	Override string
}

// BackendReservationKeys contains the Redis key group for one backend slot.
type BackendReservationKeys struct {
	HashTag string
	State   string
	Due     string
}

const (
	affinityKeySessionPrefix = "session:"
	affinityKeyState         = "state"
	affinityKeySessions      = "sessions"
	affinityKeyOverride      = "override"

	defaultSessionIndexShards = 64
	defaultUserIndexShards    = 32
	defaultBackendIndexShards = 32
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

	return KeyBuilder{
		prefix:             prefix,
		schemaVersion:      options.SchemaVersion,
		sessionIndexShards: normalizeIndexShardCount(options.SessionIndexShards, defaultSessionIndexShards),
		userIndexShards:    normalizeIndexShardCount(options.UserIndexShards, defaultUserIndexShards),
		backendIndexShards: normalizeIndexShardCount(options.BackendIndexShards, defaultBackendIndexShards),
	}, nil
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

// BackendHash returns the stable backend hash used inside Redis Cluster hash tags.
func (b KeyBuilder) BackendHash(backendID string) (string, error) {
	backendID = strings.TrimSpace(backendID)
	if backendID == "" {
		return "", newStateError(RedisErrorKindAmbiguousState, "keys", "backend id required", nil)
	}

	sum := sha256.Sum256([]byte(backendID))

	return hex.EncodeToString(sum[:]), nil
}

// BackendReservationKeys returns the same-slot reservation key group for one backend.
func (b KeyBuilder) BackendReservationKeys(backendID string) (BackendReservationKeys, error) {
	backendID = strings.TrimSpace(backendID)
	if backendID == "" {
		return BackendReservationKeys{}, newStateError(RedisErrorKindAmbiguousState, "keys", "backend id required", nil)
	}

	backendHash, err := b.BackendHash(backendID)
	if err != nil {
		return BackendReservationKeys{}, err
	}

	hashTag := "{backend:" + backendHash + "}"
	base := b.namespaceBase() + ":" + hashTag + ":runtime:backend:" + backendID

	return BackendReservationKeys{
		HashTag: hashTag,
		State:   base + ":reservations",
		Due:     base + ":reservations_due",
	}, nil
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
	return b.BackendSessionIndexShardKeyByNumber(backendID, 0)
}

// BackendSessionIndexShardKey returns the repairable backend-session shard for a session.
func (b KeyBuilder) BackendSessionIndexShardKey(backendID string, sessionID string) (string, error) {
	shard, err := b.BackendSessionIndexShard(sessionID)
	if err != nil {
		return "", err
	}

	return b.BackendSessionIndexShardKeyByNumber(backendID, shard)
}

// BackendSessionIndexShardKeyByNumber returns one repairable backend-session shard key.
func (b KeyBuilder) BackendSessionIndexShardKeyByNumber(backendID string, shard int) (string, error) {
	backendID = strings.TrimSpace(backendID)
	if backendID == "" {
		return "", newStateError(RedisErrorKindAmbiguousState, "keys", "backend id required", nil)
	}

	if err := b.validateShardNumber("keys", shard, b.backendIndexShards); err != nil {
		return "", err
	}

	return fmt.Sprintf("%s:idx:backend:%s:sessions:%02d", b.namespaceBase(), backendID, shard), nil
}

// BackendSessionIndexShardKeys returns every repairable backend-session shard key.
func (b KeyBuilder) BackendSessionIndexShardKeys(backendID string) ([]string, error) {
	keys := make([]string, 0, b.backendIndexShards)
	for shard := range b.backendIndexShards {
		key, err := b.BackendSessionIndexShardKeyByNumber(backendID, shard)
		if err != nil {
			return nil, err
		}

		keys = append(keys, key)
	}

	return keys, nil
}

// SessionIndexKey returns the repairable session index key.
func (b KeyBuilder) SessionIndexKey() string {
	return b.namespaceBase() + ":idx:sessions"
}

// SessionIndexShardKey returns the repairable session locator shard for a session.
func (b KeyBuilder) SessionIndexShardKey(sessionID string) (string, error) {
	shard, err := b.SessionIndexShard(sessionID)
	if err != nil {
		return "", err
	}

	return b.SessionIndexShardKeyByNumber(shard)
}

// SessionIndexShardKeyByNumber returns one repairable session locator shard key.
func (b KeyBuilder) SessionIndexShardKeyByNumber(shard int) (string, error) {
	if err := b.validateShardNumber("keys", shard, b.sessionIndexShards); err != nil {
		return "", err
	}

	return fmt.Sprintf("%s:idx:sessions:%02d", b.namespaceBase(), shard), nil
}

// SessionIndexShardKeys returns every repairable session locator shard key.
func (b KeyBuilder) SessionIndexShardKeys() []string {
	keys := make([]string, 0, b.sessionIndexShards)
	for shard := range b.sessionIndexShards {
		keys = append(keys, fmt.Sprintf("%s:idx:sessions:%02d", b.namespaceBase(), shard))
	}

	return keys
}

// SessionDueIndexShardKey returns the due-time shard for one session lease.
func (b KeyBuilder) SessionDueIndexShardKey(sessionID string) (string, error) {
	shard, err := b.SessionIndexShard(sessionID)
	if err != nil {
		return "", err
	}

	return b.SessionDueIndexShardKeyByNumber(shard)
}

// SessionDueIndexShardKeyByNumber returns one due-time repair shard key.
func (b KeyBuilder) SessionDueIndexShardKeyByNumber(shard int) (string, error) {
	if err := b.validateShardNumber("keys", shard, b.sessionIndexShards); err != nil {
		return "", err
	}

	return fmt.Sprintf("%s:idx:sessions_due:%02d", b.namespaceBase(), shard), nil
}

// SessionDueIndexShardKeys returns every due-time repair shard key.
func (b KeyBuilder) SessionDueIndexShardKeys() []string {
	keys := make([]string, 0, b.sessionIndexShards)
	for shard := range b.sessionIndexShards {
		keys = append(keys, fmt.Sprintf("%s:idx:sessions_due:%02d", b.namespaceBase(), shard))
	}

	return keys
}

// BackendIndexKey returns the repairable backend index key.
func (b KeyBuilder) BackendIndexKey() string {
	return b.namespaceBase() + ":idx:backends"
}

// UserIndexKey returns the repairable user-affinity index key.
func (b KeyBuilder) UserIndexKey() string {
	return b.namespaceBase() + ":idx:users"
}

// UserIndexShardKey returns the repairable user-affinity index shard for an affinity hash.
func (b KeyBuilder) UserIndexShardKey(affinityHash string) (string, error) {
	shard, err := b.UserIndexShard(affinityHash)
	if err != nil {
		return "", err
	}

	return b.UserIndexShardKeyByNumber(shard)
}

// UserIndexShardKeyByNumber returns one repairable user-affinity index shard key.
func (b KeyBuilder) UserIndexShardKeyByNumber(shard int) (string, error) {
	if err := b.validateShardNumber("keys", shard, b.userIndexShards); err != nil {
		return "", err
	}

	return fmt.Sprintf("%s:idx:users:%02d", b.namespaceBase(), shard), nil
}

// UserIndexShardKeys returns every repairable user-affinity index shard key.
func (b KeyBuilder) UserIndexShardKeys() []string {
	keys := make([]string, 0, b.userIndexShards)
	for shard := range b.userIndexShards {
		keys = append(keys, fmt.Sprintf("%s:idx:users:%02d", b.namespaceBase(), shard))
	}

	return keys
}

// UserSessionIndexKey returns the repairable user-to-session index key.
func (b KeyBuilder) UserSessionIndexKey(tenant string, normalizedAccount string) (string, error) {
	return b.UserSessionIndexShardKeyByNumber(tenant, normalizedAccount, 0)
}

// UserSessionIndexShardKey returns the repairable user-session shard for a session.
func (b KeyBuilder) UserSessionIndexShardKey(tenant string, normalizedAccount string, sessionID string) (string, error) {
	shard, err := b.UserSessionIndexShard(sessionID)
	if err != nil {
		return "", err
	}

	return b.UserSessionIndexShardKeyByNumber(tenant, normalizedAccount, shard)
}

// UserSessionIndexShardKeyByNumber returns one repairable user-session shard key.
func (b KeyBuilder) UserSessionIndexShardKeyByNumber(tenant string, normalizedAccount string, shard int) (string, error) {
	hash, err := b.AffinityHash(tenant, normalizedAccount)
	if err != nil {
		return "", err
	}

	if err := b.validateShardNumber("keys", shard, b.userIndexShards); err != nil {
		return "", err
	}

	return fmt.Sprintf("%s:idx:user:%s:sessions:%02d", b.namespaceBase(), hash, shard), nil
}

// UserSessionIndexShardKeys returns every repairable user-session shard key.
func (b KeyBuilder) UserSessionIndexShardKeys(tenant string, normalizedAccount string) ([]string, error) {
	keys := make([]string, 0, b.userIndexShards)
	for shard := range b.userIndexShards {
		key, err := b.UserSessionIndexShardKeyByNumber(tenant, normalizedAccount, shard)
		if err != nil {
			return nil, err
		}

		keys = append(keys, key)
	}

	return keys, nil
}

// SessionIndexShard returns the deterministic session locator shard number.
func (b KeyBuilder) SessionIndexShard(sessionID string) (int, error) {
	return b.indexShard("keys", sessionID, b.sessionIndexShards, "session id required")
}

// UserIndexShard returns the deterministic user index shard number.
func (b KeyBuilder) UserIndexShard(affinityHash string) (int, error) {
	return b.indexShard("keys", affinityHash, b.userIndexShards, "affinity hash required")
}

// UserSessionIndexShard returns the deterministic user-session shard number.
func (b KeyBuilder) UserSessionIndexShard(sessionID string) (int, error) {
	return b.indexShard("keys", sessionID, b.userIndexShards, "session id required")
}

// BackendSessionIndexShard returns the deterministic backend-session shard number.
func (b KeyBuilder) BackendSessionIndexShard(sessionID string) (int, error) {
	return b.indexShard("keys", sessionID, b.backendIndexShards, "session id required")
}

// namespaceBase returns the versioned Redis namespace prefix.
func (b KeyBuilder) namespaceBase() string {
	return fmt.Sprintf("%s:v%d", b.prefix, b.schemaVersion)
}

// affinityBase returns the per-affinity Redis key prefix.
func (b KeyBuilder) affinityBase(hashTag string) string {
	return b.namespaceBase() + ":" + hashTag
}

// validateShardNumber rejects a shard outside the configured index family.
func (b KeyBuilder) validateShardNumber(operation string, shard int, total int) error {
	if shard < 0 || shard >= total {
		return newStateError(RedisErrorKindAmbiguousState, operation, "index shard out of range", nil)
	}

	return nil
}

// indexShard maps a stable value to one configured index shard.
func (b KeyBuilder) indexShard(operation string, value string, total int, emptyMessage string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, newStateError(RedisErrorKindAmbiguousState, operation, emptyMessage, nil)
	}

	sum := sha256.Sum256([]byte(value))

	return int(binary.BigEndian.Uint64(sum[:8]) % uint64(total)), nil
}

// validateAffinityOwnedKeys rejects Redis script keys outside one affinity hash tag.
func (b KeyBuilder) validateAffinityOwnedKeys(operation string, keys []string) error {
	return b.validateSingleHashTaggedKeys(
		operation,
		keys,
		"affinity script keys required",
		"affinity script keys use multiple hash tags",
		b.affinityOwnedHashTag,
	)
}

// validateBackendReservationOwnedKeys rejects reservation scripts outside one backend hash tag.
func (b KeyBuilder) validateBackendReservationOwnedKeys(operation string, keys []string) error {
	return b.validateSingleHashTaggedKeys(
		operation,
		keys,
		"backend reservation script keys required",
		"backend reservation script keys use multiple hash tags",
		b.backendReservationOwnedHashTag,
	)
}

// validateSingleHashTaggedKeys rejects script key lists spanning multiple Redis hash tags.
func (b KeyBuilder) validateSingleHashTaggedKeys(
	operation string,
	keys []string,
	emptyMessage string,
	mismatchMessage string,
	extractHashTag func(string, string) (string, error),
) error {
	if len(keys) == 0 {
		return newStateError(RedisErrorKindConfig, operation, emptyMessage, nil)
	}

	hashTag := ""

	for _, key := range keys {
		keyHashTag, err := extractHashTag(operation, key)
		if err != nil {
			return err
		}

		if hashTag == "" {
			hashTag = keyHashTag

			continue
		}

		if keyHashTag != hashTag {
			return newStateError(RedisErrorKindConfig, operation, mismatchMessage, nil)
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

// backendReservationOwnedHashTag extracts and validates one backend reservation key family.
func (b KeyBuilder) backendReservationOwnedHashTag(operation string, key string) (string, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return "", newStateError(RedisErrorKindConfig, operation, "empty backend reservation script key", nil)
	}

	start := strings.Index(key, "{backend:")
	if start < 0 {
		return "", newStateError(RedisErrorKindConfig, operation, "missing backend hash tag", nil)
	}

	end := strings.Index(key[start:], "}")
	if end < 0 {
		return "", newStateError(RedisErrorKindConfig, operation, "unterminated backend hash tag", nil)
	}

	end += start

	hashTag := key[start : end+1]
	if len(hashTag) <= len("{backend:}") {
		return "", newStateError(RedisErrorKindConfig, operation, "empty backend hash tag", nil)
	}

	prefix := b.namespaceBase() + ":" + hashTag + ":runtime:backend:"
	if !strings.HasPrefix(key, prefix) {
		return "", newStateError(RedisErrorKindConfig, operation, "backend reservation namespace mismatch", nil)
	}

	if !backendReservationKeySuffixAllowed(strings.TrimPrefix(key, prefix)) {
		return "", newStateError(RedisErrorKindConfig, operation, "non-reservation key in backend reservation script", nil)
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

// backendReservationKeySuffixAllowed reports whether a suffix belongs to one backend reservation group.
func backendReservationKeySuffixAllowed(suffix string) bool {
	return strings.HasSuffix(suffix, ":reservations") || strings.HasSuffix(suffix, ":reservations_due")
}

// normalizeAffinityPart canonicalizes input before hashing.
func normalizeAffinityPart(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// normalizeIndexShardCount applies production-safe defaults for zero-valued tests.
func normalizeIndexShardCount(value int, fallback int) int {
	if value <= 0 {
		return fallback
	}

	return value
}
