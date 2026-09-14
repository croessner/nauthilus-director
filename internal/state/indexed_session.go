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
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// indexedSessionKeys resolves a repairable locator into a validated affinity-owned key group.
func (s *RedisSessionStore) indexedSessionKeys(ctx context.Context, indexKey, sessionID string) ([]string, error) {
	sessionKey, err := s.client.HGet(redisContext(ctx), indexKey, sessionID).Result()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}

	if err != nil {
		return nil, ClassifyRedisError("session_locator_get", err)
	}

	tag, err := s.keys.affinityOwnedHashTag("session_locator_get", sessionKey)
	if err != nil {
		return nil, err
	}

	base := s.keys.affinityBase(tag)
	if sessionKey != base+":"+affinityKeySessionPrefix+sessionID {
		return nil, newStateError(RedisErrorKindAmbiguousState, "session_locator_get", "session locator mismatch", nil)
	}

	return []string{base + ":state", base + ":sessions", sessionKey}, nil
}

// missingSessionKillRecord supplies an authoritative timestamp for an absent repairable locator.
func (s *RedisSessionStore) missingSessionKillRecord(ctx context.Context, sessionID string) (SessionKillRecord, error) {
	now, err := s.client.Time(redisContext(ctx)).Result()
	if err != nil {
		return SessionKillRecord{}, ClassifyRedisError(scriptSessionKill, err)
	}

	return SessionKillRecord{Status: SessionKillStatusMissing, SessionID: strings.TrimSpace(sessionID), ControlAction: ControlActionNone, ServerTime: now}, nil
}

// removeReapedIndexes repairs secondary memberships after the authoritative session operation.
func (s *RedisSessionStore) removeReapedIndexes(ctx context.Context, indexKey, dueKey, sessionID string, record ReapRecord) error {
	value, err := s.runScript(ctx, "session_index_repair", []string{indexKey, dueKey},
		sessionID, record.sessionKey, record.ServerTime.UnixMilli(), record.nextDue)
	if err != nil {
		return err
	}

	repaired, ok := value.(int64)
	if !ok || (repaired != 0 && repaired != 1) {
		return newStateError(RedisErrorKindAmbiguousState, scriptReap, "invalid index repair result", nil)
	}

	if repaired == 0 || record.nextDue > 0 {
		return nil
	}

	for _, key := range []string{record.backendSessionsKey, record.userSessionsKey} {
		if key == "" {
			continue
		}

		if !strings.HasPrefix(key, s.keys.namespaceBase()+":idx:") {
			return newStateError(RedisErrorKindAmbiguousState, scriptReap, "secondary index namespace mismatch", nil)
		}

		if err := s.runRequiredRepairableIndexCommand(ctx, "reap_membership_remove", func(ctx context.Context) error {
			return s.client.SRem(ctx, key, sessionID, encodeBackendSessionIndexMember(sessionID, record.sessionKey)).Err()
		}); err != nil {
			return err
		}
	}

	return nil
}

// reapIndexedSession performs the authority mutation in the session's own slot before index repair.
func (s *RedisSessionStore) reapIndexedSession(ctx context.Context, indexKey, dueKey, sessionID string, now time.Time) (ReapRecord, error) {
	keys, err := s.indexedSessionKeys(ctx, indexKey, sessionID)
	if err != nil {
		return ReapRecord{}, err
	}

	record := ReapRecord{Status: statusReaped, ScannedSessions: 1, StaleIndexEntries: 1, ServerTime: now}

	if len(keys) > 0 {
		value, runErr := s.runScript(ctx, scriptReap, keys, sessionID)
		if runErr != nil {
			return ReapRecord{}, runErr
		}

		record, err = parseReapRecord(value)
		if err != nil {
			return ReapRecord{}, err
		}

		record.sessionKey = keys[2]
	}

	record.RepairedBackends = s.releaseReapedBackendReservations(ctx, record.releases)
	s.removeReapedSessionAggregates(ctx, record.aggregateRemovals)
	s.addReapedIdleAffinities(ctx, record.idleAffinities)

	if err := s.removeReapedIndexes(ctx, indexKey, dueKey, sessionID, record); err != nil {
		return ReapRecord{}, err
	}

	return record, nil
}

// dueSessionCandidates batches bounded, advisory index reads without running a script per empty shard.
func (s *RedisSessionStore) dueSessionCandidates(ctx context.Context, now time.Time, limit int) ([]*redis.StringSliceCmd, error) {
	commands := make([]*redis.StringSliceCmd, 0, s.keys.sessionIndexShards)

	_, err := s.client.Pipelined(redisContext(ctx), func(pipe redis.Pipeliner) error {
		for _, key := range s.keys.SessionDueIndexShardKeys() {
			commands = append(commands, pipe.ZRangeByScore(ctx, key, &redis.ZRangeBy{Min: "-inf", Max: strconv.FormatInt(now.UnixMilli(), 10), Count: int64(limit)}))
		}

		return nil
	})
	if err != nil {
		return nil, ClassifyRedisError(scriptReap, err)
	}

	return commands, nil
}
