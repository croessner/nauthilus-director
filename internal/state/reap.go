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
	"time"
)

const scriptReap = "reap"

// ReapSessions repairs expired session leases, counts and listing indexes.
func (s *RedisSessionStore) ReapSessions(ctx context.Context, request ReapRequest) (ReapRecord, error) {
	if request.Limit <= 0 {
		return ReapRecord{}, newStateError(RedisErrorKindAmbiguousState, scriptReap, "limit must be greater than zero", nil)
	}

	remaining := request.Limit

	deadline := time.Time{}
	if request.MaxPassDuration > 0 {
		deadline = time.Now().Add(request.MaxPassDuration)
	}

	total := ReapRecord{Status: "reaped"}

	for shard := 0; shard < s.keys.sessionIndexShards && remaining > 0; shard++ {
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			break
		}

		sessionIndexKey, err := s.keys.SessionIndexShardKeyByNumber(shard)
		if err != nil {
			return ReapRecord{}, err
		}

		sessionDueIndexKey, err := s.keys.SessionDueIndexShardKeyByNumber(shard)
		if err != nil {
			return ReapRecord{}, err
		}

		value, err := s.runScript(ctx, scriptReap, []string{sessionIndexKey, sessionDueIndexKey}, remaining)
		if err != nil {
			return ReapRecord{}, err
		}

		record, err := parseReapRecord(value)
		if err != nil {
			return ReapRecord{}, err
		}

		total.ScannedSessions += record.ScannedSessions
		total.ExpiredSessions += record.ExpiredSessions
		total.RepairedBackends += record.RepairedBackends
		total.ServerTime = record.ServerTime

		if total.ScannedSessions > 0 {
			total.Status = record.Status
		}

		remaining -= record.ScannedSessions
	}

	return total, nil
}

// parseReapRecord converts the expired-session repair payload.
func parseReapRecord(value any) (ReapRecord, error) {
	fields, err := parseScriptFields(value)
	if err != nil {
		return ReapRecord{}, err
	}

	record := ReapRecord{Status: fields["status"]}
	if record.Status == "" {
		return ReapRecord{}, newStateError(RedisErrorKindAmbiguousState, "script_result", "status required", nil)
	}

	record.ScannedSessions, err = parseIntField(fields, "scanned_sessions")
	if err != nil {
		return ReapRecord{}, err
	}

	record.ExpiredSessions, err = parseIntField(fields, "expired_sessions")
	if err != nil {
		return ReapRecord{}, err
	}

	record.RepairedBackends, err = parseIntField(fields, "repaired_backends")
	if err != nil {
		return ReapRecord{}, err
	}

	record.ServerTime, err = parseTimeField(fields, "server_time_ms")
	if err != nil {
		return ReapRecord{}, err
	}

	return record, nil
}
