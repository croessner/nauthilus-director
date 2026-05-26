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

import "context"

const scriptReap = "reap"

// ReapSessions repairs expired session leases, counts and listing indexes.
func (s *RedisSessionStore) ReapSessions(ctx context.Context, request ReapRequest) (ReapRecord, error) {
	if request.Limit < 0 {
		return ReapRecord{}, newStateError(RedisErrorKindAmbiguousState, scriptReap, "limit must not be negative", nil)
	}

	value, err := s.runScript(ctx, scriptReap, []string{s.keys.SessionIndexKey()}, request.Limit)
	if err != nil {
		return ReapRecord{}, err
	}

	return parseReapRecord(value)
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
