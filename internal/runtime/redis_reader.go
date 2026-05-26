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
	"context"
	"strings"

	"github.com/croessner/nauthilus-director/internal/state"
)

const (
	operationSessionRead = "session_read"
	operationUserRead    = "user_read"
)

// RedisRuntimeReader adapts Redis state read models to REST runtime readers.
type RedisRuntimeReader struct {
	store redisRuntimeReadStore
}

type redisRuntimeReadStore interface {
	ListRuntimeSessions(ctx context.Context, protocol string) ([]state.RuntimeSessionRecord, error)
	GetRuntimeSession(ctx context.Context, sessionID string) (state.RuntimeSessionRecord, bool, error)
	ListRuntimeSessionsForUser(ctx context.Context, key state.AffinityKey) ([]state.RuntimeSessionRecord, error)
	ListRuntimeUsers(ctx context.Context) ([]state.RuntimeUserReadRecord, error)
	GetRuntimeUser(ctx context.Context, key state.AffinityKey) (state.RuntimeUserReadRecord, bool, error)
}

// NewRedisRuntimeReader creates a runtime reader over Redis-backed state.
func NewRedisRuntimeReader(store redisRuntimeReadStore) *RedisRuntimeReader {
	return &RedisRuntimeReader{store: store}
}

// ListSessions returns active sessions visible through Redis runtime state.
func (r *RedisRuntimeReader) ListSessions(ctx context.Context, protocol string) ([]SessionRuntimeState, error) {
	if r == nil || r.store == nil {
		return nil, newRuntimeError(ErrorKindUnavailable, operationSessionRead, "session reader unavailable")
	}

	records, err := r.store.ListRuntimeSessions(ctx, protocol)
	if err != nil {
		return nil, err
	}

	sessions := make([]SessionRuntimeState, 0, len(records))
	for _, record := range records {
		sessions = append(sessions, sessionRuntimeStateFromRedis(record))
	}

	return sessions, nil
}

// GetSession returns one active session visible through Redis runtime state.
func (r *RedisRuntimeReader) GetSession(ctx context.Context, sessionID string) (SessionRuntimeState, error) {
	if r == nil || r.store == nil {
		return SessionRuntimeState{}, newRuntimeError(ErrorKindUnavailable, operationSessionRead, "session reader unavailable")
	}

	record, ok, err := r.store.GetRuntimeSession(ctx, sessionID)
	if err != nil {
		return SessionRuntimeState{}, err
	}

	if !ok {
		return SessionRuntimeState{}, newRuntimeError(ErrorKindNotFound, operationSessionRead, "session not found")
	}

	return sessionRuntimeStateFromRedis(record), nil
}

// ListUserSessions returns active sessions for one Redis affinity key.
func (r *RedisRuntimeReader) ListUserSessions(ctx context.Context, key UserKey) ([]SessionRuntimeState, error) {
	if r == nil || r.store == nil {
		return nil, newRuntimeError(ErrorKindUnavailable, operationSessionRead, "session reader unavailable")
	}

	key = key.Normalize()

	records, err := r.store.ListRuntimeSessionsForUser(ctx, state.AffinityKey{Tenant: key.Tenant, AccountKey: key.UserHash})
	if err != nil {
		return nil, err
	}

	sessions := make([]SessionRuntimeState, 0, len(records))
	for _, record := range records {
		sessions = append(sessions, sessionRuntimeStateFromRedis(record))
	}

	return sessions, nil
}

// ListUsers returns users with currently visible Redis runtime state.
func (r *RedisRuntimeReader) ListUsers(ctx context.Context) ([]UserRuntimeState, error) {
	if r == nil || r.store == nil {
		return nil, newRuntimeError(ErrorKindUnavailable, operationUserRead, "user reader unavailable")
	}

	records, err := r.store.ListRuntimeUsers(ctx)
	if err != nil {
		return nil, err
	}

	users := make([]UserRuntimeState, 0, len(records))
	for _, record := range records {
		users = append(users, userRuntimeStateFromRedisRead(record))
	}

	return users, nil
}

// GetUser returns one user's current affinity view.
func (r *RedisRuntimeReader) GetUser(ctx context.Context, key UserKey) (UserRuntimeState, error) {
	return r.GetUserAffinity(ctx, key)
}

// GetUserAffinity reads one user's active affinity without refreshing leases.
func (r *RedisRuntimeReader) GetUserAffinity(ctx context.Context, key UserKey) (UserRuntimeState, error) {
	if r == nil || r.store == nil {
		return UserRuntimeState{}, newRuntimeError(ErrorKindUnavailable, operationUserRead, "user reader unavailable")
	}

	key = key.Normalize()

	record, ok, err := r.store.GetRuntimeUser(ctx, state.AffinityKey{Tenant: key.Tenant, AccountKey: key.UserHash})
	if err != nil {
		return UserRuntimeState{}, err
	}

	if !ok {
		return UserRuntimeState{}, newRuntimeError(ErrorKindNotFound, operationUserRead, "user affinity not found")
	}

	return userRuntimeStateFromRedisRead(record), nil
}

// sessionRuntimeStateFromRedis maps Redis read state into the runtime REST model.
func sessionRuntimeStateFromRedis(record state.RuntimeSessionRecord) SessionRuntimeState {
	return SessionRuntimeState{
		SessionID:         record.SessionID,
		UserHash:          record.Key.AccountKey,
		Tenant:            record.Key.Tenant,
		Protocol:          record.Protocol,
		ListenerName:      record.ListenerName,
		ServiceName:       record.ServiceName,
		EffectiveShardTag: record.ShardTag,
		BackendIdentifier: record.BackendIdentifier,
		DirectorInstance:  record.DirectorInstance,
		OpenedAt:          record.OpenedAt,
		LeaseExpiresAt:    record.LeaseExpiresAt,
		ControlGeneration: record.ControlGeneration,
		Status:            sessionStatusFromRedis(record.Status),
	}.Normalize()
}

// userRuntimeStateFromRedisRead maps Redis affinity reads into runtime user state.
func userRuntimeStateFromRedisRead(record state.RuntimeUserReadRecord) UserRuntimeState {
	return UserRuntimeState{
		Key: UserKey{
			Tenant:   record.Key.Tenant,
			UserHash: record.Key.AccountKey,
		}.Normalize(),
		ActiveShard:        record.ShardTag,
		ActiveSessionCount: record.ActiveSessionCount,
		Generation:         record.Generation,
		UpdatedAt:          record.UpdatedAt,
	}
}

// sessionStatusFromRedis normalizes Redis session status into public runtime status.
func sessionStatusFromRedis(value string) SessionStatus {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(SessionStatusClosing):
		return SessionStatusClosing
	case string(SessionStatusExpired):
		return SessionStatusExpired
	default:
		return SessionStatusActive
	}
}
