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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/croessner/nauthilus-director/internal/state"
)

const (
	operationSessionRead = "session_read"
	operationUserRead    = "user_read"
)

const (
	defaultRuntimeReadPageLimit = 100
	maxRuntimeReadPageLimit     = 1000
)

const (
	publicRuntimeCursorVersion        = 1
	publicRuntimeCursorFamilySessions = "sessions"
	publicRuntimeCursorFamilyUsers    = "users"
	publicRuntimeCursorMACKeyBytes    = 32
)

var publicRuntimeCursorMACKey = newPublicRuntimeCursorMACKey()

// RedisRuntimeReader adapts Redis state read models to REST runtime readers.
type RedisRuntimeReader struct {
	store redisRuntimeReadStore
}

type redisRuntimeReadStore interface {
	ListRuntimeSessionsPage(ctx context.Context, request state.RuntimeSessionPageRequest) (state.RuntimeSessionPage, error)
	ListRuntimeSessionsForBackendPage(ctx context.Context, backendIdentifier string, request state.RuntimeSessionPageRequest) (state.RuntimeSessionPage, error)
	GetRuntimeSession(ctx context.Context, sessionID string) (state.RuntimeSessionRecord, bool, error)
	ListRuntimeSessionsForUser(ctx context.Context, key state.AffinityKey) ([]state.RuntimeSessionRecord, error)
	ListRuntimeUsersPage(ctx context.Context, request state.RuntimeUserPageRequest) (state.RuntimeUserPage, error)
	GetRuntimeUser(ctx context.Context, key state.AffinityKey) (state.RuntimeUserReadRecord, bool, error)
	RuntimeReadPageLimits() state.RuntimeReadPageLimits
	RuntimeAggregateSummary(ctx context.Context) (state.RuntimeAggregateSummary, error)
}

type publicRuntimeReadCursor struct {
	Version     int    `json:"v"`
	Family      string `json:"f"`
	ScopeDigest string `json:"q"`
	StateCursor string `json:"s"`
}

// NewRedisRuntimeReader creates a runtime reader over Redis-backed state.
func NewRedisRuntimeReader(store redisRuntimeReadStore) *RedisRuntimeReader {
	return &RedisRuntimeReader{store: store}
}

// ListSessions returns active sessions visible through Redis runtime state.
func (r *RedisRuntimeReader) ListSessions(ctx context.Context, request SessionListRequest) (SessionListResult, error) {
	if r == nil || r.store == nil {
		return SessionListResult{}, newRuntimeError(ErrorKindUnavailable, operationSessionRead, "session reader unavailable")
	}

	limit, err := normalizeRuntimeReadLimit(request.Limit, r.store.RuntimeReadPageLimits(), operationSessionRead)
	if err != nil {
		return SessionListResult{}, err
	}

	request.Protocol = strings.ToLower(strings.TrimSpace(request.Protocol))
	request.BackendIdentifier = strings.TrimSpace(request.BackendIdentifier)
	scope := sessionRuntimeCursorScope(request)

	stateCursor, err := decodePublicRuntimeReadCursor(request.Cursor, publicRuntimeCursorFamilySessions, scope, operationSessionRead)
	if err != nil {
		return SessionListResult{}, err
	}

	pageRequest := state.RuntimeSessionPageRequest{
		Protocol: request.Protocol,
		Limit:    limit,
		Cursor:   stateCursor,
	}

	var page state.RuntimeSessionPage
	if request.BackendIdentifier != "" {
		page, err = r.store.ListRuntimeSessionsForBackendPage(ctx, request.BackendIdentifier, pageRequest)
	} else {
		page, err = r.store.ListRuntimeSessionsPage(ctx, pageRequest)
	}

	if err != nil {
		return SessionListResult{}, err
	}

	sessions := make([]SessionRuntimeState, 0, len(page.Records))
	for _, record := range page.Records {
		sessions = append(sessions, sessionRuntimeStateFromRedis(record))
	}

	sort.Slice(sessions, func(left int, right int) bool {
		return sessions[left].SessionID < sessions[right].SessionID
	})

	return SessionListResult{
		Sessions:   sessions,
		NextCursor: encodePublicRuntimeReadCursor(publicRuntimeCursorFamilySessions, scope, page.NextCursor),
	}, nil
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
func (r *RedisRuntimeReader) ListUsers(ctx context.Context, request UserListRequest) (UserListResult, error) {
	if r == nil || r.store == nil {
		return UserListResult{}, newRuntimeError(ErrorKindUnavailable, operationUserRead, "user reader unavailable")
	}

	limit, err := normalizeRuntimeReadLimit(request.Limit, r.store.RuntimeReadPageLimits(), operationUserRead)
	if err != nil {
		return UserListResult{}, err
	}

	scope := userRuntimeCursorScope()

	stateCursor, err := decodePublicRuntimeReadCursor(request.Cursor, publicRuntimeCursorFamilyUsers, scope, operationUserRead)
	if err != nil {
		return UserListResult{}, err
	}

	page, err := r.store.ListRuntimeUsersPage(ctx, state.RuntimeUserPageRequest{
		Limit:  limit,
		Cursor: stateCursor,
	})
	if err != nil {
		return UserListResult{}, err
	}

	users := make([]UserRuntimeState, 0, len(page.Records))
	for _, record := range page.Records {
		users = append(users, userRuntimeStateFromRedisRead(record))
	}

	sort.Slice(users, func(left int, right int) bool {
		if users[left].Key.Tenant == users[right].Key.Tenant {
			return users[left].Key.UserHash < users[right].Key.UserHash
		}

		return users[left].Key.Tenant < users[right].Key.Tenant
	})

	return UserListResult{
		Users:      users,
		NextCursor: encodePublicRuntimeReadCursor(publicRuntimeCursorFamilyUsers, scope, page.NextCursor),
	}, nil
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

// RuntimeSummary returns repairable operator totals without listing sessions.
func (r *RedisRuntimeReader) RuntimeSummary(ctx context.Context) (Summary, error) {
	if r == nil || r.store == nil {
		return Summary{}, newRuntimeError(ErrorKindUnavailable, operationRuntimeSummary, "runtime summary reader unavailable")
	}

	summary, err := r.store.RuntimeAggregateSummary(ctx)
	if err != nil {
		return Summary{}, err
	}

	return runtimeSummaryFromState(summary), nil
}

// runtimeSummaryFromState maps state aggregate summaries into runtime domain values.
func runtimeSummaryFromState(summary state.RuntimeAggregateSummary) Summary {
	return Summary{
		GeneratedAt:      summary.GeneratedAt,
		RoutingAuthority: summary.RoutingAuthority,
		ActiveSessions: ActiveSessionSummary{
			Total:      runtimeCountFromState(summary.ActiveSessions.Total),
			ByProtocol: runtimeDimensionCountsFromState(summary.ActiveSessions.ByProtocol),
			ByListener: runtimeDimensionCountsFromState(summary.ActiveSessions.ByListener),
			ByService:  runtimeDimensionCountsFromState(summary.ActiveSessions.ByService),
			ByShardTag: runtimeDimensionCountsFromState(summary.ActiveSessions.ByShardTag),
		},
		IdleAffinities:  runtimeCountFromState(summary.IdleAffinities),
		BackendCapacity: runtimeBackendCapacityFromState(summary.BackendCapacity),
		Repairs: RepairSummary{
			ExpiredSessions:     runtimeCountFromState(summary.Repairs.ExpiredSessions),
			StaleIndexEntries:   runtimeCountFromState(summary.Repairs.StaleIndexEntries),
			BackendReservations: runtimeCountFromState(summary.Repairs.BackendReservations),
		},
	}
}

// runtimeCountFromState maps one state count summary into runtime domain values.
func runtimeCountFromState(count state.RuntimeCountSummary) CountSummary {
	return CountSummary{Count: count.Count, Accuracy: count.Accuracy}
}

// runtimeDimensionCountsFromState maps dimension aggregate counts into runtime values.
func runtimeDimensionCountsFromState(counts []state.RuntimeDimensionCount) []DimensionCount {
	mapped := make([]DimensionCount, 0, len(counts))
	for _, count := range counts {
		mapped = append(mapped, DimensionCount{
			Value:    count.Value,
			Count:    count.Count,
			Accuracy: count.Accuracy,
		})
	}

	return mapped
}

// runtimeBackendCapacityFromState maps backend capacity aggregate counts into runtime values.
func runtimeBackendCapacityFromState(counts []state.RuntimeBackendCapacitySummary) []BackendCapacitySummary {
	mapped := make([]BackendCapacitySummary, 0, len(counts))
	for _, count := range counts {
		mapped = append(mapped, BackendCapacitySummary{
			BackendIdentifier: count.BackendIdentifier,
			ActiveSessions:    runtimeCountFromState(count.ActiveSessions),
			ReservedSessions:  runtimeCountFromState(count.ReservedSessions),
			SummaryRepairable: count.SummaryRepairable,
			RoutingAuthority:  count.RoutingAuthority,
		})
	}

	return mapped
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

// normalizeRuntimeReadLimit applies default and hard maximum page sizes.
func normalizeRuntimeReadLimit(limit int, configured state.RuntimeReadPageLimits, operation string) (int, error) {
	if configured.Default <= 0 {
		configured.Default = defaultRuntimeReadPageLimit
	}

	if configured.Max <= 0 {
		configured.Max = maxRuntimeReadPageLimit
	}

	if configured.Default > configured.Max {
		configured.Default = configured.Max
	}

	switch {
	case limit < 0:
		return 0, newRuntimeError(ErrorKindInvalidRequest, operation, "limit must be greater than zero")
	case limit == 0:
		return configured.Default, nil
	case limit > configured.Max:
		return 0, newRuntimeError(ErrorKindInvalidRequest, operation, fmt.Sprintf("limit must not exceed %d", configured.Max))
	default:
		return limit, nil
	}
}

// sessionRuntimeCursorScope creates a query-shape digest without raw filter values.
func sessionRuntimeCursorScope(request SessionListRequest) string {
	return runtimeCursorScope(
		publicRuntimeCursorFamilySessions,
		strings.ToLower(strings.TrimSpace(request.Protocol)),
		strings.TrimSpace(request.BackendIdentifier),
	)
}

// userRuntimeCursorScope creates the cursor scope for runtime user lists.
func userRuntimeCursorScope() string {
	return runtimeCursorScope(publicRuntimeCursorFamilyUsers)
}

// runtimeCursorScope hashes request shape so cursors cannot cross filters.
func runtimeCursorScope(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		hash.Write([]byte(part))
		hash.Write([]byte{0})
	}

	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}

// encodePublicRuntimeReadCursor wraps an internal state cursor for REST clients.
func encodePublicRuntimeReadCursor(family string, scope string, stateCursor string) string {
	if strings.TrimSpace(stateCursor) == "" {
		return ""
	}

	payload, err := json.Marshal(publicRuntimeReadCursor{
		Version:     publicRuntimeCursorVersion,
		Family:      family,
		ScopeDigest: scope,
		StateCursor: stateCursor,
	})
	if err != nil {
		return ""
	}

	mac := hmac.New(sha256.New, publicRuntimeCursorMACKey)
	mac.Write(payload)

	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// decodePublicRuntimeReadCursor verifies a public cursor and returns state position data.
func decodePublicRuntimeReadCursor(raw string, family string, scope string, operation string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}

	payload, actualMAC, err := decodePublicRuntimeCursorParts(raw)
	if err != nil {
		return "", invalidRuntimeCursor(operation)
	}

	if !publicRuntimeCursorMACValid(payload, actualMAC) {
		return "", invalidRuntimeCursor(operation)
	}

	var cursor publicRuntimeReadCursor
	if err := json.Unmarshal(payload, &cursor); err != nil {
		return "", invalidRuntimeCursor(operation)
	}

	if !cursor.validFor(family, scope) {
		return "", invalidRuntimeCursor(operation)
	}

	return cursor.StateCursor, nil
}

// decodePublicRuntimeCursorParts decodes public cursor payload and MAC sections.
func decodePublicRuntimeCursorParts(raw string) ([]byte, []byte, error) {
	payloadText, macText, ok := strings.Cut(raw, ".")
	if !ok || payloadText == "" || macText == "" {
		return nil, nil, invalidRuntimeCursor("")
	}

	payload, err := base64.RawURLEncoding.DecodeString(payloadText)
	if err != nil {
		return nil, nil, err
	}

	actualMAC, err := base64.RawURLEncoding.DecodeString(macText)
	if err != nil {
		return nil, nil, err
	}

	return payload, actualMAC, nil
}

// publicRuntimeCursorMACValid verifies the cursor integrity tag.
func publicRuntimeCursorMACValid(payload []byte, actualMAC []byte) bool {
	expectedMAC := hmac.New(sha256.New, publicRuntimeCursorMACKey)
	expectedMAC.Write(payload)

	return hmac.Equal(actualMAC, expectedMAC.Sum(nil))
}

// validFor checks cursor version, family, scope and state payload presence.
func (c publicRuntimeReadCursor) validFor(family string, scope string) bool {
	return c.Version == publicRuntimeCursorVersion &&
		c.Family == family &&
		c.ScopeDigest == scope &&
		strings.TrimSpace(c.StateCursor) != ""
}

// invalidRuntimeCursor returns the stable client error for malformed cursors.
func invalidRuntimeCursor(operation string) error {
	return newRuntimeError(ErrorKindInvalidRequest, operation, "cursor invalid")
}

// newPublicRuntimeCursorMACKey creates the process-local cursor integrity key.
func newPublicRuntimeCursorMACKey() []byte {
	key := make([]byte, publicRuntimeCursorMACKeyBytes)
	if _, err := rand.Read(key); err != nil {
		panic(fmt.Sprintf("runtime cursor integrity key unavailable: %v", err))
	}

	return key
}
