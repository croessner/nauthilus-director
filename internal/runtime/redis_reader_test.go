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
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/state"
)

const (
	runtimeReaderCursorInvalid = "not-a-valid-cursor"
	runtimeReaderSessionA      = "session-a"
	runtimeReaderSessionB      = "session-b"
	runtimeReaderStateCursorB  = "state-cursor-b"
	runtimeReaderUserA         = "user-a"
	runtimeReaderUserB         = "user-b"
	runtimeReaderUserCursor    = "user-state-cursor"
	runtimeReaderShardTag      = "shard-a"
)

// TestRedisRuntimeReaderListSessionsUsesPagedStore verifies public cursors wrap state cursors.
func TestRedisRuntimeReaderListSessionsUsesPagedStore(t *testing.T) {
	store := &pagedRuntimeReadStore{
		limits: state.RuntimeReadPageLimits{Default: 2, Max: 3},
		sessionPage: state.RuntimeSessionPage{
			Records: []state.RuntimeSessionRecord{
				runtimeReaderSessionRecord(runtimeReaderSessionB),
				runtimeReaderSessionRecord(runtimeReaderSessionA),
			},
			NextCursor: runtimeReaderStateCursorB,
		},
	}
	reader := NewRedisRuntimeReader(store)

	result, err := reader.ListSessions(context.Background(), SessionListRequest{
		Protocol:          "IMAP",
		BackendIdentifier: runtimeTestBackendIdentifier,
		Limit:             2,
	})
	if err != nil {
		t.Fatalf("ListSessions returned error: %v", err)
	}

	assertSessionPageRequest(t, store, listenerTestIMAPName, 2, "")
	assertSessionListResult(t, result, runtimeReaderSessionA, runtimeReaderSessionB)

	if result.NextCursor == "" || strings.Contains(result.NextCursor, "state-cursor-b") {
		t.Fatalf("next cursor = %q, want opaque public cursor", result.NextCursor)
	}
}

// TestRedisRuntimeReaderListSessionsAcceptsPublicCursor verifies cursor unwrapping.
func TestRedisRuntimeReaderListSessionsAcceptsPublicCursor(t *testing.T) {
	store := &pagedRuntimeReadStore{
		limits:      state.RuntimeReadPageLimits{Default: 2, Max: 3},
		sessionPage: state.RuntimeSessionPage{NextCursor: runtimeReaderStateCursorB},
	}
	reader := NewRedisRuntimeReader(store)

	first, err := reader.ListSessions(context.Background(), SessionListRequest{BackendIdentifier: runtimeTestBackendIdentifier})
	if err != nil {
		t.Fatalf("ListSessions returned error: %v", err)
	}

	store.sessionPage = state.RuntimeSessionPage{}

	if _, err := reader.ListSessions(context.Background(), SessionListRequest{
		BackendIdentifier: runtimeTestBackendIdentifier,
		Cursor:            first.NextCursor,
	}); err != nil {
		t.Fatalf("ListSessions with public cursor returned error: %v", err)
	}

	if store.sessionPageRequest.Cursor != runtimeReaderStateCursorB {
		t.Fatalf("state cursor = %q, want wrapped cursor", store.sessionPageRequest.Cursor)
	}
}

// TestRedisRuntimeReaderRejectsTamperedPublicCursor verifies public cursor integrity.
func TestRedisRuntimeReaderRejectsTamperedPublicCursor(t *testing.T) {
	store := &pagedRuntimeReadStore{
		limits:      state.RuntimeReadPageLimits{Default: 2, Max: 3},
		sessionPage: state.RuntimeSessionPage{NextCursor: runtimeReaderStateCursorB},
	}
	reader := NewRedisRuntimeReader(store)

	first, err := reader.ListSessions(context.Background(), SessionListRequest{})
	if err != nil {
		t.Fatalf("ListSessions returned error: %v", err)
	}

	_, err = reader.ListSessions(context.Background(), SessionListRequest{Cursor: tamperRuntimeCursor(first.NextCursor)})
	if !IsErrorKind(err, ErrorKindInvalidRequest) {
		t.Fatalf("ListSessions tampered cursor error = %v, want invalid request", err)
	}
}

// TestRedisRuntimeReaderListUsersUsesPagedStore verifies user pages do not derive from sessions.
func TestRedisRuntimeReaderListUsersUsesPagedStore(t *testing.T) {
	store := &pagedRuntimeReadStore{
		limits: state.RuntimeReadPageLimits{Default: 1, Max: 3},
		userPage: state.RuntimeUserPage{
			Records: []state.RuntimeUserReadRecord{
				runtimeReaderUserRecord("tenant-b", runtimeReaderUserB),
				runtimeReaderUserRecord("tenant-a", runtimeReaderUserA),
			},
			NextCursor: runtimeReaderUserCursor,
		},
	}
	reader := NewRedisRuntimeReader(store)

	result, err := reader.ListUsers(context.Background(), UserListRequest{})
	if err != nil {
		t.Fatalf("ListUsers returned error: %v", err)
	}

	if store.userPageCalls != 1 || store.userPageRequest.Limit != 1 {
		t.Fatalf("user page calls=%d request=%#v, want one default-limited page", store.userPageCalls, store.userPageRequest)
	}

	if len(result.Users) != 2 || result.Users[0].Key.UserHash != runtimeReaderUserA || result.Users[1].Key.UserHash != runtimeReaderUserB {
		t.Fatalf("users = %#v, want deterministic key order", result.Users)
	}

	if result.NextCursor == "" {
		t.Fatal("next cursor was empty")
	}
}

// TestRedisRuntimeReaderRejectsBadCursorAndLimit verifies stable client errors.
func TestRedisRuntimeReaderRejectsBadCursorAndLimit(t *testing.T) {
	store := &pagedRuntimeReadStore{limits: state.RuntimeReadPageLimits{Default: 1, Max: 3}}
	reader := NewRedisRuntimeReader(store)

	if _, err := reader.ListSessions(context.Background(), SessionListRequest{Cursor: runtimeReaderCursorInvalid}); !IsErrorKind(err, ErrorKindInvalidRequest) {
		t.Fatalf("ListSessions bad cursor error = %v, want invalid request", err)
	}

	if _, err := reader.ListUsers(context.Background(), UserListRequest{Limit: 4}); !IsErrorKind(err, ErrorKindInvalidRequest) {
		t.Fatalf("ListUsers excessive limit error = %v, want invalid request", err)
	}

	if store.sessionPageCalls != 0 || store.userPageCalls != 0 {
		t.Fatalf("store calls after rejected input: session=%d user=%d", store.sessionPageCalls, store.userPageCalls)
	}
}

// TestRedisRuntimeReaderSummaryUsesAggregateStore verifies summary reads avoid paged lists.
func TestRedisRuntimeReaderSummaryUsesAggregateStore(t *testing.T) {
	store := &pagedRuntimeReadStore{
		summary: state.RuntimeAggregateSummary{
			RoutingAuthority: false,
			ActiveSessions: state.RuntimeActiveSessionSummary{
				Total: state.RuntimeCountSummary{Count: 5, Accuracy: AccuracyEventuallyRepaired},
			},
		},
	}
	reader := NewRedisRuntimeReader(store)

	summary, err := reader.RuntimeSummary(context.Background())
	if err != nil {
		t.Fatalf("RuntimeSummary returned error: %v", err)
	}

	if store.summaryCalls != 1 || store.sessionPageCalls != 0 || store.userPageCalls != 0 {
		t.Fatalf("calls summary=%d sessions=%d users=%d, want summary only", store.summaryCalls, store.sessionPageCalls, store.userPageCalls)
	}

	if summary.ActiveSessions.Total.Count != 5 || summary.RoutingAuthority {
		t.Fatalf("summary = %#v, want non-authority aggregate total", summary)
	}
}

type pagedRuntimeReadStore struct {
	limits                  state.RuntimeReadPageLimits
	sessionPage             state.RuntimeSessionPage
	userPage                state.RuntimeUserPage
	summary                 state.RuntimeAggregateSummary
	sessionPageRequest      state.RuntimeSessionPageRequest
	userPageRequest         state.RuntimeUserPageRequest
	backendIdentifier       string
	sessionPageCalls        int
	backendSessionPageCalls int
	userPageCalls           int
	summaryCalls            int
}

// ListRuntimeSessionsPage records global session page requests.
func (s *pagedRuntimeReadStore) ListRuntimeSessionsPage(_ context.Context, request state.RuntimeSessionPageRequest) (state.RuntimeSessionPage, error) {
	s.sessionPageCalls++
	s.sessionPageRequest = request

	return s.sessionPage, nil
}

// ListRuntimeSessionsForBackendPage records backend-scoped page requests.
func (s *pagedRuntimeReadStore) ListRuntimeSessionsForBackendPage(
	_ context.Context,
	backendIdentifier string,
	request state.RuntimeSessionPageRequest,
) (state.RuntimeSessionPage, error) {
	s.backendSessionPageCalls++
	s.backendIdentifier = backendIdentifier
	s.sessionPageRequest = request

	return s.sessionPage, nil
}

// GetRuntimeSession is unused by pagination tests.
func (s *pagedRuntimeReadStore) GetRuntimeSession(context.Context, string) (state.RuntimeSessionRecord, bool, error) {
	return state.RuntimeSessionRecord{}, false, errors.New("unused")
}

// ListRuntimeSessionsForUser is unused by pagination tests.
func (s *pagedRuntimeReadStore) ListRuntimeSessionsForUser(context.Context, state.AffinityKey) ([]state.RuntimeSessionRecord, error) {
	return nil, errors.New("unused")
}

// ListRuntimeUsersPage records user page requests.
func (s *pagedRuntimeReadStore) ListRuntimeUsersPage(_ context.Context, request state.RuntimeUserPageRequest) (state.RuntimeUserPage, error) {
	s.userPageCalls++
	s.userPageRequest = request

	return s.userPage, nil
}

// GetRuntimeUser is unused by pagination tests.
func (s *pagedRuntimeReadStore) GetRuntimeUser(context.Context, state.AffinityKey) (state.RuntimeUserReadRecord, bool, error) {
	return state.RuntimeUserReadRecord{}, false, errors.New("unused")
}

// RuntimeReadPageLimits returns fake configured page limits.
func (s *pagedRuntimeReadStore) RuntimeReadPageLimits() state.RuntimeReadPageLimits {
	return s.limits
}

// RuntimeAggregateSummary records aggregate summary requests.
func (s *pagedRuntimeReadStore) RuntimeAggregateSummary(context.Context) (state.RuntimeAggregateSummary, error) {
	s.summaryCalls++

	return s.summary, nil
}

// runtimeReaderSessionRecord builds one Redis session read fixture.
func runtimeReaderSessionRecord(sessionID string) state.RuntimeSessionRecord {
	return state.RuntimeSessionRecord{
		SessionID:         sessionID,
		Key:               state.AffinityKey{Tenant: defaultTenant, AccountKey: runtimeReaderUserA},
		Protocol:          listenerTestIMAPName,
		ShardTag:          runtimeReaderShardTag,
		BackendIdentifier: runtimeTestBackendIdentifier,
		LeaseExpiresAt:    time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC),
		Status:            "active",
	}
}

// runtimeReaderUserRecord builds one Redis user read fixture.
func runtimeReaderUserRecord(tenant string, accountKey string) state.RuntimeUserReadRecord {
	return state.RuntimeUserReadRecord{
		Key:                state.AffinityKey{Tenant: tenant, AccountKey: accountKey},
		ShardTag:           runtimeReaderShardTag,
		ActiveSessionCount: 1,
		Present:            true,
	}
}

// assertSessionPageRequest verifies the store saw one bounded backend page request.
func assertSessionPageRequest(t *testing.T, store *pagedRuntimeReadStore, protocol string, limit int, cursor string) {
	t.Helper()

	if store.backendSessionPageCalls != 1 {
		t.Fatalf("backend page calls = %d, want 1", store.backendSessionPageCalls)
	}

	if store.backendIdentifier != runtimeTestBackendIdentifier {
		t.Fatalf("backend identifier = %q, want %q", store.backendIdentifier, runtimeTestBackendIdentifier)
	}

	if store.sessionPageRequest.Protocol != protocol ||
		store.sessionPageRequest.Limit != limit ||
		store.sessionPageRequest.Cursor != cursor {
		t.Fatalf("session page request = %#v", store.sessionPageRequest)
	}
}

// assertSessionListResult verifies deterministic session ordering.
func assertSessionListResult(t *testing.T, result SessionListResult, wantFirst string, wantSecond string) {
	t.Helper()

	if len(result.Sessions) != 2 ||
		result.Sessions[0].SessionID != wantFirst ||
		result.Sessions[1].SessionID != wantSecond {
		t.Fatalf("sessions = %#v, want deterministic session-id order", result.Sessions)
	}
}

// tamperRuntimeCursor changes one byte while keeping a non-empty cursor string.
func tamperRuntimeCursor(cursor string) string {
	payloadText, macText, ok := strings.Cut(cursor, ".")
	if !ok {
		return cursor + "A"
	}

	payload, err := base64.RawURLEncoding.DecodeString(payloadText)
	if err != nil || len(payload) == 0 {
		return cursor + "A"
	}

	payload[0] ^= 0x01

	return base64.RawURLEncoding.EncodeToString(payload) + "." + macText
}
