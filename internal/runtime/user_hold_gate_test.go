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
	"sync"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/state"
)

const (
	runtimeTestHoldStatusFound = "found"
	runtimeTestOtherUserHash   = "hash-b"
	runtimeTestPlacementMail   = "mail"
)

// TestPlacementGateWithoutHoldContinuesImmediately verifies normal placement is unchanged.
func TestPlacementGateWithoutHoldContinuesImmediately(t *testing.T) {
	key := UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash}
	store := newTestUserHoldStore(false)
	service := newTestUserHoldService(t, store, UserHoldServiceConfig{
		Enabled:                true,
		MaxDuration:            time.Minute,
		MaxWait:                time.Second,
		PollInterval:           10 * time.Millisecond,
		MaxLocalWaiters:        2,
		MaxLocalWaitersPerUser: 1,
	})

	result, err := service.WaitForPlacement(context.Background(), testPlacementGateRequest(key))
	if err != nil {
		t.Fatalf("WaitForPlacement returned error: %v", err)
	}

	if result.Outcome != PlacementGateOutcomeAllowed || result.RuntimeStateRecheckRequired {
		t.Fatalf("placement result = %#v, want allowed without recheck", result)
	}

	if store.checkCount() != 1 {
		t.Fatalf("hold checks = %d, want one initial check", store.checkCount())
	}
}

// TestPlacementGateActiveHoldDoesNotBlockUnrelatedUser verifies hold keys stay scoped.
func TestPlacementGateActiveHoldDoesNotBlockUnrelatedUser(t *testing.T) {
	heldKey := UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash}
	otherKey := UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestOtherUserHash}
	store := newTestUserHoldStore(false)
	store.setHeldForKey(heldKey, true)
	service := newTestUserHoldService(t, store, UserHoldServiceConfig{
		Enabled:                true,
		MaxDuration:            time.Minute,
		MaxWait:                25 * time.Millisecond,
		PollInterval:           5 * time.Millisecond,
		MaxLocalWaiters:        2,
		MaxLocalWaitersPerUser: 1,
	})

	result, err := service.WaitForPlacement(context.Background(), testPlacementGateRequest(otherKey))
	if err != nil {
		t.Fatalf("unrelated WaitForPlacement returned error: %v", err)
	}

	if result.Outcome != PlacementGateOutcomeAllowed || result.RuntimeStateRecheckRequired {
		t.Fatalf("unrelated placement result = %#v, want allowed without recheck", result)
	}

	_, err = service.WaitForPlacement(context.Background(), testPlacementGateRequest(heldKey))
	if !IsErrorKind(err, ErrorKindUnavailable) {
		t.Fatalf("held WaitForPlacement error = %v, want temporary unavailable", err)
	}

	assertNoPlacementWaiters(t, service, heldKey)
	assertNoPlacementWaiters(t, service, otherKey)
}

// TestPlacementGateLocalClearReleasesAndRequiresRecheck verifies same-process clear wakes waiters.
func TestPlacementGateLocalClearReleasesAndRequiresRecheck(t *testing.T) {
	key := UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash}
	store := newTestUserHoldStore(true)
	recorder := &recordingRuntimeObservation{}
	service := newObservedTestUserHoldService(t, store, UserHoldServiceConfig{
		Enabled:                true,
		MaxDuration:            time.Minute,
		MaxWait:                time.Second,
		PollInterval:           500 * time.Millisecond,
		MaxLocalWaiters:        2,
		MaxLocalWaitersPerUser: 1,
	}, recorder)

	ctx := t.Context()

	done := make(chan placementGateCall, 1)

	go func() {
		result, err := service.WaitForPlacement(ctx, testPlacementGateRequest(key))
		done <- placementGateCall{result: result, err: err}
	}()

	waitForPlacementWaiters(t, service, key, 1)

	if _, err := service.ClearUserHold(context.Background(), ClearUserHoldRequest{
		Key:    key,
		Reason: runtimeTestHoldReason,
	}); err != nil {
		t.Fatalf("ClearUserHold returned error: %v", err)
	}

	call := readPlacementGateCall(t, done, 120*time.Millisecond)
	if call.err != nil {
		t.Fatalf("WaitForPlacement returned error after local clear: %v", call.err)
	}

	if call.result.Outcome != PlacementGateOutcomeReleased || !call.result.RuntimeStateRecheckRequired {
		t.Fatalf("placement result = %#v, want released with runtime recheck", call.result)
	}

	assertUserHoldObservationReason(t, recorder, routeLookupUserHoldActive)
	assertUserHoldObservationReason(t, recorder, "user_hold_wait_started")
	assertUserHoldObservationReason(t, recorder, "user_hold_wait_released")
	assertNoPlacementWaiters(t, service, key)
}

// TestPlacementGateExpiredHoldReleasesThroughRecheck verifies expired holds do not wait for cleanup TTL.
func TestPlacementGateExpiredHoldReleasesThroughRecheck(t *testing.T) {
	key := UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash}
	store := newTestUserHoldStore(true)
	store.setPresenceSequence([]bool{true, false})
	service := newTestUserHoldService(t, store, UserHoldServiceConfig{
		Enabled:                true,
		MaxDuration:            time.Minute,
		MaxWait:                time.Second,
		PollInterval:           10 * time.Millisecond,
		MaxLocalWaiters:        2,
		MaxLocalWaitersPerUser: 1,
	})

	result, err := service.WaitForPlacement(context.Background(), testPlacementGateRequest(key))
	if err != nil {
		t.Fatalf("WaitForPlacement returned error: %v", err)
	}

	if result.Outcome != PlacementGateOutcomeReleased || !result.RuntimeStateRecheckRequired {
		t.Fatalf("placement result = %#v, want released with runtime recheck", result)
	}

	if store.checkCount() < 2 {
		t.Fatalf("hold checks = %d, want recheck after observed hold", store.checkCount())
	}
}

// TestPlacementGatePollingReleaseWorksWithoutLocalWake verifies cross-process clear needs only polling.
func TestPlacementGatePollingReleaseWorksWithoutLocalWake(t *testing.T) {
	key := UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash}
	store := newTestUserHoldStore(true)
	service := newTestUserHoldService(t, store, UserHoldServiceConfig{
		Enabled:                true,
		MaxDuration:            time.Minute,
		MaxWait:                time.Second,
		PollInterval:           15 * time.Millisecond,
		MaxLocalWaiters:        2,
		MaxLocalWaitersPerUser: 1,
	})

	done := make(chan placementGateCall, 1)

	go func() {
		result, err := service.WaitForPlacement(context.Background(), testPlacementGateRequest(key))
		done <- placementGateCall{result: result, err: err}
	}()

	waitForPlacementWaiters(t, service, key, 1)

	store.setHeld(false)

	call := readPlacementGateCall(t, done, time.Second)
	if call.err != nil {
		t.Fatalf("WaitForPlacement returned error after polling release: %v", call.err)
	}

	if store.clearCount() != 0 {
		t.Fatalf("clear calls = %d, want no local clear wake-up", store.clearCount())
	}

	if call.result.Outcome != PlacementGateOutcomeReleased || !call.result.RuntimeStateRecheckRequired {
		t.Fatalf("placement result = %#v, want released with runtime recheck", call.result)
	}
}

// TestPlacementGateTimeoutTemporaryFails verifies max_wait does not fall through to routing.
func TestPlacementGateTimeoutTemporaryFails(t *testing.T) {
	key := UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash}
	store := newTestUserHoldStore(true)
	recorder := &recordingRuntimeObservation{}
	service := newObservedTestUserHoldService(t, store, UserHoldServiceConfig{
		Enabled:                true,
		MaxDuration:            time.Minute,
		MaxWait:                25 * time.Millisecond,
		PollInterval:           5 * time.Millisecond,
		MaxLocalWaiters:        2,
		MaxLocalWaitersPerUser: 1,
	}, recorder)

	_, err := service.WaitForPlacement(context.Background(), testPlacementGateRequest(key))
	if !IsErrorKind(err, ErrorKindUnavailable) {
		t.Fatalf("WaitForPlacement error = %v, want temporary unavailable", err)
	}

	assertUserHoldObservationReason(t, recorder, "user_hold_wait_timeout")
	assertNoPlacementWaiters(t, service, key)
}

// TestPlacementGateGlobalWaiterLimitRejectsWithoutQueuing verifies the process-wide bound.
func TestPlacementGateGlobalWaiterLimitRejectsWithoutQueuing(t *testing.T) {
	firstKey := UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash}
	secondKey := UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestOtherUserHash}
	store := newTestUserHoldStore(true)
	recorder := &recordingRuntimeObservation{}
	service := newObservedTestUserHoldService(t, store, UserHoldServiceConfig{
		Enabled:                true,
		MaxDuration:            time.Minute,
		MaxWait:                time.Second,
		PollInterval:           100 * time.Millisecond,
		MaxLocalWaiters:        1,
		MaxLocalWaitersPerUser: 1,
	}, recorder)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan placementGateCall, 1)

	go func() {
		result, err := service.WaitForPlacement(ctx, testPlacementGateRequest(firstKey))
		done <- placementGateCall{result: result, err: err}
	}()

	waitForPlacementWaiters(t, service, firstKey, 1)

	_, err := service.WaitForPlacement(context.Background(), testPlacementGateRequest(secondKey))
	if !IsErrorKind(err, ErrorKindUnavailable) {
		t.Fatalf("second WaitForPlacement error = %v, want waiter-limit temporary failure", err)
	}

	assertUserHoldObservationReason(t, recorder, "user_hold_waiter_limit_exceeded")

	total, perUser := service.waiters.counts(secondKey)
	if total != 1 || perUser != 0 {
		t.Fatalf("waiter counts after global rejection = total:%d per-user:%d, want queued first only", total, perUser)
	}

	cancel()

	_ = readPlacementGateCall(t, done, time.Second)

	assertNoPlacementWaiters(t, service, firstKey)
}

// TestPlacementGatePerUserLimitRejectsWithoutQueuing verifies one affinity cannot exhaust all waiters.
func TestPlacementGatePerUserLimitRejectsWithoutQueuing(t *testing.T) {
	key := UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash}
	store := newTestUserHoldStore(true)
	service := newTestUserHoldService(t, store, UserHoldServiceConfig{
		Enabled:                true,
		MaxDuration:            time.Minute,
		MaxWait:                time.Second,
		PollInterval:           100 * time.Millisecond,
		MaxLocalWaiters:        2,
		MaxLocalWaitersPerUser: 1,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan placementGateCall, 1)

	go func() {
		result, err := service.WaitForPlacement(ctx, testPlacementGateRequest(key))
		done <- placementGateCall{result: result, err: err}
	}()

	waitForPlacementWaiters(t, service, key, 1)

	_, err := service.WaitForPlacement(context.Background(), testPlacementGateRequest(key))
	if !IsErrorKind(err, ErrorKindUnavailable) {
		t.Fatalf("second WaitForPlacement error = %v, want per-user waiter-limit temporary failure", err)
	}

	total, perUser := service.waiters.counts(key)
	if total != 1 || perUser != 1 {
		t.Fatalf("waiter counts after per-user rejection = total:%d per-user:%d, want original waiter only", total, perUser)
	}

	cancel()

	_ = readPlacementGateCall(t, done, time.Second)

	assertNoPlacementWaiters(t, service, key)
}

// TestPlacementGateCancellationReleasesWaiterAccounting verifies shutdown-style cancellation is clean.
func TestPlacementGateCancellationReleasesWaiterAccounting(t *testing.T) {
	key := UserKey{Tenant: runtimeTestTenant, UserHash: runtimeTestUserHash}
	store := newTestUserHoldStore(true)
	service := newTestUserHoldService(t, store, UserHoldServiceConfig{
		Enabled:                true,
		MaxDuration:            time.Minute,
		MaxWait:                time.Second,
		PollInterval:           100 * time.Millisecond,
		MaxLocalWaiters:        2,
		MaxLocalWaitersPerUser: 1,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan placementGateCall, 1)

	go func() {
		result, err := service.WaitForPlacement(ctx, testPlacementGateRequest(key))
		done <- placementGateCall{result: result, err: err}
	}()

	waitForPlacementWaiters(t, service, key, 1)
	cancel()

	call := readPlacementGateCall(t, done, time.Second)
	if call.err == nil {
		t.Fatal("WaitForPlacement returned nil after caller cancellation")
	}

	assertNoPlacementWaiters(t, service, key)
}

// newTestUserHoldService builds a gate with focused test policy.
func newTestUserHoldService(t *testing.T, store state.UserHoldStore, config UserHoldServiceConfig) *UserHoldService {
	t.Helper()

	service, err := NewUserHoldService(store, config)
	if err != nil {
		t.Fatalf("NewUserHoldService returned error: %v", err)
	}

	return service
}

// newObservedTestUserHoldService builds a gate with a recording observability sink.
func newObservedTestUserHoldService(
	t *testing.T,
	store state.UserHoldStore,
	config UserHoldServiceConfig,
	recorder *recordingRuntimeObservation,
) *UserHoldService {
	t.Helper()

	service, err := NewUserHoldService(store, config, WithObservabilityRecorder(recorder))
	if err != nil {
		t.Fatalf("NewUserHoldService returned error: %v", err)
	}

	return service
}

// assertUserHoldObservationReason verifies at least one hold event has the expected reason.
func assertUserHoldObservationReason(t *testing.T, recorder *recordingRuntimeObservation, reason string) {
	t.Helper()

	for _, event := range recorder.eventsByName(observability.EventUserHold) {
		if event.MetricLabels["reason_class"] == reason {
			return
		}
	}

	t.Fatalf("user-hold events = %#v, want reason %q", recorder.events, reason)
}

// testPlacementGateRequest returns one valid protocol placement request.
func testPlacementGateRequest(key UserKey) PlacementGateRequest {
	return PlacementGateRequest{
		Key:          key,
		Protocol:     listenerTestIMAPName,
		ListenerName: listenerTestIMAPName,
		ServiceName:  runtimeTestPlacementMail,
	}
}

// waitForPlacementWaiters waits until local waiter accounting reaches the expected count.
func waitForPlacementWaiters(t *testing.T, service *UserHoldService, key UserKey, want int) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		total, perUser := service.waiters.counts(key)
		if perUser == want {
			return
		}

		if total < 0 {
			t.Fatalf("unexpected negative waiter count %d", total)
		}

		time.Sleep(time.Millisecond)
	}

	total, perUser := service.waiters.counts(key)
	t.Fatalf("waiter counts = total:%d per-user:%d, want per-user %d", total, perUser, want)
}

// assertNoPlacementWaiters verifies all local waiter accounting was released.
func assertNoPlacementWaiters(t *testing.T, service *UserHoldService, key UserKey) {
	t.Helper()

	total, perUser := service.waiters.counts(key)
	if total != 0 || perUser != 0 {
		t.Fatalf("waiter counts = total:%d per-user:%d, want zero", total, perUser)
	}
}

// readPlacementGateCall reads one async gate result within a bounded test timeout.
func readPlacementGateCall(t *testing.T, done <-chan placementGateCall, timeout time.Duration) placementGateCall {
	t.Helper()

	select {
	case call := <-done:
		return call
	case <-time.After(timeout):
		t.Fatalf("WaitForPlacement did not finish within %s", timeout)

		return placementGateCall{}
	}
}

type placementGateCall struct {
	result PlacementGateResult
	err    error
}

type testUserHoldStore struct {
	mu               sync.Mutex
	held             bool
	heldKeys         map[state.AffinityKey]bool
	presenceSequence []bool
	checks           int
	clears           int
}

// newTestUserHoldStore creates a mutable in-memory placement-hold read model.
func newTestUserHoldStore(held bool) *testUserHoldStore {
	return &testUserHoldStore{held: held}
}

// SetUserHold records an active hold in the fake state store.
func (s *testUserHoldStore) SetUserHold(
	_ context.Context,
	request state.UserHoldSetRequest,
) (state.UserHoldRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.heldKeys != nil {
		s.heldKeys[request.Key] = true
	} else {
		s.held = true
	}

	return s.recordLocked(request.Key, true), nil
}

// GetUserHold returns the current fake hold without changing waiter state.
func (s *testUserHoldStore) GetUserHold(
	_ context.Context,
	request state.UserHoldGetRequest,
) (state.UserHoldRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.recordLocked(request.Key, s.heldLocked(request.Key)), nil
}

// ClearUserHold clears the fake hold for same-process wake-up tests.
func (s *testUserHoldStore) ClearUserHold(
	_ context.Context,
	request state.UserHoldClearRequest,
) (state.UserHoldRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.heldKeys != nil {
		s.heldKeys[request.Key] = false
	} else {
		s.held = false
	}
	s.clears++

	return s.recordLocked(request.Key, false), nil
}

// CheckUserHold returns a configured sequence or the current mutable hold state.
func (s *testUserHoldStore) CheckUserHold(
	ctx context.Context,
	request state.UserHoldCheckRequest,
) (state.UserHoldRecord, error) {
	select {
	case <-ctx.Done():
		return state.UserHoldRecord{}, ctx.Err()
	default:
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.checks++

	present := s.heldLocked(request.Key)
	if len(s.presenceSequence) > 0 {
		index := s.checks - 1
		if index >= len(s.presenceSequence) {
			index = len(s.presenceSequence) - 1
		}

		present = s.presenceSequence[index]
	}

	return s.recordLocked(request.Key, present), nil
}

// setHeld updates the fake hold without local wake-up.
func (s *testUserHoldStore) setHeld(held bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.held = held
}

// setHeldForKey updates one fake hold key without affecting unrelated users.
func (s *testUserHoldStore) setHeldForKey(key UserKey, held bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.heldKeys == nil {
		s.heldKeys = map[state.AffinityKey]bool{}
	}

	s.heldKeys[key.Normalize().affinityKey()] = held
}

// setPresenceSequence installs deterministic check results.
func (s *testUserHoldStore) setPresenceSequence(sequence []bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.presenceSequence = append([]bool(nil), sequence...)
}

// checkCount reports how often placement checked the hold.
func (s *testUserHoldStore) checkCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.checks
}

// clearCount reports how often the local service cleared the hold.
func (s *testUserHoldStore) clearCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.clears
}

// heldLocked reports the fake hold state while the mutex is held.
func (s *testUserHoldStore) heldLocked(key state.AffinityKey) bool {
	if s.heldKeys != nil {
		return s.heldKeys[key]
	}

	return s.held
}

// recordLocked builds one fake Redis hold record while the mutex is held.
func (s *testUserHoldStore) recordLocked(key state.AffinityKey, present bool) state.UserHoldRecord {
	now := time.Unix(100, 0).UTC()
	record := state.UserHoldRecord{
		Present:           present,
		Status:            "absent",
		Key:               key,
		ServerTime:        now,
		UpdatedAt:         now,
		RequestedDuration: time.Minute,
	}

	if present {
		record.Status = runtimeTestHoldStatusFound
		record.Generation = runtimeTestHoldGenerationSet
		record.CreatedAt = now
		record.ExpiresAt = now.Add(time.Minute)
	}

	return record
}
