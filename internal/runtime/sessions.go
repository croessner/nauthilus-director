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
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/state"
)

const (
	operationSessionKill = "session_kill"
	operationSessionReap = "session_reap"
)

// SessionStatus describes the runtime control state of one frontend session.
type SessionStatus string

const (
	// SessionStatusActive marks a live session lease.
	SessionStatusActive SessionStatus = "active"
	// SessionStatusClosing marks a session that should close after a control action.
	SessionStatusClosing SessionStatus = "closing"
	// SessionStatusExpired marks a session whose lease has expired.
	SessionStatusExpired SessionStatus = "expired"
)

// SessionRuntimeState describes one lease-backed frontend session.
type SessionRuntimeState struct {
	SessionID         string
	UserHash          string
	Tenant            string
	Protocol          string
	ListenerName      string
	ServiceName       string
	EffectiveShardTag string
	BackendIdentifier string
	DirectorInstance  string
	OpenedAt          time.Time
	LeaseExpiresAt    time.Time
	ControlGeneration string
	Status            SessionStatus
}

// KillSessionRequest asks runtime state to mark one session for closure.
type KillSessionRequest struct {
	SessionID          string
	Reason             string
	Actor              Actor
	ExpectedGeneration string
}

// ReapSessionsRequest asks runtime state to repair expired session leases.
type ReapSessionsRequest struct {
	Reason string
	Actor  Actor
	Limit  int
}

// SessionMutationResult describes a runtime session mutation outcome.
type SessionMutationResult struct {
	State SessionRuntimeState
	Audit AuditMetadata
}

// SessionStateStore persists session control and reap operations.
type SessionStateStore interface {
	KillSession(ctx context.Context, request state.SessionKillRequest) (state.SessionKillRecord, error)
	ReapSessions(ctx context.Context, request state.ReapRequest) (state.ReapRecord, error)
}

// ReapSessionsResult describes a bounded expired-session repair pass.
type ReapSessionsResult struct {
	ScannedSessions  int
	ExpiredSessions  int
	RepairedBackends int
	ServerTime       time.Time
	Audit            AuditMetadata
}

// SessionService coordinates Redis-backed session operations and local acceleration.
type SessionService struct {
	store    SessionStateStore
	local    *LocalSessionRegistry
	recorder observability.Recorder
}

// ReaperConfig configures lifecycle-managed expired-session repair.
type ReaperConfig struct {
	Interval time.Duration
	Limit    int
	Reason   string
	Actor    Actor
}

// Reaper runs bounded expired-session repair until process shutdown.
type Reaper struct {
	service *SessionService
	config  ReaperConfig
	mu      sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
}

// NewSessionService creates the runtime session operation service.
func NewSessionService(store SessionStateStore, local *LocalSessionRegistry, options ...ServiceOption) *SessionService {
	applied := applyServiceOptions(options)

	return &SessionService{store: store, local: local, recorder: applied.recorder}
}

// NewReaper creates a lifecycle-managed expired-session repair loop.
func NewReaper(service *SessionService, config ReaperConfig) (*Reaper, error) {
	if service == nil {
		return nil, newRuntimeError(ErrorKindInvalidRequest, operationSessionReap, "session service required")
	}

	if config.Interval <= 0 {
		return nil, newRuntimeError(ErrorKindInvalidRequest, operationSessionReap, "interval required")
	}

	if config.Reason == "" {
		config.Reason = "periodic session reap"
	}

	if config.Limit < 0 {
		return nil, newRuntimeError(ErrorKindInvalidRequest, operationSessionReap, "limit must not be negative")
	}

	return &Reaper{service: service, config: config}, nil
}

// Start begins the periodic reaper loop.
func (r *Reaper) Start(ctx context.Context) error {
	if r == nil {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.cancel != nil {
		return nil
	}

	if ctx == nil {
		ctx = context.Background()
	}

	runCtx, cancel := context.WithCancel(ctx)

	r.cancel = cancel
	r.done = make(chan struct{})

	go r.run(runCtx, r.done)

	return nil
}

// Stop stops the periodic reaper loop without mutating backend runtime state.
func (r *Reaper) Stop(ctx context.Context) error {
	if r == nil {
		return nil
	}

	if ctx == nil {
		ctx = context.Background()
	}

	r.mu.Lock()
	cancel := r.cancel
	done := r.done
	r.cancel = nil
	r.done = nil
	r.mu.Unlock()

	if cancel == nil {
		return nil
	}

	cancel()

	if done == nil {
		return nil
	}

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// RunOnce performs one bounded expired-session repair pass.
func (r *Reaper) RunOnce(ctx context.Context) (ReapSessionsResult, error) {
	if r == nil || r.service == nil {
		return ReapSessionsResult{}, newRuntimeError(ErrorKindInvalidRequest, operationSessionReap, "session service required")
	}

	return r.service.ReapSessions(ctx, ReapSessionsRequest{
		Reason: r.config.Reason,
		Actor:  r.config.Actor,
		Limit:  r.config.Limit,
	})
}

// KillSession marks one session in Redis and closes a local stream when present.
func (s *SessionService) KillSession(ctx context.Context, request KillSessionRequest) (SessionMutationResult, error) {
	if err := request.Validate(); err != nil {
		return SessionMutationResult{}, err
	}

	if s == nil || s.store == nil {
		return SessionMutationResult{}, newRuntimeError(ErrorKindInvalidRequest, operationSessionKill, "session store required")
	}

	record, err := s.store.KillSession(ctx, state.SessionKillRequest{
		SessionID: strings.TrimSpace(request.SessionID),
		Reason:    request.Reason,
		Actor:     actorAuditValue(request.Actor),
	})
	if err != nil {
		return SessionMutationResult{}, err
	}

	audit, err := NewAuditMetadata(AuditInput{
		Operation: AuditOperationSessionKill,
		Reason:    request.Reason,
		Actor:     request.Actor,
		Generation: firstNonEmpty(
			record.ControlGeneration,
			request.ExpectedGeneration,
		),
		ServerTime: record.ServerTime,
		SessionID:  record.SessionID,
		Fields: map[string]string{
			auditFieldControlAction: string(record.ControlAction),
			auditFieldStatus:        record.Status,
		},
	})
	if err != nil {
		return SessionMutationResult{}, err
	}

	if s.local != nil {
		_, closeErr := s.local.CloseSession(ctx, record.SessionID, LocalSessionControl{
			Action: string(record.ControlAction),
			Reason: request.Reason,
		})
		if closeErr != nil {
			return SessionMutationResult{}, closeErr
		}
	}

	s.recordSessionOperation(ctx, observability.EventSessionKill, operationSessionKill, runtimeObservationResultOK, "session_kill", map[string]string{
		auditFieldControlAction:                  string(record.ControlAction),
		runtimeObservationFieldRuntimeGeneration: record.ControlGeneration,
		runtimeObservationFieldRuntimeStatus:     record.Status,
		"session_id":                             record.SessionID,
	})

	return SessionMutationResult{
		State: SessionRuntimeState{
			SessionID:         record.SessionID,
			ControlGeneration: record.ControlGeneration,
			Status:            SessionStatusClosing,
		},
		Audit: audit,
	}, nil
}

// ReapSessions repairs expired Redis leases, backend counts and secondary indexes.
func (s *SessionService) ReapSessions(ctx context.Context, request ReapSessionsRequest) (ReapSessionsResult, error) {
	if err := request.Validate(); err != nil {
		return ReapSessionsResult{}, err
	}

	if s == nil || s.store == nil {
		return ReapSessionsResult{}, newRuntimeError(ErrorKindInvalidRequest, operationSessionReap, "session store required")
	}

	record, err := s.store.ReapSessions(ctx, state.ReapRequest{Limit: request.Limit})
	if err != nil {
		return ReapSessionsResult{}, err
	}

	audit, err := NewAuditMetadata(AuditInput{
		Operation:  AuditOperationSessionReap,
		Reason:     request.Reason,
		Actor:      request.Actor,
		ServerTime: record.ServerTime,
		Generation: record.Status,
		Fields: map[string]string{
			auditFieldExpiredSessions:  strconv.Itoa(record.ExpiredSessions),
			auditFieldRepairedBackends: strconv.Itoa(record.RepairedBackends),
			auditFieldScannedSessions:  strconv.Itoa(record.ScannedSessions),
			auditFieldStatus:           record.Status,
		},
	})
	if err != nil {
		return ReapSessionsResult{}, err
	}

	s.recordSessionOperation(ctx, observability.EventSessionReap, operationSessionReap, runtimeObservationResultOK, "reap", map[string]string{
		auditFieldExpiredSessions:            strconv.Itoa(record.ExpiredSessions),
		auditFieldRepairedBackends:           strconv.Itoa(record.RepairedBackends),
		auditFieldScannedSessions:            strconv.Itoa(record.ScannedSessions),
		runtimeObservationFieldRuntimeStatus: record.Status,
	})

	return ReapSessionsResult{
		ScannedSessions:  record.ScannedSessions,
		ExpiredSessions:  record.ExpiredSessions,
		RepairedBackends: record.RepairedBackends,
		ServerTime:       record.ServerTime,
		Audit:            audit,
	}, nil
}

// recordSessionOperation emits one secret-safe session runtime observation.
func (s *SessionService) recordSessionOperation(
	ctx context.Context,
	event string,
	operation string,
	result string,
	reasonClass string,
	fields map[string]string,
) {
	if s == nil {
		return
	}

	recordRuntimeObservation(ctx, s.recorder, event, observability.TraceBoundaryRESTRequest, operation, result, reasonClass, fields, nil)
}

// LocalSessionInfo describes one locally proxied session for acceleration indexes.
type LocalSessionInfo struct {
	SessionID         string
	ListenerName      string
	Tenant            string
	UserHash          string
	BackendIdentifier string
	DirectorInstance  string
}

// LocalSessionControl describes a local stream close requested by runtime state.
type LocalSessionControl struct {
	Action string
	Reason string
}

// LocalSessionHandle closes a locally owned proxy stream without mutating global state.
type LocalSessionHandle interface {
	CloseRuntimeSession(ctx context.Context, control LocalSessionControl) error
}

// LocalSessionHandleFunc adapts a function into a local session handle.
type LocalSessionHandleFunc func(context.Context, LocalSessionControl) error

// CloseRuntimeSession calls the wrapped local session close function.
func (f LocalSessionHandleFunc) CloseRuntimeSession(ctx context.Context, control LocalSessionControl) error {
	if f == nil {
		return nil
	}

	return f(ctx, control)
}

// LocalSessionRegistry indexes sessions owned by the current process only.
type LocalSessionRegistry struct {
	mu         sync.Mutex
	bySession  map[string]localSessionEntry
	byListener map[string]map[string]struct{}
	byUser     map[UserKey]map[string]struct{}
	byBackend  map[string]map[string]struct{}
}

type localSessionEntry struct {
	info   LocalSessionInfo
	handle LocalSessionHandle
}

// NewLocalSessionRegistry creates an empty local active-session accelerator.
func NewLocalSessionRegistry() *LocalSessionRegistry {
	return &LocalSessionRegistry{
		bySession:  make(map[string]localSessionEntry),
		byListener: make(map[string]map[string]struct{}),
		byUser:     make(map[UserKey]map[string]struct{}),
		byBackend:  make(map[string]map[string]struct{}),
	}
}

// Register records one local session and returns an idempotent unregister callback.
func (r *LocalSessionRegistry) Register(info LocalSessionInfo, handle LocalSessionHandle) (func(), error) {
	info = info.Normalize()
	if info.SessionID == "" {
		return nil, newRuntimeError(ErrorKindInvalidRequest, "local_session_register", "session id required")
	}

	if handle == nil {
		return nil, newRuntimeError(ErrorKindInvalidRequest, "local_session_register", "session handle required")
	}

	if r == nil {
		return func() {}, nil
	}

	r.mu.Lock()

	r.bySession[info.SessionID] = localSessionEntry{info: info, handle: handle}
	if info.ListenerName != "" {
		addLocalIndex(r.byListener, info.ListenerName, info.SessionID)
	}

	if key := info.UserKey(); key.UserHash != "" && key.Tenant != "" {
		addLocalIndex(r.byUser, key, info.SessionID)
	}

	if info.BackendIdentifier != "" {
		addLocalIndex(r.byBackend, info.BackendIdentifier, info.SessionID)
	}
	r.mu.Unlock()

	var once sync.Once

	return func() {
		once.Do(func() {
			r.unregister(info)
		})
	}, nil
}

// CloseSession closes one locally owned session if this process has it.
func (r *LocalSessionRegistry) CloseSession(
	ctx context.Context,
	sessionID string,
	control LocalSessionControl,
) (int, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" || r == nil {
		return 0, nil
	}

	return closeLocalEntries(ctx, control, r.entriesForSessions([]string{sessionID}))
}

// CloseListener closes locally owned sessions accepted by one listener.
func (r *LocalSessionRegistry) CloseListener(
	ctx context.Context,
	listenerName string,
	control LocalSessionControl,
) (int, error) {
	if r == nil {
		return 0, nil
	}

	listenerName = strings.TrimSpace(listenerName)
	if listenerName == "" {
		return 0, nil
	}

	return closeLocalEntries(ctx, control, entriesForIndexedKey(r, r.byListener, listenerName))
}

// CloseUser closes locally owned sessions for one affinity key.
func (r *LocalSessionRegistry) CloseUser(ctx context.Context, key UserKey, control LocalSessionControl) (int, error) {
	if r == nil {
		return 0, nil
	}

	key = key.Normalize()
	if key.Tenant == "" || key.UserHash == "" {
		return 0, nil
	}

	return closeLocalEntries(ctx, control, entriesForIndexedKey(r, r.byUser, key))
}

// CloseBackend closes locally owned sessions attached to one backend.
func (r *LocalSessionRegistry) CloseBackend(
	ctx context.Context,
	backendIdentifier string,
	control LocalSessionControl,
) (int, error) {
	if r == nil {
		return 0, nil
	}

	backendIdentifier = strings.TrimSpace(backendIdentifier)
	if backendIdentifier == "" {
		return 0, nil
	}

	return closeLocalEntries(ctx, control, entriesForIndexedKey(r, r.byBackend, backendIdentifier))
}

// CloseAll closes every locally owned session in the current process.
func (r *LocalSessionRegistry) CloseAll(ctx context.Context, control LocalSessionControl) (int, error) {
	if r == nil {
		return 0, nil
	}

	r.mu.Lock()

	entries := make([]localSessionEntry, 0, len(r.bySession))
	for _, entry := range r.bySession {
		entries = append(entries, entry)
	}
	r.mu.Unlock()

	return closeLocalEntries(ctx, control, entries)
}

// Normalize returns local session info with stable index fields trimmed.
func (i LocalSessionInfo) Normalize() LocalSessionInfo {
	i.SessionID = strings.TrimSpace(i.SessionID)
	i.ListenerName = strings.TrimSpace(i.ListenerName)
	i.Tenant = strings.TrimSpace(i.Tenant)
	i.UserHash = strings.TrimSpace(i.UserHash)
	i.BackendIdentifier = strings.TrimSpace(i.BackendIdentifier)
	i.DirectorInstance = strings.TrimSpace(i.DirectorInstance)

	return i
}

// UserKey returns the registry's user-affinity index key.
func (i LocalSessionInfo) UserKey() UserKey {
	return UserKey{Tenant: i.Tenant, UserHash: i.UserHash}.Normalize()
}

// run executes the periodic repair loop until cancellation.
func (r *Reaper) run(ctx context.Context, done chan struct{}) {
	defer close(done)

	ticker := time.NewTicker(r.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = r.RunOnce(ctx)
		}
	}
}

// unregister removes one local session from all accelerator indexes.
func (r *LocalSessionRegistry) unregister(info LocalSessionInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.bySession, info.SessionID)

	if info.ListenerName != "" {
		removeLocalIndex(r.byListener, info.ListenerName, info.SessionID)
	}

	if key := info.UserKey(); key.Tenant != "" && key.UserHash != "" {
		removeLocalIndex(r.byUser, key, info.SessionID)
	}

	if info.BackendIdentifier != "" {
		removeLocalIndex(r.byBackend, info.BackendIdentifier, info.SessionID)
	}
}

// entriesForSessions snapshots local handles for the requested session identifiers.
func (r *LocalSessionRegistry) entriesForSessions(sessionIDs []string) []localSessionEntry {
	r.mu.Lock()
	defer r.mu.Unlock()

	entries := make([]localSessionEntry, 0, len(sessionIDs))
	for _, sessionID := range sessionIDs {
		if entry, ok := r.bySession[sessionID]; ok {
			entries = append(entries, entry)
		}
	}

	return entries
}

// entriesForIndexedKey snapshots local handles through a secondary registry index.
func entriesForIndexedKey[K comparable](
	r *LocalSessionRegistry,
	index map[K]map[string]struct{},
	key K,
) []localSessionEntry {
	r.mu.Lock()
	defer r.mu.Unlock()

	sessionIDs := index[key]

	entries := make([]localSessionEntry, 0, len(sessionIDs))
	for sessionID := range sessionIDs {
		if entry, ok := r.bySession[sessionID]; ok {
			entries = append(entries, entry)
		}
	}

	return entries
}

// addLocalIndex adds one session identifier to a secondary registry index.
func addLocalIndex[K comparable](index map[K]map[string]struct{}, key K, sessionID string) {
	if _, ok := index[key]; !ok {
		index[key] = make(map[string]struct{})
	}

	index[key][sessionID] = struct{}{}
}

// removeLocalIndex removes one session identifier from a secondary registry index.
func removeLocalIndex[K comparable](index map[K]map[string]struct{}, key K, sessionID string) {
	sessionIDs := index[key]
	if len(sessionIDs) == 0 {
		return
	}

	delete(sessionIDs, sessionID)

	if len(sessionIDs) == 0 {
		delete(index, key)
	}
}

// closeLocalEntries invokes local close handles outside the registry lock.
func closeLocalEntries(
	ctx context.Context,
	control LocalSessionControl,
	entries []localSessionEntry,
) (int, error) {
	var errs []error

	for _, entry := range entries {
		if entry.handle == nil {
			continue
		}

		if err := entry.handle.CloseRuntimeSession(ctx, control); err != nil {
			errs = append(errs, err)
		}
	}

	return len(entries), errors.Join(errs...)
}

// Validate checks the session kill request before it crosses a persistence boundary.
func (r KillSessionRequest) Validate() error {
	if strings.TrimSpace(r.SessionID) == "" {
		return newRuntimeError(ErrorKindInvalidRequest, operationSessionKill, "session id required")
	}

	return requireReason(operationSessionKill, r.Reason)
}

// Validate checks the reap request before it crosses a persistence boundary.
func (r ReapSessionsRequest) Validate() error {
	if r.Limit < 0 {
		return newRuntimeError(ErrorKindInvalidRequest, operationSessionReap, "limit must not be negative")
	}

	return requireReason(operationSessionReap, r.Reason)
}

// Normalize returns a session state with stable string fields trimmed.
func (s SessionRuntimeState) Normalize() SessionRuntimeState {
	s.SessionID = strings.TrimSpace(s.SessionID)
	s.UserHash = strings.TrimSpace(s.UserHash)
	s.Tenant = strings.TrimSpace(s.Tenant)
	s.Protocol = strings.ToLower(strings.TrimSpace(s.Protocol))
	s.ListenerName = strings.TrimSpace(s.ListenerName)
	s.ServiceName = strings.TrimSpace(s.ServiceName)
	s.EffectiveShardTag = strings.TrimSpace(s.EffectiveShardTag)
	s.BackendIdentifier = strings.TrimSpace(s.BackendIdentifier)
	s.DirectorInstance = strings.TrimSpace(s.DirectorInstance)
	s.ControlGeneration = strings.TrimSpace(s.ControlGeneration)

	return s
}
