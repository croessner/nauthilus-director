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

//nolint:revive // Runtime aggregate names intentionally mirror the operator REST vocabulary.
package runtime

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/state"
)

const (
	operationRuntimeAggregateReconcile = "runtime_aggregate_reconcile"

	maxRuntimeAggregateReconcileLimit        = 1000
	maxRuntimeAggregateReconcilePassDuration = 30 * time.Second
)

// RuntimeAggregateReconcileScope limits one aggregate repair pass to a known aggregate family.
type RuntimeAggregateReconcileScope string

const (
	// RuntimeAggregateReconcileScopeAll asks the state layer to reconcile every supported aggregate family.
	RuntimeAggregateReconcileScopeAll RuntimeAggregateReconcileScope = "all"
	// RuntimeAggregateReconcileScopeActiveSessions repairs active-session aggregate markers and counters.
	RuntimeAggregateReconcileScopeActiveSessions RuntimeAggregateReconcileScope = "active_sessions"
	// RuntimeAggregateReconcileScopeBackendCapacity reserves a public scope for backend-capacity aggregates.
	RuntimeAggregateReconcileScopeBackendCapacity RuntimeAggregateReconcileScope = "backend_capacity"
	// RuntimeAggregateReconcileScopeIdleAffinities reserves a public scope for idle-affinity aggregates.
	RuntimeAggregateReconcileScopeIdleAffinities RuntimeAggregateReconcileScope = "idle_affinities"
	// RuntimeAggregateReconcileScopeRepairs reserves a public scope for cumulative repair counters.
	RuntimeAggregateReconcileScopeRepairs RuntimeAggregateReconcileScope = "repairs"
)

// RuntimeAggregateReconcileRequest asks runtime state to repair aggregate-only drift.
type RuntimeAggregateReconcileRequest struct {
	Reason          string
	Actor           Actor
	Limit           int
	MaxPassDuration time.Duration
	DryRun          bool
	Scope           RuntimeAggregateReconcileScope
}

// RuntimeAggregateReconcileResult describes one bounded aggregate repair pass.
type RuntimeAggregateReconcileResult struct {
	Status                       string
	Scope                        RuntimeAggregateReconcileScope
	ScannedMarkers               int
	StaleMarkersRemoved          int
	MarkersUpserted              int
	CounterFieldsChanged         int
	CounterFieldsRemoved         int
	BackendCapacityFieldsChanged int
	IdleAffinitiesRemoved        int
	AuthoritativeConflicts       int
	ServerTime                   time.Time
	Audit                        AuditMetadata
}

// RuntimeAggregateStateStore persists aggregate reconciliation operations.
type RuntimeAggregateStateStore interface {
	ReconcileRuntimeAggregates(ctx context.Context, request state.RuntimeAggregateReconcileRequest) (state.RuntimeAggregateReconcileRecord, error)
}

// RuntimeAggregateService coordinates aggregate repair through the state layer.
type RuntimeAggregateService struct {
	store    RuntimeAggregateStateStore
	recorder observability.Recorder
}

// NewRuntimeAggregateService creates the runtime aggregate operation service.
func NewRuntimeAggregateService(store RuntimeAggregateStateStore, options ...ServiceOption) *RuntimeAggregateService {
	applied := applyServiceOptions(options)

	return &RuntimeAggregateService{store: store, recorder: applied.recorder}
}

// ReconcileRuntimeAggregates repairs repairable aggregate drift from authoritative state.
func (s *RuntimeAggregateService) ReconcileRuntimeAggregates(
	ctx context.Context,
	request RuntimeAggregateReconcileRequest,
) (RuntimeAggregateReconcileResult, error) {
	if err := request.Validate(); err != nil {
		return RuntimeAggregateReconcileResult{}, err
	}

	if ctx == nil {
		ctx = context.Background()
	}

	if s == nil || s.store == nil {
		return RuntimeAggregateReconcileResult{}, newRuntimeError(ErrorKindInvalidRequest, operationRuntimeAggregateReconcile, "runtime aggregate store required")
	}

	reconcileCtx, cancel := context.WithTimeout(ctx, request.MaxPassDuration)
	defer cancel()

	started := time.Now()

	record, err := s.store.ReconcileRuntimeAggregates(reconcileCtx, state.RuntimeAggregateReconcileRequest{
		Limit:           request.Limit,
		MaxPassDuration: request.MaxPassDuration,
		DryRun:          request.DryRun,
		Scope:           stateRuntimeAggregateScope(request.Scope),
	})
	if err != nil {
		return RuntimeAggregateReconcileResult{}, err
	}

	result := runtimeAggregateReconcileResultFromState(record)

	audit, err := runtimeAggregateReconcileAudit(request, result)
	if err != nil {
		return RuntimeAggregateReconcileResult{}, err
	}

	result.Audit = audit

	s.recordRuntimeAggregateOperation(ctx, result, request.DryRun, time.Since(started))

	return result, nil
}

// Validate checks the aggregate reconcile request before state repair.
func (r RuntimeAggregateReconcileRequest) Validate() error {
	if r.Limit <= 0 {
		return newRuntimeError(ErrorKindInvalidRequest, operationRuntimeAggregateReconcile, "limit must be greater than zero")
	}

	if r.Limit > maxRuntimeAggregateReconcileLimit {
		return newRuntimeError(ErrorKindInvalidRequest, operationRuntimeAggregateReconcile, "limit exceeds maximum")
	}

	if r.MaxPassDuration <= 0 {
		return newRuntimeError(ErrorKindInvalidRequest, operationRuntimeAggregateReconcile, "max pass duration required")
	}

	if r.MaxPassDuration > maxRuntimeAggregateReconcilePassDuration {
		return newRuntimeError(ErrorKindInvalidRequest, operationRuntimeAggregateReconcile, "max pass duration exceeds maximum")
	}

	if normalizeRuntimeAggregateReconcileScope(r.Scope) == "" {
		return newRuntimeError(ErrorKindInvalidRequest, operationRuntimeAggregateReconcile, "scope invalid")
	}

	return requireReason(operationRuntimeAggregateReconcile, r.Reason)
}

// normalizeRuntimeAggregateReconcileScope returns the public canonical scope name.
func normalizeRuntimeAggregateReconcileScope(scope RuntimeAggregateReconcileScope) RuntimeAggregateReconcileScope {
	switch RuntimeAggregateReconcileScope(strings.ReplaceAll(strings.ToLower(strings.TrimSpace(string(scope))), "-", "_")) {
	case "", RuntimeAggregateReconcileScopeAll:
		return RuntimeAggregateReconcileScopeAll
	case RuntimeAggregateReconcileScopeActiveSessions:
		return RuntimeAggregateReconcileScopeActiveSessions
	case RuntimeAggregateReconcileScopeBackendCapacity:
		return RuntimeAggregateReconcileScopeBackendCapacity
	case RuntimeAggregateReconcileScopeIdleAffinities:
		return RuntimeAggregateReconcileScopeIdleAffinities
	case RuntimeAggregateReconcileScopeRepairs:
		return RuntimeAggregateReconcileScopeRepairs
	default:
		return ""
	}
}

// stateRuntimeAggregateScope maps the runtime scope onto the currently implemented state repair family.
func stateRuntimeAggregateScope(scope RuntimeAggregateReconcileScope) string {
	switch normalizeRuntimeAggregateReconcileScope(scope) {
	case RuntimeAggregateReconcileScopeActiveSessions:
		return state.RuntimeAggregateReconcileScopeActiveSessions
	default:
		return state.RuntimeAggregateReconcileScopeAll
	}
}

// runtimeAggregateReconcileResultFromState adapts state repair counts into runtime-domain fields.
func runtimeAggregateReconcileResultFromState(record state.RuntimeAggregateReconcileRecord) RuntimeAggregateReconcileResult {
	return RuntimeAggregateReconcileResult{
		Status:                 record.Status,
		Scope:                  RuntimeAggregateReconcileScope(record.Scope),
		ScannedMarkers:         record.ScannedMarkers,
		StaleMarkersRemoved:    record.StaleMarkersRemoved,
		MarkersUpserted:        record.MarkersUpserted,
		CounterFieldsChanged:   record.CounterFieldsChanged,
		CounterFieldsRemoved:   record.CounterFieldsRemoved,
		AuthoritativeConflicts: record.AuthoritativeConflicts,
		ServerTime:             record.ServerTime,
	}
}

// runtimeAggregateReconcileAudit creates secret-safe audit metadata for aggregate repair.
func runtimeAggregateReconcileAudit(
	request RuntimeAggregateReconcileRequest,
	result RuntimeAggregateReconcileResult,
) (AuditMetadata, error) {
	return NewAuditMetadata(AuditInput{
		Operation:  AuditOperationRuntimeAggregateReconcile,
		Reason:     request.Reason,
		Actor:      request.Actor,
		ServerTime: result.ServerTime,
		Generation: result.Status,
		Fields: map[string]string{
			auditFieldAuthoritative:   strconv.Itoa(result.AuthoritativeConflicts),
			auditFieldCountersChanged: strconv.Itoa(result.CounterFieldsChanged),
			auditFieldCountersRemoved: strconv.Itoa(result.CounterFieldsRemoved),
			auditFieldDryRun:          boolAuditValue(request.DryRun),
			auditFieldScannedMarkers:  strconv.Itoa(result.ScannedMarkers),
			auditFieldScope:           string(normalizeRuntimeAggregateReconcileScope(request.Scope)),
			auditFieldStaleMarkers:    strconv.Itoa(result.StaleMarkersRemoved),
			auditFieldStatus:          result.Status,
		},
	})
}

// recordRuntimeAggregateOperation emits one bounded aggregate repair observation.
func (s *RuntimeAggregateService) recordRuntimeAggregateOperation(
	ctx context.Context,
	result RuntimeAggregateReconcileResult,
	dryRun bool,
	duration time.Duration,
) {
	if s == nil {
		return
	}

	recordRuntimeObservation(
		ctx,
		s.recorder,
		observability.EventSessionReap,
		observability.TraceBoundaryRESTRequest,
		operationRuntimeAggregateReconcile,
		runtimeObservationResultOK,
		result.Status,
		map[string]string{
			auditFieldAuthoritative:              strconv.Itoa(result.AuthoritativeConflicts),
			auditFieldCountersChanged:            strconv.Itoa(result.CounterFieldsChanged),
			auditFieldCountersRemoved:            strconv.Itoa(result.CounterFieldsRemoved),
			auditFieldDryRun:                     boolAuditValue(dryRun),
			auditFieldScannedMarkers:             strconv.Itoa(result.ScannedMarkers),
			auditFieldScope:                      string(result.Scope),
			auditFieldStaleMarkers:               strconv.Itoa(result.StaleMarkersRemoved),
			runtimeObservationFieldRuntimeStatus: result.Status,
			runtimeObservationFieldServerTime:    strconv.FormatBool(!result.ServerTime.IsZero()),
		},
		nil,
		duration,
	)
}
