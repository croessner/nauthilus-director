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
	"strconv"
	"strings"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/state"
)

const (
	operationBackendDrain        = "backend_drain"
	operationBackendInOut        = "backend_in_out"
	operationBackendMaintenance  = "backend_maintenance"
	operationBackendRuntimeClear = "backend_runtime_clear"
	operationBackendWeight       = "backend_weight"
)

// SetBackendInServiceRequest asks runtime state to mark a backend in or out.
type SetBackendInServiceRequest struct {
	BackendIdentifier  string
	InService          bool
	Reason             string
	Actor              Actor
	ExpectedGeneration string
}

// SetBackendWeightRequest asks runtime state to overlay a backend weight.
type SetBackendWeightRequest struct {
	BackendIdentifier  string
	Weight             int
	Reason             string
	Actor              Actor
	ExpectedGeneration string
}

// SetBackendMaintenanceRequest asks runtime state to overlay backend maintenance.
type SetBackendMaintenanceRequest struct {
	BackendIdentifier  string
	Maintenance        backend.MaintenanceState
	Reason             string
	Actor              Actor
	ExpectedGeneration string
}

// StartBackendDrainRequest asks runtime state to start an auditable drain.
type StartBackendDrainRequest struct {
	BackendIdentifier  string
	Drain              backend.DrainState
	Reason             string
	Actor              Actor
	ExpectedGeneration string
}

// ClearBackendRuntimeRequest asks runtime state to remove runtime-only backend overrides.
type ClearBackendRuntimeRequest struct {
	BackendIdentifier  string
	Reason             string
	Actor              Actor
	ExpectedGeneration string
}

// BackendMutationResult describes a runtime backend mutation outcome.
type BackendMutationResult struct {
	BackendIdentifier  string
	Override           backend.RuntimeOverride
	EffectiveState     backend.EffectiveBackendState
	MarkedSessionCount int
	Audit              AuditMetadata
}

// BackendStateStore persists Redis-backed backend runtime mutations.
type BackendStateStore interface {
	SetBackendRuntime(ctx context.Context, mutation state.BackendRuntimeMutation) (state.BackendRuntimeRecord, error)
	ClearBackendRuntime(ctx context.Context, request state.BackendRuntimeClearRequest) (state.BackendRuntimeRecord, error)
}

// BackendService coordinates backend runtime operations with local session acceleration.
type BackendService struct {
	store    BackendStateStore
	local    *LocalSessionRegistry
	recorder observability.Recorder
}

// NewBackendService creates the runtime backend operation service.
func NewBackendService(store BackendStateStore, local *LocalSessionRegistry, options ...ServiceOption) *BackendService {
	applied := applyServiceOptions(options)

	return &BackendService{store: store, local: local, recorder: applied.recorder}
}

// SetInService changes the runtime in/out overlay without terminating active sessions.
func (s *BackendService) SetInService(ctx context.Context, request SetBackendInServiceRequest) (BackendMutationResult, error) {
	if err := request.Validate(); err != nil {
		return BackendMutationResult{}, err
	}

	record, err := s.setRuntime(ctx, state.BackendRuntimeMutation{
		BackendIdentifier: strings.TrimSpace(request.BackendIdentifier),
		InService:         &request.InService,
		Reason:            request.Reason,
		Actor:             actorAuditValue(request.Actor),
	})
	if err != nil {
		return BackendMutationResult{}, err
	}

	result, err := s.backendMutationResult(ctx, AuditOperationBackendRuntimeSet, request.Reason, request.Actor, request.RuntimeOverride(), record, nil)
	if err != nil {
		return BackendMutationResult{}, err
	}

	reasonClass := runtimeObservationReasonBackendRuntime
	if !request.InService {
		reasonClass = "runtime_out"
	}

	s.recordBackendOperation(ctx, observability.EventBackendRuntimeOperation, operationBackendInOut, runtimeObservationResultOK, reasonClass, record, nil)

	return result, nil
}

// SetWeight changes the runtime weight overlay without terminating active sessions.
func (s *BackendService) SetWeight(
	ctx context.Context,
	request SetBackendWeightRequest,
	policy backend.RuntimeOverridePolicy,
) (BackendMutationResult, error) {
	if err := request.Validate(policy); err != nil {
		return BackendMutationResult{}, err
	}

	record, err := s.setRuntime(ctx, state.BackendRuntimeMutation{
		BackendIdentifier: strings.TrimSpace(request.BackendIdentifier),
		Weight:            &request.Weight,
		Reason:            request.Reason,
		Actor:             actorAuditValue(request.Actor),
	})
	if err != nil {
		return BackendMutationResult{}, err
	}

	result, err := s.backendMutationResult(ctx, AuditOperationBackendRuntimeSet, request.Reason, request.Actor, request.RuntimeOverride(), record, nil)
	if err != nil {
		return BackendMutationResult{}, err
	}

	reasonClass := runtimeObservationReasonBackendRuntime
	if request.Weight == 0 {
		reasonClass = "weight_zero"
	}

	s.recordBackendOperation(ctx, observability.EventBackendRuntimeOperation, operationBackendWeight, runtimeObservationResultOK, reasonClass, record, nil)

	return result, nil
}

// SetMaintenance changes runtime maintenance and closes local streams for hard maintenance.
func (s *BackendService) SetMaintenance(
	ctx context.Context,
	request SetBackendMaintenanceRequest,
) (BackendMutationResult, error) {
	if err := request.Validate(); err != nil {
		return BackendMutationResult{}, err
	}

	maintenance, err := request.Maintenance.Normalize(backend.MaintenanceModeDisabled)
	if err != nil {
		return BackendMutationResult{}, err
	}

	record, err := s.setRuntime(ctx, state.BackendRuntimeMutation{
		BackendIdentifier: strings.TrimSpace(request.BackendIdentifier),
		MaintenanceMode:   string(maintenance.Mode),
		Reason:            request.Reason,
		Actor:             actorAuditValue(request.Actor),
	})
	if err != nil {
		return BackendMutationResult{}, err
	}

	closeLocal := maintenance.Mode == backend.MaintenanceModeHard

	result, err := s.backendMutationResult(
		ctx,
		AuditOperationBackendMaintenance,
		request.Reason,
		request.Actor,
		request.RuntimeOverride(),
		record,
		closeLocalControl(closeLocal, "hard_maintenance", request.Reason),
	)
	if err != nil {
		return BackendMutationResult{}, err
	}

	s.recordBackendOperation(ctx, observability.EventBackendMaintenanceOperation, operationBackendMaintenance, runtimeObservationResultOK, maintenanceReasonClass(maintenance.Mode), record, map[string]string{
		runtimeObservationFieldMaintenanceMode: string(maintenance.Mode),
	})

	return result, nil
}

// StartDrain starts an auditable backend drain and closes local attached streams.
func (s *BackendService) StartDrain(ctx context.Context, request StartBackendDrainRequest) (BackendMutationResult, error) {
	if err := request.Validate(); err != nil {
		return BackendMutationResult{}, err
	}

	drain, err := request.Drain.Normalize()
	if err != nil {
		return BackendMutationResult{}, err
	}

	record, err := s.setRuntime(ctx, state.BackendRuntimeMutation{
		BackendIdentifier: strings.TrimSpace(request.BackendIdentifier),
		DrainEnabled:      drain.Enabled,
		DrainMode:         string(drain.Mode),
		Reason:            request.Reason,
		Actor:             actorAuditValue(request.Actor),
	})
	if err != nil {
		return BackendMutationResult{}, err
	}

	result, err := s.backendMutationResult(
		ctx,
		AuditOperationBackendDrain,
		request.Reason,
		request.Actor,
		request.RuntimeOverride(),
		record,
		closeLocalControl(record.MarkedSessionCount > 0, "drain", request.Reason),
	)
	if err != nil {
		return BackendMutationResult{}, err
	}

	s.recordBackendOperation(ctx, observability.EventBackendDrain, operationBackendDrain, runtimeObservationResultOK, "drain", record, map[string]string{
		runtimeObservationFieldMaintenanceMode: string(drain.Mode),
	})

	return result, nil
}

// ClearRuntime removes runtime-only backend overrides without touching active sessions.
func (s *BackendService) ClearRuntime(ctx context.Context, request ClearBackendRuntimeRequest) (BackendMutationResult, error) {
	if err := request.Validate(); err != nil {
		return BackendMutationResult{}, err
	}

	if s == nil || s.store == nil {
		return BackendMutationResult{}, newRuntimeError(ErrorKindInvalidRequest, operationBackendRuntimeClear, "backend store required")
	}

	record, err := s.store.ClearBackendRuntime(ctx, state.BackendRuntimeClearRequest{
		BackendIdentifier: strings.TrimSpace(request.BackendIdentifier),
		Reason:            request.Reason,
		Actor:             actorAuditValue(request.Actor),
	})
	if err != nil {
		return BackendMutationResult{}, err
	}

	result, err := s.backendMutationResult(ctx, AuditOperationBackendRuntimeClear, request.Reason, request.Actor, backend.RuntimeOverride{}, record, nil)
	if err != nil {
		return BackendMutationResult{}, err
	}

	s.recordBackendOperation(ctx, observability.EventBackendRuntimeOperation, operationBackendRuntimeClear, runtimeObservationResultOK, runtimeObservationReasonCleared, record, nil)
	s.recordBackendOperation(ctx, observability.EventBackendDrain, operationBackendRuntimeClear, runtimeObservationResultOK, runtimeObservationReasonCleared, record, nil)

	return result, nil
}

// Validate checks the in/out request before it crosses a persistence boundary.
func (r SetBackendInServiceRequest) Validate() error {
	if err := requireBackendIdentifier(operationBackendInOut, r.BackendIdentifier); err != nil {
		return err
	}

	return requireReason(operationBackendInOut, r.Reason)
}

// Validate checks the weight request before it crosses a persistence boundary.
func (r SetBackendWeightRequest) Validate(policy backend.RuntimeOverridePolicy) error {
	if err := requireBackendIdentifier(operationBackendWeight, r.BackendIdentifier); err != nil {
		return err
	}

	if err := requireReason(operationBackendWeight, r.Reason); err != nil {
		return err
	}

	override := backend.RuntimeOverride{Weight: new(r.Weight)}

	return override.Validate(policy)
}

// Validate checks the maintenance request before it crosses a persistence boundary.
func (r SetBackendMaintenanceRequest) Validate() error {
	if err := requireBackendIdentifier(operationBackendMaintenance, r.BackendIdentifier); err != nil {
		return err
	}

	if err := requireReason(operationBackendMaintenance, r.Reason); err != nil {
		return err
	}

	_, err := r.Maintenance.Normalize(backend.MaintenanceModeDisabled)

	return err
}

// Validate checks the drain request before it crosses a persistence boundary.
func (r StartBackendDrainRequest) Validate() error {
	if err := requireBackendIdentifier(operationBackendDrain, r.BackendIdentifier); err != nil {
		return err
	}

	if err := requireReason(operationBackendDrain, r.Reason); err != nil {
		return err
	}

	_, err := r.Drain.Normalize()

	return err
}

// Validate checks the runtime clear request before it crosses a persistence boundary.
func (r ClearBackendRuntimeRequest) Validate() error {
	if err := requireBackendIdentifier(operationBackendRuntimeClear, r.BackendIdentifier); err != nil {
		return err
	}

	return requireReason(operationBackendRuntimeClear, r.Reason)
}

// RuntimeOverride converts an in/out request into optional runtime state.
func (r SetBackendInServiceRequest) RuntimeOverride() backend.RuntimeOverride {
	return backend.RuntimeOverride{
		InService:  new(r.InService),
		Generation: strings.TrimSpace(r.ExpectedGeneration),
	}
}

// RuntimeOverride converts a weight request into optional runtime state.
func (r SetBackendWeightRequest) RuntimeOverride() backend.RuntimeOverride {
	return backend.RuntimeOverride{
		Weight:     new(r.Weight),
		Generation: strings.TrimSpace(r.ExpectedGeneration),
	}
}

// RuntimeOverride converts a maintenance request into optional runtime state.
func (r SetBackendMaintenanceRequest) RuntimeOverride() backend.RuntimeOverride {
	maintenance := r.Maintenance

	return backend.RuntimeOverride{
		Maintenance: &maintenance,
		Generation:  strings.TrimSpace(r.ExpectedGeneration),
	}
}

// RuntimeOverride converts a drain request into optional runtime state.
func (r StartBackendDrainRequest) RuntimeOverride() backend.RuntimeOverride {
	drain := r.Drain

	return backend.RuntimeOverride{
		Drain:      &drain,
		Generation: strings.TrimSpace(r.ExpectedGeneration),
	}
}

// requireBackendIdentifier rejects empty backend mutation targets.
func requireBackendIdentifier(operation string, identifier string) error {
	if strings.TrimSpace(identifier) == "" {
		return newRuntimeError(ErrorKindInvalidRequest, operation, "backend identifier required")
	}

	return nil
}

// setRuntime applies one Redis-backed backend runtime mutation.
func (s *BackendService) setRuntime(
	ctx context.Context,
	mutation state.BackendRuntimeMutation,
) (state.BackendRuntimeRecord, error) {
	if s == nil || s.store == nil {
		return state.BackendRuntimeRecord{}, newRuntimeError(ErrorKindInvalidRequest, operationBackendInOut, "backend store required")
	}

	return s.store.SetBackendRuntime(ctx, mutation)
}

// backendMutationResult maps Redis mutation output into runtime domain state.
func (s *BackendService) backendMutationResult(
	ctx context.Context,
	operation AuditOperation,
	reason string,
	actor Actor,
	override backend.RuntimeOverride,
	record state.BackendRuntimeRecord,
	localControl *LocalSessionControl,
) (BackendMutationResult, error) {
	audit, err := NewAuditMetadata(AuditInput{
		Operation:         operation,
		Reason:            reason,
		Actor:             actor,
		Generation:        record.Generation,
		ServerTime:        record.ServerTime,
		BackendIdentifier: record.BackendIdentifier,
		Fields: map[string]string{
			auditFieldActiveSessionCount: strconv.Itoa(record.ActiveSessionCount),
			auditFieldMarkedSessionCount: strconv.Itoa(record.MarkedSessionCount),
			auditFieldStatus:             record.Status,
		},
	})
	if err != nil {
		return BackendMutationResult{}, err
	}

	if localControl != nil && s.local != nil {
		_, closeErr := s.local.CloseBackend(ctx, record.BackendIdentifier, *localControl)
		if closeErr != nil {
			return BackendMutationResult{}, closeErr
		}
	}

	return BackendMutationResult{
		BackendIdentifier:  record.BackendIdentifier,
		Override:           override,
		MarkedSessionCount: record.MarkedSessionCount,
		Audit:              audit,
	}, nil
}

// closeLocalControl returns a local close request when a backend operation affects streams.
func closeLocalControl(enabled bool, action string, reason string) *LocalSessionControl {
	if !enabled {
		return nil
	}

	return &LocalSessionControl{Action: action, Reason: reason}
}

// maintenanceReasonClass maps maintenance mode into bounded observability classes.
func maintenanceReasonClass(mode backend.MaintenanceMode) string {
	switch mode {
	case backend.MaintenanceModeHard:
		return "hard_maintenance"
	case backend.MaintenanceModeSoft:
		return "soft_maintenance"
	default:
		return runtimeObservationReasonCleared
	}
}

// recordBackendOperation emits one secret-safe backend runtime observation.
func (s *BackendService) recordBackendOperation(
	ctx context.Context,
	event string,
	operation string,
	result string,
	reasonClass string,
	record state.BackendRuntimeRecord,
	labels map[string]string,
) {
	if s == nil {
		return
	}

	recordRuntimeObservation(ctx, s.recorder, event, observability.TraceBoundaryRESTRequest, operation, result, reasonClass, map[string]string{
		runtimeObservationFieldActiveSessions:    strconv.Itoa(record.ActiveSessionCount),
		runtimeObservationFieldBackendID:         record.BackendIdentifier,
		auditFieldMarkedSessionCount:             strconv.Itoa(record.MarkedSessionCount),
		runtimeObservationFieldRuntimeGeneration: record.Generation,
		runtimeObservationFieldRuntimeStatus:     record.Status,
		runtimeObservationFieldServerTime:        boolAuditValue(!record.ServerTime.IsZero()),
	}, labels)
}
