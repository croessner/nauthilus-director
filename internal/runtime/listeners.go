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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/observability"
)

const (
	operationListenerDrain  = "listener_drain"
	operationListenerGet    = "listener_get"
	operationListenerList   = "listener_list"
	operationListenerResume = "listener_resume"

	listenerObservationFieldDrainMode     = "drain_mode"
	listenerObservationFieldListenerState = "listener_state"
	listenerObservationFieldListenerTotal = "listener_total"
)

var (
	// ErrListenerManagerUnavailable reports that process-local listener state is not usable.
	ErrListenerManagerUnavailable = errors.New("listener manager unavailable")
	// ErrListenerNotFound reports a runtime operation for an unknown configured listener.
	ErrListenerNotFound = errors.New("listener not found")
	// ErrListenerOperationConflict reports an idempotency or current-state conflict.
	ErrListenerOperationConflict = errors.New("listener operation conflict")
)

// ListenerState describes one listener's process-local runtime state.
type ListenerState string

const (
	// ListenerStateAccepting means the listener socket is bound and accepting sockets.
	ListenerStateAccepting ListenerState = "accepting"
	// ListenerStateDraining means accepts are stopped while active local sessions remain.
	ListenerStateDraining ListenerState = "draining"
	// ListenerStateDrained means accepts are stopped and no local sessions remain.
	ListenerStateDrained ListenerState = "drained"
	// ListenerStateStopped means startup or resume failed and the listener is not bound.
	ListenerStateStopped ListenerState = "stopped"
)

// ListenerDrainMode describes how listener runtime drain handles active local sessions.
type ListenerDrainMode string

const (
	// ListenerDrainModeSoft closes only the accept socket and keeps active streams running.
	ListenerDrainModeSoft ListenerDrainMode = "soft"
	// ListenerDrainModeHard closes the accept socket and then closes active streams after grace.
	ListenerDrainModeHard ListenerDrainMode = "hard"
)

// ListenerDetail is a secret-safe listener runtime projection.
type ListenerDetail struct {
	Name                string
	Protocol            string
	ServiceName         string
	Network             string
	Address             string
	TLSMode             string
	ImplicitTLS         bool
	ProxyProtocol       bool
	BoundAddress        string
	State               ListenerState
	ActiveLocalSessions int
	DrainMode           ListenerDrainMode
}

// ListenerManagerDrainRequest asks the listener manager to drain one process-local listener.
type ListenerManagerDrainRequest struct {
	Name  string
	Mode  ListenerDrainMode
	Grace *time.Duration
}

// Normalize validates manager-facing drain input before socket state changes happen.
func (r ListenerManagerDrainRequest) Normalize() (ListenerManagerDrainRequest, error) {
	r.Name = strings.TrimSpace(r.Name)
	r.Mode = normalizeListenerDrainMode(r.Mode)

	if err := requireListenerName(operationListenerDrain, r.Name); err != nil {
		return ListenerManagerDrainRequest{}, err
	}

	if err := validateListenerDrainGrace(operationListenerDrain, r.Mode, r.Grace); err != nil {
		return ListenerManagerDrainRequest{}, err
	}

	return r, nil
}

// ListListenersRequest asks for process-local listener inventory.
type ListListenersRequest struct {
	Actor Actor
}

// GetListenerRequest asks for one process-local listener projection.
type GetListenerRequest struct {
	Name  string
	Actor Actor
}

// DrainListenerRequest asks the runtime service to drain one local listener.
type DrainListenerRequest struct {
	Name   string
	Mode   ListenerDrainMode
	Reason string
	Grace  *time.Duration
	Actor  Actor
}

// ResumeListenerRequest asks the runtime service to resume one local listener.
type ResumeListenerRequest struct {
	Name   string
	Reason string
	Actor  Actor
}

// ListListenersResult describes a stable process-local listener inventory read.
type ListListenersResult struct {
	Listeners []ListenerDetail
}

// ListenerMutationResult describes a listener drain or resume outcome.
type ListenerMutationResult struct {
	Listener ListenerDetail
	Audit    AuditMetadata
}

// ListenerManager exposes only the listener operations required by runtime control.
type ListenerManager interface {
	Snapshots() []ListenerDetail
	Drain(ctx context.Context, request ListenerManagerDrainRequest) (ListenerDetail, error)
	Resume(ctx context.Context, name string) (ListenerDetail, error)
}

// ListenerService coordinates listener runtime reads and process-local mutations.
type ListenerService struct {
	manager  ListenerManager
	recorder observability.Recorder
}

// NewListenerService creates the listener runtime coordinator.
func NewListenerService(manager ListenerManager, options ...ServiceOption) *ListenerService {
	applied := applyServiceOptions(options)

	return &ListenerService{manager: manager, recorder: applied.recorder}
}

// ListListeners returns configured process-local listener state sorted by name.
func (s *ListenerService) ListListeners(ctx context.Context, _ ListListenersRequest) (ListListenersResult, error) {
	manager, err := s.requireManager(operationListenerList)
	if err != nil {
		s.recordListenerFailure(ctx, operationListenerList, err)

		return ListListenersResult{}, err
	}

	listeners := normalizeListenerDetails(manager.Snapshots())
	s.recordListenerInventory(ctx, operationListenerList, listeners)

	return ListListenersResult{Listeners: listeners}, nil
}

// GetListener returns one configured process-local listener state.
func (s *ListenerService) GetListener(ctx context.Context, request GetListenerRequest) (ListenerDetail, error) {
	if err := request.Validate(); err != nil {
		s.recordListenerFailure(ctx, operationListenerGet, err)

		return ListenerDetail{}, err
	}

	manager, err := s.requireManager(operationListenerGet)
	if err != nil {
		s.recordListenerFailure(ctx, operationListenerGet, err)

		return ListenerDetail{}, err
	}

	detail, ok := listenerByName(manager.Snapshots(), request.Name)
	if !ok {
		err := newRuntimeError(ErrorKindNotFound, operationListenerGet, "listener not found")
		s.recordListenerFailure(ctx, operationListenerGet, err)

		return ListenerDetail{}, err
	}

	detail = normalizeListenerDetail(detail)
	s.recordListenerDetail(ctx, observability.EventListenerInventory, operationListenerGet, runtimeObservationResultOK, runtimeObservationResultOK, detail)

	return detail, nil
}

// DrainListener validates, audits and delegates one process-local listener drain.
func (s *ListenerService) DrainListener(ctx context.Context, request DrainListenerRequest) (ListenerMutationResult, error) {
	managerRequest, err := request.managerRequest()
	if err != nil {
		s.recordListenerFailure(ctx, operationListenerDrain, err)

		return ListenerMutationResult{}, err
	}

	manager, err := s.requireManager(operationListenerDrain)
	if err != nil {
		s.recordListenerFailure(ctx, operationListenerDrain, err)

		return ListenerMutationResult{}, err
	}

	detail, err := manager.Drain(ctx, managerRequest)
	if err != nil {
		classified := classifyListenerError(operationListenerDrain, err)
		s.recordListenerFailure(ctx, operationListenerDrain, classified)

		return ListenerMutationResult{}, classified
	}

	audit, err := listenerAuditMetadata(AuditOperationListenerDrain, request.Reason, request.Actor, detail, map[string]string{
		auditFieldListenerDrainMode: string(managerRequest.Mode),
		auditFieldListenerGrace:     graceAuditValue(managerRequest.Grace),
	})
	if err != nil {
		s.recordListenerFailure(ctx, operationListenerDrain, err)

		return ListenerMutationResult{}, err
	}

	detail = normalizeListenerDetail(detail)
	s.recordListenerDetail(ctx, observability.EventListenerDrain, operationListenerDrain, runtimeObservationResultOK, "drain", detail)

	return ListenerMutationResult{Listener: detail, Audit: audit}, nil
}

// ResumeListener validates, audits and delegates one process-local listener resume.
func (s *ListenerService) ResumeListener(ctx context.Context, request ResumeListenerRequest) (ListenerMutationResult, error) {
	if err := request.Validate(); err != nil {
		s.recordListenerFailure(ctx, operationListenerResume, err)

		return ListenerMutationResult{}, err
	}

	manager, err := s.requireManager(operationListenerResume)
	if err != nil {
		s.recordListenerFailure(ctx, operationListenerResume, err)

		return ListenerMutationResult{}, err
	}

	detail, err := manager.Resume(ctx, strings.TrimSpace(request.Name))
	if err != nil {
		classified := classifyListenerError(operationListenerResume, err)
		s.recordListenerFailure(ctx, operationListenerResume, classified)

		return ListenerMutationResult{}, classified
	}

	audit, err := listenerAuditMetadata(AuditOperationListenerResume, request.Reason, request.Actor, detail, nil)
	if err != nil {
		s.recordListenerFailure(ctx, operationListenerResume, err)

		return ListenerMutationResult{}, err
	}

	detail = normalizeListenerDetail(detail)
	s.recordListenerDetail(ctx, observability.EventListenerResume, operationListenerResume, runtimeObservationResultOK, runtimeObservationResultOK, detail)

	return ListenerMutationResult{Listener: detail, Audit: audit}, nil
}

// Validate checks the listener lookup request before manager access.
func (r GetListenerRequest) Validate() error {
	return requireListenerName(operationListenerGet, r.Name)
}

// Validate checks the listener drain request before manager access.
func (r DrainListenerRequest) Validate() error {
	if err := requireListenerName(operationListenerDrain, r.Name); err != nil {
		return err
	}

	if err := requireReason(operationListenerDrain, r.Reason); err != nil {
		return err
	}

	return validateListenerDrainGrace(operationListenerDrain, normalizeListenerDrainMode(r.Mode), r.Grace)
}

// Validate checks the listener resume request before manager access.
func (r ResumeListenerRequest) Validate() error {
	if err := requireListenerName(operationListenerResume, r.Name); err != nil {
		return err
	}

	return requireReason(operationListenerResume, r.Reason)
}

// managerRequest converts a validated runtime drain request into manager input.
func (r DrainListenerRequest) managerRequest() (ListenerManagerDrainRequest, error) {
	if err := r.Validate(); err != nil {
		return ListenerManagerDrainRequest{}, err
	}

	return ListenerManagerDrainRequest{
		Name:  strings.TrimSpace(r.Name),
		Mode:  normalizeListenerDrainMode(r.Mode),
		Grace: cloneGrace(r.Grace),
	}, nil
}

// requireManager returns a listener manager or a classified unavailable error.
func (s *ListenerService) requireManager(operation string) (ListenerManager, error) {
	if s == nil || s.manager == nil {
		return nil, newRuntimeError(ErrorKindUnavailable, operation, "listener manager unavailable")
	}

	return s.manager, nil
}

// requireListenerName rejects blank listener names before manager access.
func requireListenerName(operation string, name string) error {
	if strings.TrimSpace(name) == "" {
		return newRuntimeError(ErrorKindInvalidRequest, operation, "listener name required")
	}

	return nil
}

// validateListenerDrainGrace enforces mode and grace rules for process-local drains.
func validateListenerDrainGrace(operation string, mode ListenerDrainMode, grace *time.Duration) error {
	switch mode {
	case ListenerDrainModeSoft:
		if grace != nil && *grace < 0 {
			return newRuntimeError(ErrorKindInvalidRequest, operation, "grace must not be negative")
		}

		return nil
	case ListenerDrainModeHard:
		if grace == nil {
			return newRuntimeError(ErrorKindInvalidRequest, operation, "hard drain requires explicit grace")
		}

		if *grace < 0 {
			return newRuntimeError(ErrorKindInvalidRequest, operation, "grace must not be negative")
		}

		return nil
	default:
		return newRuntimeError(ErrorKindInvalidRequest, operation, "unsupported drain mode")
	}
}

// normalizeListenerDrainMode trims and lowercases listener drain modes.
func normalizeListenerDrainMode(mode ListenerDrainMode) ListenerDrainMode {
	return ListenerDrainMode(strings.ToLower(strings.TrimSpace(string(mode))))
}

// cloneGrace copies the optional grace pointer before passing it to a manager.
func cloneGrace(grace *time.Duration) *time.Duration {
	if grace == nil {
		return nil
	}

	value := *grace

	return &value
}

// listenerByName finds a listener projection by its configured name.
func listenerByName(listeners []ListenerDetail, name string) (ListenerDetail, bool) {
	name = strings.TrimSpace(name)
	for _, detail := range listeners {
		if strings.TrimSpace(detail.Name) == name {
			return detail, true
		}
	}

	return ListenerDetail{}, false
}

// normalizeListenerDetails returns stable listener projections ordered by name.
func normalizeListenerDetails(listeners []ListenerDetail) []ListenerDetail {
	normalized := make([]ListenerDetail, 0, len(listeners))
	for _, detail := range listeners {
		normalized = append(normalized, normalizeListenerDetail(detail))
	}

	sort.Slice(normalized, func(left int, right int) bool {
		return normalized[left].Name < normalized[right].Name
	})

	return normalized
}

// normalizeListenerDetail trims operator-visible string fields without adding state.
func normalizeListenerDetail(detail ListenerDetail) ListenerDetail {
	detail.Name = strings.TrimSpace(detail.Name)
	detail.Protocol = strings.TrimSpace(detail.Protocol)
	detail.ServiceName = strings.TrimSpace(detail.ServiceName)
	detail.Network = strings.TrimSpace(detail.Network)
	detail.Address = strings.TrimSpace(detail.Address)
	detail.TLSMode = strings.TrimSpace(detail.TLSMode)
	detail.BoundAddress = strings.TrimSpace(detail.BoundAddress)
	detail.DrainMode = normalizeListenerDrainMode(detail.DrainMode)

	return detail
}

// classifyListenerError maps manager failures into runtime control errors.
func classifyListenerError(operation string, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrListenerNotFound):
		return newRuntimeError(ErrorKindNotFound, operation, "listener not found")
	case errors.Is(err, ErrListenerManagerUnavailable):
		return newRuntimeError(ErrorKindUnavailable, operation, "listener manager unavailable")
	case errors.Is(err, ErrListenerOperationConflict):
		return newRuntimeError(ErrorKindConflict, operation, "listener operation conflict")
	default:
		return newRuntimeError(ErrorKindConflict, operation, "listener operation failed")
	}
}

// listenerAuditMetadata builds secret-safe metadata for listener mutations.
func listenerAuditMetadata(
	operation AuditOperation,
	reason string,
	actor Actor,
	detail ListenerDetail,
	fields map[string]string,
) (AuditMetadata, error) {
	detail = normalizeListenerDetail(detail)

	if fields == nil {
		fields = map[string]string{}
	}

	fields[auditFieldListenerName] = detail.Name
	fields[auditFieldStatus] = string(detail.State)
	fields[auditFieldActiveSessionCount] = strconv.Itoa(detail.ActiveLocalSessions)

	return NewAuditMetadata(AuditInput{
		Operation:  operation,
		Reason:     reason,
		Actor:      actor,
		ServerTime: time.Now().UTC(),
		Fields:     fields,
	})
}

// graceAuditValue renders the explicit grace value without losing explicit zero.
func graceAuditValue(grace *time.Duration) string {
	if grace == nil {
		return ""
	}

	return strconv.FormatInt(int64(grace.Seconds()), 10)
}

// recordListenerInventory emits an aggregate low-cardinality inventory event.
func (s *ListenerService) recordListenerInventory(ctx context.Context, operation string, listeners []ListenerDetail) {
	if s == nil {
		return
	}

	recordRuntimeObservation(
		ctx,
		s.recorder,
		observability.EventListenerInventory,
		observability.TraceBoundaryRESTRequest,
		operation,
		runtimeObservationResultOK,
		runtimeObservationResultOK,
		map[string]string{
			listenerObservationFieldListenerTotal: strconv.Itoa(len(listeners)),
		},
		nil,
	)
}

// recordListenerDetail emits one low-cardinality listener runtime event.
func (s *ListenerService) recordListenerDetail(
	ctx context.Context,
	event string,
	operation string,
	result string,
	reasonClass string,
	detail ListenerDetail,
) {
	if s == nil {
		return
	}

	detail = normalizeListenerDetail(detail)
	fields := map[string]string{
		runtimeObservationFieldActiveSessions: strconv.Itoa(detail.ActiveLocalSessions),
		runtimeObservationFieldListener:       detail.Name,
		runtimeObservationFieldProtocol:       detail.Protocol,
		runtimeObservationFieldService:        detail.ServiceName,
		listenerObservationFieldDrainMode:     string(detail.DrainMode),
		listenerObservationFieldListenerState: string(detail.State),
	}
	labels := map[string]string{
		runtimeObservationFieldListener: detail.Name,
		runtimeObservationFieldProtocol: detail.Protocol,
		runtimeObservationFieldService:  detail.ServiceName,
	}

	recordRuntimeObservation(ctx, s.recorder, event, observability.TraceBoundaryRESTRequest, operation, result, reasonClass, fields, labels)
}

// recordListenerFailure emits a bounded failure event without operator reason text.
func (s *ListenerService) recordListenerFailure(ctx context.Context, operation string, err error) {
	if s == nil {
		return
	}

	recordRuntimeObservation(
		ctx,
		s.recorder,
		observability.EventListenerOperationFailure,
		observability.TraceBoundaryRESTRequest,
		operation,
		runtimeObservationResultFailure,
		listenerFailureReasonClass(err),
		nil,
		nil,
	)
}

// listenerFailureReasonClass maps runtime errors into bounded failure classes.
func listenerFailureReasonClass(err error) string {
	var runtimeErr *Error
	if errors.As(err, &runtimeErr) {
		return string(runtimeErr.Kind)
	}

	return runtimeObservationReasonOther
}
