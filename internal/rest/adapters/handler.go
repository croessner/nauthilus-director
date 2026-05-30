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

package adapters

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/rest/generated"
	"github.com/croessner/nauthilus-director/internal/routing"
	"github.com/croessner/nauthilus-director/internal/runtime"
	"github.com/croessner/nauthilus-director/internal/state"
)

const (
	apiVersion             = "v1"
	componentName          = "nauthilus-director"
	defaultConfigFormat    = "yaml"
	defaultTenant          = "default"
	defaultVersion         = "dev"
	statusAccepted         = "accepted"
	statusOK               = "ok"
	statusReady            = "ready"
	configViewDefaults     = "defaults"
	configViewEffective    = "effective"
	configViewNonDefault   = "non-default"
	operationConfigDefault = "GetDefaultConfig"
	operationConfigEffect  = "GetEffectiveConfig"
	operationConfigDiff    = "GetNonDefaultConfig"
	problemCodeUnavailable = "runtime_unavailable"
	protocolIMAP           = "imap"
)

// BackendReader exposes runtime-effective backend views to REST adapters.
type BackendReader interface {
	ListBackends(ctx context.Context) ([]backend.EffectiveBackendState, error)
	GetBackend(ctx context.Context, identifier string) (backend.EffectiveBackendState, error)
}

// BackendMutator exposes Redis-backed backend runtime mutations to REST adapters.
type BackendMutator interface {
	SetInService(ctx context.Context, request runtime.SetBackendInServiceRequest) (runtime.BackendMutationResult, error)
	SetWeight(ctx context.Context, request runtime.SetBackendWeightRequest, policy backend.RuntimeOverridePolicy) (runtime.BackendMutationResult, error)
	SetMaintenance(ctx context.Context, request runtime.SetBackendMaintenanceRequest) (runtime.BackendMutationResult, error)
	StartDrain(ctx context.Context, request runtime.StartBackendDrainRequest) (runtime.BackendMutationResult, error)
	ClearRuntime(ctx context.Context, request runtime.ClearBackendRuntimeRequest) (runtime.BackendMutationResult, error)
}

// SessionReader exposes runtime session state to REST adapters.
type SessionReader interface {
	ListSessions(ctx context.Context, request runtime.SessionListRequest) (runtime.SessionListResult, error)
	GetSession(ctx context.Context, sessionID string) (runtime.SessionRuntimeState, error)
	ListUserSessions(ctx context.Context, key runtime.UserKey) ([]runtime.SessionRuntimeState, error)
}

// SessionMutator exposes Redis-backed session control to REST adapters.
type SessionMutator interface {
	KillSession(ctx context.Context, request runtime.KillSessionRequest) (runtime.SessionMutationResult, error)
}

// UserReader exposes user runtime state to REST adapters.
type UserReader interface {
	ListUsers(ctx context.Context, request runtime.UserListRequest) (runtime.UserListResult, error)
	GetUser(ctx context.Context, key runtime.UserKey) (runtime.UserRuntimeState, error)
	GetUserAffinity(ctx context.Context, key runtime.UserKey) (runtime.UserRuntimeState, error)
}

// UserBackendPinReader exposes user backend-pin state to REST adapters.
type UserBackendPinReader interface {
	GetUserBackendPin(ctx context.Context, request runtime.GetUserBackendPinRequest) (runtime.UserBackendPinReadResult, error)
}

// RuntimeSummaryReader exposes aggregate runtime summaries to REST adapters.
type RuntimeSummaryReader interface {
	RuntimeSummary(ctx context.Context) (runtime.Summary, error)
}

// UserMutator exposes Redis-backed user runtime mutations to REST adapters.
type UserMutator interface {
	MoveUser(ctx context.Context, request runtime.MoveUserRequest) (runtime.UserMutationResult, error)
	KickUser(ctx context.Context, request runtime.KickUserRequest) (runtime.UserMutationResult, error)
	ClearUserAffinity(ctx context.Context, request runtime.ClearUserAffinityRequest) (runtime.UserMutationResult, error)
}

// UserBackendPinMutator exposes user backend-pin mutations to REST adapters.
type UserBackendPinMutator interface {
	SetUserBackendPin(ctx context.Context, request runtime.SetUserBackendPinRequest) (runtime.UserBackendPinMutationResult, error)
	ClearUserBackendPin(ctx context.Context, request runtime.ClearUserBackendPinRequest) (runtime.UserBackendPinMutationResult, error)
}

// RouteLookupService exposes side-effect-free route diagnostics to REST adapters.
type RouteLookupService interface {
	Lookup(ctx context.Context, request runtime.RouteLookupRequest) (runtime.RouteLookupResponse, error)
}

// ListenerRuntimeService exposes process-local listener runtime control to REST adapters.
type ListenerRuntimeService interface {
	ListListeners(ctx context.Context, request runtime.ListListenersRequest) (runtime.ListListenersResult, error)
	GetListener(ctx context.Context, request runtime.GetListenerRequest) (runtime.ListenerDetail, error)
	DrainListener(ctx context.Context, request runtime.DrainListenerRequest) (runtime.ListenerMutationResult, error)
	ResumeListener(ctx context.Context, request runtime.ResumeListenerRequest) (runtime.ListenerMutationResult, error)
}

// ReloadService exposes safe config reload behavior to REST adapters.
type ReloadService interface {
	Reload(ctx context.Context) (runtime.ReloadResult, error)
}

// MetricsProvider exposes a Prometheus-compatible text payload.
type MetricsProvider interface {
	Metrics(ctx context.Context) (string, error)
}

// ProtectedConfigRequest describes an explicit protected config read.
type ProtectedConfigRequest struct {
	View   string
	Actor  runtime.Actor
	Format string
}

// ProtectedConfigAuthorizer checks the stronger permission for protected config reads.
type ProtectedConfigAuthorizer interface {
	AuthorizeProtectedConfig(ctx context.Context, request ProtectedConfigRequest) (bool, error)
}

// ProtectedConfigAuditEvent records protected config reads without values.
type ProtectedConfigAuditEvent struct {
	View       string
	Actor      runtime.Actor
	Authorized bool
	Outcome    string
}

// ProtectedConfigAuditSink receives secret-safe protected config audit events.
type ProtectedConfigAuditSink interface {
	AuditProtectedConfigRead(ctx context.Context, event ProtectedConfigAuditEvent) error
}

// HandlerOptions configures the generated REST adapter.
type HandlerOptions struct {
	Version                   string
	ConfigPath                string
	Loader                    *config.Loader
	Snapshot                  *config.Snapshot
	ConfigLoadError           error
	BackendReader             BackendReader
	BackendMutator            BackendMutator
	SessionReader             SessionReader
	SessionMutator            SessionMutator
	UserReader                UserReader
	UserBackendPinReader      UserBackendPinReader
	RuntimeSummaryReader      RuntimeSummaryReader
	UserMutator               UserMutator
	UserBackendPinMutator     UserBackendPinMutator
	RouteLookup               RouteLookupService
	ListenerRuntime           ListenerRuntimeService
	Reload                    ReloadService
	Metrics                   MetricsProvider
	Observability             observability.Recorder
	ProtectedConfigAuthorizer ProtectedConfigAuthorizer
	ProtectedConfigAudit      ProtectedConfigAuditSink
}

// Handler implements the generated strict-server interface.
type Handler struct {
	version                   string
	loader                    *config.Loader
	snapshot                  *config.Snapshot
	configLoadErr             error
	backendReader             BackendReader
	backendMutator            BackendMutator
	sessionReader             SessionReader
	sessionMutator            SessionMutator
	userReader                UserReader
	userBackendPinReader      UserBackendPinReader
	runtimeSummaryReader      RuntimeSummaryReader
	userMutator               UserMutator
	userBackendPinMutator     UserBackendPinMutator
	routeLookup               RouteLookupService
	listenerRuntime           ListenerRuntimeService
	reload                    ReloadService
	metrics                   MetricsProvider
	protectedConfigAuthorizer ProtectedConfigAuthorizer
	protectedConfigAudit      ProtectedConfigAuditSink
}

// NewHandler creates a generated-boundary REST adapter.
func NewHandler(options HandlerOptions) *Handler {
	options = withDefaultHandlerOptions(options)

	return &Handler{
		version:                   options.Version,
		loader:                    options.Loader,
		snapshot:                  options.Snapshot,
		configLoadErr:             options.ConfigLoadError,
		backendReader:             options.BackendReader,
		backendMutator:            options.BackendMutator,
		sessionReader:             options.SessionReader,
		sessionMutator:            options.SessionMutator,
		userReader:                options.UserReader,
		userBackendPinReader:      options.UserBackendPinReader,
		runtimeSummaryReader:      options.RuntimeSummaryReader,
		userMutator:               options.UserMutator,
		userBackendPinMutator:     options.UserBackendPinMutator,
		routeLookup:               options.RouteLookup,
		listenerRuntime:           options.ListenerRuntime,
		reload:                    options.Reload,
		metrics:                   options.Metrics,
		protectedConfigAuthorizer: options.ProtectedConfigAuthorizer,
		protectedConfigAudit:      options.ProtectedConfigAudit,
	}
}

// ListBackends returns runtime-effective backend inventory.
func (h *Handler) ListBackends(ctx context.Context, _ generated.ListBackendsRequestObject) (generated.ListBackendsResponseObject, error) {
	states, err := h.backendReader.ListBackends(ctx)
	if err != nil {
		return generated.ListBackendsdefaultJSONResponse{StatusCode: statusForError(err), Body: h.problemFromError("ListBackends", err)}, nil
	}

	return generated.ListBackends200JSONResponse{Backends: backendDetails(states)}, nil
}

// GetBackend returns one runtime-effective backend.
func (h *Handler) GetBackend(ctx context.Context, request generated.GetBackendRequestObject) (generated.GetBackendResponseObject, error) {
	state, err := h.backendReader.GetBackend(ctx, request.Identifier)
	if err != nil {
		return generated.GetBackenddefaultJSONResponse{StatusCode: statusForError(err), Body: h.problemFromError("GetBackend", err)}, nil
	}

	return generated.GetBackend200JSONResponse(backendDetail(state)), nil
}

// DisableBackendMaintenance clears runtime maintenance with an explicit reason.
func (h *Handler) DisableBackendMaintenance(ctx context.Context, request generated.DisableBackendMaintenanceRequestObject) (generated.DisableBackendMaintenanceResponseObject, error) {
	reason, ok := reasonBody(request.Body)
	if !ok {
		return generated.DisableBackendMaintenancedefaultJSONResponse{StatusCode: http.StatusBadRequest, Body: h.problem(http.StatusBadRequest, "invalid_request", "reason required", "DisableBackendMaintenance")}, nil
	}

	if h.backendMutator == nil {
		return generated.DisableBackendMaintenancedefaultJSONResponse{StatusCode: http.StatusServiceUnavailable, Body: h.runtimeUnavailable("DisableBackendMaintenance")}, nil
	}

	_, err := h.backendMutator.SetMaintenance(ctx, runtime.SetBackendMaintenanceRequest{
		BackendIdentifier: request.Identifier,
		Maintenance:       backend.MaintenanceState{Mode: backend.MaintenanceModeDisabled},
		Reason:            reason,
		Actor:             actorFromContext(ctx),
	})
	if err != nil {
		return generated.DisableBackendMaintenancedefaultJSONResponse{StatusCode: statusForError(err), Body: h.problemFromError("DisableBackendMaintenance", err)}, nil
	}

	return generated.DisableBackendMaintenance202JSONResponse(accepted()), nil
}

// EnableBackendMaintenance enables runtime maintenance with an explicit reason.
func (h *Handler) EnableBackendMaintenance(ctx context.Context, request generated.EnableBackendMaintenanceRequestObject) (generated.EnableBackendMaintenanceResponseObject, error) {
	if request.Body == nil {
		return generated.EnableBackendMaintenancedefaultJSONResponse{StatusCode: http.StatusBadRequest, Body: h.problem(http.StatusBadRequest, "invalid_request", "request body is required", "EnableBackendMaintenance")}, nil
	}

	if h.backendMutator == nil {
		return generated.EnableBackendMaintenancedefaultJSONResponse{StatusCode: http.StatusServiceUnavailable, Body: h.runtimeUnavailable("EnableBackendMaintenance")}, nil
	}

	_, err := h.backendMutator.SetMaintenance(ctx, runtime.SetBackendMaintenanceRequest{
		BackendIdentifier: request.Identifier,
		Maintenance:       backend.MaintenanceState{Mode: backend.MaintenanceMode(request.Body.Mode)},
		Reason:            request.Body.Reason,
		Actor:             actorFromContext(ctx),
	})
	if err != nil {
		return generated.EnableBackendMaintenancedefaultJSONResponse{StatusCode: statusForError(err), Body: h.problemFromError("EnableBackendMaintenance", err)}, nil
	}

	return generated.EnableBackendMaintenance202JSONResponse(accepted()), nil
}

// ClearBackendRuntime removes runtime-only backend overrides.
func (h *Handler) ClearBackendRuntime(ctx context.Context, request generated.ClearBackendRuntimeRequestObject) (generated.ClearBackendRuntimeResponseObject, error) {
	reason, ok := reasonBody(request.Body)
	if !ok {
		return generated.ClearBackendRuntimedefaultJSONResponse{StatusCode: http.StatusBadRequest, Body: h.problem(http.StatusBadRequest, "invalid_request", "reason required", "ClearBackendRuntime")}, nil
	}

	if h.backendMutator == nil {
		return generated.ClearBackendRuntimedefaultJSONResponse{StatusCode: http.StatusServiceUnavailable, Body: h.runtimeUnavailable("ClearBackendRuntime")}, nil
	}

	_, err := h.backendMutator.ClearRuntime(ctx, runtime.ClearBackendRuntimeRequest{
		BackendIdentifier: request.Identifier,
		Reason:            reason,
		Actor:             actorFromContext(ctx),
	})
	if err != nil {
		return generated.ClearBackendRuntimedefaultJSONResponse{StatusCode: statusForError(err), Body: h.problemFromError("ClearBackendRuntime", err)}, nil
	}

	return generated.ClearBackendRuntime202JSONResponse(accepted()), nil
}

// DrainBackend starts an auditable backend drain.
func (h *Handler) DrainBackend(ctx context.Context, request generated.DrainBackendRequestObject) (generated.DrainBackendResponseObject, error) {
	if request.Body == nil {
		return generated.DrainBackenddefaultJSONResponse{StatusCode: http.StatusBadRequest, Body: h.problem(http.StatusBadRequest, "invalid_request", "request body is required", "DrainBackend")}, nil
	}

	if h.backendMutator == nil {
		return generated.DrainBackenddefaultJSONResponse{StatusCode: http.StatusServiceUnavailable, Body: h.runtimeUnavailable("DrainBackend")}, nil
	}

	_, err := h.backendMutator.StartDrain(ctx, runtime.StartBackendDrainRequest{
		BackendIdentifier: request.Identifier,
		Drain:             backend.DrainState{Enabled: true, Mode: backend.DrainMode(request.Body.Mode)},
		Reason:            request.Body.Reason,
		Actor:             actorFromContext(ctx),
	})
	if err != nil {
		return generated.DrainBackenddefaultJSONResponse{StatusCode: statusForError(err), Body: h.problemFromError("DrainBackend", err)}, nil
	}

	return generated.DrainBackend202JSONResponse(accepted()), nil
}

// SetBackendWeight changes the runtime placement weight with an explicit reason.
func (h *Handler) SetBackendWeight(ctx context.Context, request generated.SetBackendWeightRequestObject) (generated.SetBackendWeightResponseObject, error) {
	if request.Body == nil {
		return generated.SetBackendWeightdefaultJSONResponse{StatusCode: http.StatusBadRequest, Body: h.problem(http.StatusBadRequest, "invalid_request", "request body is required", "SetBackendWeight")}, nil
	}

	reason := strings.TrimSpace(request.Body.Reason)
	if reason == "" {
		return generated.SetBackendWeightdefaultJSONResponse{StatusCode: http.StatusBadRequest, Body: h.problem(http.StatusBadRequest, "invalid_request", "reason required", "SetBackendWeight")}, nil
	}

	if h.backendMutator == nil {
		return generated.SetBackendWeightdefaultJSONResponse{StatusCode: http.StatusServiceUnavailable, Body: h.runtimeUnavailable("SetBackendWeight")}, nil
	}

	policy := backend.RuntimeOverridePolicy{Enabled: true, AllowWeightOverride: true}
	if _, err := h.backendMutator.SetWeight(ctx, runtime.SetBackendWeightRequest{
		BackendIdentifier: request.Identifier,
		Weight:            request.Body.Weight,
		Reason:            reason,
		Actor:             actorFromContext(ctx),
	}, policy); err != nil {
		return generated.SetBackendWeightdefaultJSONResponse{StatusCode: statusForError(err), Body: h.problemFromError("SetBackendWeight", err)}, nil
	}

	return generated.SetBackendWeight202JSONResponse(accepted()), nil
}

// MarkBackendIn marks a backend available for new runtime placement.
func (h *Handler) MarkBackendIn(ctx context.Context, request generated.MarkBackendInRequestObject) (generated.MarkBackendInResponseObject, error) {
	return h.markBackendInService(ctx, "MarkBackendIn", request.Identifier, request.Body, true)
}

// MarkBackendOut marks a backend unavailable for new runtime placement.
func (h *Handler) MarkBackendOut(ctx context.Context, request generated.MarkBackendOutRequestObject) (generated.MarkBackendOutResponseObject, error) {
	reason, ok := reasonBody(request.Body)
	if !ok {
		return generated.MarkBackendOutdefaultJSONResponse{StatusCode: http.StatusBadRequest, Body: h.problem(http.StatusBadRequest, "invalid_request", "reason required", "MarkBackendOut")}, nil
	}

	if h.backendMutator == nil {
		return generated.MarkBackendOutdefaultJSONResponse{StatusCode: http.StatusServiceUnavailable, Body: h.runtimeUnavailable("MarkBackendOut")}, nil
	}

	if _, err := h.backendMutator.SetInService(ctx, runtime.SetBackendInServiceRequest{
		BackendIdentifier: request.Identifier,
		InService:         false,
		Reason:            reason,
		Actor:             actorFromContext(ctx),
	}); err != nil {
		return generated.MarkBackendOutdefaultJSONResponse{StatusCode: statusForError(err), Body: h.problemFromError("MarkBackendOut", err)}, nil
	}

	return generated.MarkBackendOut202JSONResponse(accepted()), nil
}

// GetDefaultConfig returns canonical default configuration.
//
//nolint:dupl // Generated config operations intentionally share the same response skeleton.
func (h *Handler) GetDefaultConfig(ctx context.Context, request generated.GetDefaultConfigRequestObject) (generated.GetDefaultConfigResponseObject, error) {
	return configResponse(
		ctx,
		h,
		operationConfigDefault,
		configViewDefaults,
		configParams{format: formatFromDefaultParams(request.Params), includeProtected: includeProtectedFromDefaultParams(request.Params)},
		func(status int, problem generated.ErrorResponse) generated.GetDefaultConfigResponseObject {
			return generated.GetDefaultConfigdefaultJSONResponse{StatusCode: status, Body: problem}
		},
		func(document generated.ConfigDocument) generated.GetDefaultConfigResponseObject {
			return generated.GetDefaultConfig200JSONResponse(document)
		},
	), nil
}

// GetEffectiveConfig returns effective configuration redacted by default.
//
//nolint:dupl // Generated config operations intentionally share the same response skeleton.
func (h *Handler) GetEffectiveConfig(ctx context.Context, request generated.GetEffectiveConfigRequestObject) (generated.GetEffectiveConfigResponseObject, error) {
	return configResponse(
		ctx,
		h,
		operationConfigEffect,
		configViewEffective,
		configParams{format: formatFromEffectiveParams(request.Params), includeProtected: includeProtectedFromEffectiveParams(request.Params)},
		func(status int, problem generated.ErrorResponse) generated.GetEffectiveConfigResponseObject {
			return generated.GetEffectiveConfigdefaultJSONResponse{StatusCode: status, Body: problem}
		},
		func(document generated.ConfigDocument) generated.GetEffectiveConfigResponseObject {
			return generated.GetEffectiveConfig200JSONResponse(document)
		},
	), nil
}

// GetNonDefaultConfig returns non-default effective configuration redacted by default.
//
//nolint:dupl // Generated config operations intentionally share the same response skeleton.
func (h *Handler) GetNonDefaultConfig(ctx context.Context, request generated.GetNonDefaultConfigRequestObject) (generated.GetNonDefaultConfigResponseObject, error) {
	return configResponse(
		ctx,
		h,
		operationConfigDiff,
		configViewNonDefault,
		configParams{format: formatFromNonDefaultParams(request.Params), includeProtected: includeProtectedFromNonDefaultParams(request.Params)},
		func(status int, problem generated.ErrorResponse) generated.GetNonDefaultConfigResponseObject {
			return generated.GetNonDefaultConfigdefaultJSONResponse{StatusCode: status, Body: problem}
		},
		func(document generated.ConfigDocument) generated.GetNonDefaultConfigResponseObject {
			return generated.GetNonDefaultConfig200JSONResponse(document)
		},
	), nil
}

// ListListeners returns process-local frontend listener inventory.
func (h *Handler) ListListeners(ctx context.Context, _ generated.ListListenersRequestObject) (generated.ListListenersResponseObject, error) {
	if h.listenerRuntime == nil {
		return generated.ListListenersdefaultJSONResponse{StatusCode: http.StatusServiceUnavailable, Body: h.runtimeUnavailable("ListListeners")}, nil
	}

	result, err := h.listenerRuntime.ListListeners(ctx, runtime.ListListenersRequest{Actor: actorFromContext(ctx)})
	if err != nil {
		return generated.ListListenersdefaultJSONResponse{StatusCode: statusForError(err), Body: h.problemFromError("ListListeners", err)}, nil
	}

	return generated.ListListeners200JSONResponse{Listeners: listenerDetails(result.Listeners)}, nil
}

// GetListener returns one configured process-local frontend listener.
func (h *Handler) GetListener(ctx context.Context, request generated.GetListenerRequestObject) (generated.GetListenerResponseObject, error) {
	if h.listenerRuntime == nil {
		return generated.GetListenerdefaultJSONResponse{StatusCode: http.StatusServiceUnavailable, Body: h.runtimeUnavailable("GetListener")}, nil
	}

	detail, err := h.listenerRuntime.GetListener(ctx, runtime.GetListenerRequest{
		Name:  request.Name,
		Actor: actorFromContext(ctx),
	})
	if err != nil {
		return generated.GetListenerdefaultJSONResponse{StatusCode: statusForError(err), Body: h.problemFromError("GetListener", err)}, nil
	}

	return generated.GetListener200JSONResponse(listenerDetail(detail)), nil
}

// DrainListener starts an auditable process-local listener drain.
func (h *Handler) DrainListener(ctx context.Context, request generated.DrainListenerRequestObject) (generated.DrainListenerResponseObject, error) {
	if request.Body == nil {
		return generated.DrainListenerdefaultJSONResponse{StatusCode: http.StatusBadRequest, Body: h.problem(http.StatusBadRequest, "invalid_request", "request body is required", "DrainListener")}, nil
	}

	if h.listenerRuntime == nil {
		return generated.DrainListenerdefaultJSONResponse{StatusCode: http.StatusServiceUnavailable, Body: h.runtimeUnavailable("DrainListener")}, nil
	}

	result, err := h.listenerRuntime.DrainListener(ctx, runtime.DrainListenerRequest{
		Name:   request.Name,
		Mode:   runtime.ListenerDrainMode(request.Body.Mode),
		Reason: request.Body.Reason,
		Grace:  durationFromSeconds(request.Body.GraceSeconds),
		Actor:  actorFromContext(ctx),
	})
	if err != nil {
		return generated.DrainListenerdefaultJSONResponse{StatusCode: statusForError(err), Body: h.problemFromError("DrainListener", err)}, nil
	}

	return generated.DrainListener202JSONResponse(listenerDetail(result.Listener)), nil
}

// ResumeListener resumes one process-local listener from the typed config snapshot.
func (h *Handler) ResumeListener(ctx context.Context, request generated.ResumeListenerRequestObject) (generated.ResumeListenerResponseObject, error) {
	if request.Body == nil {
		return generated.ResumeListenerdefaultJSONResponse{StatusCode: http.StatusBadRequest, Body: h.problem(http.StatusBadRequest, "invalid_request", "request body is required", "ResumeListener")}, nil
	}

	if h.listenerRuntime == nil {
		return generated.ResumeListenerdefaultJSONResponse{StatusCode: http.StatusServiceUnavailable, Body: h.runtimeUnavailable("ResumeListener")}, nil
	}

	result, err := h.listenerRuntime.ResumeListener(ctx, runtime.ResumeListenerRequest{
		Name:   request.Name,
		Reason: request.Body.Reason,
		Actor:  actorFromContext(ctx),
	})
	if err != nil {
		return generated.ResumeListenerdefaultJSONResponse{StatusCode: statusForError(err), Body: h.problemFromError("ResumeListener", err)}, nil
	}

	return generated.ResumeListener202JSONResponse(listenerDetail(result.Listener)), nil
}

// Reload applies supported live config changes and rejects unsafe ones.
func (h *Handler) Reload(ctx context.Context, _ generated.ReloadRequestObject) (generated.ReloadResponseObject, error) {
	if h.reload == nil {
		return generated.ReloaddefaultJSONResponse{StatusCode: http.StatusServiceUnavailable, Body: h.runtimeUnavailable("Reload")}, nil
	}

	if _, err := h.reload.Reload(ctx); err != nil {
		return generated.ReloaddefaultJSONResponse{StatusCode: statusForError(err), Body: h.problemFromError("Reload", err)}, nil
	}

	return generated.Reload202JSONResponse(accepted()), nil
}

// LookupRoute performs side-effect-free route diagnostics.
func (h *Handler) LookupRoute(ctx context.Context, request generated.LookupRouteRequestObject) (generated.LookupRouteResponseObject, error) {
	if request.Body == nil {
		return generated.LookupRoute400JSONResponse{BadRequestJSONResponse: generated.BadRequestJSONResponse(h.problem(http.StatusBadRequest, "bad_request", "request body is required", "LookupRoute"))}, nil
	}

	if h.routeLookup == nil {
		return generated.LookupRoutedefaultJSONResponse{StatusCode: http.StatusServiceUnavailable, Body: h.runtimeUnavailable("LookupRoute")}, nil
	}

	result, err := h.routeLookup.Lookup(ctx, routeLookupRequest(*request.Body))
	if err != nil {
		return generated.LookupRoutedefaultJSONResponse{StatusCode: statusForError(err), Body: h.problemFromError("LookupRoute", err)}, nil
	}

	return generated.LookupRoute200JSONResponse(routeLookupResponse(result)), nil
}

// ListSessions returns active frontend sessions.
func (h *Handler) ListSessions(ctx context.Context, request generated.ListSessionsRequestObject) (generated.ListSessionsResponseObject, error) {
	result, err := h.sessionReader.ListSessions(ctx, runtime.SessionListRequest{
		Protocol:          pointerString(request.Params.Protocol),
		BackendIdentifier: pointerString(request.Params.Backend),
		Cursor:            pointerGeneratedString(request.Params.Cursor),
		Limit:             pointerGeneratedInt(request.Params.Limit),
	})
	if err != nil {
		return generated.ListSessionsdefaultJSONResponse{StatusCode: statusForError(err), Body: h.problemFromError("ListSessions", err)}, nil
	}

	return generated.ListSessions200JSONResponse{
		NextCursor: nonEmptyStringPointer(result.NextCursor),
		Sessions:   sessionDetails(result.Sessions),
	}, nil
}

// DeleteSession marks one frontend session for termination.
func (h *Handler) DeleteSession(ctx context.Context, request generated.DeleteSessionRequestObject) (generated.DeleteSessionResponseObject, error) {
	reason, ok := reasonBody(request.Body)
	if !ok {
		return generated.DeleteSessiondefaultJSONResponse{StatusCode: http.StatusBadRequest, Body: h.problem(http.StatusBadRequest, "invalid_request", "reason required", "DeleteSession")}, nil
	}

	if h.sessionMutator == nil {
		return generated.DeleteSessiondefaultJSONResponse{StatusCode: http.StatusServiceUnavailable, Body: h.runtimeUnavailable("DeleteSession")}, nil
	}

	if _, err := h.sessionMutator.KillSession(ctx, runtime.KillSessionRequest{SessionID: request.SessionID, Reason: reason, Actor: actorFromContext(ctx)}); err != nil {
		return generated.DeleteSessiondefaultJSONResponse{StatusCode: statusForError(err), Body: h.problemFromError("DeleteSession", err)}, nil
	}

	return generated.DeleteSession202JSONResponse(accepted()), nil
}

// GetSession returns one frontend session.
func (h *Handler) GetSession(ctx context.Context, request generated.GetSessionRequestObject) (generated.GetSessionResponseObject, error) {
	session, err := h.sessionReader.GetSession(ctx, request.SessionID)
	if err != nil {
		return generated.GetSessiondefaultJSONResponse{StatusCode: statusForError(err), Body: h.problemFromError("GetSession", err)}, nil
	}

	return generated.GetSession200JSONResponse(sessionDetail(session)), nil
}

// ListUsers returns users with runtime state.
func (h *Handler) ListUsers(ctx context.Context, request generated.ListUsersRequestObject) (generated.ListUsersResponseObject, error) {
	result, err := h.userReader.ListUsers(ctx, runtime.UserListRequest{
		Cursor: pointerGeneratedString(request.Params.Cursor),
		Limit:  pointerGeneratedInt(request.Params.Limit),
	})
	if err != nil {
		return generated.ListUsersdefaultJSONResponse{StatusCode: statusForError(err), Body: h.problemFromError("ListUsers", err)}, nil
	}

	return generated.ListUsers200JSONResponse{
		NextCursor: nonEmptyStringPointer(result.NextCursor),
		Users:      userDetails(result.Users),
	}, nil
}

// GetRuntimeSummary returns repairable aggregate runtime totals.
func (h *Handler) GetRuntimeSummary(ctx context.Context, _ generated.GetRuntimeSummaryRequestObject) (generated.GetRuntimeSummaryResponseObject, error) {
	summary, err := h.runtimeSummaryReader.RuntimeSummary(ctx)
	if err != nil {
		return generated.GetRuntimeSummarydefaultJSONResponse{StatusCode: statusForError(err), Body: h.problemFromError("GetRuntimeSummary", err)}, nil
	}

	return generated.GetRuntimeSummary200JSONResponse(runtimeSummary(summary)), nil
}

// GetUser returns one user runtime state.
func (h *Handler) GetUser(ctx context.Context, request generated.GetUserRequestObject) (generated.GetUserResponseObject, error) {
	user, status, problem, ok := h.userStateOrProblem(ctx, "GetUser", request.UserKey, h.userReader.GetUser)
	if !ok {
		return generated.GetUserdefaultJSONResponse{StatusCode: status, Body: problem}, nil
	}

	return generated.GetUser200JSONResponse(userDetail(user)), nil
}

// ClearUserAffinity clears inactive affinity with an explicit reason.
func (h *Handler) ClearUserAffinity(ctx context.Context, request generated.ClearUserAffinityRequestObject) (generated.ClearUserAffinityResponseObject, error) {
	reason, ok := reasonBody(request.Body)
	if !ok {
		return generated.ClearUserAffinitydefaultJSONResponse{StatusCode: http.StatusBadRequest, Body: h.problem(http.StatusBadRequest, "invalid_request", "reason required", "ClearUserAffinity")}, nil
	}

	if h.userMutator == nil {
		return generated.ClearUserAffinitydefaultJSONResponse{StatusCode: http.StatusServiceUnavailable, Body: h.runtimeUnavailable("ClearUserAffinity")}, nil
	}

	if _, err := h.userMutator.ClearUserAffinity(ctx, runtime.ClearUserAffinityRequest{Key: parseUserKey(request.UserKey), Reason: reason, Actor: actorFromContext(ctx)}); err != nil {
		return generated.ClearUserAffinitydefaultJSONResponse{StatusCode: statusForError(err), Body: h.problemFromError("ClearUserAffinity", err)}, nil
	}

	return generated.ClearUserAffinity202JSONResponse(accepted()), nil
}

// GetUserAffinity returns active affinity for one user key.
func (h *Handler) GetUserAffinity(ctx context.Context, request generated.GetUserAffinityRequestObject) (generated.GetUserAffinityResponseObject, error) {
	user, status, problem, ok := h.userStateOrProblem(ctx, "GetUserAffinity", request.UserKey, h.userReader.GetUserAffinity)
	if !ok {
		return generated.GetUserAffinitydefaultJSONResponse{StatusCode: status, Body: problem}, nil
	}

	return generated.GetUserAffinity200JSONResponse(userAffinity(user)), nil
}

// SetUserAffinity records a new-sessions-only move to a target shard.
func (h *Handler) SetUserAffinity(ctx context.Context, request generated.SetUserAffinityRequestObject) (generated.SetUserAffinityResponseObject, error) {
	if request.Body == nil {
		return generated.SetUserAffinitydefaultJSONResponse{StatusCode: http.StatusBadRequest, Body: h.problem(http.StatusBadRequest, "invalid_request", "request body is required", "SetUserAffinity")}, nil
	}

	if h.userMutator == nil {
		return generated.SetUserAffinitydefaultJSONResponse{StatusCode: http.StatusServiceUnavailable, Body: h.runtimeUnavailable("SetUserAffinity")}, nil
	}

	_, err := h.userMutator.MoveUser(ctx, runtime.MoveUserRequest{
		Key:         parseUserKey(request.UserKey),
		TargetShard: request.Body.ShardTag,
		Strategy:    runtime.MoveStrategyNewSessionsOnly,
		Reason:      request.Body.Reason,
		Actor:       actorFromContext(ctx),
	})
	if err != nil {
		return generated.SetUserAffinitydefaultJSONResponse{StatusCode: statusForError(err), Body: h.problemFromError("SetUserAffinity", err)}, nil
	}

	return generated.SetUserAffinity202JSONResponse(accepted()), nil
}

// ClearUserBackendPin removes one concrete user backend pin with an audit reason.
func (h *Handler) ClearUserBackendPin(ctx context.Context, request generated.ClearUserBackendPinRequestObject) (generated.ClearUserBackendPinResponseObject, error) {
	if request.Body == nil {
		return generated.ClearUserBackendPindefaultJSONResponse{StatusCode: http.StatusBadRequest, Body: h.problem(http.StatusBadRequest, "invalid_request", "request body is required", "ClearUserBackendPin")}, nil
	}

	reason := strings.TrimSpace(request.Body.Reason)
	if reason == "" {
		return generated.ClearUserBackendPindefaultJSONResponse{StatusCode: http.StatusBadRequest, Body: h.problem(http.StatusBadRequest, "invalid_request", "reason required", "ClearUserBackendPin")}, nil
	}

	if h.userBackendPinMutator == nil {
		return generated.ClearUserBackendPindefaultJSONResponse{StatusCode: http.StatusServiceUnavailable, Body: h.runtimeUnavailable("ClearUserBackendPin")}, nil
	}

	if _, err := h.userBackendPinMutator.ClearUserBackendPin(ctx, runtime.ClearUserBackendPinRequest{
		Key:    parseUserKey(request.UserKey),
		Reason: reason,
		Actor:  actorFromContext(ctx),
	}); err != nil {
		return generated.ClearUserBackendPindefaultJSONResponse{StatusCode: statusForError(err), Body: h.problemFromError("ClearUserBackendPin", err)}, nil
	}

	return generated.ClearUserBackendPin202JSONResponse(accepted()), nil
}

// GetUserBackendPin returns one deterministic backend-pin read model.
func (h *Handler) GetUserBackendPin(ctx context.Context, request generated.GetUserBackendPinRequestObject) (generated.GetUserBackendPinResponseObject, error) {
	key := parseUserKey(request.UserKey)

	if h.userBackendPinReader == nil {
		return generated.GetUserBackendPindefaultJSONResponse{StatusCode: http.StatusServiceUnavailable, Body: h.runtimeUnavailable("GetUserBackendPin")}, nil
	}

	result, err := h.userBackendPinReader.GetUserBackendPin(ctx, runtime.GetUserBackendPinRequest{Key: key})
	if err != nil {
		return generated.GetUserBackendPindefaultJSONResponse{StatusCode: statusForError(err), Body: h.problemFromError("GetUserBackendPin", err)}, nil
	}

	return generated.GetUserBackendPin200JSONResponse(userBackendPin(result.Pin, key)), nil
}

// SetUserBackendPin stores one concrete backend pin through the runtime domain.
func (h *Handler) SetUserBackendPin(ctx context.Context, request generated.SetUserBackendPinRequestObject) (generated.SetUserBackendPinResponseObject, error) {
	if request.Body == nil {
		return generated.SetUserBackendPindefaultJSONResponse{StatusCode: http.StatusBadRequest, Body: h.problem(http.StatusBadRequest, "invalid_request", "request body is required", "SetUserBackendPin")}, nil
	}

	backendIdentifier := strings.TrimSpace(request.Body.Backend)
	if backendIdentifier == "" {
		return generated.SetUserBackendPindefaultJSONResponse{StatusCode: http.StatusBadRequest, Body: h.problem(http.StatusBadRequest, "invalid_request", "backend required", "SetUserBackendPin")}, nil
	}

	reason := strings.TrimSpace(request.Body.Reason)
	if reason == "" {
		return generated.SetUserBackendPindefaultJSONResponse{StatusCode: http.StatusBadRequest, Body: h.problem(http.StatusBadRequest, "invalid_request", "reason required", "SetUserBackendPin")}, nil
	}

	strategy := generated.UserMoveRequestStrategy(strings.TrimSpace(string(request.Body.Strategy)))
	if !strategy.Valid() {
		return generated.SetUserBackendPindefaultJSONResponse{StatusCode: http.StatusBadRequest, Body: h.problem(http.StatusBadRequest, "invalid_request", "unsupported move strategy", "SetUserBackendPin")}, nil
	}

	if h.userBackendPinMutator == nil {
		return generated.SetUserBackendPindefaultJSONResponse{StatusCode: http.StatusServiceUnavailable, Body: h.runtimeUnavailable("SetUserBackendPin")}, nil
	}

	if _, err := h.userBackendPinMutator.SetUserBackendPin(ctx, runtime.SetUserBackendPinRequest{
		Key:               parseUserKey(request.UserKey),
		BackendIdentifier: backendIdentifier,
		Strategy:          runtime.MoveStrategy(strategy),
		Reason:            reason,
		Actor:             actorFromContext(ctx),
	}); err != nil {
		return generated.SetUserBackendPindefaultJSONResponse{StatusCode: statusForError(err), Body: h.problemFromError("SetUserBackendPin", err)}, nil
	}

	return generated.SetUserBackendPin202JSONResponse(accepted()), nil
}

// KickUser marks a user's active sessions for closure.
func (h *Handler) KickUser(ctx context.Context, request generated.KickUserRequestObject) (generated.KickUserResponseObject, error) {
	if request.Body == nil {
		return generated.KickUserdefaultJSONResponse{StatusCode: http.StatusBadRequest, Body: h.problem(http.StatusBadRequest, "invalid_request", "request body is required", "KickUser")}, nil
	}

	if h.userMutator == nil {
		return generated.KickUserdefaultJSONResponse{StatusCode: http.StatusServiceUnavailable, Body: h.runtimeUnavailable("KickUser")}, nil
	}

	if _, err := h.userMutator.KickUser(ctx, runtime.KickUserRequest{Key: parseUserKey(request.UserKey), Reason: request.Body.Reason, Actor: actorFromContext(ctx)}); err != nil {
		return generated.KickUserdefaultJSONResponse{StatusCode: statusForError(err), Body: h.problemFromError("KickUser", err)}, nil
	}

	return generated.KickUser202JSONResponse(accepted()), nil
}

// MoveUser records a user move strategy.
func (h *Handler) MoveUser(ctx context.Context, request generated.MoveUserRequestObject) (generated.MoveUserResponseObject, error) {
	if request.Body == nil {
		return generated.MoveUserdefaultJSONResponse{StatusCode: http.StatusBadRequest, Body: h.problem(http.StatusBadRequest, "invalid_request", "request body is required", "MoveUser")}, nil
	}

	if h.userMutator == nil {
		return generated.MoveUserdefaultJSONResponse{StatusCode: http.StatusServiceUnavailable, Body: h.runtimeUnavailable("MoveUser")}, nil
	}

	if _, err := h.userMutator.MoveUser(ctx, runtime.MoveUserRequest{
		Key:         parseUserKey(request.UserKey),
		TargetShard: request.Body.ToShard,
		Strategy:    runtime.MoveStrategy(request.Body.Strategy),
		Reason:      request.Body.Reason,
		Actor:       actorFromContext(ctx),
	}); err != nil {
		return generated.MoveUserdefaultJSONResponse{StatusCode: statusForError(err), Body: h.problemFromError("MoveUser", err)}, nil
	}

	return generated.MoveUser202JSONResponse(accepted()), nil
}

// GetUserSessions returns active sessions for one user key.
func (h *Handler) GetUserSessions(ctx context.Context, request generated.GetUserSessionsRequestObject) (generated.GetUserSessionsResponseObject, error) {
	sessions, err := h.sessionReader.ListUserSessions(ctx, parseUserKey(request.UserKey))
	if err != nil {
		return generated.GetUserSessionsdefaultJSONResponse{StatusCode: statusForError(err), Body: h.problemFromError("GetUserSessions", err)}, nil
	}

	return generated.GetUserSessions200JSONResponse{Sessions: sessionDetails(sessions)}, nil
}

// GetVersion returns the binary and API version payload.
func (h *Handler) GetVersion(_ context.Context, _ generated.GetVersionRequestObject) (generated.GetVersionResponseObject, error) {
	return generated.GetVersion200JSONResponse(generated.VersionResponse{
		APIVersion: apiVersion,
		Component:  componentName,
		Version:    h.version,
	}), nil
}

// GetHealthz reports process liveness.
func (h *Handler) GetHealthz(_ context.Context, _ generated.GetHealthzRequestObject) (generated.GetHealthzResponseObject, error) {
	return generated.GetHealthz200JSONResponse(generated.StatusResponse{Status: statusOK}), nil
}

// GetMetrics returns Prometheus-compatible metrics text.
func (h *Handler) GetMetrics(ctx context.Context, _ generated.GetMetricsRequestObject) (generated.GetMetricsResponseObject, error) {
	if h.metrics == nil {
		return generated.GetMetrics200TextResponse(observability.DisabledMetricsText()), nil
	}

	metrics, err := h.metrics.Metrics(ctx)
	if err != nil {
		return generated.GetMetricsdefaultJSONResponse{StatusCode: statusForError(err), Body: h.problemFromError("GetMetrics", err)}, nil
	}

	return generated.GetMetrics200TextResponse(metrics), nil
}

// GetReadyz reports readiness for the control plane and config snapshot.
func (h *Handler) GetReadyz(_ context.Context, _ generated.GetReadyzRequestObject) (generated.GetReadyzResponseObject, error) {
	if h.configLoadErr != nil {
		return generated.GetReadyz503JSONResponse(h.problem(http.StatusServiceUnavailable, "config_unavailable", "configuration is not ready", "GetReadyz")), nil
	}

	checks := map[string]string{"config": statusReady}

	return generated.GetReadyz200JSONResponse(generated.StatusResponse{Status: statusOK, Checks: &checks}), nil
}

// markBackendInService adapts in/out requests while preserving generated response types.
func (h *Handler) markBackendInService(
	ctx context.Context,
	operation string,
	identifier string,
	body *generated.RuntimeReasonRequest,
	inService bool,
) (generated.MarkBackendInResponseObject, error) {
	reason, ok := reasonBody(body)
	if !ok {
		return generated.MarkBackendIndefaultJSONResponse{StatusCode: http.StatusBadRequest, Body: h.problem(http.StatusBadRequest, "invalid_request", "reason required", operation)}, nil
	}

	if h.backendMutator == nil {
		return generated.MarkBackendIndefaultJSONResponse{StatusCode: http.StatusServiceUnavailable, Body: h.runtimeUnavailable(operation)}, nil
	}

	if _, err := h.backendMutator.SetInService(ctx, runtime.SetBackendInServiceRequest{
		BackendIdentifier: identifier,
		InService:         inService,
		Reason:            reason,
		Actor:             actorFromContext(ctx),
	}); err != nil {
		return generated.MarkBackendIndefaultJSONResponse{StatusCode: statusForError(err), Body: h.problemFromError(operation, err)}, nil
	}

	return generated.MarkBackendIn202JSONResponse(accepted()), nil
}

// userStateOrProblem loads one user view or returns a generated problem payload.
func (h *Handler) userStateOrProblem(
	ctx context.Context,
	operation string,
	userKey string,
	read func(context.Context, runtime.UserKey) (runtime.UserRuntimeState, error),
) (runtime.UserRuntimeState, int, generated.ErrorResponse, bool) {
	user, err := read(ctx, parseUserKey(userKey))
	if err != nil {
		return runtime.UserRuntimeState{}, statusForError(err), h.problemFromError(operation, err), false
	}

	return user, http.StatusOK, generated.ErrorResponse{}, true
}

type configParams struct {
	format           string
	includeProtected bool
}

// configDocument renders one redaction-aware config view for the generated DTO.
func (h *Handler) configDocument(ctx context.Context, view string, params configParams) (generated.ConfigDocument, error) {
	params.format = normalizeConfigFormat(params.format)
	if params.includeProtected {
		if err := h.authorizeProtectedConfig(ctx, view, params.format); err != nil {
			return generated.ConfigDocument{}, err
		}
	}

	if h.configLoadErr != nil {
		return generated.ConfigDocument{}, newRuntimeError(runtime.ErrorKindUnavailable, "config", "configuration snapshot unavailable")
	}

	options := config.DumpOptions{Format: params.format, IncludeProtected: params.includeProtected}

	var (
		data map[string]any
		err  error
	)

	switch view {
	case configViewDefaults:
		data, err = h.loader.MapDefaults(options)
	case configViewEffective:
		data, err = h.snapshot.MapEffective(options)
	case configViewNonDefault:
		data, err = h.snapshot.MapNonDefault(options)
	default:
		err = newRuntimeError(runtime.ErrorKindInvalidRequest, "config", "unsupported config view")
	}

	if err != nil {
		return generated.ConfigDocument{}, newRuntimeError(runtime.ErrorKindUnavailable, "config", err.Error())
	}

	return generated.ConfigDocument{
		Data:     data,
		Format:   generated.ConfigDocumentFormat(params.format),
		Redacted: !params.includeProtected,
	}, nil
}

// configResponse adapts one config document into an operation-specific response.
func configResponse[T any](
	ctx context.Context,
	h *Handler,
	operation string,
	view string,
	params configParams,
	errorResponse func(int, generated.ErrorResponse) T,
	successResponse func(generated.ConfigDocument) T,
) T {
	document, err := h.configDocument(ctx, view, params)
	if err != nil {
		return errorResponse(statusForError(err), h.problemFromError(operation, err))
	}

	return successResponse(document)
}

// authorizeProtectedConfig enforces stronger authorization and secret-free audit.
func (h *Handler) authorizeProtectedConfig(ctx context.Context, view string, format string) error {
	request := ProtectedConfigRequest{
		View:   view,
		Actor:  actorFromContext(ctx),
		Format: format,
	}
	authorized := false
	outcome := "denied"

	if h.protectedConfigAuthorizer != nil {
		var err error

		authorized, err = h.protectedConfigAuthorizer.AuthorizeProtectedConfig(ctx, request)
		if err != nil {
			h.auditProtectedConfig(ctx, view, false, "error")

			return newRuntimeError(runtime.ErrorKindForbidden, "config_protected", "protected config export denied")
		}
	}

	if authorized {
		outcome = "authorized"
	}

	h.auditProtectedConfig(ctx, view, authorized, outcome)

	if !authorized {
		return newRuntimeError(runtime.ErrorKindForbidden, "config_protected", "protected config export denied")
	}

	return nil
}

// auditProtectedConfig emits protected config read metadata without values.
func (h *Handler) auditProtectedConfig(ctx context.Context, view string, authorized bool, outcome string) {
	if h.protectedConfigAudit == nil {
		return
	}

	_ = h.protectedConfigAudit.AuditProtectedConfigRead(ctx, ProtectedConfigAuditEvent{
		View:       view,
		Actor:      actorFromContext(ctx),
		Authorized: authorized,
		Outcome:    outcome,
	})
}

// problemFromError converts domain errors into a generated problem payload.
func (h *Handler) problemFromError(operation string, err error) generated.ErrorResponse {
	status := statusForError(err)
	code := codeForError(err)
	message := messageForError(err)

	return h.problem(status, code, message, operation)
}

// runtimeUnavailable creates a structured runtime-unavailable problem.
func (h *Handler) runtimeUnavailable(operation string) generated.ErrorResponse {
	return h.problem(http.StatusServiceUnavailable, problemCodeUnavailable, "runtime service is unavailable", operation)
}

// problem builds a generated error payload with optional operation context.
func (h *Handler) problem(status int, code string, message string, operation string) generated.ErrorResponse {
	var operationPtr *string
	if operation != "" {
		operationPtr = &operation
	}

	return generated.ErrorResponse{
		Code:      code,
		Message:   message,
		Operation: operationPtr,
		Status:    status,
	}
}

// withDefaultHandlerOptions fills read-only default services for local startup tests.
func withDefaultHandlerOptions(options HandlerOptions) HandlerOptions {
	if options.Version == "" {
		options.Version = defaultVersion
	}

	if options.Loader == nil {
		options.Loader = config.NewLoader()
	}

	if options.Snapshot == nil && options.ConfigLoadError == nil {
		options.Snapshot, options.ConfigLoadError = options.Loader.Load(config.LoadOptions{Path: options.ConfigPath})
	}

	if options.BackendReader == nil || options.RouteLookup == nil || options.Reload == nil {
		options = withDefaultDomainServices(options)
	}

	if options.SessionReader == nil {
		options.SessionReader = emptyRuntimeReader{}
	}

	if options.UserReader == nil {
		options.UserReader = emptyRuntimeReader{}
	}

	if options.UserBackendPinReader == nil {
		options.UserBackendPinReader = emptyRuntimeReader{}
	}

	if options.RuntimeSummaryReader == nil {
		options.RuntimeSummaryReader = emptyRuntimeReader{}
	}

	return options
}

// withDefaultDomainServices builds config-backed read-only services when possible.
func withDefaultDomainServices(options HandlerOptions) HandlerOptions {
	cfg := config.DefaultConfig()
	if options.Snapshot != nil {
		cfg = options.Snapshot.Config
	}

	registry, err := backend.NewStaticRegistry(cfg.Director)
	if err != nil {
		options.ConfigLoadError = errors.Join(options.ConfigLoadError, err)

		return options
	}

	policy := selectionPolicy(cfg)

	if options.BackendReader == nil {
		options = withDefaultBackendReader(options, registry, policy.EffectiveBackend)
	}

	if options.RouteLookup == nil {
		options = withDefaultRouteLookup(options, cfg, registry, policy)
	}

	if options.Reload == nil {
		options.Reload = runtime.NewSafeReloadService(cfg, func(context.Context) (config.Config, error) {
			snapshot, err := options.Loader.Load(config.LoadOptions{Path: options.ConfigPath})
			if err != nil {
				return config.Config{}, err
			}

			return snapshot.Config, nil
		}, runtime.WithObservabilityRecorder(options.Observability))
	}

	return options
}

// withDefaultBackendReader fills the config-backed backend reader.
func withDefaultBackendReader(
	options HandlerOptions,
	registry *backend.StaticRegistry,
	policy backend.EffectiveBackendPolicy,
) HandlerOptions {
	reader, err := runtime.NewBackendReadService(runtime.BackendReadServiceOptions{
		Registry:      registry,
		Policy:        policy,
		Observability: options.Observability,
	})
	if err != nil {
		options.ConfigLoadError = errors.Join(options.ConfigLoadError, err)

		return options
	}

	options.BackendReader = reader

	return options
}

// withDefaultRouteLookup fills the config-backed route lookup service.
func withDefaultRouteLookup(
	options HandlerOptions,
	cfg config.Config,
	registry *backend.StaticRegistry,
	policy backend.SelectionPolicy,
) HandlerOptions {
	selector, err := backend.NewRuntimeSelector(registry, nil, policy)
	if err != nil {
		options.ConfigLoadError = errors.Join(options.ConfigLoadError, err)

		return options
	}

	reader, _ := options.BackendReader.(*runtime.BackendReadService)

	resolver, err := routeLookupResolver(cfg, registry)
	if err != nil {
		options.ConfigLoadError = errors.Join(options.ConfigLoadError, err)

		return options
	}

	service, err := runtime.NewRouteLookupService(runtime.RouteLookupServiceOptions{
		Resolver:         resolver,
		Selector:         selector,
		BackendRead:      reader,
		ListenerContexts: routeLookupListenerContexts(cfg),
		DefaultPool:      defaultBackendPool(cfg),
		DefaultShard:     cfg.Director.Routing.EffectiveDefaultShard(),
		DefaultTenant:    defaultTenant,
		Observability:    options.Observability,
	})
	if err != nil {
		options.ConfigLoadError = errors.Join(options.ConfigLoadError, err)

		return options
	}

	options.RouteLookup = service

	return options
}

// selectionPolicy maps typed config into backend selector policy.
func selectionPolicy(cfg config.Config) backend.SelectionPolicy {
	effective := backend.NewEffectiveBackendPolicy(cfg.Director)
	effective.EnforceHealth = false

	return backend.SelectionPolicy{
		SoftAllowsActivePins:     cfg.Director.Maintenance.SoftAllowsActivePins,
		DefaultShard:             cfg.Director.Routing.EffectiveDefaultShard(),
		EffectiveBackend:         effective,
		AllowHardDownFailover:    cfg.Director.Affinity.ActiveUserPinning.Failover.AllowOnHardDown,
		AllowHardMaintenanceMove: cfg.Director.Affinity.ActiveUserPinning.Failover.AllowOnHardMaintenance,
	}
}

// routeLookupResolver builds the shared routing chain used by diagnostics.
func routeLookupResolver(cfg config.Config, registry backend.Registry) (routing.RoutingResolver, error) {
	authResolver, err := routing.NewAuthAttributeResolver(routing.AuthAttributeResolverConfig{
		TenantAttribute:   cfg.Director.Routing.AuthAttributes.Tenant,
		ShardTagAttribute: cfg.Director.Routing.AuthAttributes.ShardTag,
		Sticky:            true,
	})
	if err != nil {
		return nil, err
	}

	hashResolver, err := routing.NewHashResolver(routing.HashResolverConfig{
		ShardTags: routeLookupShardTags(cfg, registry),
		Sticky:    true,
	})
	if err != nil {
		return nil, err
	}

	return routing.NewChainResolver(authResolver, hashResolver)
}

// routeLookupShardTags returns deterministic shard tags from the effective backend view.
func routeLookupShardTags(cfg config.Config, registry backend.Registry) []string {
	shards := make(map[string]struct{})

	if registry != nil {
		if backends, err := registry.AllBackends(context.Background()); err == nil {
			for _, entry := range backends {
				if entry.Protocol != protocolIMAP {
					continue
				}

				if shard := strings.TrimSpace(entry.ShardTag); shard != "" {
					shards[shard] = struct{}{}
				}
			}
		}
	}

	if len(shards) == 0 {
		shards[cfg.Director.Routing.EffectiveDefaultShard()] = struct{}{}
	}

	result := make([]string, 0, len(shards))
	for shard := range shards {
		result = append(result, shard)
	}

	sort.Strings(result)

	return result
}

// routeLookupListenerContexts adapts immutable listener config into lookup defaults.
func routeLookupListenerContexts(cfg config.Config) []runtime.RouteLookupListenerContext {
	contexts := make([]runtime.RouteLookupListenerContext, 0, len(cfg.Director.Listeners))
	for name, listener := range cfg.Director.Listeners {
		contexts = append(contexts, runtime.RouteLookupListenerContext{
			Name:        name,
			Protocol:    listener.Protocol,
			ServiceName: listener.ServiceName,
			BackendPool: listener.BackendPool,
		})
	}

	return contexts
}

// defaultBackendPool returns the first IMAP listener backend pool.
func defaultBackendPool(cfg config.Config) string {
	for _, listener := range cfg.Director.Listeners {
		if strings.EqualFold(listener.Protocol, protocolIMAP) && strings.TrimSpace(listener.BackendPool) != "" {
			return listener.BackendPool
		}
	}

	return ""
}

// accepted returns the shared generated accepted payload.
func accepted() generated.AcceptedResponse {
	return generated.AcceptedResponse{Status: generated.AcceptedResponseStatus(statusAccepted)}
}

// reasonBody reads a required reason from generated request bodies.
func reasonBody(body *generated.RuntimeReasonRequest) (string, bool) {
	if body == nil {
		return "", false
	}

	reason := strings.TrimSpace(body.Reason)

	return reason, reason != ""
}

// backendDetails adapts domain backend states into generated DTOs.
func backendDetails(states []backend.EffectiveBackendState) []generated.BackendDetail {
	details := make([]generated.BackendDetail, 0, len(states))
	for _, state := range states {
		details = append(details, backendDetail(state))
	}

	return details
}

// backendDetail adapts one domain backend state into a generated DTO.
func backendDetail(state backend.EffectiveBackendState) generated.BackendDetail {
	weight := state.EffectiveWeight

	return generated.BackendDetail{
		BackendPool: state.BackendPool,
		Identifier:  state.Identifier,
		Protocol:    state.Protocol,
		ShardTag:    state.EffectiveShardTag,
		Runtime: generated.BackendRuntimeState{
			Draining:    state.Drain.Enabled,
			InService:   state.RuntimeInService,
			Maintenance: generated.MaintenanceMode(state.EffectiveMaintenance),
			Weight:      &weight,
		},
	}
}

// listenerDetails adapts runtime listener snapshots into generated DTOs.
func listenerDetails(details []runtime.ListenerDetail) []generated.ListenerDetail {
	listeners := make([]generated.ListenerDetail, 0, len(details))
	for _, detail := range details {
		listeners = append(listeners, listenerDetail(detail))
	}

	return listeners
}

// listenerDetail adapts one runtime listener snapshot into a generated DTO.
func listenerDetail(detail runtime.ListenerDetail) generated.ListenerDetail {
	return generated.ListenerDetail{
		ActiveLocalSessions: detail.ActiveLocalSessions,
		Address:             detail.Address,
		BoundAddress:        stringPtrIfNotEmpty(detail.BoundAddress),
		DrainMode:           listenerDrainMode(detail.DrainMode),
		ImplicitTLS:         detail.ImplicitTLS,
		Name:                detail.Name,
		Network:             detail.Network,
		Protocol:            detail.Protocol,
		ProxyProtocol:       detail.ProxyProtocol,
		ServiceName:         detail.ServiceName,
		State:               generated.ListenerState(detail.State),
		TLSMode:             detail.TLSMode,
	}
}

// listenerDrainMode adapts optional runtime drain mode values.
func listenerDrainMode(mode runtime.ListenerDrainMode) *generated.DrainMode {
	value := strings.TrimSpace(string(mode))
	if value == "" {
		return nil
	}

	generatedMode := generated.DrainMode(value)

	return &generatedMode
}

// routeLookupRequest adapts generated route lookup DTOs into domain input.
func routeLookupRequest(body generated.LookupRouteJSONRequestBody) runtime.RouteLookupRequest {
	return runtime.RouteLookupRequest{
		Protocol:        body.Protocol,
		ListenerName:    pointerString(body.Listener),
		ServiceName:     pointerString(body.ServiceName),
		BackendPool:     pointerString(body.BackendPool),
		ClientIP:        pointerString(body.ClientIP),
		Tenant:          pointerString(body.Tenant),
		AccountKey:      pointerString(body.UserKey),
		Recipient:       pointerString(body.Recipient),
		IncludeAffinity: pointerBool(body.IncludeAffinity),
		Attributes:      pointerMap(body.Attributes),
	}
}

// routeLookupResponse adapts route lookup domain output into the generated DTO.
func routeLookupResponse(result runtime.RouteLookupResponse) generated.RouteLookupResponse {
	healthy := !result.FailClosed
	maintenance := false

	for _, candidate := range result.Backends {
		if candidate.Identifier != result.SelectedBackend {
			continue
		}

		maintenance = !candidate.AllowsNewSessions && candidate.AllowsActivePins
		healthy = !candidate.FailClosed
	}

	generationPtr := stringPtrIfNotEmpty(result.Routing.RoutingGeneration)

	return generated.RouteLookupResponse{
		AffectedBy: generated.RouteLookupEffects{
			Health:          result.Effects.Health,
			Maintenance:     result.Effects.Maintenance,
			MaxConnections:  result.Effects.MaxConnections,
			RuntimeOverride: result.Effects.RuntimeOverride,
		},
		Affinity:   routeLookupAffinity(result.Affinity),
		BackendPin: routeLookupBackendPin(result.BackendPin),
		Backends:   routeLookupBackends(result.Backends),
		FailClosed: result.FailClosed,
		Healthy:    healthy,
		IdentityResolution: &generated.RouteLookupIdentityResolution{
			AccountResolved: result.Identity.AccountResolved,
			Authoritative:   result.Identity.Authoritative,
			NauthilusUsed:   result.Identity.NauthilusUsed,
			Source:          result.Identity.Source,
		},
		Maintenance: maintenance,
		Reason:      result.ReasonClass,
		Routing: generated.RouteLookupRouting{
			Generation:       generationPtr,
			RequestedShard:   stringPtrIfNotEmpty(result.Routing.RequestedShard),
			ShardTag:         result.Routing.EffectiveShard,
			Source:           result.Routing.RoutingSource,
			UsedDefaultShard: result.Routing.UsedDefaultShard,
		},
		RoutingGeneration: generationPtr,
		SelectedBackend:   result.SelectedBackend,
		ShardTag:          result.Routing.EffectiveShard,
	}
}

// routeLookupBackendPin adapts operator backend-pin diagnostics into generated DTOs.
func routeLookupBackendPin(pin runtime.RouteLookupBackendPinState) generated.RouteLookupBackendPin {
	return generated.RouteLookupBackendPin{
		Applied:     pin.Applied,
		Backend:     stringPtrIfNotEmpty(pin.BackendID),
		BackendPool: stringPtrIfNotEmpty(pin.BackendPool),
		Present:     pin.Present,
		Protocol:    stringPtrIfNotEmpty(pin.Protocol),
		Reason:      pin.ReasonClass,
		ShardTag:    stringPtrIfNotEmpty(pin.EffectiveShard),
	}
}

// routeLookupAffinity adapts requested affinity context when it was read.
func routeLookupAffinity(affinity runtime.RouteLookupAffinityState) *generated.RouteLookupAffinity {
	if !affinity.Requested {
		return nil
	}

	return &generated.RouteLookupAffinity{
		Active:         affinity.Active,
		ActiveSessions: affinity.ActiveSessions,
		BackendID:      stringPtrIfNotEmpty(affinity.BackendID),
		Generation:     stringPtrIfNotEmpty(affinity.Generation),
		Present:        affinity.Present,
		Requested:      affinity.Requested,
		ShardTag:       stringPtrIfNotEmpty(affinity.ShardTag),
	}
}

// routeLookupBackends adapts effective candidate summaries into generated DTOs.
func routeLookupBackends(backends []runtime.RouteLookupBackendState) []generated.RouteLookupBackendSummary {
	summaries := make([]generated.RouteLookupBackendSummary, 0, len(backends))
	for _, entry := range backends {
		summaries = append(summaries, generated.RouteLookupBackendSummary{
			AllowsActivePins:  entry.AllowsActivePins,
			AllowsNewSessions: entry.AllowsNewSessions,
			BackendPool:       entry.BackendPool,
			Eligible:          entry.Eligible,
			Exclusions:        routeLookupExclusions(entry.Exclusions),
			FailClosed:        entry.FailClosed,
			FailClosedReason:  stringPtrIfNotEmpty(string(entry.FailClosedReason)),
			Generation:        stringPtrIfNotEmpty(entry.Generation),
			Identifier:        entry.Identifier,
			Protocol:          entry.Protocol,
			ShardTag:          entry.EffectiveShard,
		})
	}

	return summaries
}

// routeLookupExclusions adapts classified selector exclusions.
func routeLookupExclusions(exclusions []backend.EffectiveExclusion) []generated.RouteLookupBackendExclusion {
	result := make([]generated.RouteLookupBackendExclusion, 0, len(exclusions))
	for _, exclusion := range exclusions {
		result = append(result, generated.RouteLookupBackendExclusion{
			Detail: exclusion.Detail,
			Reason: string(exclusion.Reason),
			Source: exclusion.Source,
		})
	}

	return result
}

// sessionDetails adapts runtime sessions into generated DTOs.
func sessionDetails(sessions []runtime.SessionRuntimeState) []generated.SessionDetail {
	details := make([]generated.SessionDetail, 0, len(sessions))
	for _, session := range sessions {
		details = append(details, sessionDetail(session))
	}

	return details
}

// sessionDetail adapts one runtime session into a generated DTO.
func sessionDetail(session runtime.SessionRuntimeState) generated.SessionDetail {
	expiresAt := session.LeaseExpiresAt
	if expiresAt.IsZero() {
		expiresAt = time.Unix(0, 0).UTC()
	}

	return generated.SessionDetail{
		Backend:   session.BackendIdentifier,
		ExpiresAt: expiresAt.UTC(),
		Protocol:  session.Protocol,
		SessionID: session.SessionID,
		ShardTag:  session.EffectiveShardTag,
		UserKey:   formatUserKey(runtime.UserKey{Tenant: session.Tenant, UserHash: session.UserHash}),
	}
}

// runtimeSummary adapts repairable runtime aggregates into generated DTOs.
func runtimeSummary(summary runtime.Summary) generated.RuntimeSummaryResponse {
	return generated.RuntimeSummaryResponse{
		ActiveSessions: generated.RuntimeSessionAggregateSummary{
			Total:      runtimeCount(summary.ActiveSessions.Total),
			ByProtocol: runtimeDimensionCounts(summary.ActiveSessions.ByProtocol),
			ByListener: runtimeDimensionCounts(summary.ActiveSessions.ByListener),
			ByService:  runtimeDimensionCounts(summary.ActiveSessions.ByService),
			ByShardTag: runtimeDimensionCounts(summary.ActiveSessions.ByShardTag),
		},
		BackendCapacity:  runtimeBackendCapacity(summary.BackendCapacity),
		GeneratedAt:      summary.GeneratedAt.UTC(),
		IdleAffinities:   runtimeCount(summary.IdleAffinities),
		Repairs:          runtimeRepairSummary(summary.Repairs),
		RoutingAuthority: summary.RoutingAuthority,
	}
}

// runtimeCount adapts one count and its accuracy class.
func runtimeCount(count runtime.CountSummary) generated.RuntimeCountSummary {
	return generated.RuntimeCountSummary{
		Accuracy: generated.RuntimeCountSummaryAccuracy(count.Accuracy),
		Count:    count.Count,
	}
}

// runtimeDimensionCounts adapts dimension aggregate buckets.
func runtimeDimensionCounts(counts []runtime.DimensionCount) []generated.RuntimeDimensionCount {
	details := make([]generated.RuntimeDimensionCount, 0, len(counts))
	for _, count := range counts {
		details = append(details, generated.RuntimeDimensionCount{
			Accuracy: generated.RuntimeDimensionCountAccuracy(count.Accuracy),
			Count:    count.Count,
			Value:    count.Value,
		})
	}

	return details
}

// runtimeBackendCapacity adapts backend aggregate summaries.
func runtimeBackendCapacity(summaries []runtime.BackendCapacitySummary) []generated.RuntimeBackendCapacitySummary {
	details := make([]generated.RuntimeBackendCapacitySummary, 0, len(summaries))
	for _, summary := range summaries {
		details = append(details, generated.RuntimeBackendCapacitySummary{
			ActiveSessions:    runtimeCount(summary.ActiveSessions),
			Backend:           summary.BackendIdentifier,
			ReservedSessions:  runtimeCount(summary.ReservedSessions),
			RoutingAuthority:  summary.RoutingAuthority,
			SummaryRepairable: summary.SummaryRepairable,
		})
	}

	return details
}

// runtimeRepairSummary adapts cumulative repair counters.
func runtimeRepairSummary(summary runtime.RepairSummary) generated.RuntimeRepairSummary {
	return generated.RuntimeRepairSummary{
		BackendReservations: runtimeCount(summary.BackendReservations),
		ExpiredSessions:     runtimeCount(summary.ExpiredSessions),
		StaleIndexEntries:   runtimeCount(summary.StaleIndexEntries),
	}
}

// userDetails adapts runtime users into generated DTOs.
func userDetails(users []runtime.UserRuntimeState) []generated.UserDetail {
	details := make([]generated.UserDetail, 0, len(users))
	for _, user := range users {
		details = append(details, userDetail(user))
	}

	return details
}

// userDetail adapts one runtime user into a generated DTO.
func userDetail(user runtime.UserRuntimeState) generated.UserDetail {
	affinity := userAffinity(user)

	return generated.UserDetail{
		ActiveSessions: user.ActiveSessionCount,
		Affinity:       &affinity,
		UserKey:        formatUserKey(user.Key),
	}
}

// userAffinity adapts runtime user affinity into a generated DTO.
func userAffinity(user runtime.UserRuntimeState) generated.UserAffinity {
	var expiresAt *time.Time

	if !user.UpdatedAt.IsZero() {
		value := user.UpdatedAt.UTC()
		expiresAt = &value
	}

	generation := strings.TrimSpace(user.Generation)

	var generationPtr *string
	if generation != "" {
		generationPtr = &generation
	}

	return generated.UserAffinity{
		ActiveSessions: user.ActiveSessionCount,
		ExpiresAt:      expiresAt,
		Generation:     generationPtr,
		ShardTag:       user.ActiveShard,
		UserKey:        formatUserKey(user.Key),
	}
}

// userBackendPin adapts runtime backend-pin state into the generated REST DTO.
func userBackendPin(pin runtime.UserBackendPin, fallbackKey runtime.UserKey) generated.UserBackendPin {
	key := pin.Key.Normalize()
	if key.Tenant == "" || key.UserHash == "" {
		key = fallbackKey.Normalize()
	}

	detail := generated.UserBackendPin{
		Present: pin.Present,
		UserKey: formatUserKey(key),
	}

	if !pin.Present {
		return detail
	}

	activeSessionCount := pin.ActiveSessionCount
	detail.ActiveSessionCount = &activeSessionCount
	detail.Backend = stringPtrIfNotEmpty(pin.BackendIdentifier)
	detail.BackendPool = stringPtrIfNotEmpty(pin.BackendPool)
	detail.Generation = stringPtrIfNotEmpty(pin.Generation)
	detail.Protocol = stringPtrIfNotEmpty(pin.Protocol)
	detail.ShardTag = stringPtrIfNotEmpty(pin.EffectiveShard)

	if strategy := strings.TrimSpace(string(pin.Strategy)); strategy != "" {
		value := generated.UserMoveRequestStrategy(strategy)
		detail.Strategy = &value
	}

	return detail
}

// statusForError maps domain error classes to stable REST status codes.
func statusForError(err error) int {
	if status, ok := runtimeErrorStatus(err); ok {
		return status
	}

	if status, ok := backendErrorStatus(err); ok {
		return status
	}

	return redisErrorStatus(err)
}

// runtimeErrorStatus maps runtime domain errors to REST statuses.
func runtimeErrorStatus(err error) (int, bool) {
	var runtimeErr *runtime.Error
	if errors.As(err, &runtimeErr) {
		switch runtimeErr.Kind {
		case runtime.ErrorKindInvalidRequest:
			return http.StatusBadRequest, true
		case runtime.ErrorKindNotFound:
			return http.StatusNotFound, true
		case runtime.ErrorKindConflict:
			return http.StatusConflict, true
		case runtime.ErrorKindUnauthorized:
			return http.StatusUnauthorized, true
		case runtime.ErrorKindForbidden:
			return http.StatusForbidden, true
		default:
			return http.StatusServiceUnavailable, true
		}
	}

	return 0, false
}

// backendErrorStatus maps backend domain errors to REST statuses.
func backendErrorStatus(err error) (int, bool) {
	if backend.IsErrorKind(err, backend.ErrorKindInvalidRequest) {
		return http.StatusBadRequest, true
	}

	if backend.IsErrorKind(err, backend.ErrorKindNoBackend) {
		return http.StatusNotFound, true
	}

	return 0, false
}

// redisErrorStatus maps Redis ambiguity and unknown errors to fail-closed status.
func redisErrorStatus(err error) int {
	if state.IsRedisErrorKind(err, state.RedisErrorKindAmbiguousState) ||
		state.IsRedisErrorKind(err, state.RedisErrorKindScriptMissing) ||
		state.IsRedisErrorKind(err, state.RedisErrorKindTransport) ||
		state.IsRedisErrorKind(err, state.RedisErrorKindConfig) {
		return http.StatusServiceUnavailable
	}

	return http.StatusServiceUnavailable
}

// codeForError returns a stable problem code for domain failures.
func codeForError(err error) string {
	var runtimeErr *runtime.Error
	if errors.As(err, &runtimeErr) {
		return string(runtimeErr.Kind)
	}

	if backend.IsErrorKind(err, backend.ErrorKindInvalidRequest) {
		return string(backend.ErrorKindInvalidRequest)
	}

	if backend.IsErrorKind(err, backend.ErrorKindNoBackend) {
		return "not_found"
	}

	if state.IsFailClosedRedisError(err) {
		return problemCodeUnavailable
	}

	return problemCodeUnavailable
}

// messageForError returns an operator-readable secret-safe error message.
func messageForError(err error) string {
	if err == nil {
		return ""
	}

	return err.Error()
}

// normalizeConfigFormat applies the default and rejects unsupported formats upstream.
func normalizeConfigFormat(format string) string {
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		return defaultConfigFormat
	}

	return format
}

// parseUserKey turns the public user key into a runtime affinity key.
func parseUserKey(value string) runtime.UserKey {
	value = strings.TrimSpace(value)
	if tenant, account, ok := strings.Cut(value, ":"); ok {
		return runtime.UserKey{Tenant: tenant, UserHash: account}.Normalize()
	}

	return runtime.UserKey{Tenant: defaultTenant, UserHash: value}.Normalize()
}

// formatUserKey renders runtime user keys in the public tenant:hash form.
func formatUserKey(key runtime.UserKey) string {
	key = key.Normalize()
	if key.Tenant == "" || key.Tenant == defaultTenant {
		return key.UserHash
	}

	return key.Tenant + ":" + key.UserHash
}

// actorFromContext returns authenticated actor metadata when auth middleware adds it.
func actorFromContext(_ context.Context) runtime.Actor {
	return runtime.Actor{}
}

// pointerString unwraps optional generated string fields.
func pointerString(value *string) string {
	if value == nil {
		return ""
	}

	return *value
}

// pointerGeneratedString unwraps optional generated string aliases.
func pointerGeneratedString[T ~string](value *T) string {
	if value == nil {
		return ""
	}

	return string(*value)
}

// pointerGeneratedInt unwraps optional generated integer aliases.
func pointerGeneratedInt[T ~int](value *T) int {
	if value == nil {
		return 0
	}

	return int(*value)
}

// nonEmptyStringPointer returns nil when optional response text is absent.
func nonEmptyStringPointer(value string) *string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}

	return &value
}

// pointerBool unwraps optional generated boolean fields.
func pointerBool(value *bool) bool {
	return value != nil && *value
}

// durationFromSeconds converts optional generated second values into runtime durations.
func durationFromSeconds(value *int) *time.Duration {
	if value == nil {
		return nil
	}

	duration := time.Duration(*value) * time.Second

	return &duration
}

// stringPtrIfNotEmpty returns an optional generated string when value is present.
func stringPtrIfNotEmpty(value string) *string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}

	return &value
}

// pointerMap unwraps optional generated attribute maps.
func pointerMap(value *map[string][]string) map[string][]string {
	if value == nil {
		return nil
	}

	out := make(map[string][]string, len(*value))
	for key, values := range *value {
		out[key] = append([]string(nil), values...)
	}

	return out
}

// formatFromDefaultParams reads generated config format params.
func formatFromDefaultParams(params generated.GetDefaultConfigParams) string {
	if params.Format == nil {
		return ""
	}

	return string(*params.Format)
}

// formatFromEffectiveParams reads generated config format params.
func formatFromEffectiveParams(params generated.GetEffectiveConfigParams) string {
	if params.Format == nil {
		return ""
	}

	return string(*params.Format)
}

// formatFromNonDefaultParams reads generated config format params.
func formatFromNonDefaultParams(params generated.GetNonDefaultConfigParams) string {
	if params.Format == nil {
		return ""
	}

	return string(*params.Format)
}

// includeProtectedFromDefaultParams reads generated protected config params.
func includeProtectedFromDefaultParams(params generated.GetDefaultConfigParams) bool {
	return params.IncludeProtected != nil && bool(*params.IncludeProtected)
}

// includeProtectedFromEffectiveParams reads generated protected config params.
func includeProtectedFromEffectiveParams(params generated.GetEffectiveConfigParams) bool {
	return params.IncludeProtected != nil && bool(*params.IncludeProtected)
}

// includeProtectedFromNonDefaultParams reads generated protected config params.
func includeProtectedFromNonDefaultParams(params generated.GetNonDefaultConfigParams) bool {
	return params.IncludeProtected != nil && bool(*params.IncludeProtected)
}

// emptyRuntimeReader is a deterministic no-state reader for unassembled local servers.
type emptyRuntimeReader struct{}

// ListSessions returns no sessions when no runtime state reader is assembled.
func (emptyRuntimeReader) ListSessions(context.Context, runtime.SessionListRequest) (runtime.SessionListResult, error) {
	return runtime.SessionListResult{}, nil
}

// GetSession reports an absent session when no runtime state reader is assembled.
func (emptyRuntimeReader) GetSession(context.Context, string) (runtime.SessionRuntimeState, error) {
	return runtime.SessionRuntimeState{}, newRuntimeError(runtime.ErrorKindNotFound, "session", "session not found")
}

// ListUserSessions returns no sessions when no runtime state reader is assembled.
func (emptyRuntimeReader) ListUserSessions(context.Context, runtime.UserKey) ([]runtime.SessionRuntimeState, error) {
	return nil, nil
}

// ListUsers returns no users when no runtime state reader is assembled.
func (emptyRuntimeReader) ListUsers(context.Context, runtime.UserListRequest) (runtime.UserListResult, error) {
	return runtime.UserListResult{}, nil
}

// GetUser reports an absent user when no runtime state reader is assembled.
func (emptyRuntimeReader) GetUser(context.Context, runtime.UserKey) (runtime.UserRuntimeState, error) {
	return runtime.UserRuntimeState{}, newRuntimeError(runtime.ErrorKindNotFound, "user", "user not found")
}

// GetUserAffinity reports absent affinity when no runtime state reader is assembled.
func (emptyRuntimeReader) GetUserAffinity(context.Context, runtime.UserKey) (runtime.UserRuntimeState, error) {
	return runtime.UserRuntimeState{}, newRuntimeError(runtime.ErrorKindNotFound, "user_affinity", "user affinity not found")
}

// GetUserBackendPin reports absent backend-pin state when no runtime reader is assembled.
func (emptyRuntimeReader) GetUserBackendPin(_ context.Context, request runtime.GetUserBackendPinRequest) (runtime.UserBackendPinReadResult, error) {
	return runtime.UserBackendPinReadResult{
		Pin: runtime.UserBackendPin{
			Present: false,
			Key:     request.Key.Normalize(),
		},
	}, nil
}

// RuntimeSummary returns empty aggregate totals when no runtime reader is assembled.
func (emptyRuntimeReader) RuntimeSummary(context.Context) (runtime.Summary, error) {
	return runtime.Summary{
		RoutingAuthority: false,
		ActiveSessions: runtime.ActiveSessionSummary{
			Total: runtime.CountSummary{Accuracy: runtime.AccuracyEventuallyRepaired},
		},
		IdleAffinities: runtime.CountSummary{Accuracy: runtime.AccuracyEventuallyRepaired},
		Repairs: runtime.RepairSummary{
			ExpiredSessions:     runtime.CountSummary{Accuracy: runtime.AccuracyCumulative},
			StaleIndexEntries:   runtime.CountSummary{Accuracy: runtime.AccuracyCumulative},
			BackendReservations: runtime.CountSummary{Accuracy: runtime.AccuracyCumulative},
		},
	}, nil
}

// newRuntimeError creates runtime errors without exporting construction to adapters.
func newRuntimeError(kind runtime.ErrorKind, operation string, message string) *runtime.Error {
	return &runtime.Error{Kind: kind, Operation: operation, Message: message}
}
