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
	"net/http"

	"github.com/croessner/nauthilus-director/internal/rest/generated"
)

const (
	apiVersion      = "v1"
	componentName   = "nauthilus-director"
	defaultVersion  = "dev"
	notImplemented  = "not_implemented"
	notImplementedM = "domain behavior is not implemented in this foundation milestone"
	statusOK        = "ok"
)

// HandlerOptions configures the M0 generated REST adapter.
type HandlerOptions struct {
	Version string
}

// Handler implements the generated strict-server interface.
type Handler struct {
	version string
}

// NewHandler creates a generated-boundary REST adapter.
func NewHandler(options HandlerOptions) *Handler {
	version := options.Version
	if version == "" {
		version = defaultVersion
	}

	return &Handler{version: version}
}

// ListBackends returns the M0 backend inventory placeholder.
func (h *Handler) ListBackends(_ context.Context, _ generated.ListBackendsRequestObject) (generated.ListBackendsResponseObject, error) {
	return generated.ListBackends501JSONResponse{NotImplementedJSONResponse: h.notImplemented("ListBackends")}, nil
}

// GetBackend returns the M0 backend detail placeholder.
func (h *Handler) GetBackend(_ context.Context, _ generated.GetBackendRequestObject) (generated.GetBackendResponseObject, error) {
	return generated.GetBackend501JSONResponse{NotImplementedJSONResponse: h.notImplemented("GetBackend")}, nil
}

// DisableBackendMaintenance returns the M0 maintenance-clear placeholder.
func (h *Handler) DisableBackendMaintenance(_ context.Context, _ generated.DisableBackendMaintenanceRequestObject) (generated.DisableBackendMaintenanceResponseObject, error) {
	return generated.DisableBackendMaintenance501JSONResponse{NotImplementedJSONResponse: h.notImplemented("DisableBackendMaintenance")}, nil
}

// EnableBackendMaintenance returns the M0 maintenance-enable placeholder.
func (h *Handler) EnableBackendMaintenance(_ context.Context, _ generated.EnableBackendMaintenanceRequestObject) (generated.EnableBackendMaintenanceResponseObject, error) {
	return generated.EnableBackendMaintenance501JSONResponse{NotImplementedJSONResponse: h.notImplemented("EnableBackendMaintenance")}, nil
}

// ClearBackendRuntime returns the M0 runtime-clear placeholder.
func (h *Handler) ClearBackendRuntime(_ context.Context, _ generated.ClearBackendRuntimeRequestObject) (generated.ClearBackendRuntimeResponseObject, error) {
	return generated.ClearBackendRuntime501JSONResponse{NotImplementedJSONResponse: h.notImplemented("ClearBackendRuntime")}, nil
}

// DrainBackend returns the M0 backend-drain placeholder.
func (h *Handler) DrainBackend(_ context.Context, _ generated.DrainBackendRequestObject) (generated.DrainBackendResponseObject, error) {
	return generated.DrainBackend501JSONResponse{NotImplementedJSONResponse: h.notImplemented("DrainBackend")}, nil
}

// MarkBackendIn returns the M0 runtime-in placeholder.
func (h *Handler) MarkBackendIn(_ context.Context, _ generated.MarkBackendInRequestObject) (generated.MarkBackendInResponseObject, error) {
	return generated.MarkBackendIn501JSONResponse{NotImplementedJSONResponse: h.notImplemented("MarkBackendIn")}, nil
}

// MarkBackendOut returns the M0 runtime-out placeholder.
func (h *Handler) MarkBackendOut(_ context.Context, _ generated.MarkBackendOutRequestObject) (generated.MarkBackendOutResponseObject, error) {
	return generated.MarkBackendOut501JSONResponse{NotImplementedJSONResponse: h.notImplemented("MarkBackendOut")}, nil
}

// GetDefaultConfig returns the M0 default-config placeholder.
func (h *Handler) GetDefaultConfig(_ context.Context, _ generated.GetDefaultConfigRequestObject) (generated.GetDefaultConfigResponseObject, error) {
	return generated.GetDefaultConfig501JSONResponse{NotImplementedJSONResponse: h.notImplemented("GetDefaultConfig")}, nil
}

// GetEffectiveConfig returns the M0 effective-config placeholder.
func (h *Handler) GetEffectiveConfig(_ context.Context, _ generated.GetEffectiveConfigRequestObject) (generated.GetEffectiveConfigResponseObject, error) {
	return generated.GetEffectiveConfig501JSONResponse{NotImplementedJSONResponse: h.notImplemented("GetEffectiveConfig")}, nil
}

// GetNonDefaultConfig returns the M0 non-default-config placeholder.
func (h *Handler) GetNonDefaultConfig(_ context.Context, _ generated.GetNonDefaultConfigRequestObject) (generated.GetNonDefaultConfigResponseObject, error) {
	return generated.GetNonDefaultConfig501JSONResponse{NotImplementedJSONResponse: h.notImplemented("GetNonDefaultConfig")}, nil
}

// Reload returns the M0 reload placeholder.
func (h *Handler) Reload(_ context.Context, _ generated.ReloadRequestObject) (generated.ReloadResponseObject, error) {
	return generated.Reload501JSONResponse{NotImplementedJSONResponse: h.notImplemented("Reload")}, nil
}

// LookupRoute returns the M0 side-effect-free route lookup placeholder.
func (h *Handler) LookupRoute(_ context.Context, request generated.LookupRouteRequestObject) (generated.LookupRouteResponseObject, error) {
	if request.Body == nil {
		return generated.LookupRoute400JSONResponse{BadRequestJSONResponse: h.badRequest("LookupRoute")}, nil
	}

	return generated.LookupRoute501JSONResponse{NotImplementedJSONResponse: h.notImplemented("LookupRoute")}, nil
}

// ListSessions returns the M0 session-list placeholder.
func (h *Handler) ListSessions(_ context.Context, _ generated.ListSessionsRequestObject) (generated.ListSessionsResponseObject, error) {
	return generated.ListSessions501JSONResponse{NotImplementedJSONResponse: h.notImplemented("ListSessions")}, nil
}

// DeleteSession returns the M0 session-termination placeholder.
func (h *Handler) DeleteSession(_ context.Context, _ generated.DeleteSessionRequestObject) (generated.DeleteSessionResponseObject, error) {
	return generated.DeleteSession501JSONResponse{NotImplementedJSONResponse: h.notImplemented("DeleteSession")}, nil
}

// GetSession returns the M0 session-detail placeholder.
func (h *Handler) GetSession(_ context.Context, _ generated.GetSessionRequestObject) (generated.GetSessionResponseObject, error) {
	return generated.GetSession501JSONResponse{NotImplementedJSONResponse: h.notImplemented("GetSession")}, nil
}

// ListUsers returns the M0 user-list placeholder.
func (h *Handler) ListUsers(_ context.Context, _ generated.ListUsersRequestObject) (generated.ListUsersResponseObject, error) {
	return generated.ListUsers501JSONResponse{NotImplementedJSONResponse: h.notImplemented("ListUsers")}, nil
}

// GetUser returns the M0 user-detail placeholder.
func (h *Handler) GetUser(_ context.Context, _ generated.GetUserRequestObject) (generated.GetUserResponseObject, error) {
	return generated.GetUser501JSONResponse{NotImplementedJSONResponse: h.notImplemented("GetUser")}, nil
}

// ClearUserAffinity returns the M0 affinity-clear placeholder.
func (h *Handler) ClearUserAffinity(_ context.Context, _ generated.ClearUserAffinityRequestObject) (generated.ClearUserAffinityResponseObject, error) {
	return generated.ClearUserAffinity501JSONResponse{NotImplementedJSONResponse: h.notImplemented("ClearUserAffinity")}, nil
}

// GetUserAffinity returns the M0 affinity-read placeholder.
func (h *Handler) GetUserAffinity(_ context.Context, _ generated.GetUserAffinityRequestObject) (generated.GetUserAffinityResponseObject, error) {
	return generated.GetUserAffinity501JSONResponse{NotImplementedJSONResponse: h.notImplemented("GetUserAffinity")}, nil
}

// SetUserAffinity returns the M0 affinity-set placeholder.
func (h *Handler) SetUserAffinity(_ context.Context, _ generated.SetUserAffinityRequestObject) (generated.SetUserAffinityResponseObject, error) {
	return generated.SetUserAffinity501JSONResponse{NotImplementedJSONResponse: h.notImplemented("SetUserAffinity")}, nil
}

// KickUser returns the M0 user-kick placeholder.
func (h *Handler) KickUser(_ context.Context, _ generated.KickUserRequestObject) (generated.KickUserResponseObject, error) {
	return generated.KickUser501JSONResponse{NotImplementedJSONResponse: h.notImplemented("KickUser")}, nil
}

// MoveUser returns the M0 user-move placeholder.
func (h *Handler) MoveUser(_ context.Context, _ generated.MoveUserRequestObject) (generated.MoveUserResponseObject, error) {
	return generated.MoveUser501JSONResponse{NotImplementedJSONResponse: h.notImplemented("MoveUser")}, nil
}

// GetUserSessions returns the M0 user-session-list placeholder.
func (h *Handler) GetUserSessions(_ context.Context, _ generated.GetUserSessionsRequestObject) (generated.GetUserSessionsResponseObject, error) {
	return generated.GetUserSessions501JSONResponse{NotImplementedJSONResponse: h.notImplemented("GetUserSessions")}, nil
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

// GetMetrics returns the M0 metrics placeholder.
func (h *Handler) GetMetrics(_ context.Context, _ generated.GetMetricsRequestObject) (generated.GetMetricsResponseObject, error) {
	return generated.GetMetrics501JSONResponse{NotImplementedJSONResponse: h.notImplemented("GetMetrics")}, nil
}

// GetReadyz reports minimal M0 readiness.
func (h *Handler) GetReadyz(_ context.Context, _ generated.GetReadyzRequestObject) (generated.GetReadyzResponseObject, error) {
	return generated.GetReadyz200JSONResponse(generated.StatusResponse{Status: statusOK}), nil
}

// notImplemented builds a structured generated-boundary 501 payload.
func (h *Handler) notImplemented(operation string) generated.NotImplementedJSONResponse {
	return generated.NotImplementedJSONResponse(h.problem(http.StatusNotImplemented, notImplemented, notImplementedM, operation))
}

// badRequest builds a structured generated-boundary 400 payload.
func (h *Handler) badRequest(operation string) generated.BadRequestJSONResponse {
	return generated.BadRequestJSONResponse(h.problem(http.StatusBadRequest, "bad_request", "request body is required", operation))
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
