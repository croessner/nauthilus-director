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

package rest

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/rest/generated"
)

const (
	restFieldMethod      = "method"
	restFieldOperation   = "operation"
	restFieldReasonClass = "reason_class"
	restFieldResult      = "result"
	restFieldRoute       = "route"
	restFieldStatusClass = "status_class"
	restReasonHTTPError  = "http_error"
	restResultFailure    = "failure"
	restResultOK         = "ok"
	restStatusUnknown    = "unknown"

	restRouteBackendMaintenance = "/api/v1/backends/{identifier}/maintenance"
	restRouteRouteLookup        = "/api/v1/route/lookup"
	restRouteSession            = "/api/v1/sessions/{session_id}"
	restRouteUserAffinity       = "/api/v1/users/{user_key}/affinity"
)

var restRouteTemplates = map[string]string{
	"ClearBackendRuntime":       "/api/v1/backends/{identifier}/runtime",
	"ClearUserAffinity":         restRouteUserAffinity,
	"DeleteSession":             restRouteSession,
	"DisableBackendMaintenance": restRouteBackendMaintenance,
	"DrainBackend":              "/api/v1/backends/{identifier}/runtime/drain",
	"EnableBackendMaintenance":  restRouteBackendMaintenance,
	"GetBackend":                "/api/v1/backends/{identifier}",
	"GetDefaultConfig":          "/api/v1/config/defaults",
	"GetEffectiveConfig":        "/api/v1/config/effective",
	"GetHealthz":                "/healthz",
	"GetMetrics":                "/metrics",
	"GetNonDefaultConfig":       "/api/v1/config/non-default",
	"GetReadyz":                 "/readyz",
	"GetSession":                restRouteSession,
	"GetUser":                   "/api/v1/users/{user_key}",
	"GetUserAffinity":           restRouteUserAffinity,
	"GetUserSessions":           "/api/v1/users/{user_key}/sessions",
	"GetVersion":                "/api/v1/version",
	"KickUser":                  "/api/v1/users/{user_key}/kick",
	"ListBackends":              "/api/v1/backends",
	"ListSessions":              "/api/v1/sessions",
	"ListUsers":                 "/api/v1/users",
	"LookupRoute":               restRouteRouteLookup,
	"MarkBackendIn":             "/api/v1/backends/{identifier}/runtime/in",
	"MarkBackendOut":            "/api/v1/backends/{identifier}/runtime/out",
	"MoveUser":                  "/api/v1/users/{user_key}/move",
	"Reload":                    "/api/v1/reload",
	"SetBackendWeight":          "/api/v1/backends/{identifier}/runtime/weight",
	"SetUserAffinity":           restRouteUserAffinity,
}

// traceRESTRequests wraps generated operations with a normalized REST span.
func traceRESTRequests(recorder observability.Recorder) generated.StrictMiddlewareFunc {
	recorder = observability.NormalizeRecorder(recorder)

	return func(next generated.StrictHandlerFunc, operationID string) generated.StrictHandlerFunc {
		return func(ctx context.Context, w http.ResponseWriter, r *http.Request, request any) (any, error) {
			started := time.Now()
			route := routeTemplateForOperation(operationID)
			fields := restObservationFields(r.Method, operationID, route, restResultOK, restStatusUnknown)
			ctx, span := observability.StartSpan(ctx, recorder, observability.TraceBoundaryRESTRequest, fields)

			response, err := next(ctx, w, r, request)
			statusCode := restStatusCode(response, err)
			statusClass := restStatusClass(statusCode)
			result := restResultForStatus(statusCode, err)

			reasonClass := ""
			if result == restResultFailure {
				reasonClass = restReasonHTTPError
			}

			fields = restObservationFields(r.Method, operationID, route, result, statusClass)
			if reasonClass != "" {
				fields[restFieldReasonClass] = reasonClass
			}

			span.SetAttributes(fields)
			recordRESTRequest(ctx, recorder, fields, time.Since(started))
			span.End(result, reasonClass)

			return response, err
		}
	}
}

// recordRESTRequest emits the generated-route REST observation.
func recordRESTRequest(ctx context.Context, recorder observability.Recorder, fields map[string]string, duration time.Duration) {
	event, err := observability.NewEvent(observability.EventRESTRequest, observability.TraceBoundaryRESTRequest, fields, map[string]string{
		restFieldMethod:      fields[restFieldMethod],
		restFieldOperation:   fields[restFieldOperation],
		restFieldResult:      fields[restFieldResult],
		restFieldRoute:       fields[restFieldRoute],
		restFieldStatusClass: fields[restFieldStatusClass],
	})
	if err != nil {
		return
	}

	if duration > 0 {
		event.Measurements = observability.NewMetricMeasurements(map[string]float64{
			observability.MetricMeasurementDurationSeconds: duration.Seconds(),
		})
	}

	recorder.Record(ctx, event)
}

// restObservationFields returns low-cardinality fields for one REST operation.
func restObservationFields(method string, operation string, route string, result string, statusClass string) map[string]string {
	return map[string]string{
		restFieldMethod:      strings.ToUpper(strings.TrimSpace(method)),
		restFieldOperation:   strings.TrimSpace(operation),
		restFieldResult:      result,
		restFieldRoute:       route,
		restFieldStatusClass: statusClass,
	}
}

// routeTemplateForOperation maps generated operation names to stable templates.
func routeTemplateForOperation(operationID string) string {
	if route := restRouteTemplates[operationID]; route != "" {
		return route
	}

	return "operation:" + strings.TrimSpace(operationID)
}

// restStatusCode extracts a response status without reading response bodies.
func restStatusCode(response any, err error) int {
	if err != nil {
		return http.StatusInternalServerError
	}

	if response == nil {
		return http.StatusNoContent
	}

	if status, ok := responseStatusCodeField(response); ok {
		return status
	}

	if status, ok := responseStatusCodeFromType(response); ok {
		return status
	}

	return http.StatusOK
}

// responseStatusCodeField reads generated default response StatusCode fields.
func responseStatusCodeField(response any) (int, bool) {
	value := reflect.ValueOf(response)
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return 0, false
		}

		value = value.Elem()
	}

	if !value.IsValid() || value.Kind() != reflect.Struct {
		return 0, false
	}

	field := value.FieldByName("StatusCode")
	if !field.IsValid() || !field.CanInt() {
		return 0, false
	}

	return int(field.Int()), true
}

// responseStatusCodeFromType parses generated response type names such as 202.
func responseStatusCodeFromType(response any) (int, bool) {
	responseType := reflect.TypeOf(response)
	if responseType == nil {
		return 0, false
	}

	name := responseType.Name()
	for index := 0; index+3 <= len(name); index++ {
		code, err := strconv.Atoi(name[index : index+3])
		if err == nil && code >= 100 && code <= 599 {
			return code, true
		}
	}

	return 0, false
}

// restStatusClass maps status codes into bounded OpenTelemetry values.
func restStatusClass(statusCode int) string {
	if statusCode < 100 || statusCode > 599 {
		return restStatusUnknown
	}

	return fmt.Sprintf("%dxx", statusCode/100)
}

// restResultForStatus maps HTTP and handler errors into bounded result values.
func restResultForStatus(statusCode int, err error) string {
	if err != nil || statusCode >= http.StatusBadRequest {
		return restResultFailure
	}

	return restResultOK
}
