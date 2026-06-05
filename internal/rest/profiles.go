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
	"fmt"
	"net/http"
	httppprof "net/http/pprof"
	"strings"

	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/observability"
)

const (
	profileBasePath         = "/debug/pprof"
	profileRouteTemplate    = "/debug/pprof/{profile}"
	profileOperation        = "diagnostic_profile"
	profileFieldActorID     = "actor_id"
	profileFieldAuthMethod  = "auth_method"
	profileFieldProfile     = "profile_route"
	profileResultFailure    = "failure"
	profileResultOK         = "ok"
	profileStatusUnknown    = "unknown"
	profileClassAllocs      = "allocs"
	profileClassBlock       = "block"
	profileClassCmdline     = "cmdline"
	profileClassGoroutine   = "goroutine"
	profileClassHeap        = "heap"
	profileClassIndex       = "index"
	profileClassMutex       = "mutex"
	profileClassProfile     = "profile"
	profileClassSymbol      = "symbol"
	profileClassThread      = "threadcreate"
	profileClassTrace       = "trace"
	profileClassUnknown     = "unknown"
	profileIndexContentType = "text/plain; charset=utf-8"
)

type diagnosticProfileHandler struct {
	mux      *http.ServeMux
	profiles config.ProfilesConfig
	recorder observability.Recorder
}

type statusTrackingResponseWriter struct {
	http.ResponseWriter
	status int
}

// profileControlHandler combines generated REST routes with optional protected pprof routes.
func profileControlHandler(generated http.Handler, profiles config.ProfilesConfig, profile http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isProfilePath(r.URL.Path) {
			generated.ServeHTTP(w, r)

			return
		}

		if !profiles.PProf.Enabled {
			http.NotFound(w, r)

			return
		}

		profile.ServeHTTP(w, r)
	})
}

// newDiagnosticProfileHandler creates the protected pprof handler set.
func newDiagnosticProfileHandler(profiles config.ProfilesConfig, recorder observability.Recorder) http.Handler {
	handler := &diagnosticProfileHandler{
		mux:      http.NewServeMux(),
		profiles: profiles,
		recorder: observability.NormalizeRecorder(recorder),
	}
	handler.register(profiles)

	return handler
}

// ServeHTTP enforces protected authorization before serving sensitive profile data.
func (h *diagnosticProfileHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	state, ok := ControlAuthStateFromContext(r.Context())
	if !ok || !state.Protected {
		h.record(r, http.StatusForbidden, profileClassForPath(r.URL.Path), state)
		writeProblem(w, http.StatusForbidden, problemCodeForbidden, "requested operation is not authorized", "")

		return
	}

	tracker := &statusTrackingResponseWriter{ResponseWriter: w, status: http.StatusOK}
	h.mux.ServeHTTP(tracker, r)
	h.record(r, tracker.status, profileClassForPath(r.URL.Path), state)
}

// Header returns the wrapped response headers.
func (w *statusTrackingResponseWriter) Header() http.Header {
	return w.ResponseWriter.Header()
}

// Write records an implicit status before passing bytes through.
func (w *statusTrackingResponseWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}

	return w.ResponseWriter.Write(body)
}

// WriteHeader records the response status before passing it through.
func (w *statusTrackingResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// register installs only explicitly enabled profile handlers.
func (h *diagnosticProfileHandler) register(profiles config.ProfilesConfig) {
	h.mux.HandleFunc(profileBasePath, h.index)
	h.mux.HandleFunc(profileBasePath+"/", h.index)
	h.mux.HandleFunc(profileBasePath+"/cmdline", httppprof.Cmdline)
	h.mux.HandleFunc(profileBasePath+"/profile", httppprof.Profile)
	h.mux.HandleFunc(profileBasePath+"/symbol", httppprof.Symbol)
	h.mux.HandleFunc(profileBasePath+"/trace", httppprof.Trace)
	h.mux.Handle(profileBasePath+"/allocs", httppprof.Handler(profileClassAllocs))
	h.mux.Handle(profileBasePath+"/heap", httppprof.Handler(profileClassHeap))
	h.mux.Handle(profileBasePath+"/threadcreate", httppprof.Handler(profileClassThread))

	if profiles.Goroutine.Enabled {
		h.mux.Handle(profileBasePath+"/goroutine", httppprof.Handler(profileClassGoroutine))
	}

	if profiles.Block.Enabled {
		h.mux.Handle(profileBasePath+"/block", httppprof.Handler(profileClassBlock))
	}

	if profiles.Mutex.Enabled {
		h.mux.Handle(profileBasePath+"/mutex", httppprof.Handler(profileClassMutex))
	}
}

// index writes a minimal bounded route inventory for enabled profile handlers.
func (h *diagnosticProfileHandler) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != profileBasePath && r.URL.Path != profileBasePath+"/" {
		http.NotFound(w, r)

		return
	}

	w.Header().Set("Content-Type", profileIndexContentType)
	_, _ = fmt.Fprintln(w, profileBasePath+"/")

	for _, path := range []string{
		profileBasePath + "/allocs",
		profileBasePath + "/cmdline",
		profileBasePath + "/heap",
		profileBasePath + "/profile",
		profileBasePath + "/symbol",
		profileBasePath + "/threadcreate",
		profileBasePath + "/trace",
	} {
		_, _ = fmt.Fprintln(w, path)
	}

	if h.profiles.Goroutine.Enabled {
		_, _ = fmt.Fprintln(w, profileBasePath+"/goroutine")
	}

	if h.profiles.Block.Enabled {
		_, _ = fmt.Fprintln(w, profileBasePath+"/block")
	}

	if h.profiles.Mutex.Enabled {
		_, _ = fmt.Fprintln(w, profileBasePath+"/mutex")
	}
}

// record emits one secret-safe profile access audit event.
func (h *diagnosticProfileHandler) record(
	r *http.Request,
	status int,
	profileClass string,
	state ControlAuthState,
) {
	if h == nil {
		return
	}

	statusClass := restStatusClass(status)
	result := profileResultForStatus(status)

	fields := profileObservationFields(r.Method, profileClass, state, result, statusClass)
	if result == profileResultFailure {
		fields[restFieldReasonClass] = restReasonHTTPError
	}

	event, err := observability.NewEvent(observability.EventDiagnosticProfileAccess, observability.TraceBoundaryRESTRequest, fields, map[string]string{
		restFieldMethod:      fields[restFieldMethod],
		restFieldOperation:   fields[restFieldOperation],
		restFieldResult:      fields[restFieldResult],
		restFieldRoute:       fields[restFieldRoute],
		restFieldStatusClass: fields[restFieldStatusClass],
	})
	if err != nil {
		return
	}

	h.recorder.Record(r.Context(), event)
}

// isProfilePath reports whether a request belongs to the protected pprof namespace.
func isProfilePath(path string) bool {
	return path == profileBasePath || strings.HasPrefix(path, profileBasePath+"/")
}

// profileObservationFields returns low-cardinality labels plus audit-only actor fields.
func profileObservationFields(
	method string,
	profileClass string,
	state ControlAuthState,
	result string,
	statusClass string,
) map[string]string {
	return map[string]string{
		restFieldMethod:        strings.ToUpper(strings.TrimSpace(method)),
		restFieldOperation:     profileOperation,
		restFieldResult:        result,
		restFieldRoute:         profileRouteTemplate,
		restFieldStatusClass:   statusClass,
		profileFieldActorID:    state.Actor.ID,
		profileFieldAuthMethod: firstNonEmpty(state.AuthMethod, state.Actor.AuthMethod),
		profileFieldProfile:    profileClass,
	}
}

// profileClassForPath maps pprof paths into bounded route classes.
func profileClassForPath(path string) string {
	switch strings.TrimRight(path, "/") {
	case profileBasePath:
		return profileClassIndex
	case profileBasePath + "/allocs":
		return profileClassAllocs
	case profileBasePath + "/block":
		return profileClassBlock
	case profileBasePath + "/cmdline":
		return profileClassCmdline
	case profileBasePath + "/goroutine":
		return profileClassGoroutine
	case profileBasePath + "/heap":
		return profileClassHeap
	case profileBasePath + "/mutex":
		return profileClassMutex
	case profileBasePath + "/profile":
		return profileClassProfile
	case profileBasePath + "/symbol":
		return profileClassSymbol
	case profileBasePath + "/threadcreate":
		return profileClassThread
	case profileBasePath + "/trace":
		return profileClassTrace
	default:
		return profileClassUnknown
	}
}

// profileResultForStatus maps HTTP status to bounded profile audit results.
func profileResultForStatus(status int) string {
	if status >= http.StatusBadRequest {
		return profileResultFailure
	}

	return profileResultOK
}

// firstNonEmpty returns the first non-empty value for audit fields.
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}

	return profileStatusUnknown
}
