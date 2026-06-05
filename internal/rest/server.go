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
	"net/http"

	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/rest/adapters"
	"github.com/croessner/nauthilus-director/internal/rest/generated"
)

// Options configures the generated REST boundary wrapper.
type Options struct {
	Version          string
	ConfigPath       string
	Control          config.ControlServerConfig
	Authorities      map[string]config.AuthorityConfig
	Profiles         config.ProfilesConfig
	AuthHTTPClient   *http.Client
	OIDCIntrospector OIDCIntrospector
	HandlerOptions   adapters.HandlerOptions
}

// Server owns the control API HTTP handler and generated route registration.
type Server struct {
	handler http.Handler
}

// NewServer builds the generated strict-server boundary with local adapters.
func NewServer(options Options) *Server {
	handlerOptions := options.HandlerOptions
	if handlerOptions.Version == "" {
		handlerOptions.Version = options.Version
	}

	if handlerOptions.ConfigPath == "" {
		handlerOptions.ConfigPath = options.ConfigPath
	}

	if handlerOptions.ProtectedConfigAuthorizer == nil {
		handlerOptions.ProtectedConfigAuthorizer = ProtectedContextAuthorizer{}
	}

	handler := adapters.NewHandler(handlerOptions)
	strict := generated.NewStrictHandlerWithOptions(handler, []generated.StrictMiddlewareFunc{
		traceRESTRequests(handlerOptions.Observability),
	}, generated.StrictHTTPServerOptions{
		RequestErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, _ error) {
			writeProblem(w, http.StatusBadRequest, "bad_request", "request body, path parameter or query parameter is invalid", "")
		},
		ResponseErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, _ error) {
			writeProblem(w, http.StatusInternalServerError, "internal_error", "control API response failed", "")
		},
	})
	registered := generated.Handler(strict)
	authenticator := NewControlAuthenticator(ControlAuthOptions{
		Config:           options.Control,
		Authorities:      options.Authorities,
		HTTPClient:       options.AuthHTTPClient,
		OIDCIntrospector: options.OIDCIntrospector,
	})
	guarded := authenticator.Wrap(registered)
	profiles := newDiagnosticProfileHandler(options.Profiles, handlerOptions.Observability)
	handlerWithProfiles := profileControlHandler(guarded, options.Profiles, authenticator.Wrap(profiles))

	return &Server{handler: handlerWithProfiles}
}

// Handler returns the registered control API handler.
func (s *Server) Handler() http.Handler {
	return s.handler
}

// ServeHTTP lets Server satisfy http.Handler directly.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}
