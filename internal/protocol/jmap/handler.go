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

// Package jmap owns the JMAP-to-JMAP reverse-proxy boundary after the generic listener accepts
// and TLS-terminates a frontend connection.
//
// The package authenticates every HTTP request through Nauthilus, routes it strictly by the
// authenticated account, holds director placement state for the request or event-stream lifetime
// and forwards it unchanged to the selected JMAP backend. It never interprets JMAP method calls.
package jmap

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/placement"
	"github.com/croessner/nauthilus-director/internal/routing"
	runtimectl "github.com/croessner/nauthilus-director/internal/runtime"
)

// Protocol is the canonical director protocol value for JMAP.
const Protocol = "jmap"

// ErrHandlerClosed reports a connection handed to a handler whose HTTP server has shut down.
var ErrHandlerClosed = errors.New("jmap: handler closed")

// BackendDialer is the narrow TCP dial boundary used for backend connections and tests.
type BackendDialer interface {
	DialContext(ctx context.Context, network string, address string) (net.Conn, error)
}

// Config contains immutable listener settings and collaborators for one JMAP handler.
type Config struct {
	ListenerName          string
	AuthorityName         string
	ServiceName           string
	BackendPool           string
	DirectorInstanceID    string
	DefaultTenant         string
	Settings              config.JMAPListenerConfig
	AuthTimeout           time.Duration
	BackendConnectTimeout time.Duration
	SessionLeaseTTL       time.Duration
	SessionIdleGrace      time.Duration
	BackendRetentionTTL   time.Duration
	MaxBearerTokenBytes   int
	Authenticator         nauthilus.Authenticator
	IdentityLookuper      nauthilus.IdentityLookuper
	BearerIntrospector    nauthilus.BearerIntrospector
	RoutingResolver       routing.RoutingResolver
	PlacementService      placement.RequestPlacer
	PlacementGate         runtimectl.PlacementGate
	LocalSessions         *runtimectl.LocalSessionRegistry
	BackendDialer         BackendDialer
	Observability         observability.Recorder
}

// Handler serves one JMAP listener: it feeds accepted connections into an HTTP/1.1 server and
// proxies every admitted request to the backend selected for the authenticated account.
type Handler struct {
	config     Config
	auth       *authenticator
	transports *transportFactory
	proxy      *httputil.ReverseProxy
	recorder   observability.Recorder

	startOnce sync.Once
	mu        sync.Mutex
	server    *http.Server
	listener  *connListener
	conns     map[net.Conn]*downstreamConn
}

// NewHandler creates a JMAP handler from typed listener configuration.
func NewHandler(cfg Config) (*Handler, error) {
	cfg.Settings = cfg.Settings.Normalize()

	auth, err := newAuthenticator(cfg)
	if err != nil {
		return nil, err
	}

	handler := &Handler{
		config:     cfg,
		auth:       auth,
		transports: newTransportFactory(cfg),
		recorder:   observability.NormalizeRecorder(cfg.Observability),
		conns:      map[net.Conn]*downstreamConn{},
	}
	handler.proxy = handler.newReverseProxy()

	return handler, nil
}

// Serve hands one accepted, TLS-terminated frontend connection to the HTTP server and blocks
// until the server has finished with it, so listener drain and shutdown accounting stay exact.
func (h *Handler) Serve(ctx context.Context, conn net.Conn) error {
	h.startOnce.Do(h.startServer)

	downstream := h.trackDownstream(conn)
	if err := h.listener.deliver(conn); err != nil {
		h.releaseDownstream(conn)

		return err
	}

	select {
	case <-downstream.done:
		return nil
	case <-ctx.Done():
		_ = conn.Close()

		<-downstream.done

		return ctx.Err()
	}
}

// AcceptStateChanged disables keep-alive and closes idle connections while the listener drains,
// and restores keep-alive when it accepts again.
func (h *Handler) AcceptStateChanged(accepting bool) {
	h.mu.Lock()
	server := h.server
	h.mu.Unlock()

	if server != nil {
		server.SetKeepAlivesEnabled(accepting)
	}
}

// ServeHTTP runs the per-request admission, placement and proxy pipeline.
func (h *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	h.serveRequest(writer, request)
}

// startServer creates the HTTP server that owns every connection of this listener.
func (h *Handler) startServer() {
	limits := h.config.Settings.Limits
	timeouts := h.config.Settings.Timeouts
	server := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: timeouts.ReadHeader.Std(),
		ReadTimeout:       timeouts.Read.Std(),
		IdleTimeout:       timeouts.Idle.Std(),
		MaxHeaderBytes:    limits.MaxHeaderBytes,
		ConnContext:       h.connContext,
		ConnState:         h.connState,
		ErrorLog:          log.New(io.Discard, "", 0),
		// Event streams are long-lived responses, so no write timeout is set.
		WriteTimeout: 0,
	}
	server.SetKeepAlivesEnabled(true)

	listener := newConnListener()

	h.mu.Lock()
	h.server = server
	h.listener = listener
	h.mu.Unlock()

	go func() {
		_ = server.Serve(listener)
	}()
}

// trackDownstream registers one frontend connection before the HTTP server sees it.
func (h *Handler) trackDownstream(conn net.Conn) *downstreamConn {
	downstream := newDownstreamConn(conn)

	h.mu.Lock()
	h.conns[conn] = downstream
	h.mu.Unlock()

	return downstream
}

// releaseDownstream closes backend transports of one frontend connection and unblocks Serve.
func (h *Handler) releaseDownstream(conn net.Conn) {
	h.mu.Lock()
	downstream := h.conns[conn]
	delete(h.conns, conn)
	h.mu.Unlock()

	if downstream != nil {
		downstream.close()
	}
}

// connContext binds the frontend connection state to every request served on it.
func (h *Handler) connContext(ctx context.Context, conn net.Conn) context.Context {
	h.mu.Lock()
	downstream := h.conns[conn]
	h.mu.Unlock()

	if downstream == nil {
		return ctx
	}

	return withDownstream(ctx, downstream)
}

// connState releases per-connection backend transports once the frontend connection ends.
func (h *Handler) connState(conn net.Conn, state http.ConnState) {
	switch state {
	case http.StateClosed, http.StateHijacked:
		h.releaseDownstream(conn)
	default:
	}
}
