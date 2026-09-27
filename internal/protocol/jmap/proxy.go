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

package jmap

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/croessner/nauthilus-director/internal/backend"
)

const (
	schemeHTTPS          = "https"
	headerForwarded      = "Forwarded"
	headerXForwardedFrom = "X-Forwarded-"
	headerXRealIP        = "X-Real-Ip"
	headerXClientIP      = "X-Client-Ip"
	headerTrueClientIP   = "True-Client-Ip"
	headerContentType    = "Content-Type"
	headerUpgrade        = "Upgrade"
	headerConnection     = "Connection"
)

// errDownstreamClosed reports a proxied request whose frontend connection already ended.
var errDownstreamClosed = errors.New("jmap: frontend connection closed")

// proxyTarget is the per-request routing decision the reverse proxy forwards to.
type proxyTarget struct {
	backend    backend.Backend
	downstream *downstreamConn
	record     *requestRecord
}

type proxyTargetContextKey struct{}

// withProxyTarget attaches the selected backend to the outbound request context.
func withProxyTarget(ctx context.Context, target proxyTarget) context.Context {
	return context.WithValue(ctx, proxyTargetContextKey{}, target)
}

// proxyTargetFromContext returns the selected backend of one proxied request.
func proxyTargetFromContext(ctx context.Context) (proxyTarget, bool) {
	target, ok := ctx.Value(proxyTargetContextKey{}).(proxyTarget)

	return target, ok
}

// newReverseProxy builds the shared reverse proxy; the backend and transport come from the context.
func (h *Handler) newReverseProxy() *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite:        rewriteRequest,
		Transport:      downstreamRoundTripper{factory: h.transports},
		FlushInterval:  0,
		ErrorHandler:   h.proxyError,
		ModifyResponse: h.modifyResponse,
		ErrorLog:       log.New(io.Discard, "", 0),
	}
}

// rewriteRequest points the outbound request at the backend and drops client-asserted address headers.
//
// The Authorization header is forwarded unchanged because the backend verifies every request
// itself. The client address reaches the backend only through the PROXY header of the backend
// connection, never through headers a client could forge.
func rewriteRequest(proxyRequest *httputil.ProxyRequest) {
	target, ok := proxyTargetFromContext(proxyRequest.In.Context())
	if !ok {
		return
	}

	// Path, RawPath and RawQuery stay exactly as the client sent them: encoded blob names and
	// download query parameters must reach the backend byte for byte.
	proxyRequest.Out.URL.Scheme = schemeHTTPS
	proxyRequest.Out.URL.Host = target.backend.Address
	proxyRequest.Out.Host = proxyRequest.In.Host

	// ReverseProxy re-adds Connection/Upgrade for upgrade requests before Rewrite; admission
	// already refuses them, and removing them here keeps the backend request a plain one.
	proxyRequest.Out.Header.Del(headerUpgrade)
	proxyRequest.Out.Header.Del(headerConnection)

	stripClientAddressHeaders(proxyRequest.Out.Header)
}

// stripClientAddressHeaders removes every header that claims a client or proxy address.
func stripClientAddressHeaders(header http.Header) {
	for name := range header {
		canonical := http.CanonicalHeaderKey(name)
		if canonical == headerForwarded || strings.HasPrefix(canonical, headerXForwardedFrom) ||
			canonical == headerXRealIP || canonical == headerXClientIP || canonical == headerTrueClientIP {
			header.Del(name)
		}
	}
}

// downstreamRoundTripper sends each request over the transport owned by its frontend connection.
type downstreamRoundTripper struct {
	factory *transportFactory
}

// RoundTrip selects this frontend connection's transport for the chosen backend.
func (t downstreamRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	target, ok := proxyTargetFromContext(request.Context())
	if !ok || target.downstream == nil {
		return nil, errDownstreamClosed
	}

	transport, ok := t.factory.forDownstream(target.downstream, target.backend)
	if !ok {
		return nil, errDownstreamClosed
	}

	return transport.RoundTrip(request)
}

// modifyResponse flushes event streams immediately and inspects session URLs when configured.
func (h *Handler) modifyResponse(response *http.Response) error {
	target, ok := proxyTargetFromContext(response.Request.Context())
	if !ok || target.record == nil {
		return nil
	}

	target.record.backendStatus = response.StatusCode

	if target.record.endpoint == endpointSession && response.StatusCode == http.StatusOK {
		h.inspectSessionResource(response)
	}

	return nil
}

// proxyError maps backend and body failures to bounded HTTP answers.
func (h *Handler) proxyError(writer http.ResponseWriter, request *http.Request, err error) {
	record := recordFromContext(request.Context())

	var tooLarge *http.MaxBytesError

	switch {
	case errors.As(err, &tooLarge):
		record.setReason(reasonBodyTooLarge)
		h.writeProblem(writer, http.StatusRequestEntityTooLarge, "request body too large")
	case request.Context().Err() != nil:
		record.setReason(reasonCanceled)
	case isTimeout(err):
		record.setReason(reasonTimeout)
		h.writeProblem(writer, http.StatusGatewayTimeout, "backend timeout")
	default:
		record.setReason(reasonBackendConnect)
		h.writeProblem(writer, http.StatusBadGateway, "backend unavailable")
	}
}

// isTimeout detects context and network timeouts without exposing raw error text.
func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	var netErr net.Error

	return errors.As(err, &netErr) && netErr.Timeout()
}
