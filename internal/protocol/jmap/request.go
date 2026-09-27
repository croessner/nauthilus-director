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
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/placement"
)

const (
	problemContentType    = "application/problem+json"
	retryAfterHeader      = "Retry-After"
	retryAfterSeconds     = "5"
	healthBody            = "ok\n"
	healthContentType     = "text/plain; charset=utf-8"
	leaseCloseTimeout     = 5 * time.Second
	headerNoSniff         = "X-Content-Type-Options"
	headerNoSniffValue    = "nosniff"
	headerCacheControl    = "Cache-Control"
	headerNoStore         = "no-store"
	problemTypeAboutBlank = "about:blank"
)

// problem is the RFC 7807 body of every response the director answers itself.
type problem struct {
	Type   string `json:"type"`
	Status int    `json:"status"`
	Title  string `json:"title"`
}

// serveRequest admits, authenticates, routes, places and proxies one JMAP request.
func (h *Handler) serveRequest(writer http.ResponseWriter, request *http.Request) {
	record := newRequestRecord(request.Method)
	responseWriter := &statusWriter{ResponseWriter: writer}
	request = request.WithContext(withRequestRecord(request.Context(), record))

	defer func() {
		h.recordRequest(request.Context(), record, responseWriter.status)
	}()

	target, ok := h.admit(responseWriter, request, record)
	if !ok {
		return
	}

	who, ok := h.authenticateRequest(responseWriter, request, record)
	if !ok {
		return
	}

	lease, ok := h.routeAndPlace(responseWriter, request, record, target, who)
	if !ok {
		return
	}

	defer h.closeLease(lease)

	h.forward(responseWriter, request, record, target, lease)
}

// admit applies the path allowlist, method allowlist, local health answer and body bounds.
func (h *Handler) admit(writer *statusWriter, request *http.Request, record *requestRecord) (endpoint, bool) {
	target := classifyEndpoint(request.URL.Path, h.config.Settings.HealthPath)
	record.endpoint = target

	if target == endpointUnknown {
		record.setReason(reasonNotFound)
		h.writeProblem(writer, http.StatusNotFound, "not found")

		return target, false
	}

	if !target.allowsMethod(request.Method) {
		record.setReason(reasonUnsupported)
		writer.Header().Set(allowHeader, target.allowHeaderValue())
		h.writeProblem(writer, http.StatusMethodNotAllowed, "method not allowed")

		return target, false
	}

	if request.Header.Get(headerUpgrade) != "" {
		// JMAP over WebSocket (RFC 8887) is not proxied; no request may switch protocols.
		record.setReason(reasonUnsupported)
		h.writeProblem(writer, http.StatusBadRequest, "protocol upgrade not supported")

		return target, false
	}

	if target == endpointHealth {
		writer.Header().Set(headerContentType, healthContentType)
		writer.Header().Set(headerCacheControl, headerNoStore)
		writer.WriteHeader(http.StatusOK)

		if request.Method != http.MethodHead {
			_, _ = writer.Write([]byte(healthBody))
		}

		return target, false
	}

	limit := target.bodyLimit(h.config.Settings.Limits)
	if request.ContentLength > limit {
		record.setReason(reasonBodyTooLarge)
		h.writeProblem(writer, http.StatusRequestEntityTooLarge, "request body too large")

		return target, false
	}

	request.Body = http.MaxBytesReader(writer, request.Body, limit)

	return target, true
}

// authenticateRequest resolves the principal or answers 401/503 with the configured challenges.
func (h *Handler) authenticateRequest(writer *statusWriter, request *http.Request, record *requestRecord) (principal, bool) {
	who, outcome := h.auth.authenticate(request.Context(), request)
	record.auth = outcome

	switch outcome {
	case authOutcomeAuthenticated, authOutcomeCached:
		return who, true
	case authOutcomeTempfail:
		record.setReason(reasonTemporaryFailure)
		writer.Header().Set(retryAfterHeader, retryAfterSeconds)
		h.writeProblem(writer, http.StatusServiceUnavailable, "authentication temporarily unavailable")
	default:
		record.setReason(reasonAuth)

		for _, challenge := range h.auth.challenges(outcome, bearerAttempt(request)) {
			writer.Header().Add(authenticateHeader, challenge)
		}

		h.writeProblem(writer, http.StatusUnauthorized, "authentication required")
	}

	return principal{}, false
}

// routeAndPlace resolves the shard and opens the placement lease for the request.
func (h *Handler) routeAndPlace(
	writer *statusWriter,
	request *http.Request,
	record *requestRecord,
	target endpoint,
	who principal,
) (placement.LeaseHandle, bool) {
	decided, err := h.resolveRoute(request.Context(), request, who)
	if err != nil {
		h.writeRoutingFailure(writer, record, err)

		return nil, false
	}

	record.shardTag = decided.result.ShardTag
	record.routingSource = decided.result.RoutingSource

	lease, err := h.placementLease(request.Context(), target, decided)
	if err != nil {
		record.setReason(placementReason(err))
		writer.Header().Set(retryAfterHeader, retryAfterSeconds)
		h.writeProblem(writer, http.StatusServiceUnavailable, "no backend available")

		return nil, false
	}

	return lease, true
}

// writeRoutingFailure answers the configured missing-shard status or 503 for other routing errors.
func (h *Handler) writeRoutingFailure(writer *statusWriter, record *requestRecord, err error) {
	record.setReason(reasonRouting)

	if errors.Is(err, errMissingShard) && h.config.Settings.Routing.MissingShard == config.JMAPMissingShardForbidden {
		h.writeProblem(writer, http.StatusForbidden, "account is not served here")

		return
	}

	writer.Header().Set(retryAfterHeader, retryAfterSeconds)
	h.writeProblem(writer, http.StatusServiceUnavailable, "routing unavailable")
}

// forward proxies the admitted request to the leased backend.
func (h *Handler) forward(
	writer *statusWriter,
	request *http.Request,
	record *requestRecord,
	target endpoint,
	lease placement.LeaseHandle,
) {
	selected := lease.Backend().Backend
	record.backendIdentifier = selected.Identifier

	downstream, ok := downstreamFromContext(request.Context())
	if !ok {
		record.setReason(reasonUnavailable)
		h.writeProblem(writer, http.StatusServiceUnavailable, "connection state unavailable")

		return
	}

	ctx := withProxyTarget(request.Context(), proxyTarget{backend: selected, downstream: downstream, record: record})

	if target == endpointEventSource {
		streamCtx, stop := h.superviseEventStream(ctx, lease, record)
		defer stop()

		ctx = streamCtx
	} else {
		defer h.keepRequestHold(ctx, lease)()
	}

	h.proxy.ServeHTTP(writer, request.WithContext(ctx))
}

// closeLease releases the request hold or event-stream lease independent of the request context.
func (h *Handler) closeLease(lease placement.LeaseHandle) {
	ctx, cancel := context.WithTimeout(context.Background(), leaseCloseTimeout)
	defer cancel()

	_ = lease.Close(ctx)
}

// writeProblem answers one director-owned error as a small RFC 7807 document.
func (h *Handler) writeProblem(writer http.ResponseWriter, status int, title string) {
	body, err := json.Marshal(problem{Type: problemTypeAboutBlank, Status: status, Title: title})
	if err != nil {
		writer.WriteHeader(status)

		return
	}

	header := writer.Header()
	header.Set(headerContentType, problemContentType)
	header.Set(headerNoSniff, headerNoSniffValue)
	header.Set(headerCacheControl, headerNoStore)
	header.Set("Content-Length", strconv.Itoa(len(body)))
	writer.WriteHeader(status)
	_, _ = writer.Write(body)
}

// placementReason classifies placement failures into bounded reasons.
func placementReason(err error) string {
	if placement.IsErrorKind(err, placement.ErrorKindNoBackend) || backend.IsErrorKind(err, backend.ErrorKindNoBackend) {
		return reasonNoBackend
	}

	return reasonUnavailable
}

// statusWriter records the response status while staying transparent for flushing.
type statusWriter struct {
	http.ResponseWriter
	status int
}

// WriteHeader records the first status code.
func (w *statusWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}

	w.ResponseWriter.WriteHeader(status)
}

// Write records an implicit 200 before the first body bytes.
func (w *statusWriter) Write(payload []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}

	return w.ResponseWriter.Write(payload)
}

// Flush forwards streaming flushes such as event-stream records.
func (w *statusWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Unwrap exposes the underlying writer to http.ResponseController.
func (w *statusWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
