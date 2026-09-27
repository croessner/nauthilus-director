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
	"strconv"
	"sync"
	"time"

	"github.com/croessner/nauthilus-director/internal/observability"
)

const (
	reasonOK               = "ok"
	reasonAuth             = "auth"
	reasonBackendConnect   = "backend_connect"
	reasonBodyTooLarge     = "size_body_too_large"
	reasonCanceled         = "canceled"
	reasonControlAction    = "control_action"
	reasonNoBackend        = "no_backend"
	reasonNotFound         = "not_found"
	reasonRouting          = "routing"
	reasonTemporaryFailure = "temporary_failure"
	reasonTimeout          = "timeout"
	reasonUnavailable      = "unavailable"
	reasonUnsupported      = "unsupported"

	fieldLevel             = "level"
	fieldListener          = "listener"
	fieldService           = "service"
	fieldProtocol          = "protocol"
	fieldBackendPool       = "backend_pool"
	fieldOperation         = "operation"
	fieldStatusClass       = "status_class"
	fieldResult            = "result"
	fieldReasonClass       = "reason_class"
	fieldHTTPMethod        = "http_method"
	fieldHTTPStatus        = "http_status"
	fieldBackendStatus     = "backend_status"
	fieldShardTag          = "shard_tag"
	fieldRoutingSource     = "routing_source"
	fieldBackendIdentifier = "backend_identifier"
	levelDebug             = "debug"
	levelInfo              = "info"
	levelWarn              = "warn"
	statusClassNone        = "none"
)

// requestRecord accumulates bounded facts of one request for its terminal observation.
type requestRecord struct {
	started           time.Time
	method            string
	endpoint          endpoint
	auth              authOutcome
	shardTag          string
	routingSource     string
	backendIdentifier string
	backendStatus     int

	mu     sync.Mutex
	reason string
}

type requestRecordContextKey struct{}

// newRequestRecord starts the observation of one request.
func newRequestRecord(method string) *requestRecord {
	return &requestRecord{started: time.Now(), method: boundedMethod(method), endpoint: endpointUnknown, auth: authOutcomeNone}
}

// withRequestRecord attaches the record so the proxy error path can classify failures.
func withRequestRecord(ctx context.Context, record *requestRecord) context.Context {
	return context.WithValue(ctx, requestRecordContextKey{}, record)
}

// recordFromContext returns the request record or a detached placeholder.
func recordFromContext(ctx context.Context) *requestRecord {
	if record, ok := ctx.Value(requestRecordContextKey{}).(*requestRecord); ok && record != nil {
		return record
	}

	return newRequestRecord("")
}

// setReason stores the first failure reason of the request.
func (r *requestRecord) setReason(reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.reason == "" {
		r.reason = reason
	}
}

// reasonClass returns the stored failure reason or ok.
func (r *requestRecord) reasonClass() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.reason == "" {
		return reasonOK
	}

	return r.reason
}

// recordRequest emits one jmap.request event without credentials, paths or account names.
func (h *Handler) recordRequest(ctx context.Context, record *requestRecord, status int) {
	reason := record.reasonClass()
	statusClass := httpStatusClass(status)

	labels := map[string]string{
		fieldProtocol:    Protocol,
		fieldListener:    h.config.ListenerName,
		fieldBackendPool: h.config.BackendPool,
		fieldOperation:   string(record.endpoint),
		fieldStatusClass: statusClass,
		fieldResult:      string(record.auth),
		fieldReasonClass: reason,
	}

	fields := map[string]string{
		fieldLevel:             requestLogLevel(reason, status),
		fieldService:           h.config.ServiceName,
		fieldHTTPMethod:        record.method,
		fieldHTTPStatus:        strconv.Itoa(status),
		fieldShardTag:          record.shardTag,
		fieldRoutingSource:     record.routingSource,
		fieldBackendIdentifier: record.backendIdentifier,
	}

	if record.backendStatus > 0 {
		fields[fieldBackendStatus] = strconv.Itoa(record.backendStatus)
	}

	event, err := observability.NewEvent(observability.EventJMAPRequest, "", fields, labels)
	if err != nil {
		return
	}

	event.Measurements = observability.NewMetricMeasurements(map[string]float64{
		observability.MetricMeasurementDurationSeconds: time.Since(record.started).Seconds(),
	})

	h.recorder.Record(ctx, event)
}

// httpStatusClass maps a status code to a bounded label value.
func httpStatusClass(status int) string {
	if status < 100 || status > 599 {
		return statusClassNone
	}

	return strconv.Itoa(status/100) + "xx"
}

// requestLogLevel logs ordinary successful traffic at debug and director refusals at info.
func requestLogLevel(reason string, status int) string {
	if reason == reasonOK && status < 500 {
		return levelDebug
	}

	return levelInfo
}

// boundedMethod keeps the logged HTTP method within the standard vocabulary.
func boundedMethod(method string) string {
	switch method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
		return method
	default:
		return "other"
	}
}

// recordSessionURLMismatch reports a session resource that advertises URLs outside the public origin.
func (h *Handler) recordSessionURLMismatch(ctx context.Context, field string) {
	event, err := observability.NewEvent(observability.EventJMAPSessionURL, "", map[string]string{
		fieldLevel:      levelWarn,
		fieldListener:   h.config.ListenerName,
		fieldOperation:  "session_url_check",
		"session_field": field,
		fieldResult:     "mismatch",
	}, nil)
	if err != nil {
		return
	}

	h.recorder.Record(ctx, event)
}
