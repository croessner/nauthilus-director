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

package mcpserver

import (
	"context"
	"strconv"

	"github.com/croessner/nauthilus-director/internal/observability"
)

// Request results of the transport audit and the request metric.
const (
	resultOK           = "ok"
	resultToolError    = "tool_error"
	resultUnauthorized = "unauthorized"
	resultForbidden    = "forbidden"
	resultRejected     = "rejected"
	resultRateLimited  = "rate_limited"
	resultBusy         = "busy"
	resultError        = "error"
)

// Audit and metric field names of the MCP request event.
const (
	fieldLevel       = "level"
	fieldAudit       = "audit"
	fieldOperation   = "operation"
	fieldResult      = "result"
	fieldStatusClass = "status_class"
	fieldHTTPStatus  = "http_status"
	fieldReason      = "mcp_reason"
	fieldActorID     = "actor_id"
	fieldProblemCode = "problem_code"
	fieldClientIP    = "client_ip"
	fieldFailed      = "internal_failure"

	auditValue          = "mcp_diagnostics"
	operationTransport  = "transport"
	levelInfo           = "info"
	levelDebug          = "debug"
	levelWarn           = "warn"
	statusClassFallback = "none"
)

// accessRecord is one transport audit record. It never carries tokens, arguments or results.
type accessRecord struct {
	result    string
	reason    string
	tool      string
	principal string
	code      string
	status    int
	failed    bool
}

// record emits the request event: the metric always counts it, and the audit log record is
// written at info level when audit is enabled (debug otherwise; warn for an internal failure).
// The director log policy keeps the client address collapsed to a presence flag.
func (s *Server) record(ctx context.Context, entry accessRecord) {
	if ctx == nil {
		ctx = context.Background()
	}

	operation := entry.tool
	if operation == "" {
		operation = operationTransport
	}

	statusClass := httpStatusClass(entry.status)
	labels := map[string]string{fieldOperation: operation, fieldStatusClass: statusClass, fieldResult: entry.result}
	fields := map[string]string{
		fieldLevel:       s.auditLevel(entry),
		fieldAudit:       auditValue,
		fieldOperation:   operation,
		fieldResult:      entry.result,
		fieldStatusClass: statusClass,
		fieldHTTPStatus:  strconv.Itoa(entry.status),
	}

	if client := clientIPOf(ctx); client.IsValid() {
		fields[fieldClientIP] = client.String()
	}

	for name, value := range map[string]string{fieldReason: entry.reason, fieldActorID: entry.principal, fieldProblemCode: entry.code} {
		if value != "" {
			fields[name] = value
		}
	}

	if entry.failed {
		fields[fieldFailed] = "true"
	}

	event, err := observability.NewEvent(observability.EventMCPRequest, "", fields, labels)
	if err != nil {
		return
	}

	s.recorder.Record(context.WithoutCancel(ctx), event)
}

// auditLevel returns the log level of one access record.
func (s *Server) auditLevel(entry accessRecord) string {
	switch {
	case entry.failed:
		return levelWarn
	case s.audit:
		return levelInfo
	default:
		return levelDebug
	}
}

// httpStatusClass maps a status code to a bounded label value.
func httpStatusClass(status int) string {
	if status < 100 || status > 599 {
		return statusClassFallback
	}

	return strconv.Itoa(status/100) + "xx"
}
