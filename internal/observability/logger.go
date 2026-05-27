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

package observability

import (
	"context"
	"io"
	"log/slog"
	"maps"
	"sort"
	"strings"

	"github.com/croessner/nauthilus-director/internal/config"
	oteltrace "go.opentelemetry.io/otel/trace"
)

const (
	logFieldComponent   = "component"
	logFieldEventName   = "event_name"
	logFieldOperation   = "operation"
	logFieldReason      = "reason_class"
	logFieldResult      = "result"
	logLevelDebug       = "debug"
	logLevelDisabled    = "disabled"
	logLevelInfo        = "info"
	logLevelWarn        = "warn"
	logResultFailClosed = "fail_closed"
)

// structuredLogger writes normalized events through the standard slog API.
type structuredLogger struct {
	enabled bool
	logger  *slog.Logger
	policy  LogPolicy
}

// newStructuredLogger builds the configured structured logging sink.
func newStructuredLogger(cfg config.LogConfig, writer io.Writer) *structuredLogger {
	level, enabled := slogLevel(cfg.Level)

	if writer == nil {
		writer = io.Discard
	}

	handlerOptions := &slog.HandlerOptions{
		AddSource: cfg.AddSource,
		Level:     level,
	}

	var handler slog.Handler
	if cfg.JSON {
		handler = slog.NewJSONHandler(writer, handlerOptions)
	} else {
		handler = slog.NewTextHandler(writer, handlerOptions)
	}

	return &structuredLogger{
		enabled: enabled,
		logger:  slog.New(handler),
		policy:  NewLogPolicy(cfg.RedactSecrets),
	}
}

// Record writes one event as a structured log record.
func (l *structuredLogger) Record(ctx context.Context, event Event) error {
	if l == nil || !l.enabled || l.logger == nil {
		return nil
	}

	fields := l.logFields(event)
	level := slogLevelForFields(fields)

	attrs := []slog.Attr{slog.String(logFieldEventName, event.Name)}
	for _, name := range sortedLogFieldNames(fields) {
		attrs = append(attrs, slog.String(name, fields[name]))
	}

	attrs = appendTraceCorrelationAttrs(ctx, attrs)
	l.logger.LogAttrs(ctx, level, event.Name, attrs...)

	return nil
}

// logFields merges event metadata and applies the runtime log-field policy.
func (l *structuredLogger) logFields(event Event) LogFields {
	raw := make(map[string]string, len(event.MetricLabels)+len(event.LogFields)+3)
	maps.Copy(raw, event.MetricLabels)

	maps.Copy(raw, event.LogFields)

	fields := l.policy.Sanitize(raw)
	addDefaultLogFields(fields, event)

	return fields
}

// addDefaultLogFields ensures every runtime log has the core operator fields.
func addDefaultLogFields(fields LogFields, event Event) {
	if strings.TrimSpace(fields[logFieldComponent]) == "" {
		fields[logFieldComponent] = componentFromEventName(event.Name)
	}

	if strings.TrimSpace(fields[logFieldOperation]) == "" {
		fields[logFieldOperation] = operationFromEventName(event.Name)
	}

	if strings.TrimSpace(fields[logFieldResult]) == "" {
		fields[logFieldResult] = defaultLogResult(event)
	}

	if strings.TrimSpace(fields[logFieldReason]) == "" {
		fields[logFieldReason] = defaultLogReason(event, fields[logFieldResult])
	}
}

// appendTraceCorrelationAttrs adds active span identifiers to structured logs.
func appendTraceCorrelationAttrs(ctx context.Context, attrs []slog.Attr) []slog.Attr {
	spanContext := oteltrace.SpanContextFromContext(ctx)
	if !spanContext.IsValid() {
		return attrs
	}

	return append(
		attrs,
		slog.String(fieldTraceID, spanContext.TraceID().String()),
		slog.String(fieldSpanID, spanContext.SpanID().String()),
	)
}

// componentFromEventName derives a stable component from the event namespace.
func componentFromEventName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return metricOperationUnknown
	}

	component, _, _ := strings.Cut(name, ".")

	return normalizeLogToken(component, metricOperationUnknown)
}

// operationFromEventName derives a stable operation when callers omit one.
func operationFromEventName(name string) string {
	operation := strings.ReplaceAll(strings.TrimSpace(name), ".", "_")

	return normalizeLogToken(operation, metricOperationUnknown)
}

// defaultLogResult extracts a bounded result from event metadata.
func defaultLogResult(event Event) string {
	if value := normalizeLogToken(eventResult(event), ""); value != "" {
		return value
	}

	return metricResultObserved
}

// defaultLogReason extracts or infers a bounded reason class.
func defaultLogReason(event Event, result string) string {
	if value := NormalizeReasonClass(eventReasonClass(event)); value != reasonClassOther || strings.TrimSpace(eventReasonClass(event)) != "" {
		return value
	}

	if result == telemetryResultFailed || result == logResultFailClosed || result == reasonClassTemporaryFailure {
		return reasonClassOther
	}

	return reasonClassOK
}

// slogLevel maps config strings to standard library log levels.
func slogLevel(level string) (slog.Level, bool) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "trace", logLevelDebug:
		return slog.LevelDebug, true
	case "", logLevelInfo:
		return slog.LevelInfo, true
	case logLevelWarn, "warning":
		return slog.LevelWarn, true
	case "error", "fatal", "panic":
		return slog.LevelError, true
	case "off", "none", logLevelDisabled:
		return slog.LevelError, false
	default:
		return slog.LevelInfo, true
	}
}

// slogLevelForFields allows normalized events to carry their chosen severity.
func slogLevelForFields(fields LogFields) slog.Level {
	if fields == nil {
		return slog.LevelInfo
	}

	level, enabled := slogLevel(fields["level"])
	if !enabled {
		return slog.LevelInfo
	}

	return level
}

// sortedLogFieldNames returns deterministic field order for stable test output.
func sortedLogFieldNames(fields LogFields) []string {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}

	sort.Strings(names)

	return names
}
