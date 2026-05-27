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
	"sort"
	"strings"

	"github.com/croessner/nauthilus-director/internal/config"
)

const (
	logFieldEventName = "event_name"
	logLevelDisabled  = "disabled"
	logLevelWarn      = "warn"
)

// structuredLogger writes normalized events through the standard slog API.
type structuredLogger struct {
	enabled bool
	logger  *slog.Logger
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
	}
}

// Record writes one event as a structured log record.
func (l *structuredLogger) Record(ctx context.Context, event Event) error {
	if l == nil || !l.enabled || l.logger == nil {
		return nil
	}

	level := slogLevelForEvent(event)

	attrs := []slog.Attr{slog.String(logFieldEventName, event.Name)}
	for _, name := range sortedLogFieldNames(event.LogFields) {
		attrs = append(attrs, slog.String(name, event.LogFields[name]))
	}

	l.logger.LogAttrs(ctx, level, event.Name, attrs...)

	return nil
}

// slogLevel maps config strings to standard library log levels.
func slogLevel(level string) (slog.Level, bool) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "trace", "debug":
		return slog.LevelDebug, true
	case "", "info":
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

// slogLevelForEvent allows normalized events to carry their chosen severity.
func slogLevelForEvent(event Event) slog.Level {
	if event.LogFields == nil {
		return slog.LevelInfo
	}

	level, enabled := slogLevel(event.LogFields["level"])
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
