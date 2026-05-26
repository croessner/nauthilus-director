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

package app

import (
	"context"
	"strings"

	"github.com/croessner/nauthilus-director/internal/observability"
	"go.uber.org/fx/fxevent"
)

const (
	fxLogEventName = "app.fx"

	fxLogLevelDebug = "debug"
	fxLogLevelInfo  = "info"
	fxLogLevelWarn  = "warn"
	fxLogLevelError = "error"
	fxLogLevelOff   = "off"

	fxLogFieldComponent    = "component"
	fxLogFieldErrorPresent = "error_present"
	fxLogFieldEvent        = "event"
	fxLogFieldFunction     = "function"
	fxLogFieldLevel        = "level"
	fxLogFieldOperation    = "operation"
	fxLogFieldReasonClass  = "reason_class"
	fxLogFieldResult       = "result"
	fxLogFieldSource       = "source"
	fxLogFieldType         = "type"
	fxLogReasonConfig      = "config"
	fxLogReasonLifecycle   = "lifecycle"
	fxLogReasonUnavailable = "unavailable"
	fxLogResultFailure     = "failure"
	fxLogResultOK          = "ok"
	fxLogSource            = "uber_fx"
	fxLogValueTrue         = "true"
)

var fxLogLevelRanks = map[string]int{
	fxLogLevelDebug: 10,
	fxLogLevelInfo:  20,
	fxLogLevelWarn:  30,
	fxLogLevelError: 40,
	fxLogLevelOff:   100,
}

type fxEventLogger struct {
	minLevel string
	recorder observability.Recorder
}

type fxLogEntry struct {
	level       string
	event       string
	operation   string
	result      string
	reasonClass string
	function    string
	typeName    string
	err         error
}

// newFxEventLogger creates the Fx logger from typed process logging config.
func newFxEventLogger(options runtimeOptions) fxevent.Logger {
	level := fxLogLevel("")
	if options.Snapshot != nil {
		level = fxLogLevel(options.Snapshot.Config.Observability.Log.Level)
	}

	return &fxEventLogger{
		minLevel: level,
		recorder: observability.NormalizeRecorder(options.Recorder),
	}
}

// LogEvent records Fx events through the director observability policy.
func (l *fxEventLogger) LogEvent(event fxevent.Event) {
	if l == nil {
		return
	}

	entry, ok := l.entryFor(event)
	if !ok || !l.enabled(entry.level) {
		return
	}

	fields := map[string]string{
		fxLogFieldComponent:   "app",
		fxLogFieldEvent:       entry.event,
		fxLogFieldLevel:       entry.level,
		fxLogFieldOperation:   entry.operation,
		fxLogFieldReasonClass: entry.reasonClass,
		fxLogFieldResult:      entry.result,
		fxLogFieldSource:      fxLogSource,
	}
	if entry.function != "" {
		fields[fxLogFieldFunction] = entry.function
	}

	if entry.typeName != "" {
		fields[fxLogFieldType] = entry.typeName
	}

	if entry.err != nil {
		fields[fxLogFieldErrorPresent] = fxLogValueTrue
	}

	eventRecord, err := observability.NewEvent(fxLogEventName, "", fields, nil)
	if err != nil {
		return
	}

	observability.NormalizeRecorder(l.recorder).Record(context.Background(), eventRecord)
}

// enabled reports whether a candidate Fx event passes the configured threshold.
func (l *fxEventLogger) enabled(level string) bool {
	minRank, ok := fxLogLevelRanks[l.minLevel]
	if !ok {
		minRank = fxLogLevelRanks[fxLogLevelInfo]
	}

	if minRank >= fxLogLevelRanks[fxLogLevelOff] {
		return false
	}

	eventRank, ok := fxLogLevelRanks[fxLogLevel(level)]
	if !ok {
		eventRank = fxLogLevelRanks[fxLogLevelInfo]
	}

	return eventRank >= minRank
}

// entryFor classifies Fx's verbose event stream into director log levels.
func (l *fxEventLogger) entryFor(event fxevent.Event) (fxLogEntry, bool) {
	if entry, ok := fxHookExecutionEntry(event); ok {
		return entry, true
	}

	if entry, ok := fxDependencyEntry(event); ok {
		return entry, true
	}

	if entry, ok := fxApplicationEntry(event); ok {
		return entry, true
	}

	return fxLogEntry{}, false
}

// fxHookExecutionEntry maps hook and invoke events into log entries.
func fxHookExecutionEntry(event fxevent.Event) (fxLogEntry, bool) {
	switch e := event.(type) {
	case *fxevent.OnStartExecuting:
		return fxDebugEntry("on_start_executing", "start", e.FunctionName, ""), true
	case *fxevent.OnStartExecuted:
		return fxHookEntry("on_start_executed", "start", e.FunctionName, e.Err), true
	case *fxevent.OnStopExecuting:
		return fxDebugEntry("on_stop_executing", "stop", e.FunctionName, ""), true
	case *fxevent.OnStopExecuted:
		return fxHookEntry("on_stop_executed", "stop", e.FunctionName, e.Err), true
	case *fxevent.Invoking:
		return fxDebugEntry("invoking", "invoke", e.FunctionName, ""), true
	case *fxevent.Invoked:
		if e.Err == nil {
			return fxLogEntry{}, false
		}

		return fxErrorEntry("invoked", "invoke", e.FunctionName, "", e.Err, fxLogReasonConfig), true
	default:
		return fxLogEntry{}, false
	}
}

// fxDependencyEntry maps dependency graph events into log entries.
func fxDependencyEntry(event fxevent.Event) (fxLogEntry, bool) {
	switch e := event.(type) {
	case *fxevent.Supplied:
		return fxOptionEntry("supplied", "supply", e.TypeName, e.Err), true
	case *fxevent.Provided:
		return fxOptionEntry("provided", "provide", e.ConstructorName, e.Err), true
	case *fxevent.Replaced:
		return fxOptionEntry("replaced", "replace", firstString(e.OutputTypeNames), e.Err), true
	case *fxevent.Decorated:
		return fxOptionEntry("decorated", "decorate", e.DecoratorName, e.Err), true
	case *fxevent.BeforeRun:
		return fxDebugEntry("before_run", e.Kind, e.Name, ""), true
	case *fxevent.Run:
		return fxRunEntry(e), true
	default:
		return fxLogEntry{}, false
	}
}

// fxApplicationEntry maps application lifecycle events into log entries.
func fxApplicationEntry(event fxevent.Event) (fxLogEntry, bool) {
	switch e := event.(type) {
	case *fxevent.Stopping:
		return fxInfoEntry("stopping", "stop", "", fxLogReasonLifecycle), true
	case *fxevent.Stopped:
		return fxTerminalEntry("stopped", "stop", e.Err), true
	case *fxevent.RollingBack:
		return fxErrorEntry("rolling_back", "rollback", "", "", e.StartErr, fxLogReasonLifecycle), true
	case *fxevent.RolledBack:
		return fxTerminalEntry("rolled_back", "rollback", e.Err), true
	case *fxevent.Started:
		return fxTerminalEntry("started", "start", e.Err), true
	case *fxevent.LoggerInitialized:
		return fxHookEntry("logger_initialized", "logger", e.ConstructorName, e.Err), true
	default:
		return fxLogEntry{}, false
	}
}

// fxLogLevel normalizes configured log levels into the supported threshold set.
func fxLogLevel(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "trace", fxLogLevelDebug:
		return fxLogLevelDebug
	case "", fxLogLevelInfo:
		return fxLogLevelInfo
	case "warning", fxLogLevelWarn:
		return fxLogLevelWarn
	case fxLogLevelError, "fatal", "panic":
		return fxLogLevelError
	case "disabled", "none", fxLogLevelOff:
		return fxLogLevelOff
	default:
		return fxLogLevelInfo
	}
}

// fxDebugEntry creates a debug-level structural Fx event.
func fxDebugEntry(event string, operation string, function string, typeName string) fxLogEntry {
	return fxLogEntry{
		level:       fxLogLevelDebug,
		event:       event,
		operation:   operation,
		result:      fxLogResultOK,
		reasonClass: fxLogResultOK,
		function:    function,
		typeName:    typeName,
	}
}

// fxInfoEntry creates an info-level lifecycle Fx event.
func fxInfoEntry(event string, operation string, function string, reasonClass string) fxLogEntry {
	if reasonClass == "" {
		reasonClass = fxLogResultOK
	}

	return fxLogEntry{
		level:       fxLogLevelInfo,
		event:       event,
		operation:   operation,
		result:      fxLogResultOK,
		reasonClass: reasonClass,
		function:    function,
	}
}

// fxErrorEntry creates an error-level Fx event without preserving raw error text.
func fxErrorEntry(event string, operation string, function string, typeName string, err error, reasonClass string) fxLogEntry {
	if reasonClass == "" {
		reasonClass = fxLogReasonUnavailable
	}

	return fxLogEntry{
		level:       fxLogLevelError,
		event:       event,
		operation:   operation,
		result:      fxLogResultFailure,
		reasonClass: reasonClass,
		function:    function,
		typeName:    typeName,
		err:         err,
	}
}

// fxHookEntry maps hook completion into debug or error severity.
func fxHookEntry(event string, operation string, function string, err error) fxLogEntry {
	if err != nil {
		return fxErrorEntry(event, operation, function, "", err, fxLogReasonLifecycle)
	}

	return fxDebugEntry(event, operation, function, "")
}

// fxOptionEntry maps dependency option events into debug or error severity.
func fxOptionEntry(event string, operation string, name string, err error) fxLogEntry {
	if err != nil {
		return fxErrorEntry(event, operation, name, "", err, fxLogReasonConfig)
	}

	return fxDebugEntry(event, operation, name, "")
}

// fxRunEntry maps constructor execution events into debug or error severity.
func fxRunEntry(event *fxevent.Run) fxLogEntry {
	if event.Err != nil {
		return fxErrorEntry("run", event.Kind, event.Name, "", event.Err, fxLogReasonConfig)
	}

	return fxDebugEntry("run", event.Kind, event.Name, "")
}

// fxTerminalEntry maps application-level outcomes into info or error severity.
func fxTerminalEntry(event string, operation string, err error) fxLogEntry {
	if err != nil {
		return fxErrorEntry(event, operation, "", "", err, fxLogReasonLifecycle)
	}

	return fxInfoEntry(event, operation, "", fxLogReasonLifecycle)
}

// firstString returns the first value from Fx output type details.
func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}

	return values[0]
}
