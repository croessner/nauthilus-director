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
	"errors"
	"testing"

	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/observability"
	"go.uber.org/fx/fxevent"
)

const testFxFunctionStartListener = "startListener"

type recordingFxRecorder struct {
	events []observability.Event
}

// Record stores emitted Fx log events for assertions.
func (r *recordingFxRecorder) Record(_ context.Context, event observability.Event) {
	r.events = append(r.events, event)
}

// TestFxLoggerFiltersDebugEventsAtInfo verifies Fx wiring chatter stays below info logs.
func TestFxLoggerFiltersDebugEventsAtInfo(t *testing.T) {
	recorder := &recordingFxRecorder{}
	logger := newFxEventLogger(testRuntimeOptionsForFxLogLevel("info", recorder))

	logger.LogEvent(&fxevent.OnStartExecuting{FunctionName: testFxFunctionStartListener})
	logger.LogEvent(&fxevent.Started{})

	if len(recorder.events) != 1 {
		t.Fatalf("recorded Fx events = %d, want 1", len(recorder.events))
	}

	event := recorder.events[0]
	if event.Name != fxLogEventName {
		t.Fatalf("event name = %q, want %q", event.Name, fxLogEventName)
	}

	if event.LogFields[fxLogFieldLevel] != fxLogLevelInfo {
		t.Fatalf("event level = %q, want info", event.LogFields[fxLogFieldLevel])
	}

	if event.LogFields[fxLogFieldEvent] != "started" {
		t.Fatalf("event = %q, want started", event.LogFields[fxLogFieldEvent])
	}
}

// TestFxLoggerRecordsErrorsWithoutRawText verifies Fx failures stay observable and secret-safe.
func TestFxLoggerRecordsErrorsWithoutRawText(t *testing.T) {
	recorder := &recordingFxRecorder{}
	logger := newFxEventLogger(testRuntimeOptionsForFxLogLevel("info", recorder))

	logger.LogEvent(&fxevent.OnStartExecuted{FunctionName: testFxFunctionStartListener, Err: errors.New("password=secret")})

	if len(recorder.events) != 1 {
		t.Fatalf("recorded Fx events = %d, want 1", len(recorder.events))
	}

	fields := recorder.events[0].LogFields
	if fields[fxLogFieldLevel] != fxLogLevelError {
		t.Fatalf("event level = %q, want error", fields[fxLogFieldLevel])
	}

	if fields[fxLogFieldErrorPresent] != fxLogValueTrue {
		t.Fatalf("error_present = %q, want true", fields[fxLogFieldErrorPresent])
	}

	for name, value := range fields {
		if value == "password=secret" {
			t.Fatalf("field %q leaked raw error text", name)
		}
	}
}

// TestFxLoggerAllowsDebugEventsAtDebug verifies explicit debug logging includes Fx structure.
func TestFxLoggerAllowsDebugEventsAtDebug(t *testing.T) {
	recorder := &recordingFxRecorder{}
	logger := newFxEventLogger(testRuntimeOptionsForFxLogLevel("debug", recorder))

	logger.LogEvent(&fxevent.OnStartExecuting{FunctionName: testFxFunctionStartListener})

	if len(recorder.events) != 1 {
		t.Fatalf("recorded Fx events = %d, want 1", len(recorder.events))
	}

	if recorder.events[0].LogFields[fxLogFieldLevel] != fxLogLevelDebug {
		t.Fatalf("event level = %q, want debug", recorder.events[0].LogFields[fxLogFieldLevel])
	}
}

// testRuntimeOptionsForFxLogLevel prepares logger dependencies without starting Fx.
func testRuntimeOptionsForFxLogLevel(level string, recorder observability.Recorder) runtimeOptions {
	cfg := config.DefaultConfig()
	cfg.Observability.Log.Level = level

	return runtimeOptions{
		Snapshot: &config.Snapshot{Config: cfg},
		Recorder: recorder,
	}
}
