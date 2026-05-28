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
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/observability"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
)

const testFxFunctionStartListener = "startListener"

type recordingFxRecorder struct {
	events []observability.Event
}

type fakeBackendCapabilityReader struct {
	allowed bool
	err     error
}

// Record stores emitted Fx log events for assertions.
func (r *recordingFxRecorder) Record(_ context.Context, event observability.Event) {
	r.events = append(r.events, event)
}

// PoolSupportsCapability returns the configured fake capability decision.
func (r fakeBackendCapabilityReader) PoolSupportsCapability(context.Context, string, string) (bool, error) {
	return r.allowed, r.err
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

// TestLMTPBackendChunkingAllowedFailsClosed verifies app wiring suppresses unsafe BDAT.
func TestLMTPBackendChunkingAllowedFailsClosed(t *testing.T) {
	if lmtpBackendChunkingAllowed(nil, "lmtp-default") {
		t.Fatal("nil capability reader allowed CHUNKING")
	}

	if lmtpBackendChunkingAllowed(fakeBackendCapabilityReader{err: errors.New("redis unavailable")}, "lmtp-default") {
		t.Fatal("capability reader error allowed CHUNKING")
	}

	if !lmtpBackendChunkingAllowed(fakeBackendCapabilityReader{allowed: true}, "lmtp-default") {
		t.Fatal("fresh backend capability proof did not allow CHUNKING")
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

// TestFxLoggerUsesSharedRuntimeRedaction verifies Fx failures pass through the runtime recorder.
func TestFxLoggerUsesSharedRuntimeRedaction(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Observability.Log.Level = fxLogLevelDebug
	cfg.Observability.Metrics.Enabled = false
	cfg.Observability.Tracing.Enabled = false

	var output bytes.Buffer

	runtime, err := observability.NewRuntime(cfg.Observability, observability.WithLogWriter(&output))
	if err != nil {
		t.Fatalf("NewRuntime returned error: %v", err)
	}

	logger := newFxEventLogger(runtimeOptions{
		Snapshot: &config.Snapshot{Config: cfg},
		Recorder: runtime.Recorder(),
	})
	logger.LogEvent(&fxevent.OnStartExecuted{FunctionName: testFxFunctionStartListener, Err: errors.New("token=fx-secret")})

	if strings.Contains(output.String(), "fx-secret") {
		t.Fatalf("Fx log leaked raw error text:\n%s", output.String())
	}

	if !strings.Contains(output.String(), "error_present") {
		t.Fatalf("Fx log did not preserve error presence:\n%s", output.String())
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

// TestFxRecorderProviderUsesRuntimeRecorder verifies Fx receives the shared runtime recorder.
func TestFxRecorderProviderUsesRuntimeRecorder(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Observability.Tracing.Enabled = false

	runtime, err := observability.NewRuntime(cfg.Observability, observability.WithLogWriter(io.Discard))
	if err != nil {
		t.Fatalf("NewRuntime returned error: %v", err)
	}

	var recorder observability.Recorder

	app := fx.New(
		fx.NopLogger,
		fx.Supply(runtime),
		fx.Provide(provideRecorder),
		fx.Populate(&recorder),
	)
	if err := app.Err(); err != nil {
		t.Fatalf("fx app error: %v", err)
	}

	if recorder != runtime.Recorder() {
		t.Fatal("Fx recorder provider did not return the runtime-owned recorder")
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
