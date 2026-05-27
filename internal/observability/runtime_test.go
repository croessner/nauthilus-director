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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/croessner/nauthilus-director/internal/config"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
)

const (
	testObservabilitySampleRatioPath = "observability.tracing.sample_ratio"
	testRESTOperationGetVersion      = "GetVersion"
)

// TestRuntimeConstructionSucceedsForDefaultConfig verifies canonical defaults build sinks.
func TestRuntimeConstructionSucceedsForDefaultConfig(t *testing.T) {
	factory := &recordingTraceExporterFactory{}

	runtime, err := NewRuntime(
		config.DefaultConfig().Observability,
		WithLogWriter(io.Discard),
		WithTraceExporterFactory(factory),
	)
	if err != nil {
		t.Fatalf("NewRuntime returned error: %v", err)
	}

	defer func() {
		if err := runtime.Shutdown(context.Background()); err != nil {
			t.Fatalf("shutdown runtime: %v", err)
		}
	}()

	if !runtime.MetricsEnabled() {
		t.Fatal("default runtime did not enable metrics")
	}

	if !runtime.TracingEnabled() {
		t.Fatal("default runtime did not enable tracing")
	}

	if factory.calls.Load() != 1 {
		t.Fatalf("trace exporter factory calls = %d, want 1", factory.calls.Load())
	}
}

// TestRuntimeConstructionRejectsInvalidObservabilityConfig checks local fail-closed validation.
func TestRuntimeConstructionRejectsInvalidObservabilityConfig(t *testing.T) {
	tests := map[string]struct {
		mutate func(*config.ObservabilityConfig)
		want   string
	}{
		"unknown_exporter": {
			mutate: func(cfg *config.ObservabilityConfig) { cfg.Tracing.Exporter = "zipkin" },
			want:   "observability.tracing.exporter",
		},
		"sample_below": {
			mutate: func(cfg *config.ObservabilityConfig) { cfg.Tracing.SampleRatio = -0.01 },
			want:   testObservabilitySampleRatioPath,
		},
		"sample_above": {
			mutate: func(cfg *config.ObservabilityConfig) { cfg.Tracing.SampleRatio = 1.01 },
			want:   testObservabilitySampleRatioPath,
		},
		"metrics_path": {
			mutate: func(cfg *config.ObservabilityConfig) { cfg.Metrics.Path = "/custom" },
			want:   "observability.metrics.path",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := config.DefaultConfig().Observability
			test.mutate(&cfg)

			_, err := NewRuntime(cfg, WithLogWriter(io.Discard), WithTraceExporterFactory(&recordingTraceExporterFactory{}))
			if err == nil {
				t.Fatal("NewRuntime accepted invalid observability config")
			}

			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %q, want %q", err.Error(), test.want)
			}
		})
	}
}

// TestDisabledMetricsProviderOmitsBusinessMetrics verifies disabled metrics have no stale event series.
func TestDisabledMetricsProviderOmitsBusinessMetrics(t *testing.T) {
	cfg := config.DefaultConfig().Observability
	cfg.Metrics.Enabled = false
	cfg.Tracing.Enabled = false

	runtime, err := NewRuntime(cfg, WithLogWriter(io.Discard))
	if err != nil {
		t.Fatalf("NewRuntime returned error: %v", err)
	}

	event, err := NewEvent(EventRouteLookup, TraceBoundaryRoutingResolve, nil, map[string]string{
		metricLabelOperation: "lookup",
		metricLabelResult:    reasonClassOK,
	})
	if err != nil {
		t.Fatalf("NewEvent returned error: %v", err)
	}

	runtime.Recorder().Record(context.Background(), event)

	metrics, err := runtime.MetricsProvider().Metrics(context.Background())
	if err != nil {
		t.Fatalf("Metrics returned error: %v", err)
	}

	if !strings.Contains(metrics, "nauthilus_director_metrics_enabled 0") {
		t.Fatalf("metrics did not report disabled state:\n%s", metrics)
	}

	if strings.Contains(metrics, metricNameEventsTotal) {
		t.Fatalf("disabled metrics exposed event counter:\n%s", metrics)
	}
}

// TestDisabledTracingAvoidsExporterConstruction verifies no OTLP work happens when disabled.
func TestDisabledTracingAvoidsExporterConstruction(t *testing.T) {
	cfg := config.DefaultConfig().Observability
	cfg.Tracing.Enabled = false
	factory := &recordingTraceExporterFactory{}

	runtime, err := NewRuntime(cfg, WithLogWriter(io.Discard), WithTraceExporterFactory(factory))
	if err != nil {
		t.Fatalf("NewRuntime returned error: %v", err)
	}

	if runtime.TracingEnabled() {
		t.Fatal("disabled tracing reported enabled")
	}

	if factory.calls.Load() != 0 {
		t.Fatalf("trace exporter factory calls = %d, want 0", factory.calls.Load())
	}
}

// TestTracingUsesParentBasedRatioSampling verifies sampled parents override a zero ratio.
func TestTracingUsesParentBasedRatioSampling(t *testing.T) {
	cfg := config.DefaultConfig().Observability
	cfg.Metrics.Enabled = false
	cfg.Tracing.SampleRatio = 0

	unsampledExporter := &recordingSpanExporter{}

	unsampledRuntime, err := NewRuntime(cfg, WithLogWriter(io.Discard), WithTraceExporterFactory(&recordingTraceExporterFactory{exporter: unsampledExporter}))
	if err != nil {
		t.Fatalf("NewRuntime returned error: %v", err)
	}

	ctx, span := StartSpan(context.Background(), unsampledRuntime.Recorder(), TraceBoundarySession, nil)
	unsampledRuntime.Recorder().Record(ctx, Event{Name: EventSessionStart, SpanName: traceSpanSession})
	span.End(reasonClassOK, reasonClassOK)

	if err := unsampledRuntime.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown unsampled runtime: %v", err)
	}

	if unsampledExporter.spanCount() != 0 {
		t.Fatalf("unsampled root spans = %d, want 0", unsampledExporter.spanCount())
	}

	sampledExporter := &recordingSpanExporter{}

	sampledRuntime, err := NewRuntime(cfg, WithLogWriter(io.Discard), WithTraceExporterFactory(&recordingTraceExporterFactory{exporter: sampledExporter}))
	if err != nil {
		t.Fatalf("sampled NewRuntime returned error: %v", err)
	}

	parentCtx := oteltrace.ContextWithRemoteSpanContext(context.Background(), oteltrace.NewSpanContext(oteltrace.SpanContextConfig{
		TraceID:    oteltrace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		SpanID:     oteltrace.SpanID{1, 2, 3, 4, 5, 6, 7, 8},
		TraceFlags: oteltrace.FlagsSampled,
		Remote:     true,
	}))
	ctx, span = StartSpan(parentCtx, sampledRuntime.Recorder(), TraceBoundarySession, nil)
	sampledRuntime.Recorder().Record(ctx, Event{Name: EventSessionStart, SpanName: traceSpanSession})
	span.End(reasonClassOK, reasonClassOK)

	if err := sampledRuntime.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown sampled runtime: %v", err)
	}

	if sampledExporter.spanCount() == 0 {
		t.Fatal("sampled parent did not produce an exported child span")
	}
}

// TestStructuredLogsIncludeTraceCorrelation verifies active span IDs reach logs.
func TestStructuredLogsIncludeTraceCorrelation(t *testing.T) {
	var output bytes.Buffer

	cfg := config.DefaultConfig().Observability
	cfg.Metrics.Enabled = false
	cfg.Tracing.SampleRatio = 1

	runtime, err := NewRuntime(cfg, WithLogWriter(&output), WithTraceExporterFactory(&recordingTraceExporterFactory{}))
	if err != nil {
		t.Fatalf("NewRuntime returned error: %v", err)
	}

	ctx, span := StartSpan(context.Background(), runtime.Recorder(), TraceBoundaryRESTRequest, map[string]string{
		metricLabelOperation: testRESTOperationGetVersion,
	})
	runtime.Recorder().Record(ctx, Event{
		Name:     EventRESTRequest,
		SpanName: traceSpanRESTRequest,
		LogFields: LogFields{
			metricLabelOperation: testRESTOperationGetVersion,
			metricLabelResult:    reasonClassOK,
		},
	})
	span.End(reasonClassOK, reasonClassOK)

	if err := runtime.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown runtime: %v", err)
	}

	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("decode structured log: %v\n%s", err, output.String())
	}

	if record[fieldTraceID] == "" {
		t.Fatalf("trace_id missing from log record: %#v", record)
	}

	if record[fieldSpanID] == "" {
		t.Fatalf("span_id missing from log record: %#v", record)
	}
}

// TestShutdownFlushIsIdempotent verifies repeated shutdown does not repeat exporter close.
func TestShutdownFlushIsIdempotent(t *testing.T) {
	cfg := config.DefaultConfig().Observability
	cfg.Metrics.Enabled = false
	cfg.Tracing.SampleRatio = 1
	exporter := &recordingSpanExporter{}
	factory := &recordingTraceExporterFactory{exporter: exporter}

	runtime, err := NewRuntime(cfg, WithLogWriter(io.Discard), WithTraceExporterFactory(factory))
	if err != nil {
		t.Fatalf("NewRuntime returned error: %v", err)
	}

	runtime.Recorder().Record(context.Background(), Event{Name: EventRoutingResolve, SpanName: traceSpanRoutingResolve})

	if err := runtime.Shutdown(context.Background()); err != nil {
		t.Fatalf("first shutdown returned error: %v", err)
	}

	if err := runtime.Shutdown(context.Background()); err != nil {
		t.Fatalf("second shutdown returned error: %v", err)
	}

	if exporter.shutdowns.Load() != 1 {
		t.Fatalf("exporter shutdowns = %d, want 1", exporter.shutdowns.Load())
	}
}

// TestMultipleRuntimeInstancesUseIsolatedRegistries protects tests from global collectors.
func TestMultipleRuntimeInstancesUseIsolatedRegistries(t *testing.T) {
	cfg := config.DefaultConfig().Observability
	cfg.Metrics.RuntimeMetrics = false
	cfg.Tracing.Enabled = false

	first, err := NewRuntime(cfg, WithLogWriter(io.Discard))
	if err != nil {
		t.Fatalf("first NewRuntime returned error: %v", err)
	}

	second, err := NewRuntime(cfg, WithLogWriter(io.Discard))
	if err != nil {
		t.Fatalf("second NewRuntime returned error: %v", err)
	}

	first.Recorder().Record(context.Background(), Event{Name: EventReload})
	second.Recorder().Record(context.Background(), Event{Name: EventRouteLookup})

	firstMetrics, err := first.MetricsProvider().Metrics(context.Background())
	if err != nil {
		t.Fatalf("first metrics returned error: %v", err)
	}

	secondMetrics, err := second.MetricsProvider().Metrics(context.Background())
	if err != nil {
		t.Fatalf("second metrics returned error: %v", err)
	}

	if !strings.Contains(firstMetrics, metricNameEventsTotal) {
		t.Fatalf("first metrics missing event counter:\n%s", firstMetrics)
	}

	if !strings.Contains(secondMetrics, metricNameEventsTotal) {
		t.Fatalf("second metrics missing event counter:\n%s", secondMetrics)
	}
}

type recordingTraceExporterFactory struct {
	calls    atomic.Int64
	exporter *recordingSpanExporter
}

// NewTraceExporter records factory use and returns a deterministic exporter.
func (f *recordingTraceExporterFactory) NewTraceExporter(context.Context, config.TracingConfig) (sdktrace.SpanExporter, error) {
	f.calls.Add(1)

	if f.exporter != nil {
		return f.exporter, nil
	}

	return &recordingSpanExporter{}, nil
}

type recordingSpanExporter struct {
	exports   atomic.Int64
	shutdowns atomic.Int64

	mu    sync.Mutex
	spans []recordedSpan
}

// ExportSpans records exported span count without remote collector access.
func (e *recordingSpanExporter) ExportSpans(_ context.Context, spans []sdktrace.ReadOnlySpan) error {
	e.exports.Add(int64(len(spans)))
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, span := range spans {
		attrs := make(map[string]string, len(span.Attributes()))
		for _, attr := range span.Attributes() {
			attrs[string(attr.Key)] = attr.Value.AsString()
		}

		e.spans = append(e.spans, recordedSpan{
			name:       span.Name(),
			attributes: attrs,
		})
	}

	return nil
}

// Shutdown records exporter shutdown calls.
func (e *recordingSpanExporter) Shutdown(context.Context) error {
	e.shutdowns.Add(1)

	return nil
}

// spanCount returns the number of copied exported spans.
func (e *recordingSpanExporter) spanCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()

	return len(e.spans)
}

type recordedSpan struct {
	name       string
	attributes map[string]string
}
