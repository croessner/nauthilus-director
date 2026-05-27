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
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/croessner/nauthilus-director/internal/config"
	oteltrace "go.opentelemetry.io/otel/trace"
)

const (
	defaultMetricsPath    = "/metrics"
	tracingExporterOTLP   = "otlp"
	tracingExporterNone   = "none"
	tracingExporterNoop   = "noop"
	tracingExporterOff    = "disabled"
	telemetryReasonClass  = "unavailable"
	telemetryResultFailed = "failure"
)

// Runtime owns the process-local observability sinks and their shutdown lifecycle.
type Runtime struct {
	logger   *structuredLogger
	metrics  *prometheusRuntime
	tracing  *traceRuntime
	recorder *sharedRecorder

	shutdownOnce sync.Once
}

// RuntimeOption changes observability runtime construction without changing config.
type RuntimeOption func(*runtimeOptions)

type runtimeOptions struct {
	logWriter            io.Writer
	traceExporterFactory TraceExporterFactory
	additionalRecorder   Recorder
}

// NewRuntime creates a cohesive observability runtime from typed config.
func NewRuntime(cfg config.ObservabilityConfig, opts ...RuntimeOption) (*Runtime, error) {
	if err := validateRuntimeConfig(cfg); err != nil {
		return nil, err
	}

	options := defaultRuntimeOptions()

	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}

	logger := newStructuredLogger(cfg.Log, options.logWriter)

	metrics, err := newPrometheusRuntime(cfg.Metrics)
	if err != nil {
		return nil, err
	}

	reporter := newTelemetryFailureReporter(logger, metrics)

	tracing, err := newTraceRuntime(context.Background(), cfg.Tracing, options.traceExporterFactory, reporter.Report)
	if err != nil {
		return nil, err
	}

	runtime := &Runtime{
		logger:  logger,
		metrics: metrics,
		tracing: tracing,
	}
	runtime.recorder = newSharedRecorder(sharedRecorderOptions{
		logger:             logger,
		metrics:            metrics,
		tracing:            tracing,
		additionalRecorder: options.additionalRecorder,
		reporter:           reporter,
	})

	return runtime, nil
}

// Recorder returns the single recorder that fans events into configured sinks.
func (r *Runtime) Recorder() Recorder {
	if r == nil || r.recorder == nil {
		return NoopRecorder{}
	}

	return r.recorder
}

// MetricsProvider returns the process-local Prometheus provider.
func (r *Runtime) MetricsProvider() MetricsProvider {
	if r == nil || r.metrics == nil {
		return disabledMetricsProvider{}
	}

	return r.metrics
}

// TracerProvider returns the runtime-owned OpenTelemetry tracer provider.
func (r *Runtime) TracerProvider() oteltrace.TracerProvider {
	if r == nil || r.tracing == nil {
		return nil
	}

	return r.tracing.TracerProvider()
}

// MetricsEnabled reports whether business metrics are registered.
func (r *Runtime) MetricsEnabled() bool {
	return r != nil && r.metrics != nil && r.metrics.Enabled()
}

// TracingEnabled reports whether trace export was configured.
func (r *Runtime) TracingEnabled() bool {
	return r != nil && r.tracing != nil && r.tracing.Enabled()
}

// Start marks the observability runtime ready before other lifecycle work starts.
func (r *Runtime) Start(context.Context) error {
	return nil
}

// Shutdown flushes and stops telemetry sinks once; exporter failures stay non-fatal.
func (r *Runtime) Shutdown(ctx context.Context) error {
	if r == nil {
		return nil
	}

	r.shutdownOnce.Do(func() {
		if ctx == nil {
			ctx = context.Background()
		}

		if r.tracing != nil {
			r.tracing.Shutdown(ctx)
		}
	})

	return nil
}

// WithLogWriter directs structured logs to a caller-owned writer.
func WithLogWriter(writer io.Writer) RuntimeOption {
	return func(options *runtimeOptions) {
		if writer != nil {
			options.logWriter = writer
		}
	}
}

// WithTraceExporterFactory injects an exporter constructor for deterministic tests.
func WithTraceExporterFactory(factory TraceExporterFactory) RuntimeOption {
	return func(options *runtimeOptions) {
		if factory != nil {
			options.traceExporterFactory = factory
		}
	}
}

// WithAdditionalRecorder adds a secondary recorder sink while keeping one Fx recorder.
func WithAdditionalRecorder(recorder Recorder) RuntimeOption {
	return func(options *runtimeOptions) {
		options.additionalRecorder = recorder
	}
}

// defaultRuntimeOptions returns production sink defaults.
func defaultRuntimeOptions() runtimeOptions {
	return runtimeOptions{
		logWriter:            os.Stderr,
		traceExporterFactory: otlpHTTPTraceExporterFactory{},
	}
}

// validateRuntimeConfig rejects impossible local observability settings.
func validateRuntimeConfig(cfg config.ObservabilityConfig) error {
	if strings.TrimSpace(cfg.Metrics.Path) != defaultMetricsPath {
		return fmt.Errorf("observability.metrics.path must be %q", defaultMetricsPath)
	}

	if cfg.Tracing.SampleRatio < 0 || cfg.Tracing.SampleRatio > 1 {
		return fmt.Errorf("observability.tracing.sample_ratio must be between 0.0 and 1.0")
	}

	exporter := normalizeTracingExporter(cfg.Tracing.Exporter)
	switch exporter {
	case tracingExporterOTLP:
		if cfg.Tracing.Enabled && strings.TrimSpace(cfg.Tracing.Endpoint) == "" {
			return fmt.Errorf("observability.tracing.endpoint is required when tracing is enabled")
		}
	case "", tracingExporterNone, tracingExporterNoop, tracingExporterOff:
		if cfg.Tracing.Enabled {
			return fmt.Errorf("observability.tracing.exporter must be %q when tracing is enabled", tracingExporterOTLP)
		}
	default:
		return fmt.Errorf("observability.tracing.exporter %q is not supported", cfg.Tracing.Exporter)
	}

	if cfg.Tracing.Enabled && strings.TrimSpace(cfg.Tracing.ServiceName) == "" {
		return fmt.Errorf("observability.tracing.service_name is required when tracing is enabled")
	}

	return nil
}

// normalizeTracingExporter canonicalizes supported exporter tokens.
func normalizeTracingExporter(exporter string) string {
	return strings.ToLower(strings.TrimSpace(exporter))
}
