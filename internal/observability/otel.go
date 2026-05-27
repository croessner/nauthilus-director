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
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/config"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

const (
	defaultTraceExportTimeout = 2 * time.Second
	defaultTraceBatchTimeout  = time.Second
	tracerInstrumentationName = "github.com/croessner/nauthilus-director/internal/observability"
	otelAttributeEventName    = "event.name"
	otelAttributeServiceName  = "service.name"
)

// TraceExporterFactory constructs the configured OpenTelemetry span exporter.
type TraceExporterFactory interface {
	NewTraceExporter(ctx context.Context, cfg config.TracingConfig) (sdktrace.SpanExporter, error)
}

// TraceExporterFactoryFunc adapts a function into a trace exporter factory.
type TraceExporterFactoryFunc func(context.Context, config.TracingConfig) (sdktrace.SpanExporter, error)

// NewTraceExporter calls the wrapped exporter factory function.
func (f TraceExporterFactoryFunc) NewTraceExporter(ctx context.Context, cfg config.TracingConfig) (sdktrace.SpanExporter, error) {
	if f == nil {
		return nil, fmt.Errorf("trace exporter factory is nil")
	}

	return f(ctx, cfg)
}

// traceRuntime owns a tracer provider and optional exporter shutdown.
type traceRuntime struct {
	enabled       bool
	provider      oteltrace.TracerProvider
	forceFlush    func(context.Context) error
	shutdown      func(context.Context) error
	tracer        oteltrace.Tracer
	reportFailure func(context.Context, string, error)
}

// newTraceRuntime builds either a no-op provider or the configured OTLP provider.
func newTraceRuntime(
	ctx context.Context,
	cfg config.TracingConfig,
	factory TraceExporterFactory,
	reportFailure func(context.Context, string, error),
) (*traceRuntime, error) {
	if !cfg.Enabled {
		provider := noop.NewTracerProvider()

		return &traceRuntime{provider: provider, tracer: provider.Tracer(tracerInstrumentationName)}, nil
	}

	exporter, err := factory.NewTraceExporter(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create OTLP trace exporter: %w", err)
	}

	if exporter == nil {
		return nil, fmt.Errorf("create OTLP trace exporter: exporter is nil")
	}

	reportingExporter := reportingSpanExporter{
		next:          exporter,
		reportFailure: reportFailure,
	}

	provider, err := newSDKTracerProvider(ctx, cfg, reportingExporter)
	if err != nil {
		_ = exporter.Shutdown(ctx)

		return nil, err
	}

	return &traceRuntime{
		enabled:       true,
		provider:      provider,
		forceFlush:    provider.ForceFlush,
		tracer:        provider.Tracer(tracerInstrumentationName),
		shutdown:      provider.Shutdown,
		reportFailure: reportFailure,
	}, nil
}

// Enabled reports whether the trace runtime exports spans.
func (t *traceRuntime) Enabled() bool {
	return t != nil && t.enabled
}

// TracerProvider returns the OpenTelemetry provider owned by this runtime.
func (t *traceRuntime) TracerProvider() oteltrace.TracerProvider {
	if t == nil || t.provider == nil {
		return noop.NewTracerProvider()
	}

	return t.provider
}

// Record starts and ends a minimal span for prepared event boundaries.
func (t *traceRuntime) Record(ctx context.Context, event Event) error {
	if t == nil || !t.enabled || strings.TrimSpace(event.SpanName) == "" {
		return nil
	}

	_, span := t.tracer.Start(ctx, event.SpanName)
	span.SetAttributes(traceAttributes(event)...)
	span.End()

	return nil
}

// Shutdown flushes the tracer provider and then stops exporter background work.
func (t *traceRuntime) Shutdown(ctx context.Context) {
	if t == nil || t.shutdown == nil {
		return
	}

	if t.forceFlush != nil {
		if err := t.forceFlush(ctx); err != nil && t.reportFailure != nil {
			t.reportFailure(ctx, "trace_flush", err)
		}
	}

	if err := t.shutdown(ctx); err != nil {
		if t.reportFailure != nil {
			t.reportFailure(ctx, "trace_shutdown", err)
		}

		return
	}
}

// newSDKTracerProvider creates an SDK provider with bounded batch/export timing.
func newSDKTracerProvider(ctx context.Context, cfg config.TracingConfig, exporter sdktrace.SpanExporter) (*sdktrace.TracerProvider, error) {
	resources, err := resource.New(ctx, resource.WithAttributes(attribute.String(otelAttributeServiceName, cfg.ServiceName)))
	if err != nil {
		return nil, fmt.Errorf("create trace resource: %w", err)
	}

	return sdktrace.NewTracerProvider(
		sdktrace.WithResource(resources),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.SampleRatio))),
		sdktrace.WithBatcher(
			exporter,
			sdktrace.WithBatchTimeout(defaultTraceBatchTimeout),
			sdktrace.WithExportTimeout(defaultTraceExportTimeout),
		),
	), nil
}

// traceAttributes converts normalized event metadata into safe span attributes.
func traceAttributes(event Event) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String(otelAttributeEventName, event.Name),
	}

	for _, name := range sortedMetricAttributeNames(event.MetricLabels) {
		attrs = append(attrs, attribute.String(name, event.MetricLabels[name]))
	}

	for _, name := range sortedLogFieldNames(event.LogFields) {
		attrs = append(attrs, attribute.String(name, event.LogFields[name]))
	}

	return attrs
}

// sortedMetricAttributeNames returns deterministic metric-label attributes.
func sortedMetricAttributeNames(labels MetricLabels) []string {
	names := make([]string, 0, len(labels))
	for name := range labels {
		names = append(names, name)
	}

	sort.Strings(names)

	return names
}

// otlpHTTPTraceExporterFactory constructs the OTLP HTTP trace exporter.
type otlpHTTPTraceExporterFactory struct{}

// NewTraceExporter creates an OTLP HTTP exporter without touching global telemetry.
func (otlpHTTPTraceExporterFactory) NewTraceExporter(ctx context.Context, cfg config.TracingConfig) (sdktrace.SpanExporter, error) {
	options := []otlptracehttp.Option{
		otlptracehttp.WithTimeout(defaultTraceExportTimeout),
		otlptracehttp.WithRetry(otlptracehttp.RetryConfig{Enabled: false}),
	}

	endpoint := strings.TrimSpace(cfg.Endpoint)
	if endpointURL(endpoint) {
		options = append(options, otlptracehttp.WithEndpointURL(endpoint))
	} else if endpoint != "" {
		options = append(options, otlptracehttp.WithEndpoint(endpoint))
	}

	return otlptracehttp.New(ctx, options...)
}

// endpointURL reports whether an endpoint carries an explicit URL scheme.
func endpointURL(endpoint string) bool {
	parsed, err := url.Parse(endpoint)

	return err == nil && parsed.Scheme != ""
}

// reportingSpanExporter records exporter failures without leaking raw error text.
type reportingSpanExporter struct {
	next          sdktrace.SpanExporter
	reportFailure func(context.Context, string, error)
}

// ExportSpans exports spans and reports non-fatal collector errors.
func (e reportingSpanExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	err := e.next.ExportSpans(ctx, spans)
	if err != nil && e.reportFailure != nil {
		e.reportFailure(ctx, "trace_export", err)
	}

	return err
}

// Shutdown stops the wrapped exporter and reports non-fatal shutdown errors.
func (e reportingSpanExporter) Shutdown(ctx context.Context) error {
	err := e.next.Shutdown(ctx)
	if err != nil && e.reportFailure != nil {
		e.reportFailure(ctx, "trace_shutdown", err)
	}

	return err
}
