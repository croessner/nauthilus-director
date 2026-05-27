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
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/config"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
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
	otelAttributeProcessComp  = "process.component"
	otelAttributeServiceName  = "service.name"
	otelAttributeServiceVer   = "service.version"
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

type traceRuntimeOptions struct {
	component string
	version   string
}

// TraceSpan is the domain-safe handle for an active OpenTelemetry span.
type TraceSpan interface {
	SetAttributes(fields map[string]string)
	End(result string, reasonClass string)
}

type traceSpanStarter interface {
	StartTraceSpan(ctx context.Context, boundary TraceBoundary, fields map[string]string) (context.Context, TraceSpan)
}

// StartSpan starts a prepared span through the supplied recorder when possible.
func StartSpan(ctx context.Context, recorder Recorder, boundary TraceBoundary, fields map[string]string) (context.Context, TraceSpan) {
	if ctx == nil {
		ctx = context.Background()
	}

	if starter, ok := NormalizeRecorder(recorder).(traceSpanStarter); ok {
		return starter.StartTraceSpan(ctx, boundary, fields)
	}

	return ctx, noopTraceSpan{}
}

// newTraceRuntime builds either a no-op provider or the configured OTLP provider.
func newTraceRuntime(
	ctx context.Context,
	cfg config.TracingConfig,
	factory TraceExporterFactory,
	reportFailure func(context.Context, string, error),
	options traceRuntimeOptions,
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

	provider, err := newSDKTracerProvider(ctx, cfg, reportingExporter, options)
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

	attrs := TraceAttributesForEvent(event)

	active := oteltrace.SpanFromContext(ctx)
	if active.SpanContext().IsValid() {
		active.AddEvent(event.Name, oteltrace.WithAttributes(attrs...))
		applySpanOutcome(active, eventResult(event), eventReasonClass(event))

		return nil
	}

	_, span := t.tracer.Start(ctx, event.SpanName, oteltrace.WithAttributes(attrs...))
	applySpanOutcome(span, eventResult(event), eventReasonClass(event))
	span.End()

	return nil
}

// StartTraceSpan starts an active span for one prepared boundary.
func (t *traceRuntime) StartTraceSpan(ctx context.Context, boundary TraceBoundary, fields map[string]string) (context.Context, TraceSpan) {
	if t == nil || !t.enabled {
		return ctx, noopTraceSpan{}
	}

	name, ok := SpanName(boundary)
	if !ok {
		return ctx, noopTraceSpan{}
	}

	child, span := t.tracer.Start(ctx, name, oteltrace.WithAttributes(NewTraceAttributes(fields)...))

	return child, runtimeTraceSpan{span: span}
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
func newSDKTracerProvider(
	ctx context.Context,
	cfg config.TracingConfig,
	exporter sdktrace.SpanExporter,
	options traceRuntimeOptions,
) (*sdktrace.TracerProvider, error) {
	attrs := []attribute.KeyValue{attribute.String(otelAttributeServiceName, cfg.ServiceName)}
	if component := strings.TrimSpace(options.component); component != "" {
		attrs = append(attrs, attribute.String(otelAttributeProcessComp, component))
	}

	if version := strings.TrimSpace(options.version); version != "" {
		attrs = append(attrs, attribute.String(otelAttributeServiceVer, version))
	}

	resources, err := resource.New(ctx, resource.WithAttributes(attrs...))
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

type runtimeTraceSpan struct {
	span oteltrace.Span
}

// SetAttributes adds policy-checked diagnostic attributes to the active span.
func (s runtimeTraceSpan) SetAttributes(fields map[string]string) {
	if s.span == nil {
		return
	}

	s.span.SetAttributes(NewTraceAttributes(fields)...)
}

// End records bounded outcome fields and closes the active span.
func (s runtimeTraceSpan) End(result string, reasonClass string) {
	if s.span == nil {
		return
	}

	applySpanOutcome(s.span, result, reasonClass)
	s.span.End()
}

type noopTraceSpan struct{}

// SetAttributes ignores attributes for disabled or unavailable tracing.
func (noopTraceSpan) SetAttributes(map[string]string) {}

// End closes a disabled or unavailable span handle.
func (noopTraceSpan) End(string, string) {}

// applySpanOutcome records span status without raw error text.
func applySpanOutcome(span oteltrace.Span, result string, reasonClass string) {
	if span == nil {
		return
	}

	result = strings.TrimSpace(result)
	if result == "" {
		result = reasonClassOK
	}

	result = normalizeTraceResult(result)

	if strings.TrimSpace(reasonClass) == "" && result == reasonClassOK {
		reasonClass = reasonClassOK
	}

	reasonClass = NormalizeReasonClass(reasonClass)
	span.SetAttributes(
		attribute.String(metricLabelResult, result),
		attribute.String(metricLabelReasonClass, reasonClass),
	)

	if traceResultIsError(result) {
		span.SetStatus(codes.Error, reasonClass)

		return
	}

	span.SetStatus(codes.Ok, "")
}

// traceResultIsError maps bounded result values to OpenTelemetry status.
func traceResultIsError(result string) bool {
	normalized, ok := normalizedReasonToken(strings.ToLower(strings.TrimSpace(result)))
	if !ok {
		return false
	}

	switch normalized {
	case "failure", "fail_closed", reasonClassTemporaryFailure:
		return true
	default:
		return false
	}
}

// eventResult extracts the bounded result from event metadata.
func eventResult(event Event) string {
	if value := strings.TrimSpace(event.MetricLabels[metricLabelResult]); value != "" {
		return value
	}

	return strings.TrimSpace(event.LogFields[metricLabelResult])
}

// eventReasonClass extracts the bounded reason class from event metadata.
func eventReasonClass(event Event) string {
	if value := strings.TrimSpace(event.MetricLabels[metricLabelReasonClass]); value != "" {
		return value
	}

	return strings.TrimSpace(event.LogFields[metricLabelReasonClass])
}
