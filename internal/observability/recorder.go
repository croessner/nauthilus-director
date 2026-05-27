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
	"sync"
)

const (
	telemetryFieldComponent    = "component"
	telemetryFieldErrorPresent = "error_present"
	telemetryFieldLevel        = "level"
	telemetryFieldOperation    = "operation"
	telemetryFieldReasonClass  = "reason_class"
	telemetryFieldResult       = "result"
	telemetryFieldSink         = "sink"
	telemetryValueComponent    = "observability"
	telemetryValueTrue         = "true"
)

// EventObservabilitySinkError records a bounded non-fatal telemetry sink failure.
const EventObservabilitySinkError = "observability.sink_error"

type sharedRecorderOptions struct {
	logger             *structuredLogger
	metrics            *prometheusRuntime
	tracing            *traceRuntime
	additionalRecorder Recorder
	reporter           *telemetryFailureReporter
}

// sharedRecorder fans one normalized event into the configured runtime sinks.
type sharedRecorder struct {
	logger             *structuredLogger
	metrics            *prometheusRuntime
	tracing            *traceRuntime
	additionalRecorder Recorder
	reporter           *telemetryFailureReporter
}

// newSharedRecorder creates the single recorder supplied through Fx.
func newSharedRecorder(options sharedRecorderOptions) *sharedRecorder {
	return &sharedRecorder{
		logger:             options.logger,
		metrics:            options.metrics,
		tracing:            options.tracing,
		additionalRecorder: NormalizeRecorder(options.additionalRecorder),
		reporter:           options.reporter,
	}
}

// Record fans one normalized event into logging, metrics, tracing and test sinks.
func (r *sharedRecorder) Record(ctx context.Context, event Event) {
	if r == nil {
		return
	}

	event = normalizeRecordedEvent(event)
	if event.Name == "" {
		return
	}

	if err := r.recordMetrics(ctx, event); err != nil {
		r.report(ctx, "metrics_record", err)
	}

	if err := r.recordTrace(ctx, event); err != nil {
		r.report(ctx, "trace_record", err)
	}

	if err := r.recordLog(ctx, event); err != nil {
		r.report(ctx, "log_record", err)
	}

	if r.additionalRecorder != nil {
		r.additionalRecorder.Record(ctx, event)
	}
}

// recordMetrics sends an event to the metrics sink when enabled.
func (r *sharedRecorder) recordMetrics(ctx context.Context, event Event) error {
	if r.metrics == nil {
		return nil
	}

	return r.metrics.Record(ctx, event)
}

// recordTrace sends an event to the tracing sink when enabled.
func (r *sharedRecorder) recordTrace(ctx context.Context, event Event) error {
	if r.tracing == nil {
		return nil
	}

	return r.tracing.Record(ctx, event)
}

// recordLog sends an event to the structured logger sink.
func (r *sharedRecorder) recordLog(ctx context.Context, event Event) error {
	if r.logger == nil {
		return nil
	}

	return r.logger.Record(ctx, event)
}

// report records a telemetry sink failure without exposing raw error text.
func (r *sharedRecorder) report(ctx context.Context, operation string, err error) {
	if r.reporter != nil {
		r.reporter.Report(ctx, operation, err)
	}
}

// telemetryFailureReporter records sink failures once in logs and always in metrics.
type telemetryFailureReporter struct {
	logger  *structuredLogger
	metrics *prometheusRuntime

	mu     sync.Mutex
	logged map[string]struct{}
}

// newTelemetryFailureReporter creates the bounded failure reporter for sink outages.
func newTelemetryFailureReporter(logger *structuredLogger, metrics *prometheusRuntime) *telemetryFailureReporter {
	return &telemetryFailureReporter{
		logger:  logger,
		metrics: metrics,
		logged:  make(map[string]struct{}),
	}
}

// Report records one sink failure without making telemetry failures fatal.
func (r *telemetryFailureReporter) Report(ctx context.Context, operation string, err error) {
	if r == nil || err == nil {
		return
	}

	if r.metrics != nil {
		r.metrics.RecordSinkFailure(operation)
	}

	if !r.shouldLog(operation) || r.logger == nil {
		return
	}

	_ = r.logger.Record(ctx, Event{
		Name: EventObservabilitySinkError,
		LogFields: LogFields{
			telemetryFieldComponent:    telemetryValueComponent,
			telemetryFieldErrorPresent: telemetryValueTrue,
			telemetryFieldLevel:        logLevelWarn,
			telemetryFieldOperation:    operation,
			telemetryFieldReasonClass:  telemetryReasonClass,
			telemetryFieldResult:       telemetryResultFailed,
			telemetryFieldSink:         operation,
		},
	})
}

// shouldLog reports the first failure for each sink operation.
func (r *telemetryFailureReporter) shouldLog(operation string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.logged[operation]; ok {
		return false
	}

	r.logged[operation] = struct{}{}

	return true
}

// normalizeRecordedEvent ensures sinks receive non-nil normalized event maps.
func normalizeRecordedEvent(event Event) Event {
	if event.LogFields == nil {
		event.LogFields = LogFields{}
	}

	if event.MetricLabels == nil {
		event.MetricLabels = MetricLabels{}
	}

	return event
}
