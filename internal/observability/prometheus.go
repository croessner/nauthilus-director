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
	"fmt"
	"strings"

	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/common/expfmt"
)

const (
	metricsDisabledText = "# HELP nauthilus_director_metrics_enabled Metrics exporter enabled state.\n" +
		"# TYPE nauthilus_director_metrics_enabled gauge\n" +
		"nauthilus_director_metrics_enabled 0\n"

	metricNameEventsTotal      = "nauthilus_director_observability_events_total"
	metricNameFailuresTotal    = "nauthilus_director_observability_sink_failures_total"
	metricNameMetricsEnabled   = "nauthilus_director_metrics_enabled"
	metricResultObserved       = "observed"
	metricOperationUnknown     = "unknown"
	metricSubsystemObservables = "observability"
)

// MetricsProvider exposes Prometheus-compatible metrics text.
type MetricsProvider interface {
	Metrics(ctx context.Context) (string, error)
}

// prometheusRuntime owns one process-local registry and its core instruments.
type prometheusRuntime struct {
	enabled        bool
	registry       *prometheus.Registry
	events         *prometheus.CounterVec
	sinkFailures   *prometheus.CounterVec
	metricsEnabled prometheus.Gauge
}

// newPrometheusRuntime builds an isolated Prometheus registry for this runtime.
func newPrometheusRuntime(cfg config.MetricsConfig) (*prometheusRuntime, error) {
	if !cfg.Enabled {
		return &prometheusRuntime{}, nil
	}

	registry := prometheus.NewRegistry()
	runtime := &prometheusRuntime{
		enabled:        true,
		registry:       registry,
		events:         newEventCounter(),
		sinkFailures:   newSinkFailureCounter(),
		metricsEnabled: newMetricsEnabledGauge(),
	}
	runtime.metricsEnabled.Set(1)

	if err := runtime.registerRuntimeCollectors(cfg); err != nil {
		return nil, err
	}

	return runtime, nil
}

// Enabled reports whether business metrics are exposed.
func (m *prometheusRuntime) Enabled() bool {
	return m != nil && m.enabled
}

// Record observes one normalized event with bounded metric labels.
func (m *prometheusRuntime) Record(_ context.Context, event Event) error {
	if m == nil || !m.enabled {
		return nil
	}

	if err := event.MetricLabels.Validate(); err != nil {
		return err
	}

	operation := metricOperation(event.Name)
	result := metricLabelValue(event.MetricLabels, metricLabelResult, metricResultObserved)
	m.events.WithLabelValues(operation, result).Inc()

	return nil
}

// RecordSinkFailure observes a telemetry sink failure without raw error details.
func (m *prometheusRuntime) RecordSinkFailure(operation string) {
	if m == nil || !m.enabled {
		return
	}

	m.sinkFailures.WithLabelValues(metricOperation(operation), telemetryReasonClass).Inc()
}

// Metrics renders the current registry in Prometheus text format.
func (m *prometheusRuntime) Metrics(ctx context.Context) (string, error) {
	if m == nil || !m.enabled {
		return metricsDisabledText, nil
	}

	if err := ctx.Err(); err != nil {
		return "", err
	}

	families, err := m.registry.Gather()
	if err != nil {
		return "", fmt.Errorf("gather metrics: %w", err)
	}

	var buffer bytes.Buffer

	encoder := expfmt.NewEncoder(&buffer, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, family := range families {
		if err := encoder.Encode(family); err != nil {
			return "", fmt.Errorf("encode metrics: %w", err)
		}
	}

	return buffer.String(), nil
}

// registerRuntimeCollectors registers only process-local collectors.
func (m *prometheusRuntime) registerRuntimeCollectors(cfg config.MetricsConfig) error {
	if err := registerCollector(m.registry, m.metricsEnabled); err != nil {
		return err
	}

	if err := registerCollector(m.registry, m.events); err != nil {
		return err
	}

	if err := registerCollector(m.registry, m.sinkFailures); err != nil {
		return err
	}

	if !cfg.RuntimeMetrics {
		return nil
	}

	if err := registerCollector(m.registry, collectors.NewGoCollector()); err != nil {
		return err
	}

	return registerCollector(m.registry, collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
}

// registerCollector adds one collector and returns duplicate errors to callers.
func registerCollector(registry *prometheus.Registry, collector prometheus.Collector) error {
	if err := registry.Register(collector); err != nil {
		return fmt.Errorf("register prometheus collector: %w", err)
	}

	return nil
}

// newEventCounter creates the generic observability event counter.
func newEventCounter() *prometheus.CounterVec {
	return prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: metricNameEventsTotal,
		Help: "Total normalized observability events recorded by the director.",
	}, []string{metricLabelOperation, metricLabelResult})
}

// newSinkFailureCounter creates the bounded telemetry failure counter.
func newSinkFailureCounter() *prometheus.CounterVec {
	return prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: metricNameFailuresTotal,
		Help: "Total non-fatal observability sink failures by sink operation and reason class.",
	}, []string{metricLabelOperation, metricLabelReasonClass})
}

// newMetricsEnabledGauge creates the configured metrics state gauge.
func newMetricsEnabledGauge() prometheus.Gauge {
	return prometheus.NewGauge(prometheus.GaugeOpts{
		Name: metricNameMetricsEnabled,
		Help: "Metrics exporter enabled state for this director process.",
	})
}

// metricOperation normalizes stable event names for the operation label value.
func metricOperation(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return metricOperationUnknown
	}

	return value
}

// metricLabelValue returns one metric label value with an explicit fallback.
func metricLabelValue(labels MetricLabels, name string, fallback string) string {
	if labels == nil {
		return fallback
	}

	value := strings.TrimSpace(labels[name])
	if value == "" {
		return fallback
	}

	return value
}

// Metrics returns a disabled metrics state for nil runtime fallbacks.
func (disabledMetricsProvider) Metrics(context.Context) (string, error) {
	return metricsDisabledText, nil
}

type disabledMetricsProvider struct{}

// DisabledMetricsText returns the safe scrape payload for disabled metrics.
func DisabledMetricsText() string {
	return metricsDisabledText
}
