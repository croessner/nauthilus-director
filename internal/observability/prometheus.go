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
	"maps"
	"strconv"
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

	metricNameActiveSessions          = "nauthilus_director_active_sessions"
	metricNameAffinityOperations      = "nauthilus_director_affinity_operations_total"
	metricNameBackendActiveSessions   = "nauthilus_director_backend_active_sessions"
	metricNameBackendConnect          = "nauthilus_director_backend_connect_total"
	metricNameBackendConnectSeconds   = "nauthilus_director_backend_connect_duration_seconds"
	metricNameBackendDrainOperations  = "nauthilus_director_backend_drain_operations_total"
	metricNameBackendHealthState      = "nauthilus_director_backend_health_state"
	metricNameBackendHealthTotal      = "nauthilus_director_backend_health_transitions_total"
	metricNameBackendMaintenance      = "nauthilus_director_backend_maintenance_operations_total"
	metricNameBackendSelection        = "nauthilus_director_backend_selection_total"
	metricNameBackendSelectionSeconds = "nauthilus_director_backend_selection_duration_seconds"
	metricNameBackendRuntime          = "nauthilus_director_backend_runtime_operations_total"
	metricNameEventsTotal             = "nauthilus_director_observability_events_total"
	metricNameFailuresTotal           = "nauthilus_director_observability_sink_failures_total"
	metricNameListenerLifecycle       = "nauthilus_director_listener_lifecycle_total"
	metricNameMetricsEnabled          = "nauthilus_director_metrics_enabled"
	metricNameNauthilusAuth           = "nauthilus_director_nauthilus_auth_total"
	metricNameNauthilusAuthSeconds    = "nauthilus_director_nauthilus_auth_duration_seconds"
	metricNamePreAuthCommands         = "nauthilus_director_preauth_commands_total"
	metricNameProcessUp               = "nauthilus_director_process_up"
	metricNameProxyBytes              = "nauthilus_director_proxy_bytes_total"
	metricNameProxySeconds            = "nauthilus_director_proxy_lifetime_duration_seconds"
	metricNameRedisOperations         = "nauthilus_director_redis_operations_total"
	metricNameRedisSeconds            = "nauthilus_director_redis_operation_duration_seconds"
	metricNameReloads                 = "nauthilus_director_reload_total"
	metricNameRESTRequests            = "nauthilus_director_rest_requests_total"
	metricNameRESTSeconds             = "nauthilus_director_rest_request_duration_seconds"
	metricNameRoutingResolver         = "nauthilus_director_routing_resolver_total"
	metricNameRoutingResolverSeconds  = "nauthilus_director_routing_resolver_duration_seconds"
	metricNameRuntimeOperations       = "nauthilus_director_runtime_operations_total"
	metricNameSessions                = "nauthilus_director_sessions_total"

	metricOperationUnknown = "unknown"
	metricResultObserved   = "observed"
	metricStatusHealthy    = "healthy"
	metricStatusUnknown    = "unknown"
)

var (
	activeSessionLabels = []string{
		metricLabelProtocol,
		metricLabelService,
		metricLabelListener,
		metricLabelBackendPool,
		metricLabelTLSMode,
	}
	listenerLifecycleLabels = []string{
		metricLabelProtocol,
		metricLabelService,
		metricLabelListener,
		metricLabelBackendPool,
		metricLabelTLSMode,
		metricLabelOperation,
		metricLabelResult,
		metricLabelReasonClass,
	}
	backendStateLabels = []string{
		metricLabelProtocol,
		metricLabelBackendPool,
		metricLabelShardTag,
	}
	backendStateResultLabels    = append(cloneLabelNames(backendStateLabels), metricLabelResult)
	operationResultReasonLabels = []string{
		metricLabelOperation,
		metricLabelResult,
		metricLabelReasonClass,
	}
	protocolBackendLabels = []string{
		metricLabelProtocol,
		metricLabelBackendPool,
		metricLabelShardTag,
		metricLabelResult,
		metricLabelReasonClass,
	}
	protocolSessionLabels = []string{
		metricLabelProtocol,
		metricLabelService,
		metricLabelListener,
		metricLabelBackendPool,
		metricLabelTLSMode,
		metricLabelResult,
		metricLabelReasonClass,
	}
	redisLabels = []string{
		metricLabelOperation,
		metricLabelRedisMode,
		metricLabelResult,
		metricLabelReasonClass,
	}
	restLabels = []string{
		metricLabelMethod,
		metricLabelRoute,
		metricLabelOperation,
		metricLabelStatusClass,
		metricLabelResult,
	}
	serviceProtocolLabels = []string{
		metricLabelProtocol,
		metricLabelService,
		metricLabelListener,
		metricLabelTransport,
		metricLabelMechanism,
		metricLabelResult,
		metricLabelReasonClass,
	}
)

// MetricsProvider exposes Prometheus-compatible metrics text.
type MetricsProvider interface {
	Metrics(ctx context.Context) (string, error)
}

// prometheusRuntime owns one process-local registry and its instruments.
type prometheusRuntime struct {
	enabled    bool
	registry   *prometheus.Registry
	instrument prometheusInstruments
}

type prometheusInstruments struct {
	activeSessions           *prometheus.GaugeVec
	affinityOperations       *prometheus.CounterVec
	backendActiveSessions    *prometheus.GaugeVec
	backendConnect           *prometheus.CounterVec
	backendConnectSeconds    *prometheus.HistogramVec
	backendDrainOperations   *prometheus.CounterVec
	backendHealthState       *prometheus.GaugeVec
	backendHealthTransitions *prometheus.CounterVec
	backendMaintenance       *prometheus.CounterVec
	backendSelection         *prometheus.CounterVec
	backendSelectionSeconds  *prometheus.HistogramVec
	backendRuntime           *prometheus.CounterVec
	events                   *prometheus.CounterVec
	listenerLifecycle        *prometheus.CounterVec
	metricsEnabled           prometheus.Gauge
	nauthilusAuth            *prometheus.CounterVec
	nauthilusAuthSeconds     *prometheus.HistogramVec
	preAuthCommands          *prometheus.CounterVec
	processUp                prometheus.Gauge
	proxyBytes               *prometheus.CounterVec
	proxySeconds             *prometheus.HistogramVec
	redisOperations          *prometheus.CounterVec
	redisSeconds             *prometheus.HistogramVec
	reloads                  *prometheus.CounterVec
	restRequests             *prometheus.CounterVec
	restSeconds              *prometheus.HistogramVec
	routingResolver          *prometheus.CounterVec
	routingResolverSeconds   *prometheus.HistogramVec
	runtimeOperations        *prometheus.CounterVec
	sessions                 *prometheus.CounterVec
	sinkFailures             *prometheus.CounterVec
}

// newPrometheusRuntime builds an isolated Prometheus registry for this runtime.
func newPrometheusRuntime(cfg config.MetricsConfig) (*prometheusRuntime, error) {
	if !cfg.Enabled {
		return &prometheusRuntime{}, nil
	}

	instruments, err := newPrometheusInstruments()
	if err != nil {
		return nil, err
	}

	runtime := &prometheusRuntime{
		enabled:    true,
		registry:   prometheus.NewRegistry(),
		instrument: instruments,
	}
	runtime.instrument.metricsEnabled.Set(1)
	runtime.instrument.processUp.Set(1)

	if err := runtime.registerCollectors(cfg); err != nil {
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

	m.recordGenericEvent(event)
	m.recordTypedEvent(event)

	return nil
}

// RecordSinkFailure observes a telemetry sink failure without raw error details.
func (m *prometheusRuntime) RecordSinkFailure(operation string) {
	if m == nil || !m.enabled {
		return
	}

	m.instrument.sinkFailures.WithLabelValues(metricOperation(operation), telemetryReasonClass).Inc()
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

// registerCollectors registers only this runtime's process-local collectors.
func (m *prometheusRuntime) registerCollectors(cfg config.MetricsConfig) error {
	for _, collector := range m.instrument.collectors() {
		if err := registerCollector(m.registry, collector); err != nil {
			return err
		}
	}

	if !cfg.RuntimeMetrics {
		return nil
	}

	if err := registerCollector(m.registry, collectors.NewGoCollector()); err != nil {
		return err
	}

	return registerCollector(m.registry, collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
}

// recordGenericEvent keeps a compact fallback count for event vocabulary checks.
func (m *prometheusRuntime) recordGenericEvent(event Event) {
	m.instrument.events.WithLabelValues(metricOperation(event.Name), metricResult(event)).Inc()
}

// recordTypedEvent maps normalized runtime events into reviewed metric families.
func (m *prometheusRuntime) recordTypedEvent(event Event) {
	if m.recordLifecycleMetric(event) {
		return
	}

	if m.recordPlacementMetric(event) {
		return
	}

	if m.recordBackendControlMetric(event) {
		return
	}

	m.recordRuntimeMetric(event)
}

// recordLifecycleMetric handles listener and session lifecycle observations.
func (m *prometheusRuntime) recordLifecycleMetric(event Event) bool {
	switch event.Name {
	case EventListenerStart, EventListenerStop:
		m.recordListenerLifecycle(event)
	case EventSessionStart, EventSessionEnd:
		m.recordSessionLifecycle(event)
	case EventIMAPPreAuth:
		m.instrument.preAuthCommands.WithLabelValues(metricValues(event, protocolSessionLabels)...).Inc()
	default:
		return false
	}

	return true
}

// recordPlacementMetric handles authority, routing and backend placement observations.
func (m *prometheusRuntime) recordPlacementMetric(event Event) bool {
	switch event.Name {
	case EventNauthilusAuth:
		m.recordNauthilusAuth(event)
	case EventRoutingResolve, EventRouteLookup:
		m.recordRouting(event)
	case EventAffinityOpen, EventSessionClose, EventAffinityClear:
		m.recordAffinity(event)
	case EventBackendSelect:
		m.recordBackendSelection(event)
	case EventBackendConnect:
		m.recordBackendConnect(event)
	default:
		return false
	}

	return true
}

// recordBackendControlMetric handles backend state and operator control observations.
func (m *prometheusRuntime) recordBackendControlMetric(event Event) bool {
	switch event.Name {
	case EventBackendHealthTransition:
		m.recordBackendHealth(event)
	case EventBackendEffectiveState:
		m.recordBackendEffectiveState(event)
	case EventBackendRuntimeOperation:
		m.recordBackendRuntimeOperation(event)
	case EventBackendMaintenanceOperation:
		m.recordBackendMaintenanceOperation(event)
	case EventBackendDrain:
		m.recordBackendDrainOperation(event)
	default:
		return false
	}

	return true
}

// recordRuntimeMetric handles transport, REST, Redis and runtime operation observations.
func (m *prometheusRuntime) recordRuntimeMetric(event Event) {
	switch event.Name {
	case EventProxyPipe:
		m.recordProxy(event)
	case EventRESTRequest:
		m.recordREST(event)
	case EventReload:
		m.recordReload(event)
	case EventRedisOperation:
		m.recordRedis(event)
	case EventSessionReap, EventSessionKill, EventUserMove, EventUserKick, EventSelectorExclusion, EventSessionAttach:
		m.recordRuntimeOperation(event)
	}
}

// recordListenerLifecycle counts frontend listener starts and stops.
func (m *prometheusRuntime) recordListenerLifecycle(event Event) {
	labels := eventWithOperation(event, listenerOperationForEvent(event.Name))
	m.instrument.listenerLifecycle.WithLabelValues(metricValues(labels, listenerLifecycleLabels)...).Inc()
}

// recordSessionLifecycle counts session starts and ends while tracking active sessions.
func (m *prometheusRuntime) recordSessionLifecycle(event Event) {
	m.instrument.sessions.WithLabelValues(metricValues(event, protocolSessionLabels)...).Inc()

	active := m.instrument.activeSessions.WithLabelValues(metricValues(event, activeSessionLabels)...)
	if event.Name == EventSessionStart {
		active.Inc()

		return
	}

	active.Dec()
}

// recordNauthilusAuth counts and times authority authentication requests.
func (m *prometheusRuntime) recordNauthilusAuth(event Event) {
	m.instrument.nauthilusAuth.WithLabelValues(metricValues(event, serviceProtocolLabels)...).Inc()
	observeDuration(m.instrument.nauthilusAuthSeconds, event, serviceProtocolLabels)
}

// recordRouting counts and times route resolution and route diagnostics.
func (m *prometheusRuntime) recordRouting(event Event) {
	m.instrument.routingResolver.WithLabelValues(metricValues(event, protocolBackendLabels)...).Inc()
	observeDuration(m.instrument.routingResolverSeconds, event, protocolBackendLabels)
	m.recordRuntimeOperation(event)
}

// recordAffinity counts Redis-backed affinity and session-close operations.
func (m *prometheusRuntime) recordAffinity(event Event) {
	m.instrument.affinityOperations.WithLabelValues(metricValues(event, protocolBackendLabels)...).Inc()
	m.recordRuntimeOperation(event)
}

// recordBackendSelection counts and times backend selection.
func (m *prometheusRuntime) recordBackendSelection(event Event) {
	m.instrument.backendSelection.WithLabelValues(metricValues(event, protocolBackendLabels)...).Inc()
	observeDuration(m.instrument.backendSelectionSeconds, event, protocolBackendLabels)
}

// recordBackendConnect counts and times backend connection setup.
func (m *prometheusRuntime) recordBackendConnect(event Event) {
	m.instrument.backendConnect.WithLabelValues(metricValues(event, protocolBackendLabels)...).Inc()
	observeDuration(m.instrument.backendConnectSeconds, event, protocolBackendLabels)
}

// recordBackendHealth updates aggregate health-state gauges without backend IDs.
func (m *prometheusRuntime) recordBackendHealth(event Event) {
	m.instrument.backendHealthTransitions.WithLabelValues(metricValues(event, protocolBackendLabels)...).Inc()

	current := metricLabelValue(event.LogFields, "health_status", metricStatusUnknown)
	healthLabels := eventWithResult(event, current)
	m.instrument.backendHealthState.WithLabelValues(metricValues(healthLabels, backendStateResultLabels)...).Set(1)

	previous := metricLabelValue(event.LogFields, "previous_status", "")
	if previous != "" && previous != current {
		previousLabels := eventWithResult(event, previous)
		m.instrument.backendHealthState.WithLabelValues(metricValues(previousLabels, backendStateResultLabels)...).Dec()
	}
}

// recordBackendEffectiveState updates backend active-session aggregate gauges.
func (m *prometheusRuntime) recordBackendEffectiveState(event Event) {
	if value, ok := metricMeasurement(event, MetricMeasurementActiveSessions); ok {
		m.instrument.backendActiveSessions.WithLabelValues(metricValues(event, backendStateLabels)...).Set(value)
	}
}

// recordBackendRuntimeOperation counts operator backend runtime overrides.
func (m *prometheusRuntime) recordBackendRuntimeOperation(event Event) {
	m.instrument.backendRuntime.WithLabelValues(metricValues(event, operationResultReasonLabels)...).Inc()
	m.recordRuntimeOperation(event)
}

// recordBackendMaintenanceOperation counts operator backend maintenance changes.
func (m *prometheusRuntime) recordBackendMaintenanceOperation(event Event) {
	labels := append(cloneLabelNames(operationResultReasonLabels), metricLabelMaintenanceMode)
	m.instrument.backendMaintenance.WithLabelValues(metricValues(event, labels)...).Inc()
	m.recordRuntimeOperation(event)
}

// recordBackendDrainOperation counts operator backend drain changes.
func (m *prometheusRuntime) recordBackendDrainOperation(event Event) {
	labels := append(cloneLabelNames(operationResultReasonLabels), metricLabelMaintenanceMode)
	m.instrument.backendDrainOperations.WithLabelValues(metricValues(event, labels)...).Inc()
	m.recordRuntimeOperation(event)
}

// recordProxy counts proxy byte flow and lifetime duration.
func (m *prometheusRuntime) recordProxy(event Event) {
	observeProxyBytes(m.instrument.proxyBytes, event)
	observeDuration(m.instrument.proxySeconds, event, operationResultReasonLabels)
}

// recordREST counts and times generated REST operations.
func (m *prometheusRuntime) recordREST(event Event) {
	m.instrument.restRequests.WithLabelValues(metricValues(event, restLabels)...).Inc()
	observeDuration(m.instrument.restSeconds, event, restLabels)
}

// recordReload counts safe reload outcomes.
func (m *prometheusRuntime) recordReload(event Event) {
	m.instrument.reloads.WithLabelValues(metricValues(event, operationResultReasonLabels)...).Inc()
	m.recordRuntimeOperation(event)
}

// recordRedis counts and times Redis state operation classes.
func (m *prometheusRuntime) recordRedis(event Event) {
	m.instrument.redisOperations.WithLabelValues(metricValues(event, redisLabels)...).Inc()
	observeDuration(m.instrument.redisSeconds, event, redisLabels)
}

// recordRuntimeOperation counts state-changing and diagnostic runtime operations.
func (m *prometheusRuntime) recordRuntimeOperation(event Event) {
	m.instrument.runtimeOperations.WithLabelValues(metricValues(event, operationResultReasonLabels)...).Inc()
}

// newPrometheusInstruments creates all reviewed business metric families.
func newPrometheusInstruments() (prometheusInstruments, error) {
	builders := prometheusInstrumentBuilder{}

	return prometheusInstruments{
		activeSessions:           builders.gaugeVec(metricNameActiveSessions, "Active frontend sessions by bounded listener dimensions.", activeSessionLabels...),
		affinityOperations:       builders.counterVec(metricNameAffinityOperations, "Total Redis-backed affinity operations.", protocolBackendLabels...),
		backendActiveSessions:    builders.gaugeVec(metricNameBackendActiveSessions, "Backend active-session aggregate counts by bounded backend dimensions.", backendStateLabels...),
		backendConnect:           builders.counterVec(metricNameBackendConnect, "Total backend connection setup outcomes.", protocolBackendLabels...),
		backendConnectSeconds:    builders.histogramVec(metricNameBackendConnectSeconds, "Backend connection setup duration in seconds.", backendConnectBuckets(), protocolBackendLabels...),
		backendDrainOperations:   builders.counterVec(metricNameBackendDrainOperations, "Total backend drain runtime operations.", append(cloneLabelNames(operationResultReasonLabels), metricLabelMaintenanceMode)...),
		backendHealthState:       builders.gaugeVec(metricNameBackendHealthState, "Aggregate backend health state by bounded backend dimensions.", backendStateResultLabels...),
		backendHealthTransitions: builders.counterVec(metricNameBackendHealthTotal, "Total backend health state transitions.", protocolBackendLabels...),
		backendMaintenance:       builders.counterVec(metricNameBackendMaintenance, "Total backend maintenance runtime operations.", append(cloneLabelNames(operationResultReasonLabels), metricLabelMaintenanceMode)...),
		backendSelection:         builders.counterVec(metricNameBackendSelection, "Total backend selection outcomes.", protocolBackendLabels...),
		backendSelectionSeconds:  builders.histogramVec(metricNameBackendSelectionSeconds, "Backend selection duration in seconds.", backendConnectBuckets(), protocolBackendLabels...),
		backendRuntime:           builders.counterVec(metricNameBackendRuntime, "Total backend runtime override operations.", operationResultReasonLabels...),
		events:                   builders.counterVec(metricNameEventsTotal, "Total normalized observability events recorded by the director.", metricLabelOperation, metricLabelResult),
		listenerLifecycle:        builders.counterVec(metricNameListenerLifecycle, "Total listener lifecycle outcomes.", listenerLifecycleLabels...),
		metricsEnabled:           builders.gauge(metricNameMetricsEnabled, "Metrics exporter enabled state for this director process."),
		nauthilusAuth:            builders.counterVec(metricNameNauthilusAuth, "Total Nauthilus authentication outcomes.", serviceProtocolLabels...),
		nauthilusAuthSeconds:     builders.histogramVec(metricNameNauthilusAuthSeconds, "Nauthilus authentication duration in seconds.", restBuckets(), serviceProtocolLabels...),
		preAuthCommands:          builders.counterVec(metricNamePreAuthCommands, "Total pre-auth command outcomes.", protocolSessionLabels...),
		processUp:                builders.gauge(metricNameProcessUp, "Process-local director up state."),
		proxyBytes:               builders.counterVec(metricNameProxyBytes, "Total proxy bytes by direction.", metricLabelDirection, metricLabelResult, metricLabelReasonClass),
		proxySeconds:             builders.histogramVec(metricNameProxySeconds, "Transparent proxy lifetime duration in seconds.", mailSessionBuckets(), operationResultReasonLabels...),
		redisOperations:          builders.counterVec(metricNameRedisOperations, "Total Redis state operations by operation class.", redisLabels...),
		redisSeconds:             builders.histogramVec(metricNameRedisSeconds, "Redis state operation duration in seconds.", redisBuckets(), redisLabels...),
		reloads:                  builders.counterVec(metricNameReloads, "Total safe reload outcomes.", operationResultReasonLabels...),
		restRequests:             builders.counterVec(metricNameRESTRequests, "Total generated REST control API requests.", restLabels...),
		restSeconds:              builders.histogramVec(metricNameRESTSeconds, "Generated REST control API request duration in seconds.", restBuckets(), restLabels...),
		routingResolver:          builders.counterVec(metricNameRoutingResolver, "Total routing resolver outcomes.", protocolBackendLabels...),
		routingResolverSeconds:   builders.histogramVec(metricNameRoutingResolverSeconds, "Routing resolver duration in seconds.", redisBuckets(), protocolBackendLabels...),
		runtimeOperations:        builders.counterVec(metricNameRuntimeOperations, "Total runtime control and diagnostic operations.", operationResultReasonLabels...),
		sessions:                 builders.counterVec(metricNameSessions, "Total frontend session lifecycle outcomes.", protocolSessionLabels...),
		sinkFailures:             builders.counterVec(metricNameFailuresTotal, "Total non-fatal observability sink failures by sink operation and reason class.", metricLabelOperation, metricLabelReasonClass),
	}, builders.err
}

// collectors returns all process-local business collectors.
func (i prometheusInstruments) collectors() []prometheus.Collector {
	return []prometheus.Collector{
		i.activeSessions,
		i.affinityOperations,
		i.backendActiveSessions,
		i.backendConnect,
		i.backendConnectSeconds,
		i.backendDrainOperations,
		i.backendHealthState,
		i.backendHealthTransitions,
		i.backendMaintenance,
		i.backendSelection,
		i.backendSelectionSeconds,
		i.backendRuntime,
		i.events,
		i.listenerLifecycle,
		i.metricsEnabled,
		i.nauthilusAuth,
		i.nauthilusAuthSeconds,
		i.preAuthCommands,
		i.processUp,
		i.proxyBytes,
		i.proxySeconds,
		i.redisOperations,
		i.redisSeconds,
		i.reloads,
		i.restRequests,
		i.restSeconds,
		i.routingResolver,
		i.routingResolverSeconds,
		i.runtimeOperations,
		i.sessions,
		i.sinkFailures,
	}
}

type prometheusInstrumentBuilder struct {
	err error
}

// counterVec creates a counter vector after label policy validation.
func (b *prometheusInstrumentBuilder) counterVec(name string, help string, labels ...string) *prometheus.CounterVec {
	if b.err != nil {
		return nil
	}

	if err := ValidateMetricLabels(labels...); err != nil {
		b.err = err

		return nil
	}

	return prometheus.NewCounterVec(prometheus.CounterOpts{Name: name, Help: help}, labels)
}

// gauge creates a gauge without labels.
func (b *prometheusInstrumentBuilder) gauge(name string, help string) prometheus.Gauge {
	if b.err != nil {
		return nil
	}

	return prometheus.NewGauge(prometheus.GaugeOpts{Name: name, Help: help})
}

// gaugeVec creates a gauge vector after label policy validation.
func (b *prometheusInstrumentBuilder) gaugeVec(name string, help string, labels ...string) *prometheus.GaugeVec {
	if b.err != nil {
		return nil
	}

	if err := ValidateMetricLabels(labels...); err != nil {
		b.err = err

		return nil
	}

	return prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: name, Help: help}, labels)
}

// histogramVec creates a histogram vector after label policy validation.
func (b *prometheusInstrumentBuilder) histogramVec(name string, help string, buckets []float64, labels ...string) *prometheus.HistogramVec {
	if b.err != nil {
		return nil
	}

	if err := ValidateMetricLabels(labels...); err != nil {
		b.err = err

		return nil
	}

	return prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: name, Help: help, Buckets: buckets}, labels)
}

// registerCollector adds one collector and returns duplicate errors to callers.
func registerCollector(registry *prometheus.Registry, collector prometheus.Collector) error {
	if err := registry.Register(collector); err != nil {
		return fmt.Errorf("register prometheus collector: %w", err)
	}

	return nil
}

// observeDuration records a duration measurement when the event supplies one.
func observeDuration(histogram *prometheus.HistogramVec, event Event, labels []string) {
	value, ok := event.Measurements.Value(MetricMeasurementDurationSeconds)
	if !ok || value <= 0 {
		return
	}

	histogram.WithLabelValues(metricValues(event, labels)...).Observe(value)
}

// observeProxyBytes records transparent proxy byte counts by direction.
func observeProxyBytes(counter *prometheus.CounterVec, event Event) {
	labels := []string{metricLabelDirection, metricLabelResult, metricLabelReasonClass}

	for _, observation := range []struct {
		name      string
		direction string
	}{
		{name: MetricMeasurementClientToBackendBytes, direction: "client_to_backend"},
		{name: MetricMeasurementBackendToClientBytes, direction: "backend_to_client"},
	} {
		value, ok := event.Measurements.Value(observation.name)
		if !ok || value <= 0 {
			continue
		}

		directional := eventWithLabel(event, metricLabelDirection, observation.direction)
		counter.WithLabelValues(metricValues(directional, labels)...).Add(value)
	}
}

// metricMeasurement returns a measurement or parses a same-named sanitized field.
func metricMeasurement(event Event, name string) (float64, bool) {
	if value, ok := event.Measurements.Value(name); ok {
		return value, true
	}

	text := strings.TrimSpace(event.LogFields[name])
	if text == "" {
		return 0, false
	}

	value, err := strconv.ParseFloat(text, 64)
	if err != nil || value < 0 {
		return 0, false
	}

	return value, true
}

// metricValues returns label values in registration order.
func metricValues(event Event, labels []string) []string {
	values := make([]string, 0, len(labels))
	for _, label := range labels {
		values = append(values, metricValue(event, label))
	}

	return values
}

// metricValue returns one normalized metric label value.
func metricValue(event Event, label string) string {
	switch label {
	case metricLabelOperation:
		return metricOperation(event.MetricLabels[label])
	case metricLabelReasonClass:
		return metricReasonClass(event)
	case metricLabelResult:
		return metricResult(event)
	default:
		return metricLabelValue(event.MetricLabels, label, metricOperationUnknown)
	}
}

// metricResult returns the bounded result label value.
func metricResult(event Event) string {
	return metricLabelValue(event.MetricLabels, metricLabelResult, metricOperationUnknown)
}

// metricReasonClass returns a normalized reason class for metric labels.
func metricReasonClass(event Event) string {
	reason := strings.TrimSpace(event.MetricLabels[metricLabelReasonClass])
	if reason == "" {
		return reasonClassOK
	}

	return NormalizeReasonClass(reason)
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
func metricLabelValue(labels map[string]string, name string, fallback string) string {
	if labels == nil {
		return fallback
	}

	value := strings.TrimSpace(labels[name])
	if value == "" {
		return fallback
	}

	return value
}

// listenerOperationForEvent maps listener event names to lifecycle operations.
func listenerOperationForEvent(name string) string {
	switch name {
	case EventListenerStart:
		return "start"
	case EventListenerStop:
		return "stop"
	default:
		return metricOperationUnknown
	}
}

// eventWithOperation returns an event copy with an overridden operation label.
func eventWithOperation(event Event, operation string) Event {
	return eventWithLabel(event, metricLabelOperation, operation)
}

// eventWithResult returns an event copy with an overridden result label.
func eventWithResult(event Event, result string) Event {
	return eventWithLabel(event, metricLabelResult, result)
}

// eventWithLabel returns an event copy with one metric label overridden.
func eventWithLabel(event Event, label string, value string) Event {
	cloned := make(MetricLabels, len(event.MetricLabels)+1)
	maps.Copy(cloned, event.MetricLabels)

	cloned[label] = value
	event.MetricLabels = cloned

	return event
}

// cloneLabelNames copies a metric label-name slice before callers append to it.
func cloneLabelNames(labels []string) []string {
	return append([]string(nil), labels...)
}

// mailSessionBuckets returns reviewed buckets for long-lived mail sessions.
func mailSessionBuckets() []float64 {
	return []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 300, 900, 1800}
}

// restBuckets returns reviewed buckets for HTTP and Nauthilus request latency.
func restBuckets() []float64 {
	return []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
}

// redisBuckets returns reviewed buckets for Redis and routing latency.
func redisBuckets() []float64 {
	return []float64{0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5}
}

// backendConnectBuckets returns reviewed buckets for backend placement and connect work.
func backendConnectBuckets() []float64 {
	return []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}
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
