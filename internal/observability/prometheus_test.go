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
	"io"
	"strings"
	"testing"

	"github.com/croessner/nauthilus-director/internal/config"
	dto "github.com/prometheus/client_model/go"
)

const (
	testBackendIdentifier = "mailstore-a-imap"
	testBackendPool       = "imap-default"
	testBackendShardTag   = "mailstore-a"
	testBackendHealthOp   = "backend_health"
	testHealthStatusField = "health_status"
	testHealthUnhealthy   = "unhealthy"
	testMechanismPlain    = "plain"
	testPreviousStatus    = "previous_status"
	testProtocolIMAP      = "imap"
	testRedisKey          = "{alice}:session"
	testRedisModeCluster  = "cluster"
	testRedisOpen         = "open"
	testResultTransition  = "transition"
)

// TestPrometheusBusinessMetricsUseAllowlistedLabels verifies registered director metrics obey label policy.
func TestPrometheusBusinessMetricsUseAllowlistedLabels(t *testing.T) {
	runtime := newMetricsTestRuntime(t, false)
	recordRepresentativeMetrics(t, runtime)

	families, err := runtime.metrics.registry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}

	for _, family := range families {
		if !strings.HasPrefix(family.GetName(), "nauthilus_director_") {
			continue
		}

		assertMetricFamilyLabelsAllowed(t, family)
	}
}

// TestMetricPolicyRejectsForbiddenLabelsBeforeRegistrationOrObservation checks both policy gates.
func TestMetricPolicyRejectsForbiddenLabelsBeforeRegistrationOrObservation(t *testing.T) {
	builder := prometheusInstrumentBuilder{}

	collector := builder.counterVec("test_forbidden_metric_total", "forbidden labels should fail", fieldBackendIdentifier)
	if collector != nil {
		t.Fatal("counter builder returned a collector with a forbidden label")
	}

	if builder.err == nil {
		t.Fatal("counter builder accepted a forbidden label")
	}

	runtime := newMetricsTestRuntime(t, false)

	err := runtime.metrics.Record(context.Background(), Event{
		Name:         EventRESTRequest,
		MetricLabels: MetricLabels{fieldBackendIdentifier: testBackendIdentifier},
	})
	if err == nil {
		t.Fatal("metrics runtime accepted a forbidden observation label")
	}
}

// TestRuntimeCollectorsFollowConfig verifies Go and process collectors are opt-in.
func TestRuntimeCollectorsFollowConfig(t *testing.T) {
	withoutRuntime := newMetricsTestRuntime(t, false)

	withoutBody := gatherMetricsText(t, withoutRuntime)
	if strings.Contains(withoutBody, "go_goroutines") || strings.Contains(withoutBody, "process_cpu_seconds_total") {
		t.Fatalf("runtime collectors appeared while disabled:\n%s", withoutBody)
	}

	withRuntime := newMetricsTestRuntime(t, true)

	withBody := gatherMetricsText(t, withRuntime)
	if !strings.Contains(withBody, "go_goroutines") {
		t.Fatalf("Go runtime collector missing while enabled:\n%s", withBody)
	}

	if !strings.Contains(withBody, "process_cpu_seconds_total") {
		t.Fatalf("process collector missing while enabled:\n%s", withBody)
	}
}

// TestBackendHealthMetricsDoNotExposeBackendIdentifiers keeps health aggregates bounded.
func TestBackendHealthMetricsDoNotExposeBackendIdentifiers(t *testing.T) {
	runtime := newMetricsTestRuntime(t, false)
	event := newMetricEvent(t, EventBackendHealthTransition, map[string]string{
		fieldBackendIdentifier: testBackendIdentifier,
		testHealthStatusField:  metricStatusHealthy,
		testPreviousStatus:     testHealthUnhealthy,
		metricLabelOperation:   testBackendHealthOp,
		metricLabelResult:      testResultTransition,
		metricLabelReasonClass: metricStatusHealthy,
	}, map[string]string{
		metricLabelBackendPool: testBackendPool,
		metricLabelOperation:   testBackendHealthOp,
		metricLabelProtocol:    testProtocolIMAP,
		metricLabelReasonClass: metricStatusHealthy,
		metricLabelResult:      testResultTransition,
		metricLabelShardTag:    testBackendShardTag,
	})
	runtime.Recorder().Record(context.Background(), event)

	body := gatherMetricsText(t, runtime)
	if !strings.Contains(body, metricNameBackendHealthState) {
		t.Fatalf("backend health metric missing:\n%s", body)
	}

	if strings.Contains(body, testBackendIdentifier) {
		t.Fatalf("backend identifier leaked into metrics:\n%s", body)
	}
}

// TestRedisMetricsDoNotExposeRedisKeys keeps state metrics on operation classes.
func TestRedisMetricsDoNotExposeRedisKeys(t *testing.T) {
	runtime := newMetricsTestRuntime(t, false)
	event := newMetricEvent(t, EventRedisOperation, map[string]string{
		"redis_key":            testRedisKey,
		metricLabelOperation:   testRedisOpen,
		metricLabelRedisMode:   testRedisModeCluster,
		metricLabelResult:      reasonClassOK,
		metricLabelReasonClass: reasonClassOK,
	}, map[string]string{
		metricLabelOperation:   testRedisOpen,
		metricLabelRedisMode:   testRedisModeCluster,
		metricLabelResult:      reasonClassOK,
		metricLabelReasonClass: reasonClassOK,
	})
	event.Measurements = NewMetricMeasurements(map[string]float64{MetricMeasurementDurationSeconds: 0.001})
	runtime.Recorder().Record(context.Background(), event)

	body := gatherMetricsText(t, runtime)
	if !strings.Contains(body, metricNameRedisOperations) {
		t.Fatalf("Redis metric missing:\n%s", body)
	}

	if strings.Contains(body, testRedisKey) {
		t.Fatalf("Redis key leaked into metrics:\n%s", body)
	}
}

// assertMetricFamilyLabelsAllowed checks every custom label on a gathered metric family.
func assertMetricFamilyLabelsAllowed(t *testing.T, family *dto.MetricFamily) {
	t.Helper()

	for _, metric := range family.GetMetric() {
		for _, label := range metric.GetLabel() {
			if !IsMetricLabelAllowed(label.GetName()) {
				t.Fatalf("%s uses non-allowlisted label %q", family.GetName(), label.GetName())
			}
		}
	}
}

// newMetricsTestRuntime creates an enabled metrics runtime without tracing side effects.
func newMetricsTestRuntime(t *testing.T, runtimeCollectors bool) *Runtime {
	t.Helper()

	cfg := config.DefaultConfig().Observability
	cfg.Metrics.RuntimeMetrics = runtimeCollectors
	cfg.Tracing.Enabled = false

	runtime, err := NewRuntime(cfg, WithLogWriter(io.Discard))
	if err != nil {
		t.Fatalf("NewRuntime returned error: %v", err)
	}

	return runtime
}

// gatherMetricsText renders metrics for string-based leak checks.
func gatherMetricsText(t *testing.T, runtime *Runtime) string {
	t.Helper()

	body, err := runtime.MetricsProvider().Metrics(context.Background())
	if err != nil {
		t.Fatalf("Metrics returned error: %v", err)
	}

	return body
}

// recordRepresentativeMetrics observes one event for each custom metric family.
func recordRepresentativeMetrics(t *testing.T, runtime *Runtime) {
	t.Helper()

	for _, event := range representativeMetricEvents(t) {
		runtime.Recorder().Record(context.Background(), event)
	}
}

// representativeMetricEvents builds deterministic observations for label-policy tests.
func representativeMetricEvents(t *testing.T) []Event {
	t.Helper()

	return []Event{
		newMetricEvent(t, EventListenerStart, nil, protocolLabels("start", reasonClassOK)),
		newMetricEvent(t, EventSessionStart, nil, protocolLabels("start", reasonClassOK)),
		newMetricEvent(t, EventSessionEnd, nil, protocolLabels(reasonClassOK, reasonClassOK)),
		newMetricEvent(t, EventIMAPPreAuth, nil, protocolLabels("accepted", reasonClassOK)),
		measuredEvent(t, EventNauthilusAuth, nil, authLabels(reasonClassOK, reasonClassOK), 0.002),
		measuredEvent(t, EventRoutingResolve, nil, backendLabels(reasonClassOK, reasonClassOK), 0.001),
		newMetricEvent(t, EventAffinityOpen, nil, backendLabels(reasonClassOK, reasonClassOK)),
		measuredEvent(t, EventBackendSelect, nil, backendLabels(reasonClassOK, reasonClassOK), 0.001),
		measuredEvent(t, EventBackendConnect, nil, backendLabels(reasonClassOK, reasonClassOK), 0.001),
		newMetricEvent(t, EventBackendAuth, nil, backendAuthLabelsForTest(reasonClassOK, reasonClassOK)),
		backendHealthEvent(t),
		backendEffectiveEvent(t),
		newMetricEvent(t, EventBackendRuntimeOperation, nil, operationLabels("backend_in_out", reasonClassOK, reasonClassOK)),
		newMetricEvent(t, EventBackendMaintenanceOperation, nil, maintenanceLabels("backend_maintenance", reasonClassOK, reasonClassOK, "soft")),
		newMetricEvent(t, EventBackendDrain, nil, maintenanceLabels("backend_drain", reasonClassOK, reasonClassOK, "drain_existing")),
		proxyEvent(t),
		measuredEvent(t, EventRESTRequest, nil, restRequestLabels(), 0.001),
		newMetricEvent(t, EventReload, nil, operationLabels("reload", reasonClassOK, reasonClassOK)),
		measuredEvent(t, EventRedisOperation, nil, redisOperationLabels(), 0.001),
		newMetricEvent(t, EventSessionKill, nil, operationLabels("session_kill", reasonClassOK, reasonClassOK)),
		newMetricEvent(t, EventUserMove, nil, operationLabels("user_move", reasonClassOK, reasonClassOK)),
		newMetricEvent(t, EventUserKick, nil, operationLabels("user_kick", reasonClassOK, reasonClassOK)),
		newMetricEvent(t, EventRouteLookup, nil, backendLabels(reasonClassOK, reasonClassOK)),
		newMetricEvent(t, EventSelectorExclusion, nil, operationLabels("selector_exclusion", "excluded", "runtime_out")),
		newMetricEvent(t, EventSessionAttach, nil, operationLabels("session_attach", reasonClassOK, reasonClassOK)),
		newMetricEvent(t, EventAffinityClear, nil, operationLabels("user_affinity_clear", reasonClassOK, reasonClassOK)),
	}
}

// newMetricEvent creates a policy-checked event for tests.
func newMetricEvent(t *testing.T, name string, fields map[string]string, labels map[string]string) Event {
	t.Helper()

	event, err := NewEvent(name, "", fields, labels)
	if err != nil {
		t.Fatalf("NewEvent(%s) returned error: %v", name, err)
	}

	return event
}

// measuredEvent creates an event with a duration measurement.
func measuredEvent(t *testing.T, name string, fields map[string]string, labels map[string]string, duration float64) Event {
	t.Helper()

	event := newMetricEvent(t, name, fields, labels)
	event.Measurements = NewMetricMeasurements(map[string]float64{MetricMeasurementDurationSeconds: duration})

	return event
}

// backendEffectiveEvent creates an aggregate active-session event.
func backendEffectiveEvent(t *testing.T) Event {
	t.Helper()

	event := newMetricEvent(t, EventBackendEffectiveState, nil, backendLabels(reasonClassOK, reasonClassOK))
	event.Measurements = NewMetricMeasurements(map[string]float64{MetricMeasurementActiveSessions: 3})

	return event
}

// backendHealthEvent creates one backend health state transition.
func backendHealthEvent(t *testing.T) Event {
	t.Helper()

	return newMetricEvent(t, EventBackendHealthTransition, map[string]string{
		testHealthStatusField: metricStatusHealthy,
		testPreviousStatus:    testHealthUnhealthy,
	}, backendLabels(testResultTransition, metricStatusHealthy))
}

// proxyEvent creates proxy byte and duration measurements.
func proxyEvent(t *testing.T) Event {
	t.Helper()

	event := measuredEvent(t, EventProxyPipe, nil, operationLabels("proxy", reasonClassOK, reasonClassOK), 0.01)
	event.Measurements[MetricMeasurementClientToBackendBytes] = 42
	event.Measurements[MetricMeasurementBackendToClientBytes] = 24

	return event
}

// protocolLabels returns common frontend protocol metric labels.
func protocolLabels(result string, reason string) map[string]string {
	return map[string]string{
		metricLabelBackendPool: testBackendPool,
		metricLabelListener:    testProtocolIMAP,
		metricLabelOperation:   "session",
		metricLabelProtocol:    testProtocolIMAP,
		metricLabelReasonClass: reason,
		metricLabelResult:      result,
		metricLabelService:     "mail",
		metricLabelTLSMode:     "starttls",
	}
}

// backendLabels returns bounded backend metric labels.
func backendLabels(result string, reason string) map[string]string {
	return map[string]string{
		metricLabelBackendPool: testBackendPool,
		metricLabelOperation:   "backend_select",
		metricLabelProtocol:    testProtocolIMAP,
		metricLabelReasonClass: reason,
		metricLabelResult:      result,
		metricLabelShardTag:    testBackendShardTag,
	}
}

// authLabels returns bounded Nauthilus auth metric labels.
func authLabels(result string, reason string) map[string]string {
	labels := protocolLabels(result, reason)
	labels[metricLabelMechanism] = testMechanismPlain
	labels[metricLabelTransport] = "http"

	return labels
}

// backendAuthLabelsForTest returns bounded backend auth metric labels.
func backendAuthLabelsForTest(result string, reason string) map[string]string {
	labels := backendLabels(result, reason)
	labels[metricLabelMechanism] = testMechanismPlain

	return labels
}

// operationLabels returns generic runtime operation labels.
func operationLabels(operation string, result string, reason string) map[string]string {
	return map[string]string{
		metricLabelOperation:   operation,
		metricLabelReasonClass: reason,
		metricLabelResult:      result,
	}
}

// maintenanceLabels returns backend maintenance and drain labels.
func maintenanceLabels(operation string, result string, reason string, mode string) map[string]string {
	labels := operationLabels(operation, result, reason)
	labels[metricLabelMaintenanceMode] = mode

	return labels
}

// redisOperationLabels returns bounded Redis operation labels.
func redisOperationLabels() map[string]string {
	return map[string]string{
		metricLabelOperation:   testRedisOpen,
		metricLabelReasonClass: reasonClassOK,
		metricLabelRedisMode:   "standalone",
		metricLabelResult:      reasonClassOK,
	}
}

// restRequestLabels returns generated REST route metric labels.
func restRequestLabels() map[string]string {
	return map[string]string{
		metricLabelMethod:      "GET",
		metricLabelOperation:   "GetVersion",
		metricLabelResult:      reasonClassOK,
		metricLabelRoute:       "/api/v1/version",
		metricLabelStatusClass: "2xx",
	}
}
