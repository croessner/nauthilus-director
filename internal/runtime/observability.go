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

package runtime

import (
	"context"
	"maps"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/observability"
)

const (
	runtimeObservationOperationBackendEffective = "backend_effective_state"
	runtimeObservationOperationSelectorExclude  = "selector_exclusion"

	runtimeObservationReasonBackendRuntime  = "backend_runtime"
	runtimeObservationReasonBackendPinClear = "backend_pin_clear"
	runtimeObservationReasonBackendPinSet   = "backend_pin_set"
	runtimeObservationReasonCleared         = "cleared"
	runtimeObservationReasonOther           = "other"
	runtimeObservationReasonUserHoldClear   = "user_hold_clear"
	runtimeObservationReasonUserHoldSet     = "user_hold_set"

	runtimeObservationResultEligible   = "eligible"
	runtimeObservationResultExcluded   = "excluded"
	runtimeObservationResultFailClosed = "fail_closed"
	runtimeObservationResultFailure    = "failure"
	runtimeObservationResultOK         = "ok"

	runtimeObservationFieldAccountKeyPresent = "account_key_present"
	runtimeObservationFieldActiveSessions    = "active_sessions"
	runtimeObservationFieldAppliedChanges    = "applied_changes"
	runtimeObservationFieldBackendID         = "backend_identifier"
	runtimeObservationFieldBackendPool       = "backend_pool"
	runtimeObservationFieldExclusionDetail   = "exclusion_detail"
	runtimeObservationFieldExclusionSource   = "exclusion_source"
	runtimeObservationFieldListener          = "listener"
	runtimeObservationFieldMaintenanceMode   = "maintenance_mode"
	runtimeObservationFieldOperation         = "operation"
	runtimeObservationFieldProtocol          = "protocol"
	runtimeObservationFieldReasonClass       = "reason_class"
	runtimeObservationFieldRejectedChanges   = "rejected_changes"
	runtimeObservationFieldResult            = "result"
	runtimeObservationFieldRuntimeGeneration = "runtime_generation"
	runtimeObservationFieldRuntimeStatus     = "runtime_status"
	runtimeObservationFieldSelectedPresent   = "selected_present"
	runtimeObservationFieldServerTime        = "server_time_available"
	runtimeObservationFieldService           = "service"
	runtimeObservationFieldShardTag          = "shard_tag"
	runtimeObservationFieldUserHash          = "user_hash"
)

// ServiceOption customizes runtime control services.
type ServiceOption func(*serviceOptions)

// serviceOptions carries shared runtime service dependencies.
type serviceOptions struct {
	recorder      observability.Recorder
	reloadApplier SafeReloadApplier
}

// WithObservabilityRecorder wires a secret-safe runtime event recorder.
func WithObservabilityRecorder(recorder observability.Recorder) ServiceOption {
	return func(options *serviceOptions) {
		options.recorder = observability.NormalizeRecorder(recorder)
	}
}

// WithSafeReloadApplier wires the live-object apply step for safe reloads.
func WithSafeReloadApplier(applier SafeReloadApplier) ServiceOption {
	return func(options *serviceOptions) {
		options.reloadApplier = applier
	}
}

// applyServiceOptions normalizes optional runtime service configuration.
func applyServiceOptions(options []ServiceOption) serviceOptions {
	applied := serviceOptions{recorder: observability.NoopRecorder{}}

	for _, option := range options {
		if option != nil {
			option(&applied)
		}
	}

	applied.recorder = observability.NormalizeRecorder(applied.recorder)

	return applied
}

// recordRuntimeObservation emits one bounded runtime/control event.
func recordRuntimeObservation(
	ctx context.Context,
	recorder observability.Recorder,
	name string,
	boundary observability.TraceBoundary,
	operation string,
	result string,
	reasonClass string,
	fields map[string]string,
	labels map[string]string,
	duration ...time.Duration,
) {
	operation = strings.TrimSpace(operation)
	result = strings.TrimSpace(result)

	if result == "" {
		result = runtimeObservationResultOK
	}

	if strings.TrimSpace(reasonClass) == "" && result == runtimeObservationResultOK {
		reasonClass = runtimeObservationResultOK
	}

	reasonClass = observability.NormalizeReasonClass(reasonClass)

	eventFields := map[string]string{
		runtimeObservationFieldOperation:   operation,
		runtimeObservationFieldReasonClass: reasonClass,
		runtimeObservationFieldResult:      result,
	}
	maps.Copy(eventFields, fields)

	eventLabels := map[string]string{
		runtimeObservationFieldOperation:   operation,
		runtimeObservationFieldReasonClass: reasonClass,
		runtimeObservationFieldResult:      result,
	}
	maps.Copy(eventLabels, labels)

	event, err := observability.NewEvent(name, boundary, eventFields, eventLabels)
	if err != nil {
		return
	}

	measurements := map[string]float64{}
	if activeSessions, ok := numericObservation(fields, runtimeObservationFieldActiveSessions); ok {
		measurements[observability.MetricMeasurementActiveSessions] = activeSessions
	}

	if len(duration) > 0 && duration[0] > 0 {
		measurements[observability.MetricMeasurementDurationSeconds] = duration[0].Seconds()
	}

	if len(measurements) > 0 {
		event.Measurements = observability.NewMetricMeasurements(measurements)
	}

	observability.NormalizeRecorder(recorder).Record(ctx, event)
}

// numericObservation parses one non-negative observation field.
func numericObservation(fields map[string]string, name string) (float64, bool) {
	value := strings.TrimSpace(fields[name])
	if value == "" {
		return 0, false
	}

	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil || parsed < 0 {
		return 0, false
	}

	return parsed, true
}
