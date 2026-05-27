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

package proxy

import (
	"context"
	"time"

	"github.com/croessner/nauthilus-director/internal/observability"
)

const (
	proxyOperation = "proxy"
	proxyResultOK  = "ok"

	proxyFieldOperation   = "operation"
	proxyFieldReasonClass = "reason_class"
	proxyFieldResult      = "result"
)

// recordProxyStart emits the prepared proxy span start boundary.
func recordProxyStart(ctx context.Context, config PipeConfig) {
	recordProxyEvent(ctx, config, proxyResultOK, "start", 0, Accounting{})
}

// recordProxyEnd emits the terminal proxy result using bounded reason classes.
func recordProxyEnd(ctx context.Context, config PipeConfig, started time.Time, result Result, err error) {
	metricResult := proxyResultOK
	if err != nil {
		metricResult = "failure"
	}

	reason := result.Class

	if reason == "" {
		reason = ResultClientClosed
	}

	recordProxyEvent(ctx, config, metricResult, reason, time.Since(started), result.Accounted)
}

// recordProxyEvent normalizes low-cardinality proxy labels before recording.
func recordProxyEvent(ctx context.Context, config PipeConfig, result string, reason string, duration time.Duration, accounted Accounting) {
	recorder := observability.NormalizeRecorder(config.Observability)

	event, err := observability.NewEvent(observability.EventProxyPipe, observability.TraceBoundaryProxyPipe, map[string]string{
		proxyFieldOperation:   proxyOperation,
		proxyFieldReasonClass: reason,
		proxyFieldResult:      result,
	}, map[string]string{
		proxyFieldOperation:   proxyOperation,
		proxyFieldReasonClass: reason,
		proxyFieldResult:      result,
	})
	if err != nil {
		return
	}

	measurements := map[string]float64{}
	if duration > 0 {
		measurements[observability.MetricMeasurementDurationSeconds] = duration.Seconds()
	}

	if accounted.ClientToBackend > 0 {
		measurements[observability.MetricMeasurementClientToBackendBytes] = float64(accounted.ClientToBackend)
	}

	if accounted.BackendToClient > 0 {
		measurements[observability.MetricMeasurementBackendToClientBytes] = float64(accounted.BackendToClient)
	}

	if len(measurements) > 0 {
		event.Measurements = observability.NewMetricMeasurements(measurements)
	}

	recorder.Record(ctx, event)
}
