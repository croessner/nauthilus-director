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

package state

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/observability"
)

const (
	redisObservationFieldOperation   = "operation"
	redisObservationFieldReasonClass = "reason_class"
	redisObservationFieldRedisMode   = "redis_mode"
	redisObservationFieldResult      = "result"
	redisObservationModeUnknown      = "unknown"
	redisObservationResultFailure    = "failure"
	redisObservationResultOK         = "ok"
	runtimePaginationFieldLimit      = "limit"
	runtimePaginationFieldOperation  = "operation"
	runtimePaginationFieldPageBucket = "page_size_bucket"
	runtimePaginationFieldReason     = "reason_class"
	runtimePaginationFieldResult     = "result"
	runtimePaginationResultEmpty     = "empty"
	runtimePaginationResultMore      = "more"
	runtimePaginationResultPartial   = "partial"
)

type redisStoreOptions struct {
	recorder         observability.Recorder
	redisMode        string
	indexPageDefault int
	indexPageMax     int
}

// RedisSessionStoreOption customizes Redis state-store construction.
type RedisSessionStoreOption func(*redisStoreOptions)

// WithObservabilityRecorder wires Redis operation observations into the runtime recorder.
func WithObservabilityRecorder(recorder observability.Recorder) RedisSessionStoreOption {
	return func(options *redisStoreOptions) {
		options.recorder = observability.NormalizeRecorder(recorder)
	}
}

// WithRedisMode records the configured Redis topology mode as a bounded metric label.
func WithRedisMode(mode string) RedisSessionStoreOption {
	return func(options *redisStoreOptions) {
		options.redisMode = strings.ToLower(strings.TrimSpace(mode))
	}
}

// WithRuntimeIndexPages configures bounded repairable index reads.
func WithRuntimeIndexPages(pageDefault int, pageMax int) RedisSessionStoreOption {
	return func(options *redisStoreOptions) {
		options.indexPageDefault = pageDefault
		options.indexPageMax = pageMax
	}
}

// defaultRedisStoreOptions keeps state-store telemetry disabled unless injected.
func defaultRedisStoreOptions() redisStoreOptions {
	return redisStoreOptions{
		recorder:         observability.NoopRecorder{},
		redisMode:        redisObservationModeUnknown,
		indexPageDefault: 100,
		indexPageMax:     1000,
	}
}

// applyRedisStoreOptions normalizes optional Redis store dependencies.
func applyRedisStoreOptions(options []RedisSessionStoreOption) redisStoreOptions {
	applied := defaultRedisStoreOptions()

	for _, option := range options {
		if option != nil {
			option(&applied)
		}
	}

	applied.recorder = observability.NormalizeRecorder(applied.recorder)
	if strings.TrimSpace(applied.redisMode) == "" {
		applied.redisMode = redisObservationModeUnknown
	}

	if applied.indexPageDefault <= 0 {
		applied.indexPageDefault = 100
	}

	if applied.indexPageMax <= 0 {
		applied.indexPageMax = 1000
	}

	if applied.indexPageDefault > applied.indexPageMax {
		applied.indexPageDefault = applied.indexPageMax
	}

	return applied
}

// recordRedisOperation emits one Redis operation class without raw keys or commands.
func (s *RedisSessionStore) recordRedisOperation(ctx context.Context, operation string, started time.Time, err error) {
	if s == nil {
		return
	}

	result := redisObservationResultOK
	reason := redisObservationResultOK

	if err != nil {
		result = redisObservationResultFailure
		reason = redisReasonClass(err)
	}

	event, eventErr := observability.NewEvent(observability.EventRedisOperation, "", map[string]string{
		redisObservationFieldOperation:   operation,
		redisObservationFieldReasonClass: reason,
		redisObservationFieldRedisMode:   s.redisMode,
		redisObservationFieldResult:      result,
	}, map[string]string{
		redisObservationFieldOperation:   operation,
		redisObservationFieldReasonClass: reason,
		redisObservationFieldRedisMode:   s.redisMode,
		redisObservationFieldResult:      result,
	})
	if eventErr != nil {
		return
	}

	if !started.IsZero() {
		event.Measurements = observability.NewMetricMeasurements(map[string]float64{
			observability.MetricMeasurementDurationSeconds: time.Since(started).Seconds(),
		})
	}

	observability.NormalizeRecorder(s.recorder).Record(ctx, event)
}

// redisReasonClass maps state errors into bounded metric-safe classes.
func redisReasonClass(err error) string {
	var stateErr *RedisStateError
	if errors.As(err, &stateErr) && stateErr.Kind != "" {
		return observability.NormalizeReasonClass(string(stateErr.Kind))
	}

	return "transport"
}

// recordRuntimePagination emits one bounded page-read observation without cursor values.
func (s *RedisSessionStore) recordRuntimePagination(
	ctx context.Context,
	operation string,
	records int,
	limit int,
	hasMore bool,
	started time.Time,
) {
	if s == nil {
		return
	}

	result := runtimePaginationResultPartial

	switch {
	case hasMore:
		result = runtimePaginationResultMore
	case records == 0:
		result = runtimePaginationResultEmpty
	}

	operation = strings.TrimSpace(operation)
	if operation == "" {
		operation = operationRuntimeRead
	}

	fields := map[string]string{
		runtimePaginationFieldLimit:      runtimePaginationLimitBucket(limit),
		runtimePaginationFieldOperation:  operation,
		runtimePaginationFieldPageBucket: runtimePaginationLimitBucket(records),
		runtimePaginationFieldReason:     redisObservationResultOK,
		runtimePaginationFieldResult:     result,
	}
	labels := map[string]string{
		runtimePaginationFieldOperation: operation,
		runtimePaginationFieldReason:    redisObservationResultOK,
		runtimePaginationFieldResult:    result,
	}

	event, err := observability.NewEvent(observability.EventRuntimePagination, "", fields, labels)
	if err != nil {
		return
	}

	if !started.IsZero() {
		event.Measurements = observability.NewMetricMeasurements(map[string]float64{
			observability.MetricMeasurementDurationSeconds: time.Since(started).Seconds(),
		})
	}

	observability.NormalizeRecorder(s.recorder).Record(ctx, event)
}

// runtimePaginationLimitBucket keeps page-size details bounded in logs.
func runtimePaginationLimitBucket(value int) string {
	switch {
	case value <= 0:
		return "0"
	case value <= 10:
		return "1_10"
	case value <= 100:
		return "11_100"
	case value <= 1000:
		return "101_1000"
	default:
		return "gt_1000"
	}
}
