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

package nauthilus

import (
	"context"

	oteltrace "go.opentelemetry.io/otel/trace"
)

const testTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"

// contextWithTestTrace returns a request context that carries a valid upstream trace.
func contextWithTestTrace() context.Context {
	traceID, _ := oteltrace.TraceIDFromHex(testTraceID)
	spanID, _ := oteltrace.SpanIDFromHex("00f067aa0ba902b7")

	return oteltrace.ContextWithRemoteSpanContext(context.Background(), oteltrace.NewSpanContext(oteltrace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: oteltrace.FlagsSampled,
		Remote:     true,
	}))
}
