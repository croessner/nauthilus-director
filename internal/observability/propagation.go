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
	"net/http"
	"strings"

	"go.opentelemetry.io/otel/propagation"
	"google.golang.org/grpc/metadata"
)

// InjectHTTPTraceContext writes the active W3C trace context into outbound HTTP headers.
func InjectHTTPTraceContext(ctx context.Context, headers http.Header) {
	if ctx == nil {
		ctx = context.Background()
	}

	if headers == nil {
		return
	}

	propagation.TraceContext{}.Inject(ctx, propagation.HeaderCarrier(headers))
}

// ContextWithGRPCTraceContext returns an outgoing gRPC context with active W3C trace metadata.
func ContextWithGRPCTraceContext(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}

	existing, _ := metadata.FromOutgoingContext(ctx)
	outgoing := copyGRPCMetadata(existing)
	InjectGRPCTraceContext(ctx, outgoing)

	return metadata.NewOutgoingContext(ctx, outgoing)
}

// InjectGRPCTraceContext writes the active W3C trace context into outbound gRPC metadata.
func InjectGRPCTraceContext(ctx context.Context, md metadata.MD) {
	if ctx == nil {
		ctx = context.Background()
	}

	if md == nil {
		return
	}

	propagation.TraceContext{}.Inject(ctx, grpcMetadataCarrier{md: md})
}

// copyGRPCMetadata returns a mutable copy suitable for outbound propagation.
func copyGRPCMetadata(md metadata.MD) metadata.MD {
	if len(md) == 0 {
		return metadata.MD{}
	}

	return md.Copy()
}

// grpcMetadataCarrier adapts gRPC metadata to the OpenTelemetry text-map carrier.
type grpcMetadataCarrier struct {
	md metadata.MD
}

// Get returns the first metadata value for the normalized key.
func (c grpcMetadataCarrier) Get(key string) string {
	values := c.md.Get(strings.ToLower(strings.TrimSpace(key)))
	if len(values) == 0 {
		return ""
	}

	return values[0]
}

// Set replaces metadata values for the normalized key.
func (c grpcMetadataCarrier) Set(key string, value string) {
	normalized := strings.ToLower(strings.TrimSpace(key))
	if normalized == "" {
		return
	}

	c.md.Set(normalized, value)
}

// Keys returns all metadata keys currently carried by the map.
func (c grpcMetadataCarrier) Keys() []string {
	keys := make([]string, 0, len(c.md))
	for key := range c.md {
		keys = append(keys, key)
	}

	return keys
}
