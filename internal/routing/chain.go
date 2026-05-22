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

package routing

import "context"

// ChainResolver tries resolvers in order until a complete logical result exists.
type ChainResolver struct {
	resolvers []RoutingResolver
}

// NewChainResolver creates an ordered resolver chain.
func NewChainResolver(resolvers ...RoutingResolver) (*ChainResolver, error) {
	if len(resolvers) == 0 {
		return nil, configError("chain", "at least one resolver required")
	}

	for _, resolver := range resolvers {
		if resolver == nil {
			return nil, configError("chain", "nil resolver")
		}
	}

	return &ChainResolver{resolvers: append([]RoutingResolver(nil), resolvers...)}, nil
}

// Resolve returns the first complete result or fails closed on ambiguity.
func (r *ChainResolver) Resolve(ctx context.Context, request RoutingRequest) (RoutingResult, error) {
	var lastErr error

	for _, resolver := range r.resolvers {
		result, err := resolver.Resolve(ctx, request)
		if err == nil {
			if result.Complete() {
				return result.Clone(), nil
			}

			return RoutingResult{}, missingFactError(result.RoutingSource, "routing_result")
		}

		if !IsErrorKind(err, ErrorKindMissingFact) {
			return RoutingResult{}, err
		}

		lastErr = err
		request = request.withPartialResult(result)
	}

	return RoutingResult{}, lastErr
}

// withPartialResult carries safe partial facts into fallback resolvers.
func (r RoutingRequest) withPartialResult(result RoutingResult) RoutingRequest {
	if trimValue(r.NormalizedAccount) == "" && trimValue(result.AccountKey) != "" {
		r.NormalizedAccount = result.AccountKey
	}

	if trimValue(r.Tenant) == "" && trimValue(result.Tenant) != "" {
		r.Tenant = result.Tenant
	}

	return r
}
