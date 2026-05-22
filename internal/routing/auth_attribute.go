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

import (
	"context"
	"time"

	"github.com/croessner/nauthilus-director/internal/observability"
)

// AuthAttributeResolverConfig names the auth attributes used as routing facts.
type AuthAttributeResolverConfig struct {
	AccountKeyAttribute string
	TenantAttribute     string
	ShardTagAttribute   string
	AllowFirstValue     bool
	Sticky              bool
	TTL                 time.Duration
}

// AuthAttributeResolver resolves routing facts from authenticated attributes.
type AuthAttributeResolver struct {
	config AuthAttributeResolverConfig
}

// NewAuthAttributeResolver creates an auth-attribute resolver.
func NewAuthAttributeResolver(config AuthAttributeResolverConfig) (*AuthAttributeResolver, error) {
	if trimValue(config.ShardTagAttribute) == "" {
		return nil, configError(SourceAuthAttribute, "shard tag attribute required")
	}

	return &AuthAttributeResolver{config: config}, nil
}

// Resolve reads configured singular routing facts from auth attributes.
func (r *AuthAttributeResolver) Resolve(_ context.Context, request RoutingRequest) (RoutingResult, error) {
	accountKey, err := r.resolveAccountKey(request)
	if err != nil {
		return RoutingResult{}, err
	}

	tenant, err := r.resolveTenant(request)
	if err != nil {
		return RoutingResult{}, err
	}

	result := RoutingResult{
		AccountKey:    accountKey,
		Tenant:        tenant,
		RoutingSource: SourceAuthAttribute,
		Sticky:        r.config.Sticky,
		TTL:           r.config.TTL,
		Attributes:    safeAttributes(request.AuthAttributes),
	}

	shardTag, ok, err := r.resolveAttribute(request.AuthAttributes, r.config.ShardTagAttribute, "shard_tag")
	if err != nil {
		return RoutingResult{}, err
	}

	if !ok {
		return result, missingFactError(SourceAuthAttribute, "shard_tag")
	}

	result.ShardTag = shardTag

	return result, nil
}

// resolveAccountKey determines the logical account key.
func (r *AuthAttributeResolver) resolveAccountKey(request RoutingRequest) (string, error) {
	accountKey, ok, err := r.resolveAttribute(request.AuthAttributes, r.config.AccountKeyAttribute, "account_key")
	if err != nil {
		return "", err
	}

	if ok {
		return accountKey, nil
	}

	accountKey = trimValue(request.NormalizedAccount)
	if accountKey == "" {
		return "", missingFactError(SourceAuthAttribute, "account_key")
	}

	return accountKey, nil
}

// resolveTenant determines the logical tenant.
func (r *AuthAttributeResolver) resolveTenant(request RoutingRequest) (string, error) {
	tenant, ok, err := r.resolveAttribute(request.AuthAttributes, r.config.TenantAttribute, "tenant")
	if err != nil {
		return "", err
	}

	if ok {
		return tenant, nil
	}

	tenant = trimValue(request.Tenant)
	if tenant == "" {
		return "", missingFactError(SourceAuthAttribute, "tenant")
	}

	return tenant, nil
}

// resolveAttribute extracts one configured singular attribute.
func (r *AuthAttributeResolver) resolveAttribute(
	attributes map[string][]string,
	attributeName string,
	field string,
) (string, bool, error) {
	if trimValue(attributeName) == "" {
		return "", false, nil
	}

	values := nonEmptyValues(attributes[attributeName])
	switch {
	case len(values) == 0:
		return "", false, nil
	case len(values) == 1 || r.config.AllowFirstValue:
		return values[0], true, nil
	default:
		return "", false, ambiguousFactError(SourceAuthAttribute, field)
	}
}

// nonEmptyValues trims empty attribute values before singular validation.
func nonEmptyValues(values []string) []string {
	trimmed := make([]string, 0, len(values))
	for _, value := range values {
		value = trimValue(value)
		if value != "" {
			trimmed = append(trimmed, value)
		}
	}

	return trimmed
}

// safeAttributes copies only route-explanation attributes allowed by policy.
func safeAttributes(attributes map[string][]string) map[string][]string {
	safe := make(map[string][]string)

	for name, values := range attributes {
		if !observability.IsSafeRoutingAttribute(name) {
			continue
		}

		copied := nonEmptyValues(values)
		if len(copied) > 0 {
			safe[name] = copied
		}
	}

	if len(safe) == 0 {
		return nil
	}

	return safe
}
