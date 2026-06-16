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

package backend

import (
	"context"
	"strings"
)

const (
	// SelectionReasonBackendBinding reports exact backend-node binding reuse.
	SelectionReasonBackendBinding = "backend_binding"
	// SelectionReasonBindingInvalidatedHardDown reports health-authoritative backend-node failover.
	SelectionReasonBindingInvalidatedHardDown = "binding_invalidated_hard_down"
	// SelectionReasonOperatorBackendPin reports an explicit operator backend pin.
	SelectionReasonOperatorBackendPin = selectionReasonOperatorBackendPin
)

// NodeSelectionRequest resolves a protocol endpoint inside a bound backend node.
type NodeSelectionRequest struct {
	AccountKey                string
	Tenant                    string
	ShardTag                  string
	BackendNode               string
	Protocol                  string
	BackendPool               string
	OperatorBackendIdentifier string
}

// SelectInBackendNode resolves one backend-node-local endpoint with static policy.
func (s *StaticSelector) SelectInBackendNode(ctx context.Context, request NodeSelectionRequest) (SelectionResult, error) {
	if s == nil || s.registry == nil {
		return SelectionResult{}, newBackendError(ErrorKindConfig, "selector", "selector unavailable", nil)
	}

	request = normalizeNodeSelectionRequestWithDefault(request, s.policy.DefaultShard)
	if err := validateNodeSelectionRequest(request); err != nil {
		return SelectionResult{}, err
	}

	entry, err := lookupBackendNodeEntry(ctx, s.registry, "selector", request)
	if err != nil {
		return SelectionResult{}, err
	}

	effective, err := s.effectiveBackends([]Backend{entry})
	if err != nil {
		return SelectionResult{}, err
	}

	return selectBackendNodeEntry("selector", request, effective[0], true)
}

// SelectInBackendNode resolves one backend-node-local endpoint with runtime policy.
func (s *RuntimeSelector) SelectInBackendNode(ctx context.Context, request NodeSelectionRequest) (SelectionResult, error) {
	if s == nil || s.registry == nil {
		return SelectionResult{}, newBackendError(ErrorKindConfig, "runtime_selector", "selector unavailable", nil)
	}

	request = normalizeNodeSelectionRequestWithDefault(request, s.policy.DefaultShard)
	if err := validateNodeSelectionRequest(request); err != nil {
		return SelectionResult{}, err
	}

	entry, err := lookupBackendNodeEntry(ctx, s.registry, "runtime_selector", request)
	if err != nil {
		return SelectionResult{}, err
	}

	effective, err := s.effectiveBackends(ctx, []Backend{entry})
	if err != nil {
		return SelectionResult{}, err
	}

	result, err := selectBackendNodeEntry("runtime_selector", request, effective[0], true)
	if err == nil {
		return result, nil
	}

	if request.OperatorBackendIdentifier != "" {
		return SelectionResult{}, err
	}

	if !s.backendNodeFailoverAllowed(effective[0]) {
		return SelectionResult{}, err
	}

	return s.selectBackendNodeFailover(ctx, request, effective[0].Backend.BackendNode)
}

// normalizeNodeSelectionRequestWithDefault trims and defaults backend-node selection input.
func normalizeNodeSelectionRequestWithDefault(request NodeSelectionRequest, defaultShard string) NodeSelectionRequest {
	request.AccountKey = strings.TrimSpace(request.AccountKey)
	request.Tenant = strings.TrimSpace(request.Tenant)

	request.ShardTag = strings.TrimSpace(request.ShardTag)
	if request.ShardTag == "" {
		request.ShardTag = strings.TrimSpace(defaultShard)
	}

	request.BackendNode = strings.TrimSpace(request.BackendNode)
	request.Protocol = normalizeProtocol(request.Protocol)
	request.BackendPool = strings.TrimSpace(request.BackendPool)
	request.OperatorBackendIdentifier = strings.TrimSpace(request.OperatorBackendIdentifier)

	return request
}

// validateNodeSelectionRequest rejects incomplete backend-node selection input.
func validateNodeSelectionRequest(request NodeSelectionRequest) error {
	if request.AccountKey == "" {
		return newBackendError(ErrorKindInvalidRequest, "backend_node_selector", "account key required", nil)
	}

	if request.Tenant == "" {
		return newBackendError(ErrorKindInvalidRequest, "backend_node_selector", "tenant required", nil)
	}

	if request.ShardTag == "" {
		return newBackendError(ErrorKindInvalidRequest, "backend_node_selector", "shard tag required", nil)
	}

	if request.BackendNode == "" {
		return newBackendError(ErrorKindInvalidRequest, "backend_node_selector", "backend node required", nil)
	}

	if !selectionProtocolSupported(request.Protocol) {
		return newBackendError(ErrorKindInvalidRequest, "backend_node_selector", "supported protocol required", nil)
	}

	if request.BackendPool == "" {
		return newBackendError(ErrorKindInvalidRequest, "backend_node_selector", "backend pool required", nil)
	}

	return nil
}

// lookupBackendNodeEntry returns the configured protocol endpoint for a backend node.
func lookupBackendNodeEntry(ctx context.Context, registry Registry, operation string, request NodeSelectionRequest) (Backend, error) {
	entry, err := registry.LookupInBackendNode(ctx, NodeLookupRequest{
		BackendNode: request.BackendNode,
		Protocol:    request.Protocol,
		BackendPool: request.BackendPool,
	})
	if err != nil {
		return Backend{}, err
	}

	facts := entry.PlacementFacts()
	if facts.EffectiveShard != request.ShardTag {
		return Backend{}, newBackendError(ErrorKindAmbiguous, operation, "backend node shard mismatch", nil)
	}

	return entry, nil
}

// selectBackendNodeEntry returns the exact backend-node entry when policy admits it.
func selectBackendNodeEntry(operation string, request NodeSelectionRequest, candidate EffectiveBackendState, allowWeightPin bool) (SelectionResult, error) {
	if request.OperatorBackendIdentifier != "" {
		return selectBackendNodeOperatorPin(operation, request, candidate, allowWeightPin)
	}

	if !backendNodeEntryEligible(candidate) {
		return SelectionResult{}, newBackendError(ErrorKindNoBackend, operation, "backend node entry excluded", nil)
	}

	return SelectionResult{
		Backend:          candidate.Backend,
		EffectiveBackend: candidate,
		Reason:           SelectionReasonBackendBinding,
		Generation:       candidate.Generation,
		ActiveAffinity:   true,
	}, nil
}

// backendNodeEntryEligible applies stricter bound-node reuse safety than active pins.
func backendNodeEntryEligible(candidate EffectiveBackendState) bool {
	if !candidate.AllowsActivePins {
		return false
	}

	for _, exclusion := range candidate.Exclusions {
		switch exclusion.Reason {
		case EffectiveExclusionRuntimeOut, EffectiveExclusionMaxConnections, EffectiveExclusionHealth, EffectiveExclusionAmbiguousState:
			return false
		}
	}

	return true
}

// selectBackendNodeOperatorPin enforces exact target compatibility inside a bound node.
func selectBackendNodeOperatorPin(operation string, request NodeSelectionRequest, candidate EffectiveBackendState, allowWeightPin bool) (SelectionResult, error) {
	if candidate.Identifier != request.OperatorBackendIdentifier {
		return SelectionResult{}, newBackendError(ErrorKindNoBackend, operation, "operator backend pin node mismatch", nil)
	}

	if allowWeightPin {
		if !operatorBackendPinEligible(candidate) {
			return SelectionResult{}, newBackendError(ErrorKindNoBackend, operation, "operator backend pin target excluded", nil)
		}
	} else if !candidate.Eligible(true) {
		return SelectionResult{}, newBackendError(ErrorKindNoBackend, operation, "operator backend pin target excluded", nil)
	}

	return SelectionResult{
		Backend:          candidate.Backend,
		EffectiveBackend: candidate,
		Reason:           SelectionReasonOperatorBackendPin,
		Generation:       candidate.Generation,
		ActiveAffinity:   true,
	}, nil
}

// backendNodeFailoverAllowed permits only health-authoritative hard-down movement.
func (s *RuntimeSelector) backendNodeFailoverAllowed(candidate EffectiveBackendState) bool {
	return s.policy.AllowHardDownFailover &&
		candidate.HasExclusion(EffectiveExclusionHealth) &&
		candidate.Health.Enabled &&
		candidate.Health.Status == HealthStatusUnhealthy
}

// selectBackendNodeFailover selects a different healthy backend node in the shard.
func (s *RuntimeSelector) selectBackendNodeFailover(ctx context.Context, request NodeSelectionRequest, failedNode string) (SelectionResult, error) {
	candidates, err := s.registry.BackendsForShard(ctx, RegistryRequest{
		Protocol:    request.Protocol,
		BackendPool: request.BackendPool,
		ShardTag:    request.ShardTag,
	})
	if err != nil {
		return SelectionResult{}, err
	}

	effective, err := s.effectiveBackends(ctx, candidates)
	if err != nil {
		return SelectionResult{}, err
	}

	eligible := make([]EffectiveBackendState, 0, len(effective))
	for _, candidate := range effective {
		if strings.TrimSpace(candidate.Backend.BackendNode) == strings.TrimSpace(failedNode) {
			continue
		}

		if candidate.Eligible(false) {
			eligible = append(eligible, candidate)
		}
	}

	if len(eligible) == 0 {
		return SelectionResult{}, newBackendError(ErrorKindNoBackend, "runtime_selector", "no healthy backend-node failover target", nil)
	}

	selected := selectRendezvousBackend(SelectionRequest{
		AccountKey:  request.AccountKey,
		Tenant:      request.Tenant,
		ShardTag:    request.ShardTag,
		Protocol:    request.Protocol,
		BackendPool: request.BackendPool,
	}, eligible)

	return SelectionResult{
		Backend:          selected.Backend,
		EffectiveBackend: selected,
		Reason:           SelectionReasonBindingInvalidatedHardDown,
		Generation:       selected.Generation,
		ActiveAffinity:   true,
	}, nil
}
