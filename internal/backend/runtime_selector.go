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
	"time"
)

// RuntimeSelector chooses backends from config overlaid with Redis runtime state.
type RuntimeSelector struct {
	registry  Registry
	snapshots RuntimeSnapshotReader
	policy    SelectionPolicy
	now       func() time.Time
}

// NewRuntimeSelector creates a selector that consumes runtime, health and limit state.
func NewRuntimeSelector(registry Registry, snapshots RuntimeSnapshotReader, policy SelectionPolicy) (*RuntimeSelector, error) {
	if registry == nil {
		return nil, newBackendError(ErrorKindConfig, "runtime_selector", "registry required", nil)
	}

	return &RuntimeSelector{
		registry:  registry,
		snapshots: snapshots,
		policy:    policy.Normalize(),
		now:       time.Now,
	}, nil
}

// WithClock replaces the selector clock for deterministic health freshness tests.
func (s *RuntimeSelector) WithClock(clock func() time.Time) *RuntimeSelector {
	if s != nil && clock != nil {
		s.now = clock
	}

	return s
}

// Explain maps logical routing facts to candidates and a runtime-aware backend.
func (s *RuntimeSelector) Explain(ctx context.Context, request SelectionRequest) (SelectionExplanation, error) {
	if s == nil || s.registry == nil {
		return SelectionExplanation{}, newBackendError(ErrorKindConfig, "runtime_selector", "selector unavailable", nil)
	}

	request = s.normalizeSelectionRequest(request)
	if err := validateOperatorBackendPinTarget(ctx, s.registry, "runtime_selector", request); err != nil {
		return SelectionExplanation{Request: request}, err
	}

	effective, candidateCount, err := s.explanationCandidates(ctx, request)
	if err != nil {
		return SelectionExplanation{Request: request, EffectiveBackends: effective}, err
	}

	explanation := SelectionExplanation{
		Request:           request,
		EffectiveBackends: effective,
	}

	if request.OperatorBackendIdentifier != "" {
		result, err := selectOperatorBackendPin("runtime_selector", request, effective)
		explanation.Result = result

		return explanation, err
	}

	if request.ActiveAffinity && request.PinnedBackendIdentifier != "" {
		result, err := s.selectPinnedOrFailover(request, effective)
		explanation.Result = result

		return explanation, err
	}

	eligible := eligibleEffectiveBackends(effective, request.ActiveAffinity)
	if len(eligible) == 0 {
		return explanation, newBackendError(ErrorKindNoBackend, "runtime_selector", "no eligible "+formatBackendCount(candidateCount), nil)
	}

	selected := selectRendezvousBackend(request, eligible)

	explanation.Result = SelectionResult{
		Backend:          selected.Backend,
		EffectiveBackend: selected,
		Reason:           selectionReason(request.ActiveAffinity),
		Generation:       selected.Generation,
		ActiveAffinity:   request.ActiveAffinity,
	}

	return explanation, nil
}

// explanationCandidates validates selector context and builds effective candidates.
func (s *RuntimeSelector) explanationCandidates(
	ctx context.Context,
	request SelectionRequest,
) ([]EffectiveBackendState, int, error) {
	if err := validateSelectionRequest(request); err != nil {
		return nil, 0, err
	}

	pool, err := s.registry.Pool(ctx, request.BackendPool)
	if err != nil {
		return nil, 0, err
	}

	if pool.Protocol != request.Protocol {
		return nil, 0, newBackendError(ErrorKindAmbiguous, "runtime_selector", "listener pool protocol mismatch", nil)
	}

	if !selectorSupportedForProtocol(pool.Selector, request.Protocol) {
		return nil, 0, newBackendError(ErrorKindConfig, "runtime_selector", "unsupported selector", nil)
	}

	candidates, err := s.registry.BackendsForShard(ctx, RegistryRequest{
		Protocol:    request.Protocol,
		BackendPool: request.BackendPool,
		ShardTag:    request.ShardTag,
	})
	if err != nil {
		return nil, 0, err
	}

	effective, err := s.effectiveBackends(ctx, candidates)
	if err != nil {
		return effective, len(candidates), err
	}

	return effective, len(candidates), nil
}

// Select maps logical routing facts to a runtime-aware concrete backend.
func (s *RuntimeSelector) Select(ctx context.Context, request SelectionRequest) (SelectionResult, error) {
	explanation, err := s.Explain(ctx, request)
	if err != nil {
		return SelectionResult{}, err
	}

	return explanation.Result, nil
}

// RetryAfterAttachFailure selects another eligible backend in the same effective shard.
func (s *RuntimeSelector) RetryAfterAttachFailure(ctx context.Context, request SelectionRequest, failedBackend string) (SelectionResult, error) {
	request = s.normalizeSelectionRequest(request)
	if request.OperatorBackendIdentifier != "" {
		return SelectionResult{}, newBackendError(ErrorKindNoBackend, "runtime_selector", "operator backend pin retry disabled", nil)
	}

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

	filtered := make([]EffectiveBackendState, 0, len(effective))
	for _, candidate := range effective {
		if candidate.Identifier == failedBackend {
			continue
		}

		if candidate.Eligible(request.ActiveAffinity) {
			filtered = append(filtered, candidate)
		}
	}

	if len(filtered) == 0 {
		return SelectionResult{}, newBackendError(ErrorKindNoBackend, "runtime_selector", "no retry backend in shard", nil)
	}

	selected := selectRendezvousBackend(request, filtered)

	return SelectionResult{
		Backend:          selected.Backend,
		EffectiveBackend: selected,
		Reason:           "attach_retry",
		Generation:       selected.Generation,
		ActiveAffinity:   request.ActiveAffinity,
	}, nil
}

// normalizeSelectionRequest trims, canonicalizes and defaults selector input.
func (s *RuntimeSelector) normalizeSelectionRequest(request SelectionRequest) SelectionRequest {
	return normalizeSelectionRequestWithDefault(request, s.policy.DefaultShard)
}

// effectiveBackends builds runtime-overlaid candidates in deterministic order.
func (s *RuntimeSelector) effectiveBackends(ctx context.Context, candidates []Backend) ([]EffectiveBackendState, error) {
	effective := make([]EffectiveBackendState, 0, len(candidates))
	now := s.currentTime()
	policy := s.policy.EffectiveBackend
	policy.EnforceHealth = policy.EnforceHealth && s.healthEnforced(now)

	for _, candidate := range candidates {
		snapshot, err := s.backendSnapshot(ctx, candidate.Identifier)
		if err != nil {
			return nil, err
		}

		state, err := NewEffectiveBackendState(EffectiveBackendInput{
			Backend:         candidate,
			RuntimeOverride: snapshot.RuntimeOverride,
			Health:          snapshot.Health,
			ActiveSessions:  snapshot.ActiveSessions,
			Policy:          policy,
			Now:             now,
		})
		if err != nil {
			return nil, err
		}

		effective = append(effective, state)
	}

	return effective, nil
}

// backendSnapshot reads runtime state or returns config-only defaults.
func (s *RuntimeSelector) backendSnapshot(ctx context.Context, identifier string) (RuntimeSnapshot, error) {
	if s.snapshots == nil {
		return RuntimeSnapshot{}, nil
	}

	return s.snapshots.BackendSnapshot(ctx, identifier)
}

// selectPinnedOrFailover preserves active backend pins unless explicit policy allows movement.
func (s *RuntimeSelector) selectPinnedOrFailover(request SelectionRequest, candidates []EffectiveBackendState) (SelectionResult, error) {
	var (
		pinned EffectiveBackendState
		found  bool
	)

	for _, candidate := range candidates {
		if candidate.Identifier == request.PinnedBackendIdentifier {
			pinned = candidate
			found = true

			break
		}
	}

	if !found {
		return SelectionResult{}, newBackendError(ErrorKindNoBackend, "runtime_selector", "active pin backend not in effective shard", nil)
	}

	if pinned.Eligible(true) {
		return SelectionResult{
			Backend:          pinned.Backend,
			EffectiveBackend: pinned,
			Reason:           "active_affinity_pin",
			Generation:       pinned.Generation,
			ActiveAffinity:   true,
		}, nil
	}

	if !s.failoverAllowed(pinned) {
		return SelectionResult{}, newBackendError(ErrorKindNoBackend, "runtime_selector", "active pin excluded and failover disabled", nil)
	}

	eligible := eligibleEffectiveBackends(candidates, true)
	if len(eligible) == 0 {
		return SelectionResult{}, newBackendError(ErrorKindNoBackend, "runtime_selector", "no same-shard failover backend", nil)
	}

	selected := selectRendezvousBackend(request, eligible)

	return SelectionResult{
		Backend:          selected.Backend,
		EffectiveBackend: selected,
		Reason:           "active_affinity_failover",
		Generation:       selected.Generation,
		ActiveAffinity:   true,
	}, nil
}

// failoverAllowed checks explicit hard-down and hard-maintenance movement policy.
func (s *RuntimeSelector) failoverAllowed(state EffectiveBackendState) bool {
	if state.HasExclusion(EffectiveExclusionStaticHardMaintenance) || state.HasExclusion(EffectiveExclusionRuntimeHardMaintenance) {
		return s.policy.AllowHardMaintenanceMove
	}

	if state.HasExclusion(EffectiveExclusionHealth) {
		return s.policy.AllowHardDownFailover
	}

	return false
}

// healthEnforced reports whether startup grace has elapsed for health-enabled backends.
func (s *RuntimeSelector) healthEnforced(now time.Time) bool {
	if s.policy.HealthEnforcementStartedAt.IsZero() {
		return true
	}

	return !now.Before(s.policy.HealthEnforcementStartedAt.Add(s.policy.HealthStartupGrace))
}

// currentTime returns the selector clock in UTC.
func (s *RuntimeSelector) currentTime() time.Time {
	if s.now == nil {
		return time.Now().UTC()
	}

	return s.now().UTC()
}

// eligibleEffectiveBackends filters candidates for one placement mode.
func eligibleEffectiveBackends(candidates []EffectiveBackendState, activeAffinity bool) []EffectiveBackendState {
	eligible := make([]EffectiveBackendState, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Eligible(activeAffinity) {
			eligible = append(eligible, candidate)
		}
	}

	return eligible
}
