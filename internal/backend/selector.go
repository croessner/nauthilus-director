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
	"crypto/sha256"
	"encoding/binary"
	"math"
	"strings"
	"time"
)

const (
	protocolIMAP                      = "imap"
	protocolLMTP                      = "lmtp"
	selectorDefaultShard              = "default"
	selectorRecipientHash             = "recipient_hash"
	selectorRendezvousHash            = "rendezvous_hash"
	selectionReasonOperatorBackendPin = "operator_backend_pin"
)

// SelectionRequest joins logical routing facts with protocol backend context.
type SelectionRequest struct {
	AccountKey                string
	Tenant                    string
	ShardTag                  string
	Protocol                  string
	BackendPool               string
	ActiveAffinity            bool
	PinnedBackendIdentifier   string
	OperatorBackendIdentifier string
}

// SelectionResult contains the concrete backend chosen after policy checks.
type SelectionResult struct {
	Backend          Backend
	EffectiveBackend EffectiveBackendState
	Reason           string
	Generation       string
	ActiveAffinity   bool
}

// SelectionExplanation describes selector input, candidates and the selected result.
type SelectionExplanation struct {
	Request           SelectionRequest
	EffectiveBackends []EffectiveBackendState
	Result            SelectionResult
}

// Selector selects concrete backends after routing facts are known.
type Selector interface {
	Select(ctx context.Context, request SelectionRequest) (SelectionResult, error)
}

// ExplainingSelector selects backends and returns the effective candidate view.
type ExplainingSelector interface {
	Selector
	Explain(ctx context.Context, request SelectionRequest) (SelectionExplanation, error)
}

// SelectionPolicy configures static maintenance handling for backend selection.
type SelectionPolicy struct {
	SoftAllowsActivePins       bool
	DefaultShard               string
	EffectiveBackend           EffectiveBackendPolicy
	AllowHardDownFailover      bool
	AllowHardMaintenanceMove   bool
	HealthStartupGrace         time.Duration
	HealthEnforcementStartedAt time.Time
}

// StaticSelector chooses static config-backed IMAP backends.
type StaticSelector struct {
	registry Registry
	policy   SelectionPolicy
}

// NewStaticSelector creates a backend selector over a static registry.
func NewStaticSelector(registry Registry, policy SelectionPolicy) (*StaticSelector, error) {
	if registry == nil {
		return nil, newBackendError(ErrorKindConfig, "selector", "registry required", nil)
	}

	return &StaticSelector{registry: registry, policy: policy.Normalize()}, nil
}

// Select maps a final shard tag to one concrete protocol backend.
func (s *StaticSelector) Select(ctx context.Context, request SelectionRequest) (SelectionResult, error) {
	if s == nil || s.registry == nil {
		return SelectionResult{}, newBackendError(ErrorKindConfig, "selector", "selector unavailable", nil)
	}

	request = s.normalizeSelectionRequest(request)
	if err := validateSelectionRequest(request); err != nil {
		return SelectionResult{}, err
	}

	pool, err := s.registry.Pool(ctx, request.BackendPool)
	if err != nil {
		return SelectionResult{}, err
	}

	if pool.Protocol != request.Protocol {
		return SelectionResult{}, newBackendError(ErrorKindAmbiguous, "selector", "listener pool protocol mismatch", nil)
	}

	if !selectorSupportedForProtocol(pool.Selector, request.Protocol) {
		return SelectionResult{}, newBackendError(ErrorKindConfig, "selector", "unsupported selector", nil)
	}

	candidates, err := s.registry.BackendsForShard(ctx, RegistryRequest{
		Protocol:    request.Protocol,
		BackendPool: request.BackendPool,
		ShardTag:    request.ShardTag,
	})
	if err != nil {
		return SelectionResult{}, err
	}

	effective, err := s.effectiveBackends(candidates)
	if err != nil {
		return SelectionResult{}, err
	}

	if request.OperatorBackendIdentifier != "" {
		if err := validateOperatorBackendPinTarget(ctx, s.registry, "selector", request); err != nil {
			return SelectionResult{}, err
		}

		return selectOperatorBackendPin("selector", request, effective)
	}

	eligible := eligibleEffectiveBackends(effective, request.ActiveAffinity)
	if len(eligible) == 0 {
		return SelectionResult{}, newBackendError(ErrorKindNoBackend, "selector", "no eligible "+formatBackendCount(len(candidates)), nil)
	}

	selected := selectRendezvousBackend(request, eligible)

	return SelectionResult{
		Backend:          selected.Backend,
		EffectiveBackend: selected,
		Reason:           selectionReason(request.ActiveAffinity),
		ActiveAffinity:   request.ActiveAffinity,
	}, nil
}

// effectiveBackends applies static maintenance and weight rules without selecting.
func (s *StaticSelector) effectiveBackends(backends []Backend) ([]EffectiveBackendState, error) {
	effectiveBackends := make([]EffectiveBackendState, 0, len(backends))
	for _, candidate := range backends {
		effective, err := NewEffectiveBackendState(EffectiveBackendInput{
			Backend: candidate,
			Policy:  s.policy.EffectiveBackend,
		})
		if err != nil {
			return nil, err
		}

		effectiveBackends = append(effectiveBackends, effective)
	}

	return effectiveBackends, nil
}

// Normalize applies safe defaults to selection policy.
func (p SelectionPolicy) Normalize() SelectionPolicy {
	p.DefaultShard = strings.TrimSpace(p.DefaultShard)
	if p.DefaultShard == "" {
		p.DefaultShard = selectorDefaultShard
	}

	p.EffectiveBackend = p.EffectiveBackend.Normalize()
	p.EffectiveBackend.SoftAllowsActivePins = p.SoftAllowsActivePins
	if p.HealthStartupGrace < 0 {
		p.HealthStartupGrace = 0
	}

	return p
}

// normalizeSelectionRequest trims, canonicalizes and defaults selector input.
func (s *StaticSelector) normalizeSelectionRequest(request SelectionRequest) SelectionRequest {
	return normalizeSelectionRequestWithDefault(request, s.policy.DefaultShard)
}

// normalizeSelectionRequestWithDefault trims, canonicalizes and defaults selector input.
func normalizeSelectionRequestWithDefault(request SelectionRequest, defaultShard string) SelectionRequest {
	request.AccountKey = strings.TrimSpace(request.AccountKey)
	request.Tenant = strings.TrimSpace(request.Tenant)
	request.ShardTag = strings.TrimSpace(request.ShardTag)
	if request.ShardTag == "" {
		request.ShardTag = defaultShard
	}

	request.Protocol = normalizeProtocol(request.Protocol)
	request.BackendPool = strings.TrimSpace(request.BackendPool)
	request.PinnedBackendIdentifier = strings.TrimSpace(request.PinnedBackendIdentifier)
	request.OperatorBackendIdentifier = strings.TrimSpace(request.OperatorBackendIdentifier)

	return request
}

// validateSelectionRequest rejects incomplete or unsupported selection input.
func validateSelectionRequest(request SelectionRequest) error {
	if request.AccountKey == "" {
		return newBackendError(ErrorKindInvalidRequest, "selector", "account key required", nil)
	}

	if request.Tenant == "" {
		return newBackendError(ErrorKindInvalidRequest, "selector", "tenant required", nil)
	}

	if request.ShardTag == "" {
		return newBackendError(ErrorKindInvalidRequest, "selector", "shard tag required", nil)
	}

	if !selectionProtocolSupported(request.Protocol) {
		return newBackendError(ErrorKindInvalidRequest, "selector", "supported protocol required", nil)
	}

	if request.BackendPool == "" {
		return newBackendError(ErrorKindInvalidRequest, "selector", "backend pool required", nil)
	}

	return nil
}

// selectorSupportedForProtocol reports whether a configured selector is valid for the protocol.
func selectorSupportedForProtocol(selector string, protocol string) bool {
	switch strings.TrimSpace(selector) {
	case selectorRendezvousHash:
		return protocol == protocolIMAP || protocol == protocolLMTP
	case selectorRecipientHash:
		return protocol == protocolLMTP
	default:
		return false
	}
}

// selectionProtocolSupported reports whether the selector knows the protocol.
func selectionProtocolSupported(protocol string) bool {
	switch protocol {
	case protocolIMAP, protocolLMTP:
		return true
	default:
		return false
	}
}

// validateOperatorBackendPinTarget checks that a requested operator target is in scope.
func validateOperatorBackendPinTarget(ctx context.Context, registry Registry, operation string, request SelectionRequest) error {
	if request.OperatorBackendIdentifier == "" {
		return nil
	}

	if registry == nil {
		return newBackendError(ErrorKindConfig, operation, "registry required", nil)
	}

	target, err := registry.Lookup(ctx, request.OperatorBackendIdentifier)
	if err != nil {
		return err
	}

	facts := target.PlacementFacts()
	if facts.Protocol != request.Protocol {
		return newBackendError(ErrorKindNoBackend, operation, "operator backend pin protocol mismatch", nil)
	}

	if facts.BackendPool != request.BackendPool {
		return newBackendError(ErrorKindNoBackend, operation, "operator backend pin pool mismatch", nil)
	}

	if facts.EffectiveShard != request.ShardTag {
		return newBackendError(ErrorKindNoBackend, operation, "operator backend pin shard mismatch", nil)
	}

	return nil
}

// selectOperatorBackendPin returns only the explicitly targeted backend.
func selectOperatorBackendPin(operation string, request SelectionRequest, candidates []EffectiveBackendState) (SelectionResult, error) {
	for _, candidate := range candidates {
		if candidate.Identifier != request.OperatorBackendIdentifier {
			continue
		}

		if !operatorBackendPinEligible(candidate) {
			return SelectionResult{}, newBackendError(ErrorKindNoBackend, operation, "operator backend pin target excluded", nil)
		}

		return SelectionResult{
			Backend:          candidate.Backend,
			EffectiveBackend: candidate,
			Reason:           selectionReasonOperatorBackendPin,
			Generation:       candidate.Generation,
			ActiveAffinity:   request.ActiveAffinity,
		}, nil
	}

	return SelectionResult{}, newBackendError(ErrorKindNoBackend, operation, "operator backend pin target missing from effective shard", nil)
}

// operatorBackendPinEligible allows only the explicit weight-zero commissioning bypass.
func operatorBackendPinEligible(candidate EffectiveBackendState) bool {
	for _, exclusion := range candidate.Exclusions {
		if exclusion.Reason != EffectiveExclusionWeightZero {
			return false
		}
	}

	return true
}

// selectRendezvousBackend chooses the highest weighted rendezvous score.
func selectRendezvousBackend(request SelectionRequest, backends []EffectiveBackendState) EffectiveBackendState {
	var (
		selected EffectiveBackendState
		best     float64
	)

	for index, backend := range backends {
		score := rendezvousScore(request, backend)
		if index == 0 || score > best || (score == best && backend.Identifier < selected.Identifier) {
			selected = backend
			best = score
		}
	}

	return selected
}

// rendezvousScore returns a deterministic score without exposing account input.
func rendezvousScore(request SelectionRequest, backend EffectiveBackendState) float64 {
	sum := sha256.Sum256([]byte(request.Tenant + "\x00" + request.AccountKey + "\x00" + request.ShardTag + "\x00" + backend.Identifier))
	raw := binary.BigEndian.Uint64(sum[:8])
	unit := (float64(raw) + 1) / (float64(^uint64(0)) + 1)

	weight := backend.EffectiveWeight
	if weight <= 0 {
		weight = 1
	}

	return math.Pow(unit, 1/float64(weight))
}

// selectionReason records why the selector admitted the chosen backend.
func selectionReason(activeAffinity bool) string {
	if activeAffinity {
		return "active_affinity"
	}

	return "initial_placement"
}
