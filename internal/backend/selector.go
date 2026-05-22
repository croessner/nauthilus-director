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
)

const (
	protocolIMAP           = "imap"
	selectorRendezvousHash = "rendezvous_hash"
)

// SelectionRequest joins logical routing facts with protocol backend context.
type SelectionRequest struct {
	AccountKey     string
	Tenant         string
	ShardTag       string
	Protocol       string
	BackendPool    string
	ActiveAffinity bool
}

// SelectionResult contains the concrete backend chosen after policy checks.
type SelectionResult struct {
	Backend        Backend
	Reason         string
	Generation     string
	ActiveAffinity bool
}

// Selector selects concrete backends after routing facts are known.
type Selector interface {
	Select(ctx context.Context, request SelectionRequest) (SelectionResult, error)
}

// SelectionPolicy configures static maintenance handling for backend selection.
type SelectionPolicy struct {
	SoftAllowsActivePins bool
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

	return &StaticSelector{registry: registry, policy: policy}, nil
}

// Select maps a final shard tag to one concrete IMAP backend.
func (s *StaticSelector) Select(ctx context.Context, request SelectionRequest) (SelectionResult, error) {
	if s == nil || s.registry == nil {
		return SelectionResult{}, newBackendError(ErrorKindConfig, "selector", "selector unavailable", nil)
	}

	request = normalizeSelectionRequest(request)
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

	if strings.TrimSpace(pool.Selector) != selectorRendezvousHash {
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

	eligible := s.eligibleBackends(candidates, request.ActiveAffinity)
	if len(eligible) == 0 {
		return SelectionResult{}, newBackendError(ErrorKindNoBackend, "selector", "no eligible "+formatBackendCount(len(candidates)), nil)
	}

	selected := selectRendezvousBackend(request, eligible)

	return SelectionResult{
		Backend:        selected,
		Reason:         selectionReason(request.ActiveAffinity),
		ActiveAffinity: request.ActiveAffinity,
	}, nil
}

// eligibleBackends applies static maintenance and weight rules.
func (s *StaticSelector) eligibleBackends(backends []Backend, activeAffinity bool) []Backend {
	eligible := make([]Backend, 0, len(backends))
	for _, backend := range backends {
		if backend.MaintenanceMode == MaintenanceModeHard {
			continue
		}

		if backend.MaintenanceMode == MaintenanceModeSoft && (!activeAffinity || !s.policy.SoftAllowsActivePins) {
			continue
		}

		if !activeAffinity && backend.Weight == 0 {
			continue
		}

		eligible = append(eligible, backend)
	}

	return eligible
}

// normalizeSelectionRequest trims and canonicalizes selector input.
func normalizeSelectionRequest(request SelectionRequest) SelectionRequest {
	request.AccountKey = strings.TrimSpace(request.AccountKey)
	request.Tenant = strings.TrimSpace(request.Tenant)
	request.ShardTag = strings.TrimSpace(request.ShardTag)
	request.Protocol = normalizeProtocol(request.Protocol)
	request.BackendPool = strings.TrimSpace(request.BackendPool)

	return request
}

// validateSelectionRequest rejects incomplete or non-IMAP selection input.
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

	if request.Protocol != protocolIMAP {
		return newBackendError(ErrorKindInvalidRequest, "selector", "imap protocol required", nil)
	}

	if request.BackendPool == "" {
		return newBackendError(ErrorKindInvalidRequest, "selector", "backend pool required", nil)
	}

	return nil
}

// selectRendezvousBackend chooses the highest weighted rendezvous score.
func selectRendezvousBackend(request SelectionRequest, backends []Backend) Backend {
	var (
		selected Backend
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
func rendezvousScore(request SelectionRequest, backend Backend) float64 {
	sum := sha256.Sum256([]byte(request.Tenant + "\x00" + request.AccountKey + "\x00" + request.ShardTag + "\x00" + backend.Identifier))
	raw := binary.BigEndian.Uint64(sum[:8])
	unit := (float64(raw) + 1) / (float64(^uint64(0)) + 1)

	weight := backend.Weight
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
