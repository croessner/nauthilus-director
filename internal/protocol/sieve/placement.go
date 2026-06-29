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

//nolint:funlen,goconst,wsl_v5 // Placement keeps routing, holds and session lease sequencing visible.
package sieve

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/placement"
	"github.com/croessner/nauthilus-director/internal/protocol/authbinding"
	"github.com/croessner/nauthilus-director/internal/routing"
	runtimectl "github.com/croessner/nauthilus-director/internal/runtime"
	"github.com/croessner/nauthilus-director/internal/state"
)

const (
	defaultSieveSessionLease = time.Minute
	sieveSessionIDBytes      = 16
)

// Placement records the director-owned routing and selection facts for an authenticated session.
type Placement struct {
	AuthResult       nauthilus.AuthResult
	Routing          routing.RoutingResult
	Affinity         state.AffinityRecord
	Backend          backend.SelectionResult
	Binding          placement.BackendBinding
	SelectedShardTag string
}

// Clone returns a detached placement snapshot.
func (p Placement) Clone() Placement {
	p.AuthResult.Attributes = cloneStringSlices(p.AuthResult.Attributes)
	p.Routing = p.Routing.Clone()

	return p
}

// placeAuthenticatedSession resolves routing and opens shared session placement.
func (s *Session) placeAuthenticatedSession(
	ctx context.Context,
	credentials *frontendCredentials,
	result nauthilus.AuthResult,
) error {
	if err := s.ensurePlacementDependencies(); err != nil {
		return err
	}

	routingRequest, err := s.routingRequest(credentials, result)
	if err != nil {
		return err
	}

	routingCtx, routingSpan := s.startObservationSpan(ctx, observability.TraceBoundaryRoutingResolve, sieveObservationOperationRouting, sieveObservationResultStart, "", nil)

	routingStarted := time.Now()
	routingResult, err := s.routingResolver.Resolve(routingCtx, routingRequest)
	routingDuration := time.Since(routingStarted)
	if err != nil {
		s.recordRoutingResolve(routingCtx, sieveObservationResultFailure, sieveReasonRouting, "", "", routingDuration)
		routingSpan.End(sieveObservationResultFailure, sieveReasonRouting)

		return err
	}

	routingResult = s.withEffectiveDefaultShard(routingResult)
	if !routingResult.Complete() {
		s.recordRoutingResolve(routingCtx, sieveObservationResultFailure, sieveReasonIncomplete, routingResult.RoutingSource, routingResult.ShardTag, routingDuration)
		routingSpan.SetAttributes(map[string]string{
			sieveObsFieldRoutingSource: routingResult.RoutingSource,
			sieveObsFieldShardTag:      routingResult.ShardTag,
		})
		routingSpan.End(sieveObservationResultFailure, sieveReasonIncomplete)

		return errors.New("sieve: incomplete routing result")
	}

	routingSpan.SetAttributes(map[string]string{
		sieveObsFieldRoutingSource: routingResult.RoutingSource,
		sieveObsFieldShardTag:      routingResult.ShardTag,
	})
	s.recordRoutingResolve(routingCtx, sieveObservationResultOK, sieveReasonOK, routingResult.RoutingSource, routingResult.ShardTag, routingDuration)
	routingSpan.End(sieveObservationResultOK, sieveReasonOK)

	gateResult, err := s.waitForPlacementGate(ctx, routingResult)
	gateObservationResult, gateReason := holdGateObservation(gateResult, err)
	s.recordPlacementGate(ctx, gateObservationResult, gateReason)
	if err != nil {
		return err
	}

	selectCtx, selectSpan := s.startObservationSpan(ctx, observability.TraceBoundaryBackendSelect, sieveObservationOperationBackendSelect, sieveObservationResultStart, "", map[string]string{
		sieveObsFieldShardTag: routingResult.ShardTag,
	})

	selectStarted := time.Now()
	lease, err := s.placementService.PlaceSession(selectCtx, s.sessionPlacementRequest(routingResult))
	selectDuration := time.Since(selectStarted)
	if err != nil {
		s.recordBackendSelect(selectCtx, sieveObservationResultFailure, sieveReasonClass(err), routingResult.ShardTag, "", selectDuration)
		selectSpan.End(sieveObservationResultFailure, sieveReasonClass(err))

		return err
	}

	affinity := lease.Affinity()
	binding := lease.Binding()
	backendResult := lease.Backend()
	selectedShardTag := binding.ShardTag
	bindingReason := observability.BackendBindingReasonClass(string(binding.Source))

	s.recordAffinityOpen(ctx, sieveObservationResultOK, bindingReason, string(binding.Source), selectedShardTag, binding.BackendNode)
	s.recordSessionAttach(selectCtx, sieveObservationResultOK, bindingReason, backendResult.Backend.Identifier, backendResult.Backend.BackendNode, selectedShardTag)
	s.recordBackendSelect(selectCtx, sieveObservationResultOK, bindingReason, selectedShardTag, backendResult.Backend.BackendNode, selectDuration)
	selectSpan.SetAttributes(map[string]string{
		sieveObsFieldBackendIdentifier: backendResult.Backend.Identifier,
		sieveObsFieldBackendNode:       backendResult.Backend.BackendNode,
		sieveObsFieldShardTag:          selectedShardTag,
	})
	selectSpan.End(sieveObservationResultOK, bindingReason)

	s.placement = Placement{
		AuthResult:       cloneAuthResult(result),
		Routing:          routingResult.Clone(),
		Affinity:         affinity,
		Backend:          backendResult,
		Binding:          binding,
		SelectedShardTag: selectedShardTag,
	}
	s.placementLease = lease
	s.placed = true

	return nil
}

// closePlacedSession releases a shared placement lease before frontend auth succeeds.
func (s *Session) closePlacedSession(ctx context.Context) error {
	if !s.placed {
		return nil
	}

	var err error
	if s.placementLease != nil {
		err = s.placementLease.Close(ctx)
		s.recordSessionClose(ctx, sieveResultLabel(err), sieveCloseReasonClass(err, s.placementLease.Affinity()))
	} else {
		s.recordSessionClose(ctx, sieveResultLabel(err), sieveReasonClass(err))
	}

	s.clearPlacedSession()

	return err
}

// ensurePlacementDependencies verifies that authenticated sessions can continue into placement.
func (s *Session) ensurePlacementDependencies() error {
	if s.routingResolver == nil {
		return errors.New("sieve: routing resolver unavailable")
	}

	if s.placementService == nil {
		return errors.New("sieve: placement service unavailable")
	}

	return nil
}

// routingRequest builds side-effect-free routing input from canonical auth facts.
func (s *Session) routingRequest(
	credentials *frontendCredentials,
	result nauthilus.AuthResult,
) (routing.RoutingRequest, error) {
	account, err := authbinding.CanonicalAccount(result.Account)
	if err != nil {
		return routing.RoutingRequest{}, errors.New("sieve: authenticated account unavailable")
	}

	loginName := ""
	if credentials != nil {
		loginName = normalizedRoutingFact(credentials.Username())
	}

	clientIP, _ := splitSessionAddr(s.conn.RemoteAddr())

	return routing.RoutingRequest{
		Tenant:            normalizedRoutingFact(s.defaultTenant),
		Protocol:          protocolSieve,
		ListenerName:      s.listenerName,
		ServiceName:       s.serviceName,
		BackendPool:       s.backendPool,
		LoginName:         loginName,
		NormalizedAccount: account,
		AuthAttributes:    cloneStringSlices(result.Attributes),
		ClientIP:          clientIP,
	}, nil
}

// waitForPlacementGate applies the shared user-hold gate before runtime placement reads.
func (s *Session) waitForPlacementGate(ctx context.Context, result routing.RoutingResult) (runtimectl.PlacementGateResult, error) {
	if s.placementGate == nil {
		return runtimectl.PlacementGateResult{Outcome: runtimectl.PlacementGateOutcomeAllowed}, nil
	}

	gateResult, err := s.placementGate.WaitForPlacement(ctx, runtimectl.PlacementGateRequest{
		Key: runtimectl.UserKey{
			Tenant:   normalizedRoutingFact(result.Tenant),
			UserHash: normalizedAccount(result.AccountKey),
		},
		Protocol:     protocolSieve,
		ListenerName: s.listenerName,
		ServiceName:  s.serviceName,
	})

	return gateResult, err
}

// sessionPlacementRequest builds the shared placement-domain input.
func (s *Session) sessionPlacementRequest(result routing.RoutingResult) placement.SessionRequest {
	ttl := result.TTL
	if ttl <= 0 {
		ttl = s.sessionLeaseTTL
	}

	return placement.SessionRequest{
		Key: state.AffinityKey{
			Tenant:     normalizedRoutingFact(result.Tenant),
			AccountKey: normalizedAccount(result.AccountKey),
		},
		SessionID:          s.sessionID,
		Protocol:           protocolSieve,
		BackendPool:        s.backendPool,
		ShardTag:           normalizedRoutingFact(result.ShardTag),
		ListenerName:       s.listenerName,
		ServiceName:        s.serviceName,
		DirectorInstanceID: s.directorInstanceID,
		HolderKind:         state.HolderKindSession,
		LeaseTTL:           ttl,
		IdleGrace:          s.sessionIdleGrace,
		RetentionTTL:       s.backendRetentionTTL,
	}
}

// withEffectiveDefaultShard fills an omitted route shard from listener defaults.
func (s *Session) withEffectiveDefaultShard(result routing.RoutingResult) routing.RoutingResult {
	if normalizedRoutingFact(result.ShardTag) != "" {
		return result
	}

	result.ShardTag = s.defaultShard

	return result
}

// newSessionID creates an opaque session lease identifier.
func newSessionID() (string, error) {
	var raw [sieveSessionIDBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}

	return hex.EncodeToString(raw[:]), nil
}

// normalizedAccount returns the canonical account key used for routing and affinity.
func normalizedAccount(value string) string {
	return strings.ToLower(normalizedRoutingFact(value))
}

// normalizedRoutingFact trims a routing fact without exposing it in errors.
func normalizedRoutingFact(value string) string {
	return strings.TrimSpace(value)
}

// cloneStringSlices returns detached routing attributes from authority results.
func cloneStringSlices(values map[string][]string) map[string][]string {
	if values == nil {
		return nil
	}

	cloned := make(map[string][]string, len(values))
	for key, value := range values {
		cloned[key] = append([]string(nil), value...)
	}

	return cloned
}

// cloneAuthResult returns detached auth result attributes for placement retention.
func cloneAuthResult(result nauthilus.AuthResult) nauthilus.AuthResult {
	result.Attributes = cloneStringSlices(result.Attributes)

	return result
}

// defaultTenant returns a stable fallback tenant for placement keys.
func defaultTenant(value string) string {
	if normalized := normalizedRoutingFact(value); normalized != "" {
		return normalized
	}

	return "default"
}

// defaultShard returns a stable fallback shard for incomplete routing facts.
func defaultShard(value string) string {
	if normalized := normalizedRoutingFact(value); normalized != "" {
		return normalized
	}

	return "default"
}

// defaultSessionLease returns a conservative lease TTL for opened Sieve sessions.
func defaultSessionLease(value time.Duration) time.Duration {
	if value > 0 {
		return value
	}

	return defaultSieveSessionLease
}

// defaultSessionGrace returns the retention grace for an active Sieve session lease.
func defaultSessionGrace(value time.Duration, lease time.Duration) time.Duration {
	if value >= 0 {
		return value
	}

	return defaultSessionLease(lease)
}
