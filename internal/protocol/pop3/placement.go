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

//nolint:funlen,wsl_v5 // Placement keeps routing, holds and session lease sequencing visible.
package pop3

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
	"github.com/croessner/nauthilus-director/internal/routing"
	runtimectl "github.com/croessner/nauthilus-director/internal/runtime"
	"github.com/croessner/nauthilus-director/internal/state"
)

const (
	defaultPlacementName = "default"
	sessionIDBytes       = 16
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
	p.AuthResult = cloneAuthResult(p.AuthResult)
	p.Routing = p.Routing.Clone()

	return p
}

// placeAuthenticatedSession resolves routing and opens shared POP3 session placement.
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

	routingCtx, routingSpan := s.startObservationSpan(ctx, observability.TraceBoundaryRoutingResolve, pop3ObservationOperationRouting, pop3ObservationResultStart, "", nil)

	routingStarted := time.Now()
	routingResult, err := s.routingResolver.Resolve(routingCtx, routingRequest)
	routingDuration := time.Since(routingStarted)
	if err != nil {
		s.recordRoutingResolve(routingCtx, pop3ObservationResultFailure, pop3ReasonRouting, "", "", routingDuration)
		routingSpan.End(pop3ObservationResultFailure, pop3ReasonRouting)

		return err
	}

	routingResult = s.withEffectiveDefaultShard(routingResult)
	if !routingResult.Complete() {
		s.recordRoutingResolve(routingCtx, pop3ObservationResultFailure, pop3ReasonIncomplete, routingResult.RoutingSource, routingResult.ShardTag, routingDuration)
		routingSpan.SetAttributes(map[string]string{
			pop3ObsFieldRoutingSource: routingResult.RoutingSource,
			pop3ObsFieldShardTag:      routingResult.ShardTag,
		})
		routingSpan.End(pop3ObservationResultFailure, pop3ReasonIncomplete)

		return errors.New("pop3: incomplete routing result")
	}

	routingSpan.SetAttributes(map[string]string{
		pop3ObsFieldRoutingSource: routingResult.RoutingSource,
		pop3ObsFieldShardTag:      routingResult.ShardTag,
	})
	s.recordRoutingResolve(routingCtx, pop3ObservationResultOK, pop3ReasonOK, routingResult.RoutingSource, routingResult.ShardTag, routingDuration)
	routingSpan.End(pop3ObservationResultOK, pop3ReasonOK)

	gateResult, err := s.waitForPlacementGate(ctx, routingResult)
	gateObservationResult, gateReason := pop3HoldGateObservation(gateResult, err)
	s.recordPlacementGate(ctx, gateObservationResult, gateReason)
	if err != nil {
		return err
	}

	selectCtx, selectSpan := s.startObservationSpan(ctx, observability.TraceBoundaryBackendSelect, pop3ObservationOperationBackendSelect, pop3ObservationResultStart, "", map[string]string{
		pop3ObsFieldShardTag: routingResult.ShardTag,
	})

	selectStarted := time.Now()
	lease, err := s.placementService.PlaceSession(selectCtx, s.sessionPlacementRequest(routingResult))
	selectDuration := time.Since(selectStarted)
	if err != nil {
		selectReason := pop3ReasonClass(err)
		s.recordBackendSelect(selectCtx, pop3ObservationResultFailure, selectReason, routingResult.ShardTag, "", selectDuration)
		selectSpan.End(pop3ObservationResultFailure, selectReason)

		return err
	}

	affinity := lease.Affinity()
	binding := lease.Binding()
	backendResult := lease.Backend()
	selectedShardTag := binding.ShardTag
	bindingReason := observability.BackendBindingReasonClass(string(binding.Source))

	s.recordAffinityOpen(ctx, pop3ObservationResultOK, bindingReason, string(binding.Source), selectedShardTag, binding.BackendNode)
	s.recordSessionAttach(selectCtx, pop3ObservationResultOK, bindingReason, backendResult.Backend.Identifier, backendResult.Backend.BackendNode, selectedShardTag)
	s.recordBackendSelect(selectCtx, pop3ObservationResultOK, bindingReason, selectedShardTag, backendResult.Backend.BackendNode, selectDuration)
	selectSpan.SetAttributes(map[string]string{
		pop3ObsFieldBackendIdentifier: backendResult.Backend.Identifier,
		pop3ObsFieldBackendNode:       backendResult.Backend.BackendNode,
		pop3ObsFieldShardTag:          selectedShardTag,
	})
	selectSpan.End(pop3ObservationResultOK, bindingReason)

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

// ensurePlacementDependencies verifies that successful auth can continue into placement.
func (s *Session) ensurePlacementDependencies() error {
	if s.routingResolver == nil {
		return errors.New("pop3: routing resolver unavailable")
	}

	if s.placementService == nil {
		return errors.New("pop3: placement service unavailable")
	}

	return nil
}

// routingRequest builds side-effect-free routing input from canonical auth facts.
func (s *Session) routingRequest(
	credentials *frontendCredentials,
	result nauthilus.AuthResult,
) (routing.RoutingRequest, error) {
	account := normalizedAccount(result.Account)
	if account == "" {
		return routing.RoutingRequest{}, errors.New("pop3: authenticated account unavailable")
	}

	loginName := ""
	if credentials != nil {
		loginName = normalizedRoutingFact(credentials.Username())
	}

	clientIP, _ := splitSessionAddr(s.conn.RemoteAddr())

	return routing.RoutingRequest{
		Tenant:            normalizedRoutingFact(s.defaultTenant),
		Protocol:          ProtocolPOP3,
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
		Protocol:     ProtocolPOP3,
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
		Protocol:           ProtocolPOP3,
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

// closePlacedSession closes a shared placement lease before backend readiness succeeds.
func (s *Session) closePlacedSession(ctx context.Context) error {
	if s == nil || !s.placed {
		return nil
	}

	var err error
	if s.placementLease != nil {
		err = s.placementLease.Close(ctx)
		s.recordSessionClose(ctx, pop3ResultLabel(err), pop3CloseReasonClass(err, s.placementLease.Affinity()))
	} else {
		s.recordSessionClose(ctx, pop3ResultLabel(err), pop3ReasonClass(err))
	}

	s.clearPlacedSession()

	return err
}

// clearPlacedSession removes stale placement facts after a rollback or close.
func (s *Session) clearPlacedSession() {
	s.placement = Placement{}
	s.placementLease = nil
	s.placed = false
}

// newSessionID creates an opaque POP3 session lease identifier.
func newSessionID() (string, error) {
	var raw [sessionIDBytes]byte
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

// defaultTenant returns the configured tenant fallback used for routing requests.
func defaultTenant(value string) string {
	if normalized := normalizedRoutingFact(value); normalized != "" {
		return normalized
	}

	return defaultPlacementName
}

// defaultShard returns the configured effective shard fallback for incomplete routing.
func defaultShard(value string) string {
	if normalized := normalizedRoutingFact(value); normalized != "" {
		return normalized
	}

	return defaultPlacementName
}

// defaultSessionLease returns a conservative lease TTL for opened POP3 sessions.
func defaultSessionLease(value time.Duration) time.Duration {
	if value > 0 {
		return value
	}

	return defaultSessionLeaseTTL
}

// defaultSessionGrace returns the configured idle grace or the effective lease fallback.
func defaultSessionGrace(value time.Duration, lease time.Duration) time.Duration {
	if value >= 0 {
		return value
	}

	return defaultSessionLease(lease)
}

// cloneAuthResult returns detached auth result attributes for placement retention.
func cloneAuthResult(result nauthilus.AuthResult) nauthilus.AuthResult {
	result.Attributes = cloneStringSlices(result.Attributes)

	return result
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
