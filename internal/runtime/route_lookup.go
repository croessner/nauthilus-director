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

package runtime

import (
	"context"
	"strings"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/routing"
	"github.com/croessner/nauthilus-director/internal/state"
)

const operationRouteLookup = "route_lookup"

// RouteLookupRequest describes a side-effect-free route diagnostic request.
type RouteLookupRequest struct {
	Protocol        string
	ListenerName    string
	ServiceName     string
	BackendPool     string
	ClientIP        string
	Tenant          string
	AccountKey      string
	RequestedShard  string
	IncludeAffinity bool
	Attributes      map[string][]string
}

// RouteLookupListenerContext describes immutable listener defaults for lookup.
type RouteLookupListenerContext struct {
	Name        string
	Protocol    string
	ServiceName string
	BackendPool string
}

// RouteLookupRoutingState describes logical routing facts for diagnostics.
type RouteLookupRoutingState struct {
	AccountKey        string
	Tenant            string
	RequestedShard    string
	EffectiveShard    string
	RoutingSource     string
	RoutingGeneration string
	UsedDefaultShard  bool
}

// RouteLookupAffinityState describes read-only active-affinity context.
type RouteLookupAffinityState struct {
	Requested      bool
	Present        bool
	Active         bool
	ShardTag       string
	BackendID      string
	Generation     string
	ActiveSessions int
}

// RouteLookupBackendState describes one effective backend candidate safely.
type RouteLookupBackendState struct {
	Identifier        string
	Protocol          string
	BackendPool       string
	EffectiveShard    string
	Generation        string
	Eligible          bool
	AllowsNewSessions bool
	AllowsActivePins  bool
	FailClosed        bool
	FailClosedReason  backend.EffectiveExclusionReason
	Exclusions        []backend.EffectiveExclusion
}

// RouteLookupEffects summarizes runtime factors that influenced lookup.
type RouteLookupEffects struct {
	Health          bool
	Maintenance     bool
	RuntimeOverride bool
	MaxConnections  bool
}

// RouteLookupResponse describes the read-only route lookup outcome.
type RouteLookupResponse struct {
	Routing         RouteLookupRoutingState
	Affinity        RouteLookupAffinityState
	Backends        []RouteLookupBackendState
	Effects         RouteLookupEffects
	SelectedBackend string
	FailClosed      bool
	ReasonClass     string
}

// RouteLookupServiceOptions configures read-only route diagnostics.
type RouteLookupServiceOptions struct {
	Resolver         routing.RoutingResolver
	Selector         backend.Selector
	BackendRead      *BackendReadService
	AffinityRead     state.AffinityStore
	ListenerContexts []RouteLookupListenerContext
	DefaultPool      string
	DefaultShard     string
	DefaultTenant    string
	Observability    observability.Recorder
}

// RouteLookupService explains routing through shared resolver and selector domains.
type RouteLookupService struct {
	resolver         routing.RoutingResolver
	selector         backend.Selector
	backendRead      *BackendReadService
	affinityRead     state.AffinityStore
	listenerContexts map[string]RouteLookupListenerContext
	defaultPool      string
	defaultShard     string
	defaultTenant    string
	recorder         observability.Recorder
}

// NewRouteLookupService creates a side-effect-free route lookup service.
func NewRouteLookupService(options RouteLookupServiceOptions) (*RouteLookupService, error) {
	if options.Resolver == nil {
		return nil, newRuntimeError(ErrorKindUnavailable, operationRouteLookup, "routing resolver required")
	}

	if options.Selector == nil {
		return nil, newRuntimeError(ErrorKindUnavailable, operationRouteLookup, "backend selector required")
	}

	if strings.TrimSpace(options.DefaultTenant) == "" {
		options.DefaultTenant = defaultTenant
	}

	return &RouteLookupService{
		resolver:         options.Resolver,
		selector:         options.Selector,
		backendRead:      options.BackendRead,
		affinityRead:     options.AffinityRead,
		listenerContexts: routeLookupListenerContexts(options.ListenerContexts),
		defaultPool:      strings.TrimSpace(options.DefaultPool),
		defaultShard:     strings.TrimSpace(options.DefaultShard),
		defaultTenant:    strings.TrimSpace(options.DefaultTenant),
		recorder:         observability.NormalizeRecorder(options.Observability),
	}, nil
}

// Normalize trims stable request facts before route lookup orchestration.
func (r RouteLookupRequest) Normalize() RouteLookupRequest {
	r.Protocol = strings.ToLower(strings.TrimSpace(r.Protocol))
	r.ListenerName = strings.TrimSpace(r.ListenerName)
	r.ServiceName = strings.TrimSpace(r.ServiceName)
	r.BackendPool = strings.TrimSpace(r.BackendPool)
	r.ClientIP = strings.TrimSpace(r.ClientIP)
	r.Tenant = strings.TrimSpace(r.Tenant)
	r.AccountKey = strings.TrimSpace(r.AccountKey)
	r.RequestedShard = strings.TrimSpace(r.RequestedShard)
	r.Attributes = cloneAttributes(r.Attributes)

	return r
}

// Lookup returns a read-only explanation without authenticating or mutating state.
func (s *RouteLookupService) Lookup(ctx context.Context, request RouteLookupRequest) (RouteLookupResponse, error) {
	if s == nil || s.resolver == nil || s.selector == nil {
		return RouteLookupResponse{}, newRuntimeError(ErrorKindUnavailable, operationRouteLookup, "route lookup service unavailable")
	}

	request = request.Normalize()
	if err := s.applyDefaults(&request); err != nil {
		s.recordRouteLookup(ctx, request, runtimeObservationResultFailure, "invalid_request", RouteLookupResponse{})

		return RouteLookupResponse{}, err
	}

	routingResult, err := s.resolver.Resolve(ctx, routing.RoutingRequest{
		Tenant:            request.Tenant,
		Protocol:          request.Protocol,
		ListenerName:      request.ListenerName,
		ServiceName:       request.ServiceName,
		BackendPool:       request.BackendPool,
		LoginName:         request.AccountKey,
		NormalizedAccount: request.AccountKey,
		AuthAttributes:    request.Attributes,
		ClientIP:          request.ClientIP,
	})
	if err != nil {
		s.recordRouteLookup(ctx, request, runtimeObservationResultFailure, "other", RouteLookupResponse{})

		return RouteLookupResponse{}, err
	}

	usedDefaultShard := strings.TrimSpace(routingResult.ShardTag) == ""
	routingResult = withDefaultRouteShard(routingResult, s.defaultShard)
	affinity := s.lookupAffinity(ctx, request, routingResult)
	selectionRequest := routeLookupSelectionRequest(request, routingResult, affinity)
	explanation, err := s.explainSelection(ctx, selectionRequest)

	response := routeLookupResponse(routingResult, affinity, explanation, request, selectionRequest, usedDefaultShard)

	if err != nil {
		if backend.IsErrorKind(err, backend.ErrorKindNoBackend) {
			response.FailClosed = true
			response.ReasonClass = string(backend.ErrorKindNoBackend)
			s.recordRouteLookup(ctx, request, runtimeObservationResultOK, response.ReasonClass, response)

			return response, nil
		}

		s.recordRouteLookup(ctx, request, runtimeObservationResultFailure, "other", response)

		return RouteLookupResponse{}, err
	}

	response.SelectedBackend = explanation.Result.Backend.Identifier
	response.ReasonClass = explanation.Result.Reason
	response.Routing.RoutingGeneration = firstNonEmpty(explanation.Result.Generation, routingResult.RoutingGeneration)
	response.Routing.EffectiveShard = explanation.Result.EffectiveBackend.EffectiveShardTag
	response.Effects = response.Effects.Merge(NewRouteLookupBackendState(explanation.Result.EffectiveBackend, selectionRequest.ActiveAffinity).Effects())

	s.recordRouteLookup(ctx, request, runtimeObservationResultOK, response.ReasonClass, response)

	return response, nil
}

// NewRouteLookupBackendState projects effective backend state into diagnostics.
func NewRouteLookupBackendState(state backend.EffectiveBackendState, activeAffinity bool) RouteLookupBackendState {
	return RouteLookupBackendState{
		Identifier:        state.Identifier,
		Protocol:          state.Protocol,
		BackendPool:       state.BackendPool,
		EffectiveShard:    state.EffectiveShardTag,
		Generation:        state.Generation,
		Eligible:          state.Eligible(activeAffinity),
		AllowsNewSessions: state.AllowsNewSessions,
		AllowsActivePins:  state.AllowsActivePins,
		FailClosed:        state.FailClosed,
		FailClosedReason:  state.FailClosedReason,
		Exclusions:        append([]backend.EffectiveExclusion(nil), state.Exclusions...),
	}
}

// Effects reports whether this backend summary was affected by runtime factors.
func (s RouteLookupBackendState) Effects() RouteLookupEffects {
	var effects RouteLookupEffects

	for _, exclusion := range s.Exclusions {
		switch exclusion.Reason {
		case backend.EffectiveExclusionHealth:
			effects.Health = true
		case backend.EffectiveExclusionMaxConnections:
			effects.MaxConnections = true
		case backend.EffectiveExclusionRuntimeDrain,
			backend.EffectiveExclusionRuntimeHardMaintenance,
			backend.EffectiveExclusionRuntimeOut,
			backend.EffectiveExclusionRuntimeSoftMaintenance:
			effects.RuntimeOverride = true
			effects.Maintenance = effects.Maintenance ||
				exclusion.Reason == backend.EffectiveExclusionRuntimeHardMaintenance ||
				exclusion.Reason == backend.EffectiveExclusionRuntimeSoftMaintenance
		case backend.EffectiveExclusionStaticHardMaintenance, backend.EffectiveExclusionStaticSoftMaintenance:
			effects.Maintenance = true
		}
	}

	if strings.TrimSpace(string(s.FailClosedReason)) != "" {
		effects.RuntimeOverride = effects.RuntimeOverride || s.FailClosedReason == backend.EffectiveExclusionAmbiguousState
	}

	if strings.TrimSpace(s.Generation) != "" {
		effects.RuntimeOverride = true
	}

	return effects
}

// Merge combines two route lookup effect summaries.
func (e RouteLookupEffects) Merge(other RouteLookupEffects) RouteLookupEffects {
	return RouteLookupEffects{
		Health:          e.Health || other.Health,
		Maintenance:     e.Maintenance || other.Maintenance,
		RuntimeOverride: e.RuntimeOverride || other.RuntimeOverride,
		MaxConnections:  e.MaxConnections || other.MaxConnections,
	}
}

// applyDefaults validates request facts and applies listener/config fallbacks.
func (s *RouteLookupService) applyDefaults(request *RouteLookupRequest) error {
	if request.Protocol == "" {
		return newRuntimeError(ErrorKindInvalidRequest, operationRouteLookup, "protocol required")
	}

	if request.AccountKey == "" {
		return newRuntimeError(ErrorKindInvalidRequest, operationRouteLookup, "account key required")
	}

	if request.Tenant == "" {
		request.Tenant = s.defaultTenant
	}

	if err := s.applyListenerDefaults(request); err != nil {
		return err
	}

	if request.BackendPool == "" {
		request.BackendPool = s.defaultPool
	}

	if request.BackendPool == "" {
		return newRuntimeError(ErrorKindInvalidRequest, operationRouteLookup, "backend pool required")
	}

	return nil
}

// applyListenerDefaults merges immutable listener context into the lookup request.
func (s *RouteLookupService) applyListenerDefaults(request *RouteLookupRequest) error {
	if request.ListenerName == "" {
		return nil
	}

	listener, ok := s.listenerContexts[request.ListenerName]
	if !ok {
		return nil
	}

	if listener.Protocol != "" && listener.Protocol != request.Protocol {
		return newRuntimeError(ErrorKindInvalidRequest, operationRouteLookup, "listener protocol mismatch")
	}

	if request.ServiceName == "" {
		request.ServiceName = listener.ServiceName
	}

	if request.BackendPool == "" {
		request.BackendPool = listener.BackendPool
	} else if listener.BackendPool != "" && request.BackendPool != listener.BackendPool {
		return newRuntimeError(ErrorKindInvalidRequest, operationRouteLookup, "listener backend pool mismatch")
	}

	return nil
}

// explainSelection calls selector explanation when available and otherwise selects only.
func (s *RouteLookupService) explainSelection(ctx context.Context, request backend.SelectionRequest) (backend.SelectionExplanation, error) {
	if explainer, ok := s.selector.(backend.ExplainingSelector); ok {
		return explainer.Explain(ctx, request)
	}

	result, err := s.selector.Select(ctx, request)

	explanation := backend.SelectionExplanation{Request: request, Result: result}

	if s.backendRead != nil {
		explanation.EffectiveBackends = s.lookupBackends(ctx, request)
	}

	return explanation, err
}

// lookupBackends returns safe candidate summaries when only a simple selector is available.
func (s *RouteLookupService) lookupBackends(ctx context.Context, request backend.SelectionRequest) []backend.EffectiveBackendState {
	states, err := s.backendRead.ListBackends(ctx)
	if err != nil {
		return nil
	}

	backends := make([]backend.EffectiveBackendState, 0, len(states))
	for _, state := range states {
		if state.Protocol != request.Protocol {
			continue
		}

		if request.BackendPool != "" && state.BackendPool != request.BackendPool {
			continue
		}

		if request.ShardTag != "" && state.EffectiveShardTag != request.ShardTag {
			continue
		}

		backends = append(backends, state)
	}

	return backends
}

// lookupAffinity optionally reads active affinity state without refreshing leases.
func (s *RouteLookupService) lookupAffinity(ctx context.Context, request RouteLookupRequest, result routing.RoutingResult) RouteLookupAffinityState {
	affinity := RouteLookupAffinityState{Requested: request.IncludeAffinity}
	if !request.IncludeAffinity || s.affinityRead == nil {
		return affinity
	}

	record, err := s.affinityRead.LookupAffinity(ctx, state.AffinityKey{
		Tenant:     result.Tenant,
		AccountKey: result.AccountKey,
	})
	if err != nil {
		return affinity
	}

	affinity.Present = record.Present
	affinity.Active = routeLookupAffinityActive(result, record)
	affinity.ShardTag = strings.TrimSpace(record.ShardTag)
	affinity.BackendID = strings.TrimSpace(record.BackendIdentifier)
	affinity.Generation = strings.TrimSpace(record.Generation)
	affinity.ActiveSessions = record.ActiveSessionCount

	return affinity
}

// routeLookupSelectionRequest builds the shared backend selector input.
func routeLookupSelectionRequest(
	request RouteLookupRequest,
	result routing.RoutingResult,
	affinity RouteLookupAffinityState,
) backend.SelectionRequest {
	shardTag := strings.TrimSpace(result.ShardTag)
	if affinity.ShardTag != "" {
		shardTag = affinity.ShardTag
	}

	return backend.SelectionRequest{
		AccountKey:              result.AccountKey,
		Tenant:                  result.Tenant,
		ShardTag:                shardTag,
		Protocol:                request.Protocol,
		BackendPool:             request.BackendPool,
		ActiveAffinity:          affinity.Active,
		PinnedBackendIdentifier: affinity.BackendID,
	}
}

// routeLookupResponse builds the diagnostic response shell from shared domains.
func routeLookupResponse(
	result routing.RoutingResult,
	affinity RouteLookupAffinityState,
	explanation backend.SelectionExplanation,
	request RouteLookupRequest,
	selectionRequest backend.SelectionRequest,
	usedDefaultShard bool,
) RouteLookupResponse {
	backends, effects := routeLookupBackends(explanation.EffectiveBackends, selectionRequest.ActiveAffinity)

	return RouteLookupResponse{
		Routing: RouteLookupRoutingState{
			AccountKey:        result.AccountKey,
			Tenant:            result.Tenant,
			RequestedShard:    request.RequestedShard,
			EffectiveShard:    selectionRequest.ShardTag,
			RoutingSource:     result.RoutingSource,
			RoutingGeneration: result.RoutingGeneration,
			UsedDefaultShard:  usedDefaultShard,
		},
		Affinity: affinity,
		Backends: backends,
		Effects:  effects,
	}
}

// routeLookupBackends adapts selector candidates into safe summaries.
func routeLookupBackends(states []backend.EffectiveBackendState, activeAffinity bool) ([]RouteLookupBackendState, RouteLookupEffects) {
	var (
		backends = make([]RouteLookupBackendState, 0, len(states))
		effects  RouteLookupEffects
	)

	for _, state := range states {
		summary := NewRouteLookupBackendState(state, activeAffinity)
		backends = append(backends, summary)
		effects = effects.Merge(summary.Effects())
	}

	return backends, effects
}

// routeLookupAffinityActive mirrors active pin semantics without mutating state.
func routeLookupAffinityActive(result routing.RoutingResult, record state.AffinityRecord) bool {
	switch record.Status {
	case "created", "":
		return strings.TrimSpace(record.ShardTag) != "" && strings.TrimSpace(record.ShardTag) != strings.TrimSpace(result.ShardTag)
	default:
		return record.Present
	}
}

// withDefaultRouteShard applies the immutable shard fallback used by placement.
func withDefaultRouteShard(result routing.RoutingResult, defaultShard string) routing.RoutingResult {
	if strings.TrimSpace(result.ShardTag) != "" {
		return result
	}

	result.ShardTag = strings.TrimSpace(defaultShard)

	return result
}

// routeLookupListenerContexts indexes configured listener contexts by name.
func routeLookupListenerContexts(contexts []RouteLookupListenerContext) map[string]RouteLookupListenerContext {
	index := make(map[string]RouteLookupListenerContext, len(contexts))
	for _, context := range contexts {
		context.Name = strings.TrimSpace(context.Name)
		if context.Name == "" {
			continue
		}

		context.Protocol = strings.ToLower(strings.TrimSpace(context.Protocol))
		context.ServiceName = strings.TrimSpace(context.ServiceName)
		context.BackendPool = strings.TrimSpace(context.BackendPool)
		index[context.Name] = context
	}

	return index
}

// cloneAttributes returns detached route lookup attributes for diagnostics.
func cloneAttributes(attributes map[string][]string) map[string][]string {
	if attributes == nil {
		return nil
	}

	cloned := make(map[string][]string, len(attributes))
	for key, values := range attributes {
		cloned[key] = append([]string(nil), values...)
	}

	return cloned
}

// recordRouteLookup emits one side-effect-free lookup observation.
func (s *RouteLookupService) recordRouteLookup(
	ctx context.Context,
	request RouteLookupRequest,
	result string,
	reasonClass string,
	response RouteLookupResponse,
) {
	if s == nil {
		return
	}

	fields := map[string]string{
		runtimeObservationFieldAccountKeyPresent: boolAuditValue(strings.TrimSpace(request.AccountKey) != ""),
		runtimeObservationFieldBackendPool:       request.BackendPool,
		runtimeObservationFieldListener:          request.ListenerName,
		runtimeObservationFieldProtocol:          request.Protocol,
		runtimeObservationFieldSelectedPresent:   boolAuditValue(strings.TrimSpace(response.SelectedBackend) != ""),
		runtimeObservationFieldService:           request.ServiceName,
		runtimeObservationFieldShardTag:          response.Routing.EffectiveShard,
	}

	labels := map[string]string{
		runtimeObservationFieldBackendPool: request.BackendPool,
		runtimeObservationFieldListener:    request.ListenerName,
		runtimeObservationFieldProtocol:    request.Protocol,
		runtimeObservationFieldService:     request.ServiceName,
	}
	if response.Routing.EffectiveShard != "" {
		labels[runtimeObservationFieldShardTag] = response.Routing.EffectiveShard
	}

	recordRuntimeObservation(ctx, s.recorder, observability.EventRouteLookup, observability.TraceBoundaryRESTRequest, operationRouteLookup, result, reasonClass, fields, labels)

	for _, state := range response.Backends {
		s.recordRouteBackendState(ctx, request.Protocol, state)
	}
}

// recordRouteBackendState emits the effective candidate state observed by route lookup.
func (s *RouteLookupService) recordRouteBackendState(ctx context.Context, protocol string, state RouteLookupBackendState) {
	result := runtimeObservationResultEligible
	reasonClass := runtimeObservationResultOK

	if !state.Eligible {
		result = runtimeObservationResultExcluded

		if len(state.Exclusions) > 0 {
			reasonClass = string(state.Exclusions[0].Reason)
		}
	}

	if state.FailClosed {
		result = runtimeObservationResultFailClosed
		reasonClass = string(state.FailClosedReason)
	}

	fields := map[string]string{
		runtimeObservationFieldBackendID:         state.Identifier,
		runtimeObservationFieldBackendPool:       state.BackendPool,
		runtimeObservationFieldRuntimeGeneration: state.Generation,
		runtimeObservationFieldShardTag:          state.EffectiveShard,
	}
	labels := map[string]string{
		runtimeObservationFieldBackendPool: state.BackendPool,
		runtimeObservationFieldProtocol:    protocol,
		runtimeObservationFieldShardTag:    state.EffectiveShard,
	}
	recordRuntimeObservation(ctx, s.recorder, observability.EventBackendEffectiveState, observability.TraceBoundaryBackendSelect, runtimeObservationOperationBackendEffective, result, reasonClass, fields, labels)

	for _, exclusion := range state.Exclusions {
		recordRuntimeObservation(ctx, s.recorder, observability.EventSelectorExclusion, observability.TraceBoundaryBackendSelect, runtimeObservationOperationSelectorExclude, runtimeObservationResultExcluded, string(exclusion.Reason), map[string]string{
			runtimeObservationFieldBackendID:       state.Identifier,
			runtimeObservationFieldBackendPool:     state.BackendPool,
			runtimeObservationFieldExclusionDetail: exclusion.Detail,
			runtimeObservationFieldExclusionSource: exclusion.Source,
			runtimeObservationFieldShardTag:        state.EffectiveShard,
		}, labels)
	}
}
