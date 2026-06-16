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

// Package placement owns cross-protocol backend-node placement invariants.
package placement

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/state"
)

// BindingSource classifies why a backend binding selected the returned backend.
type BindingSource string

const (
	affinityStatusFound    = "found"
	affinityStatusRetained = "retained"
	affinityStatusReused   = "reused"
	moveStrategyDrain      = "drain_existing"
	moveStrategyKick       = "kick_existing"
	moveStrategyNew        = "new_sessions_only"

	// BindingSourceActiveAffinity means an active holder binding was reused.
	BindingSourceActiveAffinity BindingSource = "active_affinity"
	// BindingSourceRetainedBinding means a retained backend-node binding was reused.
	BindingSourceRetainedBinding BindingSource = "retained_backend_binding"
	// BindingSourceOperatorBackendPin means an operator backend pin selected the backend.
	BindingSourceOperatorBackendPin BindingSource = "operator_backend_pin"
	// BindingSourceInitialPlacement means the normal selector created a new binding.
	BindingSourceInitialPlacement BindingSource = "initial_placement"
	// BindingSourceBindingInvalidatedHardDown means hard-down health permitted failover.
	BindingSourceBindingInvalidatedHardDown BindingSource = "binding_invalidated_hard_down"
	// BindingSourceMovementOverride means an explicit user move selected a target shard.
	BindingSourceMovementOverride BindingSource = "movement_override"
)

// ErrorKind classifies protocol-safe placement failures.
type ErrorKind string

const (
	// ErrorKindBackendNodeMissingProtocol reports a bound node without the requested endpoint.
	ErrorKindBackendNodeMissingProtocol ErrorKind = "backend_node_missing_protocol"
	// ErrorKindBackendNodeMismatch reports an unsafe concrete backend-node conflict.
	ErrorKindBackendNodeMismatch ErrorKind = "backend_node_mismatch"
	// ErrorKindBackendNodeUnusable reports a bound endpoint that policy excludes.
	ErrorKindBackendNodeUnusable ErrorKind = "backend_node_unusable"
	// ErrorKindConfig reports missing placement collaborators.
	ErrorKindConfig ErrorKind = "config"
	// ErrorKindInvalidRequest reports incomplete placement input.
	ErrorKindInvalidRequest ErrorKind = "invalid_request"
	// ErrorKindNoBackend reports no safe backend target for the request.
	ErrorKindNoBackend ErrorKind = "no_backend"
)

// Error is a secret-safe placement-domain failure.
type Error struct {
	Kind      ErrorKind
	Operation string
	Message   string
	cause     error
}

// Error returns a bounded placement diagnostic.
func (e *Error) Error() string {
	if e == nil {
		return ""
	}

	message := "placement failed: " + string(e.Kind)
	if e.Operation != "" {
		message += " operation=" + e.Operation
	}

	if e.Message != "" {
		message += " " + e.Message
	}

	return message
}

// Unwrap exposes the wrapped low-level failure for classification.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}

	return e.cause
}

// IsErrorKind reports whether err wraps a placement error with kind.
func IsErrorKind(err error, kind ErrorKind) bool {
	var placementErr *Error
	if !errors.As(err, &placementErr) {
		return false
	}

	return placementErr.Kind == kind
}

// BackendBinding describes the selected backend-node binding returned to protocols.
type BackendBinding struct {
	Key                state.AffinityKey
	ShardTag           string
	BackendNode        string
	BackendIdentifier  string
	Source             BindingSource
	ActiveHolderCount  int
	RetentionExpiresAt time.Time
}

// Request contains the protocol-neutral placement input.
type Request struct {
	Key                state.AffinityKey
	SessionID          string
	Protocol           string
	BackendPool        string
	ShardTag           string
	ListenerName       string
	ServiceName        string
	DirectorInstanceID string
	HolderKind         string
	LeaseTTL           time.Duration
	IdleGrace          time.Duration
	RetentionTTL       time.Duration
}

// SessionRequest identifies one user-stateful session placement.
type SessionRequest = Request

// DeliveryRequest identifies one delivery-scoped placement hold.
type DeliveryRequest = Request

// StateStore owns the Redis-backed placement state used by the domain service.
type StateStore interface {
	state.SessionStore
	state.AffinityStore
	state.BackendReservationStore
	GetUserBackendPin(context.Context, state.UserBackendPinGetRequest) (state.UserBackendPinRecord, error)
}

// BackendNodeSelector resolves exact protocol endpoints inside a backend node.
type BackendNodeSelector interface {
	SelectInBackendNode(context.Context, backend.NodeSelectionRequest) (backend.SelectionResult, error)
}

// SessionPlacer is the narrow API used by stateful login protocols.
type SessionPlacer interface {
	PlaceSession(context.Context, SessionRequest) (LeaseHandle, error)
}

// DeliveryPlacer is the narrow API used by LMTP recipient placement.
type DeliveryPlacer interface {
	PlaceDeliveryHold(context.Context, DeliveryRequest) (LeaseHandle, error)
}

// LeaseHandle owns one opened holder and its selected backend accounting.
type LeaseHandle interface {
	Affinity() state.AffinityRecord
	AttachBackend(context.Context) error
	Backend() backend.SelectionResult
	Binding() BackendBinding
	Close(context.Context) error
	Heartbeat(context.Context, time.Duration) (state.AffinityRecord, error)
	SessionID() string
}

// Service coordinates backend-node placement, holder state and reservations.
type Service struct {
	registry     backend.Registry
	selector     backend.Selector
	nodeSelector BackendNodeSelector
	store        StateStore
}

// NewService creates a shared placement service over registry, selector and state.
func NewService(registry backend.Registry, selector backend.Selector, store StateStore) (*Service, error) {
	if registry == nil {
		return nil, newPlacementError(ErrorKindConfig, "service", "backend registry required", nil)
	}

	if selector == nil {
		return nil, newPlacementError(ErrorKindConfig, "service", "backend selector required", nil)
	}

	nodeSelector, ok := selector.(BackendNodeSelector)
	if !ok {
		return nil, newPlacementError(ErrorKindConfig, "service", "backend-node selector required", nil)
	}

	if store == nil {
		return nil, newPlacementError(ErrorKindConfig, "service", "state store required", nil)
	}

	return &Service{
		registry:     registry,
		selector:     selector,
		nodeSelector: nodeSelector,
		store:        store,
	}, nil
}

// PlaceSession opens a user-session holder and attaches backend capacity.
func (s *Service) PlaceSession(ctx context.Context, request SessionRequest) (LeaseHandle, error) {
	request.HolderKind = state.HolderKindSession

	lease, err := s.openPlacement(ctx, request)
	if err != nil {
		return nil, err
	}

	if err := lease.AttachBackend(ctx); err != nil {
		_ = lease.Close(context.Background())

		return nil, err
	}

	return lease, nil
}

// PlaceDeliveryHold opens a delivery-scoped holder without counting backend capacity.
func (s *Service) PlaceDeliveryHold(ctx context.Context, request DeliveryRequest) (LeaseHandle, error) {
	request.HolderKind = state.HolderKindDelivery

	return s.openPlacement(ctx, request)
}

// openPlacement selects a backend node and opens the holder with mismatch retry.
func (s *Service) openPlacement(ctx context.Context, request Request) (LeaseHandle, error) {
	request = normalizeRequest(request)
	if err := validateRequest(request); err != nil {
		return nil, err
	}

	pin, err := s.store.GetUserBackendPin(ctx, state.UserBackendPinGetRequest{
		Key:         request.Key,
		Protocol:    request.Protocol,
		BackendPool: request.BackendPool,
	})
	if err != nil {
		return nil, err
	}

	affinity, err := s.store.LookupAffinity(ctx, request.Key)
	if err != nil {
		return nil, err
	}

	selected, source, err := s.selectPlacement(ctx, request, affinity, pin)
	if err != nil {
		return nil, err
	}

	lease, mismatch, mismatchRecord, err := s.openSelectedLease(ctx, request, selected, source)
	if err != nil || !mismatch {
		return lease, err
	}

	selected, source, err = s.selectPlacement(ctx, request, mismatchRecord, pin)
	if err != nil {
		return nil, err
	}

	lease, mismatch, _, err = s.openSelectedLease(ctx, request, selected, source)
	if err != nil {
		return nil, err
	}

	if mismatch {
		return nil, newPlacementError(ErrorKindBackendNodeMismatch, "open", "backend node changed during placement", nil)
	}

	return lease, nil
}

// selectPlacement chooses between bound-node reuse and initial placement.
func (s *Service) selectPlacement(
	ctx context.Context,
	request Request,
	affinity state.AffinityRecord,
	pin state.UserBackendPinRecord,
) (backend.SelectionResult, BindingSource, error) {
	if targetShard := movementOverrideShard(affinity); targetShard != "" {
		overrideRequest := request
		overrideRequest.ShardTag = targetShard

		selected, source, err := s.selectInitialBackend(ctx, overrideRequest, state.AffinityRecord{}, pin)
		if err != nil {
			return backend.SelectionResult{}, "", err
		}

		if source == BindingSourceInitialPlacement {
			source = BindingSourceMovementOverride
		}

		return selected, source, nil
	}

	if reusableBinding(affinity) {
		return s.selectBoundBackend(ctx, request, affinity, pin)
	}

	return s.selectInitialBackend(ctx, request, affinity, pin)
}

// selectInitialBackend runs the normal selector only when no binding is authoritative.
func (s *Service) selectInitialBackend(
	ctx context.Context,
	request Request,
	affinity state.AffinityRecord,
	pin state.UserBackendPinRecord,
) (backend.SelectionResult, BindingSource, error) {
	shardTag := initialSelectionShard(request, affinity)

	operatorBackend, err := s.initialOperatorBackendPin(ctx, request, pin, shardTag)
	if err != nil {
		return backend.SelectionResult{}, "", err
	}

	selected, err := s.selector.Select(ctx, backend.SelectionRequest{
		AccountKey:                request.Key.AccountKey,
		Tenant:                    request.Key.Tenant,
		ShardTag:                  shardTag,
		Protocol:                  request.Protocol,
		BackendPool:               request.BackendPool,
		OperatorBackendIdentifier: operatorBackend,
	})
	if err != nil {
		return backend.SelectionResult{}, "", err
	}

	if selected.Backend.BackendNode == "" {
		return backend.SelectionResult{}, "", newPlacementError(ErrorKindNoBackend, "select", "selected backend node required", nil)
	}

	source := BindingSourceInitialPlacement
	if selected.Reason == backend.SelectionReasonOperatorBackendPin {
		source = BindingSourceOperatorBackendPin
	}

	return selected, source, nil
}

// selectBoundBackend resolves the requested protocol inside the existing backend node.
func (s *Service) selectBoundBackend(
	ctx context.Context,
	request Request,
	affinity state.AffinityRecord,
	pin state.UserBackendPinRecord,
) (backend.SelectionResult, BindingSource, error) {
	operatorBackend, err := s.boundOperatorBackendPin(ctx, request, affinity, pin)
	if err != nil {
		return backend.SelectionResult{}, "", err
	}

	selected, err := s.nodeSelector.SelectInBackendNode(ctx, backend.NodeSelectionRequest{
		AccountKey:                request.Key.AccountKey,
		Tenant:                    request.Key.Tenant,
		ShardTag:                  affinity.ShardTag,
		BackendNode:               affinity.BackendNode,
		Protocol:                  request.Protocol,
		BackendPool:               request.BackendPool,
		OperatorBackendIdentifier: operatorBackend,
	})
	if err != nil {
		return backend.SelectionResult{}, "", boundBackendSelectionError(err)
	}

	source := bindingSourceFromAffinity(affinity, BindingSourceActiveAffinity)
	if selected.Reason == backend.SelectionReasonBindingInvalidatedHardDown {
		source = BindingSourceBindingInvalidatedHardDown
	}

	return selected, source, nil
}

// boundBackendSelectionError maps backend-node selection failures to placement classes.
func boundBackendSelectionError(err error) error {
	if err == nil {
		return nil
	}

	var backendErr *backend.Error
	if !errors.As(err, &backendErr) {
		return err
	}

	switch backendErr.Kind {
	case backend.ErrorKindAmbiguous:
		return newPlacementError(ErrorKindBackendNodeMismatch, "backend_node", "bound backend node mapping mismatch", err)
	case backend.ErrorKindNoBackend:
		if strings.Contains(backendErr.Message, "protocol entry not found") {
			return newPlacementError(ErrorKindBackendNodeMissingProtocol, "backend_node", "requested protocol entry missing", err)
		}

		return newPlacementError(ErrorKindBackendNodeUnusable, "backend_node", "bound backend node unusable", err)
	default:
		return err
	}
}

// openSelectedLease persists the holder against the selected backend node.
func (s *Service) openSelectedLease(
	ctx context.Context,
	request Request,
	selected backend.SelectionResult,
	source BindingSource,
) (LeaseHandle, bool, state.AffinityRecord, error) {
	record := request.sessionRecord(selected.Backend.BackendNode)

	record.ShardTag = selected.Backend.ShardTag
	if strings.TrimSpace(record.ShardTag) == "" {
		record.ShardTag = request.ShardTag
	}

	affinity, err := s.store.OpenSession(ctx, record)
	if err != nil {
		return nil, false, state.AffinityRecord{}, err
	}

	if affinity.Key == (state.AffinityKey{}) {
		affinity.Key = request.Key
	}

	if affinity.BindingStatus == state.BindingStatusBackendNodeMismatch {
		return nil, true, affinity, nil
	}

	if !sameBackendNode(affinity.BackendNode, selected.Backend.BackendNode) {
		return nil, false, affinity, newPlacementError(ErrorKindBackendNodeMismatch, "open", "opened binding changed backend node", nil)
	}

	source = bindingSourceFromAffinity(affinity, source)
	binding := BackendBinding{
		Key:                affinity.Key,
		ShardTag:           affinity.ShardTag,
		BackendNode:        selected.Backend.BackendNode,
		BackendIdentifier:  selected.Backend.Identifier,
		Source:             source,
		ActiveHolderCount:  affinity.ActiveHolderCount,
		RetentionExpiresAt: affinity.RetentionExpiresAt,
	}

	return &Lease{
		store:    s.store,
		request:  request,
		affinity: affinity,
		selected: selected,
		binding:  binding,
	}, false, affinity, nil
}

// initialOperatorBackendPin returns a scoped operator pin for unbound placement.
func (s *Service) initialOperatorBackendPin(
	ctx context.Context,
	request Request,
	pin state.UserBackendPinRecord,
	shardTag string,
) (string, error) {
	if !pinMatchesProtocolPool(pin, request.Protocol, request.BackendPool) {
		return "", nil
	}

	if strings.TrimSpace(pin.ShardTag) != strings.TrimSpace(shardTag) {
		return "", newPlacementError(ErrorKindNoBackend, "backend_pin", "operator backend pin shard mismatch", nil)
	}

	target, err := s.lookupBackendPinTarget(ctx, request, pin)
	if err != nil {
		return "", err
	}

	return target.Identifier, nil
}

// boundOperatorBackendPin validates that a pin cannot override a bound backend node.
func (s *Service) boundOperatorBackendPin(
	ctx context.Context,
	request Request,
	affinity state.AffinityRecord,
	pin state.UserBackendPinRecord,
) (string, error) {
	if !pinMatchesProtocolPool(pin, request.Protocol, request.BackendPool) {
		return "", nil
	}

	target, err := s.lookupBackendPinTarget(ctx, request, pin)
	if err != nil {
		return "", err
	}

	if !sameBackendNode(target.BackendNode, affinity.BackendNode) || strings.TrimSpace(target.ShardTag) != strings.TrimSpace(affinity.ShardTag) {
		return "", newPlacementError(ErrorKindBackendNodeMismatch, "backend_pin", "operator backend pin targets different backend node", nil)
	}

	return target.Identifier, nil
}

// lookupBackendPinTarget validates a stored pin against the backend registry.
func (s *Service) lookupBackendPinTarget(ctx context.Context, request Request, pin state.UserBackendPinRecord) (backend.Backend, error) {
	target, err := s.registry.Lookup(ctx, strings.TrimSpace(pin.BackendIdentifier))
	if err != nil {
		return backend.Backend{}, err
	}

	facts := target.PlacementFacts()
	if facts.Protocol != request.Protocol || facts.BackendPool != request.BackendPool {
		return backend.Backend{}, newPlacementError(ErrorKindNoBackend, "backend_pin", "operator backend pin scope mismatch", nil)
	}

	if facts.EffectiveShard != strings.TrimSpace(pin.ShardTag) {
		return backend.Backend{}, newPlacementError(ErrorKindNoBackend, "backend_pin", "operator backend pin shard mismatch", nil)
	}

	if facts.BackendNode != strings.TrimSpace(pin.BackendNode) {
		return backend.Backend{}, newPlacementError(ErrorKindNoBackend, "backend_pin", "operator backend pin backend-node mismatch", nil)
	}

	return target, nil
}

// Affinity returns the opened affinity record.
func (l *Lease) Affinity() state.AffinityRecord {
	if l == nil {
		return state.AffinityRecord{}
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	return l.affinity
}

// AttachBackend reserves capacity and attaches the selected backend to the holder.
func (l *Lease) AttachBackend(ctx context.Context) error {
	if l == nil {
		return newPlacementError(ErrorKindConfig, "attach", "lease unavailable", nil)
	}

	l.mu.Lock()
	if l.attached {
		l.mu.Unlock()

		return nil
	}
	l.mu.Unlock()

	reservation, err := l.store.ReserveBackendCapacity(ctx, state.BackendReservationRequest{
		BackendIdentifier: l.selected.Backend.Identifier,
		ReservationID:     l.request.SessionID,
		MaxConnections:    l.selected.Backend.MaxConnections,
		LeaseTTL:          l.request.LeaseTTL,
	})
	if err != nil {
		return err
	}

	if _, err = l.store.AttachSelectedBackend(ctx, state.SessionBackendAttachment{
		Key:               l.request.Key,
		SessionID:         l.request.SessionID,
		BackendIdentifier: l.selected.Backend.Identifier,
		BackendNode:       l.selected.Backend.BackendNode,
		ReservationID:     reservation.ReservationID,
		MaxConnections:    l.selected.Backend.MaxConnections,
	}); err != nil {
		_, _ = l.store.ReleaseBackendReservation(context.Background(), state.BackendReservationReleaseRequest{
			BackendIdentifier: l.selected.Backend.Identifier,
			ReservationID:     reservation.ReservationID,
		})

		return err
	}

	l.mu.Lock()
	l.attached = true
	l.reservationID = reservation.ReservationID
	l.mu.Unlock()

	return nil
}

// Backend returns the selected concrete backend.
func (l *Lease) Backend() backend.SelectionResult {
	if l == nil {
		return backend.SelectionResult{}
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	return l.selected
}

// Binding returns the backend-node binding visible to protocol callers.
func (l *Lease) Binding() BackendBinding {
	if l == nil {
		return BackendBinding{}
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	return l.binding
}

// Close releases the holder and leaves retained binding according to state policy.
func (l *Lease) Close(ctx context.Context) error {
	if l == nil {
		return nil
	}

	affinity, err := l.store.CloseSession(ctx, l.request.Key, l.request.SessionID)

	l.mu.Lock()
	l.affinity = affinity
	l.binding.ActiveHolderCount = affinity.ActiveHolderCount
	l.binding.RetentionExpiresAt = affinity.RetentionExpiresAt
	l.mu.Unlock()

	return err
}

// Heartbeat refreshes the holder lease and backend reservation.
func (l *Lease) Heartbeat(ctx context.Context, ttl time.Duration) (state.AffinityRecord, error) {
	if l == nil {
		return state.AffinityRecord{}, newPlacementError(ErrorKindConfig, "heartbeat", "lease unavailable", nil)
	}

	affinity, err := l.store.HeartbeatSession(ctx, l.request.Key, l.request.SessionID, ttl)

	l.mu.Lock()
	l.affinity = affinity
	l.binding.ActiveHolderCount = affinity.ActiveHolderCount
	l.binding.RetentionExpiresAt = affinity.RetentionExpiresAt
	l.mu.Unlock()

	return affinity, err
}

// SessionID returns the holder identifier used in Redis.
func (l *Lease) SessionID() string {
	if l == nil {
		return ""
	}

	return l.request.SessionID
}

// Lease is the concrete placement lease returned by Service.
type Lease struct {
	mu            sync.Mutex
	store         StateStore
	request       Request
	affinity      state.AffinityRecord
	selected      backend.SelectionResult
	binding       BackendBinding
	attached      bool
	reservationID string
}

// normalizeRequest trims string fields and defaults the holder kind.
func normalizeRequest(request Request) Request {
	request.Key.Tenant = strings.TrimSpace(request.Key.Tenant)
	request.Key.AccountKey = strings.TrimSpace(request.Key.AccountKey)
	request.SessionID = strings.TrimSpace(request.SessionID)
	request.Protocol = strings.ToLower(strings.TrimSpace(request.Protocol))
	request.BackendPool = strings.TrimSpace(request.BackendPool)
	request.ShardTag = strings.TrimSpace(request.ShardTag)
	request.ListenerName = strings.TrimSpace(request.ListenerName)
	request.ServiceName = strings.TrimSpace(request.ServiceName)
	request.DirectorInstanceID = strings.TrimSpace(request.DirectorInstanceID)

	request.HolderKind = strings.ToLower(strings.TrimSpace(request.HolderKind))
	if request.HolderKind == "" {
		request.HolderKind = state.HolderKindSession
	}

	return request
}

// validateRequest rejects incomplete placement requests before state mutation.
func validateRequest(request Request) error {
	if request.Key.Tenant == "" {
		return newPlacementError(ErrorKindInvalidRequest, "request", "tenant required", nil)
	}

	if request.Key.AccountKey == "" {
		return newPlacementError(ErrorKindInvalidRequest, "request", "account key required", nil)
	}

	if request.SessionID == "" {
		return newPlacementError(ErrorKindInvalidRequest, "request", "session id required", nil)
	}

	if request.Protocol == "" {
		return newPlacementError(ErrorKindInvalidRequest, "request", "protocol required", nil)
	}

	if request.BackendPool == "" {
		return newPlacementError(ErrorKindInvalidRequest, "request", "backend pool required", nil)
	}

	if request.ShardTag == "" {
		return newPlacementError(ErrorKindInvalidRequest, "request", "shard tag required", nil)
	}

	if request.LeaseTTL <= 0 {
		return newPlacementError(ErrorKindInvalidRequest, "request", "lease ttl required", nil)
	}

	if request.IdleGrace < 0 || request.RetentionTTL < 0 {
		return newPlacementError(ErrorKindInvalidRequest, "request", "negative ttl forbidden", nil)
	}

	switch request.HolderKind {
	case state.HolderKindSession, state.HolderKindDelivery:
		return nil
	default:
		return newPlacementError(ErrorKindInvalidRequest, "request", "holder kind unsupported", nil)
	}
}

// sessionRecord converts a placement request into the state holder record.
func (r Request) sessionRecord(backendNode string) state.SessionRecord {
	return state.SessionRecord{
		ID:                 r.SessionID,
		Key:                r.Key,
		HolderKind:         r.HolderKind,
		Protocol:           r.Protocol,
		ListenerName:       r.ListenerName,
		ServiceName:        r.ServiceName,
		ShardTag:           r.ShardTag,
		BackendNode:        strings.TrimSpace(backendNode),
		DirectorInstanceID: r.DirectorInstanceID,
		LeaseTTL:           r.LeaseTTL,
		IdleGrace:          r.IdleGrace,
		RetentionTTL:       r.RetentionTTL,
	}
}

// reusableBinding reports whether affinity state owns a concrete backend node.
func reusableBinding(record state.AffinityRecord) bool {
	if !record.Present || strings.TrimSpace(record.BackendNode) == "" {
		return false
	}

	switch record.BindingStatus {
	case state.BindingStatusActive, state.BindingStatusRetained, state.BindingStatusBackendNodeMismatch:
		return true
	default:
		return record.Status == affinityStatusFound || record.Status == affinityStatusRetained || record.Status == affinityStatusReused
	}
}

// movementOverrideShard returns the explicit move target that may supersede binding.
func movementOverrideShard(record state.AffinityRecord) string {
	targetShard := strings.TrimSpace(record.MoveTargetShard)
	if targetShard == "" {
		return ""
	}

	switch strings.TrimSpace(record.MoveStrategy) {
	case moveStrategyDrain:
		return targetShard
	case moveStrategyNew, moveStrategyKick:
		if record.ActiveHolderCount == 0 && record.ActiveSessionCount == 0 {
			return targetShard
		}
	}

	return ""
}

// initialSelectionShard preserves legacy shard affinity when no backend node exists.
func initialSelectionShard(request Request, affinity state.AffinityRecord) string {
	if affinity.Present && strings.TrimSpace(affinity.ShardTag) != "" {
		return strings.TrimSpace(affinity.ShardTag)
	}

	return request.ShardTag
}

// bindingSourceFromAffinity maps state status into a placement source.
func bindingSourceFromAffinity(record state.AffinityRecord, fallback BindingSource) BindingSource {
	switch record.Status {
	case affinityStatusRetained:
		return BindingSourceRetainedBinding
	case affinityStatusReused, affinityStatusFound:
		return BindingSourceActiveAffinity
	default:
		return fallback
	}
}

// pinMatchesProtocolPool checks whether a stored pin belongs to this protocol request.
func pinMatchesProtocolPool(pin state.UserBackendPinRecord, protocol string, backendPool string) bool {
	return pin.Present &&
		strings.TrimSpace(pin.BackendIdentifier) != "" &&
		strings.EqualFold(strings.TrimSpace(pin.Protocol), strings.TrimSpace(protocol)) &&
		strings.TrimSpace(pin.BackendPool) == strings.TrimSpace(backendPool)
}

// sameBackendNode compares concrete backend-node identifiers after normalization.
func sameBackendNode(left string, right string) bool {
	return strings.TrimSpace(left) == strings.TrimSpace(right)
}

// newPlacementError creates a classified placement error.
func newPlacementError(kind ErrorKind, operation string, message string, cause error) error {
	return &Error{
		Kind:      kind,
		Operation: operation,
		Message:   message,
		cause:     cause,
	}
}
