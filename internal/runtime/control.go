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
	"maps"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/observability"
)

const (
	operationBackendRead = "backend_read"
	operationReload      = "reload"
	defaultTenant        = "default"
)

// BackendReadServiceOptions configures backend inventory projection.
type BackendReadServiceOptions struct {
	Registry      backend.Registry
	Snapshots     backend.RuntimeSnapshotReader
	Policy        backend.EffectiveBackendPolicy
	Now           func() time.Time
	Observability observability.Recorder
}

// BackendReadService projects config plus runtime state into effective backends.
type BackendReadService struct {
	registry  backend.Registry
	snapshots backend.RuntimeSnapshotReader
	policy    backend.EffectiveBackendPolicy
	now       func() time.Time
	recorder  observability.Recorder
}

// NewBackendReadService creates a runtime-aware backend read service.
func NewBackendReadService(options BackendReadServiceOptions) (*BackendReadService, error) {
	if options.Registry == nil {
		return nil, newRuntimeError(ErrorKindUnavailable, operationBackendRead, "backend registry required")
	}

	if options.Now == nil {
		options.Now = time.Now
	}

	return &BackendReadService{
		registry:  options.Registry,
		snapshots: options.Snapshots,
		policy:    options.Policy.Normalize(),
		now:       options.Now,
		recorder:  observability.NormalizeRecorder(options.Observability),
	}, nil
}

// ListBackends returns every configured backend with runtime overlays applied.
func (s *BackendReadService) ListBackends(ctx context.Context) ([]backend.EffectiveBackendState, error) {
	if s == nil || s.registry == nil {
		return nil, newRuntimeError(ErrorKindUnavailable, operationBackendRead, "backend read service unavailable")
	}

	backends, err := s.registry.AllBackends(ctx)
	if err != nil {
		return nil, err
	}

	effective := make([]backend.EffectiveBackendState, 0, len(backends))
	for _, entry := range backends {
		state, err := s.effectiveBackend(ctx, entry)
		if err != nil {
			return nil, err
		}

		effective = append(effective, state)
	}

	return effective, nil
}

// GetBackend returns one configured backend with runtime overlays applied.
func (s *BackendReadService) GetBackend(ctx context.Context, identifier string) (backend.EffectiveBackendState, error) {
	if s == nil || s.registry == nil {
		return backend.EffectiveBackendState{}, newRuntimeError(ErrorKindUnavailable, operationBackendRead, "backend read service unavailable")
	}

	entry, err := s.registry.Lookup(ctx, strings.TrimSpace(identifier))
	if err != nil {
		return backend.EffectiveBackendState{}, err
	}

	return s.effectiveBackend(ctx, entry)
}

// effectiveBackend builds the shared effective-state domain object for one backend.
func (s *BackendReadService) effectiveBackend(ctx context.Context, entry backend.Backend) (backend.EffectiveBackendState, error) {
	var snapshot backend.RuntimeSnapshot

	if s.snapshots != nil {
		var err error

		snapshot, err = s.snapshots.BackendSnapshot(ctx, entry.Identifier)
		if err != nil {
			return backend.EffectiveBackendState{}, err
		}
	}

	state, err := backend.NewEffectiveBackendState(backend.EffectiveBackendInput{
		Backend:         entry,
		RuntimeOverride: snapshot.RuntimeOverride,
		Health:          snapshot.Health,
		ActiveSessions:  snapshot.ActiveSessions,
		Policy:          s.policy,
		Now:             s.now().UTC(),
	})
	if err != nil {
		return backend.EffectiveBackendState{}, err
	}

	s.recordEffectiveBackend(ctx, state)

	return state, nil
}

// SafeReloadLoader loads and validates the next config snapshot for reload.
type SafeReloadLoader func(context.Context) (config.Config, error)

// SafeReloadApplier applies a validated safe snapshot to live runtime objects.
type SafeReloadApplier interface {
	ApplySafeReload(ctx context.Context, current config.Config, next config.Config) error
}

// SafeReloadApplierFunc adapts a function into a safe-reload applier.
type SafeReloadApplierFunc func(context.Context, config.Config, config.Config) error

// ApplySafeReload calls the wrapped function.
func (f SafeReloadApplierFunc) ApplySafeReload(ctx context.Context, current config.Config, next config.Config) error {
	return f(ctx, current, next)
}

// ReloadResult describes one safe-reload outcome.
type ReloadResult struct {
	Generation string
	Applied    []string
}

// SafeReloadService validates and applies supported live config changes.
type SafeReloadService struct {
	mu         sync.Mutex
	current    config.Config
	load       SafeReloadLoader
	applier    SafeReloadApplier
	generation int
	recorder   observability.Recorder
}

// NewSafeReloadService creates a safe-reload domain service.
func NewSafeReloadService(current config.Config, load SafeReloadLoader, options ...ServiceOption) *SafeReloadService {
	applied := applyServiceOptions(options)

	return &SafeReloadService{
		current:  current.Normalize(),
		load:     load,
		applier:  applied.reloadApplier,
		recorder: applied.recorder,
	}
}

// Reload parses, validates and applies a safe config snapshot.
func (s *SafeReloadService) Reload(ctx context.Context) (ReloadResult, error) {
	if s == nil || s.load == nil {
		return ReloadResult{}, newRuntimeError(ErrorKindUnavailable, operationReload, "reload service unavailable")
	}

	next, err := s.load(ctx)
	if err != nil {
		s.recordReload(ctx, runtimeObservationResultFailure, "invalid_request", nil)

		return ReloadResult{}, newRuntimeError(ErrorKindInvalidRequest, operationReload, err.Error())
	}

	next = next.Normalize()

	s.mu.Lock()
	defer s.mu.Unlock()

	if rejected := unsafeReloadChanges(s.current, next); len(rejected) > 0 {
		s.recordReload(ctx, runtimeObservationResultFailure, "reload_unsafe", map[string]string{
			runtimeObservationFieldRejectedChanges: strings.Join(rejected, ";"),
		})

		return ReloadResult{}, newRuntimeError(ErrorKindConflict, operationReload, strings.Join(rejected, "; "))
	}

	applied := safeReloadChanges(s.current, next)
	if s.applier != nil {
		if err := s.applier.ApplySafeReload(ctx, s.current, next); err != nil {
			s.recordReload(ctx, runtimeObservationResultFailure, "reload_apply", map[string]string{
				runtimeObservationFieldRejectedChanges: err.Error(),
			})

			return ReloadResult{}, newRuntimeError(ErrorKindConflict, operationReload, err.Error())
		}
	}

	s.current = next
	s.generation++

	result := ReloadResult{Generation: reloadGeneration(s.generation), Applied: applied}
	s.recordReload(ctx, runtimeObservationResultOK, "reload_safe", map[string]string{
		runtimeObservationFieldAppliedChanges:    strings.Join(applied, ","),
		runtimeObservationFieldRuntimeGeneration: result.Generation,
	})

	return result, nil
}

// unsafeReloadChanges returns operator-readable reasons for unsupported live changes.
func unsafeReloadChanges(current config.Config, next config.Config) []string {
	var rejected []string

	if current.Runtime.InstanceName != next.Runtime.InstanceName {
		rejected = append(rejected, "runtime.instance_name requires restart")
	}

	if !reflect.DeepEqual(current.Runtime.Process, next.Runtime.Process) {
		rejected = append(rejected, "runtime.process requires restart")
	}

	if current.Runtime.Servers.Control.Enabled != next.Runtime.Servers.Control.Enabled {
		rejected = append(rejected, "runtime.servers.control.enabled requires restart")
	}

	if current.Runtime.Servers.Control.Address != next.Runtime.Servers.Control.Address {
		rejected = append(rejected, "runtime.servers.control.address requires restart")
	}

	if !reflect.DeepEqual(current.Runtime.Servers.Control.Auth, next.Runtime.Servers.Control.Auth) {
		rejected = append(rejected, "runtime.servers.control.auth requires restart")
	}

	if !reflect.DeepEqual(current.Runtime.Servers.Control.TLS, next.Runtime.Servers.Control.TLS) {
		rejected = append(rejected, "runtime.servers.control.tls requires restart")
	}

	if !reflect.DeepEqual(current.Runtime.State, next.Runtime.State) {
		rejected = append(rejected, "runtime.state requires restart")
	}

	if !reflect.DeepEqual(current.Runtime.Timeouts, next.Runtime.Timeouts) {
		rejected = append(rejected, "runtime.timeouts requires restart")
	}

	if !reflect.DeepEqual(current.Runtime.Clients, next.Runtime.Clients) {
		rejected = append(rejected, "runtime.clients requires restart")
	}

	if !reflect.DeepEqual(current.Auth, next.Auth) {
		rejected = append(rejected, "auth requires restart")
	}

	if !reflect.DeepEqual(current.Storage.Redis, next.Storage.Redis) {
		rejected = append(rejected, "storage.redis requires restart")
	}

	if !reflect.DeepEqual(current.Observability.Log, next.Observability.Log) {
		rejected = append(rejected, "observability.log requires restart")
	}

	if !reflect.DeepEqual(current.Observability.Metrics, next.Observability.Metrics) {
		rejected = append(rejected, "observability.metrics requires restart")
	}

	if !reflect.DeepEqual(current.Observability.Tracing, next.Observability.Tracing) {
		rejected = append(rejected, "observability.tracing requires restart")
	}

	if !reflect.DeepEqual(current.Observability.Profiles, next.Observability.Profiles) {
		rejected = append(rejected, "observability.profiles requires restart")
	}

	if !reflect.DeepEqual(current.Director.Security, next.Director.Security) {
		rejected = append(rejected, "director.security requires restart")
	}

	if !reflect.DeepEqual(current.Director.Routing, next.Director.Routing) {
		rejected = append(rejected, "director.routing requires restart")
	}

	if !reflect.DeepEqual(current.Director.Affinity, next.Director.Affinity) {
		rejected = append(rejected, "director.affinity requires restart")
	}

	if !reflect.DeepEqual(current.Director.RuntimeOverrides, next.Director.RuntimeOverrides) {
		rejected = append(rejected, "director.runtime_overrides requires restart")
	}

	if !reflect.DeepEqual(current.Director.Health, next.Director.Health) {
		rejected = append(rejected, "director.health requires restart")
	}

	if !reflect.DeepEqual(current.Director.Maintenance, next.Director.Maintenance) {
		rejected = append(rejected, "director.maintenance requires restart")
	}

	for _, listenerName := range changedExistingListeners(current.Director.Listeners, next.Director.Listeners) {
		rejected = append(rejected, "director.listeners."+listenerName+" requires restart")
	}

	return rejected
}

// changedExistingListeners returns listeners whose live socket config cannot be hot-swapped safely.
func changedExistingListeners(current map[string]config.ListenerConfig, next map[string]config.ListenerConfig) []string {
	var changed []string

	for name, currentListener := range current {
		nextListener, ok := next[name]
		if !ok {
			continue
		}

		if !reflect.DeepEqual(currentListener, nextListener) {
			changed = append(changed, name)
		}
	}

	sort.Strings(changed)

	return changed
}

// safeReloadChanges classifies supported live changes that the service applies to its snapshot.
func safeReloadChanges(current config.Config, next config.Config) []string {
	var applied []string
	if listenerInventoryChanged(current.Director.Listeners, next.Director.Listeners) {
		applied = append(applied, "director.listeners")
	}

	if !reflect.DeepEqual(current.Director.Backends, next.Director.Backends) {
		applied = append(applied, "director.backends")
	}

	if !reflect.DeepEqual(current.Director.BackendPools, next.Director.BackendPools) {
		applied = append(applied, "director.backend_pools")
	}

	if len(applied) == 0 {
		applied = append(applied, "no_change")
	}

	return applied
}

// listenerInventoryChanged reports safe add/remove changes after in-place changes are rejected.
func listenerInventoryChanged(current map[string]config.ListenerConfig, next map[string]config.ListenerConfig) bool {
	if len(current) != len(next) {
		return true
	}

	for name := range current {
		if _, ok := next[name]; !ok {
			return true
		}
	}

	return false
}

// reloadGeneration formats the local applied snapshot generation.
func reloadGeneration(value int) string {
	return "reload-" + strings.TrimSpace(time.Unix(int64(value), 0).UTC().Format("20060102150405"))
}

// recordEffectiveBackend emits effective backend state and exclusion observations.
func (s *BackendReadService) recordEffectiveBackend(ctx context.Context, state backend.EffectiveBackendState) {
	result := runtimeObservationResultEligible
	reasonClass := runtimeObservationResultOK

	if !state.Eligible(false) {
		result = runtimeObservationResultExcluded
		reasonClass = runtimeObservationReasonOther
	}

	if state.FailClosed {
		result = runtimeObservationResultFailClosed
		reasonClass = string(state.FailClosedReason)
	}

	fields := map[string]string{
		runtimeObservationFieldActiveSessions:    strconv.Itoa(state.ActiveSessions),
		runtimeObservationFieldBackendID:         state.Identifier,
		runtimeObservationFieldBackendPool:       state.BackendPool,
		runtimeObservationFieldRuntimeGeneration: state.Generation,
		runtimeObservationFieldShardTag:          state.EffectiveShardTag,
	}
	labels := map[string]string{
		runtimeObservationFieldBackendPool: state.BackendPool,
		runtimeObservationFieldProtocol:    state.Protocol,
		runtimeObservationFieldShardTag:    state.EffectiveShardTag,
	}
	recordRuntimeObservation(ctx, s.recorder, observability.EventBackendEffectiveState, observability.TraceBoundaryBackendSelect, runtimeObservationOperationBackendEffective, result, reasonClass, fields, labels)

	for _, exclusion := range state.Exclusions {
		s.recordSelectorExclusion(ctx, state, exclusion)
	}
}

// recordSelectorExclusion emits one classified selector exclusion observation.
func (s *BackendReadService) recordSelectorExclusion(ctx context.Context, state backend.EffectiveBackendState, exclusion backend.EffectiveExclusion) {
	recordRuntimeObservation(ctx, s.recorder, observability.EventSelectorExclusion, observability.TraceBoundaryBackendSelect, runtimeObservationOperationSelectorExclude, runtimeObservationResultExcluded, string(exclusion.Reason), map[string]string{
		runtimeObservationFieldBackendID:       state.Identifier,
		runtimeObservationFieldBackendPool:     state.BackendPool,
		runtimeObservationFieldExclusionDetail: exclusion.Detail,
		runtimeObservationFieldExclusionSource: exclusion.Source,
		runtimeObservationFieldShardTag:        state.EffectiveShardTag,
	}, map[string]string{
		runtimeObservationFieldBackendPool: state.BackendPool,
		runtimeObservationFieldProtocol:    state.Protocol,
		runtimeObservationFieldShardTag:    state.EffectiveShardTag,
	})
}

// recordReload emits one safe reload observation.
func (s *SafeReloadService) recordReload(ctx context.Context, result string, reasonClass string, fields map[string]string) {
	if s == nil {
		return
	}

	fields = reloadObservationFields(ctx, fields)

	recordRuntimeObservation(ctx, s.recorder, observability.EventReload, observability.TraceBoundaryRESTRequest, operationReload, result, reasonClass, fields, nil)
}

// reloadObservationFields adds audit-only actor facts to reload observations.
func reloadObservationFields(ctx context.Context, fields map[string]string) map[string]string {
	actor := ActorFromContext(ctx)
	if actor.ID == "" && actor.AuthMethod == "" && !actor.Authenticated {
		return fields
	}

	out := make(map[string]string, len(fields)+3)
	maps.Copy(out, fields)

	if actor.ID != "" {
		out[runtimeObservationFieldActorID] = actor.ID
	}

	if actor.AuthMethod != "" {
		out[runtimeObservationFieldAuthMethod] = actor.AuthMethod
	}

	out[runtimeObservationFieldActorAuthenticated] = strconv.FormatBool(actor.Authenticated)

	return out
}
