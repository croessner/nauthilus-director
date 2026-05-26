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
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/config"
)

// EffectiveExclusionReason classifies why an effective backend cannot be used.
type EffectiveExclusionReason string

const (
	runtimeOverrideErrorField = "runtime_override"

	// EffectiveExclusionAmbiguousState reports runtime state that cannot be trusted.
	EffectiveExclusionAmbiguousState EffectiveExclusionReason = "ambiguous_state"
	// EffectiveExclusionHealth reports health state that excludes placement.
	EffectiveExclusionHealth EffectiveExclusionReason = "health"
	// EffectiveExclusionMaxConnections reports a saturated backend.
	EffectiveExclusionMaxConnections EffectiveExclusionReason = "max_connections"
	// EffectiveExclusionRuntimeDrain reports an active runtime drain.
	EffectiveExclusionRuntimeDrain EffectiveExclusionReason = "runtime_drain"
	// EffectiveExclusionRuntimeHardMaintenance reports runtime hard maintenance.
	EffectiveExclusionRuntimeHardMaintenance EffectiveExclusionReason = "runtime_hard_maintenance"
	// EffectiveExclusionRuntimeOut reports an operator runtime out override.
	EffectiveExclusionRuntimeOut EffectiveExclusionReason = "runtime_out"
	// EffectiveExclusionRuntimeSoftMaintenance reports runtime soft maintenance.
	EffectiveExclusionRuntimeSoftMaintenance EffectiveExclusionReason = "runtime_soft_maintenance"
	// EffectiveExclusionStaticHardMaintenance reports configured hard maintenance.
	EffectiveExclusionStaticHardMaintenance EffectiveExclusionReason = "static_hard_maintenance"
	// EffectiveExclusionStaticSoftMaintenance reports configured soft maintenance.
	EffectiveExclusionStaticSoftMaintenance EffectiveExclusionReason = "static_soft_maintenance"
	// EffectiveExclusionWeightZero reports an effective weight of zero.
	EffectiveExclusionWeightZero EffectiveExclusionReason = "weight_zero"
)

// EffectiveExclusion is a secret-safe placement exclusion explanation.
type EffectiveExclusion struct {
	Reason EffectiveExclusionReason
	Source string
	Detail string
}

// RuntimeOverridePolicy mirrors the safe runtime override config switches.
type RuntimeOverridePolicy struct {
	Enabled             bool
	AllowWeightOverride bool
	AllowInOut          bool
	AllowDrain          bool
	MinWeight           int
	MaxWeight           int
}

// EffectiveBackendPolicy configures how the effective backend view is evaluated.
type EffectiveBackendPolicy struct {
	RuntimeOverrides     RuntimeOverridePolicy
	SoftAllowsActivePins bool
	EnforceHealth        bool
}

// RuntimeOverride contains optional Redis-backed backend overrides.
type RuntimeOverride struct {
	InService   *bool
	Weight      *int
	Maintenance *MaintenanceState
	Drain       *DrainState
	Generation  string
	UpdatedAt   time.Time
}

// EffectiveBackendInput collects all state layers for one backend.
type EffectiveBackendInput struct {
	Backend         Backend
	RuntimeOverride RuntimeOverride
	Health          HealthState
	ActiveSessions  int
	Policy          EffectiveBackendPolicy
	Now             time.Time
}

// EffectiveBackendState is the shared selector, route lookup and control view.
type EffectiveBackendState struct {
	Backend              Backend
	Identifier           string
	Protocol             string
	BackendPool          string
	EffectiveShardTag    string
	ConfiguredWeight     int
	EffectiveWeight      int
	MaxConnections       int
	ActiveSessions       int
	StaticMaintenance    MaintenanceMode
	RuntimeMaintenance   MaintenanceMode
	EffectiveMaintenance MaintenanceMode
	RuntimeInService     bool
	Health               HealthState
	Drain                DrainState
	Generation           string
	AllowsNewSessions    bool
	AllowsActivePins     bool
	FailClosed           bool
	FailClosedReason     EffectiveExclusionReason
	Exclusions           []EffectiveExclusion
}

// NewRuntimeOverridePolicy builds runtime policy from typed config.
func NewRuntimeOverridePolicy(runtimeOverrides config.RuntimeOverridesConfig) RuntimeOverridePolicy {
	return RuntimeOverridePolicy{
		Enabled:             runtimeOverrides.Enabled,
		AllowWeightOverride: runtimeOverrides.Backends.AllowWeightOverride,
		AllowInOut:          runtimeOverrides.Backends.AllowInOut,
		AllowDrain:          runtimeOverrides.Backends.AllowDrain,
		MinWeight:           runtimeOverrides.Backends.MinWeight,
		MaxWeight:           runtimeOverrides.Backends.MaxWeight,
	}.Normalize()
}

// NewEffectiveBackendPolicy builds effective-state policy from typed config.
func NewEffectiveBackendPolicy(director config.DirectorConfig) EffectiveBackendPolicy {
	return EffectiveBackendPolicy{
		RuntimeOverrides:     NewRuntimeOverridePolicy(director.RuntimeOverrides),
		SoftAllowsActivePins: director.Maintenance.SoftAllowsActivePins,
	}
}

// BoolOverride returns a pointer used to mark an optional boolean override present.
//
//go:fix inline
func BoolOverride(value bool) *bool {
	return new(value)
}

// IntOverride returns a pointer used to mark an optional integer override present.
//
//go:fix inline
func IntOverride(value int) *int {
	return new(value)
}

// Normalize applies safe defaults to a runtime override policy.
func (p RuntimeOverridePolicy) Normalize() RuntimeOverridePolicy {
	if p.MaxWeight == 0 {
		p.MaxWeight = 10000
	}

	if p.MinWeight < 0 {
		p.MinWeight = 0
	}

	return p
}

// Normalize applies safe defaults to effective backend policy.
func (p EffectiveBackendPolicy) Normalize() EffectiveBackendPolicy {
	p.RuntimeOverrides = p.RuntimeOverrides.Normalize()

	return p
}

// HasOverrides reports whether any optional runtime value is present.
func (o RuntimeOverride) HasOverrides() bool {
	return o.InService != nil || o.Weight != nil || o.Maintenance != nil || o.Drain != nil
}

// Clear returns an override with all runtime-only fields removed.
func (o RuntimeOverride) Clear() RuntimeOverride {
	return RuntimeOverride{}
}

// Validate rejects override state that cannot be safely applied.
func (o RuntimeOverride) Validate(policy RuntimeOverridePolicy) error {
	policy = policy.Normalize()

	if err := o.validatePolicyEnabled(policy); err != nil {
		return err
	}

	if err := o.validateWeightOverride(policy); err != nil {
		return err
	}

	if err := o.validateInOutOverride(policy); err != nil {
		return err
	}

	if err := o.validateDrainOverride(policy); err != nil {
		return err
	}

	return o.validateStatePayloads()
}

// validatePolicyEnabled rejects present overrides when runtime overrides are disabled.
func (o RuntimeOverride) validatePolicyEnabled(policy RuntimeOverridePolicy) error {
	if !policy.Enabled && o.HasOverrides() {
		return newBackendError(ErrorKindInvalidRequest, runtimeOverrideErrorField, "runtime overrides disabled", nil)
	}

	return nil
}

// validateWeightOverride enforces the configured weight override envelope.
func (o RuntimeOverride) validateWeightOverride(policy RuntimeOverridePolicy) error {
	if o.Weight == nil {
		return nil
	}

	if !policy.AllowWeightOverride {
		return newBackendError(ErrorKindInvalidRequest, runtimeOverrideErrorField, "weight override disabled", nil)
	}

	if *o.Weight < policy.MinWeight || *o.Weight > policy.MaxWeight {
		return newBackendError(ErrorKindInvalidRequest, runtimeOverrideErrorField, "weight override outside allowed range", nil)
	}

	return nil
}

// validateInOutOverride enforces the configured in/out override switch.
func (o RuntimeOverride) validateInOutOverride(policy RuntimeOverridePolicy) error {
	if o.InService != nil && !policy.AllowInOut {
		return newBackendError(ErrorKindInvalidRequest, runtimeOverrideErrorField, "in/out override disabled", nil)
	}

	return nil
}

// validateDrainOverride enforces the configured drain override switch.
func (o RuntimeOverride) validateDrainOverride(policy RuntimeOverridePolicy) error {
	if o.Drain != nil && !policy.AllowDrain {
		return newBackendError(ErrorKindInvalidRequest, runtimeOverrideErrorField, "drain override disabled", nil)
	}

	return nil
}

// validateStatePayloads normalizes nested maintenance and drain payloads.
func (o RuntimeOverride) validateStatePayloads() error {
	if o.Maintenance != nil {
		if _, err := o.Maintenance.Normalize(MaintenanceModeDisabled); err != nil {
			return err
		}
	}

	if o.Drain != nil {
		if _, err := o.Drain.Normalize(); err != nil {
			return err
		}
	}

	return nil
}

// NewEffectiveBackendState overlays config, runtime, health and active counts.
func NewEffectiveBackendState(input EffectiveBackendInput) (EffectiveBackendState, error) {
	input.Policy = input.Policy.Normalize()
	if err := input.RuntimeOverride.Validate(input.Policy.RuntimeOverrides); err != nil {
		return EffectiveBackendState{}, err
	}

	state, err := baseEffectiveBackendState(input)
	if err != nil {
		return EffectiveBackendState{}, err
	}

	state.applyMaintenance(input)
	state.applyRuntimeInOut(input.RuntimeOverride)
	state.applyDrain(input.RuntimeOverride)

	if err := state.applyHealth(input); err != nil {
		return EffectiveBackendState{}, err
	}

	if err := state.applyLimits(input); err != nil {
		return EffectiveBackendState{}, err
	}

	state.applyWeight()
	state.finalizeFailClosed()

	return state, nil
}

// Eligible reports whether the effective state can serve the requested placement kind.
func (s EffectiveBackendState) Eligible(activeAffinity bool) bool {
	if activeAffinity {
		return s.AllowsActivePins
	}

	return s.AllowsNewSessions
}

// HasExclusion reports whether the effective state carries a specific exclusion.
func (s EffectiveBackendState) HasExclusion(reason EffectiveExclusionReason) bool {
	for _, exclusion := range s.Exclusions {
		if exclusion.Reason == reason {
			return true
		}
	}

	return false
}

// baseEffectiveBackendState validates immutable backend facts and initializes defaults.
func baseEffectiveBackendState(input EffectiveBackendInput) (EffectiveBackendState, error) {
	backend := input.Backend
	if strings.TrimSpace(backend.Identifier) == "" {
		return EffectiveBackendState{}, newBackendError(ErrorKindAmbiguous, "effective_state", "backend identifier required", nil)
	}

	if normalizeProtocol(backend.Protocol) == "" {
		return EffectiveBackendState{}, newBackendError(ErrorKindAmbiguous, "effective_state", "backend protocol required", nil)
	}

	if strings.TrimSpace(backend.BackendPool) == "" {
		return EffectiveBackendState{}, newBackendError(ErrorKindAmbiguous, "effective_state", "backend pool required", nil)
	}

	if strings.TrimSpace(backend.ShardTag) == "" {
		return EffectiveBackendState{}, newBackendError(ErrorKindAmbiguous, "effective_state", "effective shard required", nil)
	}

	if backend.Weight < 0 {
		return EffectiveBackendState{}, newBackendError(ErrorKindAmbiguous, "effective_state", "configured weight must not be negative", nil)
	}

	staticMaintenance, err := NormalizeMaintenanceMode(backend.MaintenanceMode, MaintenanceModeDisabled)
	if err != nil {
		return EffectiveBackendState{}, err
	}

	effectiveWeight := backend.Weight
	if input.RuntimeOverride.Weight != nil {
		effectiveWeight = *input.RuntimeOverride.Weight
	}

	return EffectiveBackendState{
		Backend:              backend,
		Identifier:           strings.TrimSpace(backend.Identifier),
		Protocol:             normalizeProtocol(backend.Protocol),
		BackendPool:          strings.TrimSpace(backend.BackendPool),
		EffectiveShardTag:    strings.TrimSpace(backend.ShardTag),
		ConfiguredWeight:     backend.Weight,
		EffectiveWeight:      effectiveWeight,
		MaxConnections:       backend.MaxConnections,
		ActiveSessions:       input.ActiveSessions,
		StaticMaintenance:    staticMaintenance,
		EffectiveMaintenance: staticMaintenance,
		RuntimeInService:     true,
		AllowsNewSessions:    true,
		AllowsActivePins:     true,
		Generation:           strings.TrimSpace(input.RuntimeOverride.Generation),
	}, nil
}

// applyMaintenance overlays runtime maintenance without weakening static maintenance.
func (s *EffectiveBackendState) applyMaintenance(input EffectiveBackendInput) {
	runtimeMaintenance := MaintenanceModeDisabled
	if input.RuntimeOverride.Maintenance != nil {
		maintenance, err := input.RuntimeOverride.Maintenance.Normalize(MaintenanceModeDisabled)
		if err == nil {
			runtimeMaintenance = maintenance.Mode
		}
	}

	s.RuntimeMaintenance = runtimeMaintenance
	s.EffectiveMaintenance = StrongestMaintenanceMode(s.StaticMaintenance, runtimeMaintenance)

	if s.StaticMaintenance == MaintenanceModeHard {
		s.excludeNewAndActive(EffectiveExclusionStaticHardMaintenance, "config", "static hard maintenance")
		return
	}

	if runtimeMaintenance == MaintenanceModeHard {
		s.excludeNewAndActive(EffectiveExclusionRuntimeHardMaintenance, "runtime", "runtime hard maintenance")
		return
	}

	if s.StaticMaintenance == MaintenanceModeSoft {
		s.excludeNew(EffectiveExclusionStaticSoftMaintenance, "config", "static soft maintenance")

		if !input.Policy.SoftAllowsActivePins {
			s.excludeActive(EffectiveExclusionStaticSoftMaintenance, "config", "static soft maintenance")
		}
	}

	if runtimeMaintenance == MaintenanceModeSoft {
		s.excludeNew(EffectiveExclusionRuntimeSoftMaintenance, "runtime", "runtime soft maintenance")

		if !input.Policy.SoftAllowsActivePins {
			s.excludeActive(EffectiveExclusionRuntimeSoftMaintenance, "runtime", "runtime soft maintenance")
		}
	}
}

// applyRuntimeInOut overlays operator in/out state for new placements.
func (s *EffectiveBackendState) applyRuntimeInOut(override RuntimeOverride) {
	if override.InService == nil {
		return
	}

	s.RuntimeInService = *override.InService
	if !s.RuntimeInService {
		s.excludeNew(EffectiveExclusionRuntimeOut, "runtime", "backend marked out")
	}
}

// applyDrain overlays runtime drain state for new and active placement.
func (s *EffectiveBackendState) applyDrain(override RuntimeOverride) {
	if override.Drain == nil {
		s.Drain = DrainState{Mode: DrainModeDisabled}
		return
	}

	drain, err := override.Drain.Normalize()
	if err != nil {
		s.excludeNewAndActive(EffectiveExclusionAmbiguousState, "runtime", "invalid drain state")
		return
	}

	s.Drain = drain
	if !drain.Enabled {
		return
	}

	s.excludeNew(EffectiveExclusionRuntimeDrain, "runtime", "backend draining")

	if !drain.PreservesActivePins() {
		s.excludeActive(EffectiveExclusionRuntimeDrain, "runtime", "hard drain")
	}
}

// applyHealth overlays health state when health enforcement is enabled.
func (s *EffectiveBackendState) applyHealth(input EffectiveBackendInput) error {
	health, err := input.Health.Normalize(input.Now)
	if err != nil {
		return err
	}

	if !health.Enabled && input.Policy.EnforceHealth && input.Backend.HealthEnabled {
		health.Enabled = true
		health.Status = HealthStatusUnknown
	}

	s.Health = health
	if !health.AllowsNewPlacement(input.Policy.EnforceHealth) {
		s.excludeNew(EffectiveExclusionHealth, "health", string(health.Status))
	}

	return nil
}

// applyLimits overlays Redis-backed active counts with configured max connections.
func (s *EffectiveBackendState) applyLimits(input EffectiveBackendInput) error {
	limits, err := (ConnectionLimitState{
		MaxConnections: input.Backend.MaxConnections,
		ActiveSessions: input.ActiveSessions,
	}).Normalize()
	if err != nil {
		return err
	}

	s.MaxConnections = limits.MaxConnections
	s.ActiveSessions = limits.ActiveSessions

	if limits.AtCapacity() {
		s.excludeNew(EffectiveExclusionMaxConnections, "runtime", "backend at capacity")
	}

	return nil
}

// applyWeight excludes only new initial placement for effective weight zero.
func (s *EffectiveBackendState) applyWeight() {
	if s.EffectiveWeight == 0 {
		s.excludeNew(EffectiveExclusionWeightZero, "effective", "effective weight zero")
	}
}

// finalizeFailClosed marks ambiguous exclusions as fail-closed state.
func (s *EffectiveBackendState) finalizeFailClosed() {
	for _, exclusion := range s.Exclusions {
		if exclusion.Reason == EffectiveExclusionAmbiguousState {
			s.FailClosed = true
			s.FailClosedReason = exclusion.Reason

			return
		}
	}
}

// excludeNew records an exclusion for new sessions.
func (s *EffectiveBackendState) excludeNew(reason EffectiveExclusionReason, source string, detail string) {
	s.AllowsNewSessions = false
	s.addExclusion(reason, source, detail)
}

// excludeActive records an exclusion for active pins.
func (s *EffectiveBackendState) excludeActive(reason EffectiveExclusionReason, source string, detail string) {
	s.AllowsActivePins = false
	s.addExclusion(reason, source, detail)
}

// excludeNewAndActive records an exclusion that blocks all placement.
func (s *EffectiveBackendState) excludeNewAndActive(reason EffectiveExclusionReason, source string, detail string) {
	s.AllowsNewSessions = false
	s.AllowsActivePins = false
	s.addExclusion(reason, source, detail)
}

// addExclusion appends one classified exclusion if it is not already present.
func (s *EffectiveBackendState) addExclusion(reason EffectiveExclusionReason, source string, detail string) {
	for _, existing := range s.Exclusions {
		if existing.Reason == reason && existing.Source == source {
			return
		}
	}

	s.Exclusions = append(s.Exclusions, EffectiveExclusion{
		Reason: reason,
		Source: source,
		Detail: detail,
	})
}
