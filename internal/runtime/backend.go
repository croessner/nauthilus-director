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
	"strings"

	"github.com/croessner/nauthilus-director/internal/backend"
)

const (
	operationBackendDrain        = "backend_drain"
	operationBackendInOut        = "backend_in_out"
	operationBackendMaintenance  = "backend_maintenance"
	operationBackendRuntimeClear = "backend_runtime_clear"
	operationBackendWeight       = "backend_weight"
)

// SetBackendInServiceRequest asks runtime state to mark a backend in or out.
type SetBackendInServiceRequest struct {
	BackendIdentifier  string
	InService          bool
	Reason             string
	Actor              Actor
	ExpectedGeneration string
}

// SetBackendWeightRequest asks runtime state to overlay a backend weight.
type SetBackendWeightRequest struct {
	BackendIdentifier  string
	Weight             int
	Reason             string
	Actor              Actor
	ExpectedGeneration string
}

// SetBackendMaintenanceRequest asks runtime state to overlay backend maintenance.
type SetBackendMaintenanceRequest struct {
	BackendIdentifier  string
	Maintenance        backend.MaintenanceState
	Reason             string
	Actor              Actor
	ExpectedGeneration string
}

// StartBackendDrainRequest asks runtime state to start an auditable drain.
type StartBackendDrainRequest struct {
	BackendIdentifier  string
	Drain              backend.DrainState
	Reason             string
	Actor              Actor
	ExpectedGeneration string
}

// ClearBackendRuntimeRequest asks runtime state to remove runtime-only backend overrides.
type ClearBackendRuntimeRequest struct {
	BackendIdentifier  string
	Reason             string
	Actor              Actor
	ExpectedGeneration string
}

// BackendMutationResult describes a runtime backend mutation outcome.
type BackendMutationResult struct {
	BackendIdentifier string
	Override          backend.RuntimeOverride
	EffectiveState    backend.EffectiveBackendState
	Audit             AuditMetadata
}

// Validate checks the in/out request before it crosses a persistence boundary.
func (r SetBackendInServiceRequest) Validate() error {
	if err := requireBackendIdentifier(operationBackendInOut, r.BackendIdentifier); err != nil {
		return err
	}

	return requireReason(operationBackendInOut, r.Reason)
}

// Validate checks the weight request before it crosses a persistence boundary.
func (r SetBackendWeightRequest) Validate(policy backend.RuntimeOverridePolicy) error {
	if err := requireBackendIdentifier(operationBackendWeight, r.BackendIdentifier); err != nil {
		return err
	}

	if err := requireReason(operationBackendWeight, r.Reason); err != nil {
		return err
	}

	override := backend.RuntimeOverride{Weight: new(r.Weight)}

	return override.Validate(policy)
}

// Validate checks the maintenance request before it crosses a persistence boundary.
func (r SetBackendMaintenanceRequest) Validate() error {
	if err := requireBackendIdentifier(operationBackendMaintenance, r.BackendIdentifier); err != nil {
		return err
	}

	if err := requireReason(operationBackendMaintenance, r.Reason); err != nil {
		return err
	}

	_, err := r.Maintenance.Normalize(backend.MaintenanceModeDisabled)

	return err
}

// Validate checks the drain request before it crosses a persistence boundary.
func (r StartBackendDrainRequest) Validate() error {
	if err := requireBackendIdentifier(operationBackendDrain, r.BackendIdentifier); err != nil {
		return err
	}

	if err := requireReason(operationBackendDrain, r.Reason); err != nil {
		return err
	}

	_, err := r.Drain.Normalize()

	return err
}

// Validate checks the runtime clear request before it crosses a persistence boundary.
func (r ClearBackendRuntimeRequest) Validate() error {
	if err := requireBackendIdentifier(operationBackendRuntimeClear, r.BackendIdentifier); err != nil {
		return err
	}

	return requireReason(operationBackendRuntimeClear, r.Reason)
}

// RuntimeOverride converts an in/out request into optional runtime state.
func (r SetBackendInServiceRequest) RuntimeOverride() backend.RuntimeOverride {
	return backend.RuntimeOverride{
		InService:  new(r.InService),
		Generation: strings.TrimSpace(r.ExpectedGeneration),
	}
}

// RuntimeOverride converts a weight request into optional runtime state.
func (r SetBackendWeightRequest) RuntimeOverride() backend.RuntimeOverride {
	return backend.RuntimeOverride{
		Weight:     new(r.Weight),
		Generation: strings.TrimSpace(r.ExpectedGeneration),
	}
}

// RuntimeOverride converts a maintenance request into optional runtime state.
func (r SetBackendMaintenanceRequest) RuntimeOverride() backend.RuntimeOverride {
	maintenance := r.Maintenance

	return backend.RuntimeOverride{
		Maintenance: &maintenance,
		Generation:  strings.TrimSpace(r.ExpectedGeneration),
	}
}

// RuntimeOverride converts a drain request into optional runtime state.
func (r StartBackendDrainRequest) RuntimeOverride() backend.RuntimeOverride {
	drain := r.Drain

	return backend.RuntimeOverride{
		Drain:      &drain,
		Generation: strings.TrimSpace(r.ExpectedGeneration),
	}
}

// requireBackendIdentifier rejects empty backend mutation targets.
func requireBackendIdentifier(operation string, identifier string) error {
	if strings.TrimSpace(identifier) == "" {
		return newRuntimeError(ErrorKindInvalidRequest, operation, "backend identifier required")
	}

	return nil
}
