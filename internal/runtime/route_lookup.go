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

// RouteLookupRequest describes a side-effect-free route diagnostic request.
type RouteLookupRequest struct {
	Protocol       string
	ListenerName   string
	ServiceName    string
	BackendPool    string
	Tenant         string
	AccountKey     string
	RequestedShard string
	Attributes     map[string][]string
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

// RouteLookupBackendState describes one effective backend candidate safely.
type RouteLookupBackendState struct {
	Identifier        string
	Protocol          string
	BackendPool       string
	EffectiveShard    string
	AllowsNewSessions bool
	AllowsActivePins  bool
	FailClosed        bool
	FailClosedReason  backend.EffectiveExclusionReason
	Exclusions        []backend.EffectiveExclusion
}

// RouteLookupResponse describes the read-only route lookup outcome.
type RouteLookupResponse struct {
	Routing         RouteLookupRoutingState
	Backends        []RouteLookupBackendState
	SelectedBackend string
	FailClosed      bool
	ReasonClass     string
}

// Normalize trims stable request facts before route lookup orchestration.
func (r RouteLookupRequest) Normalize() RouteLookupRequest {
	r.Protocol = strings.ToLower(strings.TrimSpace(r.Protocol))
	r.ListenerName = strings.TrimSpace(r.ListenerName)
	r.ServiceName = strings.TrimSpace(r.ServiceName)
	r.BackendPool = strings.TrimSpace(r.BackendPool)
	r.Tenant = strings.TrimSpace(r.Tenant)
	r.AccountKey = strings.TrimSpace(r.AccountKey)
	r.RequestedShard = strings.TrimSpace(r.RequestedShard)
	r.Attributes = cloneAttributes(r.Attributes)

	return r
}

// NewRouteLookupBackendState projects effective backend state into diagnostics.
func NewRouteLookupBackendState(state backend.EffectiveBackendState) RouteLookupBackendState {
	return RouteLookupBackendState{
		Identifier:        state.Identifier,
		Protocol:          state.Protocol,
		BackendPool:       state.BackendPool,
		EffectiveShard:    state.EffectiveShardTag,
		AllowsNewSessions: state.AllowsNewSessions,
		AllowsActivePins:  state.AllowsActivePins,
		FailClosed:        state.FailClosed,
		FailClosedReason:  state.FailClosedReason,
		Exclusions:        append([]backend.EffectiveExclusion(nil), state.Exclusions...),
	}
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
