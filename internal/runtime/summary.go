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

import "time"

const (
	operationRuntimeSummary = "runtime_summary"

	// AccuracyEventuallyRepaired marks aggregate values that repair asynchronously.
	AccuracyEventuallyRepaired = "eventually_repaired"
	// AccuracyCumulative marks monotonically increasing repair counters.
	AccuracyCumulative = "cumulative"
)

// Summary carries repairable operator totals and never participates in routing.
type Summary struct {
	GeneratedAt      time.Time
	RoutingAuthority bool
	ActiveSessions   ActiveSessionSummary
	IdleAffinities   CountSummary
	BackendCapacity  []BackendCapacitySummary
	Repairs          RepairSummary
}

// ActiveSessionSummary groups active sessions by bounded operational dimensions.
type ActiveSessionSummary struct {
	Total      CountSummary
	ByProtocol []DimensionCount
	ByListener []DimensionCount
	ByService  []DimensionCount
	ByShardTag []DimensionCount
}

// CountSummary carries a count with its operator-facing accuracy class.
type CountSummary struct {
	Count    int
	Accuracy string
}

// DimensionCount carries one dimension bucket count.
type DimensionCount struct {
	Value    string
	Count    int
	Accuracy string
}

// BackendCapacitySummary carries backend active and reserved capacity totals.
type BackendCapacitySummary struct {
	BackendIdentifier string
	ActiveSessions    CountSummary
	ReservedSessions  CountSummary
	SummaryRepairable bool
	RoutingAuthority  bool
}

// RepairSummary carries cumulative repair counters.
type RepairSummary struct {
	ExpiredSessions     CountSummary
	StaleIndexEntries   CountSummary
	BackendReservations CountSummary
}
