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

package observability

import "context"

const (
	// EventListenerStart records a frontend listener bind.
	EventListenerStart = "listener.start"
	// EventListenerStop records a frontend listener shutdown.
	EventListenerStop = "listener.stop"
	// EventSessionStart records an accepted frontend protocol session.
	EventSessionStart = "session.start"
	// EventSessionEnd records the terminal frontend protocol session outcome.
	EventSessionEnd = "session.end"
	// EventIMAPPreAuth records pre-auth IMAP command handling.
	EventIMAPPreAuth = "imap.pre_auth"
	// EventProxyProtocol records listener PROXY protocol handling.
	EventProxyProtocol = "listener.proxy_protocol"
	// EventNauthilusAuth records one Nauthilus authentication request outcome.
	EventNauthilusAuth = "nauthilus.auth"
	// EventRoutingResolve records director-owned routing resolution.
	EventRoutingResolve = "routing.resolve"
	// EventAffinityOpen records active affinity and session-open state.
	EventAffinityOpen = "affinity.open"
	// EventBackendSelect records director-owned backend selection.
	EventBackendSelect = "backend.select"
	// EventBackendConnect records selected backend connection setup.
	EventBackendConnect = "backend.connect"
	// EventBackendAuth records selected backend authentication.
	EventBackendAuth = "backend.auth"
	// EventBackendHealth records backend health transition and ownership results.
	EventBackendHealth = "backend.health"
	// EventBackendHealthTransition records a classified backend health state change.
	EventBackendHealthTransition = "backend.health.transition"
	// EventBackendEffectiveState records an effective backend eligibility state change.
	EventBackendEffectiveState = "backend.effective_state"
	// EventBackendRuntimeOperation records an operator backend runtime override.
	EventBackendRuntimeOperation = "backend.runtime.operation"
	// EventBackendMaintenance records backend maintenance and drain transitions.
	EventBackendMaintenance = "backend.maintenance"
	// EventBackendMaintenanceOperation records an operator backend maintenance change.
	EventBackendMaintenanceOperation = "backend.maintenance.operation"
	// EventBackendDrain records backend drain start and terminal outcomes.
	EventBackendDrain = "backend.drain"
	// EventSelectorExclusion records a classified backend selector exclusion.
	EventSelectorExclusion = "selector.exclusion"
	// EventSessionAttach records selected-backend session attachment.
	EventSessionAttach = "session.attach"
	// EventSessionClose records session lease closure.
	EventSessionClose = "session.close"
	// EventSessionReap records expired-session repair.
	EventSessionReap = "session.reap"
	// EventSessionKill records an operator session kill.
	EventSessionKill = "session.kill"
	// EventUserMove records an operator user move.
	EventUserMove = "user.move"
	// EventUserKick records an operator user kick.
	EventUserKick = "user.kick"
	// EventAffinityClear records an operator affinity clear.
	EventAffinityClear = "affinity.clear"
	// EventRouteLookup records a side-effect-free route diagnostic.
	EventRouteLookup = "route.lookup"
	// EventRESTRequest records one generated REST control API request.
	EventRESTRequest = "rest.request"
	// EventReload records safe reload attempts and outcomes.
	EventReload = "reload"
	// EventRedisOperation records one Redis state operation class.
	EventRedisOperation = "redis.operation"
	// EventProxyPipe records transparent proxy lifecycle completion.
	EventProxyPipe = "proxy.pipe"
)

// Event contains one secret-safe observability observation.
type Event struct {
	Name         string
	SpanName     string
	LogFields    LogFields
	MetricLabels MetricLabels
	Measurements MetricMeasurements
}

// Recorder receives normalized events from runtime packages.
type Recorder interface {
	Record(ctx context.Context, event Event)
}

// RecorderFunc adapts a function into a Recorder.
type RecorderFunc func(context.Context, Event)

// Record calls the wrapped recorder function.
func (f RecorderFunc) Record(ctx context.Context, event Event) {
	if f == nil {
		return
	}

	f(ctx, event)
}

// NoopRecorder drops events while keeping runtime hooks cheap by default.
type NoopRecorder struct{}

// Record intentionally ignores the supplied event.
func (NoopRecorder) Record(context.Context, Event) {}

// NormalizeRecorder returns a usable recorder for nil-safe runtime code.
func NormalizeRecorder(recorder Recorder) Recorder {
	if recorder == nil {
		return NoopRecorder{}
	}

	return recorder
}

// RuntimeEventNames returns the stable runtime/control event vocabulary.
func RuntimeEventNames() []string {
	return []string{
		EventBackendHealthTransition,
		EventBackendEffectiveState,
		EventBackendRuntimeOperation,
		EventBackendMaintenanceOperation,
		EventBackendDrain,
		EventSelectorExclusion,
		EventSessionAttach,
		EventSessionClose,
		EventSessionReap,
		EventSessionKill,
		EventUserMove,
		EventUserKick,
		EventAffinityClear,
		EventRouteLookup,
		EventReload,
		EventRedisOperation,
	}
}

// NewEvent sanitizes log fields and validates metric labels before recording.
func NewEvent(name string, boundary TraceBoundary, fields map[string]string, labels map[string]string) (Event, error) {
	metricLabels, err := NewMetricLabels(labels)
	if err != nil {
		return Event{}, err
	}

	spanName := ""

	if boundary != "" {
		if prepared, ok := SpanName(boundary); ok {
			spanName = prepared
		}
	}

	return Event{
		Name:         name,
		SpanName:     spanName,
		LogFields:    SanitizeLogFields(fields),
		MetricLabels: metricLabels,
		Measurements: MetricMeasurements{},
	}, nil
}
