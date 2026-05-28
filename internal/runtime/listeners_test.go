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
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/observability"
)

const (
	listenerTestIMAPName    = "imap"
	listenerTestIMAPSName   = "imaps"
	listenerTestReason      = "node maintenance window"
	listenerTestServiceName = "imap-login"
	listenerTestEmptyName   = "empty name"
	listenerTestNoReason    = "missing reason"
)

// TestListenerServiceListAndGetReturnStableDetails verifies manager snapshots are projected deterministically.
func TestListenerServiceListAndGetReturnStableDetails(t *testing.T) {
	recorder := &recordingRuntimeObservation{}
	manager := &recordingListenerManager{
		snapshots: []ListenerDetail{
			listenerTestDetail(listenerTestIMAPSName, "imap", "imaps-login", ListenerStateDrained, 0),
			listenerTestDetail(listenerTestIMAPName, "imap", listenerTestServiceName, ListenerStateAccepting, 2),
		},
	}
	service := NewListenerService(manager, WithObservabilityRecorder(recorder))

	list, err := service.ListListeners(context.Background(), ListListenersRequest{})
	if err != nil {
		t.Fatalf("ListListeners returned error: %v", err)
	}

	gotNames := []string{list.Listeners[0].Name, list.Listeners[1].Name}
	if !reflect.DeepEqual(gotNames, []string{listenerTestIMAPName, listenerTestIMAPSName}) {
		t.Fatalf("listener order = %v, want stable name order", gotNames)
	}

	detail, err := service.GetListener(context.Background(), GetListenerRequest{Name: " " + listenerTestIMAPName + " "})
	if err != nil {
		t.Fatalf("GetListener returned error: %v", err)
	}

	if detail.Name != listenerTestIMAPName || detail.ActiveLocalSessions != 2 || detail.State != ListenerStateAccepting {
		t.Fatalf("listener detail = %#v, want manager projection", detail)
	}

	event, ok := recorder.last(observability.EventListenerInventory)
	if !ok {
		t.Fatal("listener inventory event was not recorded")
	}

	if event.MetricLabels[runtimeObservationFieldOperation] != operationListenerGet {
		t.Fatalf("inventory operation label = %q, want get", event.MetricLabels[runtimeObservationFieldOperation])
	}
}

// TestListenerServiceMissingListenerMapsNotFound verifies absent configured listeners get a classified error.
func TestListenerServiceMissingListenerMapsNotFound(t *testing.T) {
	service := NewListenerService(&recordingListenerManager{})

	_, err := service.GetListener(context.Background(), GetListenerRequest{Name: "missing"})
	if !IsErrorKind(err, ErrorKindNotFound) {
		t.Fatalf("GetListener error = %v, want not_found", err)
	}
}

// TestListenerDrainValidationRejectsInvalidInput verifies drain validation before manager access.
func TestListenerDrainValidationRejectsInvalidInput(t *testing.T) {
	negativeGrace := -time.Second

	testCases := []runtimeValidationCase{
		{
			name: listenerTestEmptyName,
			validate: func() error {
				return DrainListenerRequest{Mode: ListenerDrainModeSoft, Reason: listenerTestReason}.Validate()
			},
		},
		{
			name: listenerTestNoReason,
			validate: func() error {
				return DrainListenerRequest{Name: listenerTestIMAPName, Mode: ListenerDrainModeSoft}.Validate()
			},
		},
		{
			name: "invalid mode",
			validate: func() error {
				return DrainListenerRequest{Name: listenerTestIMAPName, Mode: "paused", Reason: listenerTestReason}.Validate()
			},
		},
		{
			name: "negative grace",
			validate: func() error {
				return DrainListenerRequest{
					Name:   listenerTestIMAPName,
					Mode:   ListenerDrainModeSoft,
					Reason: listenerTestReason,
					Grace:  &negativeGrace,
				}.Validate()
			},
		},
	}

	assertInvalidRuntimeRequests(t, testCases)
}

// TestListenerHardDrainRequiresExplicitGrace verifies hard drain rejects omitted grace.
func TestListenerHardDrainRequiresExplicitGrace(t *testing.T) {
	err := DrainListenerRequest{
		Name:   listenerTestIMAPName,
		Mode:   ListenerDrainModeHard,
		Reason: listenerTestReason,
	}.Validate()
	if !IsErrorKind(err, ErrorKindInvalidRequest) {
		t.Fatalf("hard drain validation error = %v, want invalid_request", err)
	}
}

// TestListenerHardDrainAcceptsExplicitZeroGrace verifies explicit zero is preserved as operator intent.
func TestListenerHardDrainAcceptsExplicitZeroGrace(t *testing.T) {
	zeroGrace := time.Duration(0)
	manager := &recordingListenerManager{
		drainDetail: listenerTestDetail(listenerTestIMAPName, "imap", listenerTestServiceName, ListenerStateDrained, 0),
	}
	service := NewListenerService(manager)

	result, err := service.DrainListener(context.Background(), DrainListenerRequest{
		Name:   listenerTestIMAPName,
		Mode:   ListenerDrainModeHard,
		Reason: listenerTestReason,
		Grace:  &zeroGrace,
	})
	if err != nil {
		t.Fatalf("DrainListener returned error: %v", err)
	}

	if manager.drainRequest.Grace == nil || *manager.drainRequest.Grace != 0 {
		t.Fatalf("manager grace = %v, want explicit zero", manager.drainRequest.Grace)
	}

	if result.Audit.Fields[auditFieldListenerGrace] != "0" {
		t.Fatalf("audit grace = %q, want explicit 0", result.Audit.Fields[auditFieldListenerGrace])
	}
}

// TestListenerResumeValidationRejectsInvalidInput verifies resume validates name and reason.
func TestListenerResumeValidationRejectsInvalidInput(t *testing.T) {
	assertInvalidRuntimeRequests(t, []runtimeValidationCase{
		{
			name: listenerTestEmptyName,
			validate: func() error {
				return ResumeListenerRequest{Reason: listenerTestReason}.Validate()
			},
		},
		{
			name: listenerTestNoReason,
			validate: func() error {
				return ResumeListenerRequest{Name: listenerTestIMAPName}.Validate()
			},
		},
	})
}

// TestListenerManagerUnavailableMapsUnavailable verifies absent managers fail closed.
func TestListenerManagerUnavailableMapsUnavailable(t *testing.T) {
	service := NewListenerService(nil)

	_, err := service.ListListeners(context.Background(), ListListenersRequest{})
	if !IsErrorKind(err, ErrorKindUnavailable) {
		t.Fatalf("ListListeners error = %v, want unavailable", err)
	}
}

// TestListenerOperationConflictMapsConflict verifies manager conflict sentinels become runtime conflicts.
func TestListenerOperationConflictMapsConflict(t *testing.T) {
	grace := time.Second
	service := NewListenerService(&recordingListenerManager{
		drainErr: ErrListenerOperationConflict,
	})

	_, err := service.DrainListener(context.Background(), DrainListenerRequest{
		Name:   listenerTestIMAPName,
		Mode:   ListenerDrainModeHard,
		Reason: listenerTestReason,
		Grace:  &grace,
	})
	if !IsErrorKind(err, ErrorKindConflict) {
		t.Fatalf("DrainListener error = %v, want conflict", err)
	}
}

// TestListenerResumeRecordsAuditAndObservation verifies successful resume emits bounded metadata.
func TestListenerResumeRecordsAuditAndObservation(t *testing.T) {
	recorder := &recordingRuntimeObservation{}
	manager := &recordingListenerManager{
		resumeDetail: listenerTestDetail(listenerTestIMAPName, "imap", listenerTestServiceName, ListenerStateAccepting, 0),
	}
	service := NewListenerService(manager, WithObservabilityRecorder(recorder))

	result, err := service.ResumeListener(context.Background(), ResumeListenerRequest{
		Name:   listenerTestIMAPName,
		Reason: listenerTestReason,
	})
	if err != nil {
		t.Fatalf("ResumeListener returned error: %v", err)
	}

	if result.Audit.Operation != AuditOperationListenerResume {
		t.Fatalf("audit operation = %q, want listener resume", result.Audit.Operation)
	}

	event, ok := recorder.last(observability.EventListenerResume)
	if !ok {
		t.Fatal("listener resume event was not recorded")
	}

	if event.MetricLabels[runtimeObservationFieldListener] != listenerTestIMAPName {
		t.Fatalf("resume listener label = %q, want listener name", event.MetricLabels[runtimeObservationFieldListener])
	}
}

// TestListenerObservabilityLabelsStayLowCardinality verifies operator reasons never become metric labels.
func TestListenerObservabilityLabelsStayLowCardinality(t *testing.T) {
	recorder := &recordingRuntimeObservation{}
	manager := &recordingListenerManager{
		drainDetail: listenerTestDetail(listenerTestIMAPName, "imap", listenerTestServiceName, ListenerStateDraining, 4),
	}
	service := NewListenerService(manager, WithObservabilityRecorder(recorder))

	if _, err := service.DrainListener(context.Background(), DrainListenerRequest{
		Name:   listenerTestIMAPName,
		Mode:   ListenerDrainModeSoft,
		Reason: "replace rack switch near Alice mailbox",
	}); err != nil {
		t.Fatalf("DrainListener returned error: %v", err)
	}

	event, ok := recorder.last(observability.EventListenerDrain)
	if !ok {
		t.Fatal("listener drain event was not recorded")
	}

	if err := event.MetricLabels.Validate(); err != nil {
		t.Fatalf("metric labels are not allowlisted: %v", err)
	}

	renderedLabels := strings.Join(mapValues(map[string]string(event.MetricLabels)), "\n")
	if strings.Contains(renderedLabels, "replace rack switch") || slices.Contains(mapKeys(map[string]string(event.MetricLabels)), "reason") {
		t.Fatalf("metric labels leaked operator reason text: %#v", event.MetricLabels)
	}
}

type recordingListenerManager struct {
	snapshots    []ListenerDetail
	drainRequest ListenerManagerDrainRequest
	drainDetail  ListenerDetail
	drainErr     error
	resumeName   string
	resumeDetail ListenerDetail
	resumeErr    error
}

// Snapshots returns the configured fake listener inventory.
func (m *recordingListenerManager) Snapshots() []ListenerDetail {
	return append([]ListenerDetail(nil), m.snapshots...)
}

// Drain records and returns the configured drain result.
func (m *recordingListenerManager) Drain(_ context.Context, request ListenerManagerDrainRequest) (ListenerDetail, error) {
	m.drainRequest = request
	if m.drainErr != nil {
		return ListenerDetail{}, m.drainErr
	}

	return m.drainDetail, nil
}

// Resume records and returns the configured resume result.
func (m *recordingListenerManager) Resume(_ context.Context, name string) (ListenerDetail, error) {
	m.resumeName = name
	if m.resumeErr != nil {
		return ListenerDetail{}, m.resumeErr
	}

	return m.resumeDetail, nil
}

// listenerTestDetail builds one complete listener projection for tests.
func listenerTestDetail(name string, protocol string, service string, state ListenerState, active int) ListenerDetail {
	return ListenerDetail{
		Name:                name,
		Protocol:            protocol,
		ServiceName:         service,
		Network:             "tcp",
		Address:             "127.0.0.1:1143",
		TLSMode:             "starttls",
		BoundAddress:        "127.0.0.1:2143",
		State:               state,
		ActiveLocalSessions: active,
	}
}

// mapKeys returns map keys for compact membership checks.
func mapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}

	return keys
}

var _ ListenerManager = (*recordingListenerManager)(nil)
