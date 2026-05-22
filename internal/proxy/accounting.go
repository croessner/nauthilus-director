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

// Package proxy owns transparent bidirectional byte copying after protocol auth.
package proxy

const (
	// DirectionClientToBackend labels bytes copied from frontend client to backend.
	DirectionClientToBackend = "client_to_backend"
	// DirectionBackendToClient labels bytes copied from backend to frontend client.
	DirectionBackendToClient = "backend_to_client"
)

const (
	// ResultBackendClosed classifies proxy end caused by backend EOF or write failure.
	ResultBackendClosed = "backend_closed"
	// ResultClientClosed classifies proxy end caused by frontend EOF or write failure.
	ResultClientClosed = "client_closed"
	// ResultShutdown classifies proxy end caused by context cancellation.
	ResultShutdown = "shutdown"
	// ResultStateFailed classifies proxy end caused by lease heartbeat or close failure.
	ResultStateFailed = "state_failed"
	// ResultTimeout classifies proxy end caused by idle deadline expiry.
	ResultTimeout = "timeout"
)

// Accounting records byte totals in both transparent proxy directions.
type Accounting struct {
	ClientToBackend int64
	BackendToClient int64
}

// Result summarizes one completed transparent proxy lifecycle.
type Result struct {
	Class      string
	Accounted  Accounting
	Err        error
	CloseError error
}

// add records bytes for one low-cardinality direction label.
func (a *Accounting) add(direction string, bytes int64) {
	if bytes <= 0 {
		return
	}

	switch direction {
	case DirectionClientToBackend:
		a.ClientToBackend += bytes
	case DirectionBackendToClient:
		a.BackendToClient += bytes
	}
}
