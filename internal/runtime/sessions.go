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
	"time"
)

const (
	operationSessionKill = "session_kill"
	operationSessionReap = "session_reap"
)

// SessionStatus describes the runtime control state of one frontend session.
type SessionStatus string

const (
	// SessionStatusActive marks a live session lease.
	SessionStatusActive SessionStatus = "active"
	// SessionStatusClosing marks a session that should close after a control action.
	SessionStatusClosing SessionStatus = "closing"
	// SessionStatusExpired marks a session whose lease has expired.
	SessionStatusExpired SessionStatus = "expired"
)

// SessionRuntimeState describes one lease-backed frontend session.
type SessionRuntimeState struct {
	SessionID         string
	UserHash          string
	Tenant            string
	Protocol          string
	ListenerName      string
	ServiceName       string
	EffectiveShardTag string
	BackendIdentifier string
	DirectorInstance  string
	OpenedAt          time.Time
	LeaseExpiresAt    time.Time
	ControlGeneration string
	Status            SessionStatus
}

// KillSessionRequest asks runtime state to mark one session for closure.
type KillSessionRequest struct {
	SessionID          string
	Reason             string
	Actor              Actor
	ExpectedGeneration string
}

// ReapSessionsRequest asks runtime state to repair expired session leases.
type ReapSessionsRequest struct {
	Reason string
	Actor  Actor
	Limit  int
}

// SessionMutationResult describes a runtime session mutation outcome.
type SessionMutationResult struct {
	State SessionRuntimeState
	Audit AuditMetadata
}

// Validate checks the session kill request before it crosses a persistence boundary.
func (r KillSessionRequest) Validate() error {
	if strings.TrimSpace(r.SessionID) == "" {
		return newRuntimeError(ErrorKindInvalidRequest, operationSessionKill, "session id required")
	}

	return requireReason(operationSessionKill, r.Reason)
}

// Validate checks the reap request before it crosses a persistence boundary.
func (r ReapSessionsRequest) Validate() error {
	if r.Limit < 0 {
		return newRuntimeError(ErrorKindInvalidRequest, operationSessionReap, "limit must not be negative")
	}

	return requireReason(operationSessionReap, r.Reason)
}

// Normalize returns a session state with stable string fields trimmed.
func (s SessionRuntimeState) Normalize() SessionRuntimeState {
	s.SessionID = strings.TrimSpace(s.SessionID)
	s.UserHash = strings.TrimSpace(s.UserHash)
	s.Tenant = strings.TrimSpace(s.Tenant)
	s.Protocol = strings.ToLower(strings.TrimSpace(s.Protocol))
	s.ListenerName = strings.TrimSpace(s.ListenerName)
	s.ServiceName = strings.TrimSpace(s.ServiceName)
	s.EffectiveShardTag = strings.TrimSpace(s.EffectiveShardTag)
	s.BackendIdentifier = strings.TrimSpace(s.BackendIdentifier)
	s.DirectorInstance = strings.TrimSpace(s.DirectorInstance)
	s.ControlGeneration = strings.TrimSpace(s.ControlGeneration)

	return s
}
