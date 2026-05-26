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

// Package runtime owns runtime control use-case domain objects.
package runtime

import (
	"errors"
	"maps"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/observability"
)

// ErrorKind classifies runtime domain validation failures.
type ErrorKind string

const (
	// ErrorKindInvalidRequest reports missing or unsupported operator input.
	ErrorKindInvalidRequest ErrorKind = "invalid_request"
)

// Error is a secret-safe runtime domain failure.
type Error struct {
	Kind      ErrorKind
	Operation string
	Message   string
}

// Error returns an operator-facing diagnostic without credential material.
func (e *Error) Error() string {
	if e == nil {
		return ""
	}

	message := "runtime failed: " + string(e.Kind)
	if e.Operation != "" {
		message += " operation=" + e.Operation
	}

	if e.Message != "" {
		message += " " + e.Message
	}

	return message
}

// IsErrorKind reports whether err is a runtime domain error with kind.
func IsErrorKind(err error, kind ErrorKind) bool {
	var runtimeErr *Error
	if !errors.As(err, &runtimeErr) {
		return false
	}

	return runtimeErr.Kind == kind
}

// AuditOperation identifies a mutating runtime operation.
type AuditOperation string

const (
	// AuditOperationBackendDrain records a backend drain mutation.
	AuditOperationBackendDrain AuditOperation = "backend_drain"
	// AuditOperationBackendMaintenance records a backend maintenance mutation.
	AuditOperationBackendMaintenance AuditOperation = "backend_maintenance"
	// AuditOperationBackendRuntimeClear records a backend runtime clear mutation.
	AuditOperationBackendRuntimeClear AuditOperation = "backend_runtime_clear"
	// AuditOperationBackendRuntimeSet records a backend runtime state mutation.
	AuditOperationBackendRuntimeSet AuditOperation = "backend_runtime_set"
	// AuditOperationSessionKill records a session kill mutation.
	AuditOperationSessionKill AuditOperation = "session_kill"
	// AuditOperationUserAffinityClear records a user affinity clear mutation.
	AuditOperationUserAffinityClear AuditOperation = "user_affinity_clear"
	// AuditOperationUserKick records a user kick mutation.
	AuditOperationUserKick AuditOperation = "user_kick"
	// AuditOperationUserMove records a user move mutation.
	AuditOperationUserMove AuditOperation = "user_move"
)

// Actor carries the control-plane caller identity when available.
type Actor struct {
	ID            string
	AuthMethod    string
	Authenticated bool
}

// AuditInput contains the fields used to create secret-safe audit metadata.
type AuditInput struct {
	Operation         AuditOperation
	Reason            string
	Actor             Actor
	Generation        string
	ServerTime        time.Time
	BackendIdentifier string
	UserHash          string
	SessionID         string
	Fields            map[string]string
}

// AuditMetadata is the auditable metadata stored with runtime mutations.
type AuditMetadata struct {
	Operation         AuditOperation
	Reason            string
	Actor             Actor
	Generation        string
	ServerTime        time.Time
	BackendIdentifier string
	UserHash          string
	SessionID         string
	Fields            map[string]string
}

// NewAuditMetadata normalizes and sanitizes runtime mutation audit metadata.
func NewAuditMetadata(input AuditInput) (AuditMetadata, error) {
	if strings.TrimSpace(string(input.Operation)) == "" {
		return AuditMetadata{}, newRuntimeError(ErrorKindInvalidRequest, "audit", "operation required")
	}

	if err := requireReason(string(input.Operation), input.Reason); err != nil {
		return AuditMetadata{}, err
	}

	if input.ServerTime.IsZero() {
		input.ServerTime = time.Now().UTC()
	}

	return AuditMetadata{
		Operation:         input.Operation,
		Reason:            strings.TrimSpace(input.Reason),
		Actor:             normalizeActor(input.Actor),
		Generation:        strings.TrimSpace(input.Generation),
		ServerTime:        input.ServerTime.UTC(),
		BackendIdentifier: strings.TrimSpace(input.BackendIdentifier),
		UserHash:          strings.TrimSpace(input.UserHash),
		SessionID:         strings.TrimSpace(input.SessionID),
		Fields:            sanitizeAuditFields(input.Fields),
	}, nil
}

// SafeFields returns a detached copy of sanitized audit fields.
func (m AuditMetadata) SafeFields() map[string]string {
	if m.Fields == nil {
		return nil
	}

	fields := make(map[string]string, len(m.Fields))
	maps.Copy(fields, m.Fields)

	return fields
}

// requireReason rejects exposed mutating operations without an operator reason.
func requireReason(operation string, reason string) error {
	if strings.TrimSpace(reason) == "" {
		return newRuntimeError(ErrorKindInvalidRequest, operation, "reason required")
	}

	return nil
}

// normalizeActor trims actor metadata while allowing empty local-test actors.
func normalizeActor(actor Actor) Actor {
	actor.ID = strings.TrimSpace(actor.ID)
	actor.AuthMethod = strings.TrimSpace(actor.AuthMethod)

	return actor
}

// sanitizeAuditFields removes credential-bearing values from supplemental audit fields.
func sanitizeAuditFields(fields map[string]string) map[string]string {
	if len(fields) == 0 {
		return nil
	}

	safe := observability.SanitizeLogFields(fields)
	out := make(map[string]string, len(safe))
	maps.Copy(out, safe)

	return out
}

// newRuntimeError creates a classified runtime domain error.
func newRuntimeError(kind ErrorKind, operation string, message string) *Error {
	return &Error{
		Kind:      kind,
		Operation: operation,
		Message:   message,
	}
}
