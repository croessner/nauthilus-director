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

package nauthilus

import (
	"errors"
	"fmt"
	"strconv"
)

// ErrorKind classifies fail-closed authority boundary errors.
type ErrorKind string

const (
	// ErrorKindConfig reports invalid local authority configuration.
	ErrorKindConfig ErrorKind = "config"
	// ErrorKindTransport reports an authority transport failure.
	ErrorKindTransport ErrorKind = "transport"
	// ErrorKindMalformedResponse reports an ambiguous authority response.
	ErrorKindMalformedResponse ErrorKind = "malformed_response"
	// ErrorKindTemporaryFailure reports an authority-side temporary failure.
	ErrorKindTemporaryFailure ErrorKind = "tempfail"
)

// AuthError is a secret-safe authority boundary error.
type AuthError struct {
	Operation  string
	Kind       ErrorKind
	StatusCode int
	Message    string
	cause      error
}

// Error returns a secret-free diagnostic string.
func (e *AuthError) Error() string {
	if e == nil {
		return ""
	}

	message := "nauthilus " + e.Operation + " failed: " + string(e.Kind)
	if e.StatusCode > 0 {
		message += " status=" + strconv.Itoa(e.StatusCode)
	}

	if e.Message != "" {
		message += " " + e.Message
	}

	return message
}

// Unwrap returns the internal cause for error classification.
func (e *AuthError) Unwrap() error {
	if e == nil {
		return nil
	}

	return e.cause
}

// SafeFields returns log fields that avoid credential and identity values.
func (e *AuthError) SafeFields() SafeFields {
	if e == nil {
		return SafeFields{}
	}

	fields := SafeFields{
		"kind":             string(e.Kind),
		safeFieldOperation: e.Operation,
	}

	if e.StatusCode > 0 {
		fields["status_code"] = strconv.Itoa(e.StatusCode)
	}

	return fields
}

// IsAuthErrorKind reports whether err wraps an AuthError with the given kind.
func IsAuthErrorKind(err error, kind ErrorKind) bool {
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		return false
	}

	return authErr.Kind == kind
}

// newAuthError creates a secret-safe authority error.
func newAuthError(operation authOperation, kind ErrorKind, statusCode int, message string, cause error) *AuthError {
	return &AuthError{
		Operation:  string(operation),
		Kind:       kind,
		StatusCode: statusCode,
		Message:    message,
		cause:      cause,
	}
}

// configError reports invalid local configuration without leaking protected values.
func configError(message string) *AuthError {
	return newAuthError(operationConfigure, ErrorKindConfig, 0, message, nil)
}

// malformedResponseError reports an ambiguous authority response.
func malformedResponseError(operation authOperation, message string, cause error) *AuthError {
	return newAuthError(operation, ErrorKindMalformedResponse, 0, message, cause)
}

// transportError reports a failed authority transport operation.
func transportError(operation authOperation, cause error) *AuthError {
	return newAuthError(operation, ErrorKindTransport, 0, "", cause)
}

// tempfailError reports an authority-side temporary failure.
func tempfailError(operation authOperation, statusCode int, message string) *AuthError {
	return newAuthError(operation, ErrorKindTemporaryFailure, statusCode, message, nil)
}

// invalidRequestError reports request fields that would create ambiguous auth state.
func invalidRequestError(operation authOperation, field string) *AuthError {
	return malformedResponseError(operation, fmt.Sprintf("%s required", field), nil)
}
