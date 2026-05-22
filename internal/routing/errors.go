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

package routing

import (
	"errors"
	"fmt"
)

// ErrorKind classifies fail-closed routing resolver failures.
type ErrorKind string

const (
	// ErrorKindAmbiguousFact reports multiple values for a singular fact.
	ErrorKindAmbiguousFact ErrorKind = "ambiguous_fact"
	// ErrorKindConfig reports an unusable local resolver configuration.
	ErrorKindConfig ErrorKind = "config"
	// ErrorKindInvalidRequest reports missing required routing request input.
	ErrorKindInvalidRequest ErrorKind = "invalid_request"
	// ErrorKindMissingFact reports an absent logical fact.
	ErrorKindMissingFact ErrorKind = "missing_fact"
)

// Error is a secret-safe routing failure.
type Error struct {
	Kind    ErrorKind
	Source  string
	Field   string
	Message string
	cause   error
}

// Error returns a diagnostic string without raw account or credential values.
func (e *Error) Error() string {
	if e == nil {
		return ""
	}

	message := "routing failed: " + string(e.Kind)
	if e.Source != "" {
		message += " source=" + e.Source
	}

	if e.Field != "" {
		message += " field=" + e.Field
	}

	if e.Message != "" {
		message += " " + e.Message
	}

	return message
}

// Unwrap exposes the internal cause for error classification.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}

	return e.cause
}

// IsErrorKind reports whether err wraps a routing error with kind.
func IsErrorKind(err error, kind ErrorKind) bool {
	var routingErr *Error
	if !errors.As(err, &routingErr) {
		return false
	}

	return routingErr.Kind == kind
}

// newError builds a classified routing error without secret-bearing values.
func newError(kind ErrorKind, source string, field string, message string, cause error) *Error {
	return &Error{
		Kind:    kind,
		Source:  source,
		Field:   field,
		Message: message,
		cause:   cause,
	}
}

// configError reports invalid local resolver configuration.
func configError(source string, message string) *Error {
	return newError(ErrorKindConfig, source, "", message, nil)
}

// invalidRequestError reports missing request input required for routing.
func invalidRequestError(source string, field string) *Error {
	return newError(ErrorKindInvalidRequest, source, field, fmt.Sprintf("%s required", field), nil)
}

// missingFactError reports that a resolver could not produce a logical fact.
func missingFactError(source string, field string) *Error {
	return newError(ErrorKindMissingFact, source, field, fmt.Sprintf("%s unavailable", field), nil)
}

// ambiguousFactError reports multiple values for a singular routing fact.
func ambiguousFactError(source string, field string) *Error {
	return newError(ErrorKindAmbiguousFact, source, field, fmt.Sprintf("%s ambiguous", field), nil)
}
