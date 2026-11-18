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

package diagnostics

import (
	"encoding/json"
	"net/http"

	"github.com/croessner/nauthilus-director/internal/rest/generated"
)

// Stable problem codes and fixed messages shared by the REST boundary and the diagnostics table,
// so both transports answer a refused request with the same envelope.
const (
	ProblemCodeBadRequest          = "bad_request"
	ProblemMessageBadRequest       = "request body, path parameter or query parameter is invalid"
	ProblemCodeInternal            = "internal_error"
	ProblemMessageInternal         = "control API response failed"
	ProblemCodeForbidden           = "forbidden"
	ProblemMessageForbidden        = "requested operation is not authorized"
	ProblemCodeCredentialInput     = "credential_input_rejected"
	ProblemMessageCredentialInput  = "route lookup does not accept authentication or mailbox material"
	ProblemCodeResponseTooLarge    = "response_too_large"
	ProblemMessageResponseTooLarge = "the result exceeds the transport size limit; narrow the filters or the page size"
)

// NewProblem returns the control API error envelope.
func NewProblem(status int, code string, message string, operation string) generated.ErrorResponse {
	var operationPtr *string
	if operation != "" {
		operationPtr = &operation
	}

	return generated.ErrorResponse{Code: code, Message: message, Operation: operationPtr, Status: status}
}

// InvalidArguments renders the bad-request envelope of an operation.
func InvalidArguments(operation Operation) Response {
	return problemResponse(operation, http.StatusBadRequest, ProblemCodeBadRequest, ProblemMessageBadRequest, nil)
}

// Forbidden renders the forbidden envelope of an operation.
func Forbidden(operation Operation) Response {
	return problemResponse(operation, http.StatusForbidden, ProblemCodeForbidden, ProblemMessageForbidden, nil)
}

// CredentialInputRejected renders the envelope for route lookup input carrying credential or mailbox material.
func CredentialInputRejected(operation Operation) Response {
	return problemResponse(operation, http.StatusBadRequest, ProblemCodeCredentialInput, ProblemMessageCredentialInput, nil)
}

// ResponseTooLarge renders the envelope a transport returns instead of a result above its size bound.
func ResponseTooLarge(operation Operation) Response {
	return problemResponse(operation, http.StatusUnprocessableEntity, ProblemCodeResponseTooLarge, ProblemMessageResponseTooLarge, nil)
}

// internalError renders the internal-error envelope and keeps the cause for host-side logging.
func internalError(operation Operation, cause error) Response {
	return problemResponse(operation, http.StatusInternalServerError, ProblemCodeInternal, ProblemMessageInternal, cause)
}

// problemResponse renders one fixed envelope with its status.
func problemResponse(operation Operation, status int, code string, message string, cause error) Response {
	body, _ := json.Marshal(NewProblem(status, code, message, operation.goOperationName()))

	return Response{Status: status, Body: body, Code: code, cause: cause}
}
