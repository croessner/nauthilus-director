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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/croessner/nauthilus-director/internal/rest/generated"
	"github.com/croessner/nauthilus-director/internal/runtime"
)

var (
	// errInvalidArguments rejects arguments that are not exactly one object of the operation's shape.
	errInvalidArguments = errors.New("invalid diagnostic arguments")

	// errMissingResponse marks a handler that returned neither a response nor an error.
	errMissingResponse = errors.New("diagnostic operation returned no response")

	// errUnexpectedContentType marks a non-JSON response of a read operation.
	errUnexpectedContentType = errors.New("diagnostic operation returned a non-JSON response")
)

// Response is the transport-neutral outcome of one operation: an HTTP status and the exact JSON
// body bytes the REST server would send for the same request.
type Response struct {
	cause  error
	Body   []byte
	Code   string
	Status int
}

// Cause returns the internal error cause for host-side logging; it never reaches a caller.
func (r Response) Cause() error {
	return r.cause
}

// IsError reports whether the response is an error envelope.
func (r Response) IsError() bool {
	return r.Status != http.StatusOK
}

// Executor runs diagnostics against one control API handler.
type Executor struct {
	api ReadAPI
}

// NewExecutor returns an executor over the read-only part of the control API handler.
func NewExecutor(api ReadAPI) Executor {
	return Executor{api: api}
}

// Execute checks the credential's scopes, validates and decodes raw arguments, calls the operation
// and renders its response. Authorization stays here, so every transport gets the same answer: a
// credential without a scope of the operation gets the forbidden envelope.
func (e Executor) Execute(ctx context.Context, operation Operation, credential Credential, raw []byte) Response {
	if operation.invoke == nil || e.api == nil {
		return internalError(operation, errMissingResponse)
	}

	if !credential.Permits(operation) {
		return Forbidden(operation)
	}

	if response, refused := e.refuseArguments(operation, raw); refused {
		return response
	}

	ctx = runtime.WithActor(ctx, runtime.Actor{ID: credential.Identity(), AuthMethod: string(credential.Method), Authenticated: true})

	visit, err := operation.invoke(ctx, e.api, raw)

	switch {
	case errors.Is(err, errInvalidArguments):
		return InvalidArguments(operation)
	case err != nil:
		return internalError(operation, err)
	}

	return render(operation, visit)
}

// refuseArguments rejects raw arguments before decoding: missing required members and, for the
// route lookup, credential or mailbox material anywhere in the input.
func (e Executor) refuseArguments(operation Operation, raw []byte) (Response, bool) {
	contract, err := operation.argumentSchema()
	if err != nil {
		return internalError(operation, err), true
	}

	var members map[string]json.RawMessage
	if !DecodeStrict(raw, &members) {
		return InvalidArguments(operation), true
	}

	for _, name := range contract.required {
		if _, present := members[name]; !present {
			return InvalidArguments(operation), true
		}
	}

	if operation.Name == OperationRouteLookup && RouteLookupInputCarriesForbiddenKeys(raw) {
		return CredentialInputRejected(operation), true
	}

	return Response{}, false
}

// render captures the generated response renderer into a transport-neutral response.
func render(operation Operation, visit visitFunc) Response {
	recorder := newResponseBuffer()
	if err := visit(recorder); err != nil {
		return internalError(operation, err)
	}

	mediaType, _, err := mime.ParseMediaType(recorder.header.Get("Content-Type"))
	if err != nil || mediaType != contentTypeJSON {
		return internalError(operation, errUnexpectedContentType)
	}

	body := bytes.TrimSpace(recorder.body.Bytes())
	response := Response{Status: recorder.status, Body: body}

	if response.IsError() {
		var envelope generated.ErrorResponse
		if json.Unmarshal(body, &envelope) == nil {
			response.Code = envelope.Code
		}
	}

	return response
}

// DecodeStrict decodes exactly one JSON object into target: unknown fields, duplicate member
// names, trailing data and non-object values are refused. Every transport decodes operation
// arguments with it.
func DecodeStrict(raw []byte, target any) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' || HasDuplicateNames(trimmed) {
		return false
	}

	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(target); err != nil {
		return false
	}

	_, err := decoder.Token()

	return errors.Is(err, io.EOF)
}

// goOperationName returns the generated Go operation name used in REST problem envelopes.
func (o Operation) goOperationName() string {
	if o.OperationID == "" {
		return ""
	}

	return strings.ToUpper(o.OperationID[:1]) + o.OperationID[1:]
}

// responseBuffer is an in-memory http.ResponseWriter for generated response renderers.
type responseBuffer struct {
	header http.Header
	body   bytes.Buffer
	status int
}

// newResponseBuffer returns a buffer with the implicit 200 status of net/http.
func newResponseBuffer() *responseBuffer {
	return &responseBuffer{header: http.Header{}, status: http.StatusOK}
}

// Header returns the captured response headers.
func (b *responseBuffer) Header() http.Header {
	return b.header
}

// Write appends body bytes.
func (b *responseBuffer) Write(data []byte) (int, error) {
	return b.body.Write(data)
}

// WriteHeader records the status code.
func (b *responseBuffer) WriteHeader(status int) {
	b.status = status
}
