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

package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/croessner/nauthilus-director/internal/rest/diagnostics"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// errUnauthenticated is a protocol error for a tool call without verified facts; the bearer gate prevents it.
var errUnauthenticated = errors.New("unauthenticated tool call")

// newSDKServer registers every diagnostics operation as a read-only tool. All tools are listed to
// every caller; the diagnostics executor decides authorization per call.
func (s *Server) newSDKServer() (*mcp.Server, error) {
	sdkServer := mcp.NewServer(&mcp.Implementation{Name: implementationName, Title: implementationTitle, Version: s.deps.Version},
		&mcp.ServerOptions{Instructions: serverInstructions, SupportedProtocolVersions: supportedProtocolVersions,
			Logger: discardLogger()})

	closedWorld, nonDestructive := false, false

	for _, operation := range diagnostics.Operations() {
		schema, err := operation.InputSchema()
		if err != nil {
			return nil, err
		}

		sdkServer.AddTool(&mcp.Tool{Name: operation.Name, Title: operation.Title, Description: operation.ModelDescription(),
			InputSchema: schema, Annotations: &mcp.ToolAnnotations{Title: operation.Title, ReadOnlyHint: true,
				IdempotentHint: true, DestructiveHint: &nonDestructive, OpenWorldHint: &closedWorld}},
			s.toolHandler(operation))
	}

	return sdkServer, nil
}

// toolHandler executes one operation with the verified credential under the call budget.
// Handshake-era calls run on the stateless session context, so the HTTP request context is
// merged in to stop work for a gone client.
func (s *Server) toolHandler(operation diagnostics.Operation) mcp.ToolHandler {
	return func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		credential, requestCtx, ok := verifiedFacts(request)
		if !ok {
			return nil, errUnauthenticated
		}

		ctx, stop := mergeCancellation(ctx, requestCtx)
		defer stop()

		ctx, cancel := context.WithTimeout(ctx, s.timeout)
		defer cancel()

		arguments := []byte(request.Params.Arguments)
		if len(bytes.TrimSpace(arguments)) == 0 || bytes.Equal(bytes.TrimSpace(arguments), []byte("null")) {
			arguments = []byte("{}")
		}

		response := s.deps.Diagnostics.Execute(ctx, operation, credential, arguments)
		if int64(2*len(response.Body)) > s.maxResponse {
			response = diagnostics.ResponseTooLarge(operation)
		}

		s.recordTool(requestCtx, operation.Name, credential, response)

		result := &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(response.Body)}},
			IsError: response.IsError()}

		if json.Valid(response.Body) && bytes.HasPrefix(response.Body, []byte("{")) {
			result.StructuredContent = json.RawMessage(response.Body)
		}

		return result, nil
	}
}

// verifiedFacts returns the credential and the HTTP request context the bearer gate attached to the call.
func verifiedFacts(request *mcp.CallToolRequest) (diagnostics.Credential, context.Context, bool) {
	if request == nil || request.Extra == nil || request.Extra.TokenInfo == nil {
		return diagnostics.Credential{}, nil, false
	}

	credential, ok := request.Extra.TokenInfo.Extra[extraCredential].(diagnostics.Credential)
	if !ok || !credential.Verified() {
		return diagnostics.Credential{}, nil, false
	}

	requestCtx, _ := request.Extra.TokenInfo.Extra[extraRequestContext].(context.Context)

	return credential, requestCtx, true
}

// mergeCancellation cancels ctx when other ends as well; stop releases the link.
func mergeCancellation(ctx context.Context, other context.Context) (context.Context, func()) {
	if other == nil {
		return ctx, func() {}
	}

	merged, cancel := context.WithCancelCause(ctx)
	unlink := context.AfterFunc(other, func() { cancel(context.Cause(other)) })

	return merged, func() {
		unlink()
		cancel(nil)
	}
}

// recordTool writes the transport record of one tool call, including a classified internal cause.
func (s *Server) recordTool(ctx context.Context, tool string, credential diagnostics.Credential, response diagnostics.Response) {
	if ctx == nil {
		ctx = context.Background()
	}

	result := resultOK
	if response.IsError() {
		result = resultToolError
	}

	s.record(ctx, accessRecord{result: result, tool: tool, principal: credential.Identity(), code: response.Code,
		status: response.Status, failed: response.Cause() != nil})
}
