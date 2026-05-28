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
	"context"
	"fmt"
	"strings"
)

// GRPCDecision mirrors nauthilus.auth.v1.AuthDecision without importing generated code.
type GRPCDecision int32

const (
	// GRPCDecisionUnspecified mirrors AUTH_DECISION_UNSPECIFIED.
	GRPCDecisionUnspecified GRPCDecision = 0
	// GRPCDecisionOK mirrors AUTH_DECISION_OK.
	GRPCDecisionOK GRPCDecision = 1
	// GRPCDecisionFail mirrors AUTH_DECISION_FAIL.
	GRPCDecisionFail GRPCDecision = 2
	// GRPCDecisionTempFail mirrors AUTH_DECISION_TEMPFAIL.
	GRPCDecisionTempFail GRPCDecision = 3
)

// GRPCAuthService is the narrow generated-client adapter seam.
type GRPCAuthService interface {
	Authenticate(ctx context.Context, request *GRPCAuthRequest) (*GRPCAuthResponse, error)
	LookupIdentity(ctx context.Context, request *GRPCLookupIdentityRequest) (*GRPCAuthResponse, error)
	ListAccounts(ctx context.Context, request *GRPCListAccountsRequest) (*GRPCListAccountsResponse, error)
}

// GRPCAuthRequest mirrors the AuthService Authenticate request fields.
type GRPCAuthRequest struct {
	RequestContext
	Password         Secret
	AuthLoginAttempt uint32
}

// GRPCLookupIdentityRequest mirrors the AuthService LookupIdentity request fields.
type GRPCLookupIdentityRequest struct {
	RequestContext
}

// GRPCListAccountsRequest mirrors the AuthService ListAccounts request fields.
type GRPCListAccountsRequest struct {
	RequestContext
}

// GRPCAuthResponse mirrors AuthService auth and lookup response data.
type GRPCAuthResponse struct {
	OK             bool
	Decision       GRPCDecision
	Session        string
	AccountField   string
	TOTPSecret     string
	Backend        uint32
	Attributes     map[string][]string
	StatusMessage  string
	Error          string
	BackendRefName string
}

// GRPCListAccountsResponse mirrors AuthService list-accounts response data.
type GRPCListAccountsResponse struct {
	Accounts      []string
	Decision      GRPCDecision
	Session       string
	StatusMessage string
	Error         string
}

// GRPCClient maps director auth requests through the AuthService adapter.
type GRPCClient struct {
	service GRPCAuthService
}

type grpcAuthCall func(ctx context.Context) (*GRPCAuthResponse, error)

// NewGRPCClient creates a scaffolded gRPC authority client.
func NewGRPCClient(service GRPCAuthService) (*GRPCClient, error) {
	if service == nil {
		return nil, configError("grpc auth service adapter is required")
	}

	return &GRPCClient{service: service}, nil
}

// Authenticate sends credential-bearing input to AuthService.Authenticate.
func (c *GRPCClient) Authenticate(ctx context.Context, request AuthRequest) (AuthResult, error) {
	return c.invokeValidatedAuth(ctx, operationAuthenticate, validateAuthRequest(request), func(callCtx context.Context) (*GRPCAuthResponse, error) {
		return c.service.Authenticate(callCtx, newGRPCAuthRequest(request))
	})
}

// LookupIdentity sends trusted no-auth input to AuthService.LookupIdentity.
func (c *GRPCClient) LookupIdentity(ctx context.Context, request IdentityLookupRequest) (AuthResult, error) {
	return c.invokeValidatedAuth(ctx, operationLookupIdentity, validateIdentityLookupRequest(request), func(callCtx context.Context) (*GRPCAuthResponse, error) {
		return c.service.LookupIdentity(callCtx, newGRPCLookupIdentityRequest(request))
	})
}

// invokeValidatedAuth applies validation before a shared auth-shaped gRPC call.
func (c *GRPCClient) invokeValidatedAuth(
	ctx context.Context,
	operation authOperation,
	validationErr error,
	call grpcAuthCall,
) (AuthResult, error) {
	if validationErr != nil {
		return resultWithDecision(DecisionTemporaryFailure, "", "", "", nil), validationErr
	}

	return c.invokeAuth(ctx, operation, call)
}

// invokeAuth executes auth-shaped gRPC calls and applies shared error handling.
func (c *GRPCClient) invokeAuth(ctx context.Context, operation authOperation, call grpcAuthCall) (AuthResult, error) {
	response, err := call(ctx)
	if err != nil {
		return resultWithDecision(DecisionTemporaryFailure, "", "", "", nil),
			transportError(operation, err)
	}

	return mapGRPCAuthResponse(operation, response)
}

// ListAccounts sends account-listing input to AuthService.ListAccounts.
func (c *GRPCClient) ListAccounts(ctx context.Context, request ListAccountsRequest) (ListAccountsResult, error) {
	if err := validateListAccountsRequest(request); err != nil {
		return listAccountsWithDecision(DecisionTemporaryFailure, "", "", nil), err
	}

	response, err := c.service.ListAccounts(ctx, newGRPCListAccountsRequest(request))
	if err != nil {
		return listAccountsWithDecision(DecisionTemporaryFailure, "", "", nil),
			transportError(operationListAccounts, err)
	}

	return mapGRPCListAccountsResponse(response)
}

// String returns a redacted representation of the gRPC auth request.
func (r GRPCAuthRequest) String() string {
	return fmt.Sprintf(
		"GRPCAuthRequest{username_present:%t protocol:%q method:%q password:%s}",
		strings.TrimSpace(r.Username) != "",
		r.Protocol,
		r.Method,
		r.Password.String(),
	)
}

// newGRPCAuthRequest maps director input into the scaffolded AuthRequest.
func newGRPCAuthRequest(request AuthRequest) *GRPCAuthRequest {
	return &GRPCAuthRequest{
		RequestContext:   request.Context,
		Password:         request.Credential,
		AuthLoginAttempt: uint32(request.AuthLoginAttempt),
	}
}

// newGRPCLookupIdentityRequest maps director input into the scaffolded lookup request.
func newGRPCLookupIdentityRequest(request IdentityLookupRequest) *GRPCLookupIdentityRequest {
	return &GRPCLookupIdentityRequest{RequestContext: request.Context}
}

// newGRPCListAccountsRequest maps director input into the scaffolded list request.
func newGRPCListAccountsRequest(request ListAccountsRequest) *GRPCListAccountsRequest {
	return &GRPCListAccountsRequest{RequestContext: request.Context}
}

// mapGRPCAuthResponse maps AuthService auth and lookup responses.
func mapGRPCAuthResponse(operation authOperation, response *GRPCAuthResponse) (AuthResult, error) {
	if response == nil {
		return resultWithDecision(DecisionTemporaryFailure, "", "", "", nil),
			malformedResponseError(operation, "empty auth response", nil)
	}

	decision, err := authDecisionFromGRPC(response.Decision, response.OK)
	if err != nil {
		return resultWithDecision(DecisionTemporaryFailure, "", "", "", nil),
			malformedResponseError(operation, "unknown auth decision", err)
	}

	statusMessage := response.StatusMessage
	if statusMessage == "" {
		statusMessage = response.Error
	}

	switch decision {
	case DecisionAuthenticated:
		return mapGRPCAuthSuccess(operation, response, statusMessage)
	case DecisionRejected:
		return resultWithDecision(decision, "", response.Session, statusMessage, nil), nil
	case DecisionTemporaryFailure:
		return resultWithDecision(decision, "", response.Session, statusMessage, nil),
			tempfailError(operation, 0, statusMessage)
	default:
		return resultWithDecision(DecisionTemporaryFailure, "", "", "", nil),
			malformedResponseError(operation, "ambiguous auth decision", nil)
	}
}

// mapGRPCAuthSuccess maps successful gRPC auth data without backend decisions.
func mapGRPCAuthSuccess(
	operation authOperation,
	response *GRPCAuthResponse,
	statusMessage string,
) (AuthResult, error) {
	account, err := responseAccount(operation, response.AccountField, response.Attributes)
	if err != nil {
		return resultWithDecision(DecisionTemporaryFailure, "", "", "", nil), err
	}

	return resultWithDecision(
		DecisionAuthenticated,
		account,
		response.Session,
		statusMessage,
		response.Attributes,
	), nil
}

// mapGRPCListAccountsResponse maps AuthService account-listing data.
func mapGRPCListAccountsResponse(response *GRPCListAccountsResponse) (ListAccountsResult, error) {
	if response == nil {
		return listAccountsWithDecision(DecisionTemporaryFailure, "", "", nil),
			malformedResponseError(operationListAccounts, "empty list-accounts response", nil)
	}

	decision, err := listDecisionFromGRPC(response.Decision)
	if err != nil {
		return listAccountsWithDecision(DecisionTemporaryFailure, "", "", nil),
			malformedResponseError(operationListAccounts, "unknown list-accounts decision", err)
	}

	statusMessage := response.StatusMessage
	if statusMessage == "" {
		statusMessage = response.Error
	}

	if decision == DecisionTemporaryFailure {
		return listAccountsWithDecision(decision, response.Session, statusMessage, nil),
			tempfailError(operationListAccounts, 0, statusMessage)
	}

	if decision == DecisionRejected {
		return listAccountsWithDecision(decision, response.Session, statusMessage, nil), nil
	}

	return listAccountsWithDecision(decision, response.Session, statusMessage, response.Accounts), nil
}

// authDecisionFromGRPC maps gRPC decision values into internal decision strings.
func authDecisionFromGRPC(decision GRPCDecision, ok bool) (string, error) {
	switch decision {
	case GRPCDecisionOK:
		return DecisionAuthenticated, nil
	case GRPCDecisionFail:
		return DecisionRejected, nil
	case GRPCDecisionTempFail:
		return DecisionTemporaryFailure, nil
	case GRPCDecisionUnspecified:
		if ok {
			return DecisionAuthenticated, nil
		}
	}

	return "", fmt.Errorf("grpc decision %d", decision)
}

// listDecisionFromGRPC maps scaffolded list decisions into internal results.
func listDecisionFromGRPC(decision GRPCDecision) (string, error) {
	switch decision {
	case GRPCDecisionUnspecified, GRPCDecisionOK:
		return DecisionAuthenticated, nil
	case GRPCDecisionFail:
		return DecisionRejected, nil
	case GRPCDecisionTempFail:
		return DecisionTemporaryFailure, nil
	default:
		return "", fmt.Errorf("grpc decision %d", decision)
	}
}
