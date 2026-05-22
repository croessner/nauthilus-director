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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/croessner/nauthilus-director/internal/config"
)

const (
	defaultHTTPContentType = "application/json"
	maxHTTPResponseBytes   = 1 << 20
	queryMode              = "mode"
)

// HTTPClientConfig contains HTTP authority transport settings.
type HTTPClientConfig struct {
	Endpoint          string
	ContentType       string
	BasicAuthUsername string
	BasicAuthPassword Secret
	Client            *http.Client
}

// HTTPClient maps director auth requests to Nauthilus JSON requests.
type HTTPClient struct {
	endpoint          string
	contentType       string
	basicAuthUsername string
	basicAuthPassword Secret
	client            *http.Client
}

type httpAuthRequest struct {
	Username           string `json:"username"`
	Password           string `json:"password,omitempty"`
	ClientIP           string `json:"client_ip,omitempty"`
	ClientPort         string `json:"client_port,omitempty"`
	ClientHostname     string `json:"client_hostname,omitempty"`
	ClientID           string `json:"client_id,omitempty"`
	ExternalSessionID  string `json:"external_session_id,omitempty"`
	UserAgent          string `json:"user_agent,omitempty"`
	LocalIP            string `json:"local_ip,omitempty"`
	LocalPort          string `json:"local_port,omitempty"`
	Protocol           string `json:"protocol,omitempty"`
	Method             string `json:"method,omitempty"`
	TLS                string `json:"ssl,omitempty"`
	TLSSessionID       string `json:"ssl_session_id,omitempty"`
	TLSClientVerify    string `json:"ssl_client_verify,omitempty"`
	TLSClientDN        string `json:"ssl_client_dn,omitempty"`
	TLSClientCN        string `json:"ssl_client_cn,omitempty"`
	TLSIssuer          string `json:"ssl_issuer,omitempty"`
	TLSClientNotBefore string `json:"ssl_client_notbefore,omitempty"`
	TLSClientNotAfter  string `json:"ssl_client_notafter,omitempty"`
	TLSSubjectDN       string `json:"ssl_subject_dn,omitempty"`
	TLSIssuerDN        string `json:"ssl_issuer_dn,omitempty"`
	TLSClientSubjectDN string `json:"ssl_client_subject_dn,omitempty"`
	TLSClientIssuerDN  string `json:"ssl_client_issuer_dn,omitempty"`
	TLSProtocol        string `json:"ssl_protocol,omitempty"`
	TLSCipher          string `json:"ssl_cipher,omitempty"`
	TLSSerial          string `json:"ssl_serial,omitempty"`
	TLSFingerprint     string `json:"ssl_fingerprint,omitempty"`
	OIDCCID            string `json:"oidc_cid,omitempty"`
	AuthLoginAttempt   uint   `json:"auth_login_attempt,omitempty"`
}

type httpAuthResponse struct {
	OK            bool                `json:"ok"`
	AccountField  string              `json:"account_field,omitempty"`
	TOTPSecret    string              `json:"totp_secret_field,omitempty"`
	Backend       int                 `json:"backend,omitempty"`
	Attributes    map[string][]string `json:"attributes,omitempty"`
	StatusMessage string              `json:"status_message,omitempty"`
	Error         string              `json:"error,omitempty"`
}

// NewHTTPClient creates an HTTP authority client.
func NewHTTPClient(config HTTPClientConfig) (*HTTPClient, error) {
	endpoint := strings.TrimSpace(config.Endpoint)
	if endpoint == "" {
		return nil, configError("http endpoint is required")
	}

	contentType := strings.TrimSpace(config.ContentType)
	if contentType == "" {
		contentType = defaultHTTPContentType
	}

	client := config.Client
	if client == nil {
		client = http.DefaultClient
	}

	return &HTTPClient{
		endpoint:          endpoint,
		contentType:       contentType,
		basicAuthUsername: config.BasicAuthUsername,
		basicAuthPassword: config.BasicAuthPassword,
		client:            client,
	}, nil
}

// NewHTTPClientFromAuthority builds an HTTP client from typed config.
func NewHTTPClientFromAuthority(authority config.AuthorityConfig, client *http.Client) (*HTTPClient, error) {
	return NewHTTPClient(HTTPClientConfig{
		Endpoint:          authority.HTTP.Endpoint,
		ContentType:       authority.HTTP.ContentType,
		BasicAuthUsername: authority.HTTP.BasicAuth.Username,
		BasicAuthPassword: NewSecret(authority.HTTP.BasicAuth.PasswordFile.Value()),
		Client:            client,
	})
}

// Authenticate sends a credential-bearing JSON auth request.
func (c *HTTPClient) Authenticate(ctx context.Context, request AuthRequest) (AuthResult, error) {
	if err := validateAuthRequest(request); err != nil {
		return resultWithDecision(DecisionTemporaryFailure, "", "", "", nil), err
	}

	body := newHTTPAuthRequest(request.Context, request.Credential, request.AuthLoginAttempt)

	return c.doAuth(ctx, operationAuthenticate, body)
}

// LookupIdentity sends a no-auth identity lookup request.
func (c *HTTPClient) LookupIdentity(ctx context.Context, request IdentityLookupRequest) (AuthResult, error) {
	if err := validateIdentityLookupRequest(request); err != nil {
		return resultWithDecision(DecisionTemporaryFailure, "", "", "", nil), err
	}

	body := newHTTPAuthRequest(request.Context, Secret{}, 0)

	return c.doAuth(ctx, operationLookupIdentity, body)
}

// ListAccounts sends an account-provider request without director routing state.
func (c *HTTPClient) ListAccounts(ctx context.Context, request ListAccountsRequest) (ListAccountsResult, error) {
	if err := validateListAccountsRequest(request); err != nil {
		return listAccountsWithDecision(DecisionTemporaryFailure, "", "", nil), err
	}

	body := newHTTPAuthRequest(request.Context, Secret{}, 0)

	response, statusCode, err := c.postJSON(ctx, operationListAccounts, body)
	if err != nil {
		return listAccountsWithDecision(DecisionTemporaryFailure, "", "", nil), err
	}
	defer func() {
		_ = response.Body.Close()
	}()

	if statusCode >= http.StatusInternalServerError {
		return listAccountsWithDecision(DecisionTemporaryFailure, "", "", nil),
			tempfailError(operationListAccounts, statusCode, "")
	}

	if statusCode == http.StatusForbidden || statusCode == http.StatusUnauthorized {
		return listAccountsWithDecision(DecisionRejected, "", "", nil), nil
	}

	if statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices {
		return listAccountsWithDecision(DecisionTemporaryFailure, "", "", nil),
			malformedResponseError(operationListAccounts, "unexpected http status", nil)
	}

	accounts, err := decodeHTTPListAccountsResponse(response.Body)
	if err != nil {
		return listAccountsWithDecision(DecisionTemporaryFailure, "", "", nil),
			malformedResponseError(operationListAccounts, "invalid list-accounts response", err)
	}

	return listAccountsWithDecision(DecisionAuthenticated, "", "", accounts), nil
}

// doAuth sends a JSON auth or lookup request and maps the response.
func (c *HTTPClient) doAuth(ctx context.Context, operation authOperation, body httpAuthRequest) (AuthResult, error) {
	response, statusCode, err := c.postJSON(ctx, operation, body)
	if err != nil {
		return resultWithDecision(DecisionTemporaryFailure, "", "", "", nil), err
	}
	defer func() {
		_ = response.Body.Close()
	}()

	if statusCode >= http.StatusInternalServerError {
		return resultWithDecision(DecisionTemporaryFailure, "", "", "", nil),
			tempfailError(operation, statusCode, "")
	}

	if statusCode == http.StatusForbidden || statusCode == http.StatusUnauthorized {
		return resultWithDecision(DecisionRejected, "", "", "", nil), nil
	}

	if statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices {
		return resultWithDecision(DecisionTemporaryFailure, "", "", "", nil),
			malformedResponseError(operation, "unexpected http status", nil)
	}

	authorityResponse, err := decodeHTTPAuthResponse(response.Body)
	if err != nil {
		return resultWithDecision(DecisionTemporaryFailure, "", "", "", nil),
			malformedResponseError(operation, "invalid auth response", err)
	}

	return mapHTTPAuthResponse(operation, authorityResponse)
}

// postJSON executes the authority HTTP request.
func (c *HTTPClient) postJSON(
	ctx context.Context,
	operation authOperation,
	body httpAuthRequest,
) (*http.Response, int, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, 0, malformedResponseError(operation, "invalid request body", err)
	}

	endpoint, err := c.endpointForOperation(operation)
	if err != nil {
		return nil, 0, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return nil, 0, transportError(operation, err)
	}

	request.Header.Set("Content-Type", c.contentType)
	request.Header.Set("Accept", defaultHTTPContentType)

	if !c.basicAuthPassword.IsZero() || c.basicAuthUsername != "" {
		request.SetBasicAuth(c.basicAuthUsername, c.basicAuthPassword.Value())
	}

	response, err := c.client.Do(request)
	if err != nil {
		return nil, 0, transportError(operation, err)
	}

	return response, response.StatusCode, nil
}

// endpointForOperation adds the Nauthilus mode query when required.
func (c *HTTPClient) endpointForOperation(operation authOperation) (string, error) {
	parsed, err := url.Parse(c.endpoint)
	if err != nil {
		return "", configError("invalid http endpoint")
	}

	switch operation {
	case operationLookupIdentity:
		query := parsed.Query()
		query.Set(queryMode, "no-auth")
		parsed.RawQuery = query.Encode()
	case operationListAccounts:
		query := parsed.Query()
		query.Set(queryMode, string(operationListAccounts))
		parsed.RawQuery = query.Encode()
	}

	return parsed.String(), nil
}

// newHTTPAuthRequest maps director context into the strict Nauthilus JSON DTO.
func newHTTPAuthRequest(context RequestContext, credential Secret, authLoginAttempt uint) httpAuthRequest {
	return httpAuthRequest{
		Username:           context.Username,
		Password:           credential.Value(),
		ClientIP:           context.ClientIP,
		ClientPort:         context.ClientPort,
		ClientHostname:     context.ClientHostname,
		ClientID:           context.ClientID,
		ExternalSessionID:  context.ExternalSessionID,
		UserAgent:          context.UserAgent,
		LocalIP:            context.LocalIP,
		LocalPort:          context.LocalPort,
		Protocol:           context.Protocol,
		Method:             context.Method,
		TLS:                context.TLS,
		TLSSessionID:       context.TLSSessionID,
		TLSClientVerify:    context.TLSClientVerify,
		TLSClientDN:        context.TLSClientDN,
		TLSClientCN:        context.TLSClientCN,
		TLSIssuer:          context.TLSIssuer,
		TLSClientNotBefore: context.TLSClientNotBefore,
		TLSClientNotAfter:  context.TLSClientNotAfter,
		TLSSubjectDN:       context.TLSSubjectDN,
		TLSIssuerDN:        context.TLSIssuerDN,
		TLSClientSubjectDN: context.TLSClientSubjectDN,
		TLSClientIssuerDN:  context.TLSClientIssuerDN,
		TLSProtocol:        context.TLSProtocol,
		TLSCipher:          context.TLSCipher,
		TLSSerial:          context.TLSSerial,
		TLSFingerprint:     context.TLSFingerprint,
		OIDCCID:            context.OIDCCID,
		AuthLoginAttempt:   authLoginAttempt,
	}
}

// decodeHTTPAuthResponse decodes a bounded strict JSON auth response.
func decodeHTTPAuthResponse(body io.Reader) (httpAuthResponse, error) {
	var response httpAuthResponse

	decoder := json.NewDecoder(io.LimitReader(body, maxHTTPResponseBytes))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&response); err != nil {
		return httpAuthResponse{}, err
	}

	return response, nil
}

// decodeHTTPListAccountsResponse decodes a bounded JSON account list.
func decodeHTTPListAccountsResponse(body io.Reader) ([]string, error) {
	var accounts []string

	decoder := json.NewDecoder(io.LimitReader(body, maxHTTPResponseBytes))

	if err := decoder.Decode(&accounts); err != nil {
		return nil, err
	}

	return accounts, nil
}

// mapHTTPAuthResponse maps Nauthilus JSON success and rejection envelopes.
func mapHTTPAuthResponse(operation authOperation, response httpAuthResponse) (AuthResult, error) {
	statusMessage := response.StatusMessage
	if statusMessage == "" {
		statusMessage = response.Error
	}

	if !response.OK {
		return resultWithDecision(DecisionRejected, "", "", statusMessage, nil), nil
	}

	if strings.TrimSpace(response.AccountField) == "" {
		return resultWithDecision(DecisionTemporaryFailure, "", "", "", nil),
			malformedResponseError(operation, "missing account field", nil)
	}

	return resultWithDecision(
		DecisionAuthenticated,
		response.AccountField,
		"",
		statusMessage,
		response.Attributes,
	), nil
}
