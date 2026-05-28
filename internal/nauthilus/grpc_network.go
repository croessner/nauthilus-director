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
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"os"
	"strings"

	"github.com/croessner/nauthilus-director/internal/config"
	authv1 "github.com/croessner/nauthilus-director/internal/nauthilus/grpcapi/auth/v1"
	commonv1 "github.com/croessner/nauthilus-director/internal/nauthilus/grpcapi/common/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

const authorizationMetadataKey = "authorization"

// networkGRPCAuthService adapts the generated protobuf client to the local authority seam.
type networkGRPCAuthService struct {
	client        authv1.AuthServiceClient
	authorization string
}

// NewGRPCClientFromAuthority creates a gRPC authority client from typed config.
func NewGRPCClientFromAuthority(authority config.AuthorityConfig) (*GRPCClient, error) {
	service, err := newNetworkGRPCAuthService(authority)
	if err != nil {
		return nil, err
	}

	return NewGRPCClient(service)
}

// newNetworkGRPCAuthService creates the generated client adapter with production dial options.
func newNetworkGRPCAuthService(authority config.AuthorityConfig) (*networkGRPCAuthService, error) {
	return newNetworkGRPCAuthServiceWithDialOptions(authority, nil)
}

// newNetworkGRPCAuthServiceWithDialOptions creates the adapter with optional test dial options.
func newNetworkGRPCAuthServiceWithDialOptions(
	authority config.AuthorityConfig,
	extraDialOptions []grpc.DialOption,
) (*networkGRPCAuthService, error) {
	address := strings.TrimSpace(authority.GRPC.Address)
	if address == "" {
		return nil, configError("grpc address is required")
	}

	transport, err := grpcTransportCredentials(authority.GRPC.TLS)
	if err != nil {
		return nil, err
	}

	authorization, err := grpcAuthorizationHeader(authority.GRPC.CallerAuth)
	if err != nil {
		return nil, err
	}

	dialOptions := []grpc.DialOption{
		grpc.WithTransportCredentials(transport),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxHTTPResponseBytes)),
	}
	if configuredAuthority := strings.TrimSpace(authority.GRPC.Authority); configuredAuthority != "" {
		dialOptions = append(dialOptions, grpc.WithAuthority(configuredAuthority))
	}

	dialOptions = append(dialOptions, extraDialOptions...)

	connection, err := grpc.NewClient(address, dialOptions...)
	if err != nil {
		return nil, transportError(operationConfigure, err)
	}

	return &networkGRPCAuthService{
		client:        authv1.NewAuthServiceClient(connection),
		authorization: authorization,
	}, nil
}

// Authenticate maps an internal auth request to the protobuf AuthService request.
func (s *networkGRPCAuthService) Authenticate(ctx context.Context, request *GRPCAuthRequest) (*GRPCAuthResponse, error) {
	response, err := s.client.Authenticate(s.authorizedContext(ctx), newProtoAuthRequest(request))
	if err != nil {
		return nil, err
	}

	return grpcAuthResponseFromProto(response), nil
}

// LookupIdentity maps an internal lookup request to the protobuf AuthService request.
func (s *networkGRPCAuthService) LookupIdentity(
	ctx context.Context,
	request *GRPCLookupIdentityRequest,
) (*GRPCAuthResponse, error) {
	response, err := s.client.LookupIdentity(s.authorizedContext(ctx), newProtoLookupIdentityRequest(request))
	if err != nil {
		return nil, err
	}

	return grpcAuthResponseFromProto(response), nil
}

// ListAccounts maps an internal listing request to the protobuf AuthService request.
func (s *networkGRPCAuthService) ListAccounts(
	ctx context.Context,
	request *GRPCListAccountsRequest,
) (*GRPCListAccountsResponse, error) {
	response, err := s.client.ListAccounts(s.authorizedContext(ctx), newProtoListAccountsRequest(request))
	if err != nil {
		return nil, err
	}

	return grpcListAccountsResponseFromProto(response), nil
}

// authorizedContext adds configured caller authentication metadata to one RPC context.
func (s *networkGRPCAuthService) authorizedContext(ctx context.Context) context.Context {
	if s.authorization == "" {
		return ctx
	}

	return metadata.AppendToOutgoingContext(ctx, authorizationMetadataKey, s.authorization)
}

// grpcTransportCredentials builds the authority transport security policy.
func grpcTransportCredentials(tlsConfig config.AuthorityTLSConfig) (credentials.TransportCredentials, error) {
	if !tlsConfig.Enabled {
		return insecure.NewCredentials(), nil
	}

	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		rootCAs = x509.NewCertPool()
	}

	if caFile := strings.TrimSpace(tlsConfig.CAFile); caFile != "" {
		certificate, readErr := os.ReadFile(caFile)
		if readErr != nil {
			return nil, configError("failed to read grpc ca file")
		}

		if !rootCAs.AppendCertsFromPEM(certificate) {
			return nil, configError("failed to parse grpc ca file")
		}
	}

	return credentials.NewTLS(&tls.Config{
		MinVersion:         tls.VersionTLS12,
		RootCAs:            rootCAs,
		ServerName:         strings.TrimSpace(tlsConfig.ServerName),
		InsecureSkipVerify: tlsConfig.InsecureSkipVerify, //nolint:gosec // Explicit operator-controlled compatibility setting.
	}), nil
}

// grpcAuthorizationHeader builds the secret-bearing gRPC authorization metadata value.
func grpcAuthorizationHeader(callerAuth config.GRPCCallerAuthConfig) (string, error) {
	if callerAuth.Basic.Enabled && callerAuth.Bearer.Enabled {
		return "", configError("only one grpc caller auth method may be enabled")
	}

	if callerAuth.Basic.Enabled {
		username := strings.TrimSpace(callerAuth.Basic.Username)
		password := callerAuth.Basic.PasswordFile.Value()

		if username == "" || password == "" {
			return "", configError("grpc basic caller auth requires username and password")
		}

		return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password)), nil
	}

	if callerAuth.Bearer.Enabled {
		token := strings.TrimSpace(callerAuth.Bearer.TokenFile.Value())
		if token == "" {
			return "", configError("grpc bearer caller auth requires token")
		}

		return "Bearer " + token, nil
	}

	return "", nil
}

// newProtoAuthRequest maps internal credential auth input into the generated protobuf request.
func newProtoAuthRequest(request *GRPCAuthRequest) *authv1.AuthRequest {
	if request == nil {
		return &authv1.AuthRequest{}
	}

	return &authv1.AuthRequest{
		Username:           request.Username,
		Password:           request.Password.Value(),
		ClientIp:           request.ClientIP,
		ClientPort:         request.ClientPort,
		ClientHostname:     request.ClientHostname,
		ClientId:           request.ClientID,
		ExternalSessionId:  request.ExternalSessionID,
		UserAgent:          request.UserAgent,
		LocalIp:            request.LocalIP,
		LocalPort:          request.LocalPort,
		Protocol:           request.Protocol,
		Method:             request.Method,
		Ssl:                request.TLS,
		SslSessionId:       request.TLSSessionID,
		SslClientVerify:    request.TLSClientVerify,
		SslClientDn:        request.TLSClientDN,
		SslClientCn:        request.TLSClientCN,
		SslIssuer:          request.TLSIssuer,
		SslClientNotbefore: request.TLSClientNotBefore,
		SslClientNotafter:  request.TLSClientNotAfter,
		SslSubjectDn:       request.TLSSubjectDN,
		SslIssuerDn:        request.TLSIssuerDN,
		SslClientSubjectDn: request.TLSClientSubjectDN,
		SslClientIssuerDn:  request.TLSClientIssuerDN,
		SslProtocol:        request.TLSProtocol,
		SslCipher:          request.TLSCipher,
		SslSerial:          request.TLSSerial,
		SslFingerprint:     request.TLSFingerprint,
		OidcCid:            request.OIDCCID,
		AuthLoginAttempt:   request.AuthLoginAttempt,
	}
}

// newProtoLookupIdentityRequest maps internal lookup input into the generated protobuf request.
func newProtoLookupIdentityRequest(request *GRPCLookupIdentityRequest) *authv1.LookupIdentityRequest {
	if request == nil {
		return &authv1.LookupIdentityRequest{}
	}

	return &authv1.LookupIdentityRequest{
		Username:           request.Username,
		ClientIp:           request.ClientIP,
		ClientPort:         request.ClientPort,
		ClientHostname:     request.ClientHostname,
		ClientId:           request.ClientID,
		ExternalSessionId:  request.ExternalSessionID,
		UserAgent:          request.UserAgent,
		LocalIp:            request.LocalIP,
		LocalPort:          request.LocalPort,
		Protocol:           request.Protocol,
		Method:             request.Method,
		Ssl:                request.TLS,
		SslSessionId:       request.TLSSessionID,
		SslClientVerify:    request.TLSClientVerify,
		SslClientDn:        request.TLSClientDN,
		SslClientCn:        request.TLSClientCN,
		SslIssuer:          request.TLSIssuer,
		SslClientNotbefore: request.TLSClientNotBefore,
		SslClientNotafter:  request.TLSClientNotAfter,
		SslSubjectDn:       request.TLSSubjectDN,
		SslIssuerDn:        request.TLSIssuerDN,
		SslClientSubjectDn: request.TLSClientSubjectDN,
		SslClientIssuerDn:  request.TLSClientIssuerDN,
		SslProtocol:        request.TLSProtocol,
		SslCipher:          request.TLSCipher,
		SslSerial:          request.TLSSerial,
		SslFingerprint:     request.TLSFingerprint,
		OidcCid:            request.OIDCCID,
	}
}

// newProtoListAccountsRequest maps internal list input into the generated protobuf request.
func newProtoListAccountsRequest(request *GRPCListAccountsRequest) *authv1.ListAccountsRequest {
	if request == nil {
		return &authv1.ListAccountsRequest{}
	}

	return &authv1.ListAccountsRequest{
		Username:          request.Username,
		ClientIp:          request.ClientIP,
		ClientPort:        request.ClientPort,
		ClientHostname:    request.ClientHostname,
		ClientId:          request.ClientID,
		ExternalSessionId: request.ExternalSessionID,
		UserAgent:         request.UserAgent,
		LocalIp:           request.LocalIP,
		LocalPort:         request.LocalPort,
		Protocol:          request.Protocol,
		Method:            request.Method,
		OidcCid:           request.OIDCCID,
	}
}

// grpcAuthResponseFromProto maps generated protobuf auth data into the local seam DTO.
func grpcAuthResponseFromProto(response *authv1.AuthResponse) *GRPCAuthResponse {
	if response == nil {
		return nil
	}

	backendRefName := ""
	if response.BackendRef != nil {
		backendRefName = response.BackendRef.Name
	}

	return &GRPCAuthResponse{
		OK:             response.Ok,
		Decision:       GRPCDecision(response.Decision),
		Session:        response.Session,
		AccountField:   response.AccountField,
		TOTPSecret:     response.TotpSecretField,
		Backend:        response.Backend,
		Attributes:     grpcAttributesFromProto(response.Attributes),
		StatusMessage:  response.StatusMessage,
		Error:          response.Error,
		BackendRefName: backendRefName,
	}
}

// grpcListAccountsResponseFromProto maps generated list data into the local seam DTO.
func grpcListAccountsResponseFromProto(response *authv1.ListAccountsResponse) *GRPCListAccountsResponse {
	if response == nil {
		return nil
	}

	return &GRPCListAccountsResponse{
		Accounts: response.Accounts,
		Decision: GRPCDecisionOK,
		Session:  response.Session,
	}
}

// grpcAttributesFromProto converts generated attribute maps into plain string slices.
func grpcAttributesFromProto(attributes map[string]*commonv1.AttributeValues) map[string][]string {
	if attributes == nil {
		return nil
	}

	converted := make(map[string][]string, len(attributes))
	for key, values := range attributes {
		if values == nil {
			converted[key] = nil

			continue
		}

		converted[key] = append([]string(nil), values.Values...)
	}

	return converted
}
