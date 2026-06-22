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

//nolint:funlen,goconst,wsl_v5 // Tests keep the local protobuf server fixture nearby.
package nauthilus

import (
	"context"
	"encoding/base64"
	"net"
	"strings"
	"testing"

	"github.com/croessner/nauthilus-director/internal/config"
	authv1 "github.com/croessner/nauthilus-director/internal/nauthilus/grpcapi/auth/v1"
	commonv1 "github.com/croessner/nauthilus-director/internal/nauthilus/grpcapi/common/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// TestGRPCNetworkClientAuthenticatesAgainstProtoService verifies the generated client boundary.
func TestGRPCNetworkClientAuthenticatesAgainstProtoService(t *testing.T) {
	service, server := newTestProtoAuthority(t)
	client := newTestGRPCClient(t, service)

	result, err := client.Authenticate(context.Background(), AuthRequest{
		Context: RequestContext{
			Username:        "alice@example.test",
			ClientIP:        "203.0.113.10",
			ClientPort:      "12345",
			Protocol:        "imap",
			Method:          "plain",
			TLS:             "true",
			TLSClientVerify: "SUCCESS",
			TLSClientCN:     "client.example.test",
		},
		Credential:       NewSecret("secret-password"),
		AuthLoginAttempt: 1,
	})
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if result.Decision != DecisionAuthenticated || result.Account != "alice@example.test" {
		t.Fatalf("result = %#v, want authenticated alice@example.test", result)
	}
	if got := result.Attributes["mailShard"]; len(got) != 1 || got[0] != "mailstore-a" {
		t.Fatalf("mailShard attributes = %#v", got)
	}
	if server.authRequest == nil {
		t.Fatal("protobuf authority did not receive auth request")
	}
	if server.authRequest.GetPassword() != "secret-password" {
		t.Fatal("protobuf auth request did not carry credential material to authority")
	}
	if server.authRequest.GetProtocol() != "imap" || server.authRequest.GetMethod() != "plain" {
		t.Fatal("protobuf auth request did not carry expected protocol and method")
	}
	if server.authRequest.GetSsl() != "true" || server.authRequest.GetSslClientVerify() != "SUCCESS" ||
		server.authRequest.GetSslClientCn() != "client.example.test" {
		t.Fatalf("protobuf TLS context = %#v", server.authRequest)
	}
	if server.authorization != "Basic "+base64.StdEncoding.EncodeToString([]byte("director:director-api-secret")) {
		t.Fatal("authorization metadata did not carry expected basic caller auth")
	}
}

// TestGRPCNetworkClientRejectsAmbiguousCallerAuth verifies caller-auth config fails closed.
func TestGRPCNetworkClientRejectsAmbiguousCallerAuth(t *testing.T) {
	authority := testGRPCAuthority("127.0.0.1:1")
	authority.GRPC.CallerAuth.Bearer.Enabled = true
	authority.GRPC.CallerAuth.Bearer.TokenFile = config.Secret("bearer-token")

	_, err := newNetworkGRPCAuthService(authority, AuthorityContext{})
	if err == nil {
		t.Fatal("newNetworkGRPCAuthService accepted ambiguous caller auth")
	}
	if !strings.Contains(err.Error(), "only one grpc caller auth method") {
		t.Fatalf("error = %q, want ambiguous caller auth", err.Error())
	}
}

// TestGRPCNetworkAuthorityContextMetadataSentForAllOperations verifies listener context reaches every RPC.
func TestGRPCNetworkAuthorityContextMetadataSentForAllOperations(t *testing.T) {
	service, server := newTestProtoAuthorityWithContext(t, AuthorityContext{
		GRPCMetadata: map[string]string{
			"x-company-domain": "companyde",
			"x-policy-tier":    "gold",
		},
	})
	client := newTestGRPCClient(t, service)

	if _, err := client.Authenticate(context.Background(), AuthRequest{
		Context:    testAuthRequest().Context,
		Credential: NewSecret("secret-password"),
	}); err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if _, err := client.LookupIdentity(context.Background(), IdentityLookupRequest{Context: testAuthRequest().Context}); err != nil {
		t.Fatalf("LookupIdentity returned error: %v", err)
	}
	if _, err := client.ListAccounts(context.Background(), ListAccountsRequest{Context: testAuthRequest().Context}); err != nil {
		t.Fatalf("ListAccounts returned error: %v", err)
	}

	for operation, md := range map[string]metadata.MD{
		"authenticate":    server.authMetadata,
		"lookup-identity": server.lookupMetadata,
		"list-accounts":   server.listMetadata,
	} {
		assertIncomingMetadataValue(t, md, "x-company-domain", "companyde", operation)
		assertIncomingMetadataValue(t, md, "x-policy-tier", "gold", operation)
	}
}

// TestGRPCNetworkPropagatesTraceContext verifies outbound RPCs carry the active trace.
func TestGRPCNetworkPropagatesTraceContext(t *testing.T) {
	service, server := newTestProtoAuthority(t)
	client := newTestGRPCClient(t, service)

	if _, err := client.Authenticate(contextWithTestTrace(), testAuthRequest()); err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}

	if got := strings.Join(server.authMetadata.Get("traceparent"), ","); !strings.Contains(got, testTraceID) {
		t.Fatalf("traceparent metadata = %q, want trace ID %s", got, testTraceID)
	}
}

// TestGRPCNetworkAuthorityContextPreservesCallerAuthMetadata verifies context cannot replace authorization.
func TestGRPCNetworkAuthorityContextPreservesCallerAuthMetadata(t *testing.T) {
	authorityContext := AuthorityContext{
		GRPCMetadata: map[string]string{
			authorizationMetadataKey: "Bearer context-token",
			"x-company-domain":       "companyde",
		},
	}

	t.Run("basic", func(t *testing.T) {
		service, server := newTestProtoAuthorityWithContext(t, authorityContext)
		client := newTestGRPCClient(t, service)

		if _, err := client.Authenticate(context.Background(), testAuthRequest()); err != nil {
			t.Fatalf("Authenticate returned error: %v", err)
		}

		want := "Basic " + base64.StdEncoding.EncodeToString([]byte("director:director-api-secret"))
		if server.authorization != want {
			t.Fatal("authorization metadata did not preserve configured basic caller auth")
		}
		assertIncomingMetadataValue(t, server.authMetadata, "x-company-domain", "companyde", "authenticate")
	})

	t.Run("bearer", func(t *testing.T) {
		service, server := newTestProtoAuthorityWithConfig(t, authorityContext, func(authority config.AuthorityConfig) config.AuthorityConfig {
			authority.GRPC.CallerAuth.Basic.Enabled = false
			authority.GRPC.CallerAuth.Bearer.Enabled = true
			authority.GRPC.CallerAuth.Bearer.TokenFile = config.Secret("static-bearer-token")

			return authority
		})
		client := newTestGRPCClient(t, service)

		if _, err := client.Authenticate(context.Background(), testAuthRequest()); err != nil {
			t.Fatalf("Authenticate returned error: %v", err)
		}

		if server.authorization != "Bearer static-bearer-token" {
			t.Fatal("authorization metadata did not preserve configured bearer caller auth")
		}
		assertIncomingMetadataValue(t, server.authMetadata, "x-company-domain", "companyde", "authenticate")
	})

	t.Run("oidc", func(t *testing.T) {
		service, server := newTestProtoAuthorityWithContext(t, authorityContext)
		service.authorization = ""
		service.tokenSource = staticCallerTokenSource{token: "grpc-oidc-token"}
		client := newTestGRPCClient(t, service)

		if _, err := client.Authenticate(context.Background(), testAuthRequest()); err != nil {
			t.Fatalf("Authenticate returned error: %v", err)
		}

		if server.authorization != "Bearer grpc-oidc-token" {
			t.Fatal("authorization metadata did not preserve OIDC caller auth")
		}
		assertIncomingMetadataValue(t, server.authMetadata, "x-company-domain", "companyde", "authenticate")
	})
}

// TestGRPCNetworkOIDCCallerAuthSendsBearerOnly verifies OIDC metadata replaces Basic auth.
func TestGRPCNetworkOIDCCallerAuthSendsBearerOnly(t *testing.T) {
	service, server := newTestProtoAuthority(t)
	service.authorization = ""
	service.tokenSource = staticCallerTokenSource{token: "grpc-oidc-token"}
	client := newTestGRPCClient(t, service)

	result, err := client.Authenticate(context.Background(), AuthRequest{
		Context: RequestContext{
			Username: "alice@example.test",
			Protocol: "imap",
			Method:   "plain",
		},
		Credential: NewSecret("secret-password"),
	})
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if result.Decision != DecisionAuthenticated {
		t.Fatalf("decision = %q, want authenticated", result.Decision)
	}
	if server.authorization != "Bearer grpc-oidc-token" {
		t.Fatal("authorization metadata did not carry expected OIDC caller auth")
	}
	if strings.HasPrefix(server.authorization, "Basic ") {
		t.Fatal("OIDC caller auth also sent Basic metadata")
	}
}

type recordingProtoAuthServer struct {
	authv1.UnimplementedAuthServiceServer

	authRequest    *authv1.AuthRequest
	authMetadata   metadata.MD
	lookupRequest  *authv1.LookupIdentityRequest
	lookupMetadata metadata.MD
	listRequest    *authv1.ListAccountsRequest
	listMetadata   metadata.MD
	authorization  string
}

// Authenticate records the protobuf request and returns an authority success response.
func (s *recordingProtoAuthServer) Authenticate(
	ctx context.Context,
	request *authv1.AuthRequest,
) (*authv1.AuthResponse, error) {
	s.authRequest = request
	s.authMetadata = incomingMetadata(ctx)
	s.authorization = authorizationFromIncomingMetadata(ctx)

	return &authv1.AuthResponse{
		Ok:           true,
		Decision:     authv1.AuthDecision_AUTH_DECISION_OK,
		Session:      "proto-session",
		AccountField: "account",
		Attributes: map[string]*commonv1.AttributeValues{
			"account":   &commonv1.AttributeValues{Values: []string{"alice@example.test"}},
			"mailShard": &commonv1.AttributeValues{Values: []string{"mailstore-a"}},
			"tenant":    &commonv1.AttributeValues{Values: []string{"default"}},
		},
	}, nil
}

// LookupIdentity records metadata and returns an authority lookup success response.
func (s *recordingProtoAuthServer) LookupIdentity(
	ctx context.Context,
	request *authv1.LookupIdentityRequest,
) (*authv1.AuthResponse, error) {
	s.lookupRequest = request
	s.lookupMetadata = incomingMetadata(ctx)

	return &authv1.AuthResponse{
		Ok:           true,
		Decision:     authv1.AuthDecision_AUTH_DECISION_OK,
		Session:      "proto-lookup-session",
		AccountField: "account",
		Attributes: map[string]*commonv1.AttributeValues{
			"account": &commonv1.AttributeValues{Values: []string{"lookup@example.test"}},
		},
	}, nil
}

// ListAccounts records metadata and returns an authority account-listing response.
func (s *recordingProtoAuthServer) ListAccounts(
	ctx context.Context,
	request *authv1.ListAccountsRequest,
) (*authv1.ListAccountsResponse, error) {
	s.listRequest = request
	s.listMetadata = incomingMetadata(ctx)

	return &authv1.ListAccountsResponse{
		Accounts: []string{"alice@example.test"},
		Session:  "proto-list-session",
	}, nil
}

// newTestProtoAuthority starts a local protobuf authority server and returns its client adapter.
func newTestProtoAuthority(t *testing.T) (*networkGRPCAuthService, *recordingProtoAuthServer) {
	t.Helper()

	return newTestProtoAuthorityWithContext(t, AuthorityContext{})
}

// newTestProtoAuthorityWithContext starts a local authority with static outgoing context.
func newTestProtoAuthorityWithContext(
	t *testing.T,
	authorityContext AuthorityContext,
) (*networkGRPCAuthService, *recordingProtoAuthServer) {
	t.Helper()

	return newTestProtoAuthorityWithConfig(t, authorityContext, nil)
}

// newTestProtoAuthorityWithConfig starts a local authority after adjusting its client config.
func newTestProtoAuthorityWithConfig(
	t *testing.T,
	authorityContext AuthorityContext,
	configure func(config.AuthorityConfig) config.AuthorityConfig,
) (*networkGRPCAuthService, *recordingProtoAuthServer) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	server := &recordingProtoAuthServer{}
	authv1.RegisterAuthServiceServer(grpcServer, server)
	go func() {
		_ = grpcServer.Serve(listener)
	}()
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = listener.Close()
	})

	authority := testGRPCAuthority(listener.Addr().String())
	if configure != nil {
		authority = configure(authority)
	}

	service, err := newNetworkGRPCAuthService(authority, authorityContext)
	if err != nil {
		t.Fatalf("newNetworkGRPCAuthService: %v", err)
	}

	return service, server
}

// testGRPCAuthority creates a minimal insecure local authority config for network tests.
func testGRPCAuthority(address string) config.AuthorityConfig {
	return config.AuthorityConfig{
		GRPC: config.AuthorityGRPCTransportConfig{
			Address: address,
			CallerAuth: config.GRPCCallerAuthConfig{
				Basic: config.BasicCallerAuthConfig{
					Enabled:      true,
					Username:     "director",
					PasswordFile: config.Secret("director-api-secret"),
				},
			},
		},
	}
}

// authorizationFromIncomingMetadata returns the first incoming authorization metadata value.
func authorizationFromIncomingMetadata(ctx context.Context) string {
	values := metadata.ValueFromIncomingContext(ctx, authorizationMetadataKey)
	if len(values) == 0 {
		return ""
	}

	return values[0]
}

// incomingMetadata returns a detached copy of incoming RPC metadata.
func incomingMetadata(ctx context.Context) metadata.MD {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return metadata.MD{}
	}

	return md.Copy()
}

// assertIncomingMetadataValue verifies one recorded metadata value.
func assertIncomingMetadataValue(t *testing.T, md metadata.MD, key string, want string, operation string) {
	t.Helper()

	values := md.Get(key)
	if len(values) != 1 || values[0] != want {
		t.Fatalf("%s metadata %s did not match expected listener context", operation, key)
	}
}
