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
			Username:   "alice@example.test",
			ClientIP:   "203.0.113.10",
			ClientPort: "12345",
			Protocol:   "imap",
			Method:     "plain",
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
		t.Fatalf("protobuf auth request = %#v", server.authRequest)
	}
	if server.authorization != "Basic "+base64.StdEncoding.EncodeToString([]byte("director:director-api-secret")) {
		t.Fatalf("authorization metadata = %q", server.authorization)
	}
}

// TestGRPCNetworkClientRejectsAmbiguousCallerAuth verifies caller-auth config fails closed.
func TestGRPCNetworkClientRejectsAmbiguousCallerAuth(t *testing.T) {
	authority := testGRPCAuthority("127.0.0.1:1")
	authority.GRPC.CallerAuth.Bearer.Enabled = true
	authority.GRPC.CallerAuth.Bearer.TokenFile = config.Secret("bearer-token")

	_, err := newNetworkGRPCAuthService(authority)
	if err == nil {
		t.Fatal("newNetworkGRPCAuthService accepted ambiguous caller auth")
	}
	if !strings.Contains(err.Error(), "only one grpc caller auth method") {
		t.Fatalf("error = %q, want ambiguous caller auth", err.Error())
	}
}

type recordingProtoAuthServer struct {
	authv1.UnimplementedAuthServiceServer

	authRequest   *authv1.AuthRequest
	authorization string
}

// Authenticate records the protobuf request and returns an authority success response.
func (s *recordingProtoAuthServer) Authenticate(
	ctx context.Context,
	request *authv1.AuthRequest,
) (*authv1.AuthResponse, error) {
	s.authRequest = request
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

// newTestProtoAuthority starts a local protobuf authority server and returns its client adapter.
func newTestProtoAuthority(t *testing.T) (*networkGRPCAuthService, *recordingProtoAuthServer) {
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

	service, err := newNetworkGRPCAuthService(testGRPCAuthority(listener.Addr().String()))
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
