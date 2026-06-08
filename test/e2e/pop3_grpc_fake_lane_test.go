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

//nolint:funlen,goconst,wsl_v5 // The E2E fixture keeps the generated gRPC boundary explicit.
package e2e

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	authv1 "github.com/croessner/nauthilus-director/internal/nauthilus/grpcapi/auth/v1"
	commonv1 "github.com/croessner/nauthilus-director/internal/nauthilus/grpcapi/common/v1"
	pop3backend "github.com/croessner/nauthilus-director/test/e2e/fakes/pop3_backend"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const (
	e2ePOP3GRPCCallerUser   = "director"
	e2ePOP3GRPCCallerSecret = "director-api-secret"
)

// TestServerBinaryPublicPOP3GRPCAuthorityFlow proves POP3 auth through the generated gRPC authority boundary.
func TestServerBinaryPublicPOP3GRPCAuthorityFlow(t *testing.T) {
	binary := e2eServerBinary(t)
	redisFixture := startValkeySessionStore(t)
	identities := pop3AuthorityIdentities()
	identities[e2ePOP3BearerAccount] = map[string][]string{
		"account":   {e2ePOP3BearerAccount},
		"tenant":    {e2eTenant},
		"mailShard": {e2eShardTag},
	}
	authority := startFakePOP3GRPCAuthority(t, identities)
	fakePOP3 := pop3backend.Start(t, pop3backend.Options{Messages: pop3SentinelMessages()})
	pop3Address := loopbackAddress(t)
	configPath := writePOP3GRPCProcessConfig(t, pop3GRPCProcessConfigOptions{
		AuthorityContextGRPCMetadata: map[string]string{
			e2eContextMetadata: e2eContextGRPCValue,
		},
		RedisAddress: redisFixture.addr,
		GRPCAddress:  authority.Address(),
		POP3Address:  pop3Address,
		POP3Backend:  fakePOP3.Address(),
	})
	process := startDirectorProcess(t, binary, configPath)

	waitForPOP3Greeting(t, pop3Address, process)

	passwordClient := authenticatedPOP3Client(t, pop3Address, e2ePOP3Account)
	passwordClient.WriteLine(pop3CommandStat)
	passwordClient.ExpectStatusPrefix("+OK")
	passwordClient.WriteLine(pop3CommandQuit)
	passwordClient.ExpectStatusPrefix("+OK")
	passwordClient.Close()
	authority.ExpectRequest(t, e2ePOP3Protocol, "userpass")
	authority.ExpectMetadata(t, e2eContextMetadata, e2eContextGRPCValue)
	assertPOP3Observation(t, fakePOP3.ExpectObservation(t), "userpass", false)

	bearerClient := dialPOP3StartedTLS(t, pop3Address)
	bearerClient.WriteLine(pop3CommandAuth + " XOAUTH2 " + pop3XOAUTH2Payload(e2ePOP3BearerAccount, e2eToken))
	bearerClient.ExpectStatusPrefix("+OK")
	bearerClient.WriteLine(pop3CommandQuit)
	bearerClient.ExpectStatusPrefix("+OK")
	bearerClient.Close()
	authority.ExpectRequest(t, e2ePOP3Protocol, "xoauth2")
	authority.ExpectMetadata(t, e2eContextMetadata, e2eContextGRPCValue)
	assertPOP3Observation(t, fakePOP3.ExpectObservation(t), "userpass", false)
	assertOutputOmits(t, process.output.String(), e2ePassword, e2eToken)
	assertOutputOmitsAuthorityContext(t, process.output.String(), e2eContextGRPCValue)
}

type pop3GRPCProcessConfigOptions struct {
	AuthorityContextGRPCMetadata map[string]string
	RedisAddress                 string
	GRPCAddress                  string
	POP3Address                  string
	POP3Backend                  string
}

// writePOP3GRPCProcessConfig writes a minimal POP3 config using a generated gRPC authority.
func writePOP3GRPCProcessConfig(t *testing.T, options pop3GRPCProcessConfigOptions) string {
	t.Helper()

	certPath, keyPath, _ := writeTestCertificate(t)
	content := fmt.Sprintf(`patch:
  - op: remove
    path: director.listeners
    value: [imap, imaps, lmtp, lmtps, sieve, sieves, pop3s]
  - op: remove
    path: director.backend_pools
    value: [imap-default, lmtp-default, sieve-default]
  - op: remove
    path: director.backends
    value: [mailstore-a-imap, mailstore-b-imap, mailstore-a-lmtp, mailstore-b-lmtp, mailstore-a-sieve, mailstore-b-sieve, mailstore-b-pop3]
runtime:
  instance_name: "e2e-pop3-grpc-director"
  process:
    shutdown_timeout: 2s
  servers:
    control:
      enabled: false
      address: "127.0.0.1:0"
%s
  timeouts:
    preauth: 2s
    auth: 2s
    nauthilus: 2s
    backend_connect: 2s
    proxy_idle: 2s
storage:
  redis:
    protocol: 2
    key_prefix: "nauthilus-director-e2e-pop3-grpc"
    standalone:
      address: %q
    auth:
      username: ""
      password_file: ""
    tls:
      enabled: false
auth:
  authorities:
    default:
      transport: grpc
%s
      grpc:
        address: %q
        authority: ""
        caller_auth:
          basic:
            enabled: true
            username: %q
            password_file: %q
          bearer:
            enabled: false
            token_file: ""
        tls:
          enabled: false
          ca_file: ""
          server_name: ""
director:
  health:
    interval: 200ms
    timeout: 1s
    jitter: 0s
    unhealthy_after: 1
    healthy_after: 1
  routing:
    default_selector: rendezvous_hash
    default_shard: %q
  listeners:
    pop3:
      protocol: pop3
      service_name: pop3
      network: tcp
      address: %q
      authority: default
      backend_pool: pop3-default
%s
      tls:
        mode: starttls
        cert: %q
        key: %q
        min_tls_version: TLS1.2
      pop3:
        auth_mechanisms: [userpass, xoauth2, oauthbearer]
        capabilities: [STLS, USER, SASL, UIDL, TOP, RESP-CODES]
  backend_pools:
    pop3-default:
      protocol: pop3
      selector: rendezvous_hash
      backends: [mailstore-a-pop3]
  backends:
    mailstore-a-pop3:
      protocol: pop3
      shard_tag: %q
      backend_node: mailstore-a-node
      address: %q
      weight: 100
      max_connections: 100
      maintenance: disabled
      tls:
        mode: plaintext
        min_tls_version: TLS1.2
      auth:
        mode: master_user
        master_user:
          username: director-master
          password_file: %q
          user_format: "{user}*{master_user}"
          mechanism: plain
      health_check:
        enabled: false
`, processControlAuthYAML(t),
		options.RedisAddress,
		processAuthorityOIDCYAML(),
		options.GRPCAddress,
		e2ePOP3GRPCCallerUser,
		e2ePOP3GRPCCallerSecret,
		e2eShardTag,
		options.POP3Address,
		listenerAuthorityContextYAML(nil, options.AuthorityContextGRPCMetadata),
		certPath,
		keyPath,
		e2eShardTag,
		options.POP3Backend,
		e2ePassword,
	)
	content = strings.ReplaceAll(content, "\t", "")

	path := filepath.Join(t.TempDir(), "nauthilus-director-pop3-grpc.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write POP3 gRPC process config: %v", err)
	}

	return path
}

type fakePOP3GRPCAuthority struct {
	authv1.UnimplementedAuthServiceServer

	listener          net.Listener
	server            *grpc.Server
	identities        map[string]map[string][]string
	mu                sync.Mutex
	requests          []*authv1.AuthRequest
	contextMetadata   []map[string]string
	callerAuthPresent []bool
}

// startFakePOP3GRPCAuthority starts a generated AuthService fixture on loopback.
func startFakePOP3GRPCAuthority(t *testing.T, identities map[string]map[string][]string) *fakePOP3GRPCAuthority {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake POP3 gRPC authority: %v", err)
	}

	grpcServer := grpc.NewServer()
	authority := &fakePOP3GRPCAuthority{
		listener:   listener,
		server:     grpcServer,
		identities: identities,
	}
	authv1.RegisterAuthServiceServer(grpcServer, authority)
	go func() {
		_ = grpcServer.Serve(listener)
	}()
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = listener.Close()
	})

	return authority
}

// Address returns the loopback address of the generated gRPC fixture.
func (a *fakePOP3GRPCAuthority) Address() string {
	return a.listener.Addr().String()
}

// Authenticate records POP3 authority input and returns canonical account facts.
func (a *fakePOP3GRPCAuthority) Authenticate(ctx context.Context, request *authv1.AuthRequest) (*authv1.AuthResponse, error) {
	a.mu.Lock()
	a.requests = append(a.requests, request)
	a.contextMetadata = append(a.contextMetadata, safeGRPCAuthorityContextMetadata(ctx))
	a.callerAuthPresent = append(a.callerAuthPresent, metadataValuePresent(ctx, "authorization"))
	a.mu.Unlock()

	attributes := a.attributesForUsername(request.GetUsername())

	return &authv1.AuthResponse{
		Ok:           true,
		Decision:     authv1.AuthDecision_AUTH_DECISION_OK,
		Session:      "pop3-grpc-session",
		AccountField: "account",
		Attributes:   attributes,
	}, nil
}

// ExpectRequest waits until a matching gRPC auth request reaches the fixture.
func (a *fakePOP3GRPCAuthority) ExpectRequest(t *testing.T, protocol string, method string) *authv1.AuthRequest {
	t.Helper()

	for range 50 {
		a.mu.Lock()
		for index, request := range a.requests {
			hasCallerAuth := false
			if index < len(a.callerAuthPresent) {
				hasCallerAuth = a.callerAuthPresent[index]
			}
			if strings.EqualFold(request.GetProtocol(), protocol) && strings.EqualFold(request.GetMethod(), method) {
				a.mu.Unlock()
				if !hasCallerAuth {
					t.Fatal("gRPC authority request lacked caller authorization metadata")
				}

				return request
			}
		}
		a.mu.Unlock()
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("fake POP3 gRPC authority did not receive protocol=%s method=%s request", protocol, method)

	return nil
}

// ExpectMetadata waits until a selected safe gRPC metadata key reaches the authority.
func (a *fakePOP3GRPCAuthority) ExpectMetadata(t *testing.T, key string, want string) {
	t.Helper()

	for range 50 {
		a.mu.Lock()
		for _, snapshot := range a.contextMetadata {
			if snapshot[key] == want {
				a.mu.Unlock()

				return
			}
		}
		a.mu.Unlock()

		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("fake POP3 gRPC authority did not receive expected metadata key %q", key)
}

// attributesForUsername returns deterministic account attributes for a gRPC auth request.
func (a *fakePOP3GRPCAuthority) attributesForUsername(username string) map[string]*commonv1.AttributeValues {
	identity := a.identities[username]
	if identity == nil {
		identity = map[string][]string{
			"account":   {username},
			"tenant":    {e2eTenant},
			"mailShard": {e2eShardTag},
		}
	}

	return map[string]*commonv1.AttributeValues{
		"account":   {Values: identity["account"]},
		"tenant":    {Values: identity["tenant"]},
		"mailShard": {Values: identity["mailShard"]},
	}
}

// safeGRPCAuthorityContextMetadata snapshots known non-credential listener context metadata only.
func safeGRPCAuthorityContextMetadata(ctx context.Context) map[string]string {
	values := map[string]string{}
	for _, key := range []string{e2eContextMetadata} {
		metadataValues := metadata.ValueFromIncomingContext(ctx, key)
		if len(metadataValues) > 0 {
			values[key] = metadataValues[0]
		}
	}

	return values
}

// metadataValuePresent reports whether a gRPC metadata key has any value.
func metadataValuePresent(ctx context.Context, key string) bool {
	values := metadata.ValueFromIncomingContext(ctx, key)

	return len(values) > 0
}
