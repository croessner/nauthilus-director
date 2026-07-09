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

//nolint:goconst // App wiring tests repeat protocol literals to show dispatch coverage.
package app

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/listener"
	"github.com/croessner/nauthilus-director/internal/protocol/pop3"
	"github.com/croessner/nauthilus-director/internal/protocol/sieve"
	"github.com/croessner/nauthilus-director/internal/routing"
)

// TestRoutingResolverUsesConfiguredAuthAttributeNames verifies tenant and shard facts are not hard-coded.
func TestRoutingResolverUsesConfiguredAuthAttributeNames(t *testing.T) {
	const (
		configuredTenantAttribute = "organization"
		configuredShardAttribute  = "mailboxShard"
		expectedTenant            = "blue"
		expectedShardTag          = "mailstore-a"
		expectedAccountKey        = "user@example.test"
		requestTenant             = "default"
	)

	cfg := config.DefaultConfig()
	cfg.Director.Routing.AuthAttributes = config.RoutingAuthAttributesConfig{
		Tenant:   configuredTenantAttribute,
		ShardTag: configuredShardAttribute,
	}

	registry, err := backend.NewStaticRegistry(cfg.Director)
	if err != nil {
		t.Fatalf("NewStaticRegistry returned error: %v", err)
	}

	resolver, err := routingResolver(cfg.Normalize(), registry)
	if err != nil {
		t.Fatalf("routingResolver returned error: %v", err)
	}

	result, err := resolver.Resolve(context.Background(), routing.RoutingRequest{
		Tenant:            requestTenant,
		Protocol:          protocolIMAP,
		ListenerName:      protocolIMAP,
		ServiceName:       protocolIMAP,
		BackendPool:       "imap-default",
		NormalizedAccount: expectedAccountKey,
		AuthAttributes: map[string][]string{
			configuredTenantAttribute: {expectedTenant},
			configuredShardAttribute:  {expectedShardTag},
			"mailShard":               {"mailstore-b"},
		},
	})
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}

	if result.Tenant != expectedTenant || result.ShardTag != expectedShardTag || result.AccountKey != expectedAccountKey {
		t.Fatalf("routing result = %#v, want configured tenant/shard attributes and account_field-derived account", result)
	}
}

// TestSessionHandlerFactoryDispatchesSieve verifies the app path recognizes ManageSieve listeners.
func TestSessionHandlerFactoryDispatchesSieve(t *testing.T) {
	factory := sessionHandlerFactory(nil, nil, nil, nil, nil, 0, nil, nil, "test-version")
	handler := factory(listener.SessionOptions{
		ListenerName: "sieve",
		Config:       config.DefaultConfig().Director.Listeners["sieve"],
	})

	sieveHandler, ok := handler.(*sieve.Handler)
	if !ok {
		t.Fatalf("handler type = %T, want Sieve handler", handler)
	}

	capabilities := sieveHandler.Capabilities()
	if capabilities.ProtocolVersion != sieve.ProtocolVersionRFC5804 {
		t.Fatalf("Sieve protocol version = %q, want %q", capabilities.ProtocolVersion, sieve.ProtocolVersionRFC5804)
	}

	if capabilities.Implementation != "nauthilus-director test-version" {
		t.Fatalf("Sieve implementation = %q, want build-version implementation", capabilities.Implementation)
	}

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	done := make(chan error, 1)
	go func() {
		done <- handler.Serve(context.Background(), server)
	}()

	reader := bufio.NewReader(client)

	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read Sieve greeting: %v", err)
	}

	if line != "\"IMPLEMENTATION\" \"nauthilus-director test-version\"\r\n" {
		t.Fatalf("Sieve greeting line = %q, want implementation capability", line)
	}

	for line != "OK\r\n" {
		line, err = reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read Sieve greeting terminator: %v", err)
		}
	}

	_ = client.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Sieve handler error = %v, want clean close", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Sieve handler did not stop after client close")
	}
}

// TestSessionHandlerFactoryPassesSieveGreetingPolicy verifies listener greeting config reaches Sieve handlers.
func TestSessionHandlerFactoryPassesSieveGreetingPolicy(t *testing.T) {
	cfg := config.DefaultConfig().Normalize()
	listenerConfig := cfg.Director.Listeners["sieve"]
	displayName := "Norbert"
	softwareVersion := "suppress"
	listenerConfig.Sieve.Greeting = config.ListenerGreetingConfig{
		DisplayName:     &displayName,
		SoftwareVersion: &softwareVersion,
	}

	factory := sessionHandlerFactory(nil, nil, nil, nil, nil, 0, nil, nil, "test-version")
	handler := factory(listener.SessionOptions{
		ListenerName: "sieve",
		Config:       listenerConfig,
	})

	sieveHandler, ok := handler.(*sieve.Handler)
	if !ok {
		t.Fatalf("handler type = %T, want Sieve handler", handler)
	}

	capabilities := sieveHandler.Capabilities()
	if capabilities.Implementation != "Norbert" {
		t.Fatalf("Sieve implementation = %q, want custom display identity without version", capabilities.Implementation)
	}

	if capabilities.ProtocolVersion != sieve.ProtocolVersionRFC5804 {
		t.Fatalf("Sieve protocol version = %q, want %q", capabilities.ProtocolVersion, sieve.ProtocolVersionRFC5804)
	}

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	done := make(chan error, 1)
	go func() {
		done <- handler.Serve(context.Background(), server)
	}()

	reader := bufio.NewReader(client)

	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read Sieve greeting: %v", err)
	}

	if line != "\"IMPLEMENTATION\" \"Norbert\"\r\n" {
		t.Fatalf("Sieve greeting line = %q, want configured display identity", line)
	}

	_ = client.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Sieve handler error = %v, want clean close", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Sieve handler did not stop after client close")
	}
}

// TestSessionHandlerFactoryPassesGreetingPolicyToFrontendHandlers verifies app wiring for greeting policies.
func TestSessionHandlerFactoryPassesGreetingPolicyToFrontendHandlers(t *testing.T) {
	tests := []struct {
		name         string
		listenerName string
		wantGreeting string
		update       func(*config.ListenerConfig, config.ListenerGreetingConfig)
	}{
		{
			name:         "imap",
			listenerName: "imap",
			wantGreeting: "* OK Norbert test-version IMAP session ready\r\n",
			update: func(listenerConfig *config.ListenerConfig, greetingConfig config.ListenerGreetingConfig) {
				listenerConfig.IMAP.Greeting = greetingConfig
			},
		},
		{
			name:         "lmtp",
			listenerName: "lmtp",
			wantGreeting: "220 2.0.0 Norbert test-version LMTP ready\r\n",
			update: func(listenerConfig *config.ListenerConfig, greetingConfig config.ListenerGreetingConfig) {
				listenerConfig.LMTP.Greeting = greetingConfig
			},
		},
		{
			name:         "pop3",
			listenerName: "pop3",
			wantGreeting: "+OK Norbert test-version POP3 ready\r\n",
			update: func(listenerConfig *config.ListenerConfig, greetingConfig config.ListenerGreetingConfig) {
				listenerConfig.POP3.Greeting = greetingConfig
			},
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := config.DefaultConfig().Normalize()
			listenerConfig := cfg.Director.Listeners[testCase.listenerName]
			displayName := "Norbert"
			softwareVersion := "include"
			testCase.update(&listenerConfig, config.ListenerGreetingConfig{
				DisplayName:     &displayName,
				SoftwareVersion: &softwareVersion,
			})

			factory := sessionHandlerFactory(nil, nil, nil, nil, nil, 0, nil, nil, "test-version")
			handler := factory(listener.SessionOptions{
				ListenerName: testCase.listenerName,
				Config:       listenerConfig,
			})

			if line := readHandlerGreeting(t, handler); line != testCase.wantGreeting {
				t.Fatalf("greeting = %q, want %q", line, testCase.wantGreeting)
			}
		})
	}
}

// TestControlTLSConfigRejectsRequiredClientCertWithoutCA keeps control mTLS gates fail-closed.
func TestControlTLSConfigRejectsRequiredClientCertWithoutCA(t *testing.T) {
	certPath, keyPath := writeAppTestCertificate(t)
	control := config.DefaultConfig().Runtime.Servers.Control
	control.TLS.Enabled = true
	control.TLS.Cert = certPath
	control.TLS.Key = config.Secret(keyPath)
	control.TLS.RequireClientCert = true
	control.TLS.ClientCA = ""

	_, err := controlTLSConfig(control)
	if err == nil {
		t.Fatal("controlTLSConfig accepted require_client_cert without client_ca")
	}

	if !strings.Contains(err.Error(), "client_ca is required when require_client_cert is true") {
		t.Fatalf("error = %q, want client CA requirement", err.Error())
	}
}

// TestSessionHandlerFactoryDispatchesPOP3 verifies the app path recognizes POP3 listeners.
func TestSessionHandlerFactoryDispatchesPOP3(t *testing.T) {
	factory := sessionHandlerFactory(nil, nil, nil, nil, nil, 0, nil, nil, "test-version")
	handler := factory(listener.SessionOptions{
		ListenerName: "pop3",
		Config:       config.DefaultConfig().Director.Listeners["pop3"],
	})

	pop3Handler, ok := handler.(*pop3.Handler)
	if !ok {
		t.Fatalf("handler type = %T, want POP3 handler", handler)
	}

	handlerConfig := pop3Handler.Config()
	if handlerConfig.ServiceName != "pop3" || handlerConfig.BackendPool != "pop3-default" || handlerConfig.TLSMode != "starttls" {
		t.Fatalf("POP3 handler config = %#v, want listener-derived service, pool and TLS mode", handlerConfig)
	}

	if len(handlerConfig.AuthMechanisms) != 3 {
		t.Fatalf("POP3 auth methods = %v, want default userpass and bearer methods", handlerConfig.AuthMechanisms)
	}
}

// readHandlerGreeting starts one handler over net.Pipe and returns its first wire line.
func readHandlerGreeting(t *testing.T, handler listener.SessionHandler) string {
	t.Helper()

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	done := make(chan error, 1)
	go func() {
		done <- handler.Serve(context.Background(), server)
	}()

	reader := bufio.NewReader(client)

	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	_ = client.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("handler error = %v, want clean close", err)
		}
	case <-time.After(time.Second):
		t.Fatal("handler did not stop after client close")
	}

	return line
}

// writeAppTestCertificate writes a temporary self-signed TLS certificate pair.
func writeAppTestCertificate(t *testing.T) (string, string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "control.test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"control.test"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "control.crt")
	keyPath := filepath.Join(dir, "control.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}

	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	return certPath, keyPath
}
