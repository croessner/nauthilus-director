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

package listener

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
)

const (
	testBearerAccount   = "bearer-user@example.test"
	testBearerShardAttr = "mailShard"
	testBearerShard     = "shard-lookup"
	testBearerClientIP  = "192.0.2.10"
	testBearerMechanism = "xoauth2"
)

// identityRecordingAuthority records no-auth lookups and returns one fixed identity.
type identityRecordingAuthority struct {
	noopAuthenticator

	mu      sync.Mutex
	lookups []nauthilus.IdentityLookupRequest
}

// activeBearerIntrospector returns an active token principal without directory routing facts.
type activeBearerIntrospector struct{}

// LookupIdentity records the request and returns the account with its shard attribute.
func (a *identityRecordingAuthority) LookupIdentity(_ context.Context, request nauthilus.IdentityLookupRequest) (nauthilus.AuthResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.lookups = append(a.lookups, request)

	return nauthilus.AuthResult{
		Decision:   nauthilus.DecisionAuthenticated,
		Account:    request.Context.Username,
		Attributes: map[string][]string{testBearerShardAttr: {testBearerShard}},
	}, nil
}

// recordedLookups returns a detached copy of the observed lookup requests.
func (a *identityRecordingAuthority) recordedLookups() []nauthilus.IdentityLookupRequest {
	a.mu.Lock()
	defer a.mu.Unlock()

	return append([]nauthilus.IdentityLookupRequest(nil), a.lookups...)
}

// Introspect returns an authenticated token principal that names only the account.
func (activeBearerIntrospector) Introspect(context.Context, nauthilus.BearerIntrospectionRequest) (nauthilus.AuthResult, error) {
	return nauthilus.AuthResult{Decision: nauthilus.DecisionAuthenticated, Account: testBearerAccount}, nil
}

// TestManagerRefusesMailboxBearerListenerWithoutIdentityLookup keeps bearer routing fail-closed at startup.
func TestManagerRefusesMailboxBearerListenerWithoutIdentityLookup(t *testing.T) {
	cfg := singleListenerConfig(t, testIMAPListener, tlsModeStartTLS)
	entry := cfg.Director.Listeners[testIMAPListener]
	entry.IMAP.AuthMechanisms = []string{"plain", testBearerMechanism}
	cfg.Director.Listeners[testIMAPListener] = entry

	_, err := newTestManagerWithConfig(
		cfg,
		WithNauthilusClientFactory(func(config.AuthorityConfig, nauthilus.ClientOptions) (nauthilus.Authenticator, error) {
			return noopAuthenticator{}, nil
		}),
	)
	if err == nil {
		t.Fatal("NewManagerWithConfig accepted bearer SASL without identity lookup")
	}

	if !strings.Contains(err.Error(), "sasl bearer identity lookup unavailable") {
		t.Fatalf("error = %q, want identity lookup failure", err.Error())
	}
}

// TestManagerBindsMailboxBearerLoginsToIdentityLookup proves IMAP, POP3 and ManageSieve bearer
// principals are resolved through the authority lookup before routing, while LMTP peer auth is not.
func TestManagerBindsMailboxBearerLoginsToIdentityLookup(t *testing.T) {
	tests := []struct {
		listener   string
		protocol   string
		configure  func(*config.ListenerConfig)
		wantLookup bool
	}{
		{
			listener:   testIMAPListener,
			protocol:   protocolIMAP,
			configure:  func(entry *config.ListenerConfig) { entry.IMAP.AuthMechanisms = []string{testBearerMechanism} },
			wantLookup: true,
		},
		{
			listener:   testPOP3Listener,
			protocol:   protocolPOP3,
			configure:  func(entry *config.ListenerConfig) { entry.POP3.AuthMechanisms = []string{"oauthbearer"} },
			wantLookup: true,
		},
		{
			listener:   testSieveListener,
			protocol:   protocolSIEVE,
			configure:  func(entry *config.ListenerConfig) { entry.Sieve.AuthMechanisms = []string{testBearerMechanism} },
			wantLookup: true,
		},
		{
			listener:  testLMTPListener,
			protocol:  protocolLMTP,
			configure: func(entry *config.ListenerConfig) { entry.LMTP.ClientAuth.Mechanisms = []string{testBearerMechanism} },
		},
	}

	for _, test := range tests {
		t.Run(test.protocol, func(t *testing.T) {
			cfg := singleListenerConfig(t, test.listener, tlsModeStartTLS)
			cfg.Director.Routing.AuthAttributes.ShardTag = testBearerShardAttr
			entry := cfg.Director.Listeners[test.listener]
			test.configure(&entry)
			cfg.Director.Listeners[test.listener] = entry

			authority := &identityRecordingAuthority{}
			options := bearerSessionOptions(t, cfg, authority)

			result, err := options.BearerIntrospector.Introspect(context.Background(), testBearerRequest(test.protocol))
			if err != nil {
				t.Fatalf("Introspect returned error: %v", err)
			}

			if !test.wantLookup {
				if lookups := authority.recordedLookups(); len(lookups) != 0 {
					t.Fatalf("%s bearer auth performed %d identity lookups, want none", test.protocol, len(lookups))
				}

				return
			}

			assertBoundBearerLookup(t, authority.recordedLookups(), test.protocol, result)
		})
	}
}

// testBearerRequest returns a bearer introspection request carrying listener client facts.
func testBearerRequest(protocol string) nauthilus.BearerIntrospectionRequest {
	return nauthilus.BearerIntrospectionRequest{
		Context:     nauthilus.RequestContext{ClientIP: testBearerClientIP, Protocol: protocol, Method: testBearerMechanism},
		Mechanism:   testBearerMechanism,
		Protocol:    protocol,
		BearerToken: nauthilus.NewSecret("token-sentinel"),
	}
}

// bearerSessionOptions starts a manager with an active introspector and returns the session options.
func bearerSessionOptions(t *testing.T, cfg config.Config, authority *identityRecordingAuthority) SessionOptions {
	t.Helper()

	optionsSeen := make(chan SessionOptions, 1)

	_, err := NewManagerWithConfig(
		cfg,
		WithBearerIntrospectorFactory(func(context.Context, config.AuthorityConfig) (nauthilus.BearerIntrospector, error) {
			return activeBearerIntrospector{}, nil
		}),
		WithNauthilusClientFactory(func(config.AuthorityConfig, nauthilus.ClientOptions) (nauthilus.Authenticator, error) {
			return authority, nil
		}),
		WithSessionHandlerFactory(func(options SessionOptions) SessionHandler {
			optionsSeen <- options

			return newRecordingHandler()
		}),
	)
	if err != nil {
		t.Fatalf("NewManagerWithConfig returned error: %v", err)
	}

	select {
	case options := <-optionsSeen:
		return options
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for session options")
	}

	return SessionOptions{}
}

// assertBoundBearerLookup verifies one lookup for the token account and the merged shard attribute.
func assertBoundBearerLookup(t *testing.T, lookups []nauthilus.IdentityLookupRequest, protocol string, result nauthilus.AuthResult) {
	t.Helper()

	if len(lookups) != 1 {
		t.Fatalf("identity lookups = %d, want 1", len(lookups))
	}

	lookup := lookups[0].Context
	if lookup.Username != testBearerAccount || lookup.Protocol != protocol ||
		lookup.Method != nauthilus.IdentityLookupMethod || lookup.ClientIP != testBearerClientIP {
		t.Fatalf("lookup context = user %q protocol %q method %q client %q, want token account with listener facts",
			lookup.Username, lookup.Protocol, lookup.Method, lookup.ClientIP)
	}

	if got := result.Attributes[testBearerShardAttr]; len(got) != 1 || got[0] != testBearerShard {
		t.Fatalf("bound shard attribute = %v, want lookup shard", got)
	}
}
