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

package sieve

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/routing"
)

const (
	bearerRouteShardAttr = "mailShard"
	bearerRouteHashShard = "shard-hash"
	bearerRouteDirShard  = "shard-directory"
	bearerRouteTenant    = "default"

	bearerRouteTempfailLine = "NO (TRYLATER) \"Authentication service temporarily unavailable\"\r\n"
	bearerRouteRejectedLine = "NO (AUTHENTICATIONFAILED) \"Authentication failed\"\r\n"
)

// bearerRouteLookuper returns one configured identity lookup outcome and records requests.
type bearerRouteLookuper struct {
	mu       sync.Mutex
	result   nauthilus.AuthResult
	err      error
	requests []nauthilus.IdentityLookupRequest
}

// LookupIdentity records the lookup and returns the configured outcome.
func (l *bearerRouteLookuper) LookupIdentity(_ context.Context, request nauthilus.IdentityLookupRequest) (nauthilus.AuthResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.requests = append(l.requests, request)

	return l.result, l.err
}

// calls returns the recorded lookup requests.
func (l *bearerRouteLookuper) calls() []nauthilus.IdentityLookupRequest {
	l.mu.Lock()
	defer l.mu.Unlock()

	return append([]nauthilus.IdentityLookupRequest(nil), l.requests...)
}

// bearerRouteRecorder records production chain results so tests can compare them with the hash choice.
type bearerRouteRecorder struct {
	mu      sync.Mutex
	next    routing.RoutingResolver
	results []routing.RoutingResult
}

// Resolve delegates to the production chain and records the resolved route.
func (r *bearerRouteRecorder) Resolve(ctx context.Context, request routing.RoutingRequest) (routing.RoutingResult, error) {
	result, err := r.next.Resolve(ctx, request)

	r.mu.Lock()
	defer r.mu.Unlock()

	r.results = append(r.results, result)

	return result, err
}

// resolved returns the recorded routing results.
func (r *bearerRouteRecorder) resolved() []routing.RoutingResult {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]routing.RoutingResult(nil), r.results...)
}

// bearerRouteChain builds the production routing chain: shard attribute first, rendezvous hash second.
func bearerRouteChain(t *testing.T) (routing.RoutingResolver, *routing.HashResolver) {
	t.Helper()

	authResolver, err := routing.NewAuthAttributeResolver(routing.AuthAttributeResolverConfig{ShardTagAttribute: bearerRouteShardAttr, Sticky: true})
	if err != nil {
		t.Fatalf("NewAuthAttributeResolver: %v", err)
	}

	hashResolver, err := routing.NewHashResolver(routing.HashResolverConfig{ShardTags: []string{bearerRouteHashShard, bearerRouteDirShard}, Sticky: true})
	if err != nil {
		t.Fatalf("NewHashResolver: %v", err)
	}

	chain, err := routing.NewChainResolver(authResolver, hashResolver)
	if err != nil {
		t.Fatalf("NewChainResolver: %v", err)
	}

	return chain, hashResolver
}

// hashRoutedAccount returns an account the hash fallback would place on bearerRouteHashShard.
func hashRoutedAccount(t *testing.T, hash *routing.HashResolver) string {
	t.Helper()

	for index := range 256 {
		account := fmt.Sprintf("bearer-%d@example.test", index)

		result, err := hash.Resolve(context.Background(), routing.RoutingRequest{Tenant: bearerRouteTenant, NormalizedAccount: account})
		if err == nil && result.ShardTag == bearerRouteHashShard {
			return account
		}
	}

	t.Fatal("no account hashes onto the hash shard")

	return ""
}

// bearerRouteSession starts a SIEVE session whose bearer path uses the production identity binding.
func bearerRouteSession(t *testing.T, account string, lookuper *bearerRouteLookuper) (*sieveHarness, *bearerRouteRecorder) {
	t.Helper()

	chain, _ := bearerRouteChain(t)
	router := &bearerRouteRecorder{next: chain}

	binder, err := nauthilus.BindBearerIdentity(&recordingBearerIntrospector{result: nauthilus.AuthResult{
		Decision: nauthilus.DecisionAuthenticated,
		Account:  account,
	}}, nauthilus.BearerIdentityConfig{Lookuper: lookuper, ShardTagAttribute: bearerRouteShardAttr})
	if err != nil {
		t.Fatalf("BindBearerIdentity: %v", err)
	}

	config := testPlacementSessionConfig(TLSModeImplicit, &recordingAuthenticator{}, router, nil)
	config.BearerIntrospector = binder

	harness := startSieveHarness(t, config)
	harness.expectGreeting(t,
		testGreetingImplementation,
		testGreetingVersion,
		testGreetingSieve,
		testGreetingLanguage,
		testGreetingSASLTLS,
		testGreetingOK,
	)
	harness.write(t, "AUTHENTICATE \"XOAUTH2\" \""+xoauth2Payload(account, "xoauth-token")+"\"\r\n")

	return harness, router
}

// TestBearerLoginRoutesOnIdentityLookupShard proves the lookup shard wins over the hash choice.
func TestBearerLoginRoutesOnIdentityLookupShard(t *testing.T) {
	_, hash := bearerRouteChain(t)
	account := hashRoutedAccount(t, hash)
	lookuper := &bearerRouteLookuper{result: nauthilus.AuthResult{
		Decision:   nauthilus.DecisionAuthenticated,
		Account:    account,
		Attributes: map[string][]string{bearerRouteShardAttr: {bearerRouteDirShard}},
	}}

	harness, router := bearerRouteSession(t, account, lookuper)
	_ = harness.readLine(t)

	lookups := lookuper.calls()
	if len(lookups) != 1 || lookups[0].Context.Username != account || lookups[0].Context.Protocol != protocolSieve {
		t.Fatalf("identity lookups = %+v, want one SIEVE lookup for the token account", lookups)
	}

	results := router.resolved()
	if len(results) != 1 {
		t.Fatalf("routing calls = %d, want 1", len(results))
	}

	if results[0].ShardTag != bearerRouteDirShard || results[0].RoutingSource != routing.SourceAuthAttribute {
		t.Fatalf("route = %s via %s, want %s via auth attribute", results[0].ShardTag, results[0].RoutingSource, bearerRouteDirShard)
	}
}

// TestBearerLoginIdentityFailuresNeverReachRouting proves lookup failures tempfail or refuse without hashing.
func TestBearerLoginIdentityFailuresNeverReachRouting(t *testing.T) {
	tests := []struct {
		name     string
		lookuper *bearerRouteLookuper
		want     string
	}{
		{
			name:     "lookup transport failure",
			lookuper: &bearerRouteLookuper{err: errors.New("authority unavailable")},
			want:     bearerRouteTempfailLine,
		},
		{
			name:     "lookup tempfail",
			lookuper: &bearerRouteLookuper{result: nauthilus.AuthResult{Decision: nauthilus.DecisionTemporaryFailure}},
			want:     bearerRouteTempfailLine,
		},
		{
			name: "account mismatch",
			lookuper: &bearerRouteLookuper{result: nauthilus.AuthResult{
				Decision:   nauthilus.DecisionAuthenticated,
				Account:    "someone-else@example.test",
				Attributes: map[string][]string{bearerRouteShardAttr: {bearerRouteDirShard}},
			}},
			want: bearerRouteRejectedLine,
		},
		{
			name:     "identity rejected",
			lookuper: &bearerRouteLookuper{result: nauthilus.AuthResult{Decision: nauthilus.DecisionRejected, StatusMessage: "unknown user"}},
			want:     bearerRouteRejectedLine,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness, router := bearerRouteSession(t, "bearer-user@example.test", test.lookuper)
			harness.expectLine(t, test.want)

			if calls := len(router.resolved()); calls != 0 {
				t.Fatalf("routing calls = %d, want none after a failed identity lookup", calls)
			}
		})
	}
}
