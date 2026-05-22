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

//nolint:goconst // Repeated domain values keep routing fixtures readable.
package routing

import (
	"context"
	"reflect"
	"testing"
)

// TestAuthAttributeResolverSuccess verifies logical facts from auth attributes.
func TestAuthAttributeResolverSuccess(t *testing.T) {
	resolver := mustAuthAttributeResolver(t)

	result, err := resolver.Resolve(context.Background(), baseRoutingRequest())
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}

	if result.AccountKey != "user@example.org" {
		t.Fatalf("AccountKey = %q, want user@example.org", result.AccountKey)
	}

	if result.Tenant != "default" {
		t.Fatalf("Tenant = %q, want default", result.Tenant)
	}

	if result.ShardTag != "mailstore-a" {
		t.Fatalf("ShardTag = %q, want mailstore-a", result.ShardTag)
	}

	if result.RoutingSource != SourceAuthAttribute {
		t.Fatalf("RoutingSource = %q, want %q", result.RoutingSource, SourceAuthAttribute)
	}
}

// TestMissingShardAttributeFallsBackToHash verifies safe chain fallback.
func TestMissingShardAttributeFallsBackToHash(t *testing.T) {
	authResolver := mustAuthAttributeResolver(t)
	hashResolver := mustHashResolver(t, []string{"mailstore-a", "mailstore-b"})
	chain := mustChainResolver(t, authResolver, hashResolver)
	request := baseRoutingRequest()
	delete(request.AuthAttributes, "mailShard")

	result, err := chain.Resolve(context.Background(), request)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}

	if result.RoutingSource != SourceHash {
		t.Fatalf("RoutingSource = %q, want %q", result.RoutingSource, SourceHash)
	}

	if result.AccountKey != "user@example.org" || result.Tenant != "default" {
		t.Fatalf("fallback lost logical identity: %+v", result)
	}

	if result.ShardTag == "" {
		t.Fatal("fallback did not choose a shard tag")
	}
}

// TestMissingShardAttributeWithoutFallbackFailsClosed checks absent fallback behavior.
func TestMissingShardAttributeWithoutFallbackFailsClosed(t *testing.T) {
	request := baseRoutingRequest()
	delete(request.AuthAttributes, "mailShard")

	_, err := mustAuthAttributeResolver(t).Resolve(context.Background(), request)
	if !IsErrorKind(err, ErrorKindMissingFact) {
		t.Fatalf("Resolve error = %v, want missing fact", err)
	}
}

// TestMultipleSingularValuesFailClosed protects ambiguous routing facts.
func TestMultipleSingularValuesFailClosed(t *testing.T) {
	request := baseRoutingRequest()
	request.AuthAttributes["mailShard"] = []string{"mailstore-a", "mailstore-b"}

	_, err := mustAuthAttributeResolver(t).Resolve(context.Background(), request)
	if !IsErrorKind(err, ErrorKindAmbiguousFact) {
		t.Fatalf("Resolve error = %v, want ambiguous fact", err)
	}
}

// TestHashFallbackDeterministic verifies rendezvous hashing is stable.
func TestHashFallbackDeterministic(t *testing.T) {
	first := mustHashResolver(t, []string{"mailstore-b", "mailstore-a"})
	second := mustHashResolver(t, []string{"mailstore-a", "mailstore-b"})
	request := RoutingRequest{Tenant: "default", NormalizedAccount: "user@example.org"}

	firstResult, err := first.Resolve(context.Background(), request)
	if err != nil {
		t.Fatalf("first Resolve returned error: %v", err)
	}

	secondResult, err := second.Resolve(context.Background(), request)
	if err != nil {
		t.Fatalf("second Resolve returned error: %v", err)
	}

	if firstResult.ShardTag != secondResult.ShardTag {
		t.Fatalf("shard = %q and %q for same shard set", firstResult.ShardTag, secondResult.ShardTag)
	}

	if firstResult.RoutingGeneration != secondResult.RoutingGeneration {
		t.Fatalf("generation = %q and %q for same shard set", firstResult.RoutingGeneration, secondResult.RoutingGeneration)
	}

	changed := mustHashResolver(t, []string{"mailstore-a", "mailstore-b", "mailstore-c"})

	changedResult, err := changed.Resolve(context.Background(), request)
	if err != nil {
		t.Fatalf("changed Resolve returned error: %v", err)
	}

	if changedResult.RoutingGeneration == firstResult.RoutingGeneration {
		t.Fatalf("generation did not change after shard-set change: %q", changedResult.RoutingGeneration)
	}
}

// TestRoutingResultHasNoConcreteBackendIdentifier locks the routing/backend boundary.
func TestRoutingResultHasNoConcreteBackendIdentifier(t *testing.T) {
	resultType := reflect.TypeFor[RoutingResult]()

	if _, ok := resultType.FieldByName("BackendIdentifier"); ok {
		t.Fatal("RoutingResult must not expose concrete backend identifiers")
	}

	if _, ok := resultType.FieldByName("SelectedBackend"); ok {
		t.Fatal("RoutingResult must not expose selected backends")
	}
}

// TestSafeAttributesFiltering removes credential and high-cardinality attributes.
func TestSafeAttributesFiltering(t *testing.T) {
	request := baseRoutingRequest()
	request.AuthAttributes["password"] = []string{"secret"}
	request.AuthAttributes["session_id"] = []string{"session-1"}
	request.AuthAttributes["token"] = []string{"bearer"}
	request.AuthAttributes["username"] = []string{"user@example.org"}

	result, err := mustAuthAttributeResolver(t).Resolve(context.Background(), request)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}

	for _, forbidden := range []string{"password", "session_id", "token", "username"} {
		if _, ok := result.Attributes[forbidden]; ok {
			t.Fatalf("safe attributes contained forbidden key %q: %#v", forbidden, result.Attributes)
		}
	}

	if got := result.Attributes["mailShard"]; len(got) != 1 || got[0] != "mailstore-a" {
		t.Fatalf("mailShard safe attribute = %#v", got)
	}
}

// baseRoutingRequest creates a complete auth-attribute routing fixture.
func baseRoutingRequest() RoutingRequest {
	return RoutingRequest{
		Protocol:          "imap",
		ListenerName:      "imaps",
		ServiceName:       "imaps",
		BackendPool:       "imap-default",
		NormalizedAccount: "user@example.org",
		AuthAttributes: map[string][]string{
			"account":   {"user@example.org"},
			"mailShard": {"mailstore-a"},
			"tenant":    {"default"},
		},
	}
}

// mustAuthAttributeResolver creates the standard test auth-attribute resolver.
func mustAuthAttributeResolver(t *testing.T) *AuthAttributeResolver {
	t.Helper()

	resolver, err := NewAuthAttributeResolver(AuthAttributeResolverConfig{
		AccountKeyAttribute: "account",
		TenantAttribute:     "tenant",
		ShardTagAttribute:   "mailShard",
		Sticky:              true,
	})
	if err != nil {
		t.Fatalf("NewAuthAttributeResolver: %v", err)
	}

	return resolver
}

// mustHashResolver creates a deterministic hash resolver for tests.
func mustHashResolver(t *testing.T, shards []string) *HashResolver {
	t.Helper()

	resolver, err := NewHashResolver(HashResolverConfig{ShardTags: shards, Sticky: true})
	if err != nil {
		t.Fatalf("NewHashResolver: %v", err)
	}

	return resolver
}

// mustChainResolver creates an ordered resolver chain for tests.
func mustChainResolver(t *testing.T, resolvers ...RoutingResolver) *ChainResolver {
	t.Helper()

	chain, err := NewChainResolver(resolvers...)
	if err != nil {
		t.Fatalf("NewChainResolver: %v", err)
	}

	return chain
}
