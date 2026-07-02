// Copyright (C) 2026 Christian Rößner
//
// SPDX-License-Identifier: AGPL-3.0-only
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, version 3 of the License.

//nolint:funlen,goconst,gocyclo,wsl_v5 // The public repair proof keeps REST, CLI and socket evidence in one scenario.
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/rest/generated"
	"github.com/croessner/nauthilus-director/internal/state"
	"github.com/redis/go-redis/v9"
)

const (
	e2eRuntimeRepairExpiredSession = "runtime-repair-expired-session"
	e2eRuntimeRepairExpiredUser    = "runtime-repair-expired@example.test"
	e2eRuntimeRepairObsoleteShard  = "mailstack-obsolete"
)

// TestServerBinaryRuntimeRepairPublicWorkflow proves explicit runtime repair through public REST and CLI boundaries.
func TestServerBinaryRuntimeRepairPublicWorkflow(t *testing.T) {
	binary := e2eServerBinary(t)
	ctl := buildDirectorctl(t)
	redisFixture := startValkeySessionStore(t)
	processStore := processRuntimeStore(t, redisFixture.addr)
	authority := startFakeHTTPAuthority(t, map[string][]string{
		"account":   {e2eAccount},
		"tenant":    {e2eTenant},
		"mailShard": {e2eShardTag},
	})
	fakeBackend := startFakeIMAPBackend(t, fakeBackendOptions{})
	controlCertPath, controlKeyPath, _ := writeTestCertificate(t)
	directorAddress := loopbackAddress(t)
	controlAddress := loopbackAddress(t)
	controlURL := "https://" + controlAddress
	controlClient := controlTLSClient(t, controlCertPath)
	controlArgs := func(args ...string) []string {
		return append([]string{"--tls-ca-file", controlCertPath}, args...)
	}
	configPath := writeProcessConfig(t, processConfigOptions{
		RedisAddress:    redisFixture.addr,
		AuthorityURL:    authority.URL(),
		DirectorAddress: directorAddress,
		ControlAddress:  controlAddress,
		ControlEnabled:  true,
		ControlTLS: config.ControlTLSConfig{
			Enabled:       true,
			Cert:          controlCertPath,
			Key:           config.Secret(controlKeyPath),
			MinTLSVersion: "TLS1.2",
		},
		BackendAddress: fakeBackend.Address(),
		BackendTLS: config.BackendTLSConfig{
			Mode:          "plaintext",
			MinTLSVersion: "TLS1.2",
		},
		BackendAuth:    masterUserBackendAuth(),
		ReaperInterval: time.Hour,
	})
	process := startDirectorProcess(t, binary, configPath)

	waitForDirectorGreeting(t, directorAddress, process)
	waitForControlReadyWithClient(t, controlURL, controlClient, process)
	waitForRESTSessionCountWithClient(t, controlClient, controlURL, 0)
	assertRuntimeRepairSummary(t, getRuntimeSummaryWithClient(t, controlClient, controlURL), 0, 0)

	baselineSignature := runtimeRepairSummarySignature(getRuntimeSummaryWithClient(t, controlClient, controlURL))
	beforeAuthorityRequests := authority.RequestCount()
	beforeBackendConnections := fakeBackend.ConnectionCount()
	lookupRouteWithClient(t, controlClient, controlURL, e2eAccount, true)
	if authority.RequestCount() != beforeAuthorityRequests {
		t.Fatal("route lookup called the fake Nauthilus authority before repair")
	}
	if fakeBackend.ConnectionCount() != beforeBackendConnections {
		t.Fatal("route lookup opened a backend socket before repair")
	}
	if signature := runtimeRepairSummarySignature(getRuntimeSummaryWithClient(t, controlClient, controlURL)); signature != baselineSignature {
		t.Fatalf("route lookup changed clean runtime summary %q, want %q", signature, baselineSignature)
	}

	activeClient, activeReader := loginProcessIMAP(t, directorAddress, e2eAccount)
	defer func() { _ = activeClient.Close() }()
	expectBackendProxy(t, activeClient, activeReader, fakeBackend, "A002")
	activeSessions := waitForRESTSessionCountWithClient(t, controlClient, controlURL, 1)
	activeSessionID := activeSessions[0].SessionID
	assertRuntimeRepairSummary(t, getRuntimeSummaryWithClient(t, controlClient, controlURL), 1, 0)

	seedExpiredRuntimeRepairSession(t, processStore)
	seedRuntimeAggregateOnlyDrift(t, redisFixture.addr, e2eRuntimeRepairObsoleteShard, "runtime-repair-obsolete-a", "runtime-repair-obsolete-b")
	waitForRESTSessionCountWithClient(t, controlClient, controlURL, 2)
	assertRuntimeRepairSummary(t, getRuntimeSummaryWithClient(t, controlClient, controlURL), 4, 2)

	preRepairSignature := runtimeRepairSummarySignature(getRuntimeSummaryWithClient(t, controlClient, controlURL))
	preRepairSessions := runDirectorctl(t, ctl, controlURL, controlArgs("sessions", "list", "--all")...)
	preRepairUsers := runDirectorctl(t, ctl, controlURL, controlArgs("users", "list", "--all")...)
	beforeAuthorityRequests = authority.RequestCount()
	beforeBackendConnections = fakeBackend.ConnectionCount()
	lookupRouteWithClient(t, controlClient, controlURL, e2eAccount, true)
	if authority.RequestCount() != beforeAuthorityRequests {
		t.Fatal("route lookup called the fake Nauthilus authority while repairable state existed")
	}
	if fakeBackend.ConnectionCount() != beforeBackendConnections {
		t.Fatal("route lookup opened a backend socket while repairable state existed")
	}
	if signature := runtimeRepairSummarySignature(getRuntimeSummaryWithClient(t, controlClient, controlURL)); signature != preRepairSignature {
		t.Fatalf("route lookup repaired or changed runtime summary %q, want %q", signature, preRepairSignature)
	}
	if sessions := runDirectorctl(t, ctl, controlURL, controlArgs("sessions", "list", "--all")...); sessions != preRepairSessions {
		t.Fatalf("route lookup changed public sessions list\nbefore: %s\nafter: %s", preRepairSessions, sessions)
	}
	if users := runDirectorctl(t, ctl, controlURL, controlArgs("users", "list", "--all")...); users != preRepairUsers {
		t.Fatalf("route lookup changed public users list\nbefore: %s\nafter: %s", preRepairUsers, users)
	}

	reapPreview := runtimeReapREST(t, controlClient, controlURL, true)
	if reapPreview.Status != generated.RuntimeReapResponseStatusPreview {
		t.Fatalf("runtime reap dry-run status = %q, want preview", reapPreview.Status)
	}
	reapOutput := runDirectorctl(
		t,
		ctl,
		controlURL,
		controlArgs("runtime", "reap", "--reason", "public e2e expired lease repair", "--limit", "10", "--max-pass-duration", "5s")...,
	)
	assertCLIOutputFields(t, reapOutput, "status=reaped", "expired_sessions=1", "aggregate_markers_removed=1")
	postReapSessions := waitForRESTSessionCountWithClient(t, controlClient, controlURL, 1)
	if postReapSessions[0].SessionID != activeSessionID {
		t.Fatalf("runtime reap removed active holder %q, want %q", postReapSessions[0].SessionID, activeSessionID)
	}
	runDirectorctl(t, ctl, controlURL, controlArgs("users", "affinity", "clear", e2eRuntimeRepairExpiredUser, "--reason", "public e2e inactive repair affinity clear")...)

	reconcilePreview := runtimeAggregateReconcileREST(t, controlClient, controlURL, true)
	if reconcilePreview.Status != generated.RuntimeAggregateReconcileResponseStatusPreview || reconcilePreview.StaleMarkersRemoved != 2 {
		t.Fatalf("runtime reconcile dry-run = %#v, want preview with two stale markers", reconcilePreview)
	}
	reconcileOutput := runDirectorctl(
		t,
		ctl,
		controlURL,
		controlArgs("runtime", "reconcile", "aggregates", "--reason", "public e2e aggregate drift repair", "--scope", "active_sessions", "--limit", "10", "--max-pass-duration", "5s")...,
	)
	assertCLIOutputFields(t, reconcileOutput, "status=reconciled", "stale_markers_removed=2", "authoritative_conflicts=0")

	finalSessions := waitForRESTSessionCountWithClient(t, controlClient, controlURL, 1)
	if finalSessions[0].SessionID != activeSessionID {
		t.Fatalf("aggregate reconcile removed active holder %q, want %q", finalSessions[0].SessionID, activeSessionID)
	}
	finalSummary := getRuntimeSummaryWithClient(t, controlClient, controlURL)
	assertRuntimeRepairSummary(t, finalSummary, 1, 0)
	assertRuntimeRepairOutputClean(t, runDirectorctl(t, ctl, controlURL, controlArgs("sessions", "list", "--all")...))
	assertRuntimeRepairOutputClean(t, runDirectorctl(t, ctl, controlURL, controlArgs("users", "list", "--all")...))
	assertCLIOutputFields(t, runDirectorctl(t, ctl, controlURL, controlArgs("runtime", "summary")...), "routing_authority=false")

	finalSignature := runtimeRepairSummarySignature(finalSummary)
	beforeAuthorityRequests = authority.RequestCount()
	beforeBackendConnections = fakeBackend.ConnectionCount()
	lookupRouteWithClient(t, controlClient, controlURL, e2eAccount, true)
	if authority.RequestCount() != beforeAuthorityRequests {
		t.Fatal("route lookup called the fake Nauthilus authority after repair")
	}
	if fakeBackend.ConnectionCount() != beforeBackendConnections {
		t.Fatal("route lookup opened a backend socket after repair")
	}
	if signature := runtimeRepairSummarySignature(getRuntimeSummaryWithClient(t, controlClient, controlURL)); signature != finalSignature {
		t.Fatalf("route lookup changed final runtime summary %q, want %q", signature, finalSignature)
	}
	assertNoSecretText(t, process.output.String())
	assertOutputOmits(t,
		process.output.String(),
		e2eAccount,
		e2eRuntimeRepairExpiredUser,
		"public e2e expired lease repair",
		"public e2e inactive repair affinity clear",
		"public e2e aggregate drift repair",
	)
}

// seedExpiredRuntimeRepairSession creates one deterministic due lease for public reap proof.
func seedExpiredRuntimeRepairSession(t *testing.T, store *state.RedisSessionStore) {
	t.Helper()

	key := state.AffinityKey{Tenant: e2eTenant, AccountKey: e2eRuntimeRepairExpiredUser}
	if _, err := store.OpenSession(context.Background(), state.SessionRecord{
		ID:                 e2eRuntimeRepairExpiredSession,
		Key:                key,
		HolderKind:         state.HolderKindSession,
		Protocol:           e2eProtocol,
		ListenerName:       e2eListenerName,
		ServiceName:        e2eService,
		ShardTag:           e2eShardTag,
		DirectorInstanceID: "e2e-runtime-repair-fixture",
		LeaseTTL:           25 * time.Millisecond,
		IdleGrace:          5 * time.Second,
	}); err != nil {
		t.Fatalf("seed expired OpenSession: %v", err)
	}
	if _, err := store.AttachSelectedBackend(context.Background(), state.SessionBackendAttachment{
		Key:               key,
		SessionID:         e2eRuntimeRepairExpiredSession,
		BackendIdentifier: e2eBackendAID,
		ReservationID:     "runtime-repair-expired-reservation",
		MaxConnections:    100,
	}); err != nil {
		t.Fatalf("seed expired AttachSelectedBackend: %v", err)
	}

	time.Sleep(75 * time.Millisecond)
}

// seedRuntimeAggregateOnlyDrift writes repairable marker drift without authoritative sessions.
func seedRuntimeAggregateOnlyDrift(t *testing.T, redisAddress string, shard string, sessionIDs ...string) {
	t.Helper()

	client := redis.NewClient(&redis.Options{Addr: redisAddress, Protocol: 2})
	t.Cleanup(func() { _ = client.Close() })
	builder, err := state.NewKeyBuilder(state.KeyBuilderOptions{Prefix: e2eProcessKeyPrefix, SchemaVersion: 1})
	if err != nil {
		t.Fatalf("NewKeyBuilder: %v", err)
	}

	for _, sessionID := range sessionIDs {
		dimensions := map[string]string{
			"backend":   e2eBackendAID,
			"listener":  e2eListenerName,
			"protocol":  e2eProtocol,
			"service":   e2eService,
			"shard_tag": shard,
		}
		encoded, err := json.Marshal(dimensions)
		if err != nil {
			t.Fatalf("marshal aggregate marker: %v", err)
		}
		if err := client.HSet(context.Background(), builder.AggregateSessionMarkerKey(), sessionID, string(encoded)).Err(); err != nil {
			t.Fatalf("seed aggregate marker %s: %v", sessionID, err)
		}
		for _, dimension := range []string{"backend", "listener", "protocol", "service", "shard_tag"} {
			if err := client.HIncrBy(context.Background(), builder.AggregateActiveDimensionKey(dimension), dimensions[dimension], 1).Err(); err != nil {
				t.Fatalf("seed aggregate counter %s: %v", dimension, err)
			}
		}
	}
}

// runtimeReapREST calls the generated runtime reap endpoint through the public control listener.
func runtimeReapREST(t *testing.T, client *http.Client, baseURL string, dryRun bool) generated.RuntimeReapResponse {
	t.Helper()

	var response generated.RuntimeReapResponse
	requestJSONWithClient(t, client, http.MethodPost, baseURL+"/api/v1/runtime/reap", generated.RuntimeReapRequest{
		DryRun:          &dryRun,
		Limit:           10,
		MaxPassDuration: "5s",
		Reason:          "public e2e runtime reap rest",
	}, http.StatusOK, &response)

	return response
}

// runtimeAggregateReconcileREST calls the generated aggregate reconcile endpoint through public REST.
func runtimeAggregateReconcileREST(
	t *testing.T,
	client *http.Client,
	baseURL string,
	dryRun bool,
) generated.RuntimeAggregateReconcileResponse {
	t.Helper()

	var response generated.RuntimeAggregateReconcileResponse
	requestJSONWithClient(t, client, http.MethodPost, baseURL+"/api/v1/runtime/reconcile/aggregates", generated.RuntimeAggregateReconcileRequest{
		DryRun:          &dryRun,
		Limit:           10,
		MaxPassDuration: "5s",
		Reason:          "public e2e aggregate reconcile rest",
		Scope:           generated.ActiveSessions,
	}, http.StatusOK, &response)

	return response
}

// assertRuntimeRepairSummary verifies the public summary counts used by the repair proof.
func assertRuntimeRepairSummary(t *testing.T, summary generated.RuntimeSummaryResponse, activeTotal int, obsoleteShard int) {
	t.Helper()

	if summary.RoutingAuthority {
		t.Fatal("runtime summary claimed routing authority")
	}
	if summary.ActiveSessions.Total.Count != activeTotal {
		t.Fatalf("runtime summary active total = %d, want %d", summary.ActiveSessions.Total.Count, activeTotal)
	}
	if got := runtimeSummaryShardCount(summary, e2eRuntimeRepairObsoleteShard); got != obsoleteShard {
		t.Fatalf("runtime summary obsolete shard count = %d, want %d", got, obsoleteShard)
	}
}

// assertRuntimeRepairOutputClean verifies stale repair fixtures are absent from public list output.
func assertRuntimeRepairOutputClean(t *testing.T, output string) {
	t.Helper()

	assertOutputOmits(t, output, e2eRuntimeRepairExpiredSession, e2eRuntimeRepairExpiredUser, e2eRuntimeRepairObsoleteShard)
}

// runtimeSummaryShardCount returns one shard-tag aggregate from the public summary.
func runtimeSummaryShardCount(summary generated.RuntimeSummaryResponse, shard string) int {
	for _, entry := range summary.ActiveSessions.ByShardTag {
		if entry.Value == shard {
			return entry.Count
		}
	}

	return 0
}

// runtimeRepairSummarySignature creates a stable public summary signature for route-lookup mutation checks.
func runtimeRepairSummarySignature(summary generated.RuntimeSummaryResponse) string {
	parts := []string{
		fmt.Sprintf("active.total=%d", summary.ActiveSessions.Total.Count),
		fmt.Sprintf("idle=%d", summary.IdleAffinities.Count),
		fmt.Sprintf("obsolete=%d", runtimeSummaryShardCount(summary, e2eRuntimeRepairObsoleteShard)),
	}
	for _, entry := range summary.ActiveSessions.ByShardTag {
		parts = append(parts, fmt.Sprintf("shard=%s:%d", entry.Value, entry.Count))
	}
	for _, capacity := range summary.BackendCapacity {
		parts = append(parts, fmt.Sprintf("backend=%s active=%d reserved=%d", capacity.Backend, capacity.ActiveSessions.Count, capacity.ReservedSessions.Count))
	}

	return strings.Join(parts, "|")
}
