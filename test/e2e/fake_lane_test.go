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

//nolint:funlen,goconst,gocyclo,wsl_v5 // E2E fixtures keep the public socket transcript visible.
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/listener"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/protocol/imap"
	"github.com/croessner/nauthilus-director/internal/proxy"
	"github.com/croessner/nauthilus-director/internal/rest"
	"github.com/croessner/nauthilus-director/internal/rest/adapters"
	"github.com/croessner/nauthilus-director/internal/rest/generated"
	"github.com/croessner/nauthilus-director/internal/routing"
	runtimectl "github.com/croessner/nauthilus-director/internal/runtime"
	"github.com/croessner/nauthilus-director/internal/state"
	"github.com/redis/go-redis/v9"
)

const (
	e2eAccount       = "alice@example.test"
	e2eBackendAID    = "mailstore-a-imap"
	e2eBackendBID    = "mailstore-b-imap"
	e2eBackendPool   = "imap-default"
	e2eListenerName  = "imap"
	e2ePassword      = "e2e-secret-password"
	e2eProtocol      = "imap"
	e2eService       = "imap"
	e2eShardTagB     = "mailstore-b"
	e2eShardTag      = "mailstore-a"
	e2eTenant        = "default"
	e2eToken         = "e2e-bearer-token"
	fakeBackendReady = "* OK fake IMAP backend ready\r\n"
	serverBinaryEnv  = "NAUTHILUS_DIRECTOR_E2E_SERVER_BINARY"
)

// TestFakeHTTPAuthorityPublicIMAPFlow proves the guardrail lane uses public sockets.
func TestFakeHTTPAuthorityPublicIMAPFlow(t *testing.T) {
	recorder := newCapturedRecorder()
	authority := startFakeHTTPAuthority(t, map[string][]string{
		"account":   {e2eAccount},
		"tenant":    {e2eTenant},
		"mailShard": {e2eShardTag},
	})
	fakeBackend := startFakeIMAPBackend(t, fakeBackendOptions{})
	authenticator := newHTTPAuthenticator(t, authority.URL())

	director := startDirector(t, directorOptions{
		Authenticator:  authenticator,
		BackendAuth:    masterUserBackendAuth(),
		BackendAddress: fakeBackend.Address(),
		Recorder:       recorder,
		TLSMode:        imap.TLSModeStartTLS,
	})
	defer director.Stop(t)

	client := dialPlain(t, director.Address())
	defer func() { _ = client.Close() }()

	reader := bufio.NewReader(client)
	expectLine(t, reader, "* OK nauthilus-director IMAP session ready\r\n")
	writeLine(t, client, `A001 ID ("client_id" "e2e-client")`)
	expectLine(t, reader, "* ID NIL\r\n")
	expectLine(t, reader, "A001 OK ID completed\r\n")
	writeLine(t, client, `A002 LOGIN "`+e2eAccount+`" "`+e2ePassword+`"`)
	expectLine(t, reader, "A002 OK Authentication completed\r\n")
	writeLine(t, client, "A003 NOOP")
	expectLine(t, reader, "A003 OK backend noop\r\n")

	authority.ExpectRequest(t, "imap", "login", "e2e-client")
	fakeBackend.ExpectProxyLine(t, "A003 NOOP")
	_ = client.Close()
	recorder.AssertSafe(t)
	recorder.ExpectEvents(t,
		observability.EventSessionStart,
		observability.EventNauthilusAuth,
		observability.EventRoutingResolve,
		observability.EventAffinityOpen,
		observability.EventBackendSelect,
		observability.EventBackendConnect,
		observability.EventBackendAuth,
		observability.EventProxyPipe,
		observability.EventSessionEnd,
	)
}

// TestServerBinaryPublicIMAPFlow proves the real server binary owns the public IMAP entrypoint.
func TestServerBinaryPublicIMAPFlow(t *testing.T) {
	binary := e2eServerBinary(t)
	redisFixture := startValkeySessionStore(t)
	authority := startFakeHTTPAuthority(t, map[string][]string{
		"account":   {e2eAccount},
		"tenant":    {e2eTenant},
		"mailShard": {e2eShardTag},
	})
	fakeBackend := startFakeIMAPBackend(t, fakeBackendOptions{})
	directorAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(reserveLoopbackPort(t)))
	configPath := writeProcessConfig(t, processConfigOptions{
		RedisAddress:    redisFixture.addr,
		AuthorityURL:    authority.URL(),
		DirectorAddress: directorAddress,
		BackendAddress:  fakeBackend.Address(),
		BackendTLS: config.BackendTLSConfig{
			Mode:          "plaintext",
			MinTLSVersion: "TLS1.2",
		},
		BackendAuth: masterUserBackendAuth(),
	})
	process := startDirectorProcess(t, binary, configPath)

	waitForDirectorGreeting(t, directorAddress, process)

	client := dialPlain(t, directorAddress)
	defer func() { _ = client.Close() }()

	reader := bufio.NewReader(client)
	expectLine(t, reader, "* OK nauthilus-director IMAP session ready\r\n")
	writeLine(t, client, `A001 LOGIN "`+e2eAccount+`" "`+e2ePassword+`"`)
	expectLine(t, reader, "A001 OK Authentication completed\r\n")
	writeLine(t, client, "A002 NOOP")
	expectLine(t, reader, "A002 OK backend noop\r\n")

	fakeBackend.ExpectProxyLine(t, "A002 NOOP")
	authority.ExpectRequest(t, e2eProtocol, "login", "")
}

// TestServerBinaryControlRESTCLIParity proves the real process exposes shared REST and CLI state.
func TestServerBinaryControlRESTCLIParity(t *testing.T) {
	binary := e2eServerBinary(t)
	ctl := buildDirectorctl(t)
	redisFixture := startValkeySessionStore(t)
	authority := startFakeHTTPAuthority(t, map[string][]string{
		"account":   {e2eAccount},
		"tenant":    {e2eTenant},
		"mailShard": {e2eShardTag},
	})
	fakeBackend := startFakeIMAPBackend(t, fakeBackendOptions{})
	directorAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(reserveLoopbackPort(t)))
	controlAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(reserveLoopbackPort(t)))
	controlURL := "http://" + controlAddress
	configPath := writeProcessConfig(t, processConfigOptions{
		RedisAddress:    redisFixture.addr,
		AuthorityURL:    authority.URL(),
		DirectorAddress: directorAddress,
		ControlAddress:  controlAddress,
		ControlEnabled:  true,
		BackendAddress:  fakeBackend.Address(),
		BackendTLS: config.BackendTLSConfig{
			Mode:          "plaintext",
			MinTLSVersion: "TLS1.2",
		},
		BackendAuth: masterUserBackendAuth(),
	})
	process := startDirectorProcess(t, binary, configPath)

	waitForDirectorGreeting(t, directorAddress, process)

	runDirectorctl(t, ctl, controlURL, "backends", "out", e2eBackendAID, "--reason", "real process parity")
	detail := getBackendDetail(t, controlURL, e2eBackendAID)
	if detail.Runtime.InService {
		t.Fatalf("REST backend state in_service = true after CLI out: %#v", detail.Runtime)
	}

	postAccepted(t, controlURL+"/api/v1/backends/"+e2eBackendAID+"/runtime/in", generated.RuntimeReasonRequest{
		Reason: "real process parity restore",
	})
	output := runDirectorctl(t, ctl, controlURL, "backends", "show", e2eBackendAID)
	if !strings.Contains(output, "in_service=true") {
		t.Fatalf("CLI backend state after REST in = %q", output)
	}
}

// TestServerBinaryListenerDrainResumeKeepsActiveStream exercises listener drain and resume through sockets and the CLI.
func TestServerBinaryListenerDrainResumeKeepsActiveStream(t *testing.T) {
	binary := e2eServerBinary(t)
	ctl := buildDirectorctl(t)
	redisFixture := startValkeySessionStore(t)
	authority := startFakeHTTPAuthority(t, map[string][]string{
		"account":   {e2eAccount},
		"tenant":    {e2eTenant},
		"mailShard": {e2eShardTag},
	})
	fakeBackend := startFakeIMAPBackend(t, fakeBackendOptions{})
	directorAddress := loopbackAddress(t)
	controlAddress := loopbackAddress(t)
	controlURL := "http://" + controlAddress
	configPath := writeProcessConfig(t, processConfigOptions{
		RedisAddress:    redisFixture.addr,
		AuthorityURL:    authority.URL(),
		DirectorAddress: directorAddress,
		ControlAddress:  controlAddress,
		ControlEnabled:  true,
		BackendAddress:  fakeBackend.Address(),
		BackendTLS: config.BackendTLSConfig{
			Mode:          "plaintext",
			MinTLSVersion: "TLS1.2",
		},
		BackendAuth: masterUserBackendAuth(),
	})
	process := startDirectorProcess(t, binary, configPath)

	waitForDirectorGreeting(t, directorAddress, process)
	waitForControlReady(t, controlURL, process)

	listOutput := runDirectorctl(t, ctl, controlURL, "listeners", "list")
	assertCLIOutputFields(t, listOutput, "name="+e2eListenerName, "state=accepting", "bound_address="+directorAddress)

	activeClient := dialPlain(t, directorAddress)
	defer func() { _ = activeClient.Close() }()
	activeReader := bufio.NewReader(activeClient)
	expectLine(t, activeReader, "* OK nauthilus-director IMAP session ready\r\n")

	softDrainOutput := runDirectorctl(t, ctl, controlURL, "listeners", "drain", e2eListenerName, "--mode", "soft", "--reason", "e2e soft listener drain")
	assertCLIOutputFields(t, softDrainOutput, "name="+e2eListenerName, "state=draining", "active_local_sessions=1", "drain_mode=soft")
	expectListenerRejectsNewConnections(t, directorAddress)

	writeLine(t, activeClient, `A001 ID ("client_id" "listener-drain-e2e")`)
	expectLine(t, activeReader, "* ID NIL\r\n")
	expectLine(t, activeReader, "A001 OK ID completed\r\n")

	resumeOutput := runDirectorctl(t, ctl, controlURL, "listeners", "resume", e2eListenerName, "--reason", "e2e listener resume")
	assertCLIOutputFields(t, resumeOutput, "name="+e2eListenerName, "state=accepting", "bound_address="+directorAddress, "drain_mode=\"\"")

	resumedClient := dialPlain(t, directorAddress)
	resumedReader := bufio.NewReader(resumedClient)
	expectLine(t, resumedReader, "* OK nauthilus-director IMAP session ready\r\n")
	_ = resumedClient.Close()

	code, output := runDirectorctlStatus(t, ctl, controlURL, "listeners", "drain", e2eListenerName, "--mode", "hard", "--reason", "missing grace proof")
	if code != 2 || !strings.Contains(output, "--grace-seconds") {
		t.Fatalf("hard drain without grace exit/output = %d/%q, want CLI usage rejection", code, output)
	}

	hardDrainOutput := runDirectorctl(t, ctl, controlURL, "listeners", "drain", e2eListenerName, "--mode", "hard", "--reason", "e2e hard listener drain", "--grace-seconds", "0")
	assertCLIOutputFields(t, hardDrainOutput, "name="+e2eListenerName, "state=drained", "active_local_sessions=0", "drain_mode=hard")
	expectRuntimeClosedConnection(t, activeClient)
}

// TestFakeHTTPAuthorityUsesRedisLeaseStore proves active affinity through Redis-compatible state.
func TestFakeHTTPAuthorityUsesRedisLeaseStore(t *testing.T) {
	fixture := startValkeySessionStore(t)
	authority := startFakeHTTPAuthority(t, map[string][]string{
		"account":   {e2eAccount},
		"tenant":    {e2eTenant},
		"mailShard": {e2eShardTag},
	})
	fakeBackend := startFakeIMAPBackend(t, fakeBackendOptions{})

	director := startDirector(t, directorOptions{
		Authenticator:  newHTTPAuthenticator(t, authority.URL()),
		BackendAuth:    masterUserBackendAuth(),
		BackendAddress: fakeBackend.Address(),
		Recorder:       newCapturedRecorder(),
		SessionStore:   fixture.store,
		TLSMode:        imap.TLSModeStartTLS,
	})
	defer director.Stop(t)

	client := dialPlain(t, director.Address())
	defer func() { _ = client.Close() }()

	reader := bufio.NewReader(client)
	expectLine(t, reader, "* OK nauthilus-director IMAP session ready\r\n")
	writeLine(t, client, `A001 LOGIN "`+e2eAccount+`" "`+e2ePassword+`"`)
	expectLine(t, reader, "A001 OK Authentication completed\r\n")

	key := state.AffinityKey{Tenant: e2eTenant, AccountKey: e2eAccount}
	expectAffinityPresent(t, fixture.store, key, 1)

	writeLine(t, client, "A002 NOOP")
	expectLine(t, reader, "A002 OK backend noop\r\n")
	fakeBackend.ExpectProxyLine(t, "A002 NOOP")
	_ = client.Close()

	expectAffinityReleased(t, fixture.store, key)
}

// TestMaxConnectionsPreventOverbookingThroughPublicIMAP proves capacity limits at the public IMAP boundary.
func TestMaxConnectionsPreventOverbookingThroughPublicIMAP(t *testing.T) {
	redisFixture := startValkeySessionStore(t)
	store := newTrackingSessionStore(redisFixture.store)
	localSessions := runtimectl.NewLocalSessionRegistry()
	recorder := newCapturedRecorder()
	authority := startFakeHTTPAuthority(t, map[string][]string{
		"account":   {e2eAccount},
		"tenant":    {e2eTenant},
		"mailShard": {e2eShardTag},
	})
	fakeBackend := startFakeIMAPBackend(t, fakeBackendOptions{})
	options := directorOptions{
		Authenticator:  newHTTPAuthenticator(t, authority.URL()),
		BackendAuth:    masterUserBackendAuth(),
		BackendAddress: fakeBackend.Address(),
		BackendMaxSessions: map[string]int{
			e2eBackendAID: 1,
		},
		LocalSessions: localSessions,
		Recorder:      recorder,
		SessionStore:  store,
		TLSMode:       imap.TLSModeStartTLS,
	}
	cfg := e2eConfig(options)
	selector := mustRuntimeSelector(t, cfg, store)
	options.BackendSelector = selector

	director := startDirector(t, options)
	defer director.Stop(t)

	control := startE2EControlPlane(t, cfg, store, selector, localSessions, recorder)
	defer control.Close()

	firstClient, firstReader := loginIMAP(t, director.Address(), e2eAccount)
	defer func() { _ = firstClient.Close() }()
	expectBackendProxy(t, firstClient, firstReader, fakeBackend, "A002")
	waitForSessionIDs(t, store, 1)

	route := lookupRoute(t, control.URL(), "bob@example.test", false)
	if !route.FailClosed || !route.AffectedBy.MaxConnections {
		t.Fatalf("capacity route = %#v, want fail-closed max-connection proof", route)
	}

	secondClient := dialPlain(t, director.Address())
	defer func() { _ = secondClient.Close() }()
	secondReader := bufio.NewReader(secondClient)
	expectLine(t, secondReader, "* OK nauthilus-director IMAP session ready\r\n")
	writeLine(t, secondClient, `A001 LOGIN "bob@example.test" "`+e2ePassword+`"`)
	expectLine(t, secondReader, "A001 NO [UNAVAILABLE] Authentication service temporarily unavailable\r\n")
	waitForSessionIDs(t, store, 1)
	recorder.AssertSafe(t)
}

// TestFakeGRPCAuthorityPublicIMAPFlow covers the scaffolded gRPC authority path.
func TestFakeGRPCAuthorityPublicIMAPFlow(t *testing.T) {
	service := &fakeGRPCService{}
	authenticator, err := nauthilus.NewGRPCClient(service)
	if err != nil {
		t.Fatalf("NewGRPCClient: %v", err)
	}

	fakeBackend := startFakeIMAPBackend(t, fakeBackendOptions{})
	director := startDirector(t, directorOptions{
		Authenticator:  authenticator,
		BackendAuth:    credentialReplayBackendAuth(false),
		BackendAddress: fakeBackend.Address(),
		Recorder:       newCapturedRecorder(),
		TLSMode:        imap.TLSModeStartTLS,
	})
	defer director.Stop(t)

	client := dialPlain(t, director.Address())
	defer func() { _ = client.Close() }()

	reader := bufio.NewReader(client)
	expectLine(t, reader, "* OK nauthilus-director IMAP session ready\r\n")
	writeLine(t, client, `A001 LOGIN "`+e2eAccount+`" "`+e2ePassword+`"`)
	expectLine(t, reader, "A001 OK Authentication completed\r\n")
	writeLine(t, client, "A002 NOOP")
	expectLine(t, reader, "A002 OK backend noop\r\n")

	if service.AuthCalls() != 1 {
		t.Fatalf("gRPC auth calls = %d, want 1", service.AuthCalls())
	}
	fakeBackend.ExpectProxyLine(t, "A002 NOOP")
}

// TestPublicSTARTTLSAndImplicitTLSSockets verifies frontend TLS handshakes with test certificates.
func TestPublicSTARTTLSAndImplicitTLSSockets(t *testing.T) {
	certPath, keyPath, certificate := writeTestCertificate(t)

	starttlsDirector := startDirector(t, directorOptions{
		Authenticator:      unavailableAuthenticator{},
		BackendAuth:        masterUserBackendAuth(),
		BackendAddress:     "127.0.0.1:1",
		FrontendTLSConfig:  &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12},
		ListenerCertPath:   certPath,
		ListenerKeyPath:    keyPath,
		Recorder:           newCapturedRecorder(),
		TLSMode:            imap.TLSModeStartTLS,
		UsePlacementStubs:  true,
		UseProxyRunnerStub: true,
	})
	defer starttlsDirector.Stop(t)

	plain := dialPlain(t, starttlsDirector.Address())
	defer func() { _ = plain.Close() }()
	plainReader := bufio.NewReader(plain)
	expectLine(t, plainReader, "* OK nauthilus-director IMAP session ready\r\n")
	writeLine(t, plain, "A001 STARTTLS")
	expectLine(t, plainReader, "A001 OK Begin TLS negotiation now\r\n")

	tlsClient := tls.Client(plain, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("STARTTLS client handshake: %v", err)
	}
	tlsReader := bufio.NewReader(tlsClient)
	writeLine(t, tlsClient, "A002 CAPABILITY")
	line := readLine(t, tlsReader)
	if strings.Contains(line, "STARTTLS") {
		t.Fatalf("post-STARTTLS capabilities still advertise STARTTLS: %q", line)
	}
	expectLine(t, tlsReader, "A002 OK CAPABILITY completed\r\n")

	implicitDirector := startDirector(t, directorOptions{
		Authenticator:     unavailableAuthenticator{},
		BackendAuth:       masterUserBackendAuth(),
		BackendAddress:    "127.0.0.1:1",
		ListenerCertPath:  certPath,
		ListenerKeyPath:   keyPath,
		Recorder:          newCapturedRecorder(),
		TLSMode:           imap.TLSModeImplicit,
		UsePlacementStubs: true,
	})
	defer implicitDirector.Stop(t)

	implicit := dialTLS(t, implicitDirector.Address())
	defer func() { _ = implicit.Close() }()
	expectLine(t, bufio.NewReader(implicit), "* OK nauthilus-director IMAP session ready\r\n")
}

// TestRuntimeControlPublicBoundaries proves runtime control behavior through IMAP, REST and CLI.
func TestRuntimeControlPublicBoundaries(t *testing.T) {
	redisFixture := startValkeySessionStore(t)
	store := newTrackingSessionStore(redisFixture.store)
	localSessions := runtimectl.NewLocalSessionRegistry()
	recorder := newCapturedRecorder()
	authority := startFakeHTTPAuthority(t, map[string][]string{
		"account":   {e2eAccount},
		"tenant":    {e2eTenant},
		"mailShard": {e2eShardTag},
	})
	backendA := startFakeIMAPBackend(t, fakeBackendOptions{})
	backendB := startFakeIMAPBackend(t, fakeBackendOptions{})
	backendC := startFakeIMAPBackend(t, fakeBackendOptions{})
	options := directorOptions{
		Authenticator: newHTTPAuthenticator(t, authority.URL()),
		BackendAuth:   masterUserBackendAuth(),
		BackendAddresses: map[string]string{
			e2eBackendAID:      backendA.Address(),
			e2eBackendBID:      backendB.Address(),
			"mailstore-c-imap": backendC.Address(),
		},
		BackendMaxSessions: map[string]int{
			e2eBackendAID:      2,
			e2eBackendBID:      2,
			"mailstore-c-imap": 2,
		},
		BackendShards: map[string]string{
			"mailstore-c-imap": e2eShardTagB,
		},
		LocalSessions:    localSessions,
		ProxyIdleTimeout: 10 * time.Second,
		Recorder:         recorder,
		SessionLeaseTTL:  10 * time.Second,
		SessionStore:     store,
		TLSMode:          imap.TLSModeStartTLS,
	}
	cfg := e2eConfig(options)
	selector := mustRuntimeSelector(t, cfg, store)
	options.BackendSelector = selector

	director := startDirector(t, options)
	defer director.Stop(t)

	control := startE2EControlPlane(t, cfg, store, selector, localSessions, recorder)
	defer control.Close()

	ctl := buildDirectorctl(t)
	backends := map[string]*fakeIMAPBackend{
		e2eBackendAID:      backendA,
		e2eBackendBID:      backendB,
		"mailstore-c-imap": backendC,
	}

	initial := lookupRoute(t, control.URL(), e2eAccount, true)
	if initial.SelectedBackend != e2eBackendAID && initial.SelectedBackend != e2eBackendBID {
		t.Fatalf("initial selected backend = %q, want same-shard backend", initial.SelectedBackend)
	}
	selectedID := initial.SelectedBackend
	otherID := e2eBackendAID
	if selectedID == e2eBackendAID {
		otherID = e2eBackendBID
	}

	firstClient, firstReader := loginIMAP(t, director.Address(), e2eAccount)
	defer func() { _ = firstClient.Close() }()
	expectBackendProxy(t, firstClient, firstReader, backends[selectedID], "A002")
	firstID := waitForSessionIDs(t, store, 1)[0]

	authCalls := authority.RequestCount()
	idsBeforeLookup := strings.Join(store.snapshotSessionIDs(), ",")
	diagnostic := lookupRoute(t, control.URL(), e2eAccount, true)
	if authority.RequestCount() != authCalls {
		t.Fatal("route lookup called the fake Nauthilus authority")
	}
	if strings.Join(store.snapshotSessionIDs(), ",") != idsBeforeLookup {
		t.Fatal("route lookup mutated session state")
	}
	if diagnostic.Affinity == nil || !diagnostic.Affinity.Present {
		t.Fatalf("route lookup did not report read-only affinity: %#v", diagnostic.Affinity)
	}

	secondClient, secondReader := loginIMAP(t, director.Address(), e2eAccount)
	defer func() { _ = secondClient.Close() }()
	sessionIDs := waitForSessionIDs(t, store, 2)
	secondID := otherSessionID(sessionIDs, firstID)
	secondBackendID := waitForSessionBackend(t, store, secondID)

	runDirectorctl(t, ctl, control.URL(), "backends", "out", otherID, "--reason", "runtime out proof")
	outRoute := lookupRoute(t, control.URL(), "bob@example.test", false)
	if !outRoute.AffectedBy.RuntimeOverride || !routeHasBackendExclusion(outRoute, otherID, "runtime_out") {
		t.Fatalf("runtime-out route = %#v, want excluded backend %q with runtime effect", outRoute, otherID)
	}
	runDirectorctl(t, ctl, control.URL(), "backends", "in", otherID, "--reason", "runtime out proof done")

	clearPath := control.URL() + "/api/v1/users/" + escapedUserPath(e2eAccount) + "/affinity"
	activeClearStatus := requestStatus(t, http.MethodDelete, clearPath, generated.RuntimeReasonRequest{Reason: "active clear should fail"})
	if activeClearStatus == http.StatusAccepted {
		t.Fatal("affinity clear succeeded while sessions were active")
	}

	deleteAccepted(t, control.URL()+"/api/v1/sessions/"+firstID, generated.RuntimeReasonRequest{Reason: "targeted kill"})
	expectSessionClosed(t, firstClient, firstReader)
	expectBackendProxy(t, secondClient, secondReader, backends[secondBackendID], "B002")

	runDirectorctl(t, ctl, control.URL(), "users", "kick", e2eAccount, "--reason", "kick remaining active session")
	expectSessionClosed(t, secondClient, secondReader)
	waitForSessionIDs(t, store, 0)
	deleteAccepted(t, clearPath, generated.RuntimeReasonRequest{Reason: "inactive clear"})

	postAccepted(t, control.URL()+"/api/v1/backends/"+selectedID+"/runtime/weight", generated.RuntimeWeightRequest{
		Reason: "weight zero placement proof",
		Weight: 0,
	})
	weighted := lookupRoute(t, control.URL(), e2eAccount, false)
	if weighted.SelectedBackend != otherID || !weighted.AffectedBy.RuntimeOverride {
		t.Fatalf("weight-zero route selected %q affected=%#v, want %q with runtime effect", weighted.SelectedBackend, weighted.AffectedBy, otherID)
	}
	weightedClient, weightedReader := loginIMAP(t, director.Address(), e2eAccount)
	expectBackendProxy(t, weightedClient, weightedReader, backends[otherID], "C002")
	_ = weightedClient.Close()
	waitForSessionIDs(t, store, 0)

	runDirectorctl(t, ctl, control.URL(), "backends", "weight", selectedID, "--weight", "100", "--reason", "restore weight")
	runDirectorctl(t, ctl, control.URL(), "backends", "out", otherID, "--reason", "rest cli parity")
	parity := lookupRoute(t, control.URL(), e2eAccount, false)
	if parity.SelectedBackend != selectedID {
		t.Fatalf("REST/CLI parity route selected %q, want restored backend %q", parity.SelectedBackend, selectedID)
	}
	runDirectorctl(t, ctl, control.URL(), "backends", "in", otherID, "--reason", "restore in service")

	postAccepted(t, control.URL()+"/api/v1/backends/"+selectedID+"/runtime/drain", generated.DrainRequest{
		Mode:   generated.DrainModeSoft,
		Reason: "drain placement proof",
	})
	drained := lookupRoute(t, control.URL(), e2eAccount, false)
	if drained.SelectedBackend != otherID || !drained.AffectedBy.RuntimeOverride {
		t.Fatalf("drain route selected %q affected=%#v, want %q with runtime effect", drained.SelectedBackend, drained.AffectedBy, otherID)
	}
	deleteAccepted(t, control.URL()+"/api/v1/backends/"+selectedID+"/runtime", generated.RuntimeReasonRequest{Reason: "clear drain"})

	postAccepted(t, control.URL()+"/api/v1/backends/"+selectedID+"/maintenance", generated.MaintenanceRequest{
		Mode:   generated.MaintenanceModeSoft,
		Reason: "maintenance placement proof",
	})
	maintenance := lookupRoute(t, control.URL(), e2eAccount, false)
	if maintenance.SelectedBackend != otherID || !maintenance.AffectedBy.Maintenance {
		t.Fatalf("maintenance route selected %q affected=%#v, want %q with maintenance effect", maintenance.SelectedBackend, maintenance.AffectedBy, otherID)
	}
	runDirectorctl(t, ctl, control.URL(), "backends", "maintenance", "disable", selectedID, "--reason", "maintenance done")

	postAccepted(t, control.URL()+"/api/v1/users/"+escapedUserPath(e2eAccount)+"/move", generated.UserMoveRequest{
		Reason:   "move to second shard",
		Strategy: generated.NewSessionsOnly,
		ToShard:  e2eShardTagB,
	})
	movedClient, movedReader := loginIMAP(t, director.Address(), e2eAccount)
	expectBackendProxy(t, movedClient, movedReader, backendC, "D002")
	_ = movedClient.Close()
	waitForSessionIDs(t, store, 0)

	code, output := runDirectorctlStatus(t, ctl, control.URL(), "config", "dump", "-d", "-P")
	if code != 1 {
		t.Fatalf("protected config dump exit = %d, want 1; output=%s", code, output)
	}
	if control.audit.Count() == 0 {
		t.Fatal("protected config request was not audited")
	}

	safeReload := cfg
	backendConfig := safeReload.Director.Backends[selectedID]
	backendConfig.Weight = 101
	safeReload.Director.Backends[selectedID] = backendConfig
	control.reload.SetNext(safeReload)
	postAccepted(t, control.URL()+"/api/v1/reload", nil)

	unsafeReload := safeReload
	unsafeReload.Runtime.Servers.Control.Address = "127.0.0.1:19090"
	control.reload.SetNext(unsafeReload)
	reloadStatus := requestStatus(t, http.MethodPost, control.URL()+"/api/v1/reload", nil)
	if reloadStatus != http.StatusConflict {
		t.Fatalf("unsafe reload status = %d, want %d", reloadStatus, http.StatusConflict)
	}

	recorder.ExpectEvents(t,
		observability.EventBackendEffectiveState,
		observability.EventBackendMaintenanceOperation,
		observability.EventBackendRuntimeOperation,
		observability.EventBackendDrain,
		observability.EventSelectorExclusion,
		observability.EventSessionAttach,
		observability.EventSessionClose,
		observability.EventSessionKill,
		observability.EventUserKick,
		observability.EventAffinityClear,
		observability.EventUserMove,
		observability.EventRouteLookup,
		observability.EventReload,
	)
	recorder.AssertSafe(t)
}

type directorOptions struct {
	Authenticator      nauthilus.Authenticator
	BackendAuth        backend.AuthConfig
	BackendAddress     string
	BackendAddresses   map[string]string
	BackendMaxSessions map[string]int
	BackendSelector    backend.Selector
	BackendShards      map[string]string
	BackendTLS         config.BackendTLSConfig
	FrontendTLSConfig  *tls.Config
	ListenerCertPath   string
	ListenerKeyPath    string
	LocalSessions      *runtimectl.LocalSessionRegistry
	ProxyIdleTimeout   time.Duration
	Recorder           observability.Recorder
	SessionLeaseTTL    time.Duration
	SessionStore       state.SessionStore
	TLSMode            string
	UsePlacementStubs  bool
	UseProxyRunnerStub bool
}

type directorInstance struct {
	address string
	manager *listener.Manager
}

// Address returns the public listener address for clients.
func (d directorInstance) Address() string {
	return d.address
}

// Stop shuts down the public listener.
func (d directorInstance) Stop(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := d.manager.Stop(ctx); err != nil {
		t.Fatalf("stop director: %v", err)
	}
}

type directorProcess struct {
	command *exec.Cmd
	output  *bytes.Buffer
	done    chan error
}

type processConfigOptions struct {
	RedisAddress    string
	AuthorityURL    string
	DirectorAddress string
	ControlAddress  string
	ControlEnabled  bool
	BackendAddress  string
	BackendTLS      config.BackendTLSConfig
	BackendAuth     backend.AuthConfig
}

// e2eServerBinary returns the real server binary built by the E2E runner.
func e2eServerBinary(t *testing.T) string {
	t.Helper()

	binary := os.Getenv(serverBinaryEnv)
	if binary == "" {
		t.Skipf("%s is required for real-binary E2E", serverBinaryEnv)
	}

	return binary
}

// startDirectorProcess starts the server binary as an external process.
func startDirectorProcess(t *testing.T, binary string, configPath string) *directorProcess {
	t.Helper()

	output := &bytes.Buffer{}
	cmd := exec.Command(binary, "--config", configPath)
	cmd.Stdout = output
	cmd.Stderr = output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start director process: %v", err)
	}

	process := &directorProcess{command: cmd, output: output, done: make(chan error, 1)}
	go func() {
		process.done <- cmd.Wait()
	}()

	t.Cleanup(func() {
		stopDirectorProcess(t, process)
	})

	return process
}

// stopDirectorProcess terminates the external server process.
func stopDirectorProcess(t *testing.T, process *directorProcess) {
	t.Helper()

	select {
	case <-process.done:
		return
	default:
	}

	if process.command.Process != nil {
		_ = process.command.Process.Signal(os.Interrupt)
	}

	select {
	case <-process.done:
	case <-time.After(time.Second):
		if process.command.Process != nil {
			_ = process.command.Process.Kill()
		}
		<-process.done
	}
}

// waitForDirectorGreeting waits until the process exposes its public IMAP socket.
func waitForDirectorGreeting(t *testing.T, address string, process *directorProcess) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			line, readErr := bufio.NewReader(conn).ReadString('\n')
			_ = conn.Close()
			if readErr == nil && line == "* OK nauthilus-director IMAP session ready\r\n" {
				return
			}
		}

		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("director process did not expose IMAP at %s:\n%s", address, process.output.String())
}

// writeProcessConfig writes a minimal production config for real-binary E2E.
func writeProcessConfig(t *testing.T, options processConfigOptions) string {
	t.Helper()

	backendTLS := options.BackendTLS
	if strings.TrimSpace(backendTLS.Mode) == "" {
		backendTLS = config.BackendTLSConfig{Mode: "plaintext", MinTLSVersion: "TLS1.2"}
	}

	backendAuth := options.BackendAuth
	if strings.TrimSpace(backendAuth.Mode) == "" {
		backendAuth = masterUserBackendAuth()
	}

	controlAddress := options.ControlAddress
	if controlAddress == "" {
		controlAddress = "127.0.0.1:0"
	}
	listenerCertPath, listenerKeyPath, _ := writeTestCertificate(t)

	content := fmt.Sprintf(`patch:
  - op: remove
    path: director.listeners
    value: [imaps, lmtp, lmtps]
  - op: remove
    path: director.backend_pools
    value: [lmtp-default]
  - op: remove
    path: director.backends
    value: [mailstore-b-imap, mailstore-a-lmtp, mailstore-b-lmtp]
runtime:
  instance_name: "e2e-director"
  process:
    shutdown_timeout: 2s
  servers:
    control:
      enabled: %t
      address: %q
  timeouts:
    preauth: 2s
    auth: 2s
    nauthilus: 2s
    backend_connect: 2s
    proxy_idle: 2s
storage:
  redis:
    protocol: 2
    key_prefix: "nauthilus-director-e2e-process"
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
      http:
        endpoint: %q
        basic_auth:
          password_file: "unused"
director:
  listeners:
    imap:
      address: %q
      tls:
        mode: starttls
        cert: %q
        key: %q
      imap:
        capabilities: [IMAP4rev1, ID, SASL-IR, STARTTLS, AUTH=PLAIN]
        auth_mechanisms: [plain]
  backend_pools:
    imap-default:
      backends: [mailstore-a-imap]
  backends:
    mailstore-a-imap:
      address: %q
      shard_tag: %q
      tls:
        mode: %q
        ca_file: %q
        cert: %q
        key: %q
        server_name: %q
        min_tls_version: %q
        insecure_skip_verify: %t
      auth:
        mode: %q
        master_user:
          username: %q
          password_file: %q
          user_format: %q
          mechanism: %q
        credential_replay:
          require_backend_tls: %t
          preserve_mechanism: %t
          allowed_mechanisms: [%s]
      health_check:
        enabled: false
`, options.ControlEnabled,
		controlAddress,
		options.RedisAddress,
		options.AuthorityURL,
		options.DirectorAddress,
		listenerCertPath,
		listenerKeyPath,
		options.BackendAddress,
		e2eShardTag,
		backendTLS.Mode,
		backendTLS.CAFile,
		backendTLS.Cert,
		backendTLS.Key.Value(),
		backendTLS.ServerName,
		backendTLS.MinTLSVersion,
		backendTLS.InsecureSkipVerify,
		backendAuth.Mode,
		backendAuth.MasterUser.Username,
		backendAuth.MasterUser.Password.Value(),
		backendAuth.MasterUser.UserFormat,
		backendAuth.MasterUser.Mechanism,
		backendAuth.CredentialReplay.RequireBackendTLS,
		backendAuth.CredentialReplay.PreserveMechanism,
		quotedYAMLStrings(backendAuth.CredentialReplay.AllowedMechanisms),
	)

	path := filepath.Join(t.TempDir(), "nauthilus-director.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write process config: %v", err)
	}

	return path
}

// quotedYAMLStrings renders a small inline string sequence.
func quotedYAMLStrings(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, fmt.Sprintf("%q", value))
	}

	return strings.Join(quoted, ", ")
}

// startDirector starts the production listener/session stack on public sockets.
func startDirector(t *testing.T, options directorOptions) directorInstance {
	t.Helper()

	cfg := e2eConfig(options)
	store := options.SessionStore
	if store == nil {
		store = newMemorySessionStore()
	}
	resolver := mustRoutingResolver(t)
	selector := options.BackendSelector
	if selector == nil {
		selector = mustBackendSelector(t, cfg)
	}
	proxyRunner := proxy.Runner(proxy.NewPipe())
	if options.UseProxyRunnerStub {
		proxyRunner = stubProxyRunner{}
	}
	sessionLeaseTTL := options.SessionLeaseTTL
	if sessionLeaseTTL <= 0 {
		sessionLeaseTTL = time.Second
	}
	proxyIdleTimeout := options.ProxyIdleTimeout
	if proxyIdleTimeout <= 0 {
		proxyIdleTimeout = time.Second
	}

	manager, err := listener.NewManagerWithConfig(
		cfg,
		listener.WithNauthilusClientFactory(func(config.AuthorityConfig) (nauthilus.Authenticator, error) {
			return options.Authenticator, nil
		}),
		listener.WithObservabilityRecorder(options.Recorder),
		listener.WithSessionHandlerFactory(func(listenerOptions listener.SessionOptions) listener.SessionHandler {
			sessionConfig := imap.SessionConfig{
				ListenerName:           listenerOptions.ListenerName,
				AuthorityName:          listenerOptions.Config.Authority,
				ServiceName:            listenerOptions.Config.ServiceName,
				Network:                listenerOptions.Config.Network,
				BackendPool:            listenerOptions.Config.BackendPool,
				DirectorInstanceID:     listenerOptions.DirectorInstanceID,
				DefaultTenant:          e2eTenant,
				TLSMode:                listenerOptions.Config.TLS.Mode,
				Capabilities:           listenerOptions.Config.IMAP.Capabilities,
				AuthMechanisms:         listenerOptions.Config.IMAP.AuthMechanisms,
				MaxBearerTokenBytes:    listenerOptions.BearerTokenMaxBytes,
				SessionLeaseTTL:        sessionLeaseTTL,
				SessionIdleGrace:       0,
				PreauthTimeout:         time.Second,
				AuthTimeout:            time.Second,
				BackendConnectTimeout:  time.Second,
				ProxyIdleTimeout:       proxyIdleTimeout,
				MaxPreauthLineBytes:    8192,
				MaxPreauthLiteralBytes: 16,
				FrontendTLSConfig:      options.FrontendTLSConfig,
				Authenticator:          listenerOptions.Authenticator,
				RoutingResolver:        resolver,
				SessionStore:           store,
				BackendSelector:        selector,
				BackendConnector:       imap.NewTCPBackendConnector(nil),
				ProxyRunner:            proxyRunner,
				LocalSessions:          options.LocalSessions,
				Observability:          options.Recorder,
			}
			if options.UsePlacementStubs {
				sessionConfig.RoutingResolver = nil
				sessionConfig.SessionStore = nil
				sessionConfig.BackendSelector = nil
			}

			return imap.NewHandler(sessionConfig)
		}),
	)
	if err != nil {
		t.Fatalf("NewManagerWithConfig: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := manager.Start(ctx); err != nil {
		t.Fatalf("start director: %v", err)
	}

	address, ok := manager.BoundAddress(e2eListenerName)
	if !ok {
		t.Fatal("director did not expose bound IMAP address")
	}

	return directorInstance{address: address, manager: manager}
}

// e2eConfig builds a narrow typed config for one public IMAP listener and backend.
func e2eConfig(options directorOptions) config.Config {
	cfg := config.DefaultConfig()
	listenerConfig := cfg.Director.Listeners[e2eListenerName]
	listenerConfig.Address = "127.0.0.1:0"
	listenerConfig.TLS.Mode = options.TLSMode
	listenerConfig.TLS.Cert = options.ListenerCertPath
	listenerConfig.TLS.Key = config.Secret(options.ListenerKeyPath)
	listenerConfig.IMAP.Capabilities = []string{"IMAP4rev1", "ID", "SASL-IR", "STARTTLS", "AUTH=PLAIN", "AUTH=XOAUTH2", "AUTH=OAUTHBEARER"}
	listenerConfig.IMAP.AuthMechanisms = []string{"plain", "xoauth2", "oauthbearer"}
	cfg.Director.Listeners = map[string]config.ListenerConfig{e2eListenerName: listenerConfig}

	cfg.Director.BackendPools = map[string]config.BackendPoolConfig{
		e2eBackendPool: {
			Protocol: "imap",
			Selector: "rendezvous_hash",
			Backends: e2eBackendIdentifiers(options),
		},
	}
	backendTLS := options.BackendTLS
	if strings.TrimSpace(backendTLS.Mode) == "" {
		backendTLS = config.BackendTLSConfig{
			Mode:          "plaintext",
			MinTLSVersion: "TLS1.2",
		}
	}
	cfg.Director.Backends = make(map[string]config.BackendConfig, len(cfg.Director.BackendPools[e2eBackendPool].Backends))
	for _, identifier := range cfg.Director.BackendPools[e2eBackendPool].Backends {
		maxConnections := 100
		if options.BackendMaxSessions != nil && options.BackendMaxSessions[identifier] > 0 {
			maxConnections = options.BackendMaxSessions[identifier]
		}
		cfg.Director.Backends[identifier] = config.BackendConfig{
			Protocol:       "imap",
			ShardTag:       e2eBackendShard(options, identifier),
			Address:        e2eBackendAddress(options, identifier),
			Weight:         100,
			MaxConnections: maxConnections,
			Maintenance:    "disabled",
			TLS:            backendTLS,
			Auth:           backendAuthConfig(options.BackendAuth),
			HealthCheck: config.BackendHealthConfig{
				Enabled: false,
			},
		}
	}

	return cfg
}

// e2eBackendIdentifiers returns configured backend identifiers in deterministic order.
func e2eBackendIdentifiers(options directorOptions) []string {
	if len(options.BackendAddresses) == 0 {
		return []string{e2eBackendAID}
	}

	identifiers := make([]string, 0, len(options.BackendAddresses))
	for identifier := range options.BackendAddresses {
		identifiers = append(identifiers, identifier)
	}
	sort.Strings(identifiers)

	return identifiers
}

// e2eBackendAddress returns the fake backend address for one configured backend.
func e2eBackendAddress(options directorOptions, identifier string) string {
	if len(options.BackendAddresses) == 0 {
		return options.BackendAddress
	}

	return options.BackendAddresses[identifier]
}

// e2eBackendShard returns the effective shard for one fake backend.
func e2eBackendShard(options directorOptions, identifier string) string {
	if options.BackendShards != nil && strings.TrimSpace(options.BackendShards[identifier]) != "" {
		return strings.TrimSpace(options.BackendShards[identifier])
	}

	return e2eShardTag
}

// backendAuthConfig maps backend-domain auth settings back into typed config.
func backendAuthConfig(auth backend.AuthConfig) config.BackendAuthConfig {
	return config.BackendAuthConfig{
		Mode: auth.Mode,
		MasterUser: config.BackendMasterUserConfig{
			Username:     auth.MasterUser.Username,
			PasswordFile: auth.MasterUser.Password,
			UserFormat:   auth.MasterUser.UserFormat,
			Mechanism:    auth.MasterUser.Mechanism,
		},
		CredentialReplay: config.BackendCredentialReplayConfig{
			RequireBackendTLS: auth.CredentialReplay.RequireBackendTLS,
			PreserveMechanism: auth.CredentialReplay.PreserveMechanism,
			AllowedMechanisms: auth.CredentialReplay.AllowedMechanisms,
		},
	}
}

// masterUserBackendAuth returns the safe default backend auth mode.
func masterUserBackendAuth() backend.AuthConfig {
	return backend.AuthConfig{
		Mode: "master_user",
		MasterUser: backend.MasterUserConfig{
			Username:   "director-master",
			Password:   config.Secret("backend-master-secret"),
			UserFormat: "{user}*{master_user}",
			Mechanism:  "plain",
		},
	}
}

// credentialReplayBackendAuth returns an explicit test replay backend mode.
func credentialReplayBackendAuth(requireTLS bool) backend.AuthConfig {
	return backend.AuthConfig{
		Mode: "credential_replay",
		CredentialReplay: backend.CredentialReplayConfig{
			RequireBackendTLS: requireTLS,
			PreserveMechanism: true,
			AllowedMechanisms: []string{"plain", "login", "xoauth2", "oauthbearer"},
		},
	}
}

// mustBackendSelector creates the production static backend selector for E2E.
func mustBackendSelector(t *testing.T, cfg config.Config) backend.Selector {
	t.Helper()

	registry, err := backend.NewStaticRegistry(cfg.Director)
	if err != nil {
		t.Fatalf("NewStaticRegistry: %v", err)
	}
	selector, err := backend.NewStaticSelector(registry, backend.SelectionPolicy{SoftAllowsActivePins: true})
	if err != nil {
		t.Fatalf("NewStaticSelector: %v", err)
	}

	return selector
}

// mustRoutingResolver creates the production routing chain used by the fake lane.
func mustRoutingResolver(t *testing.T) routing.RoutingResolver {
	t.Helper()

	authResolver, err := routing.NewAuthAttributeResolver(routing.AuthAttributeResolverConfig{
		AccountKeyAttribute: "account",
		TenantAttribute:     "tenant",
		ShardTagAttribute:   "mailShard",
		Sticky:              true,
	})
	if err != nil {
		t.Fatalf("NewAuthAttributeResolver: %v", err)
	}
	hashResolver, err := routing.NewHashResolver(routing.HashResolverConfig{
		ShardTags: []string{e2eShardTag},
		Sticky:    true,
	})
	if err != nil {
		t.Fatalf("NewHashResolver: %v", err)
	}
	chain, err := routing.NewChainResolver(authResolver, hashResolver)
	if err != nil {
		t.Fatalf("NewChainResolver: %v", err)
	}

	return chain
}

type redisSessionFixture struct {
	store *state.RedisSessionStore
	addr  string
}

// startValkeySessionStore starts a Redis-compatible server for public-socket E2E state.
func startValkeySessionStore(t *testing.T) redisSessionFixture {
	t.Helper()

	path, err := exec.LookPath("valkey-server")
	if err != nil {
		t.Skip("valkey-server is required for Redis-compatible e2e affinity")
	}

	port := reserveLoopbackPort(t)
	var output bytes.Buffer
	cmd := exec.Command(
		path,
		"--bind", "127.0.0.1",
		"--port", strconv.Itoa(port),
		"--save", "",
		"--appendonly", "no",
		"--dir", t.TempDir(),
		"--loglevel", "warning",
	)
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start valkey-server: %v", err)
	}

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	client := redis.NewClient(&redis.Options{Addr: addr, Protocol: 2})
	t.Cleanup(func() {
		_ = client.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	})

	waitForRedis(t, client, &output)

	builder, err := state.NewKeyBuilder(state.KeyBuilderOptions{Prefix: "nauthilus-director-e2e", SchemaVersion: 1})
	if err != nil {
		t.Fatalf("NewKeyBuilder: %v", err)
	}
	store, err := state.NewRedisSessionStore(client, builder, nil)
	if err != nil {
		t.Fatalf("NewRedisSessionStore: %v", err)
	}

	return redisSessionFixture{store: store, addr: addr}
}

// reserveLoopbackPort reserves and releases one local TCP port for a child server.
func reserveLoopbackPort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve valkey port: %v", err)
	}
	defer func() { _ = listener.Close() }()

	return listener.Addr().(*net.TCPAddr).Port
}

// waitForRedis waits until the Redis-compatible test service accepts commands.
func waitForRedis(t *testing.T, client *redis.Client, output *bytes.Buffer) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		err := client.Ping(ctx).Err()
		cancel()
		if err == nil {
			return
		}

		time.Sleep(25 * time.Millisecond)
	}

	t.Fatalf("valkey-server did not become ready: %s", output.String())
}

// expectAffinityPresent waits for an active Redis-backed affinity record.
func expectAffinityPresent(t *testing.T, store state.AffinityStore, key state.AffinityKey, activeCount int) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		record, err := store.LookupAffinity(context.Background(), key)
		if err == nil && record.Present && record.ShardTag == e2eShardTag && record.ActiveSessionCount == activeCount {
			return
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("affinity %v was not present with %d active session(s)", key, activeCount)
}

// expectAffinityReleased waits for the active Redis-backed affinity to disappear.
func expectAffinityReleased(t *testing.T, store state.AffinityStore, key state.AffinityKey) {
	t.Helper()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		record, err := store.LookupAffinity(context.Background(), key)
		if err == nil && !record.Present {
			return
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("affinity %v was not released", key)
}

type trackingSessionStore struct {
	*state.RedisSessionStore
	mu       sync.Mutex
	sessions map[string]runtimectl.SessionRuntimeState
}

// newTrackingSessionStore adds REST-readable session projections around Redis state.
func newTrackingSessionStore(store *state.RedisSessionStore) *trackingSessionStore {
	return &trackingSessionStore{
		RedisSessionStore: store,
		sessions:          make(map[string]runtimectl.SessionRuntimeState),
	}
}

// OpenSession records the public runtime session view after Redis accepts a lease.
func (s *trackingSessionStore) OpenSession(ctx context.Context, record state.SessionRecord) (state.AffinityRecord, error) {
	affinity, err := s.RedisSessionStore.OpenSession(ctx, record)
	if err != nil {
		return state.AffinityRecord{}, err
	}

	now := time.Now().UTC()
	s.mu.Lock()
	s.sessions[record.ID] = runtimectl.SessionRuntimeState{
		SessionID:         record.ID,
		UserHash:          record.Key.AccountKey,
		Tenant:            record.Key.Tenant,
		Protocol:          record.Protocol,
		ListenerName:      record.ListenerName,
		ServiceName:       record.ServiceName,
		EffectiveShardTag: affinity.ShardTag,
		DirectorInstance:  record.DirectorInstanceID,
		OpenedAt:          now,
		LeaseExpiresAt:    now.Add(record.LeaseTTL),
		Status:            runtimectl.SessionStatusActive,
	}
	s.mu.Unlock()

	return affinity, nil
}

// AttachSelectedBackend records the selected backend in the public runtime view.
func (s *trackingSessionStore) AttachSelectedBackend(
	ctx context.Context,
	attachment state.SessionBackendAttachment,
) (state.SessionBackendRecord, error) {
	record, err := s.RedisSessionStore.AttachSelectedBackend(ctx, attachment)
	if err != nil {
		return state.SessionBackendRecord{}, err
	}

	s.mu.Lock()
	session := s.sessions[attachment.SessionID]
	session.BackendIdentifier = attachment.BackendIdentifier
	session.ControlGeneration = record.ControlGeneration
	if !record.LeaseExpiresAt.IsZero() {
		session.LeaseExpiresAt = record.LeaseExpiresAt
	}
	s.sessions[attachment.SessionID] = session
	s.mu.Unlock()

	return record, nil
}

// HeartbeatSession refreshes Redis and mirrors the lease expiry for REST reads.
func (s *trackingSessionStore) HeartbeatSession(
	ctx context.Context,
	key state.AffinityKey,
	sessionID string,
	ttl time.Duration,
) (state.AffinityRecord, error) {
	record, err := s.RedisSessionStore.HeartbeatSession(ctx, key, sessionID, ttl)
	if err != nil {
		return state.AffinityRecord{}, err
	}

	s.mu.Lock()
	session := s.sessions[sessionID]
	session.LeaseExpiresAt = time.Now().UTC().Add(ttl)
	session.ControlGeneration = record.ControlGeneration
	s.sessions[sessionID] = session
	s.mu.Unlock()

	return record, nil
}

// CloseSession removes a REST-visible session after Redis closes its lease.
func (s *trackingSessionStore) CloseSession(ctx context.Context, key state.AffinityKey, sessionID string) (state.AffinityRecord, error) {
	record, err := s.RedisSessionStore.CloseSession(ctx, key, sessionID)
	if err != nil {
		return state.AffinityRecord{}, err
	}

	s.mu.Lock()
	delete(s.sessions, sessionID)
	s.mu.Unlock()

	return record, nil
}

// ListSessions returns active sessions visible through the REST control API.
func (s *trackingSessionStore) ListSessions(_ context.Context, protocol string) ([]runtimectl.SessionRuntimeState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	protocol = strings.ToLower(strings.TrimSpace(protocol))
	sessions := make([]runtimectl.SessionRuntimeState, 0, len(s.sessions))
	for _, session := range s.sessions {
		if protocol != "" && session.Protocol != protocol {
			continue
		}
		sessions = append(sessions, session.Normalize())
	}

	sort.Slice(sessions, func(left int, right int) bool {
		return sessions[left].SessionID < sessions[right].SessionID
	})

	return sessions, nil
}

// GetSession returns one active REST-visible session.
func (s *trackingSessionStore) GetSession(_ context.Context, sessionID string) (runtimectl.SessionRuntimeState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[strings.TrimSpace(sessionID)]
	if !ok {
		return runtimectl.SessionRuntimeState{}, &runtimectl.Error{Kind: runtimectl.ErrorKindNotFound, Operation: "session", Message: "session not found"}
	}

	return session.Normalize(), nil
}

// ListUserSessions returns active REST-visible sessions for one user key.
func (s *trackingSessionStore) ListUserSessions(_ context.Context, key runtimectl.UserKey) ([]runtimectl.SessionRuntimeState, error) {
	key = key.Normalize()

	s.mu.Lock()
	defer s.mu.Unlock()

	sessions := make([]runtimectl.SessionRuntimeState, 0, len(s.sessions))
	for _, session := range s.sessions {
		if session.Tenant == key.Tenant && session.UserHash == key.UserHash {
			sessions = append(sessions, session.Normalize())
		}
	}

	return sessions, nil
}

// ListUsers returns users that currently have REST-visible sessions.
func (s *trackingSessionStore) ListUsers(context.Context) ([]runtimectl.UserRuntimeState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	users := make(map[runtimectl.UserKey]runtimectl.UserRuntimeState)
	for _, session := range s.sessions {
		key := runtimectl.UserKey{Tenant: session.Tenant, UserHash: session.UserHash}.Normalize()
		user := users[key]
		user.Key = key
		user.ActiveShard = session.EffectiveShardTag
		user.ActiveSessionCount++
		users[key] = user
	}

	result := make([]runtimectl.UserRuntimeState, 0, len(users))
	for _, user := range users {
		result = append(result, user)
	}

	return result, nil
}

// GetUser returns one active user view from REST-visible sessions.
func (s *trackingSessionStore) GetUser(ctx context.Context, key runtimectl.UserKey) (runtimectl.UserRuntimeState, error) {
	return s.GetUserAffinity(ctx, key)
}

// GetUserAffinity reads one user affinity through Redis without refreshing it.
func (s *trackingSessionStore) GetUserAffinity(ctx context.Context, key runtimectl.UserKey) (runtimectl.UserRuntimeState, error) {
	key = key.Normalize()
	record, err := s.LookupAffinity(ctx, state.AffinityKey{Tenant: key.Tenant, AccountKey: key.UserHash})
	if err != nil {
		return runtimectl.UserRuntimeState{}, err
	}

	if !record.Present {
		return runtimectl.UserRuntimeState{}, &runtimectl.Error{Kind: runtimectl.ErrorKindNotFound, Operation: "user_affinity", Message: "user affinity not found"}
	}

	return runtimectl.UserRuntimeState{
		Key:                key,
		ActiveShard:        record.ShardTag,
		ActiveSessionCount: record.ActiveSessionCount,
		Generation:         record.Generation,
		UpdatedAt:          record.ServerTime,
	}, nil
}

// snapshotSessionIDs returns active session IDs for public-control assertions.
func (s *trackingSessionStore) snapshotSessionIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	ids := make([]string, 0, len(s.sessions))
	for id := range s.sessions {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	return ids
}

type e2eControlPlane struct {
	server *httptest.Server
	audit  *recordingProtectedConfigAudit
	reload *switchingReloadService
}

// URL returns the public control API base URL.
func (p *e2eControlPlane) URL() string {
	return p.server.URL
}

// Close stops the public control API listener.
func (p *e2eControlPlane) Close() {
	p.server.Close()
}

// startE2EControlPlane starts the generated REST control boundary on localhost.
func startE2EControlPlane(
	t *testing.T,
	cfg config.Config,
	store *trackingSessionStore,
	selector backend.Selector,
	localSessions *runtimectl.LocalSessionRegistry,
	recorder observability.Recorder,
) *e2eControlPlane {
	t.Helper()

	registry, err := backend.NewStaticRegistry(cfg.Director)
	if err != nil {
		t.Fatalf("NewStaticRegistry: %v", err)
	}

	reader, err := runtimectl.NewBackendReadService(runtimectl.BackendReadServiceOptions{
		Registry:      registry,
		Snapshots:     store,
		Policy:        backend.NewEffectiveBackendPolicy(cfg.Director),
		Observability: recorder,
	})
	if err != nil {
		t.Fatalf("NewBackendReadService: %v", err)
	}

	lookup, err := runtimectl.NewRouteLookupService(runtimectl.RouteLookupServiceOptions{
		Resolver:     mustRoutingResolver(t),
		Selector:     selector,
		BackendRead:  reader,
		AffinityRead: store,
		ListenerContexts: []runtimectl.RouteLookupListenerContext{{
			Name:        e2eListenerName,
			Protocol:    e2eProtocol,
			ServiceName: e2eService,
			BackendPool: e2eBackendPool,
		}},
		DefaultPool:   e2eBackendPool,
		DefaultShard:  e2eShardTag,
		DefaultTenant: e2eTenant,
		Observability: recorder,
	})
	if err != nil {
		t.Fatalf("NewRouteLookupService: %v", err)
	}

	reload := &switchingReloadService{current: cfg, next: cfg, recorder: recorder}
	audit := &recordingProtectedConfigAudit{}
	server := rest.NewServer(rest.Options{HandlerOptions: adapters.HandlerOptions{
		BackendReader:             reader,
		BackendMutator:            runtimectl.NewBackendService(store, localSessions, runtimectl.WithObservabilityRecorder(recorder)),
		SessionReader:             store,
		SessionMutator:            runtimectl.NewSessionService(store, localSessions, runtimectl.WithObservabilityRecorder(recorder)),
		UserReader:                store,
		UserMutator:               runtimectl.NewUserService(store, localSessions, runtimectl.WithObservabilityRecorder(recorder)),
		RouteLookup:               lookup,
		Reload:                    reload,
		Observability:             recorder,
		ProtectedConfigAudit:      audit,
		ProtectedConfigAuthorizer: deniedProtectedConfigAuthorizer{},
	}})

	return &e2eControlPlane{
		server: httptest.NewServer(server),
		audit:  audit,
		reload: reload,
	}
}

type deniedProtectedConfigAuthorizer struct{}

// AuthorizeProtectedConfig denies protected config export for explicit E2E proof.
func (deniedProtectedConfigAuthorizer) AuthorizeProtectedConfig(context.Context, adapters.ProtectedConfigRequest) (bool, error) {
	return false, nil
}

type recordingProtectedConfigAudit struct {
	mu     sync.Mutex
	events []adapters.ProtectedConfigAuditEvent
}

// AuditProtectedConfigRead records protected config reads without config values.
func (r *recordingProtectedConfigAudit) AuditProtectedConfigRead(_ context.Context, event adapters.ProtectedConfigAuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.events = append(r.events, event)

	return nil
}

// Count returns the number of protected config audit events.
func (r *recordingProtectedConfigAudit) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	return len(r.events)
}

type switchingReloadService struct {
	mu       sync.Mutex
	current  config.Config
	next     config.Config
	err      error
	recorder observability.Recorder
}

// Reload applies a test-controlled safe reload or returns a classified conflict.
func (s *switchingReloadService) Reload(ctx context.Context) (runtimectl.ReloadResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.err != nil {
		return runtimectl.ReloadResult{}, s.err
	}

	service := runtimectl.NewSafeReloadService(s.current, func(context.Context) (config.Config, error) {
		return s.next, nil
	}, runtimectl.WithObservabilityRecorder(s.recorder))
	result, err := service.Reload(ctx)
	if err != nil {
		return runtimectl.ReloadResult{}, err
	}

	s.current = s.next

	return result, nil
}

// SetNext sets the next reload snapshot for public reload E2E calls.
func (s *switchingReloadService) SetNext(next config.Config) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.next = next
	s.err = nil
}

// mustRuntimeSelector creates the runtime-aware selector used by IMAP and route lookup E2E.
func mustRuntimeSelector(t *testing.T, cfg config.Config, snapshots backend.RuntimeSnapshotReader) backend.Selector {
	t.Helper()

	registry, err := backend.NewStaticRegistry(cfg.Director)
	if err != nil {
		t.Fatalf("NewStaticRegistry: %v", err)
	}

	policy := backend.SelectionPolicy{
		SoftAllowsActivePins: true,
		DefaultShard:         cfg.Director.Routing.EffectiveDefaultShard(),
		EffectiveBackend:     backend.NewEffectiveBackendPolicy(cfg.Director),
	}
	policy.EffectiveBackend.EnforceHealth = false

	selector, err := backend.NewRuntimeSelector(registry, snapshots, policy)
	if err != nil {
		t.Fatalf("NewRuntimeSelector: %v", err)
	}

	return selector
}

// lookupRoute posts one public route lookup request.
func lookupRoute(t *testing.T, baseURL string, userKey string, includeAffinity bool) generated.RouteLookupResponse {
	t.Helper()

	listenerName := e2eListenerName
	body := generated.LookupRouteJSONRequestBody{
		IncludeAffinity: &includeAffinity,
		Listener:        &listenerName,
		Protocol:        e2eProtocol,
		UserKey:         &userKey,
	}

	var response generated.RouteLookupResponse
	requestJSON(t, http.MethodPost, baseURL+"/api/v1/route/lookup", body, http.StatusOK, &response)

	return response
}

// routeHasBackendExclusion reports whether route lookup explained a backend exclusion.
func routeHasBackendExclusion(response generated.RouteLookupResponse, backendID string, reason string) bool {
	for _, summary := range response.Backends {
		if summary.Identifier != backendID {
			continue
		}

		for _, exclusion := range summary.Exclusions {
			if exclusion.Reason == reason {
				return true
			}
		}
	}

	return false
}

// getBackendDetail reads one backend through the public REST boundary.
func getBackendDetail(t *testing.T, baseURL string, backendID string) generated.BackendDetail {
	t.Helper()

	var response generated.BackendDetail
	requestJSON(t, http.MethodGet, baseURL+"/api/v1/backends/"+backendID, nil, http.StatusOK, &response)

	return response
}

// postAccepted posts one generated JSON body and expects an accepted response.
func postAccepted(t *testing.T, target string, body any) {
	t.Helper()

	var accepted generated.AcceptedResponse
	requestJSON(t, http.MethodPost, target, body, http.StatusAccepted, &accepted)
}

// deleteAccepted sends one generated JSON body and expects an accepted response.
func deleteAccepted(t *testing.T, target string, body any) {
	t.Helper()

	var accepted generated.AcceptedResponse
	requestJSON(t, http.MethodDelete, target, body, http.StatusAccepted, &accepted)
}

// requestJSON sends a JSON request to a public control endpoint.
func requestJSON(t *testing.T, method string, target string, body any, wantStatus int, out any) {
	t.Helper()

	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		reader = bytes.NewReader(payload)
	}

	request, err := http.NewRequest(method, target, reader)
	if err != nil {
		t.Fatalf("new request %s %s: %v", method, target, err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("request %s %s: %v", method, target, err)
	}
	defer func() { _ = response.Body.Close() }()

	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	if response.StatusCode != wantStatus {
		t.Fatalf("%s %s status = %d, want %d, body=%s", method, target, response.StatusCode, wantStatus, data)
	}

	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			t.Fatalf("decode response body %s: %v", data, err)
		}
	}
}

// requestStatus sends JSON and returns only the HTTP status for negative assertions.
func requestStatus(t *testing.T, method string, target string, body any) int {
	t.Helper()

	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		reader = bytes.NewReader(payload)
	}

	request, err := http.NewRequest(method, target, reader)
	if err != nil {
		t.Fatalf("new request %s %s: %v", method, target, err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("request %s %s: %v", method, target, err)
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, response.Body)

	return response.StatusCode
}

// buildDirectorctl builds the real CLI binary for public-boundary parity tests.
func buildDirectorctl(t *testing.T) string {
	t.Helper()

	root := repoRoot(t)
	binary := filepath.Join(t.TempDir(), "nauthilus-directorctl")
	cmd := exec.Command("go", "build", "-mod=vendor", "-o", binary, "./cmd/nauthilus-directorctl")
	cmd.Dir = root
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build nauthilus-directorctl: %v\n%s", err, output)
	}

	return binary
}

// runDirectorctl runs the real CLI binary against the public control API.
func runDirectorctl(t *testing.T, binary string, baseURL string, args ...string) string {
	t.Helper()

	fullArgs := append([]string{"--address", baseURL}, args...)
	cmd := exec.Command(binary, fullArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("nauthilus-directorctl %v failed: %v\n%s", args, err, output)
	}

	rendered := string(output)
	assertNoSecretText(t, rendered)

	return rendered
}

// runDirectorctlStatus runs the real CLI and returns its exit code and output.
func runDirectorctlStatus(t *testing.T, binary string, baseURL string, args ...string) (int, string) {
	t.Helper()

	fullArgs := append([]string{"--address", baseURL}, args...)
	cmd := exec.Command(binary, fullArgs...)
	output, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		} else {
			t.Fatalf("nauthilus-directorctl %v failed without exit status: %v\n%s", args, err, output)
		}
	}

	rendered := string(output)
	assertNoSecretText(t, rendered)

	return code, rendered
}

// repoRoot finds the repository root from the E2E package directory.
func repoRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repository root with go.mod was not found")
		}
		dir = parent
	}
}

// loginIMAP authenticates one public IMAP client and leaves it in proxy mode.
func loginIMAP(t *testing.T, address string, account string) (net.Conn, *bufio.Reader) {
	t.Helper()

	client := dialPlain(t, address)
	reader := bufio.NewReader(client)
	expectLine(t, reader, "* OK nauthilus-director IMAP session ready\r\n")
	writeLine(t, client, `A001 LOGIN "`+account+`" "`+e2ePassword+`"`)
	expectLine(t, reader, "A001 OK Authentication completed\r\n")

	return client, reader
}

// expectBackendProxy sends one NOOP and verifies the expected fake backend observed it.
func expectBackendProxy(t *testing.T, client net.Conn, reader *bufio.Reader, backend *fakeIMAPBackend, tag string) {
	t.Helper()

	writeLine(t, client, tag+" NOOP")
	expectLine(t, reader, tag+" OK backend noop\r\n")
	backend.ExpectProxyLine(t, tag+" NOOP")
}

// expectSessionClosed waits for a connection to be closed by runtime control.
func expectSessionClosed(t *testing.T, client net.Conn, reader *bufio.Reader) {
	t.Helper()

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := reader.ReadString('\n')
	if err == nil {
		t.Fatal("session stayed readable after runtime control close")
	}
}

// expectRuntimeClosedConnection waits for a server-side close and fails if the socket only idles.
func expectRuntimeClosedConnection(t *testing.T, client net.Conn) {
	t.Helper()

	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}

	buffer := make([]byte, 1)
	_, err := client.Read(buffer)
	if err == nil {
		t.Fatal("connection remained readable after runtime close")
	}

	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatalf("connection stayed open after runtime close: %v", err)
	}
}

// expectListenerRejectsNewConnections verifies a drained listener stops accepting frontend sockets.
func expectListenerRejectsNewConnections(t *testing.T, address string) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
	if err == nil {
		_ = conn.Close()

		t.Fatalf("dial %s succeeded, want drained listener to reject new connections", address)
	}
}

// assertCLIOutputFields verifies compact key-value CLI output contains all expected fields.
func assertCLIOutputFields(t *testing.T, output string, fields ...string) {
	t.Helper()

	for _, field := range fields {
		if !strings.Contains(output, field) {
			t.Fatalf("CLI output = %q, want field %q", output, field)
		}
	}
}

// waitForSessionIDs waits until the control reader sees the requested count.
func waitForSessionIDs(t *testing.T, store *trackingSessionStore, count int) []string {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ids := store.snapshotSessionIDs()
		if len(ids) == count {
			return ids
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("session count did not become %d; ids=%v", count, store.snapshotSessionIDs())
	return nil
}

// otherSessionID returns the active session id that does not match the excluded id.
func otherSessionID(ids []string, excluded string) string {
	for _, id := range ids {
		if id != excluded {
			return id
		}
	}

	return ""
}

// waitForSessionBackend waits until the REST-visible session has selected-backend metadata.
func waitForSessionBackend(t *testing.T, store *trackingSessionStore, sessionID string) string {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		session, err := store.GetSession(context.Background(), sessionID)
		if err == nil && strings.TrimSpace(session.BackendIdentifier) != "" {
			return session.BackendIdentifier
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("session %q did not record a selected backend", sessionID)
	return ""
}

// escapedUserPath returns a safe user-key path segment.
func escapedUserPath(userKey string) string {
	return url.PathEscape(userKey)
}

// assertNoSecretText fails if output contains credential-bearing E2E values.
func assertNoSecretText(t *testing.T, output string) {
	t.Helper()

	for _, secret := range []string{e2ePassword, e2eToken, "sasl_blob"} {
		if strings.Contains(output, secret) {
			t.Fatalf("output leaked secret %q: %s", secret, output)
		}
	}
}

type fakeHTTPAuthority struct {
	server       *http.Server
	listener     net.Listener
	attributes   map[string][]string
	requests     []map[string]any
	requestsLock sync.Mutex
}

// startFakeHTTPAuthority starts a public HTTP auth socket.
func startFakeHTTPAuthority(t *testing.T, attributes map[string][]string) *fakeHTTPAuthority {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake HTTP authority: %v", err)
	}
	fake := &fakeHTTPAuthority{listener: ln, attributes: attributes}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/json", fake.handle)
	fake.server = &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}

	go func() {
		_ = fake.server.Serve(ln)
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = fake.server.Shutdown(ctx)
	})

	return fake
}

// URL returns the fake authority endpoint.
func (f *fakeHTTPAuthority) URL() string {
	return "http://" + f.listener.Addr().String() + "/api/v1/auth/json"
}

// ExpectRequest verifies the fake authority saw the expected safe context.
func (f *fakeHTTPAuthority) ExpectRequest(t *testing.T, protocol string, method string, clientID string) {
	t.Helper()

	f.requestsLock.Lock()
	defer f.requestsLock.Unlock()

	if len(f.requests) != 1 {
		t.Fatalf("fake authority requests = %d, want 1", len(f.requests))
	}
	request := f.requests[0]
	if request["protocol"] != protocol || request["method"] != method || !matchesOptionalString(request["client_id"], clientID) {
		t.Fatalf("fake authority request = %#v", request)
	}
	for _, forbidden := range []string{"backend_identifier", "listener", "session_id", "routing_hint"} {
		if _, ok := request[forbidden]; ok {
			t.Fatalf("fake authority received forbidden field %q: %#v", forbidden, request)
		}
	}
}

// matchesOptionalString treats an omitted optional JSON field as an empty string.
func matchesOptionalString(value any, want string) bool {
	if want == "" && value == nil {
		return true
	}

	return value == want
}

// RequestCount returns how often the fake authority was called.
func (f *fakeHTTPAuthority) RequestCount() int {
	f.requestsLock.Lock()
	defer f.requestsLock.Unlock()

	return len(f.requests)
}

// handle maps one JSON auth request into a successful Nauthilus-shaped response.
func (f *fakeHTTPAuthority) handle(writer http.ResponseWriter, request *http.Request) {
	var body map[string]any
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		http.Error(writer, "bad request", http.StatusBadRequest)

		return
	}

	f.requestsLock.Lock()
	f.requests = append(f.requests, body)
	f.requestsLock.Unlock()

	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"ok":            true,
		"account_field": "account",
		"attributes":    f.attributes,
	})
}

// newHTTPAuthenticator creates the real HTTP authority client used by IMAP sessions.
func newHTTPAuthenticator(t *testing.T, endpoint string) nauthilus.Authenticator {
	t.Helper()

	client, err := nauthilus.NewHTTPClient(nauthilus.HTTPClientConfig{
		Endpoint:    endpoint,
		ContentType: "application/json",
	})
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}

	return client
}

type fakeGRPCService struct {
	mu               sync.Mutex
	calls            int
	lookupCalls      []nauthilus.GRPCLookupIdentityRequest
	lookupIdentities map[string]lmtpAuthorityIdentity
}

// Authenticate records one scaffolded gRPC auth request.
func (s *fakeGRPCService) Authenticate(_ context.Context, request *nauthilus.GRPCAuthRequest) (*nauthilus.GRPCAuthResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.calls++
	return &nauthilus.GRPCAuthResponse{
		OK:           true,
		Decision:     nauthilus.GRPCDecisionOK,
		AccountField: "account",
		Attributes: map[string][]string{
			"account":   {request.Username},
			"tenant":    {e2eTenant},
			"mailShard": {e2eShardTag},
		},
	}, nil
}

// LookupIdentity records a scaffolded recipient lookup and returns configured identity facts.
func (s *fakeGRPCService) LookupIdentity(_ context.Context, request *nauthilus.GRPCLookupIdentityRequest) (*nauthilus.GRPCAuthResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.lookupCalls = append(s.lookupCalls, *request)
	if s.lookupIdentities == nil {
		return &nauthilus.GRPCAuthResponse{Decision: nauthilus.GRPCDecisionTempFail}, nil
	}

	identity, ok := s.lookupIdentities[request.Username]
	if !ok {
		return &nauthilus.GRPCAuthResponse{Decision: nauthilus.GRPCDecisionTempFail}, nil
	}

	return &nauthilus.GRPCAuthResponse{
		OK:           true,
		Decision:     nauthilus.GRPCDecisionOK,
		AccountField: "account",
		Attributes: map[string][]string{
			"account":   {identity.Account},
			"tenant":    {identity.Tenant},
			"mailShard": {identity.Shard},
		},
	}, nil
}

// ListAccounts returns an empty account list for unused gRPC surface.
func (s *fakeGRPCService) ListAccounts(context.Context, *nauthilus.GRPCListAccountsRequest) (*nauthilus.GRPCListAccountsResponse, error) {
	return &nauthilus.GRPCListAccountsResponse{Decision: nauthilus.GRPCDecisionOK}, nil
}

// AuthCalls returns the number of authentication requests.
func (s *fakeGRPCService) AuthCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.calls
}

// SingleLookup returns the only recorded gRPC identity lookup.
func (s *fakeGRPCService) SingleLookup(t *testing.T) nauthilus.GRPCLookupIdentityRequest {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.lookupCalls) != 1 {
		t.Fatalf("gRPC lookup calls = %d, want 1", len(s.lookupCalls))
	}

	return s.lookupCalls[0]
}

type fakeBackendOptions struct {
	TLSConfig *tls.Config
	TLSMode   string
}

type fakeIMAPBackend struct {
	listener     net.Listener
	observations chan fakeBackendObservation
	options      fakeBackendOptions
}

type fakeBackendObservation struct {
	authLine  string
	proxyLine string
}

// startFakeIMAPBackend starts a public fake IMAP backend socket.
func startFakeIMAPBackend(t *testing.T, options fakeBackendOptions) *fakeIMAPBackend {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake backend: %v", err)
	}
	backend := &fakeIMAPBackend{
		listener:     ln,
		observations: make(chan fakeBackendObservation, 8),
		options:      options,
	}

	go backend.accept()
	t.Cleanup(func() {
		_ = ln.Close()
	})

	return backend
}

// Address returns the public fake backend address.
func (b *fakeIMAPBackend) Address() string {
	return b.listener.Addr().String()
}

// ExpectProxyLine verifies backend auth reached transparent proxy mode.
func (b *fakeIMAPBackend) ExpectProxyLine(t *testing.T, want string) {
	t.Helper()

	select {
	case observation := <-b.observations:
		if strings.TrimSpace(observation.proxyLine) != want {
			t.Fatalf("backend proxy line = %q, want %q", observation.proxyLine, want)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for fake backend observation")
	}
}

// accept serves backend connections until the listener closes.
func (b *fakeIMAPBackend) accept() {
	for {
		conn, err := b.listener.Accept()
		if err != nil {
			return
		}

		go b.serve(conn)
	}
}

// serve executes a minimal IMAP backend auth and proxy script.
func (b *fakeIMAPBackend) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	var ok bool
	conn, ok = b.prepareBackendConn(conn)
	if !ok {
		return
	}

	reader := bufio.NewReader(conn)
	_, _ = io.WriteString(conn, fakeBackendReady)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}

		var done bool
		conn, reader, done = b.handleBackendLine(conn, reader, line)
		if done {
			return
		}
	}
}

// prepareBackendConn applies implicit TLS when the fake backend is configured for it.
func (b *fakeIMAPBackend) prepareBackendConn(conn net.Conn) (net.Conn, bool) {
	if b.options.TLSMode == imap.TLSModeImplicit && b.options.TLSConfig != nil {
		tlsConn := tls.Server(conn, b.options.TLSConfig.Clone())
		if err := tlsConn.Handshake(); err != nil {
			return conn, false
		}

		conn = tlsConn
	}

	return conn, true
}

// handleBackendLine dispatches one minimal fake backend command.
func (b *fakeIMAPBackend) handleBackendLine(conn net.Conn, reader *bufio.Reader, line string) (net.Conn, *bufio.Reader, bool) {
	tag, command, _ := strings.Cut(strings.TrimSpace(line), " ")
	upper := strings.ToUpper(command)

	switch {
	case strings.HasPrefix(upper, "STARTTLS") && b.options.TLSConfig != nil:
		return b.handleBackendStartTLS(conn, tag)
	case strings.HasPrefix(upper, "CAPABILITY"):
		_, _ = io.WriteString(conn, "* CAPABILITY IMAP4rev1 AUTH=PLAIN AUTH=LOGIN AUTH=XOAUTH2 AUTH=OAUTHBEARER\r\n")
		_, _ = io.WriteString(conn, tag+" OK capability completed\r\n")
	case strings.HasPrefix(upper, "LOGIN") || strings.HasPrefix(upper, "AUTHENTICATE"):
		return conn, reader, b.handleBackendAuth(conn, reader, tag, line)
	default:
		_, _ = io.WriteString(conn, tag+" BAD unsupported\r\n")
	}

	return conn, reader, false
}

// handleBackendStartTLS upgrades the fake backend stream.
func (b *fakeIMAPBackend) handleBackendStartTLS(conn net.Conn, tag string) (net.Conn, *bufio.Reader, bool) {
	_, _ = io.WriteString(conn, tag+" OK begin TLS\r\n")
	tlsConn := tls.Server(conn, b.options.TLSConfig.Clone())
	if err := tlsConn.Handshake(); err != nil {
		return conn, bufio.NewReader(conn), true
	}

	return tlsConn, bufio.NewReader(tlsConn), false
}

// handleBackendAuth accepts backend auth and records the first proxied command.
func (b *fakeIMAPBackend) handleBackendAuth(conn net.Conn, reader *bufio.Reader, tag string, authLine string) bool {
	_, _ = io.WriteString(conn, tag+" OK backend auth completed\r\n")
	for {
		proxyLine, err := reader.ReadString('\n')
		if err != nil {
			return true
		}

		proxyTag, _, _ := strings.Cut(strings.TrimSpace(proxyLine), " ")
		_, _ = io.WriteString(conn, proxyTag+" OK backend noop\r\n")
		b.observations <- fakeBackendObservation{authLine: authLine, proxyLine: proxyLine}
	}

}

type memorySessionStore struct {
	mu           sync.Mutex
	records      map[state.AffinityKey]state.AffinityRecord
	counts       map[state.AffinityKey]int
	attachments  map[string]state.SessionBackendAttachment
	reservations map[string]state.BackendReservationRequest
}

// newMemorySessionStore creates deterministic lease semantics for the fake lane.
func newMemorySessionStore() *memorySessionStore {
	return &memorySessionStore{
		records:      make(map[state.AffinityKey]state.AffinityRecord),
		counts:       make(map[state.AffinityKey]int),
		attachments:  make(map[string]state.SessionBackendAttachment),
		reservations: make(map[string]state.BackendReservationRequest),
	}
}

// OpenSession creates or reuses an active shard pin.
func (s *memorySessionStore) OpenSession(_ context.Context, record state.SessionRecord) (state.AffinityRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	current, ok := s.records[record.Key]
	if !ok {
		current = state.AffinityRecord{Key: record.Key, ShardTag: record.ShardTag, Status: "created", Present: true}
		s.records[record.Key] = current
	} else {
		current.Status = "reused"
	}
	s.counts[record.Key]++
	current.ActiveSessionCount = s.counts[record.Key]
	s.records[record.Key] = current

	return current, nil
}

// ReserveBackendCapacity records one in-memory backend reservation.
func (s *memorySessionStore) ReserveBackendCapacity(
	_ context.Context,
	request state.BackendReservationRequest,
) (state.BackendReservationRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.reservations[request.ReservationID] = request

	return state.BackendReservationRecord{
		Status:             "reserved",
		BackendIdentifier:  request.BackendIdentifier,
		ReservationID:      request.ReservationID,
		BackendActiveCount: len(s.reservations),
		LeaseExpiresAt:     time.Now().Add(request.LeaseTTL),
	}, nil
}

// ReleaseBackendReservation removes one in-memory backend reservation.
func (s *memorySessionStore) ReleaseBackendReservation(
	_ context.Context,
	request state.BackendReservationReleaseRequest,
) (state.BackendReservationRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.reservations, request.ReservationID)

	return state.BackendReservationRecord{
		Status:             "released",
		BackendIdentifier:  request.BackendIdentifier,
		ReservationID:      request.ReservationID,
		BackendActiveCount: len(s.reservations),
		RepairedCount:      1,
	}, nil
}

// ReapBackendReservations is unused by the in-memory fake lane.
func (s *memorySessionStore) ReapBackendReservations(
	context.Context,
	state.BackendReservationReapRequest,
) (state.BackendReservationRecord, error) {
	return state.BackendReservationRecord{}, nil
}

// AttachSelectedBackend records selected-backend metadata for fake-lane sessions.
func (s *memorySessionStore) AttachSelectedBackend(
	_ context.Context,
	attachment state.SessionBackendAttachment,
) (state.SessionBackendRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.attachments[attachment.SessionID] = attachment

	return state.SessionBackendRecord{
		Status:             "attached",
		BackendIdentifier:  attachment.BackendIdentifier,
		ReservationID:      attachment.ReservationID,
		BackendActiveCount: len(s.attachments),
	}, nil
}

// HeartbeatSession refreshes an active in-memory lease.
func (s *memorySessionStore) HeartbeatSession(_ context.Context, key state.AffinityKey, _ string, _ time.Duration) (state.AffinityRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.records[key], nil
}

// CloseSession releases an active in-memory lease.
func (s *memorySessionStore) CloseSession(_ context.Context, key state.AffinityKey, sessionID string) (state.AffinityRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.attachments, sessionID)
	delete(s.reservations, sessionID)

	current := s.records[key]
	if s.counts[key] > 0 {
		s.counts[key]--
	}
	current.ActiveSessionCount = s.counts[key]
	if current.ActiveSessionCount == 0 {
		current.Status = "released"
		delete(s.records, key)
	} else {
		current.Status = "closed"
		s.records[key] = current
	}

	return current, nil
}

type capturedRecorder struct {
	mu     sync.Mutex
	events []observability.Event
}

// newCapturedRecorder creates an in-memory event sink for assertions.
func newCapturedRecorder() *capturedRecorder {
	return &capturedRecorder{}
}

// Record stores one normalized event.
func (r *capturedRecorder) Record(_ context.Context, event observability.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.events = append(r.events, event)
}

// AssertSafe checks secret safety and label policy for every captured event.
func (r *capturedRecorder) AssertSafe(t *testing.T) {
	t.Helper()

	for _, event := range r.snapshot() {
		for key, value := range event.LogFields {
			if strings.Contains(value, e2ePassword) || strings.Contains(value, e2eToken) {
				t.Fatalf("event %s log field %s leaked secret value %q", event.Name, key, value)
			}
		}
		if err := event.MetricLabels.Validate(); err != nil {
			t.Fatalf("event %s has invalid metric labels: %v", event.Name, err)
		}
		for _, forbidden := range observability.ForbiddenMetricLabels() {
			if _, ok := event.MetricLabels[forbidden]; ok {
				t.Fatalf("event %s has forbidden metric label %q", event.Name, forbidden)
			}
		}
	}
}

// ExpectEvents checks that required event names were observed at least once.
func (r *capturedRecorder) ExpectEvents(t *testing.T, names ...string) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for {
		seen := map[string]bool{}
		for _, event := range r.snapshot() {
			seen[event.Name] = true
		}

		missing := ""
		for _, name := range names {
			if !seen[name] {
				missing = name
				break
			}
		}
		if missing == "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("event %s was not recorded; seen=%v", missing, seen)
		}

		time.Sleep(10 * time.Millisecond)
	}
}

// snapshot returns a detached event slice.
func (r *capturedRecorder) snapshot() []observability.Event {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]observability.Event(nil), r.events...)
}

type unavailableAuthenticator struct{}

// Authenticate returns a temporary failure for TLS-only E2E sessions.
func (unavailableAuthenticator) Authenticate(context.Context, nauthilus.AuthRequest) (nauthilus.AuthResult, error) {
	return nauthilus.AuthResult{Decision: nauthilus.DecisionTemporaryFailure}, nil
}

type stubProxyRunner struct{}

// Run closes the streams for tests that do not enter real proxy mode.
func (stubProxyRunner) Run(_ context.Context, pipeConfig proxy.PipeConfig) (proxy.Result, error) {
	_ = pipeConfig.Frontend.Close()
	_ = pipeConfig.Backend.Close()

	return proxy.Result{Class: proxy.ResultClientClosed}, nil
}

// dialPlain connects to one public TCP listener.
func dialPlain(t *testing.T, address string) net.Conn {
	t.Helper()

	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", address, err)
	}

	return conn
}

// dialTLS connects to one public TLS listener.
func dialTLS(t *testing.T, address string) net.Conn {
	t.Helper()

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("dial TLS %s: %v", address, err)
	}

	return conn
}

// writeLine writes one CRLF-terminated IMAP line.
func writeLine(t *testing.T, writer io.Writer, line string) {
	t.Helper()

	if _, err := io.WriteString(writer, line+"\r\n"); err != nil {
		t.Fatalf("write line %q: %v", line, err)
	}
}

// readLine reads one CRLF-terminated IMAP line.
func readLine(t *testing.T, reader *bufio.Reader) string {
	t.Helper()

	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read line: %v", err)
	}

	return line
}

// expectLine asserts one exact IMAP response line.
func expectLine(t *testing.T, reader *bufio.Reader, want string) {
	t.Helper()

	if got := readLine(t, reader); got != want {
		t.Fatalf("line = %q, want %q", got, want)
	}
}

// writeTestCertificate writes a localhost certificate usable by listener tests.
func writeTestCertificate(t *testing.T) (string, string, tls.Certificate) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	certPath := writeTempFile(t, "e2e-listener-*.crt", certPEM)
	keyPath := writeTempFile(t, "e2e-listener-*.key", keyPEM)
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}

	return certPath, keyPath, certificate
}

// writeTempFile writes a temporary fixture file.
func writeTempFile(t *testing.T, pattern string, contents []byte) string {
	t.Helper()

	file, err := os.CreateTemp(t.TempDir(), pattern)
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer func() { _ = file.Close() }()
	if _, err := file.Write(contents); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	return file.Name()
}
