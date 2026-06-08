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
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/listener"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/placement"
	"github.com/croessner/nauthilus-director/internal/protocol/imap"
	"github.com/croessner/nauthilus-director/internal/protocol/sieve"
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
	e2eAccount          = "alice@example.test"
	e2eBackendAID       = "mailstore-a-imap"
	e2eBackendBID       = "mailstore-b-imap"
	e2eBackendCID       = "mailstore-c-imap"
	e2eBackendPool      = "imap-default"
	e2eListenerName     = "imap"
	e2ePassword         = "e2e-secret-password"
	e2eProtocol         = "imap"
	e2eProcessKeyPrefix = "nauthilus-director-e2e-process"
	e2eService          = "imap"
	e2eSieveAccount     = "sieve-alice@example.test"
	e2eSieveBackendAID  = "mailstore-a-sieve"
	e2eSieveBackendBID  = "mailstore-b-sieve"
	e2eSieveBackendPool = "sieve-default"
	e2eSieveListener    = "sieve"
	e2eSieveProtocol    = "sieve"
	e2eSieveService     = "sieve"
	e2eSievesListener   = "sieves"
	e2eHoldAccountKey   = "hold-account-key-e2e"
	e2eHoldLogin        = "hold-login@example.test"
	e2eHoldOtherKey     = "hold-other-account-key-e2e"
	e2eHoldOtherLogin   = "hold-other-login@example.test"
	e2eHoldTimeoutKey   = "hold-timeout-account-key-e2e"
	e2eHoldTimeoutLogin = "hold-timeout-login@example.test"
	e2ePinnedAccountKey = "pin-account-key-e2e"
	e2ePinnedLogin      = "pin-login@example.test"
	e2eProxyAccountKey  = "proxy-account-key-e2e"
	e2eProxyLogin       = "proxy-login@example.test"
	e2eShardTagB        = "mailstore-b"
	e2eShardTag         = "mailstore-a"
	e2eTenant           = "default"
	e2eToken            = "e2e-bearer-token"
	e2eOIDCClientID     = "nauthilus-director-e2e"
	e2eOIDCClientSecret = "nauthilus-director-e2e-secret"
	e2eOIDCScopeAuth    = "nauthilus:authenticate"
	e2eOIDCScopeLookup  = "nauthilus:lookup_identity"
	e2eOIDCScopeList    = "nauthilus:list_accounts"
	e2eOIDCDiscovery    = "/.well-known/openid-configuration"
	e2eContextHeader    = "X-Company-Domain"
	e2eContextHTTPValue = "e2e-http-authority-context"
	e2eContextMetadata  = "x-company-domain"
	e2eContextGRPCValue = "e2e-grpc-authority-context"
	fakeBackendReady    = "* OK fake IMAP backend ready\r\n"
	fakeProxyPrefix     = "PROXY "
	fakeProxyReadLimit  = 256
	fakeProxyTimeout    = 500 * time.Millisecond
	serverBinaryEnv     = "NAUTHILUS_DIRECTOR_E2E_SERVER_BINARY"
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

	director := startDirector(t, directorOptions{
		AuthorityContextHTTPHeaders: map[string]string{
			e2eContextHeader: e2eContextHTTPValue,
		},
		AuthorityURL:   authority.URL(),
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
	markIMAPStartTLS(t, client, reader)
	writeLine(t, client, `A001 ID ("client_id" "e2e-client")`)
	expectLine(t, reader, "* ID NIL\r\n")
	expectLine(t, reader, "A001 OK ID completed\r\n")
	writeLine(t, client, `A002 LOGIN "`+e2eAccount+`" "`+e2ePassword+`"`)
	expectLine(t, reader, "A002 OK Authentication completed\r\n")
	writeLine(t, client, "A003 NOOP")
	expectLine(t, reader, "A003 OK backend noop\r\n")

	authority.ExpectRequest(t, "imap", "login", "e2e-client")
	authority.ExpectContextHeader(t, e2eContextHeader, e2eContextHTTPValue)
	fakeBackend.ExpectProxyLine(t, "A003 NOOP")
	_ = client.Close()
	recorder.AssertSafe(t)
	recorder.AssertOmits(t, e2eContextHTTPValue)
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
	client, reader = upgradeIMAPStartTLS(t, client, reader)
	writeLine(t, client, `A001 LOGIN "`+e2eAccount+`" "`+e2ePassword+`"`)
	expectLine(t, reader, "A001 OK Authentication completed\r\n")
	writeLine(t, client, "A002 NOOP")
	expectLine(t, reader, "A002 OK backend noop\r\n")

	fakeBackend.ExpectProxyLine(t, "A002 NOOP")
	authority.ExpectRequest(t, e2eProtocol, "login", "")
}

// TestServerBinaryOIDCAuthorityCallerAuthPublicIMAPFlow proves public auth uses OIDC caller tokens.
func TestServerBinaryOIDCAuthorityCallerAuthPublicIMAPFlow(t *testing.T) {
	binary := e2eServerBinary(t)
	redisFixture := startValkeySessionStore(t)
	authority := startFakeOIDCHTTPAuthority(t, map[string][]string{
		"account":   {e2eAccount},
		"tenant":    {e2eTenant},
		"mailShard": {e2eShardTag},
	}, fakeOIDCAuthorityOptions{})
	fakeBackend := startFakeIMAPBackend(t, fakeBackendOptions{})
	directorAddress := loopbackAddress(t)
	configPath := writeProcessConfig(t, processConfigOptions{
		RedisAddress:    redisFixture.addr,
		AuthorityURL:    authority.URL(),
		AuthorityOIDC:   processAuthorityOIDCForFake(authority, nil),
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
	client, reader = upgradeIMAPStartTLS(t, client, reader)
	writeLine(t, client, `A001 LOGIN "`+e2eAccount+`" "`+e2ePassword+`"`)
	expectLine(t, reader, "A001 OK Authentication completed\r\n")
	writeLine(t, client, "A002 NOOP")
	expectLine(t, reader, "A002 OK backend noop\r\n")

	fakeBackend.ExpectProxyLine(t, "A002 NOOP")
	authority.ExpectRequest(t, e2eProtocol, "login", "")
	authority.ExpectOIDCCallerAuth(t)
	assertNoSecretText(t, process.output.String())
}

// TestServerBinaryOIDCAuthorityCallerAuthRejectsInsufficientScope proves Nauthilus denial is fail-closed.
func TestServerBinaryOIDCAuthorityCallerAuthRejectsInsufficientScope(t *testing.T) {
	binary := e2eServerBinary(t)
	redisFixture := startValkeySessionStore(t)
	authority := startFakeOIDCHTTPAuthority(t, map[string][]string{
		"account":   {e2eAccount},
		"tenant":    {e2eTenant},
		"mailShard": {e2eShardTag},
	}, fakeOIDCAuthorityOptions{})
	fakeBackend := startFakeIMAPBackend(t, fakeBackendOptions{})
	directorAddress := loopbackAddress(t)
	configPath := writeProcessConfig(t, processConfigOptions{
		RedisAddress:    redisFixture.addr,
		AuthorityURL:    authority.URL(),
		AuthorityOIDC:   processAuthorityOIDCForFake(authority, []string{e2eOIDCScopeList}),
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
	client, reader = upgradeIMAPStartTLS(t, client, reader)
	writeLine(t, client, `A001 LOGIN "`+e2eAccount+`" "`+e2ePassword+`"`)
	expectLine(t, reader, "A001 NO [AUTHENTICATIONFAILED] Authentication failed\r\n")

	if fakeBackend.ConnectionCount() != 0 {
		t.Fatalf("backend connections = %d, want no placement after OIDC denial", fakeBackend.ConnectionCount())
	}
	authority.ExpectOIDCCallerAuth(t)
	assertNoSecretText(t, process.output.String())
}

// TestServerBinaryOIDCAuthorityCallerAuthRejectsBadSecret proves token acquisition fails closed.
func TestServerBinaryOIDCAuthorityCallerAuthRejectsBadSecret(t *testing.T) {
	binary := e2eServerBinary(t)
	redisFixture := startValkeySessionStore(t)
	authority := startFakeOIDCHTTPAuthority(t, map[string][]string{
		"account":   {e2eAccount},
		"tenant":    {e2eTenant},
		"mailShard": {e2eShardTag},
	}, fakeOIDCAuthorityOptions{})
	fakeBackend := startFakeIMAPBackend(t, fakeBackendOptions{})
	directorAddress := loopbackAddress(t)
	oidcOptions := processAuthorityOIDCForFake(authority, nil)
	oidcOptions.ClientSecret = "wrong-client-secret"
	configPath := writeProcessConfig(t, processConfigOptions{
		RedisAddress:    redisFixture.addr,
		AuthorityURL:    authority.URL(),
		AuthorityOIDC:   oidcOptions,
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
	client, reader = upgradeIMAPStartTLS(t, client, reader)
	writeLine(t, client, `A001 LOGIN "`+e2eAccount+`" "`+e2ePassword+`"`)
	expectLine(t, reader, "A001 NO [UNAVAILABLE] Authentication service temporarily unavailable\r\n")

	if fakeBackend.ConnectionCount() != 0 {
		t.Fatalf("backend connections = %d, want no placement after OIDC token denial", fakeBackend.ConnectionCount())
	}
	authority.ExpectOIDCTokenAttemptWithoutBackchannel(t)
	assertNoSecretText(t, process.output.String())
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

// TestServerBinaryBackendProxyProtocolPublicIMAPFlow proves outbound PROXY through real process boundaries.
func TestServerBinaryBackendProxyProtocolPublicIMAPFlow(t *testing.T) {
	binary := e2eServerBinary(t)
	ctl := buildDirectorctl(t)
	redisFixture := startValkeySessionStore(t)
	authority := startFakeHTTPAuthority(t, map[string][]string{
		"account":   {e2eProxyAccountKey},
		"tenant":    {e2eTenant},
		"mailShard": {e2eShardTag},
	})
	proxyRequiredBackend := startFakeIMAPBackend(t, fakeBackendOptions{RequireProxyProtocol: true})
	directorAddress := loopbackAddress(t)
	controlAddress := loopbackAddress(t)
	controlURL := "http://" + controlAddress
	configPath := writeProcessConfig(t, processConfigOptions{
		RedisAddress:    redisFixture.addr,
		AuthorityURL:    authority.URL(),
		DirectorAddress: directorAddress,
		ControlAddress:  controlAddress,
		ControlEnabled:  true,
		BackendAddress:  proxyRequiredBackend.Address(),
		BackendHAProxy:  true,
		BackendTLS: config.BackendTLSConfig{
			Mode:          "plaintext",
			MinTLSVersion: "TLS1.2",
		},
		BackendAuth: masterUserBackendAuth(),
	})
	process := startDirectorProcess(t, binary, configPath)

	waitForDirectorGreeting(t, directorAddress, process)
	waitForControlReady(t, controlURL, process)

	route := lookupRoute(t, controlURL, e2eProxyAccountKey, true)
	assertRouteLookupBackendProxy(t, route, e2eBackendAID, true)
	if proxyRequiredBackend.ConnectionCount() != 0 || proxyRequiredBackend.ProxyProtocolHeaderCount() != 0 {
		t.Fatal("route lookup opened a backend socket or wrote outbound PROXY")
	}
	assertNoRuntimePlacement(t, controlURL)

	detail := getBackendDetail(t, controlURL, e2eBackendAID)
	if !detail.OutboundProxyProtocol || detail.BackendNode == "" {
		t.Fatalf("backend detail = %#v, want outbound PROXY read-back", detail)
	}
	cliOutput := runDirectorctl(t, ctl, controlURL, "backends", "show", e2eBackendAID)
	assertCLIOutputFields(t, cliOutput, "backend_node=", "outbound_proxy_protocol=true")
	assertOutputOmits(t, cliOutput, e2ePassword, e2eProxyLogin, proxyRequiredBackend.Address())

	client, reader := loginProcessIMAP(t, directorAddress, e2eProxyLogin)
	expectBackendProxy(t, client, reader, proxyRequiredBackend, "A002")
	_ = client.Close()
	assertProxyProtocolHeader(t, proxyRequiredBackend.ExpectProxyProtocolHeader(t))
	assertNoSecretText(t, process.output.String())
	authority.ExpectRequest(t, e2eProtocol, "login", "")
}

// TestServerBinaryBackendProxyProtocolHealthRequiresPreface proves health honors backend PROXY policy.
func TestServerBinaryBackendProxyProtocolHealthRequiresPreface(t *testing.T) {
	binary := e2eServerBinary(t)

	healthyRedis := startValkeySessionStore(t)
	healthyAuthority := startFakeHTTPAuthority(t, map[string][]string{
		"account":   {e2eProxyAccountKey},
		"tenant":    {e2eTenant},
		"mailShard": {e2eShardTag},
	})
	healthyBackend := startFakeIMAPBackend(t, fakeBackendOptions{RequireProxyProtocol: true})
	healthyDirectorAddress := loopbackAddress(t)
	healthyControlAddress := loopbackAddress(t)
	healthyConfig := writeProcessConfig(t, processConfigOptions{
		RedisAddress:           healthyRedis.addr,
		AuthorityURL:           healthyAuthority.URL(),
		DirectorAddress:        healthyDirectorAddress,
		ControlAddress:         healthyControlAddress,
		ControlEnabled:         true,
		BackendAddress:         healthyBackend.Address(),
		BackendHAProxy:         true,
		BackendHealthEnabled:   true,
		BackendHealthDeepCheck: true,
		BackendAuth:            masterUserBackendAuth(),
	})
	healthyProcess := startDirectorProcess(t, binary, healthyConfig)
	waitForControlReady(t, "http://"+healthyControlAddress, healthyProcess)
	waitForProcessHealthStatus(t, processRuntimeStore(t, healthyRedis.addr), e2eBackendAID, backend.HealthStatusHealthy)
	assertProxyProtocolHeader(t, healthyBackend.ExpectProxyProtocolHeader(t))

	unhealthyRedis := startValkeySessionStore(t)
	unhealthyAuthority := startFakeHTTPAuthority(t, map[string][]string{
		"account":   {e2eProxyAccountKey},
		"tenant":    {e2eTenant},
		"mailShard": {e2eShardTag},
	})
	unhealthyBackend := startFakeIMAPBackend(t, fakeBackendOptions{RequireProxyProtocol: true})
	unhealthyDirectorAddress := loopbackAddress(t)
	unhealthyControlAddress := loopbackAddress(t)
	unhealthyConfig := writeProcessConfig(t, processConfigOptions{
		RedisAddress:           unhealthyRedis.addr,
		AuthorityURL:           unhealthyAuthority.URL(),
		DirectorAddress:        unhealthyDirectorAddress,
		ControlAddress:         unhealthyControlAddress,
		ControlEnabled:         true,
		BackendAddress:         unhealthyBackend.Address(),
		BackendHAProxy:         false,
		BackendHealthEnabled:   true,
		BackendHealthDeepCheck: true,
		BackendAuth:            masterUserBackendAuth(),
	})
	unhealthyProcess := startDirectorProcess(t, binary, unhealthyConfig)
	waitForDirectorGreeting(t, unhealthyDirectorAddress, unhealthyProcess)
	waitForControlReady(t, "http://"+unhealthyControlAddress, unhealthyProcess)
	waitForProcessHealthStatus(t, processRuntimeStore(t, unhealthyRedis.addr), e2eBackendAID, backend.HealthStatusUnhealthy)
	if unhealthyBackend.ProxyProtocolHeaderCount() != 0 || unhealthyBackend.MissingProxyProtocolCount() == 0 {
		t.Fatalf("disabled backend headers=%d missing=%d, want no PROXY and a required-preface miss",
			unhealthyBackend.ProxyProtocolHeaderCount(),
			unhealthyBackend.MissingProxyProtocolCount(),
		)
	}
	expectProcessIMAPLoginUnavailable(t, unhealthyDirectorAddress, e2eProxyLogin)
	assertNoSecretText(t, unhealthyProcess.output.String())
}

// TestServerBinaryBackendPinPublicIMAPFlow proves backend pinning through real process boundaries.
func TestServerBinaryBackendPinPublicIMAPFlow(t *testing.T) {
	binary := e2eServerBinary(t)
	ctl := buildDirectorctl(t)
	redisFixture := startValkeySessionStore(t)
	authority := startFakeHTTPAuthority(t, map[string][]string{
		"account":   {e2ePinnedAccountKey},
		"tenant":    {e2eTenant},
		"mailShard": {e2eShardTag},
	})
	backendA := startFakeIMAPBackend(t, fakeBackendOptions{})
	backendB := startFakeIMAPBackend(t, fakeBackendOptions{})
	backendC := startFakeIMAPBackend(t, fakeBackendOptions{})
	directorAddress := loopbackAddress(t)
	controlAddress := loopbackAddress(t)
	controlURL := "http://" + controlAddress
	configPath := writeBackendPinProcessConfig(t, processConfigOptions{
		RedisAddress:    redisFixture.addr,
		AuthorityURL:    authority.URL(),
		DirectorAddress: directorAddress,
		ControlAddress:  controlAddress,
		ControlEnabled:  true,
		BackendAuth:     masterUserBackendAuth(),
	}, []processBackendDefinition{
		{Identifier: e2eBackendAID, Address: backendA.Address(), Shard: e2eShardTag, Weight: 100},
		{Identifier: e2eBackendBID, Address: backendB.Address(), Shard: e2eShardTag, Weight: 100},
		{Identifier: e2eBackendCID, Address: backendC.Address(), Shard: e2eShardTag, Weight: 0},
	})
	process := startDirectorProcess(t, binary, configPath)

	waitForDirectorGreeting(t, directorAddress, process)
	waitForControlReady(t, controlURL, process)

	backends := map[string]*fakeIMAPBackend{
		e2eBackendAID: backendA,
		e2eBackendBID: backendB,
		e2eBackendCID: backendC,
	}

	unrelated := lookupRoute(t, controlURL, "unrelated-account-key-e2e", false)
	if unrelated.FailClosed || unrelated.SelectedBackend == e2eBackendCID || !routeHasBackendExclusion(unrelated, e2eBackendCID, "weight_zero") {
		t.Fatalf("unrelated route = %#v, want normal backend and weight-zero exclusion", unrelated)
	}

	activeClient, activeReader := loginProcessIMAP(t, directorAddress, e2ePinnedLogin)
	activeBackend := waitForRESTSessionCount(t, controlURL, 1)[0].Backend
	if activeBackend == e2eBackendCID {
		t.Fatalf("normal login selected weight-zero backend %q", activeBackend)
	}
	expectBackendProxy(t, activeClient, activeReader, backends[activeBackend], "A002")

	runDirectorctl(t, ctl, controlURL, "users", "backend-pin", "set", e2ePinnedAccountKey,
		"--backend", e2eBackendCID,
		"--strategy", "new_sessions_only",
		"--reason", "e2e new sessions only")
	expectBackendProxy(t, activeClient, activeReader, backends[activeBackend], "A003")

	runDirectorctl(t, ctl, controlURL, "users", "backend-pin", "set", e2ePinnedAccountKey,
		"--backend", e2eBackendCID,
		"--strategy", "drain_existing",
		"--reason", "e2e drain existing")
	expectBackendProxy(t, activeClient, activeReader, backends[activeBackend], "A004")

	activeRoute := lookupRoute(t, controlURL, e2ePinnedAccountKey, true)
	if !activeRoute.BackendPin.Present || activeRoute.BackendPin.Applied || activeRoute.BackendPin.Reason != "active_affinity" {
		t.Fatalf("active-affinity backend-pin route = %#v, want diagnostic pin without forced move", activeRoute.BackendPin)
	}

	runDirectorctl(t, ctl, controlURL, "users", "backend-pin", "set", e2ePinnedAccountKey,
		"--backend", e2eBackendCID,
		"--strategy", "kick_existing",
		"--reason", "e2e kick existing")
	expectSessionClosed(t, activeClient, activeReader)
	waitForRESTSessionCount(t, controlURL, 0)

	showPin := runDirectorctl(t, ctl, controlURL, "users", "backend-pin", "show", e2ePinnedAccountKey)
	assertCLIOutputFields(t, showPin, "present=true", "backend="+e2eBackendCID, "strategy=kick_existing")

	beforeLookup := len(waitForRESTSessionCount(t, controlURL, 0))
	pinnedRoute := lookupRoute(t, controlURL, e2ePinnedAccountKey, true)
	assertBackendPinRoute(t, pinnedRoute, e2eBackendCID)
	afterLookup := len(waitForRESTSessionCount(t, controlURL, 0))
	if beforeLookup != afterLookup {
		t.Fatalf("route lookup changed session count from %d to %d", beforeLookup, afterLookup)
	}

	pinnedClient, pinnedReader := loginProcessIMAP(t, directorAddress, e2ePinnedLogin)
	expectBackendProxy(t, pinnedClient, pinnedReader, backendC, "B002")

	runDirectorctl(t, ctl, controlURL, "users", "backend-pin", "clear", e2ePinnedAccountKey, "--reason", "e2e clear weight zero")
	expectBackendProxy(t, pinnedClient, pinnedReader, backendC, "B003")
	_ = pinnedClient.Close()
	waitForRESTSessionCount(t, controlURL, 0)
	runDirectorctl(t, ctl, controlURL, "users", "affinity", "clear", e2ePinnedAccountKey, "--reason", "e2e clear inactive affinity")

	clearedRoute := lookupRoute(t, controlURL, e2ePinnedAccountKey, true)
	if clearedRoute.BackendPin.Present || clearedRoute.SelectedBackend == e2eBackendCID {
		t.Fatalf("cleared route = %#v, want absent pin and normal placement", clearedRoute)
	}

	runDirectorctl(t, ctl, controlURL, "users", "backend-pin", "set", e2ePinnedAccountKey,
		"--backend", e2eBackendAID,
		"--strategy", "kick_existing",
		"--reason", "e2e normal backend pin")
	normalPinRoute := lookupRoute(t, controlURL, e2ePinnedAccountKey, true)
	assertBackendPinRoute(t, normalPinRoute, e2eBackendAID)
	normalPinClient, normalPinReader := loginProcessIMAP(t, directorAddress, e2ePinnedLogin)
	expectBackendProxy(t, normalPinClient, normalPinReader, backendA, "C002")
	runDirectorctl(t, ctl, controlURL, "users", "backend-pin", "clear", e2ePinnedAccountKey, "--reason", "e2e clear normal backend pin")
	_ = normalPinClient.Close()
	waitForRESTSessionCount(t, controlURL, 0)
	runDirectorctl(t, ctl, controlURL, "users", "affinity", "clear", e2ePinnedAccountKey, "--reason", "e2e clear normal affinity")

	runDirectorctl(t, ctl, controlURL, "backends", "out", e2eBackendCID, "--reason", "e2e fail closed")
	runDirectorctl(t, ctl, controlURL, "users", "backend-pin", "set", e2ePinnedAccountKey,
		"--backend", e2eBackendCID,
		"--strategy", "kick_existing",
		"--reason", "e2e fail closed pin")
	failClosed := lookupRoute(t, controlURL, e2ePinnedAccountKey, true)
	if !failClosed.FailClosed || failClosed.SelectedBackend != "" || failClosed.BackendPin.Applied || failClosed.BackendPin.Reason != "runtime_out" {
		t.Fatalf("fail-closed route = %#v, want runtime_out without selected backend", failClosed)
	}
	expectProcessIMAPLoginUnavailable(t, directorAddress, e2ePinnedLogin)
	waitForRESTSessionCount(t, controlURL, 0)
	runDirectorctl(t, ctl, controlURL, "backends", "in", e2eBackendCID, "--reason", "e2e fail closed restore")
	runDirectorctl(t, ctl, controlURL, "users", "backend-pin", "clear", e2ePinnedAccountKey, "--reason", "e2e clear failed pin")
	runDirectorctl(t, ctl, controlURL, "users", "affinity", "clear", e2ePinnedAccountKey, "--reason", "e2e clear failed affinity")

	output := process.output.String()
	assertNoSecretText(t, output)
	if strings.Contains(output, e2ePinnedLogin) {
		t.Fatalf("process output leaked raw login name: %s", output)
	}
}

// TestServerBinaryUserHoldPublicIMAPReleaseFlow proves user holds through public process boundaries.
func TestServerBinaryUserHoldPublicIMAPReleaseFlow(t *testing.T) {
	binary := e2eServerBinary(t)
	ctl := buildDirectorctl(t)
	redisFixture := startValkeySessionStore(t)
	authority := startMappedFakeHTTPAuthority(t, map[string]map[string][]string{
		e2eHoldLogin: {
			"account":   {e2eHoldAccountKey},
			"tenant":    {e2eTenant},
			"mailShard": {e2eShardTag},
		},
		e2eHoldOtherLogin: {
			"account":   {e2eHoldOtherKey},
			"tenant":    {e2eTenant},
			"mailShard": {e2eShardTag},
		},
	}, nil)
	backendA := startFakeIMAPBackend(t, fakeBackendOptions{})
	backendB := startFakeIMAPBackend(t, fakeBackendOptions{})
	directorAddress := loopbackAddress(t)
	controlAddress := loopbackAddress(t)
	controlURL := "http://" + controlAddress
	configPath := writeBackendPinProcessConfig(t, processConfigOptions{
		RedisAddress:         redisFixture.addr,
		AuthorityURL:         authority.URL(),
		DirectorAddress:      directorAddress,
		ControlAddress:       controlAddress,
		ControlEnabled:       true,
		BackendAuth:          masterUserBackendAuth(),
		UserHoldMaxWait:      8 * time.Second,
		UserHoldPollInterval: 25 * time.Millisecond,
	}, []processBackendDefinition{
		{Identifier: e2eBackendAID, Address: backendA.Address(), Shard: e2eShardTag, Weight: 100},
		{Identifier: e2eBackendBID, Address: backendB.Address(), Shard: e2eShardTag, Weight: 100},
	})
	process := startDirectorProcess(t, binary, configPath)

	waitForDirectorGreeting(t, directorAddress, process)
	waitForControlReady(t, controlURL, process)
	assertNoRuntimePlacement(t, controlURL)

	runDirectorctl(t, ctl, controlURL, "users", "hold", "set", e2eHoldAccountKey,
		"--duration", "15s",
		"--reason", "e2e hold migration")
	holdShow := runDirectorctl(t, ctl, controlURL, "users", "hold", "show", e2eHoldAccountKey)
	assertCLIOutputFields(t, holdShow, "user_key="+e2eHoldAccountKey, "present=true")
	assertOutputOmits(t, holdShow, "e2e hold migration")

	pending := beginProcessIMAPLogin(t, directorAddress, e2eHoldLogin)
	defer func() { _ = pending.client.Close() }()

	expectNoIMAPLoginResult(t, pending, 150*time.Millisecond)
	assertNoFakeBackendConnections(t, backendA, backendB)
	assertNoRuntimePlacement(t, controlURL)

	beforeLookup := getRuntimeSummary(t, controlURL)
	routeStarted := time.Now()
	heldRoute := lookupRoute(t, controlURL, e2eHoldAccountKey, true)
	if time.Since(routeStarted) > 500*time.Millisecond {
		t.Fatalf("route lookup waited behind hold for %s", time.Since(routeStarted))
	}
	assertRouteLookupUserHoldActive(t, heldRoute)
	assertNoRuntimePlacement(t, controlURL)
	afterLookup := getRuntimeSummary(t, controlURL)
	if beforeLookup.ActiveSessions.Total.Count != afterLookup.ActiveSessions.Total.Count {
		t.Fatalf("route lookup changed session count from %#v to %#v", beforeLookup.ActiveSessions.Total, afterLookup.ActiveSessions.Total)
	}

	otherClient, otherReader := loginProcessIMAP(t, directorAddress, e2eHoldOtherLogin)
	otherBackend := waitForRESTSessionCount(t, controlURL, 1)[0].Backend
	backends := map[string]*fakeIMAPBackend{e2eBackendAID: backendA, e2eBackendBID: backendB}
	expectBackendProxy(t, otherClient, otherReader, backends[otherBackend], "U002")
	_ = otherClient.Close()
	waitForRESTSessionCount(t, controlURL, 0)
	expectNoIMAPLoginResult(t, pending, 150*time.Millisecond)

	runDirectorctl(t, ctl, controlURL, "users", "backend-pin", "set", e2eHoldAccountKey,
		"--backend", e2eBackendBID,
		"--strategy", "kick_existing",
		"--reason", "e2e hold target ready")
	pinnedWhileHeld := lookupRoute(t, controlURL, e2eHoldAccountKey, true)
	assertRouteLookupUserHoldActive(t, pinnedWhileHeld)
	assertBackendPinRoute(t, pinnedWhileHeld, e2eBackendBID)

	runDirectorctl(t, ctl, controlURL, "users", "hold", "clear", e2eHoldAccountKey, "--reason", "e2e hold release")
	expectIMAPLoginResult(t, pending, "A001 OK Authentication completed\r\n")
	expectBackendProxy(t, pending.client, pending.reader, backendB, "H002")
	waitForRESTSessionCount(t, controlURL, 1)

	runDirectorctl(t, ctl, controlURL, "users", "hold", "clear", e2eHoldAccountKey, "--reason", "e2e idempotent cleanup")
	runDirectorctl(t, ctl, controlURL, "users", "backend-pin", "clear", e2eHoldAccountKey, "--reason", "e2e hold cleanup")
	_ = pending.client.Close()
	waitForRESTSessionCount(t, controlURL, 0)
	runDirectorctl(t, ctl, controlURL, "users", "affinity", "clear", e2eHoldAccountKey, "--reason", "e2e hold affinity cleanup")

	output := process.output.String()
	assertNoSecretText(t, output)
	assertOutputOmits(t, output, e2eHoldLogin, e2eHoldOtherLogin, "e2e hold migration", "e2e hold target ready")
}

// TestServerBinaryUserHoldPublicIMAPTimeoutFlow proves max_wait fails closed without placement.
func TestServerBinaryUserHoldPublicIMAPTimeoutFlow(t *testing.T) {
	binary := e2eServerBinary(t)
	ctl := buildDirectorctl(t)
	redisFixture := startValkeySessionStore(t)
	authority := startMappedFakeHTTPAuthority(t, map[string]map[string][]string{
		e2eHoldTimeoutLogin: {
			"account":   {e2eHoldTimeoutKey},
			"tenant":    {e2eTenant},
			"mailShard": {e2eShardTag},
		},
	}, nil)
	fakeBackend := startFakeIMAPBackend(t, fakeBackendOptions{})
	directorAddress := loopbackAddress(t)
	controlAddress := loopbackAddress(t)
	controlURL := "http://" + controlAddress
	configPath := writeProcessConfig(t, processConfigOptions{
		RedisAddress:         redisFixture.addr,
		AuthorityURL:         authority.URL(),
		DirectorAddress:      directorAddress,
		ControlAddress:       controlAddress,
		ControlEnabled:       true,
		BackendAddress:       fakeBackend.Address(),
		BackendAuth:          masterUserBackendAuth(),
		UserHoldMaxWait:      175 * time.Millisecond,
		UserHoldPollInterval: 25 * time.Millisecond,
	})
	process := startDirectorProcess(t, binary, configPath)

	waitForDirectorGreeting(t, directorAddress, process)
	waitForControlReady(t, controlURL, process)

	runDirectorctl(t, ctl, controlURL, "users", "hold", "set", e2eHoldTimeoutKey,
		"--duration", "5s",
		"--reason", "e2e hold timeout")
	pending := beginProcessIMAPLogin(t, directorAddress, e2eHoldTimeoutLogin)
	defer func() { _ = pending.client.Close() }()

	expectIMAPLoginResult(t, pending, "A001 NO [UNAVAILABLE] Authentication service temporarily unavailable\r\n")
	assertNoFakeBackendConnections(t, fakeBackend)
	assertNoRuntimePlacement(t, controlURL)

	timedOutRoute := lookupRoute(t, controlURL, e2eHoldTimeoutKey, true)
	assertRouteLookupUserHoldActive(t, timedOutRoute)

	runDirectorctl(t, ctl, controlURL, "users", "hold", "clear", e2eHoldTimeoutKey, "--reason", "e2e hold timeout cleanup")

	output := process.output.String()
	assertNoSecretText(t, output)
	assertOutputOmits(t, output, e2eHoldTimeoutLogin, "e2e hold timeout")
}

// TestServerBinaryRuntimePaginationUsesSeededRedisState proves generated REST and CLI pagination.
func TestServerBinaryRuntimePaginationUsesSeededRedisState(t *testing.T) {
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
	})
	process := startDirectorProcess(t, binary, configPath)

	waitForControlReady(t, controlURL, process)
	seedProcessRuntimeSessions(t, processRuntimeStore(t, redisFixture.addr), 3)

	first := getSessionListPage(t, controlURL, "2", "")
	if len(first.Sessions) != 2 || first.NextCursor == nil || strings.TrimSpace(*first.NextCursor) == "" {
		t.Fatalf("first REST session page = %#v, want two sessions and cursor", first)
	}
	second := getSessionListPage(t, controlURL, "2", *first.NextCursor)
	if len(second.Sessions) != 1 || second.NextCursor != nil {
		t.Fatalf("second REST session page = %#v, want final single session", second)
	}

	cliFirst := runDirectorctl(t, ctl, controlURL, "sessions", "list", "--limit", "2")
	cliCursor := nextCursorFromCLI(t, cliFirst)
	cliSecond := runDirectorctl(t, ctl, controlURL, "sessions", "list", "--limit", "2", "--cursor", cliCursor)
	if strings.Count(cliFirst, "session_id=") != 2 || strings.Count(cliSecond, "session_id=") != 1 {
		t.Fatalf("CLI session pages = %q / %q, want 2 then 1 sessions", cliFirst, cliSecond)
	}
	if strings.Contains(cliSecond, "more=true") {
		t.Fatalf("second CLI session page still advertised continuation: %q", cliSecond)
	}

	cliUsers := runDirectorctl(t, ctl, controlURL, "users", "list", "--limit", "2", "--all")
	for _, want := range []string{"user_key=e2e-scale-0@example.test", "user_key=e2e-scale-1@example.test", "user_key=e2e-scale-2@example.test"} {
		if !strings.Contains(cliUsers, want) {
			t.Fatalf("CLI users --all output = %q, want %q", cliUsers, want)
		}
	}
	if strings.Contains(cliUsers, "more=true") {
		t.Fatalf("CLI users --all output advertised continuation: %q", cliUsers)
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

// TestServerBinarySieveListenersAndRouteLookup proves Sieve M6.1 wiring through the real process.
func TestServerBinarySieveListenersAndRouteLookup(t *testing.T) {
	binary := e2eServerBinary(t)
	ctl := buildDirectorctl(t)
	redisFixture := startValkeySessionStore(t)
	authority := startFakeHTTPAuthority(t, map[string][]string{
		"account":   {e2eSieveAccount},
		"tenant":    {e2eTenant},
		"mailShard": {e2eShardTag},
	})
	sieveAddress := loopbackAddress(t)
	sievesAddress := loopbackAddress(t)
	controlAddress := loopbackAddress(t)
	controlURL := "http://" + controlAddress
	configPath := writeSieveProcessConfig(t, processConfigOptions{
		RedisAddress:   redisFixture.addr,
		AuthorityURL:   authority.URL(),
		ControlAddress: controlAddress,
		ControlEnabled: true,
	}, sieveAddress, sievesAddress)
	process := startDirectorProcess(t, binary, configPath)

	waitForTCPListener(t, sieveAddress, process)
	waitForTCPListener(t, sievesAddress, process)
	waitForControlReady(t, controlURL, process)

	listOutput := runDirectorctl(t, ctl, controlURL, "listeners", "list")
	assertCLIOutputFields(
		t,
		listOutput,
		"name="+e2eSieveListener+" protocol="+e2eSieveProtocol+" service_name="+e2eSieveService,
		"bound_address="+sieveAddress,
		"name="+e2eSievesListener+" protocol="+e2eSieveProtocol+" service_name="+e2eSievesListener,
		"bound_address="+sievesAddress,
	)

	routeOutput := runDirectorctl(
		t,
		ctl,
		controlURL,
		"route", "lookup",
		"--protocol", e2eSieveProtocol,
		"--user", e2eSieveAccount,
		"--listener", e2eSieveListener,
	)
	assertCLIOutputFields(t, routeOutput, "selected_backend=mailstore-", "routing_source=hash")
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
	markIMAPStartTLS(t, client, reader)
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
	markIMAPStartTLS(t, secondClient, secondReader)
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
	markIMAPStartTLS(t, client, reader)
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

// TestSieveListenersAndRouteLookupPublicBoundaries proves M6.1 listener dispatch over public boundaries.
func TestSieveListenersAndRouteLookupPublicBoundaries(t *testing.T) {
	certPath, keyPath, _ := writeTestCertificate(t)
	redisFixture := startValkeySessionStore(t)
	store := newTrackingSessionStore(redisFixture.store)
	recorder := newCapturedRecorder()
	cfg := e2eSieveConfig(certPath, keyPath)
	selector := mustRuntimeSelector(t, cfg, store)
	manager := startSieveDirector(t, cfg, recorder)
	defer stopListenerManager(t, manager)

	sieveAddress := requireBoundListener(t, manager, e2eSieveListener)
	sievesAddress := requireBoundListener(t, manager, e2eSievesListener)
	assertListenerSnapshot(t, manager, e2eSieveListener, e2eSieveProtocol, "starttls", false)
	assertListenerSnapshot(t, manager, e2eSievesListener, e2eSieveProtocol, "implicit", true)

	sieveConn := dialPlain(t, sieveAddress)
	_ = sieveConn.Close()
	sievesConn := dialPlain(t, sievesAddress)
	_ = sievesConn.Close()

	control := startE2EControlPlane(t, cfg, store, selector, runtimectl.NewLocalSessionRegistry(), recorder, manager)
	defer control.Close()

	ctl := buildDirectorctl(t)
	listOutput := runDirectorctl(t, ctl, control.URL(), "listeners", "list")
	assertCLIOutputFields(
		t,
		listOutput,
		"name="+e2eSieveListener+" protocol="+e2eSieveProtocol+" service_name="+e2eSieveService,
		"bound_address="+sieveAddress,
		"name="+e2eSievesListener+" protocol="+e2eSieveProtocol+" service_name="+e2eSievesListener,
		"bound_address="+sievesAddress,
	)

	route := lookupRouteFor(t, control.URL(), e2eSieveProtocol, e2eSieveListener, e2eSieveAccount, false)
	if route.SelectedBackend != e2eSieveBackendAID && route.SelectedBackend != e2eSieveBackendBID {
		t.Fatalf("sieve route selected backend = %q, want configured sieve backend", route.SelectedBackend)
	}

	routeOutput := runDirectorctl(
		t,
		ctl,
		control.URL(),
		"route", "lookup",
		"--protocol", e2eSieveProtocol,
		"--user", e2eSieveAccount,
		"--listener", e2eSieveListener,
	)
	assertCLIOutputFields(t, routeOutput, "selected_backend="+route.SelectedBackend, "routing_source=hash")
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
		AuthorityContextHTTPHeaders: map[string]string{
			e2eContextHeader: e2eContextHTTPValue,
		},
		AuthorityURL: authority.URL(),
		BackendAuth:  masterUserBackendAuth(),
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
	if authority.RequestCount() != 0 {
		t.Fatal("initial route lookup called the fake Nauthilus authority")
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
	authority.ExpectContextHeader(t, e2eContextHeader, e2eContextHTTPValue)
	rawRoute := lookupRouteRaw(t, control.URL(), e2eProtocol, e2eListenerName, e2eAccount, true)
	assertOutputOmitsAuthorityContext(t, rawRoute, e2eContextHTTPValue)
	routeOutput := runDirectorctl(
		t,
		ctl,
		control.URL(),
		"route", "lookup",
		"--protocol", e2eProtocol,
		"--user", e2eAccount,
		"--listener", e2eListenerName,
		"--include-affinity",
	)
	assertOutputOmitsAuthorityContext(t, routeOutput, e2eContextHTTPValue)

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

	retained := lookupRoute(t, control.URL(), e2eAccount, true)
	if retained.SelectedBackend != otherID || retained.Source != "retained_backend_binding" {
		t.Fatalf("retained route selected %q source=%q, want retained backend %q", retained.SelectedBackend, retained.Source, otherID)
	}
	deleteAccepted(t, clearPath, generated.RuntimeReasonRequest{Reason: "clear retained weighted binding"})

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
	recorder.AssertOmits(t, e2eContextHTTPValue)
}

type directorOptions struct {
	Authenticator               nauthilus.Authenticator
	AuthorityContextHTTPHeaders map[string]string
	AuthorityURL                string
	BackendAuth                 backend.AuthConfig
	BackendAddress              string
	BackendAddresses            map[string]string
	BackendMaxSessions          map[string]int
	BackendSelector             backend.Selector
	BackendShards               map[string]string
	BackendTLS                  config.BackendTLSConfig
	FrontendTLSConfig           *tls.Config
	ListenerCertPath            string
	ListenerKeyPath             string
	LocalSessions               *runtimectl.LocalSessionRegistry
	ProxyIdleTimeout            time.Duration
	Recorder                    observability.Recorder
	SessionLeaseTTL             time.Duration
	SessionStore                state.SessionStore
	TLSMode                     string
	UsePlacementStubs           bool
	UseProxyRunnerStub          bool
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
	RedisAddress           string
	AuthorityURL           string
	AuthorityOIDC          processAuthorityOIDCOptions
	DirectorAddress        string
	ControlAddress         string
	ControlEnabled         bool
	BackendAddress         string
	BackendHAProxy         bool
	BackendHealthEnabled   bool
	BackendHealthDeepCheck bool
	BackendTLS             config.BackendTLSConfig
	BackendAuth            backend.AuthConfig
	UserHoldMaxWait        time.Duration
	UserHoldPollInterval   time.Duration
}

type processAuthorityOIDCOptions struct {
	Enabled                 bool
	Issuer                  string
	ClientID                string
	ClientSecret            string
	ClientSecretFile        string
	TokenEndpointAuthMethod string
	Scopes                  []string
}

type processBackendDefinition struct {
	Identifier      string
	Address         string
	Shard           string
	Weight          int
	HAProxy         bool
	HealthEnabled   bool
	HealthDeepCheck bool
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

// waitForTCPListener waits until a process exposes one public TCP listener.
func waitForTCPListener(t *testing.T, address string, process *directorProcess) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()

			return
		}

		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("director process did not expose TCP listener at %s:\n%s", address, process.output.String())
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
    value: [imaps, lmtp, lmtps, sieve, sieves, pop3, pop3s]
  - op: remove
    path: director.backend_pools
    value: [lmtp-default, sieve-default, pop3-default]
  - op: remove
    path: director.backends
    value: [mailstore-b-imap, mailstore-a-lmtp, mailstore-b-lmtp, mailstore-a-sieve, mailstore-b-sieve, mailstore-a-pop3, mailstore-b-pop3]
runtime:
  instance_name: "e2e-director"
  process:
    shutdown_timeout: 2s
  servers:
    control:
      enabled: %t
      address: %q
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
    key_prefix: %q
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
      transport: http
%s
      http:
        endpoint: %q
        basic_auth:
          password_file: "unused"
director:
  health:
    interval: 200ms
    timeout: 1s
    jitter: 0s
    unhealthy_after: 1
    healthy_after: 1
%s
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
      haproxy:
        enabled: %t
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
        enabled: %t
        deep_check: %t
        username: healthcheck@example.test
        password_file: %q
	`, options.ControlEnabled,
		controlAddress,
		processControlAuthYAML(t),
		e2eProcessKeyPrefix,
		options.RedisAddress,
		processAuthorityOIDCYAMLForOptions(t, options.AuthorityOIDC),
		options.AuthorityURL,
		processUserHoldConfigYAML(options),
		options.DirectorAddress,
		listenerCertPath,
		listenerKeyPath,
		options.BackendAddress,
		e2eShardTag,
		options.BackendHAProxy,
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
		options.BackendHealthEnabled,
		options.BackendHealthDeepCheck,
		e2ePassword,
	)
	content = strings.ReplaceAll(content, "\t", "")

	path := filepath.Join(t.TempDir(), "nauthilus-director.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write process config: %v", err)
	}

	return path
}

// writeSieveProcessConfig writes a real-process config with STARTTLS and implicit Sieve listeners.
func writeSieveProcessConfig(t *testing.T, options processConfigOptions, sieveAddress string, sievesAddress string) string {
	t.Helper()

	controlAddress := options.ControlAddress
	if controlAddress == "" {
		controlAddress = "127.0.0.1:0"
	}
	listenerCertPath, listenerKeyPath, _ := writeTestCertificate(t)
	backendAuth := masterUserBackendAuth()

	content := fmt.Sprintf(`patch:
  - op: remove
    path: director.listeners
    value: [imap, imaps, lmtp, lmtps, pop3, pop3s]
  - op: remove
    path: director.backend_pools
    value: [imap-default, lmtp-default, pop3-default]
  - op: remove
    path: director.backends
    value: [mailstore-a-imap, mailstore-b-imap, mailstore-a-lmtp, mailstore-b-lmtp, mailstore-a-pop3, mailstore-b-pop3]
runtime:
  instance_name: "e2e-director"
  process:
    shutdown_timeout: 2s
  servers:
    control:
      enabled: %t
      address: %q
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
    key_prefix: %q
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
      transport: http
%s
      http:
        endpoint: %q
        basic_auth:
          password_file: "unused"
director:
  health:
    interval: 200ms
    timeout: 1s
    jitter: 0s
    unhealthy_after: 1
    healthy_after: 1
  listeners:
    sieve:
      protocol: sieve
      service_name: sieve
      network: tcp
      address: %q
      authority: default
      backend_pool: sieve-default
      tls:
        mode: starttls
        cert: %q
        key: %q
      sieve:
        auth_mechanisms: [plain]
        capabilities:
          script_extensions: []
          language: en
    sieves:
      protocol: sieve
      service_name: sieves
      network: tcp
      address: %q
      authority: default
      backend_pool: sieve-default
      tls:
        mode: implicit
        cert: %q
        key: %q
      sieve:
        auth_mechanisms: [plain]
        capabilities:
          script_extensions: []
          language: en
  backend_pools:
    sieve-default:
      protocol: sieve
      selector: rendezvous_hash
      backends: [mailstore-a-sieve, mailstore-b-sieve]
  backends:
    mailstore-a-sieve:
      protocol: sieve
      shard_tag: %q
      backend_node: mailstore-a-node-1
      address: "127.0.0.1:1"
      weight: 100
      max_connections: 100
      maintenance: disabled
      tls:
        mode: starttls
        server_name: mailstore-a-sieve.example.test
        min_tls_version: TLS1.2
      auth:
        mode: %q
        master_user:
          username: %q
          password_file: %q
          user_format: %q
          mechanism: %q
      health_check:
        enabled: false
    mailstore-b-sieve:
      protocol: sieve
      shard_tag: %q
      backend_node: mailstore-b-node-1
      address: "127.0.0.1:2"
      weight: 100
      max_connections: 100
      maintenance: disabled
      tls:
        mode: starttls
        server_name: mailstore-b-sieve.example.test
        min_tls_version: TLS1.2
      auth:
        mode: %q
        master_user:
          username: %q
          password_file: %q
          user_format: %q
          mechanism: %q
      health_check:
        enabled: false
	`, options.ControlEnabled,
		controlAddress,
		processControlAuthYAML(t),
		e2eProcessKeyPrefix,
		options.RedisAddress,
		processAuthorityOIDCYAMLForOptions(t, options.AuthorityOIDC),
		options.AuthorityURL,
		sieveAddress,
		listenerCertPath,
		listenerKeyPath,
		sievesAddress,
		listenerCertPath,
		listenerKeyPath,
		e2eShardTag,
		backendAuth.Mode,
		backendAuth.MasterUser.Username,
		backendAuth.MasterUser.Password.Value(),
		backendAuth.MasterUser.UserFormat,
		backendAuth.MasterUser.Mechanism,
		e2eShardTag,
		backendAuth.Mode,
		backendAuth.MasterUser.Username,
		backendAuth.MasterUser.Password.Value(),
		backendAuth.MasterUser.UserFormat,
		backendAuth.MasterUser.Mechanism,
	)
	content = strings.ReplaceAll(content, "\t", "")

	path := filepath.Join(t.TempDir(), "nauthilus-director-sieve.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write sieve process config: %v", err)
	}

	return path
}

// writeBackendPinProcessConfig writes a real-process config with one IMAP pool and explicit backend weights.
func writeBackendPinProcessConfig(t *testing.T, options processConfigOptions, backends []processBackendDefinition) string {
	t.Helper()

	if len(backends) == 0 {
		t.Fatal("backend-pin process config requires backends")
	}

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
	backends = sortedProcessBackends(backends)

	content := fmt.Sprintf(`patch:
  - op: remove
    path: director.listeners
    value: [imaps, lmtp, lmtps, sieve, sieves, pop3, pop3s]
  - op: remove
    path: director.backend_pools
    value: [lmtp-default, sieve-default, pop3-default]
  - op: remove
    path: director.backends
    value: [mailstore-a-lmtp, mailstore-b-lmtp, mailstore-a-sieve, mailstore-b-sieve, mailstore-a-pop3, mailstore-b-pop3]
runtime:
  instance_name: "e2e-director"
  process:
    shutdown_timeout: 2s
  servers:
    control:
      enabled: %t
      address: %q
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
    key_prefix: %q
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
      transport: http
%s
      http:
        endpoint: %q
        basic_auth:
          password_file: "unused"
director:
  health:
    interval: 200ms
    timeout: 1s
    jitter: 0s
    unhealthy_after: 1
    healthy_after: 1
%s
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
      protocol: imap
      selector: rendezvous_hash
      backends: [%s]
  backends:
	%s`, options.ControlEnabled,
		controlAddress,
		processControlAuthYAML(t),
		e2eProcessKeyPrefix,
		options.RedisAddress,
		processAuthorityOIDCYAMLForOptions(t, options.AuthorityOIDC),
		options.AuthorityURL,
		processUserHoldConfigYAML(options),
		options.DirectorAddress,
		listenerCertPath,
		listenerKeyPath,
		quotedYAMLStrings(processBackendIdentifiers(backends)),
		processBackendConfigYAML(backends, backendTLS, backendAuth),
	)
	content = strings.ReplaceAll(content, "\t", "")

	path := filepath.Join(t.TempDir(), "nauthilus-director.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write backend-pin process config: %v", err)
	}

	return path
}

// sortedProcessBackends returns backend definitions by identifier for stable YAML.
func sortedProcessBackends(backends []processBackendDefinition) []processBackendDefinition {
	sorted := append([]processBackendDefinition(nil), backends...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Identifier < sorted[j].Identifier
	})

	return sorted
}

// processBackendIdentifiers returns sorted backend identifiers for a YAML pool list.
func processBackendIdentifiers(backends []processBackendDefinition) []string {
	identifiers := make([]string, 0, len(backends))
	for _, configured := range backends {
		identifiers = append(identifiers, configured.Identifier)
	}

	return identifiers
}

// processUserHoldConfigYAML renders optional hold timing overrides for process E2E.
func processUserHoldConfigYAML(options processConfigOptions) string {
	if options.UserHoldMaxWait <= 0 && options.UserHoldPollInterval <= 0 {
		return ""
	}

	maxWait := options.UserHoldMaxWait
	if maxWait <= 0 {
		maxWait = 30 * time.Second
	}
	pollInterval := options.UserHoldPollInterval
	if pollInterval <= 0 {
		pollInterval = 250 * time.Millisecond
	}

	return fmt.Sprintf(`  affinity:
    user_holds:
      enabled: true
      max_duration: %q
      max_wait: %q
      poll_interval: %q
      max_local_waiters: 1024
      max_local_waiters_per_user: 16
`, (30 * time.Minute).String(), maxWait.String(), pollInterval.String())
}

// processBackendConfigYAML renders backend definitions for the real-process fixture.
func processBackendConfigYAML(
	backends []processBackendDefinition,
	backendTLS config.BackendTLSConfig,
	backendAuth backend.AuthConfig,
) string {
	var builder strings.Builder
	for _, configured := range backends {
		shard := strings.TrimSpace(configured.Shard)
		if shard == "" {
			shard = e2eShardTag
		}

		fmt.Fprintf(&builder, `    %s:
      protocol: imap
      address: %q
      shard_tag: %q
      weight: %d
      max_connections: 100
      maintenance: disabled
      haproxy:
        enabled: %t
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
        enabled: %t
        deep_check: %t
        username: healthcheck@example.test
        password_file: %q
`, configured.Identifier,
			configured.Address,
			shard,
			configured.Weight,
			configured.HAProxy,
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
			configured.HealthEnabled,
			configured.HealthDeepCheck,
			e2ePassword,
		)
	}

	return builder.String()
}

// processRuntimeStore creates a Redis store using the real-process key prefix.
func processRuntimeStore(t *testing.T, redisAddress string) *state.RedisSessionStore {
	t.Helper()

	client := redis.NewClient(&redis.Options{Addr: redisAddress, Protocol: 2})
	t.Cleanup(func() { _ = client.Close() })
	builder, err := state.NewKeyBuilder(state.KeyBuilderOptions{Prefix: e2eProcessKeyPrefix, SchemaVersion: 1})
	if err != nil {
		t.Fatalf("NewKeyBuilder: %v", err)
	}
	store, err := state.NewRedisSessionStore(client, builder, nil)
	if err != nil {
		t.Fatalf("NewRedisSessionStore: %v", err)
	}

	return store
}

// seedProcessRuntimeSessions writes active runtime state for real-binary control reads.
func seedProcessRuntimeSessions(t *testing.T, store *state.RedisSessionStore, count int) {
	t.Helper()

	for index := range count {
		user := fmt.Sprintf("e2e-scale-%d@example.test", index)
		sessionID := fmt.Sprintf("e2e-scale-session-%d", index)
		key := state.AffinityKey{Tenant: e2eTenant, AccountKey: user}
		record := state.SessionRecord{
			ID:                 sessionID,
			Key:                key,
			Protocol:           e2eProtocol,
			ListenerName:       e2eListenerName,
			ServiceName:        e2eService,
			ShardTag:           e2eShardTag,
			DirectorInstanceID: "e2e-scale-director",
			LeaseTTL:           5 * time.Minute,
			IdleGrace:          time.Minute,
		}
		if _, err := store.OpenSession(context.Background(), record); err != nil {
			t.Fatalf("OpenSession %s: %v", sessionID, err)
		}

		attachProcessRuntimeBackend(t, store, key, sessionID)
	}
}

// attachProcessRuntimeBackend reserves and attaches one backend slot for a seeded session.
func attachProcessRuntimeBackend(t *testing.T, store *state.RedisSessionStore, key state.AffinityKey, sessionID string) {
	t.Helper()

	reservationID := "reservation-" + sessionID
	if _, err := store.ReserveBackendCapacity(context.Background(), state.BackendReservationRequest{
		BackendIdentifier: e2eBackendAID,
		ReservationID:     reservationID,
		MaxConnections:    100,
		LeaseTTL:          5 * time.Minute,
	}); err != nil {
		t.Fatalf("ReserveBackendCapacity %s: %v", sessionID, err)
	}
	if _, err := store.AttachSelectedBackend(context.Background(), state.SessionBackendAttachment{
		Key:               key,
		SessionID:         sessionID,
		BackendIdentifier: e2eBackendAID,
		ReservationID:     reservationID,
		MaxConnections:    100,
	}); err != nil {
		t.Fatalf("AttachSelectedBackend %s: %v", sessionID, err)
	}
}

// quotedYAMLStrings renders a small inline string sequence.
func quotedYAMLStrings(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, fmt.Sprintf("%q", value))
	}

	return strings.Join(quoted, ", ")
}

// listenerAuthorityContextYAML renders optional listener authority context maps.
func listenerAuthorityContextYAML(httpHeaders map[string]string, grpcMetadata map[string]string) string {
	if len(httpHeaders) == 0 && len(grpcMetadata) == 0 {
		return ""
	}

	var builder strings.Builder
	builder.WriteString("      authority_context:\n")
	appendAuthorityContextMapYAML(&builder, "http_headers", httpHeaders)
	appendAuthorityContextMapYAML(&builder, "grpc_metadata", grpcMetadata)

	return builder.String()
}

// appendAuthorityContextMapYAML renders one listener context map in stable order.
func appendAuthorityContextMapYAML(builder *strings.Builder, name string, values map[string]string) {
	if len(values) == 0 {
		fmt.Fprintf(builder, "        %s: {}\n", name)

		return
	}

	fmt.Fprintf(builder, "        %s:\n", name)
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(builder, "          %s: %q\n", key, values[key])
	}
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
	registry := mustBackendRegistry(t, cfg)
	selector := options.BackendSelector
	if selector == nil {
		selector = mustBackendSelectorWithRegistry(t, registry)
	}
	placementService := placement.SessionPlacer(nil)
	if !options.UsePlacementStubs {
		placementStore, ok := store.(placement.StateStore)
		if !ok {
			t.Fatalf("session store %T does not implement placement state", store)
		}
		service, err := placement.NewService(registry, selector, placementStore)
		if err != nil {
			t.Fatalf("NewPlacementService: %v", err)
		}
		placementService = service
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

	managerOptions := []listener.ManagerOption{
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
				PlacementService:       placementService,
				BackendConnector:       imap.NewTCPBackendConnector(nil),
				ProxyRunner:            proxyRunner,
				LocalSessions:          options.LocalSessions,
				Observability:          options.Recorder,
			}
			if options.UsePlacementStubs {
				sessionConfig.RoutingResolver = nil
				sessionConfig.SessionStore = nil
				sessionConfig.PlacementService = nil
			}

			return imap.NewHandler(sessionConfig)
		}),
	}
	if options.Authenticator != nil {
		managerOptions = append([]listener.ManagerOption{
			listener.WithNauthilusClientFactory(func(
				config.AuthorityConfig,
				nauthilus.ClientOptions,
			) (nauthilus.Authenticator, error) {
				return options.Authenticator, nil
			}),
		}, managerOptions...)
	}

	manager, err := listener.NewManagerWithConfig(cfg, managerOptions...)
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

// startSieveDirector starts only M6.1 ManageSieve listeners over the shared manager path.
func startSieveDirector(t *testing.T, cfg config.Config, recorder observability.Recorder) *listener.Manager {
	t.Helper()

	manager, err := listener.NewManagerWithConfig(
		cfg,
		listener.WithNauthilusClientFactory(func(
			config.AuthorityConfig,
			nauthilus.ClientOptions,
		) (nauthilus.Authenticator, error) {
			return unavailableAuthenticator{}, nil
		}),
		listener.WithObservabilityRecorder(recorder),
		listener.WithSessionHandlerFactory(func(listenerOptions listener.SessionOptions) listener.SessionHandler {
			if listenerOptions.Config.Sieve == nil {
				t.Fatalf("listener %q missing sieve config", listenerOptions.ListenerName)
			}

			capabilities := listenerOptions.Config.Sieve.Capabilities

			return sieve.NewHandler(sieve.SessionConfig{
				ListenerName:   listenerOptions.ListenerName,
				ServiceName:    listenerOptions.Config.ServiceName,
				Network:        listenerOptions.Config.Network,
				BackendPool:    listenerOptions.Config.BackendPool,
				TLSMode:        listenerOptions.Config.TLS.Mode,
				AuthMechanisms: listenerOptions.Config.Sieve.AuthMechanisms,
				Capabilities: sieve.CapabilitiesConfig{
					Implementation:   sieve.ImplementationCapability("e2e"),
					ProtocolVersion:  sieve.ProtocolVersionRFC5804,
					ScriptExtensions: capabilities.ScriptExtensions,
					Language:         capabilities.Language,
				},
			})
		}),
	)
	if err != nil {
		t.Fatalf("NewManagerWithConfig: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := manager.Start(ctx); err != nil {
		t.Fatalf("start sieve director: %v", err)
	}

	return manager
}

// stopListenerManager stops one test manager through the production lifecycle.
func stopListenerManager(t *testing.T, manager *listener.Manager) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := manager.Stop(ctx); err != nil {
		t.Fatalf("stop listener manager: %v", err)
	}
}

// requireBoundListener returns the bound public address for one listener.
func requireBoundListener(t *testing.T, manager *listener.Manager, name string) string {
	t.Helper()

	address, ok := manager.BoundAddress(name)
	if !ok {
		t.Fatalf("listener %q did not expose a bound address", name)
	}

	return address
}

// assertListenerSnapshot verifies shared listener runtime state for one protocol.
func assertListenerSnapshot(t *testing.T, manager *listener.Manager, name string, protocol string, tlsMode string, implicit bool) {
	t.Helper()

	for _, snapshot := range manager.Snapshots() {
		if snapshot.Name != name {
			continue
		}
		if snapshot.Protocol != protocol || snapshot.TLSMode != tlsMode || snapshot.ImplicitTLS != implicit {
			t.Fatalf("listener snapshot = %#v, want protocol=%s tls=%s implicit=%t", snapshot, protocol, tlsMode, implicit)
		}

		return
	}

	t.Fatalf("listener %q missing from snapshots", name)
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
	listenerConfig.AuthorityContext.HTTPHeaders = authorityContextConfigValues(options.AuthorityContextHTTPHeaders)
	cfg.Director.Listeners = map[string]config.ListenerConfig{e2eListenerName: listenerConfig}
	if strings.TrimSpace(options.AuthorityURL) != "" {
		authority := cfg.Auth.Authorities["default"]
		authority.Transport = "http"
		authority.OIDC.Enabled = false
		authority.OIDC.ClientCredentials.Enabled = false
		authority.HTTP.Endpoint = options.AuthorityURL
		cfg.Auth.Authorities["default"] = authority
	}

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

// authorityContextConfigValues maps test strings into typed listener context values.
func authorityContextConfigValues(values map[string]string) map[string]config.AuthorityContextValue {
	if len(values) == 0 {
		return map[string]config.AuthorityContextValue{}
	}

	configured := make(map[string]config.AuthorityContextValue, len(values))
	for name, value := range values {
		configured[name] = config.AuthorityContextValue(value)
	}

	return configured
}

// e2eSieveConfig builds a narrow typed config for public STARTTLS and implicit ManageSieve listeners.
func e2eSieveConfig(certPath string, keyPath string) config.Config {
	cfg := config.DefaultConfig()
	sieveListener := cfg.Director.Listeners[e2eSieveListener]
	sieveListener.Address = "127.0.0.1:0"
	sieveListener.TLS.Mode = "starttls"
	sieveListener.TLS.Cert = certPath
	sieveListener.TLS.Key = config.Secret(keyPath)

	sievesListener := cfg.Director.Listeners[e2eSievesListener]
	sievesListener.Address = "127.0.0.1:0"
	sievesListener.TLS.Mode = "implicit"
	sievesListener.TLS.Cert = certPath
	sievesListener.TLS.Key = config.Secret(keyPath)
	cfg.Director.Listeners = map[string]config.ListenerConfig{
		e2eSieveListener:  sieveListener,
		e2eSievesListener: sievesListener,
	}
	cfg.Director.BackendPools = map[string]config.BackendPoolConfig{
		e2eSieveBackendPool: {
			Protocol: e2eSieveProtocol,
			Selector: "rendezvous_hash",
			Backends: []string{e2eSieveBackendAID, e2eSieveBackendBID},
		},
	}
	cfg.Director.Backends = map[string]config.BackendConfig{
		e2eSieveBackendAID: e2eSieveBackendConfig(e2eSieveBackendAID, "127.0.0.1:1"),
		e2eSieveBackendBID: e2eSieveBackendConfig(e2eSieveBackendBID, "127.0.0.1:2"),
	}

	return cfg
}

// e2eSieveBackendConfig creates a verified-TLS backend entry without opening sockets.
func e2eSieveBackendConfig(identifier string, address string) config.BackendConfig {
	return config.BackendConfig{
		Protocol:       e2eSieveProtocol,
		ShardTag:       e2eShardTag,
		Address:        address,
		Weight:         100,
		MaxConnections: 100,
		Maintenance:    "disabled",
		TLS: config.BackendTLSConfig{
			Mode:          "starttls",
			ServerName:    identifier + ".example.test",
			MinTLSVersion: "TLS1.2",
		},
		Auth: backendAuthConfig(masterUserBackendAuth()),
		HealthCheck: config.BackendHealthConfig{
			Enabled: false,
		},
	}
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

	return mustBackendSelectorWithRegistry(t, registry)
}

// mustBackendRegistry creates the production static backend registry for E2E.
func mustBackendRegistry(t *testing.T, cfg config.Config) backend.Registry {
	t.Helper()

	registry, err := backend.NewStaticRegistry(cfg.Director)
	if err != nil {
		t.Fatalf("NewStaticRegistry: %v", err)
	}

	return registry
}

// mustBackendSelectorWithRegistry creates the production static selector over a registry.
func mustBackendSelectorWithRegistry(t *testing.T, registry backend.Registry) backend.Selector {
	t.Helper()

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

// ListSessions returns one bounded active-session page for the REST control API.
func (s *trackingSessionStore) ListSessions(_ context.Context, request runtimectl.SessionListRequest) (runtimectl.SessionListResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	protocol := strings.ToLower(strings.TrimSpace(request.Protocol))
	backendID := strings.TrimSpace(request.BackendIdentifier)
	sessions := make([]runtimectl.SessionRuntimeState, 0, len(s.sessions))
	for _, session := range s.sessions {
		if protocol != "" && session.Protocol != protocol {
			continue
		}
		if backendID != "" && session.BackendIdentifier != backendID {
			continue
		}
		sessions = append(sessions, session.Normalize())
	}

	sort.Slice(sessions, func(left int, right int) bool {
		return sessions[left].SessionID < sessions[right].SessionID
	})

	start, limit, err := trackingListWindow(request.Cursor, request.Limit)
	if err != nil {
		return runtimectl.SessionListResult{}, err
	}

	if start > len(sessions) {
		start = len(sessions)
	}
	end := min(start+limit, len(sessions))
	nextCursor := ""
	if end < len(sessions) {
		nextCursor = strconv.Itoa(end)
	}

	return runtimectl.SessionListResult{Sessions: sessions[start:end], NextCursor: nextCursor}, nil
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

// ListUsers returns one bounded user page for the REST control API.
func (s *trackingSessionStore) ListUsers(_ context.Context, request runtimectl.UserListRequest) (runtimectl.UserListResult, error) {
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

	sort.Slice(result, func(left int, right int) bool {
		return result[left].Key.UserHash < result[right].Key.UserHash
	})

	start, limit, err := trackingListWindow(request.Cursor, request.Limit)
	if err != nil {
		return runtimectl.UserListResult{}, err
	}

	if start > len(result) {
		start = len(result)
	}
	end := min(start+limit, len(result))
	nextCursor := ""
	if end < len(result) {
		nextCursor = strconv.Itoa(end)
	}

	return runtimectl.UserListResult{Users: result[start:end], NextCursor: nextCursor}, nil
}

// trackingListWindow converts fake REST cursors into bounded slice windows.
func trackingListWindow(cursor string, requestedLimit int) (int, int, error) {
	limit := requestedLimit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		return 0, 0, &runtimectl.Error{Kind: runtimectl.ErrorKindInvalidRequest, Operation: "list", Message: "limit must not exceed 1000"}
	}

	start := 0
	if strings.TrimSpace(cursor) != "" {
		parsed, err := strconv.Atoi(strings.TrimSpace(cursor))
		if err != nil || parsed < 0 {
			return 0, 0, &runtimectl.Error{Kind: runtimectl.ErrorKindInvalidRequest, Operation: "list", Message: "cursor invalid"}
		}
		start = parsed
	}

	return start, limit, nil
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
	listenerManagers ...runtimectl.ListenerManager,
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
		Resolver:         mustRoutingResolver(t),
		Selector:         selector,
		BackendRead:      reader,
		AffinityRead:     store,
		ListenerContexts: routeLookupListenerContextsFromConfig(cfg),
		DefaultPool:      routeLookupDefaultPool(cfg),
		DefaultShard:     e2eShardTag,
		DefaultTenant:    e2eTenant,
		Observability:    recorder,
	})
	if err != nil {
		t.Fatalf("NewRouteLookupService: %v", err)
	}

	reload := &switchingReloadService{current: cfg, next: cfg, recorder: recorder}
	audit := &recordingProtectedConfigAudit{}
	var listenerRuntime adapters.ListenerRuntimeService
	if len(listenerManagers) > 0 && listenerManagers[0] != nil {
		listenerRuntime = runtimectl.NewListenerService(listenerManagers[0], runtimectl.WithObservabilityRecorder(recorder))
	}
	server := rest.NewServer(rest.Options{HandlerOptions: adapters.HandlerOptions{
		BackendReader:             reader,
		BackendMutator:            runtimectl.NewBackendService(store, localSessions, runtimectl.WithObservabilityRecorder(recorder)),
		SessionReader:             store,
		SessionMutator:            runtimectl.NewSessionService(store, localSessions, runtimectl.WithObservabilityRecorder(recorder)),
		UserReader:                store,
		UserMutator:               runtimectl.NewUserService(store, localSessions, runtimectl.WithObservabilityRecorder(recorder)),
		RouteLookup:               lookup,
		ListenerRuntime:           listenerRuntime,
		Reload:                    reload,
		Observability:             recorder,
		ProtectedConfigAudit:      audit,
		ProtectedConfigAuthorizer: deniedProtectedConfigAuthorizer{},
	}, Control: e2eControlServerConfig(t, cfg.Runtime.Servers.Control)})

	return &e2eControlPlane{
		server: httptest.NewServer(server),
		audit:  audit,
		reload: reload,
	}
}

// e2eControlServerConfig configures public control E2E calls with static bearer auth.
func e2eControlServerConfig(t *testing.T, base config.ControlServerConfig) config.ControlServerConfig {
	t.Helper()

	base.Auth.Bearer.Enabled = true
	base.Auth.Bearer.TokenFile = config.Secret(writeE2EControlTokenFile(t))
	base.Auth.OIDC.Enabled = false
	base.Auth.MTLS.Enabled = false

	return base
}

// writeE2EControlTokenFile writes the mounted secret used by E2E control calls.
func writeE2EControlTokenFile(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "control-token")
	if err := os.WriteFile(path, []byte(e2eToken+"\n"), 0o600); err != nil {
		t.Fatalf("write control token file: %v", err)
	}

	return path
}

// processControlAuthYAML renders the static bearer auth expected by real-process E2E calls.
func processControlAuthYAML(t *testing.T) string {
	t.Helper()

	return fmt.Sprintf(`      auth:
        bearer:
          enabled: true
          token_file: %q
        oidc:
          enabled: false
        mtls:
          enabled: false
`, writeE2EControlTokenFile(t))
}

// processAuthorityOIDCYAML disables caller-token acquisition for fake HTTP authorities.
func processAuthorityOIDCYAML() string {
	return `      oidc:
        enabled: false
        client_credentials:
          enabled: false
`
}

// processAuthorityOIDCYAMLForOptions renders optional OIDC caller auth for real-process fixtures.
func processAuthorityOIDCYAMLForOptions(t *testing.T, options processAuthorityOIDCOptions) string {
	t.Helper()

	if !options.Enabled {
		return processAuthorityOIDCYAML()
	}

	clientID := strings.TrimSpace(options.ClientID)
	if clientID == "" {
		clientID = e2eOIDCClientID
	}
	clientSecretFile := strings.TrimSpace(options.ClientSecretFile)
	if clientSecretFile == "" {
		clientSecret := options.ClientSecret
		if clientSecret == "" {
			clientSecret = e2eOIDCClientSecret
		}
		clientSecretFile = writeProcessOIDCSecretFile(t, clientSecret)
	}
	method := strings.TrimSpace(options.TokenEndpointAuthMethod)
	if method == "" {
		method = "client_secret_basic"
	}
	scopes := options.Scopes
	if len(scopes) == 0 {
		scopes = []string{e2eOIDCScopeAuth, e2eOIDCScopeLookup, e2eOIDCScopeList}
	}

	return fmt.Sprintf(`      oidc:
        enabled: true
        authority_mode: nauthilus
        issuer_hint: ""
        issuer: %q
        discovery_url: ""
        audience_hint: ""
        required_scopes: []
        client_credentials:
          enabled: true
          client_id: %q
          client_secret: ""
          client_secret_file: %q
          token_endpoint_auth_method: %q
          introspection_endpoint_auth_method: %q
          client_private_key_file: ""
          client_key_id: ""
          client_assertion_alg: ""
          audience: ""
          scopes: [%s]
          refresh_before_expiry: 30s
          token_endpoint: ""
`, strings.TrimRight(strings.TrimSpace(options.Issuer), "/"),
		clientID,
		clientSecretFile,
		method,
		method,
		quotedYAMLStrings(scopes),
	)
}

// writeProcessOIDCSecretFile writes the authority client secret used by OIDC process fixtures.
func writeProcessOIDCSecretFile(t *testing.T, clientSecret string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "oidc-client-secret")
	if err := os.WriteFile(path, []byte(clientSecret+"\n"), 0o600); err != nil {
		t.Fatalf("write OIDC client secret: %v", err)
	}

	return path
}

// processAuthorityOIDCForFake returns a real-process OIDC config for the fake Nauthilus issuer.
func processAuthorityOIDCForFake(authority *fakeHTTPAuthority, scopes []string) processAuthorityOIDCOptions {
	return processAuthorityOIDCOptions{
		Enabled:      true,
		Issuer:       authority.Issuer(),
		ClientID:     e2eOIDCClientID,
		ClientSecret: e2eOIDCClientSecret,
		Scopes:       scopes,
	}
}

// routeLookupListenerContextsFromConfig projects configured listeners into route lookup contexts.
func routeLookupListenerContextsFromConfig(cfg config.Config) []runtimectl.RouteLookupListenerContext {
	names := make([]string, 0, len(cfg.Director.Listeners))
	for name := range cfg.Director.Listeners {
		names = append(names, name)
	}
	sort.Strings(names)

	contexts := make([]runtimectl.RouteLookupListenerContext, 0, len(names))
	for _, name := range names {
		listenerConfig := cfg.Director.Listeners[name]
		contexts = append(contexts, runtimectl.RouteLookupListenerContext{
			Name:        name,
			Protocol:    listenerConfig.Protocol,
			ServiceName: listenerConfig.ServiceName,
			BackendPool: listenerConfig.BackendPool,
		})
	}

	return contexts
}

// routeLookupDefaultPool returns the deterministic default pool for one narrow E2E config.
func routeLookupDefaultPool(cfg config.Config) string {
	if _, ok := cfg.Director.BackendPools[e2eBackendPool]; ok {
		return e2eBackendPool
	}
	if _, ok := cfg.Director.BackendPools[e2eSieveBackendPool]; ok {
		return e2eSieveBackendPool
	}

	names := make([]string, 0, len(cfg.Director.BackendPools))
	for name := range cfg.Director.BackendPools {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return ""
	}

	return names[0]
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

	return lookupRouteFor(t, baseURL, e2eProtocol, e2eListenerName, userKey, includeAffinity)
}

// lookupRouteFor posts one public route lookup request for an explicit protocol and listener.
func lookupRouteFor(
	t *testing.T,
	baseURL string,
	protocol string,
	listener string,
	userKey string,
	includeAffinity bool,
) generated.RouteLookupResponse {
	t.Helper()

	listenerName := listener
	body := generated.LookupRouteJSONRequestBody{
		IncludeAffinity: &includeAffinity,
		Listener:        &listenerName,
		Protocol:        protocol,
		UserKey:         &userKey,
	}

	var response generated.RouteLookupResponse
	requestJSON(t, http.MethodPost, baseURL+"/api/v1/route/lookup", body, http.StatusOK, &response)

	return response
}

// lookupRouteRaw returns the public route lookup body for output leak checks.
func lookupRouteRaw(
	t *testing.T,
	baseURL string,
	protocol string,
	listener string,
	userKey string,
	includeAffinity bool,
) string {
	t.Helper()

	listenerName := listener
	body := generated.LookupRouteJSONRequestBody{
		IncludeAffinity: &includeAffinity,
		Listener:        &listenerName,
		Protocol:        protocol,
		UserKey:         &userKey,
	}
	data := requestJSONData(t, http.MethodPost, baseURL+"/api/v1/route/lookup", body, http.StatusOK)

	return string(data)
}

// assertRouteLookupUserHoldActive verifies read-only hold diagnostics.
func assertRouteLookupUserHoldActive(t *testing.T, response generated.RouteLookupResponse) {
	t.Helper()

	if !response.AffectedBy.UserHold ||
		!response.UserHold.Present ||
		!response.UserHold.PlacementDeferred ||
		response.UserHold.Reason != "user_hold_active" ||
		response.UserHold.RemainingSeconds == nil ||
		*response.UserHold.RemainingSeconds <= 0 {
		t.Fatalf("route lookup hold diagnostics = %#v, want active deferred hold", response.UserHold)
	}
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

// assertBackendPinRoute checks that route lookup applied a concrete operator backend pin.
func assertBackendPinRoute(t *testing.T, response generated.RouteLookupResponse, backendID string) {
	t.Helper()

	if response.FailClosed ||
		response.SelectedBackend != backendID ||
		response.Reason != "operator_backend_pin" ||
		!response.BackendPin.Present ||
		!response.BackendPin.Applied ||
		response.BackendPin.Backend == nil ||
		*response.BackendPin.Backend != backendID {
		t.Fatalf("backend-pin route = %#v, want applied pin to %q", response, backendID)
	}
}

// assertRouteLookupBackendProxy verifies read-only backend transport diagnostics.
func assertRouteLookupBackendProxy(t *testing.T, response generated.RouteLookupResponse, backendID string, want bool) {
	t.Helper()

	if response.FailClosed || response.SelectedBackend != backendID {
		t.Fatalf("route lookup response = %#v, want selected backend %q", response, backendID)
	}

	for _, summary := range response.Backends {
		if summary.Identifier == backendID {
			if summary.OutboundProxyProtocol != want {
				t.Fatalf("route lookup backend summary = %#v, want outbound proxy %t", summary, want)
			}

			return
		}
	}

	t.Fatalf("route lookup response = %#v, missing backend summary %q", response, backendID)
}

// getBackendDetail reads one backend through the public REST boundary.
func getBackendDetail(t *testing.T, baseURL string, backendID string) generated.BackendDetail {
	t.Helper()

	var response generated.BackendDetail
	requestJSON(t, http.MethodGet, baseURL+"/api/v1/backends/"+backendID, nil, http.StatusOK, &response)

	return response
}

// waitForProcessHealthStatus waits until Redis carries the expected process health state.
func waitForProcessHealthStatus(t *testing.T, store *state.RedisSessionStore, backendID string, status backend.HealthStatus) backend.HealthState {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		state, err := store.ReadHealthState(context.Background(), backendID)
		if err == nil && state.Enabled && state.Status == status {
			return state
		}

		time.Sleep(25 * time.Millisecond)
	}

	state, err := store.ReadHealthState(context.Background(), backendID)
	t.Fatalf("backend %s health state = %#v err=%v, want %s", backendID, state, err, status)

	return backend.HealthState{}
}

// getRuntimeSummary reads the public runtime summary.
func getRuntimeSummary(t *testing.T, baseURL string) generated.RuntimeSummaryResponse {
	t.Helper()

	var response generated.RuntimeSummaryResponse
	requestJSON(t, http.MethodGet, baseURL+"/api/v1/runtime/summary", nil, http.StatusOK, &response)

	return response
}

// assertNoRuntimePlacement verifies no session or backend reservation was opened.
func assertNoRuntimePlacement(t *testing.T, baseURL string) {
	t.Helper()

	waitForRESTSessionCount(t, baseURL, 0)
	summary := getRuntimeSummary(t, baseURL)
	if summary.ActiveSessions.Total.Count != 0 {
		t.Fatalf("runtime active sessions = %#v, want none", summary.ActiveSessions.Total)
	}
	for _, capacity := range summary.BackendCapacity {
		if capacity.ActiveSessions.Count != 0 || capacity.ReservedSessions.Count != 0 {
			t.Fatalf("backend capacity = %#v, want no active or reserved sessions", capacity)
		}
	}
}

// getSessionListPage reads one generated session page through the public REST API.
func getSessionListPage(t *testing.T, baseURL string, limit string, cursor string) generated.SessionListResponse {
	t.Helper()

	values := url.Values{"limit": []string{limit}}
	if strings.TrimSpace(cursor) != "" {
		values.Set("cursor", cursor)
	}

	var response generated.SessionListResponse
	requestJSON(t, http.MethodGet, baseURL+"/api/v1/sessions?"+values.Encode(), nil, http.StatusOK, &response)

	return response
}

// waitForRESTSessionCount waits until the public REST session list has the expected size.
func waitForRESTSessionCount(t *testing.T, baseURL string, count int) []generated.SessionDetail {
	t.Helper()

	deadline := time.Now().Add(3 * time.Second)
	var sessions []generated.SessionDetail
	for time.Now().Before(deadline) {
		page := getSessionListPage(t, baseURL, "50", "")
		sessions = page.Sessions
		if len(sessions) == count {
			return sessions
		}

		time.Sleep(25 * time.Millisecond)
	}

	t.Fatalf("REST session count did not become %d; sessions=%#v", count, sessions)
	return nil
}

// nextCursorFromCLI extracts the continuation cursor from text-mode CLI output.
func nextCursorFromCLI(t *testing.T, output string) string {
	t.Helper()

	for field := range strings.FieldsSeq(output) {
		if value, ok := strings.CutPrefix(field, "next_cursor="); ok {
			value = strings.Trim(value, `"`)
			if value != "" {
				return value
			}
		}
	}

	t.Fatalf("CLI output did not contain next_cursor: %q", output)

	return ""
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

	data := requestJSONData(t, method, target, body, wantStatus)
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			t.Fatalf("decode response body %s: %v", data, err)
		}
	}
}

// requestJSONData sends a JSON request and returns the public response body.
func requestJSONData(t *testing.T, method string, target string, body any, wantStatus int) []byte {
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
	authorizeE2EControlRequest(request)

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

	return data
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
	authorizeE2EControlRequest(request)

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
	cmd.Env = e2eDirectorctlEnv()
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
	cmd.Env = e2eDirectorctlEnv()
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

// authorizeE2EControlRequest adds the static bearer token expected by E2E control servers.
func authorizeE2EControlRequest(request *http.Request) {
	request.Header.Set("Authorization", "Bearer "+e2eToken)
}

// e2eDirectorctlEnv provides secret-safe auth material to the real CLI binary.
func e2eDirectorctlEnv() []string {
	return append(os.Environ(), "NAUTHILUS_DIRECTORCTL_BEARER_TOKEN="+e2eToken)
}

type pendingIMAPLogin struct {
	client net.Conn
	reader *bufio.Reader
	done   chan imapLoginResult
}

type imapLoginResult struct {
	line string
	err  error
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
	markIMAPStartTLS(t, client, reader)
	writeLine(t, client, `A001 LOGIN "`+account+`" "`+e2ePassword+`"`)
	expectLine(t, reader, "A001 OK Authentication completed\r\n")

	return client, reader
}

// loginProcessIMAP authenticates one real-process IMAP client after a TLS handshake.
func loginProcessIMAP(t *testing.T, address string, account string) (net.Conn, *bufio.Reader) {
	t.Helper()

	client := dialPlain(t, address)
	reader := bufio.NewReader(client)
	expectLine(t, reader, "* OK nauthilus-director IMAP session ready\r\n")
	client, reader = upgradeIMAPStartTLS(t, client, reader)
	writeLine(t, client, `A001 LOGIN "`+account+`" "`+e2ePassword+`"`)
	expectLine(t, reader, "A001 OK Authentication completed\r\n")

	return client, reader
}

// markIMAPStartTLS asks in-memory sessions to enter logical TLS without a socket handshake.
func markIMAPStartTLS(t *testing.T, client net.Conn, reader *bufio.Reader) {
	t.Helper()

	writeLine(t, client, "S001 STARTTLS")
	expectLine(t, reader, "S001 OK Begin TLS negotiation now\r\n")
}

// upgradeIMAPStartTLS negotiates real STARTTLS for production-process tests.
func upgradeIMAPStartTLS(t *testing.T, client net.Conn, reader *bufio.Reader) (net.Conn, *bufio.Reader) {
	t.Helper()

	writeLine(t, client, "S001 STARTTLS")
	expectLine(t, reader, "S001 OK Begin TLS negotiation now\r\n")
	tlsClient := tls.Client(client, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("STARTTLS client handshake: %v", err)
	}

	return tlsClient, bufio.NewReader(tlsClient)
}

// beginIMAPLogin starts one public LOGIN command and leaves the tagged result pending.
func beginIMAPLogin(t *testing.T, address string, account string) pendingIMAPLogin {
	t.Helper()

	client := dialPlain(t, address)
	reader := bufio.NewReader(client)
	expectLine(t, reader, "* OK nauthilus-director IMAP session ready\r\n")
	markIMAPStartTLS(t, client, reader)
	writeLine(t, client, `A001 LOGIN "`+account+`" "`+e2ePassword+`"`)

	pending := pendingIMAPLogin{client: client, reader: reader, done: make(chan imapLoginResult, 1)}
	go func() {
		line, err := reader.ReadString('\n')
		pending.done <- imapLoginResult{line: line, err: err}
	}()

	return pending
}

// beginProcessIMAPLogin starts a real-process TLS LOGIN command and leaves the result pending.
func beginProcessIMAPLogin(t *testing.T, address string, account string) pendingIMAPLogin {
	t.Helper()

	client := dialPlain(t, address)
	reader := bufio.NewReader(client)
	expectLine(t, reader, "* OK nauthilus-director IMAP session ready\r\n")
	client, reader = upgradeIMAPStartTLS(t, client, reader)
	writeLine(t, client, `A001 LOGIN "`+account+`" "`+e2ePassword+`"`)

	pending := pendingIMAPLogin{client: client, reader: reader, done: make(chan imapLoginResult, 1)}
	go func() {
		line, err := reader.ReadString('\n')
		pending.done <- imapLoginResult{line: line, err: err}
	}()

	return pending
}

// expectNoIMAPLoginResult verifies placement is still waiting without a tagged response.
func expectNoIMAPLoginResult(t *testing.T, pending pendingIMAPLogin, duration time.Duration) {
	t.Helper()

	select {
	case result := <-pending.done:
		t.Fatalf("IMAP login completed while hold should block placement: line=%q err=%v", result.line, result.err)
	case <-time.After(duration):
	}
}

// expectIMAPLoginResult waits for one pending LOGIN result.
func expectIMAPLoginResult(t *testing.T, pending pendingIMAPLogin, want string) {
	t.Helper()

	select {
	case result := <-pending.done:
		if result.err != nil {
			t.Fatalf("IMAP login read failed: %v", result.err)
		}
		if result.line != want {
			t.Fatalf("IMAP login line = %q, want %q", result.line, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for IMAP login result %q", want)
	}
}

// expectIMAPLoginUnavailable verifies a public login fails closed before proxy mode.
func expectIMAPLoginUnavailable(t *testing.T, address string, account string) {
	t.Helper()

	client := dialPlain(t, address)
	defer func() { _ = client.Close() }()

	reader := bufio.NewReader(client)
	expectLine(t, reader, "* OK nauthilus-director IMAP session ready\r\n")
	markIMAPStartTLS(t, client, reader)
	writeLine(t, client, `A001 LOGIN "`+account+`" "`+e2ePassword+`"`)
	expectLine(t, reader, "A001 NO [UNAVAILABLE] Authentication service temporarily unavailable\r\n")
}

// expectProcessIMAPLoginUnavailable verifies a real-process TLS login fails before proxy mode.
func expectProcessIMAPLoginUnavailable(t *testing.T, address string, account string) {
	t.Helper()

	client := dialPlain(t, address)
	defer func() { _ = client.Close() }()

	reader := bufio.NewReader(client)
	expectLine(t, reader, "* OK nauthilus-director IMAP session ready\r\n")
	client, reader = upgradeIMAPStartTLS(t, client, reader)
	writeLine(t, client, `A001 LOGIN "`+account+`" "`+e2ePassword+`"`)
	expectLine(t, reader, "A001 NO [UNAVAILABLE] Authentication service temporarily unavailable\r\n")
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

// assertOutputOmits verifies output avoids sensitive or unsupported text.
func assertOutputOmits(t *testing.T, output string, forbidden ...string) {
	t.Helper()

	for _, value := range forbidden {
		if strings.TrimSpace(value) != "" && strings.Contains(output, value) {
			t.Fatalf("output contained forbidden value %q: %s", value, output)
		}
	}
}

// assertOutputOmitsAuthorityContext checks context sentinels without echoing them on failure.
func assertOutputOmitsAuthorityContext(t *testing.T, output string, forbidden ...string) {
	t.Helper()

	for _, value := range forbidden {
		if strings.TrimSpace(value) != "" && strings.Contains(output, value) {
			t.Fatal("output contained a forbidden authority context value")
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

// assertProxyProtocolHeader checks only bounded syntax, not raw address values.
func assertProxyProtocolHeader(t *testing.T, header string) {
	t.Helper()

	if !strings.HasPrefix(header, "PROXY TCP4 ") && !strings.HasPrefix(header, "PROXY TCP6 ") {
		t.Fatalf("PROXY header = %q, want TCP4 or TCP6 preface", header)
	}
	if !strings.HasSuffix(header, "\r\n") {
		t.Fatalf("PROXY header = %q, want CRLF terminator", header)
	}
}

// readProxyProtocolPreface reads exactly one PROXY line without buffering later protocol bytes.
func readProxyProtocolPreface(conn net.Conn) (string, bool) {
	_ = conn.SetReadDeadline(time.Now().Add(fakeProxyTimeout))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	var builder strings.Builder
	var current [1]byte
	for builder.Len() < fakeProxyReadLimit {
		if _, err := conn.Read(current[:]); err != nil {
			return "", false
		}

		builder.WriteByte(current[0])
		if current[0] == '\n' {
			return builder.String(), true
		}
	}

	return builder.String(), false
}

type fakeHTTPAuthority struct {
	server         *http.Server
	listener       net.Listener
	attributes     map[string][]string
	identities     map[string]map[string][]string
	oidc           *fakeOIDCAuthority
	requests       []map[string]any
	contextHeaders []map[string]string
	authSchemes    []string
	requestsLock   sync.Mutex
}

type fakeOIDCAuthority struct {
	clientID       string
	clientSecret   string
	requiredScopes []string
	issuedTokens   map[string][]string
	discoveryCalls int
	tokenAttempts  int
	tokenCalls     int
	tokenCounter   int
}

type fakeOIDCAuthorityOptions struct {
	ClientID       string
	ClientSecret   string
	RequiredScopes []string
}

// startFakeHTTPAuthority starts a public HTTP auth socket.
func startFakeHTTPAuthority(t *testing.T, attributes map[string][]string) *fakeHTTPAuthority {
	t.Helper()

	return startMappedFakeHTTPAuthority(t, nil, attributes)
}

// startFakeOIDCHTTPAuthority starts a public HTTP auth socket with Nauthilus-compatible OIDC endpoints.
func startFakeOIDCHTTPAuthority(
	t *testing.T,
	attributes map[string][]string,
	options fakeOIDCAuthorityOptions,
) *fakeHTTPAuthority {
	t.Helper()

	return startMappedFakeOIDCHTTPAuthority(t, nil, attributes, options)
}

// startMappedFakeHTTPAuthority starts an HTTP auth socket with per-login identities.
func startMappedFakeHTTPAuthority(
	t *testing.T,
	identities map[string]map[string][]string,
	fallback map[string][]string,
) *fakeHTTPAuthority {
	t.Helper()

	return startMappedFakeHTTPAuthorityWithOIDC(t, identities, fallback, nil)
}

// startMappedFakeOIDCHTTPAuthority starts an OIDC-backed HTTP auth socket with per-login identities.
func startMappedFakeOIDCHTTPAuthority(
	t *testing.T,
	identities map[string]map[string][]string,
	fallback map[string][]string,
	options fakeOIDCAuthorityOptions,
) *fakeHTTPAuthority {
	t.Helper()

	oidc := newFakeOIDCAuthority(options)

	return startMappedFakeHTTPAuthorityWithOIDC(t, identities, fallback, oidc)
}

// startMappedFakeHTTPAuthorityWithOIDC starts the shared fake authority listener.
func startMappedFakeHTTPAuthorityWithOIDC(
	t *testing.T,
	identities map[string]map[string][]string,
	fallback map[string][]string,
	oidc *fakeOIDCAuthority,
) *fakeHTTPAuthority {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake HTTP authority: %v", err)
	}
	fake := &fakeHTTPAuthority{listener: ln, attributes: fallback, identities: identities, oidc: oidc}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/json", fake.handle)
	mux.HandleFunc(e2eOIDCDiscovery, fake.handleOIDCDiscovery)
	mux.HandleFunc("/oidc/token", fake.handleOIDCToken)
	mux.HandleFunc("/oidc/introspect", fake.handleOIDCIntrospection)
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

// newFakeOIDCAuthority returns deterministic client-credentials settings.
func newFakeOIDCAuthority(options fakeOIDCAuthorityOptions) *fakeOIDCAuthority {
	clientID := strings.TrimSpace(options.ClientID)
	if clientID == "" {
		clientID = e2eOIDCClientID
	}
	clientSecret := options.ClientSecret
	if clientSecret == "" {
		clientSecret = e2eOIDCClientSecret
	}
	requiredScopes := options.RequiredScopes
	if len(requiredScopes) == 0 {
		requiredScopes = []string{e2eOIDCScopeAuth}
	}

	return &fakeOIDCAuthority{
		clientID:       clientID,
		clientSecret:   clientSecret,
		requiredScopes: append([]string(nil), requiredScopes...),
		issuedTokens:   map[string][]string{},
	}
}

// URL returns the fake authority endpoint.
func (f *fakeHTTPAuthority) URL() string {
	return "http://" + f.listener.Addr().String() + "/api/v1/auth/json"
}

// Issuer returns the fake Nauthilus OIDC issuer URL.
func (f *fakeHTTPAuthority) Issuer() string {
	return "http://" + f.listener.Addr().String()
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
		t.Fatal("fake authority request did not match the expected protocol context")
	}
	for _, forbidden := range []string{"backend_identifier", "listener", "session_id", "routing_hint"} {
		if _, ok := request[forbidden]; ok {
			t.Fatalf("fake authority received forbidden field %q", forbidden)
		}
	}
}

// ExpectContextHeader verifies one selected safe listener context header reached the authority.
func (f *fakeHTTPAuthority) ExpectContextHeader(t *testing.T, name string, want string) {
	t.Helper()

	canonical := http.CanonicalHeaderKey(name)
	for range 50 {
		f.requestsLock.Lock()
		for _, headers := range f.contextHeaders {
			if headers[canonical] == want {
				f.requestsLock.Unlock()

				return
			}
		}
		f.requestsLock.Unlock()

		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("fake authority did not receive expected context header %q", canonical)
}

// ExpectOIDCCallerAuth verifies the caller obtained and used a Bearer token instead of Basic auth.
func (f *fakeHTTPAuthority) ExpectOIDCCallerAuth(t *testing.T) {
	t.Helper()

	f.requestsLock.Lock()
	defer f.requestsLock.Unlock()

	if f.oidc == nil {
		t.Fatal("fake authority was not configured for OIDC")
	}
	if f.oidc.discoveryCalls == 0 {
		t.Fatal("fake authority did not receive OIDC discovery")
	}
	if f.oidc.tokenCalls == 0 {
		t.Fatal("fake authority did not receive a client-credentials token request")
	}
	if len(f.authSchemes) == 0 {
		t.Fatal("fake authority did not receive an authenticated backchannel request")
	}
	for _, scheme := range f.authSchemes {
		if scheme != "bearer" {
			t.Fatalf("fake authority saw caller auth scheme %q, want bearer only", scheme)
		}
	}
}

// ExpectOIDCTokenAttemptWithoutBackchannel verifies token denial stopped authority use.
func (f *fakeHTTPAuthority) ExpectOIDCTokenAttemptWithoutBackchannel(t *testing.T) {
	t.Helper()

	f.requestsLock.Lock()
	defer f.requestsLock.Unlock()

	if f.oidc == nil {
		t.Fatal("fake authority was not configured for OIDC")
	}
	if f.oidc.discoveryCalls == 0 {
		t.Fatal("fake authority did not receive OIDC discovery")
	}
	if f.oidc.tokenAttempts == 0 {
		t.Fatal("fake authority did not receive a client-credentials token attempt")
	}
	if f.oidc.tokenCalls != 0 {
		t.Fatalf("fake authority issued %d tokens, want none", f.oidc.tokenCalls)
	}
	if len(f.requests) != 0 {
		t.Fatalf("fake authority received %d backchannel requests, want none", len(f.requests))
	}
	if len(f.authSchemes) != 0 {
		t.Fatalf("fake authority saw caller auth schemes %v, want none", f.authSchemes)
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
	if !f.authorizeBackchannel(writer, request) {
		return
	}

	var body map[string]any
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		http.Error(writer, "bad request", http.StatusBadRequest)

		return
	}

	f.requestsLock.Lock()
	f.requests = append(f.requests, body)
	f.contextHeaders = append(f.contextHeaders, safeHTTPAuthorityContextHeaders(request))
	f.requestsLock.Unlock()

	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"ok":            true,
		"account_field": "account",
		"attributes":    f.attributesForRequest(body),
	})
}

// safeHTTPAuthorityContextHeaders snapshots known non-credential listener context headers only.
func safeHTTPAuthorityContextHeaders(request *http.Request) map[string]string {
	headers := map[string]string{}
	for _, name := range []string{e2eContextHeader} {
		value := request.Header.Get(name)
		if value != "" {
			headers[http.CanonicalHeaderKey(name)] = value
		}
	}

	return headers
}

// authorizeBackchannel enforces fake Nauthilus OIDC bearer auth when enabled.
func (f *fakeHTTPAuthority) authorizeBackchannel(writer http.ResponseWriter, request *http.Request) bool {
	if f.oidc == nil {
		return true
	}

	scheme, payload, ok := splitFakeAuthorization(request.Header.Get("Authorization"))
	f.requestsLock.Lock()
	if scheme != "" {
		f.authSchemes = append(f.authSchemes, scheme)
	}
	f.requestsLock.Unlock()
	if !ok || scheme != "bearer" {
		http.Error(writer, "missing or invalid authorization header", http.StatusUnauthorized)

		return false
	}

	scopes, ok := f.oidcScopesForToken(payload)
	if !ok {
		http.Error(writer, "invalid token", http.StatusUnauthorized)

		return false
	}
	if !hasAllStrings(scopes, f.oidc.requiredScopes) {
		http.Error(writer, "missing required scope", http.StatusForbidden)

		return false
	}

	return true
}

// handleOIDCDiscovery returns a minimal Nauthilus-compatible discovery document.
func (f *fakeHTTPAuthority) handleOIDCDiscovery(writer http.ResponseWriter, request *http.Request) {
	if f.oidc == nil {
		http.NotFound(writer, request)

		return
	}

	f.requestsLock.Lock()
	f.oidc.discoveryCalls++
	f.requestsLock.Unlock()

	issuer := f.Issuer()
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"issuer":                                issuer,
		"token_endpoint":                        issuer + "/oidc/token",
		"introspection_endpoint":                issuer + "/oidc/introspect",
		"jwks_uri":                              issuer + "/oidc/jwks",
		"grant_types_supported":                 []string{"client_credentials"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"introspection_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"response_types_supported":                      []string{"code"},
		"subject_types_supported":                       []string{"public"},
		"id_token_signing_alg_values_supported":         []string{"RS256"},
		"code_challenge_methods_supported":              []string{"S256"},
		"scopes_supported":                              []string{e2eOIDCScopeAuth, e2eOIDCScopeLookup, e2eOIDCScopeList},
		"claims_supported":                              []string{"sub", "client_id", "scope"},
		"backchannel_logout_supported":                  false,
		"backchannel_logout_session_supported":          false,
		"frontchannel_logout_supported":                 false,
		"frontchannel_logout_session_supported":         false,
	})
}

// handleOIDCToken issues an opaque fake client-credentials token.
func (f *fakeHTTPAuthority) handleOIDCToken(writer http.ResponseWriter, request *http.Request) {
	if f.oidc == nil {
		http.NotFound(writer, request)

		return
	}
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)

		return
	}
	if err := request.ParseForm(); err != nil {
		http.Error(writer, "bad request", http.StatusBadRequest)

		return
	}
	f.requestsLock.Lock()
	f.oidc.tokenAttempts++
	f.requestsLock.Unlock()
	clientID, clientSecret, ok := request.BasicAuth()
	if !ok {
		clientID = request.Form.Get("client_id")
		clientSecret = request.Form.Get("client_secret")
	}
	if clientID != f.oidc.clientID || clientSecret != f.oidc.clientSecret {
		http.Error(writer, "invalid client", http.StatusUnauthorized)

		return
	}
	if request.Form.Get("grant_type") != "client_credentials" {
		http.Error(writer, "unsupported grant", http.StatusBadRequest)

		return
	}

	scopes := strings.Fields(request.Form.Get("scope"))
	if len(scopes) == 0 {
		scopes = []string{e2eOIDCScopeAuth}
	}

	f.requestsLock.Lock()
	f.oidc.tokenCalls++
	f.oidc.tokenCounter++
	token := fmt.Sprintf("fake-oidc-token-%d", f.oidc.tokenCounter)
	f.oidc.issuedTokens[token] = append([]string(nil), scopes...)
	f.requestsLock.Unlock()

	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"scope":        strings.Join(scopes, " "),
	})
}

// handleOIDCIntrospection marks known fake tokens active for control-auth tests.
func (f *fakeHTTPAuthority) handleOIDCIntrospection(writer http.ResponseWriter, request *http.Request) {
	if f.oidc == nil {
		http.NotFound(writer, request)

		return
	}
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)

		return
	}
	if err := request.ParseForm(); err != nil {
		http.Error(writer, "bad request", http.StatusBadRequest)

		return
	}

	token := request.Form.Get("token")
	scopes, ok := f.oidcScopesForToken(token)
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"active":    ok,
		"sub":       f.oidc.clientID,
		"client_id": f.oidc.clientID,
		"aud":       f.oidc.clientID,
		"scope":     strings.Join(scopes, " "),
	})
}

// oidcScopesForToken returns scopes for an issued fake token without exposing it in failures.
func (f *fakeHTTPAuthority) oidcScopesForToken(token string) ([]string, bool) {
	f.requestsLock.Lock()
	defer f.requestsLock.Unlock()

	if f.oidc == nil {
		return nil, false
	}
	scopes, ok := f.oidc.issuedTokens[token]

	return append([]string(nil), scopes...), ok
}

// splitFakeAuthorization parses a single Authorization header for fake services.
func splitFakeAuthorization(header string) (string, string, bool) {
	scheme, payload, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok {
		return "", "", false
	}
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	payload = strings.TrimSpace(payload)
	if scheme == "" || payload == "" {
		return "", "", false
	}

	return scheme, payload, true
}

// hasAllStrings reports whether every required value is present.
func hasAllStrings(values []string, required []string) bool {
	for _, want := range required {
		found := slices.Contains(values, want)
		if !found {
			return false
		}
	}

	return true
}

// attributesForRequest returns fixed or per-login Nauthilus attributes.
func (f *fakeHTTPAuthority) attributesForRequest(body map[string]any) map[string][]string {
	username, _ := body["username"].(string)
	if f.identities != nil {
		if attributes, ok := f.identities[username]; ok {
			return attributes
		}
	}

	return f.attributes
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
	RequireProxyProtocol bool
	TLSConfig            *tls.Config
	TLSMode              string
}

type fakeIMAPBackend struct {
	listener             net.Listener
	observations         chan fakeBackendObservation
	proxyProtocolHeaders chan string
	options              fakeBackendOptions
	connections          atomic.Int64
	proxyProtocolCount   atomic.Int64
	missingProxyProtocol atomic.Int64
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
		listener:             ln,
		observations:         make(chan fakeBackendObservation, 8),
		proxyProtocolHeaders: make(chan string, 8),
		options:              options,
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

// ExpectProxyProtocolHeader verifies a required outbound PROXY preface arrived.
func (b *fakeIMAPBackend) ExpectProxyProtocolHeader(t *testing.T) string {
	t.Helper()

	select {
	case header := <-b.proxyProtocolHeaders:
		return header
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for fake backend PROXY protocol header")
	}

	return ""
}

// ConnectionCount returns how many backend sockets were accepted.
func (b *fakeIMAPBackend) ConnectionCount() int64 {
	if b == nil {
		return 0
	}

	return b.connections.Load()
}

// ProxyProtocolHeaderCount returns how many required PROXY prefaces arrived.
func (b *fakeIMAPBackend) ProxyProtocolHeaderCount() int64 {
	if b == nil {
		return 0
	}

	return b.proxyProtocolCount.Load()
}

// MissingProxyProtocolCount returns how often a required PROXY preface was absent.
func (b *fakeIMAPBackend) MissingProxyProtocolCount() int64 {
	if b == nil {
		return 0
	}

	return b.missingProxyProtocol.Load()
}

// assertNoFakeBackendConnections verifies placement has not reached fake backends.
func assertNoFakeBackendConnections(t *testing.T, backends ...*fakeIMAPBackend) {
	t.Helper()

	for _, backend := range backends {
		if count := backend.ConnectionCount(); count != 0 {
			t.Fatalf("fake backend %s accepted %d connections while hold should block placement", backend.Address(), count)
		}
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

	b.connections.Add(1)

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
	if b.options.RequireProxyProtocol && !b.consumeProxyProtocolPreface(conn) {
		return conn, false
	}

	if b.options.TLSMode == imap.TLSModeImplicit && b.options.TLSConfig != nil {
		tlsConn := tls.Server(conn, b.options.TLSConfig.Clone())
		if err := tlsConn.Handshake(); err != nil {
			return conn, false
		}

		conn = tlsConn
	}

	return conn, true
}

// consumeProxyProtocolPreface requires one HAProxy PROXY line before backend bytes.
func (b *fakeIMAPBackend) consumeProxyProtocolPreface(conn net.Conn) bool {
	header, ok := readProxyProtocolPreface(conn)
	if !ok || !strings.HasPrefix(header, fakeProxyPrefix) {
		b.missingProxyProtocol.Add(1)

		return false
	}

	b.proxyProtocolCount.Add(1)
	b.proxyProtocolHeaders <- header

	return true
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
		current = state.AffinityRecord{
			Key:           record.Key,
			ShardTag:      record.ShardTag,
			BackendNode:   record.BackendNode,
			Status:        "created",
			Present:       true,
			BindingStatus: state.BindingStatusActive,
		}
		s.records[record.Key] = current
	} else {
		current.Status = "reused"
		current.Present = true
		current.BindingStatus = state.BindingStatusActive
	}
	s.counts[record.Key]++
	current.ActiveSessionCount = s.counts[record.Key]
	current.ActiveHolderCount = s.counts[record.Key]
	s.records[record.Key] = current

	return current, nil
}

// LookupAffinity returns the current in-memory backend binding without mutation.
func (s *memorySessionStore) LookupAffinity(_ context.Context, key state.AffinityKey) (state.AffinityRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	current, ok := s.records[key]
	if !ok {
		return state.AffinityRecord{Key: key, BindingStatus: state.BindingStatusNone}, nil
	}
	current.Present = true
	if current.BindingStatus == "" {
		current.BindingStatus = state.BindingStatusActive
	}
	current.ActiveSessionCount = s.counts[key]
	current.ActiveHolderCount = s.counts[key]

	return current, nil
}

// GetUserBackendPin returns an absent backend pin for the in-memory fake lane.
func (s *memorySessionStore) GetUserBackendPin(
	_ context.Context,
	request state.UserBackendPinGetRequest,
) (state.UserBackendPinRecord, error) {
	return state.UserBackendPinRecord{Key: request.Key}, nil
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

// AssertOmits checks captured log and metric fields without echoing forbidden values.
func (r *capturedRecorder) AssertOmits(t *testing.T, forbidden ...string) {
	t.Helper()

	for _, event := range r.snapshot() {
		for key, value := range event.LogFields {
			if containsForbiddenText(value, forbidden) {
				t.Fatalf("event %s log field %s contained forbidden authority context", event.Name, key)
			}
		}
		for key, value := range event.MetricLabels {
			if containsForbiddenText(value, forbidden) {
				t.Fatalf("event %s metric label %s contained forbidden authority context", event.Name, key)
			}
		}
	}
}

// containsForbiddenText reports whether text contains any non-empty forbidden sentinel.
func containsForbiddenText(text string, forbidden []string) bool {
	for _, value := range forbidden {
		if strings.TrimSpace(value) != "" && strings.Contains(text, value) {
			return true
		}
	}

	return false
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
