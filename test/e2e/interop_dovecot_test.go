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

//go:build interop

package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
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
	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/redis/go-redis/v9"
)

const interopBackendAddressEnv = "NAUTHILUS_DIRECTOR_INTEROP_BACKEND_ADDR"

const (
	interopDefaultAAddressEnv       = "NAUTHILUS_DIRECTOR_INTEROP_DEFAULT_A_ADDR"
	interopDefaultBAddressEnv       = "NAUTHILUS_DIRECTOR_INTEROP_DEFAULT_B_ADDR"
	interopDefaultALMTPAddressEnv   = "NAUTHILUS_DIRECTOR_INTEROP_DEFAULT_A_LMTP_ADDR"
	interopDefaultBLMTPAddressEnv   = "NAUTHILUS_DIRECTOR_INTEROP_DEFAULT_B_LMTP_ADDR"
	interopShard1AAddressEnv        = "NAUTHILUS_DIRECTOR_INTEROP_SHARD1_A_ADDR"
	interopShard1BAddressEnv        = "NAUTHILUS_DIRECTOR_INTEROP_SHARD1_B_ADDR"
	interopShard2AAddressEnv        = "NAUTHILUS_DIRECTOR_INTEROP_SHARD2_A_ADDR"
	interopShard2BAddressEnv        = "NAUTHILUS_DIRECTOR_INTEROP_SHARD2_B_ADDR"
	interopDefaultAContainerEnv     = "NAUTHILUS_DIRECTOR_INTEROP_DEFAULT_A_CONTAINER"
	interopDefaultBContainerEnv     = "NAUTHILUS_DIRECTOR_INTEROP_DEFAULT_B_CONTAINER"
	interopShard1AContainerEnv      = "NAUTHILUS_DIRECTOR_INTEROP_SHARD1_A_CONTAINER"
	interopShard1BContainerEnv      = "NAUTHILUS_DIRECTOR_INTEROP_SHARD1_B_CONTAINER"
	interopShard2AContainerEnv      = "NAUTHILUS_DIRECTOR_INTEROP_SHARD2_A_CONTAINER"
	interopShard2BContainerEnv      = "NAUTHILUS_DIRECTOR_INTEROP_SHARD2_B_CONTAINER"
	interopDockerCommandEnv         = "NAUTHILUS_DIRECTOR_INTEROP_DOCKER"
	interopClusterRedisKeyPrefix    = "nauthilus-director-e2e-cluster"
	interopDirectorAInstance        = "e2e-director-a"
	interopDirectorBInstance        = "e2e-director-b"
	interopDirectorCInstance        = "e2e-director-c"
	interopDovecotBackendProofDelay = 3 * time.Second
	interopDefaultShard             = "default"
	interopShard1                   = "test_shard1"
	interopShard2                   = "test_shard2"
	interopDefaultUser              = "default-user@example.test"
	interopShard1User               = "shard1-user@example.test"
	interopShard2User               = "shard2-user@example.test"
	interopMovedUser                = "moved-user@example.test"
	interopBackendDefaultAID        = "mailstore-default-a-imap"
	interopBackendDefaultBID        = "mailstore-default-b-imap"
	interopBackendShard1AID         = "mailstore-shard1-a-imap"
	interopBackendShard1BID         = "mailstore-shard1-b-imap"
	interopBackendShard2AID         = "mailstore-shard2-a-imap"
	interopBackendShard2BID         = "mailstore-shard2-b-imap"
	interopHealthUsername           = "healthcheck@example.test"
)

// TestDovecotCredentialReplayInterop proves public director login and proxy handoff to real Dovecot.
func TestDovecotCredentialReplayInterop(t *testing.T) {
	binary := e2eServerBinary(t)
	backendAddress := os.Getenv(interopBackendAddressEnv)
	if backendAddress == "" {
		t.Skipf("%s is required for real IMAP interop", interopBackendAddressEnv)
	}

	redisFixture := startValkeySessionStore(t)
	authority := startFakeHTTPAuthority(t, map[string][]string{
		"account":   {e2eAccount},
		"tenant":    {e2eTenant},
		"mailShard": {e2eShardTag},
	})
	directorAddress := "127.0.0.1:" + strconv.Itoa(reserveLoopbackPort(t))
	configPath := writeProcessConfig(t, processConfigOptions{
		RedisAddress:    redisFixture.addr,
		AuthorityURL:    authority.URL(),
		DirectorAddress: directorAddress,
		BackendAddress:  backendAddress,
		BackendAuth:     credentialReplayBackendAuth(false),
		BackendTLS: config.BackendTLSConfig{
			Mode:               "starttls",
			MinTLSVersion:      "TLS1.2",
			InsecureSkipVerify: true,
		},
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

	response := readLine(t, reader)
	if !strings.HasPrefix(response, "A002 OK") {
		t.Fatalf("Dovecot post-auth response = %q, want tagged OK", response)
	}

	authority.ExpectRequest(t, e2eProtocol, "login", "")
}

// TestDovecotClusterRuntimeInterop proves multi-director affinity and control against real Dovecot backends.
func TestDovecotClusterRuntimeInterop(t *testing.T) {
	binary := e2eServerBinary(t)
	backendAddresses := map[string]string{
		interopBackendDefaultAID: os.Getenv(interopDefaultAAddressEnv),
		interopBackendDefaultBID: os.Getenv(interopDefaultBAddressEnv),
		interopBackendShard1AID:  os.Getenv(interopShard1AAddressEnv),
		interopBackendShard1BID:  os.Getenv(interopShard1BAddressEnv),
		interopBackendShard2AID:  os.Getenv(interopShard2AAddressEnv),
		interopBackendShard2BID:  os.Getenv(interopShard2BAddressEnv),
	}
	if missing := missingBackendAddressNames(backendAddresses); len(missing) > 0 {
		t.Skipf("real cluster interop requires backend addresses for %s", strings.Join(missing, ", "))
	}

	redisFixture := startValkeySessionStore(t)
	authority := startClusterHTTPAuthority(t)

	directorAAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(reserveLoopbackPort(t)))
	directorBAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(reserveLoopbackPort(t)))
	directorCAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(reserveLoopbackPort(t)))
	controlAAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(reserveLoopbackPort(t)))
	controlBAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(reserveLoopbackPort(t)))
	controlCAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(reserveLoopbackPort(t)))
	controlAURL := "http://" + controlAAddress

	configA := writeDovecotClusterProcessConfig(t, interopClusterProcessConfigOptions{
		InstanceName:     interopDirectorAInstance,
		RedisAddress:     redisFixture.addr,
		AuthorityURL:     authority.URL(),
		DirectorAddress:  directorAAddress,
		ControlAddress:   controlAAddress,
		BackendAddresses: backendAddresses,
	})
	configB := writeDovecotClusterProcessConfig(t, interopClusterProcessConfigOptions{
		InstanceName:     interopDirectorBInstance,
		RedisAddress:     redisFixture.addr,
		AuthorityURL:     authority.URL(),
		DirectorAddress:  directorBAddress,
		ControlAddress:   controlBAddress,
		BackendAddresses: backendAddresses,
	})
	configC := writeDovecotClusterProcessConfig(t, interopClusterProcessConfigOptions{
		InstanceName:     interopDirectorCInstance,
		RedisAddress:     redisFixture.addr,
		AuthorityURL:     authority.URL(),
		DirectorAddress:  directorCAddress,
		ControlAddress:   controlCAddress,
		BackendAddresses: backendAddresses,
	})

	processA := startDirectorProcess(t, binary, configA)
	processB := startDirectorProcess(t, binary, configB)
	processC := startDirectorProcess(t, binary, configC)
	waitForDirectorGreeting(t, directorAAddress, processA)
	waitForDirectorGreeting(t, directorBAddress, processB)
	waitForDirectorGreeting(t, directorCAddress, processC)

	ctl := buildDirectorctl(t)
	healthOwners := waitForHealthOwners(t, redisFixture.addr, interopClusterBackendIDs(), interopClusterDirectorIDs())
	if len(uniqueStringValues(healthOwners)) < 2 {
		t.Fatalf("health ownership was not distributed across directors: %#v", healthOwners)
	}
	waitForDirectorctlSessions(t, ctl, controlAURL, 0)

	firstClient, firstReader := loginIMAP(t, directorAAddress, interopShard1User)
	defer func() { _ = firstClient.Close() }()
	expectDovecotNOOP(t, firstClient, firstReader, "A002")

	secondClient, secondReader := loginIMAP(t, directorBAddress, interopShard1User)
	defer func() { _ = secondClient.Close() }()
	expectDovecotNOOP(t, secondClient, secondReader, "B002")

	sessions := waitForDirectorctlSessions(t, ctl, controlAURL, 2)
	shard1Sessions := sessionsForUser(sessions, interopShard1User)
	shard1Backend := expectUserSessionsOnOneBackendInSet(t, shard1Sessions, interopShard1BackendIDs(), interopShard1)
	expectDovecotWhoContains(t, containerEnvForBackend(shard1Backend), interopShard1User)

	routeOutput := runDirectorctl(t, ctl, controlAURL,
		"route", "lookup",
		"--protocol", e2eProtocol,
		"--user", interopShard1User,
		"--listener", e2eListenerName,
		"--attribute", "mailShard="+interopShard2,
		"--include-affinity",
	)
	routeFields := parseDirectorctlFields(routeOutput)
	if routeFields["selected_backend"] != shard1Backend || routeFields["affinity_present"] != "true" || routeFields["affinity_shard"] != interopShard1 {
		t.Fatalf("active-affinity route lookup = %q", routeOutput)
	}

	runDirectorctl(t, ctl, controlAURL, "sessions", "kill", shard1Sessions[0].ID, "--reason", "cluster targeted kill")
	firstAlive, secondAlive := waitForExactlyOneLiveClient(t, firstClient, firstReader, secondClient, secondReader)
	if firstAlive == secondAlive {
		t.Fatalf("targeted session kill left first_alive=%t second_alive=%t", firstAlive, secondAlive)
	}

	remainingClient := firstClient
	remainingReader := firstReader
	if secondAlive {
		remainingClient = secondClient
		remainingReader = secondReader
	}
	remainingSessions := waitForDirectorctlSessions(t, ctl, controlAURL, 1)
	expectUserSessionsOnOneBackendInSet(t, sessionsForUser(remainingSessions, interopShard1User), []string{shard1Backend}, interopShard1)

	runDirectorctl(t, ctl, controlAURL, "users", "kick", interopShard1User, "--reason", "cluster remote kick")
	expectSessionClosed(t, remainingClient, remainingReader)
	waitForDirectorctlSessions(t, ctl, controlAURL, 0)

	defaultClient, defaultReader := loginIMAP(t, directorCAddress, interopDefaultUser)
	defer func() { _ = defaultClient.Close() }()
	expectDovecotNOOP(t, defaultClient, defaultReader, "D002")
	defaultSessions := waitForDirectorctlSessions(t, ctl, controlAURL, 1)
	expectUserSessionsOnOneBackendInSet(t, sessionsForUser(defaultSessions, interopDefaultUser), interopDefaultBackendIDs(), interopDefaultShard)
	runDirectorctl(t, ctl, controlAURL, "users", "kick", interopDefaultUser, "--reason", "cluster default cleanup")
	expectSessionClosed(t, defaultClient, defaultReader)
	waitForDirectorctlSessions(t, ctl, controlAURL, 0)

	runDirectorctl(t, ctl, controlAURL, "users", "move", interopMovedUser, "--to-shard", interopShard2, "--strategy", "new_sessions_only", "--reason", "cluster move proof")
	movedClient, movedReader := loginIMAP(t, directorBAddress, interopMovedUser)
	defer func() { _ = movedClient.Close() }()
	expectDovecotNOOP(t, movedClient, movedReader, "C002")

	movedSessions := waitForDirectorctlSessions(t, ctl, controlAURL, 1)
	movedBackend := expectUserSessionsOnOneBackendInSet(t, sessionsForUser(movedSessions, interopMovedUser), interopShard2BackendIDs(), interopShard2)
	expectDovecotWhoContains(t, containerEnvForBackend(movedBackend), interopMovedUser)

	runDirectorctl(t, ctl, controlAURL, "backends", "drain", movedBackend, "--mode", "hard", "--reason", "cluster backend drain")
	expectSessionClosed(t, movedClient, movedReader)
	waitForDirectorctlSessions(t, ctl, controlAURL, 0)

	shard2Client, shard2Reader := loginIMAP(t, directorCAddress, interopShard2User)
	defer func() { _ = shard2Client.Close() }()
	expectDovecotNOOP(t, shard2Client, shard2Reader, "E002")
	shard2Sessions := waitForDirectorctlSessions(t, ctl, controlAURL, 1)
	remainingShard2Backends := withoutString(interopShard2BackendIDs(), movedBackend)
	expectUserSessionsOnOneBackendInSet(t, sessionsForUser(shard2Sessions, interopShard2User), remainingShard2Backends, interopShard2)
	runDirectorctl(t, ctl, controlAURL, "users", "kick", interopShard2User, "--reason", "cluster shard2 cleanup")
	expectSessionClosed(t, shard2Client, shard2Reader)
	waitForDirectorctlSessions(t, ctl, controlAURL, 0)

	runDirectorctl(t, ctl, controlAURL, "users", "affinity", "clear", interopMovedUser, "--reason", "cluster cleanup")
}

type staticInteropAuthenticator struct{}

// Authenticate returns an accepted account for real-backend interop.
func (staticInteropAuthenticator) Authenticate(context.Context, nauthilus.AuthRequest) (nauthilus.AuthResult, error) {
	return nauthilus.AuthResult{
		Decision: nauthilus.DecisionAuthenticated,
		Account:  e2eAccount,
		Attributes: map[string][]string{
			"account":   {e2eAccount},
			"tenant":    {e2eTenant},
			"mailShard": {e2eShardTag},
		},
	}, nil
}

type interopClusterProcessConfigOptions struct {
	InstanceName     string
	RedisAddress     string
	AuthorityURL     string
	DirectorAddress  string
	ControlAddress   string
	BackendAddresses map[string]string
}

type directorctlSession struct {
	ID      string
	User    string
	Backend string
	Shard   string
}

type interopClusterBackend struct {
	ID           string
	Address      string
	ShardTag     string
	DeclareShard bool
}

// writeDovecotClusterProcessConfig writes one real-process config for cluster interop.
func writeDovecotClusterProcessConfig(t *testing.T, options interopClusterProcessConfigOptions) string {
	t.Helper()

	backendTLS := config.BackendTLSConfig{
		Mode:               "starttls",
		MinTLSVersion:      "TLS1.2",
		InsecureSkipVerify: true,
	}
	backendAuth := credentialReplayBackendAuth(false)
	listenerCertPath, listenerKeyPath, _ := writeTestCertificate(t)
	var content strings.Builder
	fmt.Fprintf(&content, `patch:
  - op: remove
    path: director.listeners
    value: [imaps, lmtp, lmtps]
  - op: remove
    path: director.backend_pools
    value: [lmtp-default]
  - op: remove
    path: director.backends
    value: [mailstore-a-lmtp, mailstore-b-lmtp]
runtime:
  instance_name: %q
  process:
    shutdown_timeout: 2s
  servers:
    control:
      enabled: true
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
      http:
        endpoint: %q
        basic_auth:
          password_file: "unused"
director:
  routing:
    default_shard: %q
  health:
    interval: 250ms
    timeout: 1s
    jitter: 50ms
    unhealthy_after: 1
    healthy_after: 1
  affinity:
    active_user_pinning:
      idle_grace: 1s
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
      backends: [%s]
  backends:
`, options.InstanceName,
		options.ControlAddress,
		interopClusterRedisKeyPrefix,
		options.RedisAddress,
		options.AuthorityURL,
		interopDefaultShard,
		options.DirectorAddress,
		listenerCertPath,
		listenerKeyPath,
		quotedYAMLStrings(interopClusterBackendIDs()),
	)

	for _, configured := range interopClusterBackends(options.BackendAddresses) {
		writeDovecotClusterBackendConfig(&content, configured, backendTLS, backendAuth)
	}

	path := filepath.Join(t.TempDir(), "nauthilus-director-cluster.yml")
	if err := os.WriteFile(path, []byte(content.String()), 0o600); err != nil {
		t.Fatalf("write cluster process config: %v", err)
	}

	return path
}

// writeDovecotClusterBackendConfig appends one Dovecot backend YAML entry.
func writeDovecotClusterBackendConfig(
	content *strings.Builder,
	configured interopClusterBackend,
	backendTLS config.BackendTLSConfig,
	backendAuth backend.AuthConfig,
) {
	fmt.Fprintf(content, `    %s:
      protocol: imap
      address: %q
      weight: 100
      max_connections: 100
      maintenance: disabled
`, configured.ID, configured.Address)
	if configured.DeclareShard {
		fmt.Fprintf(content, "      shard_tag: %q\n", configured.ShardTag)
	}
	fmt.Fprintf(content, `      tls:
        mode: %q
        ca_file: %q
        cert: %q
        key: %q
        server_name: %q
        min_tls_version: %q
        insecure_skip_verify: %t
      auth:
        mode: %q
        credential_replay:
          require_backend_tls: %t
          preserve_mechanism: %t
          allowed_mechanisms: [%s]
      health_check:
        enabled: true
        deep_check: true
        username: %q
        password_file: %q
`, backendTLS.Mode,
		backendTLS.CAFile,
		backendTLS.Cert,
		backendTLS.Key.Value(),
		backendTLS.ServerName,
		backendTLS.MinTLSVersion,
		backendTLS.InsecureSkipVerify,
		backendAuth.Mode,
		backendAuth.CredentialReplay.RequireBackendTLS,
		backendAuth.CredentialReplay.PreserveMechanism,
		quotedYAMLStrings(backendAuth.CredentialReplay.AllowedMechanisms),
		interopHealthUsername,
		e2ePassword,
	)
}

// missingBackendAddressNames returns sorted backend identifiers without mapped Dovecot addresses.
func missingBackendAddressNames(addresses map[string]string) []string {
	var missing []string
	for backendID, address := range addresses {
		if strings.TrimSpace(address) == "" {
			missing = append(missing, backendID)
		}
	}

	sort.Strings(missing)

	return missing
}

// interopClusterBackends returns the six-backend real-Dovecot topology.
func interopClusterBackends(addresses map[string]string) []interopClusterBackend {
	return []interopClusterBackend{
		{ID: interopBackendDefaultAID, Address: addresses[interopBackendDefaultAID], ShardTag: interopDefaultShard},
		{ID: interopBackendDefaultBID, Address: addresses[interopBackendDefaultBID], ShardTag: interopDefaultShard},
		{ID: interopBackendShard1AID, Address: addresses[interopBackendShard1AID], ShardTag: interopShard1, DeclareShard: true},
		{ID: interopBackendShard1BID, Address: addresses[interopBackendShard1BID], ShardTag: interopShard1, DeclareShard: true},
		{ID: interopBackendShard2AID, Address: addresses[interopBackendShard2AID], ShardTag: interopShard2, DeclareShard: true},
		{ID: interopBackendShard2BID, Address: addresses[interopBackendShard2BID], ShardTag: interopShard2, DeclareShard: true},
	}
}

// interopClusterBackendIDs returns the backend identifiers in config order.
func interopClusterBackendIDs() []string {
	return []string{
		interopBackendDefaultAID,
		interopBackendDefaultBID,
		interopBackendShard1AID,
		interopBackendShard1BID,
		interopBackendShard2AID,
		interopBackendShard2BID,
	}
}

// interopDefaultBackendIDs returns the untagged backend identifiers.
func interopDefaultBackendIDs() []string {
	return []string{interopBackendDefaultAID, interopBackendDefaultBID}
}

// interopShard1BackendIDs returns the first explicit shard backend identifiers.
func interopShard1BackendIDs() []string {
	return []string{interopBackendShard1AID, interopBackendShard1BID}
}

// interopShard2BackendIDs returns the second explicit shard backend identifiers.
func interopShard2BackendIDs() []string {
	return []string{interopBackendShard2AID, interopBackendShard2BID}
}

// interopClusterDirectorIDs returns the director instance names in cluster tests.
func interopClusterDirectorIDs() []string {
	return []string{interopDirectorAInstance, interopDirectorBInstance, interopDirectorCInstance}
}

// containerEnvForBackend returns the optional Docker container id for a backend.
func containerEnvForBackend(backendID string) string {
	switch backendID {
	case interopBackendDefaultAID:
		return os.Getenv(interopDefaultAContainerEnv)
	case interopBackendDefaultBID:
		return os.Getenv(interopDefaultBContainerEnv)
	case interopBackendShard1AID:
		return os.Getenv(interopShard1AContainerEnv)
	case interopBackendShard1BID:
		return os.Getenv(interopShard1BContainerEnv)
	case interopBackendShard2AID:
		return os.Getenv(interopShard2AContainerEnv)
	case interopBackendShard2BID:
		return os.Getenv(interopShard2BContainerEnv)
	default:
		return ""
	}
}

// startClusterHTTPAuthority starts dynamic fake Nauthilus auth for shard interop.
func startClusterHTTPAuthority(t *testing.T) *clusterHTTPAuthority {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen cluster HTTP authority: %v", err)
	}
	fake := &clusterHTTPAuthority{listener: ln}
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

type clusterHTTPAuthority struct {
	listener net.Listener
	server   *http.Server
	mu       sync.Mutex
	requests []map[string]any
}

// URL returns the fake cluster authority endpoint.
func (f *clusterHTTPAuthority) URL() string {
	return "http://" + f.listener.Addr().String() + "/api/v1/auth/json"
}

// handle maps each test user to a deterministic routing attribute set.
func (f *clusterHTTPAuthority) handle(writer http.ResponseWriter, request *http.Request) {
	var body map[string]any
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		http.Error(writer, "bad request", http.StatusBadRequest)

		return
	}

	f.mu.Lock()
	f.requests = append(f.requests, body)
	f.mu.Unlock()

	username, _ := body["username"].(string)
	if strings.TrimSpace(username) == "" {
		username = e2eAccount
	}

	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"ok":            true,
		"account_field": "account",
		"attributes":    interopAttributesForUser(username),
	})
}

// interopAttributesForUser returns Nauthilus-style routing facts per test account.
func interopAttributesForUser(username string) map[string][]string {
	attributes := map[string][]string{
		"account": {username},
		"tenant":  {e2eTenant},
	}

	switch username {
	case interopDefaultUser:
		attributes["mailShard"] = []string{interopDefaultShard}
	case interopShard2User:
		attributes["mailShard"] = []string{interopShard2}
	default:
		attributes["mailShard"] = []string{interopShard1}
	}

	return attributes
}

// waitForHealthOwners waits until every real backend has one healthy Redis owner.
func waitForHealthOwners(t *testing.T, redisAddress string, backendIDs []string, directorIDs []string) map[string]string {
	t.Helper()

	client := redis.NewClient(&redis.Options{Addr: redisAddress, Protocol: 2})
	defer func() { _ = client.Close() }()

	allowed := stringSet(directorIDs)
	var owners map[string]string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var complete bool
		owners, complete = readHealthOwners(context.Background(), client, backendIDs, allowed)
		if complete {
			return owners
		}

		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("health owners did not become healthy for all backends: %#v", owners)
	return nil
}

// readHealthOwners reads production Redis owner and state hashes for health proof.
func readHealthOwners(ctx context.Context, client *redis.Client, backendIDs []string, allowed map[string]struct{}) (map[string]string, bool) {
	owners := make(map[string]string, len(backendIDs))
	for _, backendID := range backendIDs {
		owner, err := client.HGet(ctx, interopHealthOwnerKey(backendID), "instance_id").Result()
		if err != nil || strings.TrimSpace(owner) == "" {
			return owners, false
		}
		if _, ok := allowed[owner]; !ok {
			return owners, false
		}

		state, err := client.HGetAll(ctx, interopHealthStateKey(backendID)).Result()
		if err != nil || state["status"] != string(backend.HealthStatusHealthy) || state["owner_instance_id"] != owner {
			return owners, false
		}

		owners[backendID] = owner
	}

	return owners, true
}

// interopHealthOwnerKey returns the production Redis owner key for one backend.
func interopHealthOwnerKey(backendID string) string {
	return interopClusterRedisKeyPrefix + ":v1:health:backend:" + backendID + ":owner"
}

// interopHealthStateKey returns the production Redis health-state key for one backend.
func interopHealthStateKey(backendID string) string {
	return interopClusterRedisKeyPrefix + ":v1:health:backend:" + backendID + ":state"
}

// stringSet converts values into a membership map.
func stringSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}

	return set
}

// uniqueStringValues returns sorted unique values from a string map.
func uniqueStringValues(values map[string]string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}

	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)

	return result
}

// withoutString returns values except the excluded string.
func withoutString(values []string, excluded string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != excluded {
			result = append(result, value)
		}
	}

	return result
}

// expectDovecotNOOP verifies post-auth proxy mode against a real Dovecot backend.
func expectDovecotNOOP(t *testing.T, client net.Conn, reader *bufio.Reader, tag string) {
	t.Helper()

	if !tryDovecotNOOP(t, client, reader, tag) {
		t.Fatalf("Dovecot NOOP %s did not return tagged OK", tag)
	}
}

// tryDovecotNOOP returns whether a proxied Dovecot connection is still alive.
func tryDovecotNOOP(t *testing.T, client net.Conn, reader *bufio.Reader, tag string) bool {
	t.Helper()

	_ = client.SetDeadline(time.Now().Add(time.Second))
	defer func() { _ = client.SetDeadline(time.Time{}) }()

	if _, err := fmt.Fprintf(client, "%s NOOP\r\n", tag); err != nil {
		return false
	}

	for range 8 {
		line, err := reader.ReadString('\n')
		if err != nil {
			return false
		}
		if strings.HasPrefix(line, tag+" OK") {
			return true
		}
		if strings.HasPrefix(line, tag+" NO") || strings.HasPrefix(line, tag+" BAD") {
			t.Fatalf("Dovecot NOOP %s failed: %q", tag, line)
		}
	}

	return false
}

// waitForExactlyOneLiveClient waits until a targeted session kill leaves one stream alive.
func waitForExactlyOneLiveClient(
	t *testing.T,
	first net.Conn,
	firstReader *bufio.Reader,
	second net.Conn,
	secondReader *bufio.Reader,
) (bool, bool) {
	t.Helper()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		firstAlive := tryDovecotNOOP(t, first, firstReader, "K101")
		secondAlive := tryDovecotNOOP(t, second, secondReader, "K102")
		if firstAlive != secondAlive {
			return firstAlive, secondAlive
		}

		time.Sleep(100 * time.Millisecond)
	}

	return false, false
}

// waitForDirectorctlSessions polls the real CLI until it sees the requested session count.
func waitForDirectorctlSessions(t *testing.T, ctl string, controlURL string, count int) []directorctlSession {
	t.Helper()

	var sessions []directorctlSession
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		output := runDirectorctl(t, ctl, controlURL, "sessions", "list", "--protocol", e2eProtocol)
		sessions = parseDirectorctlSessions(output)
		if len(sessions) == count {
			return sessions
		}

		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("directorctl sessions count = %d, want %d: %#v", len(sessions), count, sessions)
	return nil
}

// parseDirectorctlSessions converts scriptable CLI session rows into test records.
func parseDirectorctlSessions(output string) []directorctlSession {
	var sessions []directorctlSession
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		fields := parseDirectorctlFields(line)
		if len(fields) == 0 {
			continue
		}

		sessions = append(sessions, directorctlSession{
			ID:      fields["session_id"],
			User:    fields["user_key"],
			Backend: fields["backend"],
			Shard:   fields["shard_tag"],
		})
	}

	return sessions
}

// sessionsForUser returns only CLI-visible sessions for one user key.
func sessionsForUser(sessions []directorctlSession, userKey string) []directorctlSession {
	var filtered []directorctlSession
	for _, session := range sessions {
		if session.User == userKey {
			filtered = append(filtered, session)
		}
	}

	return filtered
}

// expectUserSessionsOnOneBackendInSet verifies same-user pinning and shard placement.
func expectUserSessionsOnOneBackendInSet(t *testing.T, sessions []directorctlSession, backendIDs []string, shardTag string) string {
	t.Helper()

	if len(sessions) == 0 {
		t.Fatal("no sessions available for backend assertion")
	}

	allowed := stringSet(backendIDs)
	backendID := sessions[0].Backend
	if _, ok := allowed[backendID]; !ok {
		t.Fatalf("session backend %s not in allowed set %v", backendID, backendIDs)
	}

	for _, session := range sessions {
		if session.ID == "" || session.Backend != backendID || session.Shard != shardTag {
			t.Fatalf("session placement = %#v, want backend=%s shard=%s", session, backendID, shardTag)
		}
	}

	return backendID
}

// parseDirectorctlFields parses scriptable key=value CLI output.
func parseDirectorctlFields(output string) map[string]string {
	fields := map[string]string{}
	for _, part := range strings.Fields(strings.TrimSpace(output)) {
		name, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		if unquoted, err := strconv.Unquote(value); err == nil {
			value = unquoted
		}

		fields[name] = value
	}

	return fields
}

// expectDovecotWhoContains optionally verifies active sessions through doveadm.
func expectDovecotWhoContains(t *testing.T, containerID string, account string) {
	t.Helper()

	dockerCommand := os.Getenv(interopDockerCommandEnv)
	if dockerCommand == "" || strings.TrimSpace(containerID) == "" {
		t.Log("doveadm who proof skipped because Docker container metadata is unavailable")
		return
	}

	var lastOutput string
	sawCommand := false
	deadline := time.Now().Add(interopDovecotBackendProofDelay)
	for time.Now().Before(deadline) {
		output, err := exec.Command(dockerCommand, "exec", containerID, "doveadm", "who").CombinedOutput()
		lastOutput = string(output)
		if err == nil {
			sawCommand = true
			if strings.Contains(lastOutput, account) {
				return
			}
		}

		time.Sleep(100 * time.Millisecond)
	}

	if !sawCommand {
		t.Logf("doveadm who proof skipped because command did not succeed: %s", lastOutput)
		return
	}

	t.Fatalf("doveadm who did not show %s in container %s: %s", account, containerID, lastOutput)
}
