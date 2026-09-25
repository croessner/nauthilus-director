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

package e2e

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/protocol/imap"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

const (
	sessionProfileEnv         = "NAUTHILUS_DIRECTOR_SESSION_PROFILE"
	sessionProfileSessionsEnv = "NAUTHILUS_DIRECTOR_SESSION_PROFILE_SESSIONS"
	sessionProfileWorkersEnv  = "NAUTHILUS_DIRECTOR_SESSION_PROFILE_WORKERS"
	sessionProfileUsers       = 512

	sessionProfileAttributeAccount  = "account"
	sessionProfileBackendTLSMode    = "starttls"
	sessionProfileBackendServerName = "127.0.0.1"
	sessionProfileMinTLSVersion     = "TLS1.2"
	sessionProfileGreeting          = "* OK nauthilus-director IMAP session ready\r\n"
)

// TestSessionProfileImplicitTLSLoginLoad drives complete IMAPS sessions through the production listener and
// placement path so that `go test -cpuprofile` shows where the director spends CPU per session. It runs only when
// NAUTHILUS_DIRECTOR_SESSION_PROFILE is set; every session does an implicit TLS handshake, LOGIN through the
// authority, Redis-backed placement, a STARTTLS backend connection with master-user auth, one proxied NOOP and
// the close path.
func TestSessionProfileImplicitTLSLoginLoad(t *testing.T) {
	if os.Getenv(sessionProfileEnv) == "" {
		t.Skip("set " + sessionProfileEnv + "=1 to profile the director session path")
	}

	sessions := sessionProfileSetting(t, sessionProfileSessionsEnv, 2000)
	workers := sessionProfileSetting(t, sessionProfileWorkersEnv, 32)
	director := startSessionProfileDirector(t)

	defer director.Stop(t)

	var (
		completed atomic.Int64
		failures  atomic.Int64
		next      atomic.Int64
		wait      sync.WaitGroup
	)

	started := time.Now()

	for range workers {
		wait.Go(func() {
			for {
				index := next.Add(1)
				if index > int64(sessions) {
					return
				}

				if err := runProfiledIMAPSession(director.Address(), int(index)%sessionProfileUsers); err != nil {
					if failures.Add(1) <= 5 {
						t.Logf("session %d: %v", index, err)
					}

					continue
				}

				completed.Add(1)
			}
		})
	}

	wait.Wait()

	elapsed := time.Since(started)
	t.Logf("sessions=%d failures=%d workers=%d elapsed=%s rate=%.1f/s",
		completed.Load(), failures.Load(), workers, elapsed.Round(time.Millisecond),
		float64(completed.Load())/elapsed.Seconds())

	if failures.Load() > int64(sessions)/100 {
		t.Fatalf("%d of %d profiled sessions failed", failures.Load(), sessions)
	}
}

// startSessionProfileDirector wires the production listener to Redis state, a mapped authority and a TLS backend.
func startSessionProfileDirector(t *testing.T) directorInstance {
	t.Helper()

	identities := make(map[string]map[string][]string, sessionProfileUsers)
	for index := range sessionProfileUsers {
		account := sessionProfileAccount(index)
		identities[account] = map[string][]string{
			sessionProfileAttributeAccount: {account},
			e2eAttributeTenant:             {e2eTenant},
			e2eAttributeMailShard:          {e2eShardTag},
		}
	}

	redisFixture := startValkeySessionStore(t)
	authority := startMappedFakeHTTPAuthority(t, identities, nil)
	backendCertPath, _, backendCertificate := writeTestCertificate(t)
	backendTLS := &tls.Config{Certificates: []tls.Certificate{backendCertificate}, MinVersion: tls.VersionTLS12}
	// A fixed ticket key survives the per-connection Clone of the fake backend, like the ticket key of a
	// long-running backend process, so the director can resume backend TLS sessions as in production.
	backendTLS.SetSessionTicketKeys([][32]byte{{1}})
	fakeBackend := startFakeIMAPBackend(t, fakeBackendOptions{TLSConfig: backendTLS, TLSMode: imap.TLSModeStartTLS})

	// The fake backend reports every proxied session on a small buffered channel; drain it so it never blocks.
	go func() {
		for observation := range fakeBackend.observations {
			_ = observation
		}
	}()

	listenerCertPath, listenerKeyPath, _ := writeTestCertificate(t)

	return startDirector(t, directorOptions{
		Authenticator:  newHTTPAuthenticator(t, authority.URL()),
		BackendAuth:    masterUserBackendAuth(),
		BackendAddress: fakeBackend.Address(),
		BackendTLS: config.BackendTLSConfig{
			Mode:          sessionProfileBackendTLSMode,
			CAFile:        backendCertPath,
			ServerName:    sessionProfileBackendServerName,
			MinTLSVersion: sessionProfileMinTLSVersion,
		},
		ListenerCertPath: listenerCertPath,
		ListenerKeyPath:  listenerKeyPath,
		Recorder:         sessionProfileRecorder(t),
		SessionStore:     redisFixture.store,
		TLSMode:          imap.TLSModeImplicit,
	})
}

// sessionProfileRecorder builds the production observability runtime with the prod log level, metrics and
// sampled tracing, so the profile includes the per-event log, metric and span work of a real deployment.
func sessionProfileRecorder(t *testing.T) observability.Recorder {
	t.Helper()

	cfg := config.DefaultConfig().Observability
	cfg.Log.Level = "warn"
	cfg.Log.JSON = true
	cfg.Metrics.Enabled = true
	cfg.Tracing.Enabled = true
	cfg.Tracing.Exporter = "otlp"
	cfg.Tracing.SampleRatio = 0.1

	runtime, err := observability.NewRuntime(cfg,
		observability.WithLogWriter(io.Discard),
		observability.WithTraceExporterFactory(observability.TraceExporterFactoryFunc(
			func(context.Context, config.TracingConfig) (sdktrace.SpanExporter, error) {
				return discardSpanExporter{}, nil
			},
		)),
	)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}

	t.Cleanup(func() { _ = runtime.Shutdown(t.Context()) })

	return runtime.Recorder()
}

// discardSpanExporter drops sampled spans after the SDK has built and batched them.
type discardSpanExporter struct{}

// ExportSpans discards the batch.
func (discardSpanExporter) ExportSpans(context.Context, []sdktrace.ReadOnlySpan) error {
	return nil
}

// Shutdown has nothing to release.
func (discardSpanExporter) Shutdown(context.Context) error {
	return nil
}

// runProfiledIMAPSession runs one complete client session and reports protocol deviations as errors.
func runProfiledIMAPSession(address string, user int) error {
	conn, err := tls.Dial("tcp", address, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	reader := bufio.NewReader(conn)

	for _, step := range []struct {
		command string
		want    string
	}{
		{want: sessionProfileGreeting},
		{command: `A1 LOGIN "` + sessionProfileAccount(user) + `" "` + e2ePassword + `"`, want: "A1 OK Authentication completed\r\n"},
		{command: "A2 NOOP", want: "A2 OK backend noop\r\n"},
	} {
		if step.command != "" {
			if _, err := conn.Write([]byte(step.command + "\r\n")); err != nil {
				return fmt.Errorf("write %q: %w", step.command, err)
			}
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read after %q: %w", step.command, err)
		}

		if line != step.want {
			return fmt.Errorf("after %q got %q", step.command, line)
		}
	}

	return nil
}

// sessionProfileAccount names one of the profiled mailbox accounts.
func sessionProfileAccount(index int) string {
	return "profile-" + strconv.Itoa(index) + "@example.test"
}

// sessionProfileSetting reads one positive integer override.
func sessionProfileSetting(t *testing.T, name string, fallback int) int {
	t.Helper()

	value := os.Getenv(name)
	if value == "" {
		return fallback
	}

	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		t.Fatalf("%s must be a positive integer", name)
	}

	return parsed
}
