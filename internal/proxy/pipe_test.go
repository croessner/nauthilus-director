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

package proxy

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/observability"
)

// TestPipeSendsBufferedBytesBeforeLiveCopy verifies frontend parser read-ahead is replayed first.
func TestPipeSendsBufferedBytesBeforeLiveCopy(t *testing.T) {
	frontendClient, frontendProxy := net.Pipe()
	backendProxy, backendServer := net.Pipe()

	defer func() { _ = frontendClient.Close() }()
	defer func() { _ = backendServer.Close() }()

	resultCh := runTestPipe(t, PipeConfig{
		Frontend:          frontendProxy,
		Backend:           backendProxy,
		BufferedToBackend: []byte("buffered-"),
		IdleTimeout:       time.Second,
	})

	assertReadExact(t, backendServer, "buffered-")

	if _, err := io.WriteString(frontendClient, "live"); err != nil {
		t.Fatalf("write live frontend bytes: %v", err)
	}

	assertReadExact(t, backendServer, "live")

	_ = frontendClient.Close()

	result := waitPipeResult(t, resultCh)
	if result.Accounted.ClientToBackend != int64(len("buffered-live")) {
		t.Fatalf("client_to_backend bytes = %d, want %d", result.Accounted.ClientToBackend, len("buffered-live"))
	}
}

// TestPipeClassifiesClientCloseAndCountsBytes verifies normal frontend EOF accounting.
func TestPipeClassifiesClientCloseAndCountsBytes(t *testing.T) {
	frontendClient, frontendProxy := net.Pipe()
	backendProxy, backendServer := net.Pipe()

	defer func() { _ = backendServer.Close() }()

	resultCh := runTestPipe(t, PipeConfig{
		Frontend:    frontendProxy,
		Backend:     backendProxy,
		IdleTimeout: time.Second,
	})

	if _, err := io.WriteString(frontendClient, "abc"); err != nil {
		t.Fatalf("write frontend bytes: %v", err)
	}

	assertReadExact(t, backendServer, "abc")

	_ = frontendClient.Close()

	result := waitPipeResult(t, resultCh)
	if result.Class != ResultClientClosed {
		t.Fatalf("result class = %q, want %q", result.Class, ResultClientClosed)
	}

	if result.Accounted.ClientToBackend != 3 {
		t.Fatalf("client_to_backend bytes = %d, want 3", result.Accounted.ClientToBackend)
	}
}

// TestPipeObservabilityCountsDirectionsAndCloseReason verifies proxy metrics inputs.
func TestPipeObservabilityCountsDirectionsAndCloseReason(t *testing.T) {
	frontendClient, frontendProxy := net.Pipe()
	backendProxy, backendServer := net.Pipe()

	defer func() { _ = backendServer.Close() }()

	recorder := &recordingProxyObservability{}
	resultCh := runTestPipe(t, PipeConfig{
		Frontend:      frontendProxy,
		Backend:       backendProxy,
		IdleTimeout:   time.Second,
		Observability: recorder,
	})

	if _, err := io.WriteString(frontendClient, "abc"); err != nil {
		t.Fatalf("write frontend bytes: %v", err)
	}

	assertReadExact(t, backendServer, "abc")

	if _, err := io.WriteString(backendServer, "xyz"); err != nil {
		t.Fatalf("write backend bytes: %v", err)
	}

	assertReadExact(t, frontendClient, "xyz")
	_ = frontendClient.Close()
	_ = waitPipeResult(t, resultCh)

	event, ok := recorder.last(observability.EventProxyPipe)
	if !ok {
		t.Fatalf("proxy event missing: %#v", recorder.events)
	}

	if got := event.MetricLabels["reason_class"]; got != ResultClientClosed {
		t.Fatalf("reason_class = %q, want %q", got, ResultClientClosed)
	}

	if got := event.Measurements[observability.MetricMeasurementClientToBackendBytes]; got != 3 {
		t.Fatalf("client_to_backend bytes = %f, want 3", got)
	}

	if got := event.Measurements[observability.MetricMeasurementBackendToClientBytes]; got != 3 {
		t.Fatalf("backend_to_client bytes = %f, want 3", got)
	}

	if got := event.Measurements[observability.MetricMeasurementDurationSeconds]; got <= 0 {
		t.Fatalf("duration = %f, want positive", got)
	}
}

// TestPipeClassifiesIdleTimeout verifies idle deadline expiry uses the timeout result class.
func TestPipeClassifiesIdleTimeout(t *testing.T) {
	frontendClient, frontendProxy := net.Pipe()
	backendProxy, backendServer := net.Pipe()

	defer func() { _ = frontendClient.Close() }()
	defer func() { _ = backendServer.Close() }()

	resultCh := runTestPipe(t, PipeConfig{
		Frontend:    frontendProxy,
		Backend:     backendProxy,
		IdleTimeout: 20 * time.Millisecond,
	})

	result := waitPipeResult(t, resultCh)
	if result.Class != ResultTimeout {
		t.Fatalf("result class = %q, want %q", result.Class, ResultTimeout)
	}
}

// TestPipeInvokesHeartbeatAndCloseHooks verifies Redis lease callbacks are tied to proxy lifecycle.
func TestPipeInvokesHeartbeatAndCloseHooks(t *testing.T) {
	frontendClient, frontendProxy := net.Pipe()
	backendProxy, backendServer := net.Pipe()

	defer func() { _ = backendServer.Close() }()

	lease := &recordingLeaseLifecycle{}
	resultCh := runTestPipe(t, PipeConfig{
		Frontend:          frontendProxy,
		Backend:           backendProxy,
		IdleTimeout:       time.Second,
		HeartbeatInterval: 10 * time.Millisecond,
		Lease:             lease,
	})

	time.Sleep(35 * time.Millisecond)

	_ = frontendClient.Close()

	_ = waitPipeResult(t, resultCh)
	if lease.heartbeats == 0 {
		t.Fatal("heartbeat hook was not invoked")
	}

	if lease.closes != 1 {
		t.Fatalf("close hooks = %d, want 1", lease.closes)
	}
}

// TestPipeClassifiesHeartbeatControlAction verifies operator actions are not generic state failures.
func TestPipeClassifiesHeartbeatControlAction(t *testing.T) {
	frontendClient, frontendProxy := net.Pipe()
	backendProxy, backendServer := net.Pipe()

	defer func() { _ = frontendClient.Close() }()
	defer func() { _ = backendServer.Close() }()

	lease := &recordingLeaseLifecycle{heartbeatErr: NewControlActionError("kick")}
	resultCh := runTestPipe(t, PipeConfig{
		Frontend:          frontendProxy,
		Backend:           backendProxy,
		IdleTimeout:       time.Second,
		HeartbeatInterval: 10 * time.Millisecond,
		Lease:             lease,
	})

	result := waitPipeResult(t, resultCh)
	if result.Class != ResultControlAction {
		t.Fatalf("result class = %q, want %q", result.Class, ResultControlAction)
	}

	if !IsControlActionError(result.Err) {
		t.Fatalf("result error = %v, want control action error", result.Err)
	}

	if lease.closes != 1 {
		t.Fatalf("close hooks = %d, want 1", lease.closes)
	}
}

// pipeRunResult carries a proxy run result and error through a test channel.
type pipeRunResult struct {
	result Result
	err    error
}

// runTestPipe starts a proxy pipe and returns its result channel.
func runTestPipe(t *testing.T, config PipeConfig) <-chan pipeRunResult {
	t.Helper()

	resultCh := make(chan pipeRunResult, 1)

	go func() {
		result, err := NewPipe().Run(context.Background(), config)
		resultCh <- pipeRunResult{result: result, err: err}
	}()

	return resultCh
}

// waitPipeResult waits for one proxy result without accepting test hangs.
func waitPipeResult(t *testing.T, resultCh <-chan pipeRunResult) Result {
	t.Helper()

	select {
	case result := <-resultCh:
		return result.result
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for proxy result")
	}

	return Result{}
}

// assertReadExact reads exactly the expected bytes from a connection.
func assertReadExact(t *testing.T, reader io.Reader, want string) {
	t.Helper()

	buffer := make([]byte, len(want))
	if _, err := io.ReadFull(reader, buffer); err != nil {
		t.Fatalf("read %q: %v", want, err)
	}

	if string(buffer) != want {
		t.Fatalf("read = %q, want %q", string(buffer), want)
	}
}

// recordingLeaseLifecycle records heartbeat and close callbacks.
type recordingLeaseLifecycle struct {
	heartbeats   int
	closes       int
	heartbeatErr error
}

type recordingProxyObservability struct {
	events []observability.Event
}

// Record stores one proxy event for assertions.
func (r *recordingProxyObservability) Record(_ context.Context, event observability.Event) {
	r.events = append(r.events, event)
}

// last returns the latest proxy event with the supplied name.
func (r *recordingProxyObservability) last(name string) (observability.Event, bool) {
	for index := len(r.events) - 1; index >= 0; index-- {
		if r.events[index].Name == name {
			return r.events[index], true
		}
	}

	return observability.Event{}, false
}

// Heartbeat records one active lease refresh.
func (l *recordingLeaseLifecycle) Heartbeat(context.Context) error {
	l.heartbeats++

	return l.heartbeatErr
}

// Close records one terminal lease release.
func (l *recordingLeaseLifecycle) Close(context.Context) error {
	l.closes++

	return nil
}
