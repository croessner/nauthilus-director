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
	heartbeats int
	closes     int
}

// Heartbeat records one active lease refresh.
func (l *recordingLeaseLifecycle) Heartbeat(context.Context) error {
	l.heartbeats++

	return nil
}

// Close records one terminal lease release.
func (l *recordingLeaseLifecycle) Close(context.Context) error {
	l.closes++

	return nil
}
