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

//nolint:goconst // Lifecycle fixtures repeat tool names intentionally.
package mcpserver

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/rest/diagnostics"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// slowServer builds an endpoint whose runtime summary is slow.
func slowServer(t *testing.T, api fakeAPI, timeout time.Duration, address string) *Server {
	t.Helper()

	return newTestServer(t, newAuthority(), testServerOptions{api: api, adjust: func(s *config.MCPServerConfig) {
		trustLoopback(s)
		s.Address = address
		s.Limits.Timeout = config.NewDuration(timeout)
	}})
}

// TestToolCallTimeoutInBothEras pins that limits.timeout bounds a tool call in the stateless and
// the handshake era: the slow handler is cut and reported as a tool error instead of holding the call.
func TestToolCallTimeoutInBothEras(t *testing.T) {
	api := newFakeAPI()
	api.summaryDelay = 10 * time.Second
	server := slowServer(t, api, 200*time.Millisecond, "")

	for _, version := range []string{"2026-07-28", "2025-06-18"} {
		t.Run(version, func(t *testing.T) {
			started := time.Now()

			result, err := connect(t, server, "good", version).CallTool(context.Background(),
				&mcp.CallToolParams{Name: diagnostics.OperationRuntimeSummary, Arguments: map[string]any{}})
			if err != nil || !result.IsError {
				t.Fatalf("CallTool = %+v, %v", result, err)
			}

			if elapsed := time.Since(started); elapsed > 5*time.Second ||
				!strings.Contains(resultText(t, result), diagnostics.ProblemCodeInternal) {
				t.Fatalf("call took %s: %s", elapsed, resultText(t, result))
			}
		})
	}
}

// TestMergeCancellation pins that the HTTP request context ends a handshake-era tool call and that stop unlinks.
func TestMergeCancellation(t *testing.T) {
	request, cancelRequest := context.WithCancel(context.Background())
	merged, stop := mergeCancellation(context.Background(), request)

	cancelRequest()

	select {
	case <-merged.Done():
	case <-time.After(time.Second):
		t.Fatal("the merged context must end with the request context")
	}

	stop()

	unmerged, stopNil := mergeCancellation(context.Background(), nil)
	defer stopNil()

	if unmerged.Err() != nil {
		t.Fatal("a nil request context must not cancel")
	}
}

// freeAddress returns a loopback address that was free a moment ago.
func freeAddress(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	address := listener.Addr().String()
	_ = listener.Close()

	return address
}

// TestShutdownDrainsInFlightCalls pins that the done channel closes only after a running tool call completed.
func TestShutdownDrainsInFlightCalls(t *testing.T) {
	address := freeAddress(t)
	api := newFakeAPI()
	api.summaryDelay, api.ignoreAbort = 600*time.Millisecond, true
	server := slowServer(t, api, 5*time.Second, address)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done, err := server.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}

	session := connectURL(t, "http://"+address+"/mcp", "good", "2025-06-18")
	finished := make(chan error, 1)

	go func() {
		_, callErr := session.CallTool(context.Background(), &mcp.CallToolParams{Name: diagnostics.OperationRuntimeSummary,
			Arguments: map[string]any{}})
		finished <- callErr
	}()

	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case <-done:
		t.Fatal("done closed while a tool call was still running")
	case callErr := <-finished:
		if callErr != nil && !errors.Is(callErr, context.Canceled) {
			t.Fatalf("in-flight call = %v", callErr)
		}
	}

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("done did not close after the drain")
	}
}
