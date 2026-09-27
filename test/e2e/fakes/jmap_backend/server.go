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

// Package jmapbackend provides a deterministic public-socket JMAP backend for tests.
//
// The fake terminates TLS behind an optional PROXY v1/v2 preface, answers the JMAP session, API,
// upload, download, event-source and health endpoints with fixed data and records every request
// together with the client address the PROXY header named for its connection.
//
//nolint:goconst,funlen,wsl_v5 // The fake backend keeps endpoint fixtures compact and reviewable.
package jmapbackend

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

const (
	// DownloadContent is the fixed blob body served by the download endpoint.
	DownloadContent = "0123456789abcdefghijklmnopqrstuvwxyz"
	// EventPayload is the first event the event-source endpoint emits.
	EventPayload = "event: state\ndata: {\"changed\":{}}\n\n"
	// HeaderBackend names the backend that answered a request.
	HeaderBackend = "X-Fake-Jmap-Backend"

	proxyHeaderTimeout = 2 * time.Second
	eventPingInterval  = 50 * time.Millisecond
)

// Options configures one fake JMAP backend.
type Options struct {
	Name                 string
	TLSConfig            *tls.Config
	RequireProxyProtocol bool
	PublicBaseURL        string
	HealthStatus         int
}

// Request is one recorded backend request.
type Request struct {
	Connection    int64
	ClientAddress string
	Method        string
	Path          string
	RawQuery      string
	Host          string
	Authorization string
	Header        http.Header
	BodyBytes     int64
}

// Server owns one fake JMAP backend listener.
type Server struct {
	options      Options
	listener     net.Listener
	server       *http.Server
	connections  atomic.Int64
	openStreams  atomic.Int64
	closedStream atomic.Int64
	healthChecks atomic.Int64

	mu       sync.Mutex
	requests []Request
}

type connectionKey struct{}

// Start binds a loopback TLS listener that optionally requires a PROXY preface.
func Start(t testing.TB, options Options) *Server {
	t.Helper()

	if options.TLSConfig == nil {
		t.Fatal("jmap backend requires a TLS config")
	}

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake JMAP backend: %v", err)
	}

	policy := proxyproto.USE
	if options.RequireProxyProtocol {
		policy = proxyproto.REQUIRE
	}

	proxied := &proxyproto.Listener{
		Listener:          raw,
		ReadHeaderTimeout: proxyHeaderTimeout,
		ConnPolicy: func(proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
			return policy, nil
		},
	}

	fake := &Server{options: options, listener: raw}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jmap", fake.handleSession)
	mux.HandleFunc("/jmap/api/", fake.handleAPI)
	mux.HandleFunc("/jmap/upload/", fake.handleUpload)
	mux.HandleFunc("/jmap/download/", fake.handleDownload)
	mux.HandleFunc("/jmap/eventsource/", fake.handleEventSource)
	mux.HandleFunc("/jmap/healthz", fake.handleHealth)

	fake.server = &http.Server{
		Handler:           fake.recording(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ConnContext: func(ctx context.Context, _ net.Conn) context.Context {
			return context.WithValue(ctx, connectionKey{}, fake.connections.Add(1))
		},
	}

	go func() {
		_ = fake.server.Serve(tls.NewListener(proxied, options.TLSConfig))
	}()

	t.Cleanup(fake.Close)

	return fake
}

// Address returns the backend host:port.
func (s *Server) Address() string {
	return s.listener.Addr().String()
}

// Close stops the backend and its active streams.
func (s *Server) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_ = s.server.Shutdown(ctx)
	_ = s.server.Close()
}

// Requests returns a snapshot of recorded requests, excluding health probes.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]Request(nil), s.requests...)
}

// Connections returns how many TLS connections the backend accepted.
func (s *Server) Connections() int64 {
	return s.connections.Load()
}

// OpenStreams returns how many event streams are currently open.
func (s *Server) OpenStreams() int64 {
	return s.openStreams.Load()
}

// ClosedStreams returns how many event streams ended.
func (s *Server) ClosedStreams() int64 {
	return s.closedStream.Load()
}

// HealthChecks returns how many health probes reached the backend.
func (s *Server) HealthChecks() int64 {
	return s.healthChecks.Load()
}

// recording captures every non-health request before the endpoint handler runs.
func (s *Server) recording(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set(HeaderBackend, s.options.Name)

		if request.URL.Path == "/jmap/healthz" {
			next.ServeHTTP(writer, request)

			return
		}

		body, _ := io.ReadAll(request.Body)
		request.Body = io.NopCloser(bytes.NewReader(body))
		connection, _ := request.Context().Value(connectionKey{}).(int64)

		s.mu.Lock()
		s.requests = append(s.requests, Request{
			Connection:    connection,
			ClientAddress: request.RemoteAddr,
			Method:        request.Method,
			Path:          request.URL.Path,
			RawQuery:      request.URL.RawQuery,
			Host:          request.Host,
			Authorization: request.Header.Get("Authorization"),
			Header:        request.Header.Clone(),
			BodyBytes:     int64(len(body)),
		})
		s.mu.Unlock()

		next.ServeHTTP(writer, request)
	})
}

// handleSession answers the session resource with URLs under the public base URL.
func (s *Server) handleSession(writer http.ResponseWriter, _ *http.Request) {
	base := strings.TrimRight(s.options.PublicBaseURL, "/")
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"capabilities":    map[string]any{"urn:ietf:params:jmap:core": map[string]any{}},
		"accounts":        map[string]any{},
		"username":        "fixture",
		"apiUrl":          base + "/jmap/api/",
		"downloadUrl":     base + "/jmap/download/{accountId}/{blobId}/{name}?accept={type}",
		"uploadUrl":       base + "/jmap/upload/{accountId}/",
		"eventSourceUrl":  base + "/jmap/eventsource/?types={types}&closeafter={closeafter}&ping={ping}",
		"state":           "fixture-state",
		"primaryAccounts": map[string]any{},
	})
}

// handleAPI answers a fixed method response naming the backend and the received body size.
func (s *Server) handleAPI(writer http.ResponseWriter, request *http.Request) {
	body, _ := io.ReadAll(request.Body)
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"methodResponses": []any{},
		"sessionState":    "fixture-state",
		"backend":         s.options.Name,
		"requestBytes":    len(body),
	})
}

// handleUpload stores nothing and answers the uploaded size.
func (s *Server) handleUpload(writer http.ResponseWriter, request *http.Request) {
	size, _ := io.Copy(io.Discard, request.Body)
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(writer).Encode(map[string]any{"blobId": "fixture-blob", "size": size})
}

// handleDownload serves the fixed blob with range support and the download security headers.
func (s *Server) handleDownload(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.Header().Set("Content-Disposition", `attachment; filename="fixture.bin"`)
	writer.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(writer, request, "fixture.bin", time.Unix(0, 0), strings.NewReader(DownloadContent))
}

// handleEventSource emits one state event and then pings until the client or server goes away.
func (s *Server) handleEventSource(writer http.ResponseWriter, request *http.Request) {
	s.openStreams.Add(1)
	defer func() {
		s.openStreams.Add(-1)
		s.closedStream.Add(1)
	}()

	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.WriteHeader(http.StatusOK)

	controller := http.NewResponseController(writer)
	if _, err := io.WriteString(writer, EventPayload); err != nil {
		return
	}

	if err := controller.Flush(); err != nil {
		return
	}

	ticker := time.NewTicker(eventPingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-request.Context().Done():
			return
		case <-ticker.C:
			if _, err := io.WriteString(writer, ": ping\n\n"); err != nil {
				return
			}

			if err := controller.Flush(); err != nil {
				return
			}
		}
	}
}

// handleHealth answers the configured health status without authentication.
func (s *Server) handleHealth(writer http.ResponseWriter, _ *http.Request) {
	s.healthChecks.Add(1)

	status := s.options.HealthStatus
	if status == 0 {
		status = http.StatusOK
	}

	writer.WriteHeader(status)
	_, _ = fmt.Fprintln(writer, http.StatusText(status))
}

// WaitForOpenStreams waits until the number of open event streams equals want.
func (s *Server) WaitForOpenStreams(t testing.TB, want int64) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s.OpenStreams() == want {
			return
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("open event streams = %d, want %d", s.OpenStreams(), want)
}

// ErrNoRequest reports that no request matched a lookup.
var ErrNoRequest = errors.New("jmap backend: no matching request")

// LastRequest returns the most recent recorded request for a path prefix.
func (s *Server) LastRequest(pathPrefix string) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, v := range slices.Backward(s.requests) {
		if strings.HasPrefix(v.Path, pathPrefix) {
			return v, nil
		}
	}

	return Request{}, ErrNoRequest
}
