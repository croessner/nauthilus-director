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

package jmap

import (
	"context"
	"net"
	"net/http"
	"sync"
)

// connListener is the in-process net.Listener through which the generic listener lifecycle hands
// accepted connections to the HTTP server; it never binds a socket itself.
type connListener struct {
	conns     chan net.Conn
	closed    chan struct{}
	closeOnce sync.Once
}

// newConnListener creates an open in-process listener.
func newConnListener() *connListener {
	return &connListener{conns: make(chan net.Conn), closed: make(chan struct{})}
}

// deliver passes one connection to the HTTP server's accept loop.
func (l *connListener) deliver(conn net.Conn) error {
	select {
	case l.conns <- conn:
		return nil
	case <-l.closed:
		return ErrHandlerClosed
	}
}

// Accept returns the next delivered connection.
func (l *connListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

// Close stops the accept loop; delivered connections stay owned by the HTTP server.
func (l *connListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })

	return nil
}

// Addr returns a placeholder address because the real socket belongs to the generic listener.
func (l *connListener) Addr() net.Addr {
	return &net.TCPAddr{}
}

// downstreamConn is the director-side state of one frontend connection: its client addresses and
// the backend transports opened on its behalf, which are never shared with another frontend
// connection so that pooled backend connections always carry this client's PROXY header.
type downstreamConn struct {
	source      net.Addr
	destination net.Addr
	done        chan struct{}

	mu         sync.Mutex
	closed     bool
	transports map[string]*http.Transport
}

type downstreamContextKey struct{}

// newDownstreamConn captures the frontend tuple of one accepted connection.
func newDownstreamConn(conn net.Conn) *downstreamConn {
	return &downstreamConn{
		source:      conn.RemoteAddr(),
		destination: conn.LocalAddr(),
		done:        make(chan struct{}),
		transports:  map[string]*http.Transport{},
	}
}

// withDownstream attaches the frontend connection state to a request context.
func withDownstream(ctx context.Context, downstream *downstreamConn) context.Context {
	return context.WithValue(ctx, downstreamContextKey{}, downstream)
}

// downstreamFromContext returns the frontend connection state of one request.
func downstreamFromContext(ctx context.Context) (*downstreamConn, bool) {
	downstream, ok := ctx.Value(downstreamContextKey{}).(*downstreamConn)

	return downstream, ok && downstream != nil
}

// transport returns this connection's transport for one backend, creating it on first use.
func (d *downstreamConn) transport(key string, create func() *http.Transport) (*http.Transport, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return nil, false
	}

	if existing, ok := d.transports[key]; ok {
		return existing, true
	}

	created := create()
	d.transports[key] = created

	return created, true
}

// close releases every backend connection of this frontend connection and unblocks Serve.
func (d *downstreamConn) close() {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()

		return
	}

	d.closed = true
	transports := d.transports
	d.transports = nil
	d.mu.Unlock()

	for _, transport := range transports {
		transport.CloseIdleConnections()
	}

	close(d.done)
}
