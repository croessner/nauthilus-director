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

package mcpserver

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

// maxTrackedClients bounds the failure table. A full table of live windows stops tracking new
// clients instead of refusing them, so a flood of rotating addresses can never lock out valid tokens.
const maxTrackedClients = 10000

// ipv6ClientBits is the prefix one IPv6 client is accounted under; one host usually owns a whole /64.
const ipv6ClientBits = 64

// failureWindow counts failed bearer attempts of one client in one fixed window.
type failureWindow struct {
	started time.Time
	count   int
}

// failureLimiter bounds failed bearer attempts per client (IPv4 address, IPv6 /64) in fixed
// windows. It never counts a missing token, so discovery probes stay free; the client IP comes
// from the trusted proxy chain only.
type failureLimiter struct {
	now     func() time.Time
	entries map[netip.Prefix]*failureWindow
	mu      sync.Mutex
	window  time.Duration
	limit   int
}

// newFailureLimiter returns a limiter allowing limit failures per window.
func newFailureLimiter(limit int, window time.Duration, now func() time.Time) *failureLimiter {
	return &failureLimiter{now: now, entries: make(map[netip.Prefix]*failureWindow), window: window, limit: max(limit, 1)}
}

// clientKey returns the accounting key of a client address: the address itself for IPv4, its /64 for IPv6.
func clientKey(client netip.Addr) netip.Prefix {
	client = client.Unmap()
	if client.Is4() || !client.IsValid() {
		return netip.PrefixFrom(client, client.BitLen())
	}

	prefix, _ := client.Prefix(ipv6ClientBits)

	return prefix
}

// blocked reports whether the client already used up its failures in the current window.
// Untracked clients are never blocked.
func (l *failureLimiter) blocked(client netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	key := clientKey(client)

	entry, tracked := l.entries[key]
	if !tracked {
		return false
	}

	if l.now().Sub(entry.started) >= l.window {
		delete(l.entries, key)

		return false
	}

	return entry.count >= l.limit
}

// fail records one failed attempt of the client; when the table is full of live windows the
// attempt is not tracked.
func (l *failureLimiter) fail(client netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	key := clientKey(client)

	entry, tracked := l.entries[key]
	if tracked && now.Sub(entry.started) < l.window {
		entry.count++

		return
	}

	if !tracked && len(l.entries) >= maxTrackedClients && !l.sweep(now) {
		return
	}

	l.entries[key] = &failureWindow{started: now, count: 1}
}

// sweep removes expired windows and reports whether space is free afterwards.
func (l *failureLimiter) sweep(now time.Time) bool {
	for key, entry := range l.entries {
		if now.Sub(entry.started) >= l.window {
			delete(l.entries, key)
		}
	}

	return len(l.entries) < maxTrackedClients
}

// gate bounds concurrent requests globally and per principal identity.
type gate struct {
	slots     chan struct{}
	perCaller map[string]int
	mu        sync.Mutex
	wait      time.Duration
	limit     int
}

// newGate creates a gate with global and per-identity bounds and the longest wait for a free
// global slot. Non-positive bounds are raised to one.
func newGate(global int, perIdentity int, wait time.Duration) *gate {
	return &gate{slots: make(chan struct{}, max(global, 1)), perCaller: map[string]int{}, limit: max(perIdentity, 1),
		wait: max(wait, 0)}
}

// acquire takes a slot for identity and returns its release function. It reports false, without
// waiting, when the identity already holds its share, and after the wait or cancellation when the
// global bound stays full.
func (g *gate) acquire(ctx context.Context, identity string) (func(), bool) {
	g.mu.Lock()
	if g.perCaller[identity] >= g.limit {
		g.mu.Unlock()

		return nil, false
	}

	g.perCaller[identity]++
	g.mu.Unlock()

	timer := time.NewTimer(g.wait)
	defer timer.Stop()

	select {
	case g.slots <- struct{}{}:
		var once sync.Once

		return func() { once.Do(func() { g.release(identity) }) }, true
	case <-timer.C:
	case <-ctx.Done():
	}

	g.leave(identity)

	return nil, false
}

// release frees the global slot and the identity share.
func (g *gate) release(identity string) {
	<-g.slots
	g.leave(identity)
}

// leave frees the identity share.
func (g *gate) leave(identity string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.perCaller[identity]--; g.perCaller[identity] <= 0 {
		delete(g.perCaller, identity)
	}
}
