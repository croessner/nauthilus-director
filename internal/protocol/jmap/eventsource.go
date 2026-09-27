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
	"sync"
	"time"

	"github.com/croessner/nauthilus-director/internal/placement"
	runtimectl "github.com/croessner/nauthilus-director/internal/runtime"
	"github.com/croessner/nauthilus-director/internal/state"
)

const (
	defaultEventSourceLeaseTTL = 30 * time.Minute
	heartbeatCallTimeout       = 5 * time.Second
)

// superviseEventStream keeps the session lease of one event stream alive and ends the stream on
// kick, drain, move, heartbeat failure or a local runtime close.
//
// The returned stop function must run after the proxied stream ended; it waits for the
// heartbeat loop and unregisters the local session handle.
func (h *Handler) superviseEventStream(ctx context.Context, lease placement.LeaseHandle, record *requestRecord) (context.Context, func()) {
	streamCtx, cancel := context.WithCancel(ctx)
	stopStream := func(reason string) {
		record.setReason(reason)
		cancel()
	}

	unregister := h.registerLocalStream(lease, stopStream)
	done := make(chan struct{})

	go func() {
		defer close(done)

		h.heartbeatEventStream(streamCtx, lease, stopStream)
	}()

	return streamCtx, func() {
		cancel()
		<-done
		unregister()
	}
}

// heartbeatEventStream refreshes the lease and honors control actions until the stream ends.
func (h *Handler) heartbeatEventStream(ctx context.Context, lease placement.LeaseHandle, stop func(string)) {
	ttl := h.eventSourceLeaseTTL()

	interval := h.config.Settings.EventSource.HeartbeatInterval.Std()
	if half := ttl / 2; half > 0 && (interval <= 0 || interval > half) {
		interval = half
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !h.heartbeatOnce(ctx, lease, ttl, stop) {
				return
			}
		}
	}
}

// heartbeatOnce refreshes the lease once and reports whether the stream may continue.
func (h *Handler) heartbeatOnce(ctx context.Context, lease placement.LeaseHandle, ttl time.Duration, stop func(string)) bool {
	heartbeatCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), heartbeatCallTimeout)
	defer cancel()

	record, err := lease.Heartbeat(heartbeatCtx, ttl)
	if err != nil {
		stop(reasonUnavailable)

		return false
	}

	switch record.ControlAction {
	case "", state.ControlActionNone:
		return true
	default:
		stop(reasonControlAction)

		return false
	}
}

// keepRequestHold refreshes a request hold every half TTL while a long request runs, so uploads,
// downloads and slow API calls keep the account's backend binding until they finish. Short
// requests end before the first tick and cost no extra Redis call. Control actions are not
// enforced here: an ordinary request finishes by itself and the next one is placed again.
func (h *Handler) keepRequestHold(ctx context.Context, lease placement.LeaseHandle) func() {
	ttl := h.config.Settings.Placement.RequestLeaseTTL.Std()

	interval := ttl / 2
	if interval <= 0 {
		return func() {}
	}

	holdCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})

	go func() {
		defer close(done)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-holdCtx.Done():
				return
			case <-ticker.C:
				heartbeatCtx, cancelHeartbeat := context.WithTimeout(context.WithoutCancel(holdCtx), heartbeatCallTimeout)
				_, _ = lease.Heartbeat(heartbeatCtx, ttl)

				cancelHeartbeat()
			}
		}
	}()

	return func() {
		cancel()
		<-done
	}
}

// registerLocalStream exposes the stream to runtime kick, backend drain and listener hard drain.
func (h *Handler) registerLocalStream(lease placement.LeaseHandle, stop func(string)) func() {
	if h.config.LocalSessions == nil {
		return func() {}
	}

	var once sync.Once

	handle := runtimectl.LocalSessionHandleFunc(func(context.Context, runtimectl.LocalSessionControl) error {
		once.Do(func() { stop(reasonControlAction) })

		return nil
	})

	affinity := lease.Affinity()

	unregister, err := h.config.LocalSessions.Register(runtimectl.LocalSessionInfo{
		SessionID:         lease.SessionID(),
		ListenerName:      h.config.ListenerName,
		Tenant:            affinity.Key.Tenant,
		UserHash:          affinity.Key.AccountKey,
		BackendIdentifier: lease.Backend().Backend.Identifier,
		DirectorInstance:  h.config.DirectorInstanceID,
	}, handle)
	if err != nil {
		return func() {}
	}

	return unregister
}
