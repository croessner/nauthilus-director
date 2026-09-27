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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/placement"
	"github.com/croessner/nauthilus-director/internal/routing"
	runtimectl "github.com/croessner/nauthilus-director/internal/runtime"
	"github.com/croessner/nauthilus-director/internal/state"
)

const holderIDBytes = 16

var (
	// errMissingShard reports an authenticated account whose authority result carries no shard fact.
	errMissingShard = errors.New("jmap: shard attribute missing")
	// errRoutingUnavailable reports a routing or placement dependency that cannot decide.
	errRoutingUnavailable = errors.New("jmap: routing unavailable")
)

// route is the logical routing decision for one authenticated account.
type route struct {
	result routing.RoutingResult
}

// resolveRoute maps the principal onto a shard, failing closed when the shard fact is missing.
//
// The shared resolver chain falls back to rendezvous hashing when the configured shard attribute
// is absent. For JMAP that fallback is refused unless the listener explicitly allows it, because a
// hashed shard would silently serve an empty mailbox on the wrong backend.
func (h *Handler) resolveRoute(ctx context.Context, request *http.Request, who principal) (route, error) {
	if h.config.RoutingResolver == nil {
		return route{}, errRoutingUnavailable
	}

	result, err := h.config.RoutingResolver.Resolve(ctx, routing.RoutingRequest{
		Tenant:            strings.TrimSpace(h.config.DefaultTenant),
		Protocol:          Protocol,
		ListenerName:      h.config.ListenerName,
		ServiceName:       h.config.ServiceName,
		BackendPool:       h.config.BackendPool,
		LoginName:         who.account,
		NormalizedAccount: who.account,
		AuthAttributes:    cloneAttributes(who.attributes),
		ClientIP:          requestClientIP(request),
	})
	if err != nil {
		if routing.IsErrorKind(err, routing.ErrorKindMissingFact) {
			return route{}, errMissingShard
		}

		return route{}, errors.Join(errRoutingUnavailable, err)
	}

	if result.RoutingSource == routing.SourceHash && h.config.Settings.Routing.MissingShard != config.JMAPMissingShardHashFallback {
		return route{}, errMissingShard
	}

	if !result.Complete() {
		return route{}, errRoutingUnavailable
	}

	return route{result: result}, nil
}

// placementLease opens the request hold or, for event streams, the counted session lease.
func (h *Handler) placementLease(ctx context.Context, target endpoint, decided route) (placement.LeaseHandle, error) {
	if h.config.PlacementService == nil {
		return nil, errRoutingUnavailable
	}

	key := state.AffinityKey{
		Tenant:     strings.TrimSpace(decided.result.Tenant),
		AccountKey: strings.ToLower(strings.TrimSpace(decided.result.AccountKey)),
	}

	if err := h.waitForPlacementGate(ctx, key); err != nil {
		return nil, err
	}

	holderID, err := newHolderID()
	if err != nil {
		return nil, err
	}

	request := placement.Request{
		Key:                key,
		SessionID:          holderID,
		Protocol:           Protocol,
		BackendPool:        h.config.BackendPool,
		ShardTag:           strings.TrimSpace(decided.result.ShardTag),
		ListenerName:       h.config.ListenerName,
		ServiceName:        h.config.ServiceName,
		DirectorInstanceID: h.config.DirectorInstanceID,
		IdleGrace:          h.config.SessionIdleGrace,
		RetentionTTL:       h.config.BackendRetentionTTL,
	}

	if target == endpointEventSource {
		request.LeaseTTL = h.eventSourceLeaseTTL()

		return h.config.PlacementService.PlaceSession(ctx, request)
	}

	request.LeaseTTL = h.config.Settings.Placement.RequestLeaseTTL.Std()

	return h.config.PlacementService.PlaceRequestHold(ctx, request)
}

// waitForPlacementGate applies operator user holds before placement state is read.
func (h *Handler) waitForPlacementGate(ctx context.Context, key state.AffinityKey) error {
	if h.config.PlacementGate == nil {
		return nil
	}

	_, err := h.config.PlacementGate.WaitForPlacement(ctx, runtimectl.PlacementGateRequest{
		Key:          runtimectl.UserKey{Tenant: key.Tenant, UserHash: key.AccountKey},
		Protocol:     Protocol,
		ListenerName: h.config.ListenerName,
		ServiceName:  h.config.ServiceName,
	})

	return err
}

// eventSourceLeaseTTL returns the session lease TTL for long-lived event streams.
func (h *Handler) eventSourceLeaseTTL() time.Duration {
	if h.config.SessionLeaseTTL > 0 {
		return h.config.SessionLeaseTTL
	}

	return defaultEventSourceLeaseTTL
}

// newHolderID creates an opaque placement holder identifier.
func newHolderID() (string, error) {
	raw := make([]byte, holderIDBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", errors.New("jmap: create holder id")
	}

	return hex.EncodeToString(raw), nil
}
