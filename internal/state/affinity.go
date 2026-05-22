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

package state

import (
	"context"
	"time"
)

// AffinityKey identifies a user affinity record without requiring raw usernames in keys.
type AffinityKey struct {
	Tenant     string
	AccountKey string
}

// AffinityRecord stores the logical shard pin for active sessions.
type AffinityRecord struct {
	Key                AffinityKey
	ShardTag           string
	Generation         string
	ActiveSessionCount int
	ExpiresAt          time.Time
	LeaseExpiresAt     time.Time
	ServerTime         time.Time
	Status             string
	Present            bool
}

// SessionRecord describes one lease-backed frontend session.
type SessionRecord struct {
	ID        string
	Key       AffinityKey
	Protocol  string
	ShardTag  string
	LeaseTTL  time.Duration
	IdleGrace time.Duration
}

// BackendRuntimeState contains mutable operator state for a backend entry.
type BackendRuntimeState struct {
	BackendIdentifier string
	InService         bool
	Draining          bool
	Weight            int
	Generation        string
}

// AffinityStore owns Redis-backed shard affinity reads and mutations.
type AffinityStore interface {
	LookupAffinity(ctx context.Context, key AffinityKey) (AffinityRecord, error)
}

// SessionStore owns lease-backed session coordination.
type SessionStore interface {
	OpenSession(ctx context.Context, record SessionRecord) (AffinityRecord, error)
	HeartbeatSession(ctx context.Context, key AffinityKey, sessionID string, ttl time.Duration) (AffinityRecord, error)
	CloseSession(ctx context.Context, key AffinityKey, sessionID string) (AffinityRecord, error)
}

// RuntimeStateStore owns Redis-backed operator runtime state.
type RuntimeStateStore interface {
	BackendState(ctx context.Context, backendIdentifier string) (BackendRuntimeState, error)
	SetBackendState(ctx context.Context, state BackendRuntimeState) error
}
