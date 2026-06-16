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

// ControlAction describes a heartbeat-observed runtime control action.
type ControlAction string

const (
	// ControlActionNone means the session may continue proxying.
	ControlActionNone ControlAction = "none"
	// ControlActionKick asks the proxy to close after an operator kick.
	ControlActionKick ControlAction = "kick"
	// ControlActionDrain asks the proxy to close because backend drain or maintenance affected it.
	ControlActionDrain ControlAction = "drain"
	// ControlActionMoveGenerationChanged asks the proxy to close after a move-generation change.
	ControlActionMoveGenerationChanged ControlAction = "move_generation_changed"
)

const (
	// HolderKindSession marks a mailbox login session exposed by runtime session APIs.
	HolderKindSession = "session"
	// HolderKindDelivery marks a delivery-scoped affinity hold hidden from session APIs.
	HolderKindDelivery = "delivery"
)

// BindingStatus reports whether a backend-node binding is active, retained or absent.
type BindingStatus string

const (
	// BindingStatusNone means no backend binding exists for the affinity key.
	BindingStatusNone BindingStatus = "none"
	// BindingStatusActive means at least one holder currently protects the binding.
	BindingStatusActive BindingStatus = "active_binding"
	// BindingStatusRetained means the binding has no active holders but remains authoritative.
	BindingStatusRetained BindingStatus = "retained_binding"
	// BindingStatusExpired means a stale physical binding has passed its retention deadline.
	BindingStatusExpired BindingStatus = "expired_binding"
	// BindingStatusBackendNodeMismatch means Redis preserved an existing binding over a proposal.
	BindingStatusBackendNodeMismatch BindingStatus = "backend_node_mismatch"
)

// AffinityKey identifies a user affinity record without requiring raw usernames in keys.
type AffinityKey struct {
	Tenant     string
	AccountKey string
}

// AffinityRecord stores the Redis-visible backend binding for active or retained affinity.
type AffinityRecord struct {
	Key                AffinityKey
	ShardTag           string
	BackendNode        string
	Generation         string
	ActiveSessionCount int
	ActiveHolderCount  int
	ExpiresAt          time.Time
	LeaseExpiresAt     time.Time
	RetentionExpiresAt time.Time
	ServerTime         time.Time
	Status             string
	Present            bool
	ControlAction      ControlAction
	ControlGeneration  string
	BackendIdentifier  string
	BindingGeneration  string
	BindingStatus      BindingStatus
	MoveTargetShard    string
	MoveStrategy       string
}

// SessionRecord describes one lease-backed frontend session.
type SessionRecord struct {
	ID                 string
	Key                AffinityKey
	HolderKind         string
	Protocol           string
	ListenerName       string
	ServiceName        string
	ShardTag           string
	BackendNode        string
	DirectorInstanceID string
	LeaseTTL           time.Duration
	IdleGrace          time.Duration
	RetentionTTL       time.Duration
}

// SessionBackendAttachment describes selected-backend registration after placement.
type SessionBackendAttachment struct {
	Key               AffinityKey
	SessionID         string
	BackendIdentifier string
	BackendNode       string
	ReservationID     string
	MaxConnections    int
}

// SessionBackendRecord describes the attached backend count and session generation.
type SessionBackendRecord struct {
	Status             string
	BackendIdentifier  string
	BackendNode        string
	ReservationID      string
	BackendActiveCount int
	ServerTime         time.Time
	LeaseExpiresAt     time.Time
	ControlGeneration  string
}

// BackendReservationRequest asks Redis to reserve one backend capacity slot.
type BackendReservationRequest struct {
	BackendIdentifier string
	ReservationID     string
	MaxConnections    int
	LeaseTTL          time.Duration
}

// BackendReservationReleaseRequest asks Redis to release one backend capacity slot.
type BackendReservationReleaseRequest struct {
	BackendIdentifier string
	ReservationID     string
}

// BackendReservationReapRequest asks Redis to repair expired backend reservations.
type BackendReservationReapRequest struct {
	BackendIdentifier string
	Limit             int
}

// BackendReservationRecord describes one backend reservation mutation result.
type BackendReservationRecord struct {
	Status             string
	BackendIdentifier  string
	ReservationID      string
	BackendActiveCount int
	RepairedCount      int
	ServerTime         time.Time
	LeaseExpiresAt     time.Time
}

// RuntimeSessionRecord describes one Redis-visible frontend session for control reads.
type RuntimeSessionRecord struct {
	SessionID         string
	Key               AffinityKey
	Protocol          string
	ListenerName      string
	ServiceName       string
	ShardTag          string
	BackendNode       string
	BackendIdentifier string
	DirectorInstance  string
	OpenedAt          time.Time
	LeaseExpiresAt    time.Time
	ControlGeneration string
	Status            string
}

// RuntimeUserReadRecord describes one Redis-visible user affinity for control reads.
type RuntimeUserReadRecord struct {
	Key                AffinityKey
	ShardTag           string
	BackendNode        string
	ActiveSessionCount int
	ActiveHolderCount  int
	Generation         string
	BindingGeneration  string
	BindingStatus      BindingStatus
	RetentionExpiresAt time.Time
	UpdatedAt          time.Time
	Present            bool
}

// UserMoveRequest describes an atomic user move state mutation.
type UserMoveRequest struct {
	Key         AffinityKey
	TargetShard string
	Strategy    string
	Reason      string
	Actor       string
}

// UserKickRequest describes an atomic user kick state mutation.
type UserKickRequest struct {
	Key    AffinityKey
	Reason string
	Actor  string
}

// UserClearRequest describes an atomic inactive-affinity clear mutation.
type UserClearRequest struct {
	Key              AffinityKey
	AllowActiveClear bool
	Reason           string
	Actor            string
}

// UserBackendPinScope contains the bounded selector facts for one pin scope.
type UserBackendPinScope struct {
	BackendIdentifier string
	Protocol          string
	BackendPool       string
	ShardTag          string
	BackendNode       string
}

// UserBackendPinSetRequest describes an atomic single-scope backend-pin mutation.
type UserBackendPinSetRequest struct {
	Key               AffinityKey
	BackendIdentifier string
	Protocol          string
	BackendPool       string
	ShardTag          string
	BackendNode       string
	Strategy          string
	Reason            string
	Actor             string
}

// UserBackendPinsSetRequest describes an atomic multi-scope backend-pin mutation.
type UserBackendPinsSetRequest struct {
	Key      AffinityKey
	Pins     []UserBackendPinScope
	Strategy string
	Reason   string
	Actor    string
}

// UserBackendPinGetRequest describes one scoped backend-pin read by affinity key.
type UserBackendPinGetRequest struct {
	Key         AffinityKey
	Protocol    string
	BackendPool string
}

// UserBackendPinsListRequest describes a deterministic backend-pin set read.
type UserBackendPinsListRequest struct {
	Key AffinityKey
}

// UserBackendPinClearRequest describes an atomic single-scope backend-pin clear mutation.
type UserBackendPinClearRequest struct {
	Key         AffinityKey
	Protocol    string
	BackendPool string
	Reason      string
	Actor       string
}

// UserBackendPinsClearRequest describes an atomic all-scope backend-pin clear mutation.
type UserBackendPinsClearRequest struct {
	Key    AffinityKey
	Reason string
	Actor  string
}

// UserHoldSetRequest describes an atomic user placement-hold mutation.
type UserHoldSetRequest struct {
	Key         AffinityKey
	Duration    time.Duration
	MaxDuration time.Duration
	Reason      string
	Actor       string
}

// UserHoldGetRequest describes one placement-hold read by affinity key.
type UserHoldGetRequest struct {
	Key AffinityKey
}

// UserHoldClearRequest describes an atomic placement-hold clear mutation.
type UserHoldClearRequest struct {
	Key    AffinityKey
	Reason string
	Actor  string
}

// UserHoldCheckRequest describes one read-only placement gate check.
type UserHoldCheckRequest struct {
	Key AffinityKey
}

// UserHoldRecord describes Redis-backed placement-hold state after a read or mutation.
type UserHoldRecord struct {
	Present           bool
	Status            string
	Key               AffinityKey
	Generation        string
	CreatedAt         time.Time
	ExpiresAt         time.Time
	RequestedDuration time.Duration
	UpdatedAt         time.Time
	ServerTime        time.Time
}

// UserHoldStore owns Redis-backed user placement-hold reads and mutations.
type UserHoldStore interface {
	SetUserHold(ctx context.Context, request UserHoldSetRequest) (UserHoldRecord, error)
	GetUserHold(ctx context.Context, request UserHoldGetRequest) (UserHoldRecord, error)
	ClearUserHold(ctx context.Context, request UserHoldClearRequest) (UserHoldRecord, error)
	CheckUserHold(ctx context.Context, request UserHoldCheckRequest) (UserHoldRecord, error)
}

// UserBackendPinRecord describes Redis-backed backend-pin state after a read or mutation.
type UserBackendPinRecord struct {
	Present            bool
	Status             string
	Key                AffinityKey
	BackendIdentifier  string
	Protocol           string
	BackendPool        string
	ShardTag           string
	BackendNode        string
	Strategy           string
	Generation         string
	Reason             string
	Actor              string
	ActiveSessionCount int
	UpdatedAt          time.Time
	ServerTime         time.Time
	Legacy             bool
}

// UserBackendPinsRecord describes a deterministic Redis-backed backend-pin set.
type UserBackendPinsRecord struct {
	Present            bool
	Status             string
	Key                AffinityKey
	Pins               []UserBackendPinRecord
	Generation         string
	ActiveSessionCount int
	ServerTime         time.Time
}

// UserRuntimeRecord describes Redis-backed user runtime state after a mutation.
type UserRuntimeRecord struct {
	Status             string
	Key                AffinityKey
	ShardTag           string
	TargetShard        string
	Strategy           string
	ActiveSessionCount int
	Generation         string
	ControlAction      ControlAction
	ServerTime         time.Time
}

// SessionKillRequest describes an atomic session-specific control mutation.
type SessionKillRequest struct {
	SessionID string
	Reason    string
	Actor     string
}

// SessionKillRecord describes the session-specific control action outcome.
type SessionKillRecord struct {
	Status            string
	SessionID         string
	ControlAction     ControlAction
	ControlGeneration string
	ServerTime        time.Time
}

// ReapRequest describes a bounded expired-session repair pass.
type ReapRequest struct {
	Limit           int
	MaxPassDuration time.Duration
}

// ReapRecord describes expired session repair work completed by Redis.
type ReapRecord struct {
	Status            string
	ScannedSessions   int
	ExpiredSessions   int
	StaleIndexEntries int
	RepairedBackends  int
	ServerTime        time.Time
	aggregateRemovals []string
	idleAffinities    []aggregateIdleAffinity
	releases          []BackendReservationReleaseRequest
}

// BackendRuntimeMutation describes an atomic backend runtime override change.
type BackendRuntimeMutation struct {
	BackendIdentifier string
	InService         *bool
	Weight            *int
	MaintenanceMode   string
	DrainMode         string
	DrainEnabled      bool
	Reason            string
	Actor             string
}

// BackendRuntimeClearRequest describes an atomic backend runtime override clear.
type BackendRuntimeClearRequest struct {
	BackendIdentifier string
	Reason            string
	Actor             string
}

// BackendRuntimeRecord describes Redis-backed backend runtime state after mutation.
type BackendRuntimeRecord struct {
	Status             string
	BackendIdentifier  string
	Generation         string
	ActiveSessionCount int
	MarkedSessionCount int
	ServerTime         time.Time
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
	AttachSelectedBackend(ctx context.Context, attachment SessionBackendAttachment) (SessionBackendRecord, error)
	HeartbeatSession(ctx context.Context, key AffinityKey, sessionID string, ttl time.Duration) (AffinityRecord, error)
	CloseSession(ctx context.Context, key AffinityKey, sessionID string) (AffinityRecord, error)
}

// BackendReservationStore owns Redis-backed backend capacity reservations.
type BackendReservationStore interface {
	ReserveBackendCapacity(ctx context.Context, request BackendReservationRequest) (BackendReservationRecord, error)
	ReleaseBackendReservation(ctx context.Context, request BackendReservationReleaseRequest) (BackendReservationRecord, error)
	ReapBackendReservations(ctx context.Context, request BackendReservationReapRequest) (BackendReservationRecord, error)
}

// RuntimeStateStore owns Redis-backed operator runtime state.
type RuntimeStateStore interface {
	BackendState(ctx context.Context, backendIdentifier string) (BackendRuntimeState, error)
	SetBackendState(ctx context.Context, state BackendRuntimeState) error
}
