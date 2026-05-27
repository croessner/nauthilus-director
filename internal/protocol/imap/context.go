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

package imap

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/proxy"
	"github.com/croessner/nauthilus-director/internal/routing"
	runtimectl "github.com/croessner/nauthilus-director/internal/runtime"
	"github.com/croessner/nauthilus-director/internal/state"
)

const (
	// TLSModeImplicit marks IMAPS-style listeners where TLS is active before greeting.
	TLSModeImplicit = "implicit"
	// TLSModeStartTLS marks IMAP listeners where STARTTLS will be advertised by command handling.
	TLSModeStartTLS = "starttls"

	defaultTenantName = "default"
	protocolIMAP      = "imap"
)

// Placement records the director-owned routing and selection facts for an authenticated session.
type Placement struct {
	AuthResult       nauthilus.AuthResult
	Routing          routing.RoutingResult
	Affinity         state.AffinityRecord
	Backend          backend.SelectionResult
	SelectedShardTag string
}

// Clone returns a detached placement snapshot.
func (p Placement) Clone() Placement {
	p.AuthResult.Attributes = cloneStringSlices(p.AuthResult.Attributes)
	p.Routing = p.Routing.Clone()

	return p
}

// SessionConfig contains the listener-owned values needed to create IMAP sessions.
type SessionConfig struct {
	ListenerName           string
	AuthorityName          string
	AuthorityTransport     string
	ServiceName            string
	Network                string
	BackendPool            string
	DirectorInstanceID     string
	DefaultTenant          string
	DefaultShard           string
	TLSMode                string
	Capabilities           []string
	AuthMechanisms         []string
	MaxBearerTokenBytes    int
	RequireIDBeforeAuth    bool
	SessionLeaseTTL        time.Duration
	SessionIdleGrace       time.Duration
	PreauthTimeout         time.Duration
	AuthTimeout            time.Duration
	BackendConnectTimeout  time.Duration
	ProxyIdleTimeout       time.Duration
	MaxPreauthLineBytes    int
	MaxPreauthLiteralBytes int
	FrontendTLSConfig      *tls.Config
	Authenticator          nauthilus.Authenticator
	RoutingResolver        routing.RoutingResolver
	SessionStore           state.SessionStore
	BackendSelector        backend.Selector
	BackendConnector       BackendConnector
	ProxyRunner            proxy.Runner
	LocalSessions          *runtimectl.LocalSessionRegistry
	Observability          observability.Recorder
}

// Context records stable, secret-safe session metadata for protocol handling.
type Context struct {
	ID                     string
	ListenerName           string
	AuthorityName          string
	AuthorityTransport     string
	ServiceName            string
	Network                string
	BackendPool            string
	DirectorInstanceID     string
	DefaultTenant          string
	DefaultShard           string
	TLSMode                string
	LocalAddr              net.Addr
	RemoteAddr             net.Addr
	StartedAt              time.Time
	FrontendTLSConfig      *tls.Config
	PreauthTimeout         time.Duration
	AuthTimeout            time.Duration
	BackendConnectTimeout  time.Duration
	ProxyIdleTimeout       time.Duration
	MaxPreauthLineBytes    int
	MaxPreauthLiteralBytes int
	Capabilities           []string
	AuthMechanisms         []string
	MaxBearerTokenBytes    int
	RequireIDBeforeAuth    bool
	SessionLeaseTTL        time.Duration
	SessionIdleGrace       time.Duration
}

// StartTLSAvailable reports whether this session can later expose STARTTLS.
func (c Context) StartTLSAvailable() bool {
	return c.TLSMode == TLSModeStartTLS
}

// ImplicitTLS reports whether TLS was already active when the IMAP session started.
func (c Context) ImplicitTLS() bool {
	return c.TLSMode == TLSModeImplicit
}
