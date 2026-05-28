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

package lmtp

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/routing"
	"github.com/croessner/nauthilus-director/internal/state"
)

const (
	// TLSModeImplicit marks LMTPS-style listeners where TLS is active before greeting.
	TLSModeImplicit = "implicit"
	// TLSModeStartTLS marks cleartext LMTP listeners where STARTTLS may be advertised.
	TLSModeStartTLS = "starttls"

	protocolLMTP       = "lmtp"
	defaultMaxLineSize = 8192
)

var errNilSessionConnection = errors.New("lmtp: session connection is nil")

// SessionConfig contains listener-owned values needed by the LMTP protocol boundary.
type SessionConfig struct {
	ListenerName            string
	AuthorityName           string
	AuthorityTransport      string
	ServiceName             string
	Network                 string
	BackendPool             string
	DirectorInstanceID      string
	DefaultTenant           string
	DefaultShard            string
	TLSMode                 string
	Capabilities            []string
	PreauthTimeout          time.Duration
	AuthTimeout             time.Duration
	SessionLeaseTTL         time.Duration
	SessionIdleGrace        time.Duration
	MaxLineBytes            int
	MaxBearerTokenBytes     int
	RequirePeerAuth         bool
	RequireTLSClientCert    bool
	PeerAuthMechanisms      []string
	MTLSPeerAuth            MTLSPeerAuthConfig
	BackendChunkingAllowed  bool
	RecipientLookupRequired bool
	FrontendTLSConfig       *tls.Config
	Authenticator           nauthilus.Authenticator
	IdentityLookuper        nauthilus.IdentityLookuper
	RoutingResolver         routing.RoutingResolver
	SessionStore            state.SessionStore
	BackendSelector         backend.Selector
	MessageSink             MessageSink
}

// MTLSPeerAuthConfig describes when verified client certificates may satisfy peer auth.
type MTLSPeerAuthConfig struct {
	SatisfiesRequired bool
	IdentitySource    string
}

// MessageSink opens a streaming destination for one frontend LMTP message body.
type MessageSink interface {
	OpenMessage(ctx context.Context, transaction TransactionSnapshot) (MessageBody, error)
}

// MessageBody accepts opaque DATA or BDAT payload bytes without retaining the full message.
type MessageBody interface {
	Write(payload []byte) (int, error)
	Finish(ctx context.Context) (MessageResult, error)
	Abort(ctx context.Context, reasonClass string) error
}

// TransactionSnapshot exposes bounded transaction facts to backend message handling.
type TransactionSnapshot struct {
	RecipientCount int
	Recipients     []RecipientSnapshot
}

// RecipientSnapshot exposes backend-safe recipient routing facts to the message sink.
type RecipientSnapshot struct {
	WirePath          string
	AccountKey        string
	Tenant            string
	ShardTag          string
	BackendIdentifier string
}

// MessageResult describes the final status returned after DATA or BDAT LAST.
type MessageResult struct {
	Status string
	Text   string
}

// Handler owns one accepted LMTP frontend stream.
type Handler struct {
	config SessionConfig
}

// NewHandler creates an LMTP protocol handler from typed listener config.
func NewHandler(config SessionConfig) *Handler {
	config.ListenerName = strings.TrimSpace(config.ListenerName)
	config.AuthorityName = strings.TrimSpace(config.AuthorityName)
	config.AuthorityTransport = strings.TrimSpace(config.AuthorityTransport)
	config.ServiceName = strings.TrimSpace(config.ServiceName)
	config.Network = strings.TrimSpace(config.Network)
	config.BackendPool = strings.TrimSpace(config.BackendPool)
	config.TLSMode = strings.TrimSpace(config.TLSMode)
	config.MTLSPeerAuth.IdentitySource = strings.TrimSpace(config.MTLSPeerAuth.IdentitySource)

	return &Handler{config: config}
}

// Serve accepts one frontend connection and runs the bounded LMTP session.
func (h *Handler) Serve(ctx context.Context, conn net.Conn) error {
	session, err := NewSession(h.config, conn)
	if err != nil {
		return err
	}

	return session.Serve(ctx)
}

// effectiveMaxLineBytes returns the configured protocol line bound or a conservative default.
func effectiveMaxLineBytes(configured int) int {
	if configured > 0 {
		return configured
	}

	return defaultMaxLineSize
}

// cloneTLSConfig detaches mutable frontend TLS config from session callers.
func cloneTLSConfig(config *tls.Config) *tls.Config {
	if config == nil {
		return nil
	}

	return config.Clone()
}

// defaultAuthTimeout returns the timeout used around credential authority calls.
func defaultAuthTimeout(configured time.Duration) time.Duration {
	if configured > 0 {
		return configured
	}

	return time.Second
}
