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
	"io"
	"net"
	"strings"
	"time"
)

const serviceUnavailableReply = "421 4.3.2 LMTP protocol state machine unavailable\r\n"

// SessionConfig contains listener-owned values needed by the LMTP protocol boundary.
type SessionConfig struct {
	ListenerName       string
	ServiceName        string
	BackendPool        string
	TLSMode            string
	Capabilities       []string
	PreauthTimeout     time.Duration
	MaxLineBytes       int
	RequirePeerAuth    bool
	PeerAuthMechanisms []string
	MTLSPeerAuth       MTLSPeerAuthConfig
}

// MTLSPeerAuthConfig describes when verified client certificates may satisfy peer auth.
type MTLSPeerAuthConfig struct {
	SatisfiesRequired bool
	IdentitySource    string
}

// Handler owns one accepted LMTP frontend stream.
type Handler struct {
	config SessionConfig
}

// NewHandler creates an LMTP protocol handler from typed listener config.
func NewHandler(config SessionConfig) *Handler {
	config.ListenerName = strings.TrimSpace(config.ListenerName)
	config.ServiceName = strings.TrimSpace(config.ServiceName)
	config.BackendPool = strings.TrimSpace(config.BackendPool)
	config.TLSMode = strings.TrimSpace(config.TLSMode)
	config.MTLSPeerAuth.IdentitySource = strings.TrimSpace(config.MTLSPeerAuth.IdentitySource)

	return &Handler{config: config}
}

// Serve fails accepted LMTP streams closed until the command state machine is available.
func (h *Handler) Serve(ctx context.Context, conn net.Conn) error {
	if conn == nil {
		return nil
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if h != nil && h.config.PreauthTimeout > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(h.config.PreauthTimeout))
	}

	_, err := io.WriteString(conn, serviceUnavailableReply)

	return err
}
