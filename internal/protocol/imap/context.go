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
	"net"
	"time"
)

const (
	// TLSModeImplicit marks IMAPS-style listeners where TLS is active before greeting.
	TLSModeImplicit = "implicit"
	// TLSModeStartTLS marks IMAP listeners where STARTTLS will be advertised by command handling.
	TLSModeStartTLS = "starttls"
)

// SessionConfig contains the listener-owned values needed to create IMAP sessions.
type SessionConfig struct {
	ListenerName           string
	ServiceName            string
	Network                string
	TLSMode                string
	Capabilities           []string
	PreauthTimeout         time.Duration
	AuthTimeout            time.Duration
	BackendConnectTimeout  time.Duration
	ProxyIdleTimeout       time.Duration
	MaxPreauthLineBytes    int
	MaxPreauthLiteralBytes int
}

// Context records stable, secret-safe session metadata for protocol handling.
type Context struct {
	ID                     string
	ListenerName           string
	ServiceName            string
	Network                string
	TLSMode                string
	LocalAddr              net.Addr
	RemoteAddr             net.Addr
	StartedAt              time.Time
	PreauthTimeout         time.Duration
	AuthTimeout            time.Duration
	BackendConnectTimeout  time.Duration
	ProxyIdleTimeout       time.Duration
	MaxPreauthLineBytes    int
	MaxPreauthLiteralBytes int
	Capabilities           []string
}

// StartTLSAvailable reports whether this session can later expose STARTTLS.
func (c Context) StartTLSAvailable() bool {
	return c.TLSMode == TLSModeStartTLS
}

// ImplicitTLS reports whether TLS was already active when the IMAP session started.
func (c Context) ImplicitTLS() bool {
	return c.TLSMode == TLSModeImplicit
}
