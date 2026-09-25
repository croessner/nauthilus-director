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

package backend

import (
	"crypto/tls"
	"sync"
	"time"
)

const (
	// clientTLSConfigTTL bounds how long a built backend client TLS configuration is reused, so rotated CA
	// files on disk take effect without a restart.
	clientTLSConfigTTL = 5 * time.Minute
	// clientTLSSessionCacheCapacity bounds the resumable TLS sessions kept per backend.
	clientTLSSessionCacheCapacity = 256
)

// ClientTLSConfigCache reuses the client TLS configuration of each backend across connections and gives every
// backend its own TLS session cache. Building the configuration read and parsed the CA file for every connection,
// and without a session cache every connection paid a full handshake on both sides. Sessions are kept per backend
// identifier because several backends can share one server name while running separate TLS servers.
type ClientTLSConfigCache struct {
	mu      sync.Mutex
	entries map[string]*clientTLSConfigEntry
	now     func() time.Time
}

// clientTLSConfigEntry is the configuration built for one backend's TLS settings.
type clientTLSConfigEntry struct {
	settings TLSConfig
	config   *tls.Config
	sessions tls.ClientSessionCache
	built    time.Time
}

// NewClientTLSConfigCache creates an empty cache.
func NewClientTLSConfigCache() *ClientTLSConfigCache {
	return &ClientTLSConfigCache{entries: make(map[string]*clientTLSConfigEntry), now: time.Now}
}

// Config returns the configuration for target, calling build only when none exists, the backend TLS settings
// changed or the cached one is older than the TTL. The returned configuration is shared and must not be modified.
// A nil cache builds a fresh configuration without session resumption.
func (c *ClientTLSConfigCache) Config(target Backend, build func() (*tls.Config, error)) (*tls.Config, error) {
	if c == nil {
		return build()
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()

	entry, exists := c.entries[target.Identifier]
	if exists && entry.settings == target.TLS && now.Sub(entry.built) < clientTLSConfigTTL {
		return entry.config, nil
	}

	config, err := build()
	if err != nil {
		return nil, err
	}

	sessions := tls.NewLRUClientSessionCache(clientTLSSessionCacheCapacity)
	if exists && entry.settings == target.TLS {
		sessions = entry.sessions
	}

	config.ClientSessionCache = sessions
	c.entries[target.Identifier] = &clientTLSConfigEntry{settings: target.TLS, config: config, sessions: sessions, built: now}

	return config, nil
}
