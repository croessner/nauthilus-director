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

package config

import "strings"

const fallbackDefaultShard = "default"

// Normalize returns a config snapshot with derived runtime defaults applied.
func (c Config) Normalize() Config {
	c.Director = c.Director.Normalize()

	return c
}

// Normalize returns director config with non-empty effective backend shard tags.
func (d DirectorConfig) Normalize() DirectorConfig {
	d.Routing.DefaultShard = d.Routing.EffectiveDefaultShard()

	if d.Backends == nil {
		return d
	}

	backends := make(map[string]BackendConfig, len(d.Backends))
	for name, backend := range d.Backends {
		backend.ShardTag = strings.TrimSpace(backend.ShardTag)
		if backend.ShardTag == "" {
			backend.ShardTag = d.Routing.DefaultShard
		}

		backends[name] = backend
	}

	d.Backends = backends

	return d
}

// EffectiveDefaultShard returns the non-empty routing fallback shard.
func (r RoutingConfig) EffectiveDefaultShard() string {
	shard := strings.TrimSpace(r.DefaultShard)
	if shard == "" {
		return fallbackDefaultShard
	}

	return shard
}
