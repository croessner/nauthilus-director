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

package observability

import (
	"context"
	"runtime"
	"sync"

	"github.com/croessner/nauthilus-director/internal/config"
)

const (
	runtimeBlockProfileRate     = 1
	runtimeMutexProfileFraction = 1
	runtimeProfileSamplingOff   = 0
)

// ProfileRuntime owns process-wide Go profile sampling rates for this process.
type ProfileRuntime struct {
	config       config.ProfilesConfig
	configurator profileConfigurator
	mu           sync.Mutex
}

type profileConfigurator interface {
	SetBlockProfileRate(rate int)
	SetMutexProfileFraction(fraction int) int
}

type goProfileConfigurator struct{}

// newProfileRuntime creates the runtime profile owner without applying sampling yet.
func newProfileRuntime(cfg config.ProfilesConfig, configurator profileConfigurator) *ProfileRuntime {
	if configurator == nil {
		configurator = goProfileConfigurator{}
	}

	return &ProfileRuntime{config: cfg, configurator: configurator}
}

// Apply installs explicit Go profile sampling rates for the configured profile surface.
func (p *ProfileRuntime) Apply() {
	if p == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.applyLocked()
}

// Shutdown disables process-wide profile samplers owned by this runtime.
func (p *ProfileRuntime) Shutdown(context.Context) error {
	if p == nil {
		return nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.disableLocked()

	return nil
}

// PProfEnabled reports whether the protected pprof surface is configured.
func (p *ProfileRuntime) PProfEnabled() bool {
	if p == nil {
		return false
	}

	return p.config.PProf.Enabled
}

// BlockEnabled reports whether block profiling is configured.
func (p *ProfileRuntime) BlockEnabled() bool {
	if p == nil {
		return false
	}

	return p.config.PProf.Enabled && p.config.Block.Enabled
}

// MutexEnabled reports whether mutex profiling is configured.
func (p *ProfileRuntime) MutexEnabled() bool {
	if p == nil {
		return false
	}

	return p.config.PProf.Enabled && p.config.Mutex.Enabled
}

// GoroutineEnabled reports whether goroutine profiles are configured for pprof.
func (p *ProfileRuntime) GoroutineEnabled() bool {
	if p == nil {
		return false
	}

	return p.config.PProf.Enabled && p.config.Goroutine.Enabled
}

// applyLocked applies runtime samplers while the caller holds p.mu.
func (p *ProfileRuntime) applyLocked() {
	if !p.config.PProf.Enabled {
		p.disableLocked()

		return
	}

	if p.config.Block.Enabled {
		p.configurator.SetBlockProfileRate(runtimeBlockProfileRate)
	} else {
		p.configurator.SetBlockProfileRate(runtimeProfileSamplingOff)
	}

	if p.config.Mutex.Enabled {
		_ = p.configurator.SetMutexProfileFraction(runtimeMutexProfileFraction)
	} else {
		_ = p.configurator.SetMutexProfileFraction(runtimeProfileSamplingOff)
	}
}

// disableLocked turns process-wide samplers off while the caller holds p.mu.
func (p *ProfileRuntime) disableLocked() {
	p.configurator.SetBlockProfileRate(runtimeProfileSamplingOff)
	_ = p.configurator.SetMutexProfileFraction(runtimeProfileSamplingOff)
}

// SetBlockProfileRate updates the process-wide runtime block sampler.
func (goProfileConfigurator) SetBlockProfileRate(rate int) {
	runtime.SetBlockProfileRate(rate)
}

// SetMutexProfileFraction updates the process-wide runtime mutex sampler.
func (goProfileConfigurator) SetMutexProfileFraction(fraction int) int {
	return runtime.SetMutexProfileFraction(fraction)
}
