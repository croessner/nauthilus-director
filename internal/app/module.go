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

// Package app owns production process composition and lifecycle wiring.
package app

import (
	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/listener"
	"go.uber.org/fx"
)

// Module returns the root application composition module.
func Module() fx.Option {
	return fx.Options(
		listener.Module(),
		fx.Invoke(registerHealthRunnerLifecycle),
	)
}

type healthRunnerLifecycleParams struct {
	fx.In

	Lifecycle fx.Lifecycle
	Runner    *backend.HealthRunner `optional:"true"`
}

// registerHealthRunnerLifecycle starts the backend health loop when one is assembled.
func registerHealthRunnerLifecycle(params healthRunnerLifecycleParams) {
	if params.Runner == nil {
		return
	}

	params.Lifecycle.Append(fx.Hook{
		OnStart: params.Runner.Start,
		OnStop:  params.Runner.Stop,
	})
}
