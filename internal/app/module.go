// Package app owns production process composition and lifecycle wiring.
package app

import "go.uber.org/fx"

// Module returns the root application composition module.
func Module() fx.Option {
	return fx.Options()
}
