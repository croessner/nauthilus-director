// Package config owns typed configuration models, loading, validation and redaction.
package config

import (
	"github.com/go-playground/validator/v10"
	"github.com/spf13/viper"
)

// Loader is the production configuration loader boundary.
type Loader struct {
	viper    *viper.Viper
	validate *validator.Validate
}

// NewLoader creates a loader with isolated Viper and validator instances.
func NewLoader() *Loader {
	return &Loader{
		viper:    viper.New(),
		validate: validator.New(),
	}
}
