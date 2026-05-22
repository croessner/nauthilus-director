package config

import "testing"

func TestNewLoaderCreatesIsolatedLoader(t *testing.T) {
	loader := NewLoader()
	if loader == nil {
		t.Fatal("NewLoader returned nil")
	}

	if loader.viper == nil {
		t.Fatal("NewLoader did not initialize viper")
	}

	if loader.validate == nil {
		t.Fatal("NewLoader did not initialize validator")
	}
}
