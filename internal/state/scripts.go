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

package state

import (
	"crypto/sha1"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/redis/go-redis/v9"
)

//go:embed scripts/*.lua
var embeddedScripts embed.FS

// ScriptDefinition contains the source for one Redis Lua script.
type ScriptDefinition struct {
	Name   string
	Source string
}

// Script describes a loaded script and its Redis SHA1 identifier.
type Script struct {
	Name   string
	Source string
	SHA    string
}

// ScriptRegistry tracks Redis scripts by name and SHA.
type ScriptRegistry struct {
	scripts map[string]Script
}

// LoadEmbeddedScripts loads the checked-in Redis script sources.
func LoadEmbeddedScripts() (*ScriptRegistry, error) {
	entries, err := fs.ReadDir(embeddedScripts, "scripts")
	if err != nil {
		return nil, newStateError(RedisErrorKindConfig, "script_load", "read embedded scripts", err)
	}

	definitions := make([]ScriptDefinition, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".lua") {
			continue
		}

		source, readErr := embeddedScripts.ReadFile("scripts/" + entry.Name())
		if readErr != nil {
			return nil, newStateError(RedisErrorKindConfig, "script_load", "read embedded script", readErr)
		}

		definitions = append(definitions, ScriptDefinition{
			Name:   strings.TrimSuffix(entry.Name(), ".lua"),
			Source: string(source),
		})
	}

	return NewScriptRegistry(definitions)
}

// NewScriptRegistry creates SHA-tracked script metadata from definitions.
func NewScriptRegistry(definitions []ScriptDefinition) (*ScriptRegistry, error) {
	registry := &ScriptRegistry{scripts: make(map[string]Script, len(definitions))}
	for _, definition := range definitions {
		script, err := newScript(definition)
		if err != nil {
			return nil, err
		}

		if _, exists := registry.scripts[script.Name]; exists {
			return nil, newStateError(RedisErrorKindConfig, "script_load", "duplicate script", nil)
		}

		registry.scripts[script.Name] = script
	}

	if len(registry.scripts) == 0 {
		return nil, newStateError(RedisErrorKindConfig, "script_load", "no scripts registered", nil)
	}

	return registry, nil
}

// Get returns one tracked script by name.
func (r *ScriptRegistry) Get(name string) (Script, bool) {
	if r == nil {
		return Script{}, false
	}

	script, ok := r.scripts[strings.TrimSpace(name)]

	return script, ok
}

// Names returns registered script names in deterministic order.
func (r *ScriptRegistry) Names() []string {
	if r == nil {
		return nil
	}

	names := make([]string, 0, len(r.scripts))
	for name := range r.scripts {
		names = append(names, name)
	}

	sort.Strings(names)

	return names
}

// ShouldFallbackToEval reports whether a failed EVALSHA may retry with source.
func ShouldFallbackToEval(err error) bool {
	return IsRedisErrorKind(err, RedisErrorKindScriptMissing)
}

// newScript validates one script definition and computes its Redis SHA.
func newScript(definition ScriptDefinition) (Script, error) {
	name := strings.TrimSpace(definition.Name)
	source := strings.TrimSpace(definition.Source)

	if name == "" {
		return Script{}, newStateError(RedisErrorKindConfig, "script_load", "script name required", nil)
	}

	if source == "" {
		return Script{}, newStateError(RedisErrorKindConfig, "script_load", "script source required", nil)
	}

	sum := sha1.Sum([]byte(definition.Source))

	return Script{Name: name, Source: definition.Source, SHA: hex.EncodeToString(sum[:])}, nil
}

// RedisErrorKind classifies fail-closed Redis state errors.
type RedisErrorKind string

const (
	// RedisErrorKindAmbiguousState reports state that cannot be interpreted safely.
	RedisErrorKindAmbiguousState RedisErrorKind = "ambiguous_state"
	// RedisErrorKindConfig reports invalid local state configuration.
	RedisErrorKindConfig RedisErrorKind = "config"
	// RedisErrorKindScriptMissing reports a script cache miss after EVALSHA.
	RedisErrorKindScriptMissing RedisErrorKind = "script_missing"
	// RedisErrorKindTransport reports Redis command transport failure.
	RedisErrorKindTransport RedisErrorKind = "transport"
)

// RedisStateError is a classified Redis state error.
type RedisStateError struct {
	Kind      RedisErrorKind
	Operation string
	Message   string
	cause     error
}

// Error returns a secret-free Redis state diagnostic.
func (e *RedisStateError) Error() string {
	if e == nil {
		return ""
	}

	message := "redis state failed: " + string(e.Kind)
	if e.Operation != "" {
		message += " operation=" + e.Operation
	}

	if e.Message != "" {
		message += " " + e.Message
	}

	return message
}

// Unwrap returns the classified error cause.
func (e *RedisStateError) Unwrap() error {
	if e == nil {
		return nil
	}

	return e.cause
}

// ClassifyRedisError converts Redis failures into fail-closed state errors.
func ClassifyRedisError(operation string, err error) error {
	if err == nil {
		return nil
	}

	message := strings.ToUpper(err.Error())
	switch {
	case errors.Is(err, redis.Nil):
		return newStateError(RedisErrorKindAmbiguousState, operation, "missing required state", err)
	case strings.Contains(message, "NOSCRIPT"):
		return newStateError(RedisErrorKindScriptMissing, operation, "script not loaded", err)
	default:
		return newStateError(RedisErrorKindTransport, operation, "redis command failed", err)
	}
}

// IsRedisErrorKind reports whether err wraps a RedisStateError with kind.
func IsRedisErrorKind(err error, kind RedisErrorKind) bool {
	var stateErr *RedisStateError
	if !errors.As(err, &stateErr) {
		return false
	}

	return stateErr.Kind == kind
}

// IsFailClosedRedisError reports whether err must stop routing or mutation.
func IsFailClosedRedisError(err error) bool {
	var stateErr *RedisStateError
	if !errors.As(err, &stateErr) {
		return false
	}

	switch stateErr.Kind {
	case RedisErrorKindAmbiguousState, RedisErrorKindScriptMissing, RedisErrorKindTransport:
		return true
	default:
		return false
	}
}

// newStateError creates a classified Redis state error.
func newStateError(kind RedisErrorKind, operation string, message string, cause error) *RedisStateError {
	return &RedisStateError{
		Kind:      kind,
		Operation: operation,
		Message:   message,
		cause:     cause,
	}
}

// missingScriptError creates a synthetic NOSCRIPT-like error for tests.
func missingScriptError(scriptName string) error {
	return ClassifyRedisError("evalsha", fmt.Errorf("NOSCRIPT %s", scriptName))
}
