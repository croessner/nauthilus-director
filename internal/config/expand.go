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

//nolint:wsl_v5 // Placeholder parsing is easier to audit as a compact state machine.
package config

import (
	"errors"
	"fmt"
	"os"
)

var errInvalidExpansionPlaceholder = errors.New("invalid environment placeholder syntax")

// ExpansionLookup resolves a config placeholder name to a value.
type ExpansionLookup interface {
	Lookup(name string) (string, bool)
}

// ValueExpander expands string values in a merged settings tree.
type ValueExpander interface {
	Expand(settings map[string]any) error
}

type configValueExpander struct {
	lookup ExpansionLookup
}

// NewConfigValueExpander creates a config value expander.
func NewConfigValueExpander(lookup ExpansionLookup) ValueExpander {
	if lookup == nil {
		lookup = OSExpansionLookup{}
	}

	return &configValueExpander{lookup: lookup}
}

// Expand walks the settings tree and expands string values in place.
func (e *configValueExpander) Expand(settings map[string]any) error {
	if e == nil || settings == nil {
		return nil
	}

	if e.lookup == nil {
		e.lookup = OSExpansionLookup{}
	}

	return e.expandMap(settings, "")
}

// expandMap expands values while deliberately leaving map keys untouched.
func (e *configValueExpander) expandMap(settings map[string]any, path string) error {
	for key, value := range settings {
		expanded, err := e.expandValue(value, joinExpansionPath(path, key))
		if err != nil {
			return err
		}

		settings[key] = expanded
	}

	return nil
}

// expandValue dispatches expansion by value shape without changing scalar types.
func (e *configValueExpander) expandValue(value any, path string) (any, error) {
	switch typed := value.(type) {
	case map[string]any:
		return typed, e.expandMap(typed, path)
	case []any:
		return e.expandAnySlice(typed, path)
	case []string:
		return e.expandStringSlice(typed, path)
	case string:
		return e.expandString(typed, path)
	default:
		return value, nil
	}
}

// expandAnySlice expands list entries and reports index-qualified paths.
func (e *configValueExpander) expandAnySlice(values []any, path string) ([]any, error) {
	for index, value := range values {
		expanded, err := e.expandValue(value, joinExpansionIndexPath(path, index))
		if err != nil {
			return nil, err
		}

		values[index] = expanded
	}

	return values, nil
}

// expandStringSlice expands typed string slices before mapstructure decoding.
func (e *configValueExpander) expandStringSlice(values []string, path string) ([]string, error) {
	for index, value := range values {
		expanded, err := e.expandString(value, joinExpansionIndexPath(path, index))
		if err != nil {
			return nil, err
		}

		values[index] = expanded
	}

	return values, nil
}

// expandString resolves ${NAME} placeholders and keeps ordinary dollars literal.
func (e *configValueExpander) expandString(value string, path string) (string, error) {
	var expanded []byte
	literalStart := 0

	for index := 0; index < len(value); {
		if isEscapedExpansionPlaceholder(value, index) {
			_, end, _, _ := parseExpansionPlaceholder(value, index+1)
			expanded = appendExpandedSegment(expanded, value, literalStart, index)
			expanded = append(expanded, value[index+1:end]...)
			index = end
			literalStart = end
			continue
		}

		name, end, ok, err := parseExpansionPlaceholder(value, index)
		if err != nil {
			return "", fmt.Errorf(
				"expand config value at %s: %w, expected ${NAME} with NAME matching [A-Za-z_][A-Za-z0-9_]*",
				path,
				err,
			)
		}

		if !ok {
			index++
			continue
		}

		resolved, found := e.lookup.Lookup(name)
		if !found {
			return "", fmt.Errorf("expand config value at %s: environment variable %s is not set", path, name)
		}

		expanded = appendExpandedSegment(expanded, value, literalStart, index)
		expanded = append(expanded, resolved...)
		index = end
		literalStart = end
	}

	if expanded == nil {
		return value, nil
	}

	expanded = append(expanded, value[literalStart:]...)
	return string(expanded), nil
}

// appendExpandedSegment copies an unexpanded literal segment into the output buffer.
func appendExpandedSegment(buffer []byte, value string, start int, end int) []byte {
	if buffer == nil {
		buffer = make([]byte, 0, len(value))
	}

	return append(buffer, value[start:end]...)
}

// isEscapedExpansionPlaceholder recognizes $${NAME} before normal placeholder parsing.
func isEscapedExpansionPlaceholder(value string, index int) bool {
	if index+1 >= len(value) || value[index] != '$' || value[index+1] != '$' {
		return false
	}

	_, _, ok, err := parseExpansionPlaceholder(value, index+1)
	return err == nil && ok
}

// parseExpansionPlaceholder parses a strict ${NAME} placeholder at the given byte index.
func parseExpansionPlaceholder(value string, index int) (string, int, bool, error) {
	if index >= len(value) || value[index] != '$' {
		return "", index, false, nil
	}

	if index+1 >= len(value) || value[index+1] != '{' {
		return "", index, false, nil
	}

	nameStart := index + 2
	if nameStart >= len(value) || !isExpansionNameStart(value[nameStart]) {
		return "", index, false, errInvalidExpansionPlaceholder
	}

	nameEnd := nameStart + 1
	for nameEnd < len(value) && isExpansionNamePart(value[nameEnd]) {
		nameEnd++
	}

	if nameEnd >= len(value) || value[nameEnd] != '}' {
		return "", index, false, errInvalidExpansionPlaceholder
	}

	return value[nameStart:nameEnd], nameEnd + 1, true, nil
}

// isExpansionNameStart enforces shell-style placeholder names.
func isExpansionNameStart(value byte) bool {
	return value == '_' || (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z')
}

// isExpansionNamePart permits digits after the first placeholder character.
func isExpansionNamePart(value byte) bool {
	return isExpansionNameStart(value) || (value >= '0' && value <= '9')
}

// joinExpansionPath appends a map key to a diagnostic config path.
func joinExpansionPath(parent string, key string) string {
	if parent == "" {
		return key
	}

	return parent + "." + key
}

// joinExpansionIndexPath appends a slice index to a diagnostic config path.
func joinExpansionIndexPath(parent string, index int) string {
	if parent == "" {
		return fmt.Sprintf("[%d]", index)
	}

	return fmt.Sprintf("%s[%d]", parent, index)
}

// OSExpansionLookup resolves placeholders from the process environment.
type OSExpansionLookup struct{}

// Lookup returns an OS environment value.
func (OSExpansionLookup) Lookup(name string) (string, bool) {
	return os.LookupEnv(name)
}
