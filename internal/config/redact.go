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

//nolint:wsl_v5 // Redaction walks typed metadata and values in lockstep.
package config

import (
	"reflect"
	"strings"
)

type secretPath []string

// redactProtectedValues masks values whose typed destination is SecretString.
func redactProtectedValues(settings map[string]any, configType reflect.Type) map[string]any {
	paths := collectSecretPaths(configType)
	redacted := copyMap(settings).(map[string]any)
	redactValue(redacted, nil, paths)
	return redacted
}

// collectSecretPaths derives redaction paths from typed config metadata.
func collectSecretPaths(root reflect.Type) []secretPath {
	if root.Kind() == reflect.Pointer {
		root = root.Elem()
	}

	var paths []secretPath
	collectSecretPathsInto(root, nil, &paths)
	return paths
}

// collectSecretPathsInto walks structs, maps and slices with wildcard path segments.
func collectSecretPathsInto(current reflect.Type, path []string, paths *[]secretPath) {
	if current == reflect.TypeFor[SecretString]() {
		*paths = append(*paths, append(secretPath{}, path...))
		return
	}

	if current.Kind() == reflect.Pointer {
		collectSecretPathsInto(current.Elem(), path, paths)
		return
	}

	switch current.Kind() {
	case reflect.Struct:
		for field := range current.Fields() {
			if field.PkgPath != "" {
				continue
			}

			name := configFieldName(field)
			if name == "" || name == "-" {
				continue
			}

			collectSecretPathsInto(field.Type, append(path, name), paths)
		}
	case reflect.Map:
		collectSecretPathsInto(current.Elem(), append(path, "*"), paths)
	case reflect.Slice, reflect.Array:
		collectSecretPathsInto(current.Elem(), append(path, "*"), paths)
	}
}

// redactValue mutates a copied settings tree using the collected secret paths.
func redactValue(value any, path []string, paths []secretPath) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			childPath := append(path, key)
			if secretPathMatches(paths, childPath) {
				if str, ok := child.(string); ok && str == "" {
					continue
				}
				typed[key] = redactedSecret
				continue
			}

			redactValue(child, childPath, paths)
		}
	case []any:
		for index, child := range typed {
			redactValue(child, append(path, "*"), paths)
			typed[index] = child
		}
	}
}

// secretPathMatches compares a concrete config path with wildcard metadata paths.
func secretPathMatches(paths []secretPath, path []string) bool {
	for _, candidate := range paths {
		if len(candidate) != len(path) {
			continue
		}

		matched := true
		for index := range candidate {
			if candidate[index] != "*" && candidate[index] != path[index] {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}

	return false
}

// configFieldName returns the stable config key encoded by struct tags.
func configFieldName(field reflect.StructField) string {
	tag := field.Tag.Get(configTagName)
	if tag == "" {
		tag = field.Tag.Get("yaml")
	}
	if tag == "" {
		return strings.ToLower(field.Name)
	}

	name, _, _ := strings.Cut(tag, ",")
	return name
}

// copyMap clones nested map and slice structures before redaction mutates them.
func copyMap(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, child := range typed {
			out[key] = copyMap(child)
		}

		return out
	case []any:
		out := make([]any, len(typed))
		for index, child := range typed {
			out[index] = copyMap(child)
		}

		return out
	case []string:
		out := make([]string, len(typed))
		copy(out, typed)
		return out
	default:
		return typed
	}
}
