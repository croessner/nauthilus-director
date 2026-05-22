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

//nolint:wsl_v5 // Patch operations are intentionally kept as small sequential checks.
package config

import (
	"errors"
	"fmt"
	"maps"
	"reflect"
	"strings"
)

const (
	patchOpAdd     = "add"
	patchOpReplace = "replace"
	patchOpRemove  = "remove"
)

// PatchEngine applies patch operations to a settings tree.
type PatchEngine interface {
	Apply(target map[string]any, patches []PatchOperation) error
}

// PatchOperation describes a single dot-path patch operation.
type PatchOperation struct {
	Op    string `mapstructure:"op"`
	Path  string `mapstructure:"path"`
	Value any    `mapstructure:"value"`
}

// DefaultPatchEngine applies patch operations to settings.
type DefaultPatchEngine struct{}

// Apply runs each patch operation against the target map.
func (DefaultPatchEngine) Apply(target map[string]any, patches []PatchOperation) error {
	for _, patch := range patches {
		if err := applyPatch(target, patch); err != nil {
			return err
		}
	}

	return nil
}

// parsePatchOperations decodes loader-only patch directives before they are stripped.
func parsePatchOperations(settings map[string]any) ([]PatchOperation, bool, error) {
	raw, ok := settings[patchKey]
	if !ok {
		return nil, false, nil
	}

	var patches []PatchOperation
	if err := decodeConfigValue(raw, &patches); err != nil {
		return nil, false, fmt.Errorf("decode patch operations: %w", err)
	}

	return patches, true, nil
}

// applyPatch executes one Nauthilus-compatible add, replace or remove operation.
func applyPatch(target map[string]any, patch PatchOperation) error {
	path := strings.TrimSpace(patch.Path)
	if path == "" {
		return errors.New("patch path must not be empty")
	}

	parts := strings.Split(path, ".")
	parent, key, err := resolveParentMap(target, parts, patch.Op != patchOpRemove)
	if err != nil {
		return fmt.Errorf("invalid patch path %q: %w", path, err)
	}

	switch patch.Op {
	case patchOpAdd:
		return applyAdd(parent, key, patch.Value, path)
	case patchOpReplace:
		parent[key] = patch.Value
		return nil
	case patchOpRemove:
		return applyRemove(parent, key, patch.Value, path)
	default:
		return fmt.Errorf("unsupported patch operation %q", patch.Op)
	}
}

// resolveParentMap finds or creates the parent map for a dot-path patch target.
func resolveParentMap(root map[string]any, parts []string, create bool) (map[string]any, string, error) {
	if len(parts) == 0 {
		return nil, "", errors.New("path is empty")
	}

	current := root
	for _, part := range parts[:len(parts)-1] {
		if part == "" {
			return nil, "", errors.New("path segment is empty")
		}

		next, ok := current[part]
		if !ok {
			if !create {
				return nil, "", fmt.Errorf("path %q not found", strings.Join(parts, "."))
			}

			nextMap := map[string]any{}
			current[part] = nextMap
			current = nextMap
			continue
		}

		nextMap, ok := next.(map[string]any)
		if !ok {
			return nil, "", fmt.Errorf("path %q is not a map", strings.Join(parts, "."))
		}

		current = nextMap
	}

	key := parts[len(parts)-1]
	if key == "" {
		return nil, "", errors.New("path segment is empty")
	}

	return current, key, nil
}

// applyAdd appends list values, shallow-merges maps or creates a new one-item list.
func applyAdd(parent map[string]any, key string, value any, fullPath string) error {
	current, ok := parent[key]
	if !ok {
		parent[key] = []any{value}
		return nil
	}

	switch typed := current.(type) {
	case []any:
		parent[key] = append(typed, value)
		return nil
	case []string:
		stringValue, ok := value.(string)
		if !ok {
			return fmt.Errorf("add to string list at %q requires string value, got %T", fullPath, value)
		}

		parent[key] = append(typed, stringValue)
		return nil
	case map[string]any:
		valueMap, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("add to map at %q requires map value, got %T", fullPath, value)
		}

		maps.Copy(typed, valueMap)
		return nil
	default:
		return fmt.Errorf("add operation at %q expects slice or map, got %T", fullPath, current)
	}
}

// applyRemove removes matching list entries or named map keys from an existing target.
func applyRemove(parent map[string]any, key string, value any, fullPath string) error {
	current, ok := parent[key]
	if !ok {
		return fmt.Errorf("remove operation at %q failed: path not found", fullPath)
	}

	switch typed := current.(type) {
	case []any:
		filtered := typed[:0]
		for _, item := range typed {
			if !reflect.DeepEqual(item, value) {
				filtered = append(filtered, item)
			}
		}
		parent[key] = filtered
		return nil
	case []string:
		stringValue, ok := value.(string)
		if !ok {
			return fmt.Errorf("remove operation at %q expects string value, got %T", fullPath, value)
		}

		filtered := typed[:0]
		for _, item := range typed {
			if item != stringValue {
				filtered = append(filtered, item)
			}
		}
		parent[key] = filtered
		return nil
	case map[string]any:
		return removeMapKeys(typed, value, fullPath)
	default:
		return fmt.Errorf("remove operation at %q expects slice or map, got %T", fullPath, current)
	}
}

// removeMapKeys deletes one or more string keys from a map patch target.
func removeMapKeys(target map[string]any, value any, fullPath string) error {
	switch typed := value.(type) {
	case string:
		delete(target, typed)
		return nil
	case []any:
		for _, item := range typed {
			key, ok := item.(string)
			if !ok {
				return fmt.Errorf("remove operation at %q expects string keys, got %T", fullPath, item)
			}

			delete(target, key)
		}

		return nil
	case []string:
		for _, key := range typed {
			delete(target, key)
		}

		return nil
	default:
		return fmt.Errorf("remove operation at %q expects string or []string, got %T", fullPath, value)
	}
}
