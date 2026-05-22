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

//nolint:wsl_v5 // Include resolution mirrors the upstream Nauthilus loader order.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-viper/mapstructure/v2"
)

const (
	includeKey = "includes"
	patchKey   = "patch"
	envKey     = "env"
)

type includeLoader struct {
	reader configReader
	merger SettingsMerger
}

// newIncludeLoader wires include resolution with the same reader used for the root file.
func newIncludeLoader(reader configReader) *includeLoader {
	return &includeLoader{
		reader: reader,
		merger: MapMerger{},
	}
}

// LoadFromFile reads a root file and returns merged settings plus delayed patches.
func (l *includeLoader) LoadFromFile(path string) (map[string]any, []PatchOperation, error) {
	settings, err := l.reader.Read(path)
	if err != nil {
		return nil, nil, err
	}

	return l.loadWithSettings(path, settings, map[string]struct{}{})
}

// loadWithSettings resolves recursive includes before merging the declaring file.
func (l *includeLoader) loadWithSettings(path string, settings map[string]any, visited map[string]struct{}) (map[string]any, []PatchOperation, error) {
	cleanPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		cleanPath = filepath.Clean(path)
	}

	if _, ok := visited[cleanPath]; ok {
		return nil, nil, fmt.Errorf("include cycle detected at %q", cleanPath)
	}

	visited[cleanPath] = struct{}{}
	defer delete(visited, cleanPath)

	includes, err := resolveIncludes(settings)
	if err != nil {
		return nil, nil, err
	}

	merged := map[string]any{}
	var patches []PatchOperation
	baseDir := filepath.Dir(cleanPath)

	for _, include := range includes {
		includePath := resolveIncludePath(baseDir, include.Path)
		includeSettings, includePatches, err := l.loadFromFile(includePath, visited)
		if err != nil {
			if include.Required || !isConfigNotFound(err) {
				return nil, nil, fmt.Errorf("include %q failed: %w", includePath, err)
			}

			continue
		}

		patches = append(patches, includePatches...)
		l.merger.Merge(merged, includeSettings)
	}

	filePatches, hasPatches, err := parsePatchOperations(settings)
	if err != nil {
		return nil, nil, err
	}
	if hasPatches {
		patches = append(patches, filePatches...)
	}

	stripLoaderKeys(settings)
	l.merger.Merge(merged, settings)

	return merged, patches, nil
}

// loadFromFile preserves cycle state while descending into an include file.
func (l *includeLoader) loadFromFile(path string, visited map[string]struct{}) (map[string]any, []PatchOperation, error) {
	reader := l.reader
	if typed, ok := reader.(viperConfigReader); ok && typed.ConfigType == "" {
		typed.ConfigType = inferConfigType(path)
		reader = typed
	}

	settings, err := reader.Read(path)
	if err != nil {
		return nil, nil, err
	}

	return l.loadWithSettings(path, settings, visited)
}

// resolveIncludePath makes relative include paths local to the declaring file.
func resolveIncludePath(baseDir string, includePath string) string {
	if filepath.IsAbs(includePath) {
		return filepath.Clean(includePath)
	}

	return filepath.Clean(filepath.Join(baseDir, includePath))
}

// stripLoaderKeys removes directives before typed config decoding and dump output.
func stripLoaderKeys(settings map[string]any) {
	delete(settings, includeKey)
	delete(settings, patchKey)
	delete(settings, envKey)
}

// includeFile carries the requiredness policy for one resolved include path.
type includeFile struct {
	Path     string
	Required bool
}

// includeGroup mirrors the required and optional lists under includes.env.
type includeGroup struct {
	Required []string `mapstructure:"required"`
	Optional []string `mapstructure:"optional"`
}

// includeDirectives is the loader-only shape for root includes directives.
type includeDirectives struct {
	Required []string                `mapstructure:"required"`
	Optional []string                `mapstructure:"optional"`
	Env      map[string]includeGroup `mapstructure:"env"`
}

// resolveIncludes expands base and active-environment include groups in merge order.
func resolveIncludes(root map[string]any) ([]includeFile, error) {
	raw, ok := root[includeKey]
	if !ok {
		return nil, nil
	}

	var directives includeDirectives
	if err := decodeConfigValue(raw, &directives); err != nil {
		return nil, fmt.Errorf("decode includes: %w", err)
	}

	includeFiles := make([]includeFile, 0, len(directives.Required)+len(directives.Optional))
	includeFiles = append(includeFiles, toIncludeFiles(directives.Required, true)...)
	includeFiles = append(includeFiles, toIncludeFiles(directives.Optional, false)...)

	envName, err := resolveEnvName(root)
	if err != nil {
		return nil, err
	}

	if envName != "" {
		if envIncludes, ok := directives.Env[envName]; ok {
			includeFiles = append(includeFiles, toIncludeFiles(envIncludes.Required, true)...)
			includeFiles = append(includeFiles, toIncludeFiles(envIncludes.Optional, false)...)
		}
	}

	return includeFiles, nil
}

// resolveEnvName reads the root env directive or falls back to NAUTHILUS_DIRECTOR_ENV.
func resolveEnvName(root map[string]any) (string, error) {
	raw, ok := root[envKey]
	if !ok {
		return strings.TrimSpace(os.Getenv(envPrefix + "_ENV")), nil
	}

	envName, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string, got %T", envKey, raw)
	}

	return strings.TrimSpace(envName), nil
}

// toIncludeFiles filters empty include entries while preserving requiredness.
func toIncludeFiles(paths []string, required bool) []includeFile {
	files := make([]includeFile, 0, len(paths))
	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			continue
		}

		files = append(files, includeFile{Path: path, Required: required})
	}

	return files
}

// decodeConfigValue decodes loader directive fragments with weak scalar coercion.
func decodeConfigValue(input any, output any) error {
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:           output,
		TagName:          configTagName,
		WeaklyTypedInput: true,
	})
	if err != nil {
		return err
	}

	return decoder.Decode(input)
}

// SettingsMerger merges source settings into a target map.
type SettingsMerger interface {
	Merge(target map[string]any, source map[string]any)
}

// MapMerger merges nested map settings recursively.
type MapMerger struct{}

// Merge merges the source map into the target map recursively.
func (MapMerger) Merge(target map[string]any, source map[string]any) {
	for key, value := range source {
		valueMap, ok := value.(map[string]any)
		if !ok {
			target[key] = value
			continue
		}

		if existing, ok := target[key].(map[string]any); ok {
			MapMerger{}.Merge(existing, valueMap)
			target[key] = existing
			continue
		}

		target[key] = value
	}
}
