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

//nolint:wsl_v5 // Loader steps stay grouped in the required processing order.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

const envPrefix = "NAUTHILUS_DIRECTOR"

// LoadOptions controls file-based config loading.
type LoadOptions struct {
	Path string
}

// configReader abstracts file parsing so include recursion can share one reader.
type configReader interface {
	Read(path string) (map[string]any, error)
}

// Load reads, merges, expands, decodes and validates production config.
func (l *Loader) Load(options LoadOptions) (*Snapshot, error) {
	if l == nil {
		l = NewLoader()
	}

	defaultConfig := DefaultConfig()
	effectiveTree, err := configToMap(defaultConfig, true)
	if err != nil {
		return nil, fmt.Errorf("build default config tree: %w", err)
	}

	if options.Path != "" {
		fileTree, patches, err := l.includeLoader.LoadFromFile(options.Path)
		if err != nil {
			return nil, err
		}

		l.merger.Merge(effectiveTree, fileTree)
		if err := l.patchEngine.Apply(effectiveTree, patches); err != nil {
			return nil, err
		}
	}

	if l.expander != nil {
		if err := l.expander.Expand(effectiveTree); err != nil {
			return nil, err
		}
	}

	l.applyEnvOverrides(effectiveTree)

	config, err := l.decodeConfig(effectiveTree)
	if err != nil {
		return nil, err
	}

	if err := l.Validate(config); err != nil {
		return nil, err
	}

	return &Snapshot{Config: config, defaultConfig: defaultConfig}, nil
}

// LoadFile is a convenience wrapper around Load for a concrete config path.
func (l *Loader) LoadFile(path string) (*Snapshot, error) {
	return l.Load(LoadOptions{Path: path})
}

// decodeConfig performs strict mapstructure decoding into the typed model.
func (l *Loader) decodeConfig(settings map[string]any) (Config, error) {
	var config Config
	metadata := &mapstructure.Metadata{}
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook:       mapstructure.ComposeDecodeHookFunc(durationDecodeHook, secretDecodeHook),
		ErrorUnused:      true,
		Metadata:         metadata,
		Result:           &config,
		TagName:          configTagName,
		WeaklyTypedInput: true,
	})
	if err != nil {
		return Config{}, err
	}

	if err := decoder.Decode(settings); err != nil {
		return Config{}, fmt.Errorf("decode typed config: %w", err)
	}

	if len(metadata.Unused) > 0 {
		return Config{}, fmt.Errorf("decode typed config: unknown fields: %s", strings.Join(metadata.Unused, ", "))
	}

	return config, nil
}

// durationDecodeHook accepts Go duration strings while keeping the typed wrapper.
func durationDecodeHook(_ reflect.Type, to reflect.Type, value any) (any, error) {
	if to != reflect.TypeFor[Duration]() {
		return value, nil
	}

	switch typed := value.(type) {
	case Duration:
		return typed, nil
	case time.Duration:
		return Duration(typed), nil
	case string:
		parsed, err := parseDuration(typed)
		if err != nil {
			return nil, err
		}

		return parsed, nil
	case int:
		return Duration(time.Duration(typed)), nil
	case int64:
		return Duration(time.Duration(typed)), nil
	case float64:
		return Duration(time.Duration(typed)), nil
	default:
		return nil, fmt.Errorf("cannot decode %T as duration", value)
	}
}

// parseDuration keeps duration parsing centralized for decode diagnostics.
func parseDuration(value string) (Duration, error) {
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, err
	}

	return Duration(parsed), nil
}

// applyEnvOverrides applies NAUTHILUS_DIRECTOR path overrides after placeholder expansion.
func (l *Loader) applyEnvOverrides(settings map[string]any) {
	applyEnvOverrides(settings, nil)
}

// applyEnvOverrides walks scalar leaves and coerces matching environment values.
func applyEnvOverrides(value any, path []string) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			childPath := append(path, key)
			switch child.(type) {
			case map[string]any:
				applyEnvOverrides(child, childPath)
			case []any:
				applyEnvOverrides(child, childPath)
			default:
				if override, ok := os.LookupEnv(envNameForPath(childPath)); ok {
					typed[key] = coerceEnvValue(override, child)
				}
			}
		}
	case []any:
		for index, child := range typed {
			applyEnvOverrides(child, append(path, strconv.Itoa(index)))
		}
	}
}

// envNameForPath maps a config path to the NAUTHILUS_DIRECTOR_* override name.
func envNameForPath(path []string) string {
	parts := make([]string, 0, len(path)+1)
	parts = append(parts, envPrefix)
	for _, part := range path {
		parts = append(parts, sanitizeEnvPathPart(part))
	}

	return strings.ToUpper(strings.Join(parts, "_"))
}

// sanitizeEnvPathPart keeps map keys representable in environment variable names.
func sanitizeEnvPathPart(value string) string {
	var builder strings.Builder
	for _, char := range value {
		switch {
		case char >= 'A' && char <= 'Z':
			builder.WriteRune(char)
		case char >= 'a' && char <= 'z':
			builder.WriteRune(char)
		case char >= '0' && char <= '9':
			builder.WriteRune(char)
		default:
			builder.WriteByte('_')
		}
	}

	return builder.String()
}

// coerceEnvValue preserves the existing scalar type where simple conversion is possible.
func coerceEnvValue(value string, current any) any {
	switch current.(type) {
	case bool:
		parsed, err := strconv.ParseBool(value)
		if err == nil {
			return parsed
		}
	case int:
		parsed, err := strconv.Atoi(value)
		if err == nil {
			return parsed
		}
	case int64:
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err == nil {
			return parsed
		}
	case float64:
		parsed, err := strconv.ParseFloat(value, 64)
		if err == nil {
			return parsed
		}
	}

	return value
}

// viperConfigReader is the production reader for Viper-supported config formats.
type viperConfigReader struct {
	ConfigType string
}

// Read parses a config file and normalizes nested maps to map[string]any.
func (r viperConfigReader) Read(path string) (map[string]any, error) {
	reader := viper.New()
	if r.ConfigType != "" {
		reader.SetConfigType(r.ConfigType)
	}
	reader.SetConfigFile(path)

	if err := reader.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}

	return normalizeMap(reader.AllSettings()), nil
}

// normalizeMap converts decoder-specific map shapes into the loader's map type.
func normalizeMap(input map[string]any) map[string]any {
	out := make(map[string]any, len(input))
	for key, value := range input {
		out[key] = normalizeValue(value)
	}

	return out
}

// normalizeValue recursively normalizes maps inside slices and nested values.
func normalizeValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return normalizeMap(typed)
	case map[any]any:
		out := make(map[string]any, len(typed))
		for key, value := range typed {
			out[fmt.Sprint(key)] = normalizeValue(value)
		}

		return out
	case []any:
		out := make([]any, len(typed))
		for index, value := range typed {
			out[index] = normalizeValue(value)
		}

		return out
	default:
		return value
	}
}

// isConfigNotFound identifies missing optional includes without hiding other errors.
func isConfigNotFound(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, fs.ErrNotExist) {
		return true
	}

	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return errors.Is(pathErr.Err, fs.ErrNotExist)
	}

	var notFound viper.ConfigFileNotFoundError
	return errors.As(err, &notFound)
}

// inferConfigType selects a Viper format hint from an include file extension.
func inferConfigType(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		return dumpFormatYAML
	case ".json":
		return dumpFormatJSON
	case ".toml":
		return dumpFormatTOML
	default:
		return ""
	}
}
