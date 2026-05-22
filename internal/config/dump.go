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

//nolint:funlen,gocyclo,wsl_v5 // Reflection keeps dump rendering aligned with typed config metadata.
package config

import (
	"fmt"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// DumpOptions controls config dump formatting.
type DumpOptions struct {
	Format           string
	IncludeProtected bool
}

// DumpDefaults returns canonical defaults in the requested dump format.
func (l *Loader) DumpDefaults(options DumpOptions) ([]byte, error) {
	defaults := DefaultConfig()
	settings, err := configToMap(defaults, true)
	if err != nil {
		return nil, err
	}
	if !options.IncludeProtected {
		settings = redactProtectedValues(settings, reflect.TypeFor[Config]())
	}

	return marshalDump(settings, options.Format)
}

// DumpNonDefault returns effective non-default config in the requested format.
func (s *Snapshot) DumpNonDefault(options DumpOptions) ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("config snapshot is nil")
	}

	defaults, err := configToMap(s.defaultConfig, true)
	if err != nil {
		return nil, err
	}
	effective, err := configToMap(s.Config, true)
	if err != nil {
		return nil, err
	}

	diff := diffMaps(defaults, effective)
	if !options.IncludeProtected {
		diff = redactProtectedValues(diff, reflect.TypeFor[Config]())
	}

	return marshalDump(diff, options.Format)
}

// marshalDump renders deterministic YAML and rejects unsupported inspection formats.
func marshalDump(settings map[string]any, format string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", dumpFormatYAML, dumpFormatYML:
		if len(settings) == 0 {
			return []byte("{}\n"), nil
		}

		return yaml.Marshal(settings)
	default:
		return nil, fmt.Errorf("unsupported config dump format %q", format)
	}
}

// configToMap converts typed config into a plain map while preserving protected values on request.
func configToMap(config Config, includeProtected bool) (map[string]any, error) {
	value, err := valueToPlain(reflect.ValueOf(config), includeProtected)
	if err != nil {
		return nil, err
	}

	settings, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("config did not render to a map")
	}

	return settings, nil
}

// valueToPlain reflects typed config into dump-friendly scalar, map and slice values.
func valueToPlain(value reflect.Value, includeProtected bool) (any, error) {
	if !value.IsValid() {
		return nil, nil
	}

	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return nil, nil
		}

		return valueToPlain(value.Elem(), includeProtected)
	}

	if value.Type() == reflect.TypeFor[SecretString]() {
		secret := value.Interface().(SecretString)
		if includeProtected {
			return secret.Value(), nil
		}
		return secret.String(), nil
	}

	if value.Type() == reflect.TypeFor[Duration]() {
		return value.Interface().(Duration).String(), nil
	}

	switch value.Kind() {
	case reflect.Struct:
		out := map[string]any{}
		valueType := value.Type()
		for index := 0; index < value.NumField(); index++ {
			field := valueType.Field(index)
			if field.PkgPath != "" {
				continue
			}

			name := configFieldName(field)
			if name == "" || name == "-" {
				continue
			}

			childValue := value.Field(index)
			if childValue.Kind() == reflect.Pointer && childValue.IsNil() {
				continue
			}

			child, err := valueToPlain(childValue, includeProtected)
			if err != nil {
				return nil, err
			}
			if child == nil {
				continue
			}

			out[name] = child
		}

		return out, nil
	case reflect.Map:
		out := map[string]any{}
		iter := value.MapRange()
		for iter.Next() {
			key := fmt.Sprint(iter.Key().Interface())
			child, err := valueToPlain(iter.Value(), includeProtected)
			if err != nil {
				return nil, err
			}
			out[key] = child
		}

		return out, nil
	case reflect.Slice, reflect.Array:
		out := make([]any, 0, value.Len())
		for index := 0; index < value.Len(); index++ {
			child, err := valueToPlain(value.Index(index), includeProtected)
			if err != nil {
				return nil, err
			}
			out = append(out, child)
		}

		return out, nil
	case reflect.String:
		return value.String(), nil
	case reflect.Bool:
		return value.Bool(), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return int(value.Int()), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return int(value.Uint()), nil
	case reflect.Float32, reflect.Float64:
		return value.Float(), nil
	default:
		return value.Interface(), nil
	}
}

// diffMaps returns only effective values that differ from canonical defaults.
func diffMaps(defaults map[string]any, effective map[string]any) map[string]any {
	diff := map[string]any{}
	for key, effectiveValue := range effective {
		defaultValue, ok := defaults[key]
		if !ok {
			diff[key] = effectiveValue
			continue
		}

		childDiff, different := diffValue(defaultValue, effectiveValue)
		if different {
			diff[key] = childDiff
		}
	}

	return diff
}

// diffValue handles recursive map diffs and atomic scalar or slice replacement.
func diffValue(defaultValue any, effectiveValue any) (any, bool) {
	defaultMap, defaultIsMap := defaultValue.(map[string]any)
	effectiveMap, effectiveIsMap := effectiveValue.(map[string]any)
	if defaultIsMap && effectiveIsMap {
		diff := diffMaps(defaultMap, effectiveMap)
		return diff, len(diff) > 0
	}

	if reflect.DeepEqual(defaultValue, effectiveValue) {
		return nil, false
	}

	return effectiveValue, true
}
