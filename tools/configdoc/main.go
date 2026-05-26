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

// Package main generates and checks config reference documentation.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/croessner/nauthilus-director/internal/config"
	"gopkg.in/yaml.v3"
)

const (
	defaultMetadataPath = "docs/config/metadata.yml"
	defaultDefaultsPath = "docs/reference/config-defaults.yaml"
	defaultPathsPath    = "docs/reference/config-paths.md"
	metadataTODO        = "todo"
	metadataGlobSuffix  = "**"
	metadataGlobSegment = "*"
)

// metadataFile stores human-authored path metadata.
type metadataFile struct {
	Paths map[string]pathMetadata `yaml:"paths"`
}

// pathMetadata describes one config path pattern.
type pathMetadata struct {
	Stability   string `yaml:"stability"`
	Description string `yaml:"description"`
}

// pathEntry describes one generated config path row.
type pathEntry struct {
	Path        string
	Type        string
	Default     string
	Stability   string
	Protected   bool
	Environment string
	Description string
}

// cliOptions stores file paths passed to the generator.
type cliOptions struct {
	metadataPath string
	defaultsPath string
	pathsPath    string
}

// main dispatches the configdoc subcommand.
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// run parses arguments and executes the requested mode.
func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: configdoc generate|check [flags]")
	}

	mode := args[0]
	flags := flag.NewFlagSet("configdoc "+mode, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	options := cliOptions{}
	flags.StringVar(&options.metadataPath, "metadata", defaultMetadataPath, "config path metadata")
	flags.StringVar(&options.defaultsPath, "defaults", defaultDefaultsPath, "generated defaults output")
	flags.StringVar(&options.pathsPath, "paths", defaultPathsPath, "generated path reference output")

	if err := flags.Parse(args[1:]); err != nil {
		return err
	}

	switch mode {
	case "generate":
		return generate(options)
	case "check":
		return check(options)
	default:
		return fmt.Errorf("unknown configdoc mode %q", mode)
	}
}

// generate writes reproducible config reference artifacts.
func generate(options cliOptions) error {
	defaults, paths, err := renderArtifacts(options.metadataPath)
	if err != nil {
		return err
	}

	if err := writeFile(options.defaultsPath, defaults); err != nil {
		return err
	}

	return writeFile(options.pathsPath, paths)
}

// check verifies generated config reference artifacts and metadata coverage.
func check(options cliOptions) error {
	defaults, paths, err := renderArtifacts(options.metadataPath)
	if err != nil {
		return err
	}

	var problems []string
	compareFile(options.defaultsPath, defaults, &problems)
	compareFile(options.pathsPath, paths, &problems)

	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}

	return nil
}

// renderArtifacts builds both generated docs from typed config and metadata.
func renderArtifacts(metadataPath string) ([]byte, []byte, error) {
	loader := config.NewLoader()

	defaults, err := loader.DumpDefaults(config.DumpOptions{Format: "yaml"})
	if err != nil {
		return nil, nil, err
	}

	defaultMap, err := loader.MapDefaults(config.DumpOptions{})
	if err != nil {
		return nil, nil, err
	}

	metadata, err := readMetadata(metadataPath)
	if err != nil {
		return nil, nil, err
	}

	entries, err := buildPathEntries(defaultMap, metadata)
	if err != nil {
		return nil, nil, err
	}

	paths := renderPathReference(entries)

	return defaults, paths, nil
}

// readMetadata decodes human-authored path descriptions.
func readMetadata(path string) (metadataFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return metadataFile{}, err
	}

	var metadata metadataFile
	if err := yaml.Unmarshal(data, &metadata); err != nil {
		return metadataFile{}, err
	}

	if len(metadata.Paths) == 0 {
		return metadataFile{}, fmt.Errorf("metadata paths are required")
	}

	return metadata, nil
}

// buildPathEntries flattens defaults and attaches validated metadata.
func buildPathEntries(defaults map[string]any, metadata metadataFile) ([]pathEntry, error) {
	protectedPatterns := collectProtectedPatterns(reflect.TypeFor[config.Config]())
	flat := flattenDefaults(defaults)
	entries := make([]pathEntry, 0, len(flat))
	matchedMetadata := make(map[string]bool, len(metadata.Paths))

	paths := make([]string, 0, len(flat))
	for path := range flat {
		paths = append(paths, path)
	}

	sort.Strings(paths)

	for _, path := range paths {
		value := flat[path]

		pattern, meta, ok := metadataForPath(path, metadata)
		if !ok {
			return nil, fmt.Errorf("missing metadata for stable config path %s", path)
		}

		if strings.Contains(strings.ToLower(meta.Description), metadataTODO) {
			return nil, fmt.Errorf("metadata for stable config path %s contains TODO", path)
		}

		if strings.TrimSpace(meta.Stability) == "" {
			return nil, fmt.Errorf("metadata for stable config path %s has no stability", path)
		}

		matchedMetadata[pattern] = true
		parts := strings.Split(path, ".")
		entries = append(entries, pathEntry{
			Path:        path,
			Type:        valueType(value),
			Default:     defaultValue(value),
			Stability:   strings.TrimSpace(meta.Stability),
			Protected:   matchesAnyPattern(protectedPatterns, parts),
			Environment: config.EnvNameForConfigPath(parts),
			Description: strings.TrimSpace(meta.Description),
		})
	}

	for pattern := range metadata.Paths {
		if !matchedMetadata[pattern] {
			return nil, fmt.Errorf("metadata path %s does not match a generated config path", pattern)
		}
	}

	return entries, nil
}

// metadataForPath returns the most specific metadata entry for a path.
func metadataForPath(path string, metadata metadataFile) (string, pathMetadata, bool) {
	parts := strings.Split(path, ".")
	bestPattern := ""
	bestScore := -1

	var best pathMetadata

	for pattern, candidate := range metadata.Paths {
		if !matchPattern(strings.Split(pattern, "."), parts) {
			continue
		}

		score := patternScore(pattern)
		if score > bestScore {
			bestPattern = pattern
			bestScore = score
			best = candidate
		}
	}

	return bestPattern, best, bestScore >= 0
}

// flattenDefaults returns concrete scalar config paths from the default tree.
func flattenDefaults(value any) map[string]any {
	out := map[string]any{}
	flattenValue(out, nil, value)

	return out
}

// flattenValue walks maps and slices until it reaches a reference-row value.
func flattenValue(out map[string]any, path []string, value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			flattenValue(out, append(path, key), child)
		}
	case []any:
		out[strings.Join(path, ".")] = typed
	default:
		out[strings.Join(path, ".")] = typed
	}
}

// collectProtectedPatterns derives wildcard paths for protected typed config fields.
func collectProtectedPatterns(root reflect.Type) [][]string {
	var patterns [][]string
	collectProtectedPatternsInto(root, nil, &patterns)

	return patterns
}

// collectProtectedPatternsInto recursively records SecretString field paths.
func collectProtectedPatternsInto(current reflect.Type, path []string, patterns *[][]string) {
	if current.Kind() == reflect.Pointer {
		collectProtectedPatternsInto(current.Elem(), path, patterns)
		return
	}

	if current == reflect.TypeFor[config.SecretString]() {
		*patterns = append(*patterns, append([]string(nil), path...))
		return
	}

	switch current.Kind() {
	case reflect.Struct:
		for field := range current.Fields() {
			if field.PkgPath != "" {
				continue
			}

			name := fieldName(field)
			if name == "" || name == "-" {
				continue
			}

			collectProtectedPatternsInto(field.Type, append(path, name), patterns)
		}
	case reflect.Map, reflect.Slice, reflect.Array:
		collectProtectedPatternsInto(current.Elem(), append(path, "*"), patterns)
	}
}

// fieldName returns the stable config key for one typed struct field.
func fieldName(field reflect.StructField) string {
	tag := field.Tag.Get("mapstructure")
	if tag == "" {
		tag = field.Tag.Get("yaml")
	}

	if tag == "" {
		return strings.ToLower(field.Name)
	}

	name, _, _ := strings.Cut(tag, ",")

	return name
}

// renderPathReference renders the Markdown config path table.
func renderPathReference(entries []pathEntry) []byte {
	var buffer bytes.Buffer
	buffer.WriteString("# Config Path Reference\n\n")
	buffer.WriteString("Generated from the typed config model, `DefaultConfig()` and `docs/config/metadata.yml`.\n\n")
	buffer.WriteString("| Path | Type | Default | Stability | Protected | Environment | Description |\n")
	buffer.WriteString("| --- | --- | --- | --- | --- | --- | --- |\n")

	for _, entry := range entries {
		buffer.WriteString("| `")
		buffer.WriteString(entry.Path)
		buffer.WriteString("` | ")
		buffer.WriteString(entry.Type)
		buffer.WriteString(" | `")
		buffer.WriteString(escapeMarkdown(entry.Default))
		buffer.WriteString("` | ")
		buffer.WriteString(entry.Stability)
		buffer.WriteString(" | ")
		buffer.WriteString(boolString(entry.Protected))
		buffer.WriteString(" | `")
		buffer.WriteString(entry.Environment)
		buffer.WriteString("` | ")
		buffer.WriteString(escapeMarkdown(entry.Description))
		buffer.WriteString(" |\n")
	}

	return buffer.Bytes()
}

// compareFile appends a stale-output problem when content differs.
func compareFile(path string, expected []byte, problems *[]string) {
	current, err := os.ReadFile(path)
	if err != nil {
		*problems = append(*problems, fmt.Sprintf("read %s: %v", path, err))
		return
	}

	if !bytes.Equal(current, expected) {
		*problems = append(*problems, fmt.Sprintf("stale generated config documentation: run make generate-docs for %s", path))
	}
}

// writeFile creates parent directories and writes one generated artifact.
func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	return os.WriteFile(path, data, 0o644)
}

// valueType returns a compact reference type for one default value.
func valueType(value any) string {
	switch value.(type) {
	case bool:
		return "boolean"
	case int, int64, int32:
		return "integer"
	case float32, float64:
		return "number"
	case []any:
		return "array"
	case string:
		return "string"
	default:
		return fmt.Sprintf("%T", value)
	}
}

// defaultValue renders one default value as a stable single-line string.
func defaultValue(value any) string {
	switch typed := value.(type) {
	case []any:
		data, err := json.Marshal(typed)
		if err == nil {
			return string(data)
		}
	case string:
		return typed
	}

	return fmt.Sprint(value)
}

// matchesAnyPattern reports whether a concrete path matches any pattern.
func matchesAnyPattern(patterns [][]string, path []string) bool {
	for _, pattern := range patterns {
		if matchPattern(pattern, path) {
			return true
		}
	}

	return false
}

// matchPattern supports '*' for one segment and '**' for the remaining suffix.
func matchPattern(pattern []string, path []string) bool {
	if len(pattern) == 0 {
		return len(path) == 0
	}

	if pattern[0] == metadataGlobSuffix {
		return true
	}

	if len(path) == 0 {
		return false
	}

	if pattern[0] != metadataGlobSegment && pattern[0] != path[0] {
		return false
	}

	return matchPattern(pattern[1:], path[1:])
}

// patternScore ranks exact path metadata above broad wildcard metadata.
func patternScore(pattern string) int {
	score := 0

	for part := range strings.SplitSeq(pattern, ".") {
		switch part {
		case metadataGlobSuffix:
			score++
		case metadataGlobSegment:
			score += 2
		default:
			score += 4
		}
	}

	return score
}

// escapeMarkdown keeps table cells on one line.
func escapeMarkdown(value string) string {
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "|", "\\|")

	return value
}

// boolString renders booleans for the Markdown table.
func boolString(value bool) string {
	if value {
		return "yes"
	}

	return "no"
}
