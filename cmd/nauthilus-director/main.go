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

// Package main starts the nauthilus-director server binary.
//
//nolint:wsl_v5 // CLI parsing remains deliberately compact while command surface is small.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/croessner/nauthilus-director/internal/config"
)

var version = "dev"

const (
	configCommand = "config"
	dumpCommand   = "dump"
)

// main delegates to run so command behavior stays testable at the binary boundary.
func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run parses global flags and dispatches supported top-level commands.
func run(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("nauthilus-director", flag.ContinueOnError)
	flags.SetOutput(stderr)

	showVersion := flags.Bool("version", false, "print version and exit")
	configPath := flags.String("config", "", "path to the configuration file")
	flags.StringVar(configPath, "c", "", "path to the configuration file")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	if *showVersion {
		_, _ = fmt.Fprintf(stdout, "nauthilus-director %s\n", version)
		return 0
	}

	remaining := flags.Args()
	if len(remaining) == 0 {
		return 0
	}

	if len(remaining) >= 2 && remaining[0] == configCommand && remaining[1] == dumpCommand {
		return runConfigDump(remaining[2:], *configPath, stdout, stderr)
	}

	_, _ = fmt.Fprintf(stderr, "unknown command %q\n", remaining[0])
	return 2
}

// runConfigDump handles inspection-only config dump modes without mutating config files.
func runConfigDump(args []string, configPath string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("nauthilus-director config dump", flag.ContinueOnError)
	flags.SetOutput(stderr)

	defaults := flags.Bool("d", false, "dump canonical defaults")
	nonDefaults := flags.Bool("n", false, "dump non-default effective config")
	protected := flags.Bool("P", false, "include protected values in config output")
	format := flags.String("format", "yaml", "config dump format")
	flags.StringVar(format, "f", "yaml", "config dump format")
	flags.StringVar(&configPath, "config", configPath, "path to the configuration file")
	flags.StringVar(&configPath, "c", configPath, "path to the configuration file")

	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "unexpected config dump argument %q\n", flags.Arg(0))
		return 2
	}
	if *defaults == *nonDefaults {
		_, _ = fmt.Fprintln(stderr, "choose exactly one of -d or -n")
		return 2
	}

	loader := config.NewLoader()
	options := config.DumpOptions{Format: *format, IncludeProtected: *protected}

	var (
		output []byte
		err    error
	)
	if *defaults {
		output, err = loader.DumpDefaults(options)
	} else {
		var snapshot *config.Snapshot
		snapshot, err = loader.Load(config.LoadOptions{Path: configPath})
		if err == nil {
			output, err = snapshot.DumpNonDefault(options)
		}
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "config dump failed: %v\n", err)
		return 1
	}

	_, _ = stdout.Write(output)
	return 0
}
