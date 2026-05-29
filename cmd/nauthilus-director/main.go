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
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/croessner/nauthilus-director/internal/app"
	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/spf13/cobra"
)

var version = "dev"
var serve = app.Run

const (
	configCommand = "config"
	dumpCommand   = "dump"
	serveCommand  = "serve"
)

// exitCodeError carries the intended process code through Cobra execution.
type exitCodeError struct {
	code int
}

// Error describes the non-zero command result for generic callers.
func (err exitCodeError) Error() string {
	return fmt.Sprintf("exit code %d", err.code)
}

// main delegates to run so command behavior stays testable at the binary boundary.
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	os.Exit(runWithContext(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

// run parses global flags and dispatches supported top-level commands.
func run(args []string, stdout io.Writer, stderr io.Writer) int {
	return runWithContext(context.Background(), args, stdout, stderr)
}

// runWithContext parses global flags and dispatches supported top-level commands.
func runWithContext(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	if err := rejectSingleDashLongOptions(args); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}

	root := newDirectorCommand(ctx, stdout, stderr)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		var exitErr exitCodeError
		if errors.As(err, &exitErr) {
			return exitErr.code
		}
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}

	return 0
}

// newDirectorCommand builds the server command tree.
func newDirectorCommand(ctx context.Context, stdout io.Writer, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:               "nauthilus-director",
		Short:             "Run and inspect the Nauthilus Director server process",
		SilenceUsage:      true,
		SilenceErrors:     true,
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			showVersion, _ := cmd.Root().PersistentFlags().GetBool("version")
			if showVersion {
				_, _ = fmt.Fprintf(stdout, "nauthilus-director %s\n", version)
				return exitCodeError{code: 0}
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				_, _ = fmt.Fprintf(stderr, "unknown command %q\n", args[0])
				return exitCodeError{code: 2}
			}

			return errorFromExitCode(runServe(ctx, configPathFromCommand(cmd), stdout, stderr))
		},
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.PersistentFlags().StringP("config", "c", "", "path to the configuration file")
	root.PersistentFlags().Bool("version", false, "print version and exit")
	root.AddCommand(newServeCommand(ctx, stdout, stderr))
	root.AddCommand(newConfigCommand(stdout, stderr))

	return root
}

// newServeCommand builds the explicit server startup command.
func newServeCommand(ctx context.Context, stdout io.Writer, stderr io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   serveCommand,
		Short: "Start the production server process",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				_, _ = fmt.Fprintf(stderr, "unexpected serve argument %q\n", args[0])
				return exitCodeError{code: 2}
			}

			return errorFromExitCode(runServe(ctx, configPathFromCommand(cmd), stdout, stderr))
		},
	}
}

// newConfigCommand builds local configuration inspection commands.
func newConfigCommand(stdout io.Writer, stderr io.Writer) *cobra.Command {
	command := &cobra.Command{
		Use:   configCommand,
		Short: "Inspect local server configuration",
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				_, _ = fmt.Fprintln(stderr, "config requires a subcommand")
				return exitCodeError{code: 2}
			}
			_, _ = fmt.Fprintf(stderr, "unknown config subcommand %q\n", args[0])
			return exitCodeError{code: 2}
		},
	}
	dump := &cobra.Command{
		Use:   dumpCommand,
		Short: "Print local server configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				_, _ = fmt.Fprintf(stderr, "unexpected config dump argument %q\n", args[0])
				return exitCodeError{code: 2}
			}

			return errorFromExitCode(runConfigDump(cmd, configPathFromCommand(cmd), stdout, stderr))
		},
	}
	dump.Flags().BoolP("defaults", "d", false, "dump canonical defaults")
	dump.Flags().BoolP("non-default", "n", false, "dump non-default effective config")
	dump.Flags().BoolP("protected", "P", false, "include protected values in config output")
	dump.Flags().StringP("format", "f", "yaml", "config dump format")
	command.AddCommand(dump)

	return command
}

// runServe starts the production server process.
func runServe(ctx context.Context, configPath string, _ io.Writer, stderr io.Writer) int {
	err := serve(ctx, app.Options{
		ConfigPath: configPath,
		Version:    version,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "server failed: %v\n", err)
		return 1
	}

	return 0
}

// runConfigDump handles inspection-only config dump modes without mutating config files.
func runConfigDump(command *cobra.Command, configPath string, stdout io.Writer, stderr io.Writer) int {
	defaults, _ := command.Flags().GetBool("defaults")
	nonDefaults, _ := command.Flags().GetBool("non-default")
	protected, _ := command.Flags().GetBool("protected")
	format, _ := command.Flags().GetString("format")

	if defaults == nonDefaults {
		_, _ = fmt.Fprintln(stderr, "choose exactly one of -d or -n")
		return 2
	}

	loader := config.NewLoader()
	options := config.DumpOptions{Format: format, IncludeProtected: protected}

	var (
		output []byte
		err    error
	)
	if defaults {
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

// configPathFromCommand returns the parsed persistent config path.
func configPathFromCommand(command *cobra.Command) string {
	configPath, _ := command.Root().PersistentFlags().GetString("config")

	return configPath
}

// rejectSingleDashLongOptions rejects accidental long-option shorthand forms.
func rejectSingleDashLongOptions(args []string) error {
	for _, arg := range args {
		if arg == "--" {
			return nil
		}
		if len(arg) <= 2 || !strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "--") {
			continue
		}
		if arg[1] >= '0' && arg[1] <= '9' {
			continue
		}

		return fmt.Errorf("long options require double dash: %s", arg)
	}

	return nil
}

// errorFromExitCode converts command result codes into Cobra errors.
func errorFromExitCode(code int) error {
	if code == 0 {
		return nil
	}

	return exitCodeError{code: code}
}
