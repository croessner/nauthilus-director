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

// Package main starts the nauthilus-directorctl client binary.
//
//nolint:dupl,funlen,goconst,gocyclo,wsl_v5 // The CLI keeps generated-client command paths explicit.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/client/generated"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var version = "dev"

const (
	defaultControlAddress = "http://127.0.0.1:9090"
	defaultTimeout        = 5 * time.Second
)

const (
	outputText outputMode = "text"
	outputJSON outputMode = "json"
)

const (
	commandStatus    = "status"
	commandBackends  = "backends"
	commandListeners = "listeners"
	commandConfig    = "config"
	commandSessions  = "sessions"
	commandUsers     = "users"
	commandRuntime   = "runtime"
	commandRoute     = "route"
	commandReload    = "reload"
)

type controlClientFactory func(address string, timeout time.Duration) (generated.ClientWithResponsesInterface, error)

var newControlClient controlClientFactory = newGeneratedControlClient

// outputMode selects the operator-facing rendering mode.
type outputMode string

// commandOptions carries global settings shared by all subcommands.
type commandOptions struct {
	Address string
	Timeout time.Duration
	Output  outputMode
}

// application owns command execution state for one invocation.
type application struct {
	options commandOptions
	stdout  io.Writer
	stderr  io.Writer
}

// commandFlagKind classifies a command-local flag.
type commandFlagKind int

const (
	commandFlagBool commandFlagKind = iota
	commandFlagValue
)

// commandFlag describes one command-local flag and its accepted aliases.
type commandFlag struct {
	name    string
	aliases []string
	kind    commandFlagKind
}

// parsedCommandLine stores positionals and command-local flag values.
type parsedCommandLine struct {
	positionals []string
	values      map[string][]string
	bools       map[string]bool
}

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
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run parses global flags and dispatches supported operator commands.
func run(args []string, stdout io.Writer, stderr io.Writer) int {
	if err := rejectSingleDashLongOptions(args); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}

	root := newDirectorCtlCommand(stdout, stderr)
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

// newDirectorCtlCommand builds the operator command tree.
func newDirectorCtlCommand(stdout io.Writer, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:               "nauthilus-directorctl",
		Short:             "Control a running Nauthilus Director",
		SilenceUsage:      true,
		SilenceErrors:     true,
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			showVersion, _ := cmd.Root().PersistentFlags().GetBool("version")
			if showVersion {
				_, _ = fmt.Fprintf(stdout, "nauthilus-directorctl %s\n", version)
				return exitCodeError{code: 0}
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return cobraHandler(stdout, stderr, application.dispatch)(cmd, args)
			}

			return cmd.Help()
		},
	}
	root.SetOut(stdout)
	root.SetErr(stderr)

	root.PersistentFlags().String("address", defaultControlAddress, "control API base URL")
	root.PersistentFlags().Duration("timeout", defaultTimeout, "control API request timeout")
	root.PersistentFlags().String("output", string(outputText), "output mode: text or json")
	root.PersistentFlags().Bool("version", false, "print version and exit")

	root.AddCommand(newStatusCommand(stdout, stderr))
	root.AddCommand(newBackendsCommand(stdout, stderr))
	root.AddCommand(newListenersCommand(stdout, stderr))
	root.AddCommand(newConfigCommand(stdout, stderr))
	root.AddCommand(newSessionsCommand(stdout, stderr))
	root.AddCommand(newUsersCommand(stdout, stderr))
	root.AddCommand(newRuntimeCommand(stdout, stderr))
	root.AddCommand(newRouteCommand(stdout, stderr))
	root.AddCommand(newReloadCommand(stdout, stderr))

	return root
}

// newStatusCommand builds the status command.
func newStatusCommand(stdout io.Writer, stderr io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show health, readiness and version data",
		RunE:  cobraHandler(stdout, stderr, application.runStatus),
	}
}

// newBackendsCommand builds backend inventory and runtime-control commands.
func newBackendsCommand(stdout io.Writer, stderr io.Writer) *cobra.Command {
	command := &cobra.Command{
		Use:   "backends",
		Short: "Inspect and control backend runtime state",
		RunE:  cobraHandler(stdout, stderr, application.runBackends),
	}
	command.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List backend runtime state",
		RunE:  cobraHandler(stdout, stderr, application.runBackendsList),
	})
	command.AddCommand(&cobra.Command{
		Use:   "show <identifier>",
		Short: "Show one backend",
		RunE:  cobraHandler(stdout, stderr, application.runBackendsShow),
	})
	command.AddCommand(newBackendMaintenanceCommand(stdout, stderr))
	command.AddCommand(runtimeReasonCommand("out <identifier>", "Exclude a backend from placement", stdout, stderr, application.runBackendsOut))
	command.AddCommand(runtimeReasonCommand("in <identifier>", "Return a backend to placement", stdout, stderr, application.runBackendsIn))
	drain := &cobra.Command{
		Use:   "drain <identifier>",
		Short: "Drain a backend",
		RunE:  cobraHandler(stdout, stderr, application.runBackendsDrain, "mode", "reason", "grace-seconds"),
	}
	addRuntimeDrainFlags(drain)
	command.AddCommand(drain)
	command.AddCommand(backendWeightCommand("weight <identifier>", "Override backend runtime weight", stdout, stderr, application.runBackendsWeight))
	command.AddCommand(newBackendRuntimeCommand(stdout, stderr))

	return command
}

// newBackendMaintenanceCommand builds backend maintenance commands.
func newBackendMaintenanceCommand(stdout io.Writer, stderr io.Writer) *cobra.Command {
	command := &cobra.Command{
		Use:   "maintenance",
		Short: "Control backend maintenance state",
		RunE:  cobraHandler(stdout, stderr, application.runBackendMaintenance),
	}
	enable := &cobra.Command{
		Use:   "enable <identifier>",
		Short: "Enable backend maintenance",
		RunE:  cobraHandler(stdout, stderr, application.runBackendMaintenanceEnable, "reason", "mode", "grace-seconds"),
	}
	addRuntimeDrainFlags(enable)
	command.AddCommand(enable)
	command.AddCommand(runtimeReasonCommand("disable <identifier>", "Disable backend maintenance", stdout, stderr, application.runBackendMaintenanceDisable))

	return command
}

// newBackendRuntimeCommand builds backend runtime override commands.
func newBackendRuntimeCommand(stdout io.Writer, stderr io.Writer) *cobra.Command {
	command := &cobra.Command{
		Use:   "runtime",
		Short: "Control backend runtime overrides",
		RunE:  cobraHandler(stdout, stderr, application.runBackendRuntime),
	}
	command.AddCommand(runtimeReasonCommand("clear <identifier>", "Clear backend runtime overrides", stdout, stderr, application.runBackendRuntimeClear))
	command.AddCommand(backendWeightCommand("weight <identifier>", "Override backend runtime weight", stdout, stderr, application.runBackendsWeight))

	return command
}

// newListenersCommand builds listener runtime-control commands.
func newListenersCommand(stdout io.Writer, stderr io.Writer) *cobra.Command {
	command := &cobra.Command{
		Use:   "listeners",
		Short: "Inspect and control process-local listeners",
		RunE:  cobraHandler(stdout, stderr, application.runListeners),
	}
	command.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List configured listeners",
		RunE:  cobraHandler(stdout, stderr, application.runListenersList),
	})
	command.AddCommand(&cobra.Command{
		Use:   "show <name>",
		Short: "Show one configured listener",
		RunE:  cobraHandler(stdout, stderr, application.runListenersShow),
	})
	drain := &cobra.Command{
		Use:   "drain <name>",
		Short: "Drain one process-local listener",
		RunE:  cobraHandler(stdout, stderr, application.runListenersDrain, "mode", "reason", "grace-seconds"),
	}
	addRuntimeDrainFlags(drain)
	command.AddCommand(drain)
	command.AddCommand(runtimeReasonCommand("resume <name>", "Resume one process-local listener", stdout, stderr, application.runListenersResume))

	return command
}

// newConfigCommand builds remote configuration inspection commands.
func newConfigCommand(stdout io.Writer, stderr io.Writer) *cobra.Command {
	command := &cobra.Command{
		Use:   "config",
		Short: "Inspect Director configuration through the control API",
		RunE:  cobraHandler(stdout, stderr, application.runConfig),
	}
	dump := &cobra.Command{
		Use:   "dump",
		Short: "Print remote configuration",
		RunE:  cobraHandler(stdout, stderr, application.runConfigDump, "defaults", "non-default", "protected", "format"),
	}
	dump.Flags().BoolP("defaults", "d", false, "dump canonical defaults")
	dump.Flags().BoolP("non-default", "n", false, "dump non-default effective config")
	dump.Flags().BoolP("protected", "P", false, "include protected values in config output")
	dump.Flags().StringP("format", "f", "", "config dump format: yaml or json")
	command.AddCommand(dump)

	return command
}

// newSessionsCommand builds active-session commands.
func newSessionsCommand(stdout io.Writer, stderr io.Writer) *cobra.Command {
	command := &cobra.Command{
		Use:   "sessions",
		Short: "Inspect and control active sessions",
		RunE:  cobraHandler(stdout, stderr, application.runSessions),
	}
	list := &cobra.Command{
		Use:   "list",
		Short: "List active sessions",
		RunE:  cobraHandler(stdout, stderr, application.runSessionsList, "protocol", "backend", "cursor", "limit", "all"),
	}
	list.Flags().String("protocol", "", "filter by protocol")
	list.Flags().String("backend", "", "filter by backend identifier")
	addPaginationFlags(list)
	command.AddCommand(list)
	command.AddCommand(&cobra.Command{
		Use:   "show <session-id>",
		Short: "Show one active session",
		RunE:  cobraHandler(stdout, stderr, application.runSessionsShow),
	})
	command.AddCommand(runtimeReasonCommand("kill <session-id>", "Terminate one active session", stdout, stderr, application.runSessionsKill))

	return command
}

// newUsersCommand builds user runtime-state commands.
func newUsersCommand(stdout io.Writer, stderr io.Writer) *cobra.Command {
	command := &cobra.Command{
		Use:   "users",
		Short: "Inspect and control user runtime state",
		RunE:  cobraHandler(stdout, stderr, application.runUsers),
	}
	list := &cobra.Command{
		Use:   "list",
		Short: "List users with runtime state",
		RunE:  cobraHandler(stdout, stderr, application.runUsersList, "cursor", "limit", "all"),
	}
	addPaginationFlags(list)
	command.AddCommand(list)
	command.AddCommand(&cobra.Command{
		Use:   "show <user-key>",
		Short: "Show one user's runtime state",
		RunE:  cobraHandler(stdout, stderr, application.runUsersShow),
	})
	command.AddCommand(&cobra.Command{
		Use:   "sessions <user-key>",
		Short: "List sessions for one user",
		RunE:  cobraHandler(stdout, stderr, application.runUsersSessions),
	})
	command.AddCommand(newUserAffinityCommand(stdout, stderr))
	command.AddCommand(newUserBackendPinCommand(stdout, stderr))
	command.AddCommand(newUserHoldCommand(stdout, stderr))
	move := &cobra.Command{
		Use:   "move <user-key>",
		Short: "Move future user placement",
		RunE:  cobraHandler(stdout, stderr, application.runUsersMove, "to-shard", "strategy", "reason"),
	}
	move.Flags().String("to-shard", "", "target shard")
	move.Flags().String("strategy", "", "move strategy")
	move.Flags().String("reason", "", "auditable reason")
	command.AddCommand(move)
	command.AddCommand(runtimeReasonCommand("kick <user-key>", "Terminate active sessions for one user", stdout, stderr, application.runUsersKick))

	return command
}

// newUserAffinityCommand builds user-affinity commands.
func newUserAffinityCommand(stdout io.Writer, stderr io.Writer) *cobra.Command {
	command := &cobra.Command{
		Use:   "affinity",
		Short: "Inspect and control user affinity",
		RunE:  cobraHandler(stdout, stderr, application.runUsersAffinity),
	}
	command.AddCommand(&cobra.Command{
		Use:   "show <user-key>",
		Short: "Show active affinity for one user",
		RunE:  cobraHandler(stdout, stderr, application.runUsersAffinityShow),
	})
	set := &cobra.Command{
		Use:   "set <user-key>",
		Short: "Set user affinity for future sessions",
		RunE:  cobraHandler(stdout, stderr, application.runUsersAffinitySet, "shard", "reason"),
	}
	set.Flags().String("shard", "", "target shard")
	set.Flags().String("reason", "", "auditable reason")
	command.AddCommand(set)
	command.AddCommand(runtimeReasonCommand("clear <user-key>", "Clear inactive user affinity", stdout, stderr, application.runUsersAffinityClear))

	return command
}

// newUserBackendPinCommand builds user backend-pin commands.
func newUserBackendPinCommand(stdout io.Writer, stderr io.Writer) *cobra.Command {
	command := &cobra.Command{
		Use:   "backend-pin",
		Short: "Inspect and control user backend pins",
		RunE:  cobraHandler(stdout, stderr, application.runUsersBackendPin),
	}
	command.AddCommand(&cobra.Command{
		Use:   "show <user-key>",
		Short: "Show the backend pin for one user",
		RunE:  cobraHandler(stdout, stderr, application.runUsersBackendPinShow),
	})
	set := &cobra.Command{
		Use:   "set <user-key>",
		Short: "Set a backend pin for one user",
		RunE:  cobraHandler(stdout, stderr, application.runUsersBackendPinSet, "backend", "strategy", "reason"),
	}
	set.Flags().String("backend", "", "target backend identifier")
	set.Flags().String("strategy", "", "pin strategy")
	set.Flags().String("reason", "", "auditable reason")
	command.AddCommand(set)
	command.AddCommand(runtimeReasonCommand("clear <user-key>", "Clear the backend pin for one user", stdout, stderr, application.runUsersBackendPinClear))

	return command
}

// newUserHoldCommand builds user placement-hold commands.
func newUserHoldCommand(stdout io.Writer, stderr io.Writer) *cobra.Command {
	command := &cobra.Command{
		Use:   "hold",
		Short: "Inspect and control user placement holds",
		RunE:  cobraHandler(stdout, stderr, application.runUsersHold),
	}
	command.AddCommand(&cobra.Command{
		Use:   "show <user-key>",
		Short: "Show the placement hold for one user",
		RunE:  cobraHandler(stdout, stderr, application.runUsersHoldShow),
	})
	set := &cobra.Command{
		Use:   "set <user-key>",
		Short: "Set a bounded placement hold for one user",
		RunE:  cobraHandler(stdout, stderr, application.runUsersHoldSet, "duration", "reason"),
	}
	set.Flags().String("duration", "", "hold duration")
	set.Flags().String("reason", "", "auditable reason")
	command.AddCommand(set)
	command.AddCommand(runtimeReasonCommand("clear <user-key>", "Clear the placement hold for one user", stdout, stderr, application.runUsersHoldClear))

	return command
}

// newRuntimeCommand builds runtime summary commands.
func newRuntimeCommand(stdout io.Writer, stderr io.Writer) *cobra.Command {
	command := &cobra.Command{
		Use:   "runtime",
		Short: "Inspect aggregate runtime state",
		RunE:  cobraHandler(stdout, stderr, application.runRuntime),
	}
	command.AddCommand(&cobra.Command{
		Use:   "summary",
		Short: "Show aggregate runtime totals",
		RunE:  cobraHandler(stdout, stderr, application.runRuntimeSummary),
	})

	return command
}

// newRouteCommand builds route diagnostic commands.
func newRouteCommand(stdout io.Writer, stderr io.Writer) *cobra.Command {
	command := &cobra.Command{
		Use:   "route",
		Short: "Run side-effect-free routing diagnostics",
		RunE:  cobraHandler(stdout, stderr, application.runRoute),
	}
	lookup := &cobra.Command{
		Use:   "lookup",
		Short: "Explain a route lookup",
		RunE: cobraHandler(stdout, stderr, application.runRouteLookup,
			"protocol", "user", "recipient", "tenant", "listener", "service-name",
			"backend-pool", "client-ip", "attribute", "include-affinity"),
	}
	lookup.Flags().String("protocol", "", "protocol name")
	lookup.Flags().String("user", "", "user key")
	lookup.Flags().String("recipient", "", "recipient address")
	lookup.Flags().String("tenant", "", "tenant name")
	lookup.Flags().String("listener", "", "listener name")
	lookup.Flags().String("service-name", "", "service name")
	lookup.Flags().String("backend-pool", "", "backend pool")
	lookup.Flags().String("client-ip", "", "client IP address")
	lookup.Flags().StringArray("attribute", nil, "routing attribute as key=value")
	lookup.Flags().Bool("include-affinity", false, "include read-only affinity context")
	command.AddCommand(lookup)

	return command
}

// newReloadCommand builds the safe reload command.
func newReloadCommand(stdout io.Writer, stderr io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "reload",
		Short: "Request a safe runtime reload",
		RunE:  cobraHandler(stdout, stderr, application.runReload),
	}
}

// runtimeReasonCommand builds a command with a required auditable reason.
func runtimeReasonCommand(use string, short string, stdout io.Writer, stderr io.Writer, runner func(application, []string) int) *cobra.Command {
	command := &cobra.Command{
		Use:   use,
		Short: short,
		RunE:  cobraHandler(stdout, stderr, runner, "reason"),
	}
	command.Flags().String("reason", "", "auditable reason")

	return command
}

// backendWeightCommand builds a backend weight command.
func backendWeightCommand(use string, short string, stdout io.Writer, stderr io.Writer, runner func(application, []string) int) *cobra.Command {
	command := &cobra.Command{
		Use:   use,
		Short: short,
		RunE:  cobraHandler(stdout, stderr, runner, "weight", "reason"),
	}
	command.Flags().String("weight", "", "runtime weight")
	command.Flags().String("reason", "", "auditable reason")

	return command
}

// addRuntimeDrainFlags adds shared drain and maintenance flags.
func addRuntimeDrainFlags(command *cobra.Command) {
	command.Flags().String("mode", "", "runtime mode: soft or hard")
	command.Flags().String("reason", "", "auditable reason")
	command.Flags().String("grace-seconds", "", "grace period in seconds")
}

// addPaginationFlags adds common cursor pagination flags.
func addPaginationFlags(command *cobra.Command) {
	command.Flags().String("cursor", "", "opaque pagination cursor")
	command.Flags().String("limit", "", "page size")
	command.Flags().Bool("all", false, "iterate all pages")
}

// cobraHandler adapts existing generated-client command handlers to Cobra.
func cobraHandler(stdout io.Writer, stderr io.Writer, runner func(application, []string) int, flagNames ...string) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		app, code := applicationFromCommand(cmd, stdout, stderr)
		if code != 0 {
			return exitCodeError{code: code}
		}

		commandArgs, err := commandArgsFromFlags(cmd, args, flagNames...)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return exitCodeError{code: 2}
		}

		return errorFromExitCode(runner(app, commandArgs))
	}
}

// applicationFromCommand reads validated global options from the Cobra root.
func applicationFromCommand(cmd *cobra.Command, stdout io.Writer, stderr io.Writer) (application, int) {
	flags := cmd.Root().PersistentFlags()
	address, _ := flags.GetString("address")
	timeout, _ := flags.GetDuration("timeout")
	output, _ := flags.GetString("output")

	mode, err := parseOutputMode(output)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%v\n", err)
		return application{}, 2
	}
	if timeout <= 0 {
		_, _ = fmt.Fprintln(stderr, "timeout must be greater than zero")
		return application{}, 2
	}

	return application{
		options: commandOptions{
			Address: address,
			Timeout: timeout,
			Output:  mode,
		},
		stdout: stdout,
		stderr: stderr,
	}, 0
}

// commandArgsFromFlags recreates the existing handler input from parsed flags.
func commandArgsFromFlags(cmd *cobra.Command, positionals []string, flagNames ...string) ([]string, error) {
	commandArgs := make([]string, 0, len(positionals)+(len(flagNames)*2))
	for _, name := range flagNames {
		flag := cmd.Flags().Lookup(name)
		if flag == nil || !flag.Changed {
			continue
		}

		switch flag.Value.Type() {
		case "bool":
			value, err := cmd.Flags().GetBool(name)
			if err != nil {
				return nil, err
			}
			commandArgs = append(commandArgs, "--"+name+"="+strconv.FormatBool(value))
		case "stringArray":
			values, err := cmd.Flags().GetStringArray(name)
			if err != nil {
				return nil, err
			}
			for _, value := range values {
				commandArgs = append(commandArgs, "--"+name, value)
			}
		default:
			commandArgs = append(commandArgs, "--"+name, flag.Value.String())
		}
	}

	return append(commandArgs, positionals...), nil
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

// errorFromExitCode converts handler result codes into Cobra errors.
func errorFromExitCode(code int) error {
	if code == 0 {
		return nil
	}

	return exitCodeError{code: code}
}

// parseOutputMode validates a global output mode.
func parseOutputMode(value string) (outputMode, error) {
	switch outputMode(strings.ToLower(strings.TrimSpace(value))) {
	case outputText:
		return outputText, nil
	case outputJSON:
		return outputJSON, nil
	default:
		return "", fmt.Errorf("output mode must be text or json")
	}
}

// dispatch routes the top-level command to its nested handler.
func (app application) dispatch(args []string) int {
	switch args[0] {
	case commandStatus:
		return app.runStatus(args[1:])
	case commandBackends:
		return app.runBackends(args[1:])
	case commandListeners:
		return app.runListeners(args[1:])
	case commandConfig:
		return app.runConfig(args[1:])
	case commandSessions:
		return app.runSessions(args[1:])
	case commandUsers:
		return app.runUsers(args[1:])
	case commandRuntime:
		return app.runRuntime(args[1:])
	case commandRoute:
		return app.runRoute(args[1:])
	case commandReload:
		return app.runReload(args[1:])
	default:
		return app.usageError("unknown command %q", args[0])
	}
}

// client creates the generated OpenAPI client for one command.
func (app application) client() (generated.ClientWithResponsesInterface, int) {
	client, err := newControlClient(app.options.Address, app.options.Timeout)
	if err != nil {
		_, _ = fmt.Fprintf(app.stderr, "control client failed: %v\n", err)
		return nil, 2
	}

	return client, 0
}

// runStatus calls read-only generated SDK methods for the control API status.
func (app application) runStatus(args []string) int {
	line, err := parseCommandLine(args, nil)
	if err != nil {
		return app.usageError("%v", err)
	}
	if len(line.positionals) != 0 {
		return app.usageError("status does not accept positional arguments")
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	health, err := client.GetHealthzWithResponse(ctx)
	if err != nil {
		return app.requestError("status healthz", err)
	}
	if health.StatusCode() != http.StatusOK {
		return app.serverError("status healthz", health.StatusCode(), health.JSONDefault)
	}

	ready, err := client.GetReadyzWithResponse(ctx)
	if err != nil {
		return app.requestError("status readyz", err)
	}
	if ready.StatusCode() != http.StatusOK {
		return app.serverError("status readyz", ready.StatusCode(), firstProblem(ready.JSON503, ready.JSONDefault))
	}

	versionResponse, err := client.GetVersionWithResponse(ctx)
	if err != nil {
		return app.requestError("status version", err)
	}
	if versionResponse.StatusCode() != http.StatusOK {
		return app.serverError("status version", versionResponse.StatusCode(), versionResponse.JSONDefault)
	}
	if health.JSON200 == nil || ready.JSON200 == nil || versionResponse.JSON200 == nil {
		return app.serverError("status", http.StatusBadGateway, nil)
	}

	if app.options.Output == outputJSON {
		payload := map[string]any{
			"api_version": versionResponse.JSON200.APIVersion,
			"health":      health.JSON200,
			"ready":       ready.JSON200,
			"version":     versionResponse.JSON200.Version,
		}
		return app.writeJSON(payload)
	}

	_, _ = fmt.Fprintf(app.stdout, "health=%s\n", health.JSON200.Status)
	_, _ = fmt.Fprintf(app.stdout, "ready=%s\n", ready.JSON200.Status)
	_, _ = fmt.Fprintf(app.stdout, "version=%s\n", versionResponse.JSON200.Version)
	_, _ = fmt.Fprintf(app.stdout, "api_version=%s\n", versionResponse.JSON200.APIVersion)

	return 0
}

// runBackends dispatches backend inventory and runtime-control commands.
func (app application) runBackends(args []string) int {
	if len(args) == 0 {
		return app.usageError("backends requires a subcommand")
	}

	switch args[0] {
	case "list":
		return app.runBackendsList(args[1:])
	case "show":
		return app.runBackendsShow(args[1:])
	case "maintenance":
		return app.runBackendMaintenance(args[1:])
	case "out":
		return app.runBackendsOut(args[1:])
	case "in":
		return app.runBackendsIn(args[1:])
	case "drain":
		return app.runBackendsDrain(args[1:])
	case "weight":
		return app.runBackendsWeight(args[1:])
	case "runtime":
		return app.runBackendRuntime(args[1:])
	default:
		return app.usageError("unknown backends subcommand %q", args[0])
	}
}

// runBackendsList lists backend runtime state.
func (app application) runBackendsList(args []string) int {
	line, err := parseCommandLine(args, nil)
	if err != nil {
		return app.usageError("%v", err)
	}
	if len(line.positionals) != 0 {
		return app.usageError("backends list does not accept positional arguments")
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	response, err := client.ListBackendsWithResponse(ctx)
	if err != nil {
		return app.requestError("backends list", err)
	}
	if response.StatusCode() != http.StatusOK {
		return app.serverError("backends list", response.StatusCode(), response.JSONDefault)
	}
	if response.JSON200 == nil {
		return app.serverError("backends list", http.StatusBadGateway, nil)
	}

	sort.Slice(response.JSON200.Backends, func(left int, right int) bool {
		return response.JSON200.Backends[left].Identifier < response.JSON200.Backends[right].Identifier
	})

	return app.writeObject(response.JSON200, func(writer io.Writer) error {
		for _, backend := range response.JSON200.Backends {
			writeBackendLine(writer, backend)
		}
		return nil
	})
}

// runBackendsShow shows one backend's runtime state.
func (app application) runBackendsShow(args []string) int {
	line, err := parseCommandLine(args, nil)
	if err != nil {
		return app.usageError("%v", err)
	}
	if len(line.positionals) != 1 {
		return app.usageError("backends show requires exactly one backend identifier")
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	response, err := client.GetBackendWithResponse(ctx, line.positionals[0])
	if err != nil {
		return app.requestError("backends show", err)
	}
	if response.StatusCode() != http.StatusOK {
		return app.serverError("backends show", response.StatusCode(), response.JSONDefault)
	}
	if response.JSON200 == nil {
		return app.serverError("backends show", http.StatusBadGateway, nil)
	}

	return app.writeObject(response.JSON200, func(writer io.Writer) error {
		writeBackendLine(writer, *response.JSON200)
		return nil
	})
}

// runBackendMaintenance dispatches maintenance enable and disable commands.
func (app application) runBackendMaintenance(args []string) int {
	if len(args) == 0 {
		return app.usageError("backends maintenance requires enable or disable")
	}

	switch args[0] {
	case "enable":
		return app.runBackendMaintenanceEnable(args[1:])
	case "disable":
		return app.runBackendMaintenanceDisable(args[1:])
	default:
		return app.usageError("unknown backends maintenance subcommand %q", args[0])
	}
}

// runBackendMaintenanceEnable enables soft or hard backend maintenance.
func (app application) runBackendMaintenanceEnable(args []string) int {
	line, err := parseCommandLine(args, []commandFlag{
		valueFlag("reason"),
		valueFlag("mode"),
		valueFlag("grace-seconds"),
	})
	if err != nil {
		return app.usageError("%v", err)
	}
	if len(line.positionals) != 1 {
		return app.usageError("backends maintenance enable requires exactly one backend identifier")
	}

	reason, ok := requiredValue(line, "reason")
	if !ok {
		return app.usageError("backends maintenance enable requires --reason")
	}

	modeValue := line.value("mode")
	if modeValue == "" {
		modeValue = string(generated.MaintenanceModeSoft)
	}
	mode := generated.MaintenanceMode(modeValue)
	if !mode.Valid() || mode == generated.MaintenanceModeDisabled {
		return app.usageError("maintenance mode must be soft or hard")
	}

	graceSeconds, err := optionalNonNegativeInt(line, "grace-seconds")
	if err != nil {
		return app.usageError("%v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	body := generated.EnableBackendMaintenanceJSONRequestBody{
		GraceSeconds: graceSeconds,
		Mode:         mode,
		Reason:       reason,
	}
	response, err := client.EnableBackendMaintenanceWithResponse(ctx, line.positionals[0], body)
	if err != nil {
		return app.requestError("backends maintenance enable", err)
	}

	return app.handleEnableBackendMaintenanceResponse(response)
}

// runBackendRuntime dispatches backend runtime subcommands.
func (app application) runBackendRuntime(args []string) int {
	if len(args) == 0 {
		return app.usageError("backends runtime requires a subcommand")
	}
	switch args[0] {
	case "clear":
		return app.runBackendRuntimeClear(args[1:])
	case "weight":
		return app.runBackendsWeight(args[1:])
	default:
		return app.usageError("unknown backends runtime subcommand %q", args[0])
	}
}

// backendRuntimeReasonArgs parses an identifier and mandatory reason.
func (app application) backendRuntimeReasonArgs(args []string, operation string) (string, string, int) {
	line, err := parseCommandLine(args, []commandFlag{valueFlag("reason")})
	if err != nil {
		return "", "", app.usageError("%v", err)
	}
	if len(line.positionals) != 1 {
		return "", "", app.usageError("%s requires exactly one backend identifier", operation)
	}

	reason, ok := requiredValue(line, "reason")
	if !ok {
		return "", "", app.usageError("%s requires --reason", operation)
	}

	return line.positionals[0], reason, 0
}

// runBackendMaintenanceDisable disables backend maintenance.
func (app application) runBackendMaintenanceDisable(args []string) int {
	identifier, reason, code := app.backendRuntimeReasonArgs(args, "backends maintenance disable")
	if code != 0 {
		return code
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	response, err := client.DisableBackendMaintenanceWithResponse(ctx, identifier, generated.DisableBackendMaintenanceJSONRequestBody{Reason: reason})
	if err != nil {
		return app.requestError("backends maintenance disable", err)
	}

	return app.handleDisableBackendMaintenanceResponse(response)
}

// runBackendRuntimeClear clears backend runtime overrides.
func (app application) runBackendRuntimeClear(args []string) int {
	identifier, reason, code := app.backendRuntimeReasonArgs(args, "backends runtime clear")
	if code != 0 {
		return code
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	response, err := client.ClearBackendRuntimeWithResponse(ctx, identifier, generated.ClearBackendRuntimeJSONRequestBody{Reason: reason})
	if err != nil {
		return app.requestError("backends runtime clear", err)
	}

	return app.handleClearBackendRuntimeResponse(response)
}

// runBackendsIn marks one backend in service.
func (app application) runBackendsIn(args []string) int {
	identifier, reason, code := app.backendRuntimeReasonArgs(args, "backends in")
	if code != 0 {
		return code
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	response, err := client.MarkBackendInWithResponse(ctx, identifier, generated.MarkBackendInJSONRequestBody{Reason: reason})
	if err != nil {
		return app.requestError("backends in", err)
	}

	return app.handleMarkBackendInResponse(response)
}

// runBackendsOut marks one backend out of service.
func (app application) runBackendsOut(args []string) int {
	identifier, reason, code := app.backendRuntimeReasonArgs(args, "backends out")
	if code != 0 {
		return code
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	response, err := client.MarkBackendOutWithResponse(ctx, identifier, generated.MarkBackendOutJSONRequestBody{Reason: reason})
	if err != nil {
		return app.requestError("backends out", err)
	}

	return app.handleMarkBackendOutResponse(response)
}

// runBackendsWeight changes one backend's runtime placement weight.
func (app application) runBackendsWeight(args []string) int {
	line, err := parseCommandLine(args, []commandFlag{
		valueFlag("weight"),
		valueFlag("reason"),
	})
	if err != nil {
		return app.usageError("%v", err)
	}
	if len(line.positionals) != 1 {
		return app.usageError("backends weight requires exactly one backend identifier")
	}

	reason, ok := requiredValue(line, "reason")
	if !ok {
		return app.usageError("backends weight requires --reason")
	}

	weightText, ok := requiredValue(line, "weight")
	if !ok {
		return app.usageError("backends weight requires --weight")
	}

	weight, err := strconv.Atoi(weightText)
	if err != nil || weight < 0 {
		return app.usageError("backends weight requires a non-negative integer --weight")
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	response, err := client.SetBackendWeightWithResponse(ctx, line.positionals[0], generated.SetBackendWeightJSONRequestBody{
		Reason: reason,
		Weight: weight,
	})
	if err != nil {
		return app.requestError("backends weight", err)
	}

	return app.handleSetBackendWeightResponse(response)
}

// runBackendsDrain drains one backend with an explicit mode and reason.
func (app application) runBackendsDrain(args []string) int {
	line, err := parseCommandLine(args, []commandFlag{
		valueFlag("mode"),
		valueFlag("reason"),
		valueFlag("grace-seconds"),
	})
	if err != nil {
		return app.usageError("%v", err)
	}
	if len(line.positionals) != 1 {
		return app.usageError("backends drain requires exactly one backend identifier")
	}

	reason, ok := requiredValue(line, "reason")
	if !ok {
		return app.usageError("backends drain requires --reason")
	}

	mode := generated.DrainMode(line.value("mode"))
	if !mode.Valid() {
		return app.usageError("drain mode must be soft or hard")
	}

	graceSeconds, err := optionalNonNegativeInt(line, "grace-seconds")
	if err != nil {
		return app.usageError("%v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	body := generated.DrainBackendJSONRequestBody{
		GraceSeconds: graceSeconds,
		Mode:         mode,
		Reason:       reason,
	}
	response, err := client.DrainBackendWithResponse(ctx, line.positionals[0], body)
	if err != nil {
		return app.requestError("backends drain", err)
	}

	return app.handleDrainBackendResponse(response)
}

// runListeners dispatches listener inventory and runtime-control commands.
func (app application) runListeners(args []string) int {
	if len(args) == 0 {
		return app.usageError("listeners requires a subcommand")
	}

	switch args[0] {
	case "list":
		return app.runListenersList(args[1:])
	case "show":
		return app.runListenersShow(args[1:])
	case "drain":
		return app.runListenersDrain(args[1:])
	case "resume":
		return app.runListenersResume(args[1:])
	default:
		return app.usageError("unknown listeners subcommand %q", args[0])
	}
}

// runListenersList lists process-local listener runtime state.
func (app application) runListenersList(args []string) int {
	line, err := parseCommandLine(args, nil)
	if err != nil {
		return app.usageError("%v", err)
	}
	if len(line.positionals) != 0 {
		return app.usageError("listeners list does not accept positional arguments")
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	response, err := client.ListListenersWithResponse(ctx)
	if err != nil {
		return app.requestError("listeners list", err)
	}
	if response.StatusCode() != http.StatusOK {
		return app.serverError("listeners list", response.StatusCode(), response.JSONDefault)
	}
	if response.JSON200 == nil {
		return app.serverError("listeners list", http.StatusBadGateway, nil)
	}

	sort.Slice(response.JSON200.Listeners, func(left int, right int) bool {
		return response.JSON200.Listeners[left].Name < response.JSON200.Listeners[right].Name
	})

	return app.writeObject(response.JSON200, func(writer io.Writer) error {
		for _, listener := range response.JSON200.Listeners {
			writeListenerLine(writer, listener)
		}
		return nil
	})
}

// runListenersShow shows one process-local listener.
func (app application) runListenersShow(args []string) int {
	name, code := app.listenerNameArg(args, "listeners show")
	if code != 0 {
		return code
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	response, err := client.GetListenerWithResponse(ctx, generated.ListenerName(name))
	if err != nil {
		return app.requestError("listeners show", err)
	}
	if response.StatusCode() != http.StatusOK {
		return app.serverError("listeners show", response.StatusCode(), response.JSONDefault)
	}
	if response.JSON200 == nil {
		return app.serverError("listeners show", http.StatusBadGateway, nil)
	}

	return app.writeObject(response.JSON200, func(writer io.Writer) error {
		writeListenerLine(writer, *response.JSON200)
		return nil
	})
}

// runListenersDrain drains one process-local listener with explicit operator intent.
func (app application) runListenersDrain(args []string) int {
	line, err := parseCommandLine(args, []commandFlag{
		valueFlag("mode"),
		valueFlag("reason"),
		valueFlag("grace-seconds"),
	})
	if err != nil {
		return app.usageError("%v", err)
	}
	if len(line.positionals) != 1 {
		return app.usageError("listeners drain requires exactly one listener name")
	}

	name := strings.TrimSpace(line.positionals[0])
	if name == "" {
		return app.usageError("listeners drain requires a non-empty listener name")
	}

	reason, ok := requiredValue(line, "reason")
	if !ok {
		return app.usageError("listeners drain requires --reason")
	}

	mode := generated.DrainMode(line.value("mode"))
	if !mode.Valid() {
		return app.usageError("drain mode must be soft or hard")
	}

	graceSeconds, err := optionalNonNegativeInt(line, "grace-seconds")
	if err != nil {
		return app.usageError("%v", err)
	}
	if mode == generated.DrainModeHard && len(line.all("grace-seconds")) == 0 {
		return app.usageError("listeners drain --mode hard requires --grace-seconds")
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	body := generated.DrainListenerJSONRequestBody{
		GraceSeconds: graceSeconds,
		Mode:         mode,
		Reason:       reason,
	}
	response, err := client.DrainListenerWithResponse(ctx, generated.ListenerName(name), body)
	if err != nil {
		return app.requestError("listeners drain", err)
	}

	return app.handleDrainListenerResponse(response)
}

// runListenersResume resumes one process-local listener from static config.
func (app application) runListenersResume(args []string) int {
	line, err := parseCommandLine(args, []commandFlag{valueFlag("reason")})
	if err != nil {
		return app.usageError("%v", err)
	}
	if len(line.positionals) != 1 {
		return app.usageError("listeners resume requires exactly one listener name")
	}

	name := strings.TrimSpace(line.positionals[0])
	if name == "" {
		return app.usageError("listeners resume requires a non-empty listener name")
	}

	reason, ok := requiredValue(line, "reason")
	if !ok {
		return app.usageError("listeners resume requires --reason")
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	response, err := client.ResumeListenerWithResponse(ctx, generated.ListenerName(name), generated.ResumeListenerJSONRequestBody{Reason: reason})
	if err != nil {
		return app.requestError("listeners resume", err)
	}

	return app.handleResumeListenerResponse(response)
}

// listenerNameArg parses one non-empty listener name.
func (app application) listenerNameArg(args []string, operation string) (string, int) {
	line, err := parseCommandLine(args, nil)
	if err != nil {
		return "", app.usageError("%v", err)
	}
	if len(line.positionals) != 1 {
		return "", app.usageError("%s requires exactly one listener name", operation)
	}

	name := strings.TrimSpace(line.positionals[0])
	if name == "" {
		return "", app.usageError("%s requires a non-empty listener name", operation)
	}

	return name, 0
}

// runConfig dispatches config inspection commands.
func (app application) runConfig(args []string) int {
	if len(args) == 0 {
		return app.usageError("config requires a subcommand")
	}
	if args[0] != "dump" {
		return app.usageError("unknown config subcommand %q", args[0])
	}

	return app.runConfigDump(args[1:])
}

// runConfigDump prints Director configuration from the control API.
func (app application) runConfigDump(args []string) int {
	line, err := parseCommandLine(args, []commandFlag{
		boolFlag("defaults", "d"),
		boolFlag("non-default", "n"),
		boolFlag("protected", "P"),
		valueFlag("format", "f"),
	})
	if err != nil {
		return app.usageError("%v", err)
	}
	if len(line.positionals) != 0 {
		return app.usageError("config dump does not accept positional arguments")
	}
	if line.bool("defaults") == line.bool("non-default") {
		return app.usageError("choose exactly one of -d or -n")
	}

	format := line.value("format")
	if format == "" {
		format = string(generated.ConfigDocumentFormatYaml)
	}
	if !generated.ConfigDocumentFormat(format).Valid() {
		return app.usageError("config dump format must be yaml or json")
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	includeProtected := generated.IncludeProtected(line.bool("protected"))
	if line.bool("defaults") {
		paramFormat := generated.GetDefaultConfigParamsFormat(format)
		response, err := client.GetDefaultConfigWithResponse(ctx, &generated.GetDefaultConfigParams{
			Format:           &paramFormat,
			IncludeProtected: &includeProtected,
		})
		if err != nil {
			return app.requestError("config dump", err)
		}
		if response.StatusCode() != http.StatusOK {
			return app.configDumpServerError(response.StatusCode(), response.JSONDefault, line.bool("protected"))
		}
		if response.JSON200 == nil {
			return app.serverError("config dump", http.StatusBadGateway, nil)
		}

		return app.writeConfigDocument(response.JSON200, format)
	}

	paramFormat := generated.GetNonDefaultConfigParamsFormat(format)
	response, err := client.GetNonDefaultConfigWithResponse(ctx, &generated.GetNonDefaultConfigParams{
		Format:           &paramFormat,
		IncludeProtected: &includeProtected,
	})
	if err != nil {
		return app.requestError("config dump", err)
	}
	if response.StatusCode() != http.StatusOK {
		return app.configDumpServerError(response.StatusCode(), response.JSONDefault, line.bool("protected"))
	}
	if response.JSON200 == nil {
		return app.serverError("config dump", http.StatusBadGateway, nil)
	}

	return app.writeConfigDocument(response.JSON200, format)
}

// runSessions dispatches session inventory and termination commands.
func (app application) runSessions(args []string) int {
	if len(args) == 0 {
		return app.usageError("sessions requires a subcommand")
	}

	switch args[0] {
	case "list":
		return app.runSessionsList(args[1:])
	case "show":
		return app.runSessionsShow(args[1:])
	case "kill":
		return app.runSessionsKill(args[1:])
	default:
		return app.usageError("unknown sessions subcommand %q", args[0])
	}
}

// runSessionsList lists active sessions.
func (app application) runSessionsList(args []string) int {
	line, err := parseCommandLine(args, []commandFlag{
		valueFlag("protocol"),
		valueFlag("backend"),
		valueFlag("cursor"),
		valueFlag("limit"),
		boolFlag("all"),
	})
	if err != nil {
		return app.usageError("%v", err)
	}
	if len(line.positionals) != 0 {
		return app.usageError("sessions list does not accept positional arguments")
	}

	limit, err := optionalPositiveInt(line, "limit")
	if err != nil {
		return app.usageError("%v", err)
	}

	var params generated.ListSessionsParams
	if protocol := line.value("protocol"); protocol != "" {
		params.Protocol = &protocol
	}
	if backend := line.value("backend"); backend != "" {
		params.Backend = &backend
	}
	if cursor := line.value("cursor"); cursor != "" {
		typedCursor := generated.RuntimeReadCursor(cursor)
		params.Cursor = &typedCursor
	}
	if limit != nil {
		typedLimit := generated.RuntimeReadLimit(*limit)
		params.Limit = &typedLimit
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	result := generated.SessionListResponse{}
	seenCursors := make(map[string]bool)

	for {
		if err := ctx.Err(); err != nil {
			return app.requestError("sessions list", err)
		}

		if params.Cursor != nil {
			seenCursors[string(*params.Cursor)] = true
		}

		response, err := client.ListSessionsWithResponse(ctx, &params)
		if err != nil {
			return app.requestError("sessions list", err)
		}
		if response.StatusCode() != http.StatusOK {
			return app.serverError("sessions list", response.StatusCode(), response.JSONDefault)
		}
		if response.JSON200 == nil {
			return app.serverError("sessions list", http.StatusBadGateway, nil)
		}

		result.Sessions = append(result.Sessions, response.JSON200.Sessions...)
		result.NextCursor = response.JSON200.NextCursor
		if !line.bool("all") || response.JSON200.NextCursor == nil || strings.TrimSpace(*response.JSON200.NextCursor) == "" {
			break
		}

		nextCursor := strings.TrimSpace(*response.JSON200.NextCursor)
		if seenCursors[nextCursor] {
			return app.cursorLoopError("sessions list")
		}
		typedCursor := generated.RuntimeReadCursor(nextCursor)
		params.Cursor = &typedCursor
	}

	if line.bool("all") {
		result.NextCursor = nil
	}

	return app.writeSessionList(&result)
}

// runSessionsShow shows one active session.
func (app application) runSessionsShow(args []string) int {
	line, err := parseCommandLine(args, nil)
	if err != nil {
		return app.usageError("%v", err)
	}
	if len(line.positionals) != 1 {
		return app.usageError("sessions show requires exactly one session id")
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	response, err := client.GetSessionWithResponse(ctx, line.positionals[0])
	if err != nil {
		return app.requestError("sessions show", err)
	}
	if response.StatusCode() != http.StatusOK {
		return app.serverError("sessions show", response.StatusCode(), response.JSONDefault)
	}
	if response.JSON200 == nil {
		return app.serverError("sessions show", http.StatusBadGateway, nil)
	}

	return app.writeObject(response.JSON200, func(writer io.Writer) error {
		writeSessionLine(writer, *response.JSON200)
		return nil
	})
}

// runSessionsKill terminates one active session through the control API.
func (app application) runSessionsKill(args []string) int {
	line, err := parseCommandLine(args, []commandFlag{valueFlag("reason")})
	if err != nil {
		return app.usageError("%v", err)
	}
	if len(line.positionals) != 1 {
		return app.usageError("sessions kill requires exactly one session id")
	}

	reason, ok := requiredValue(line, "reason")
	if !ok {
		return app.usageError("sessions kill requires --reason")
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	response, err := client.DeleteSessionWithResponse(ctx, line.positionals[0], generated.DeleteSessionJSONRequestBody{Reason: reason})
	if err != nil {
		return app.requestError("sessions kill", err)
	}

	return app.handleDeleteSessionResponse(response)
}

// runUsers dispatches user runtime state commands.
func (app application) runUsers(args []string) int {
	if len(args) == 0 {
		return app.usageError("users requires a subcommand")
	}

	switch args[0] {
	case "list":
		return app.runUsersList(args[1:])
	case "show":
		return app.runUsersShow(args[1:])
	case "sessions":
		return app.runUsersSessions(args[1:])
	case "affinity":
		return app.runUsersAffinity(args[1:])
	case "backend-pin":
		return app.runUsersBackendPin(args[1:])
	case "hold":
		return app.runUsersHold(args[1:])
	case "move":
		return app.runUsersMove(args[1:])
	case "kick":
		return app.runUsersKick(args[1:])
	default:
		return app.usageError("unknown users subcommand %q", args[0])
	}
}

// runUsersList lists users with active runtime state.
func (app application) runUsersList(args []string) int {
	line, err := parseCommandLine(args, []commandFlag{
		valueFlag("cursor"),
		valueFlag("limit"),
		boolFlag("all"),
	})
	if err != nil {
		return app.usageError("%v", err)
	}
	if len(line.positionals) != 0 {
		return app.usageError("users list does not accept positional arguments")
	}

	limit, err := optionalPositiveInt(line, "limit")
	if err != nil {
		return app.usageError("%v", err)
	}

	var params generated.ListUsersParams
	if cursor := line.value("cursor"); cursor != "" {
		typedCursor := generated.RuntimeReadCursor(cursor)
		params.Cursor = &typedCursor
	}
	if limit != nil {
		typedLimit := generated.RuntimeReadLimit(*limit)
		params.Limit = &typedLimit
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	result := generated.UserListResponse{}
	seenCursors := make(map[string]bool)

	for {
		if err := ctx.Err(); err != nil {
			return app.requestError("users list", err)
		}

		if params.Cursor != nil {
			seenCursors[string(*params.Cursor)] = true
		}

		response, err := client.ListUsersWithResponse(ctx, &params)
		if err != nil {
			return app.requestError("users list", err)
		}
		if response.StatusCode() != http.StatusOK {
			return app.serverError("users list", response.StatusCode(), response.JSONDefault)
		}
		if response.JSON200 == nil {
			return app.serverError("users list", http.StatusBadGateway, nil)
		}

		result.Users = append(result.Users, response.JSON200.Users...)
		result.NextCursor = response.JSON200.NextCursor
		if !line.bool("all") || response.JSON200.NextCursor == nil || strings.TrimSpace(*response.JSON200.NextCursor) == "" {
			break
		}

		nextCursor := strings.TrimSpace(*response.JSON200.NextCursor)
		if seenCursors[nextCursor] {
			return app.cursorLoopError("users list")
		}
		typedCursor := generated.RuntimeReadCursor(nextCursor)
		params.Cursor = &typedCursor
	}

	if line.bool("all") {
		result.NextCursor = nil
	}

	return app.writeUserList(&result)
}

// runUsersShow shows one user's runtime state.
func (app application) runUsersShow(args []string) int {
	line, err := parseCommandLine(args, nil)
	if err != nil {
		return app.usageError("%v", err)
	}
	if len(line.positionals) != 1 {
		return app.usageError("users show requires exactly one user key")
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	response, err := client.GetUserWithResponse(ctx, line.positionals[0])
	if err != nil {
		return app.requestError("users show", err)
	}
	if response.StatusCode() != http.StatusOK {
		return app.serverError("users show", response.StatusCode(), response.JSONDefault)
	}
	if response.JSON200 == nil {
		return app.serverError("users show", http.StatusBadGateway, nil)
	}

	return app.writeObject(response.JSON200, func(writer io.Writer) error {
		writeUserLine(writer, *response.JSON200)
		return nil
	})
}

// runUsersSessions lists sessions for one user.
func (app application) runUsersSessions(args []string) int {
	line, err := parseCommandLine(args, nil)
	if err != nil {
		return app.usageError("%v", err)
	}
	if len(line.positionals) != 1 {
		return app.usageError("users sessions requires exactly one user key")
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	response, err := client.GetUserSessionsWithResponse(ctx, line.positionals[0])
	if err != nil {
		return app.requestError("users sessions", err)
	}
	if response.StatusCode() != http.StatusOK {
		return app.serverError("users sessions", response.StatusCode(), response.JSONDefault)
	}
	if response.JSON200 == nil {
		return app.serverError("users sessions", http.StatusBadGateway, nil)
	}

	sort.Slice(response.JSON200.Sessions, func(left int, right int) bool {
		return response.JSON200.Sessions[left].SessionID < response.JSON200.Sessions[right].SessionID
	})

	return app.writeObject(response.JSON200, func(writer io.Writer) error {
		for _, session := range response.JSON200.Sessions {
			writeSessionLine(writer, session)
		}
		return nil
	})
}

// runUsersAffinity dispatches user affinity commands.
func (app application) runUsersAffinity(args []string) int {
	if len(args) == 0 {
		return app.usageError("users affinity requires a subcommand")
	}

	switch args[0] {
	case "show":
		return app.runUsersAffinityShow(args[1:])
	case "set":
		return app.runUsersAffinitySet(args[1:])
	case "clear":
		return app.runUsersAffinityClear(args[1:])
	default:
		return app.usageError("unknown users affinity subcommand %q", args[0])
	}
}

// runUsersAffinityShow shows active affinity for one user.
func (app application) runUsersAffinityShow(args []string) int {
	line, err := parseCommandLine(args, nil)
	if err != nil {
		return app.usageError("%v", err)
	}
	if len(line.positionals) != 1 {
		return app.usageError("users affinity show requires exactly one user key")
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	response, err := client.GetUserAffinityWithResponse(ctx, line.positionals[0])
	if err != nil {
		return app.requestError("users affinity show", err)
	}
	if response.StatusCode() != http.StatusOK {
		return app.serverError("users affinity show", response.StatusCode(), response.JSONDefault)
	}
	if response.JSON200 == nil {
		return app.serverError("users affinity show", http.StatusBadGateway, nil)
	}

	return app.writeObject(response.JSON200, func(writer io.Writer) error {
		writeAffinityLine(writer, *response.JSON200)
		return nil
	})
}

// runUsersAffinitySet pins future user sessions to a shard.
func (app application) runUsersAffinitySet(args []string) int {
	line, err := parseCommandLine(args, []commandFlag{valueFlag("shard"), valueFlag("reason")})
	if err != nil {
		return app.usageError("%v", err)
	}
	if len(line.positionals) != 1 {
		return app.usageError("users affinity set requires exactly one user key")
	}

	reason, ok := requiredValue(line, "reason")
	if !ok {
		return app.usageError("users affinity set requires --reason")
	}
	shard, ok := requiredValue(line, "shard")
	if !ok {
		return app.usageError("users affinity set requires --shard")
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	body := generated.SetUserAffinityJSONRequestBody{
		Reason:   reason,
		ShardTag: shard,
	}
	response, err := client.SetUserAffinityWithResponse(ctx, line.positionals[0], body)
	if err != nil {
		return app.requestError("users affinity set", err)
	}

	return app.handleSetUserAffinityResponse(response)
}

// runUsersAffinityClear removes inactive user affinity.
func (app application) runUsersAffinityClear(args []string) int {
	line, err := parseCommandLine(args, []commandFlag{valueFlag("reason")})
	if err != nil {
		return app.usageError("%v", err)
	}
	if len(line.positionals) != 1 {
		return app.usageError("users affinity clear requires exactly one user key")
	}

	reason, ok := requiredValue(line, "reason")
	if !ok {
		return app.usageError("users affinity clear requires --reason")
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	response, err := client.ClearUserAffinityWithResponse(ctx, line.positionals[0], generated.ClearUserAffinityJSONRequestBody{Reason: reason})
	if err != nil {
		return app.requestError("users affinity clear", err)
	}

	return app.handleClearUserAffinityResponse(response)
}

// runUsersBackendPin dispatches user backend-pin commands.
func (app application) runUsersBackendPin(args []string) int {
	if len(args) == 0 {
		return app.usageError("users backend-pin requires a subcommand")
	}

	switch args[0] {
	case "show":
		return app.runUsersBackendPinShow(args[1:])
	case "set":
		return app.runUsersBackendPinSet(args[1:])
	case "clear":
		return app.runUsersBackendPinClear(args[1:])
	default:
		return app.usageError("unknown users backend-pin subcommand %q", args[0])
	}
}

// runUsersBackendPinShow shows the backend pin for one user.
func (app application) runUsersBackendPinShow(args []string) int {
	userKey, code := app.userKeyArg(args, "users backend-pin show")
	if code != 0 {
		return code
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	response, err := client.GetUserBackendPinWithResponse(ctx, generated.UserKey(userKey))
	if err != nil {
		return app.requestError("users backend-pin show", err)
	}
	if response.StatusCode() != http.StatusOK {
		return app.serverError("users backend-pin show", response.StatusCode(), response.JSONDefault)
	}
	if response.JSON200 == nil {
		return app.serverError("users backend-pin show", http.StatusBadGateway, nil)
	}

	return app.writeObject(response.JSON200, func(writer io.Writer) error {
		writeBackendPinLine(writer, *response.JSON200)
		return nil
	})
}

// runUsersBackendPinSet pins future placements to one concrete backend.
func (app application) runUsersBackendPinSet(args []string) int {
	line, err := parseCommandLine(args, []commandFlag{
		valueFlag("backend"),
		valueFlag("strategy"),
		valueFlag("reason"),
	})
	if err != nil {
		return app.usageError("%v", err)
	}
	userKey, code := app.userKeyFromLine(line, "users backend-pin set")
	if code != 0 {
		return code
	}

	reason, ok := requiredValue(line, "reason")
	if !ok {
		return app.usageError("users backend-pin set requires --reason")
	}
	backend, ok := requiredValue(line, "backend")
	if !ok {
		return app.usageError("users backend-pin set requires --backend")
	}
	strategy := generated.UserMoveRequestStrategy(line.value("strategy"))
	if !strategy.Valid() {
		return app.usageError("backend-pin strategy must be new_sessions_only, kick_existing or drain_existing")
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	body := generated.SetUserBackendPinJSONRequestBody{
		Backend:  backend,
		Reason:   reason,
		Strategy: strategy,
	}
	response, err := client.SetUserBackendPinWithResponse(ctx, generated.UserKey(userKey), body)
	if err != nil {
		return app.requestError("users backend-pin set", err)
	}

	return app.handleSetUserBackendPinResponse(response)
}

// runUsersBackendPinClear clears one user's concrete backend pin.
func (app application) runUsersBackendPinClear(args []string) int {
	line, err := parseCommandLine(args, []commandFlag{valueFlag("reason")})
	if err != nil {
		return app.usageError("%v", err)
	}
	userKey, code := app.userKeyFromLine(line, "users backend-pin clear")
	if code != 0 {
		return code
	}

	reason, ok := requiredValue(line, "reason")
	if !ok {
		return app.usageError("users backend-pin clear requires --reason")
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	response, err := client.ClearUserBackendPinWithResponse(
		ctx,
		generated.UserKey(userKey),
		generated.ClearUserBackendPinJSONRequestBody{Reason: reason},
	)
	if err != nil {
		return app.requestError("users backend-pin clear", err)
	}

	return app.handleClearUserBackendPinResponse(response)
}

// runUsersHold dispatches user placement-hold commands.
func (app application) runUsersHold(args []string) int {
	if len(args) == 0 {
		return app.usageError("users hold requires a subcommand")
	}

	switch args[0] {
	case "show":
		return app.runUsersHoldShow(args[1:])
	case "set":
		return app.runUsersHoldSet(args[1:])
	case "clear":
		return app.runUsersHoldClear(args[1:])
	default:
		return app.usageError("unknown users hold subcommand %q", args[0])
	}
}

// runUsersHoldShow shows the placement hold for one user.
func (app application) runUsersHoldShow(args []string) int {
	userKey, code := app.userKeyArg(args, "users hold show")
	if code != 0 {
		return code
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	response, err := client.GetUserHoldWithResponse(ctx, generated.UserKey(userKey))
	if err != nil {
		return app.requestError("users hold show", err)
	}
	if response.StatusCode() != http.StatusOK {
		return app.serverError("users hold show", response.StatusCode(), response.JSONDefault)
	}
	if response.JSON200 == nil {
		return app.serverError("users hold show", http.StatusBadGateway, nil)
	}

	return app.writeObject(response.JSON200, func(writer io.Writer) error {
		writeUserHoldLine(writer, *response.JSON200)
		return nil
	})
}

// runUsersHoldSet creates a bounded placement hold for one user.
func (app application) runUsersHoldSet(args []string) int {
	line, err := parseCommandLine(args, []commandFlag{
		valueFlag("duration"),
		valueFlag("reason"),
	})
	if err != nil {
		return app.usageError("%v", err)
	}
	userKey, code := app.userKeyFromLine(line, "users hold set")
	if code != 0 {
		return code
	}

	reason, ok := requiredValue(line, "reason")
	if !ok {
		return app.usageError("users hold set requires --reason")
	}
	durationText, ok := requiredValue(line, "duration")
	if !ok {
		return app.usageError("users hold set requires --duration")
	}

	durationSeconds, err := parseHoldDurationSeconds(durationText)
	if err != nil {
		return app.usageError("%v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	body := generated.SetUserHoldJSONRequestBody{
		DurationSeconds: durationSeconds,
		Reason:          reason,
	}
	response, err := client.SetUserHoldWithResponse(ctx, generated.UserKey(userKey), body)
	if err != nil {
		return app.requestError("users hold set", err)
	}

	return app.handleSetUserHoldResponse(response)
}

// runUsersHoldClear removes one user's placement hold.
func (app application) runUsersHoldClear(args []string) int {
	line, err := parseCommandLine(args, []commandFlag{valueFlag("reason")})
	if err != nil {
		return app.usageError("%v", err)
	}
	userKey, code := app.userKeyFromLine(line, "users hold clear")
	if code != 0 {
		return code
	}

	reason, ok := requiredValue(line, "reason")
	if !ok {
		return app.usageError("users hold clear requires --reason")
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	response, err := client.ClearUserHoldWithResponse(
		ctx,
		generated.UserKey(userKey),
		generated.ClearUserHoldJSONRequestBody{Reason: reason},
	)
	if err != nil {
		return app.requestError("users hold clear", err)
	}

	return app.handleClearUserHoldResponse(response)
}

// userKeyArg parses one non-empty user key.
func (app application) userKeyArg(args []string, operation string) (string, int) {
	line, err := parseCommandLine(args, nil)
	if err != nil {
		return "", app.usageError("%v", err)
	}

	return app.userKeyFromLine(line, operation)
}

// userKeyFromLine returns the single non-empty user key from a parsed command.
func (app application) userKeyFromLine(line parsedCommandLine, operation string) (string, int) {
	if len(line.positionals) != 1 {
		return "", app.usageError("%s requires exactly one user key", operation)
	}

	userKey := strings.TrimSpace(line.positionals[0])
	if userKey == "" {
		return "", app.usageError("%s requires a non-empty user key", operation)
	}

	return userKey, 0
}

// runUsersMove changes future user placement according to the selected strategy.
func (app application) runUsersMove(args []string) int {
	line, err := parseCommandLine(args, []commandFlag{
		valueFlag("to-shard"),
		valueFlag("strategy"),
		valueFlag("reason"),
	})
	if err != nil {
		return app.usageError("%v", err)
	}
	if len(line.positionals) != 1 {
		return app.usageError("users move requires exactly one user key")
	}

	reason, ok := requiredValue(line, "reason")
	if !ok {
		return app.usageError("users move requires --reason")
	}
	toShard, ok := requiredValue(line, "to-shard")
	if !ok {
		return app.usageError("users move requires --to-shard")
	}
	strategy := generated.UserMoveRequestStrategy(line.value("strategy"))
	if !strategy.Valid() {
		return app.usageError("move strategy must be new_sessions_only, kick_existing or drain_existing")
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	body := generated.MoveUserJSONRequestBody{
		Reason:   reason,
		Strategy: strategy,
		ToShard:  toShard,
	}
	response, err := client.MoveUserWithResponse(ctx, line.positionals[0], body)
	if err != nil {
		return app.requestError("users move", err)
	}

	return app.handleMoveUserResponse(response)
}

// runUsersKick terminates active sessions for one user.
func (app application) runUsersKick(args []string) int {
	line, err := parseCommandLine(args, []commandFlag{valueFlag("reason")})
	if err != nil {
		return app.usageError("%v", err)
	}
	if len(line.positionals) != 1 {
		return app.usageError("users kick requires exactly one user key")
	}

	reason, ok := requiredValue(line, "reason")
	if !ok {
		return app.usageError("users kick requires --reason")
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	response, err := client.KickUserWithResponse(ctx, line.positionals[0], generated.KickUserJSONRequestBody{Reason: reason})
	if err != nil {
		return app.requestError("users kick", err)
	}

	return app.handleKickUserResponse(response)
}

// runRuntime dispatches runtime aggregate diagnostic commands.
func (app application) runRuntime(args []string) int {
	if len(args) == 0 {
		return app.usageError("runtime requires a subcommand")
	}

	switch args[0] {
	case "summary":
		return app.runRuntimeSummary(args[1:])
	default:
		return app.usageError("unknown runtime subcommand %q", args[0])
	}
}

// runRuntimeSummary prints repairable aggregate runtime totals.
func (app application) runRuntimeSummary(args []string) int {
	line, err := parseCommandLine(args, nil)
	if err != nil {
		return app.usageError("%v", err)
	}
	if len(line.positionals) != 0 {
		return app.usageError("runtime summary does not accept positional arguments")
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	response, err := client.GetRuntimeSummaryWithResponse(ctx)
	if err != nil {
		return app.requestError("runtime summary", err)
	}
	if response.StatusCode() != http.StatusOK {
		return app.serverError("runtime summary", response.StatusCode(), response.JSONDefault)
	}
	if response.JSON200 == nil {
		return app.serverError("runtime summary", http.StatusBadGateway, nil)
	}

	return app.writeRuntimeSummary(response.JSON200)
}

// runRoute dispatches route diagnostic commands.
func (app application) runRoute(args []string) int {
	if len(args) == 0 {
		return app.usageError("route requires a subcommand")
	}
	if args[0] != "lookup" {
		return app.usageError("unknown route subcommand %q", args[0])
	}

	return app.runRouteLookup(args[1:])
}

// runRouteLookup asks the Director for a side-effect-free routing decision.
func (app application) runRouteLookup(args []string) int {
	line, err := parseCommandLine(args, []commandFlag{
		valueFlag("protocol"),
		valueFlag("user"),
		valueFlag("recipient"),
		valueFlag("tenant"),
		valueFlag("listener"),
		valueFlag("service-name"),
		valueFlag("backend-pool"),
		valueFlag("client-ip"),
		valueFlag("attribute"),
		boolFlag("include-affinity"),
	})
	if err != nil {
		return app.usageError("%v", err)
	}
	if len(line.positionals) != 0 {
		return app.usageError("route lookup does not accept positional arguments")
	}

	protocol, ok := requiredValue(line, "protocol")
	if !ok {
		return app.usageError("route lookup requires --protocol")
	}
	userKey := line.value("user")
	recipient := line.value("recipient")
	if userKey == "" && recipient == "" {
		return app.usageError("route lookup requires --user or --recipient")
	}

	attributes, err := parseRouteAttributes(line.all("attribute"))
	if err != nil {
		return app.usageError("%v", err)
	}

	body := generated.LookupRouteJSONRequestBody{
		Attributes: attributes,
		Protocol:   protocol,
	}
	if userKey != "" {
		body.UserKey = &userKey
	}
	if recipient != "" {
		body.Recipient = &recipient
	}
	if tenant := line.value("tenant"); tenant != "" {
		body.Tenant = &tenant
	}
	if listener := line.value("listener"); listener != "" {
		body.Listener = &listener
	}
	if serviceName := line.value("service-name"); serviceName != "" {
		body.ServiceName = &serviceName
	}
	if backendPool := line.value("backend-pool"); backendPool != "" {
		body.BackendPool = &backendPool
	}
	if clientIP := line.value("client-ip"); clientIP != "" {
		body.ClientIP = &clientIP
	}
	if line.bool("include-affinity") {
		includeAffinity := true
		body.IncludeAffinity = &includeAffinity
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	response, err := client.LookupRouteWithResponse(ctx, body)
	if err != nil {
		return app.requestError("route lookup", err)
	}
	if response.StatusCode() != http.StatusOK {
		return app.serverError("route lookup", response.StatusCode(), firstProblem(response.JSON400, response.JSONDefault))
	}
	if response.JSON200 == nil {
		return app.serverError("route lookup", http.StatusBadGateway, nil)
	}

	return app.writeObject(response.JSON200, func(writer io.Writer) error {
		writeRouteLine(writer, *response.JSON200)
		return nil
	})
}

// runReload requests a safe runtime reload from the Director.
func (app application) runReload(args []string) int {
	line, err := parseCommandLine(args, nil)
	if err != nil {
		return app.usageError("%v", err)
	}
	if len(line.positionals) != 0 {
		return app.usageError("reload does not accept positional arguments")
	}

	ctx, cancel := context.WithTimeout(context.Background(), app.options.Timeout)
	defer cancel()

	client, code := app.client()
	if code != 0 {
		return code
	}

	response, err := client.ReloadWithResponse(ctx)
	if err != nil {
		return app.requestError("reload", err)
	}

	return app.handleReloadResponse(response)
}

// handleDisableBackendMaintenanceResponse renders a maintenance disable response.
func (app application) handleDisableBackendMaintenanceResponse(response *generated.DisableBackendMaintenanceResponse) int {
	if response.StatusCode() != http.StatusAccepted {
		return app.serverError("backends maintenance disable", response.StatusCode(), response.JSONDefault)
	}
	return app.writeAccepted(response.JSON202)
}

// handleEnableBackendMaintenanceResponse renders a maintenance enable response.
func (app application) handleEnableBackendMaintenanceResponse(response *generated.EnableBackendMaintenanceResponse) int {
	if response.StatusCode() != http.StatusAccepted {
		return app.serverError("backends maintenance enable", response.StatusCode(), response.JSONDefault)
	}
	return app.writeAccepted(response.JSON202)
}

// handleClearBackendRuntimeResponse renders a backend runtime clear response.
func (app application) handleClearBackendRuntimeResponse(response *generated.ClearBackendRuntimeResponse) int {
	if response.StatusCode() != http.StatusAccepted {
		return app.serverError("backends runtime clear", response.StatusCode(), response.JSONDefault)
	}
	return app.writeAccepted(response.JSON202)
}

// handleDrainBackendResponse renders a backend drain response.
func (app application) handleDrainBackendResponse(response *generated.DrainBackendResponse) int {
	if response.StatusCode() != http.StatusAccepted {
		return app.serverError("backends drain", response.StatusCode(), response.JSONDefault)
	}
	return app.writeAccepted(response.JSON202)
}

// handleDrainListenerResponse renders an updated listener after drain.
func (app application) handleDrainListenerResponse(response *generated.DrainListenerResponse) int {
	if response.StatusCode() != http.StatusAccepted {
		return app.serverError("listeners drain", response.StatusCode(), response.JSONDefault)
	}
	if response.JSON202 == nil {
		return app.serverError("listeners drain", http.StatusBadGateway, nil)
	}

	return app.writeObject(response.JSON202, func(writer io.Writer) error {
		writeListenerLine(writer, *response.JSON202)
		return nil
	})
}

// handleResumeListenerResponse renders an updated listener after resume.
func (app application) handleResumeListenerResponse(response *generated.ResumeListenerResponse) int {
	if response.StatusCode() != http.StatusAccepted {
		return app.serverError("listeners resume", response.StatusCode(), response.JSONDefault)
	}
	if response.JSON202 == nil {
		return app.serverError("listeners resume", http.StatusBadGateway, nil)
	}

	return app.writeObject(response.JSON202, func(writer io.Writer) error {
		writeListenerLine(writer, *response.JSON202)
		return nil
	})
}

// handleMarkBackendInResponse renders a backend in-service response.
func (app application) handleMarkBackendInResponse(response *generated.MarkBackendInResponse) int {
	if response.StatusCode() != http.StatusAccepted {
		return app.serverError("backends in", response.StatusCode(), response.JSONDefault)
	}
	return app.writeAccepted(response.JSON202)
}

// handleMarkBackendOutResponse renders a backend out-of-service response.
func (app application) handleMarkBackendOutResponse(response *generated.MarkBackendOutResponse) int {
	if response.StatusCode() != http.StatusAccepted {
		return app.serverError("backends out", response.StatusCode(), response.JSONDefault)
	}
	return app.writeAccepted(response.JSON202)
}

// handleSetBackendWeightResponse renders a backend weight override response.
func (app application) handleSetBackendWeightResponse(response *generated.SetBackendWeightResponse) int {
	if response.StatusCode() != http.StatusAccepted {
		return app.serverError("backends weight", response.StatusCode(), response.JSONDefault)
	}
	return app.writeAccepted(response.JSON202)
}

// handleDeleteSessionResponse renders a session termination response.
func (app application) handleDeleteSessionResponse(response *generated.DeleteSessionResponse) int {
	if response.StatusCode() != http.StatusAccepted {
		return app.serverError("sessions kill", response.StatusCode(), response.JSONDefault)
	}
	return app.writeAccepted(response.JSON202)
}

// handleClearUserAffinityResponse renders an affinity clear response.
func (app application) handleClearUserAffinityResponse(response *generated.ClearUserAffinityResponse) int {
	if response.StatusCode() != http.StatusAccepted {
		return app.serverError("users affinity clear", response.StatusCode(), response.JSONDefault)
	}
	return app.writeAccepted(response.JSON202)
}

// handleSetUserAffinityResponse renders an affinity set response.
func (app application) handleSetUserAffinityResponse(response *generated.SetUserAffinityResponse) int {
	if response.StatusCode() != http.StatusAccepted {
		return app.serverError("users affinity set", response.StatusCode(), response.JSONDefault)
	}
	return app.writeAccepted(response.JSON202)
}

// handleClearUserBackendPinResponse renders a backend-pin clear response.
func (app application) handleClearUserBackendPinResponse(response *generated.ClearUserBackendPinResponse) int {
	if response.StatusCode() != http.StatusAccepted {
		return app.serverError("users backend-pin clear", response.StatusCode(), response.JSONDefault)
	}
	return app.writeAccepted(response.JSON202)
}

// handleSetUserBackendPinResponse renders a backend-pin set response.
func (app application) handleSetUserBackendPinResponse(response *generated.SetUserBackendPinResponse) int {
	if response.StatusCode() != http.StatusAccepted {
		return app.serverError("users backend-pin set", response.StatusCode(), response.JSONDefault)
	}
	return app.writeAccepted(response.JSON202)
}

// handleClearUserHoldResponse renders a placement-hold clear response.
func (app application) handleClearUserHoldResponse(response *generated.ClearUserHoldResponse) int {
	if response.StatusCode() != http.StatusAccepted {
		return app.serverError("users hold clear", response.StatusCode(), response.JSONDefault)
	}
	return app.writeAccepted(response.JSON202)
}

// handleSetUserHoldResponse renders a placement-hold set response.
func (app application) handleSetUserHoldResponse(response *generated.SetUserHoldResponse) int {
	if response.StatusCode() != http.StatusAccepted {
		return app.serverError("users hold set", response.StatusCode(), response.JSONDefault)
	}
	return app.writeAccepted(response.JSON202)
}

// handleKickUserResponse renders a user kick response.
func (app application) handleKickUserResponse(response *generated.KickUserResponse) int {
	if response.StatusCode() != http.StatusAccepted {
		return app.serverError("users kick", response.StatusCode(), response.JSONDefault)
	}
	return app.writeAccepted(response.JSON202)
}

// handleMoveUserResponse renders a user move response.
func (app application) handleMoveUserResponse(response *generated.MoveUserResponse) int {
	if response.StatusCode() != http.StatusAccepted {
		return app.serverError("users move", response.StatusCode(), response.JSONDefault)
	}
	return app.writeAccepted(response.JSON202)
}

// handleReloadResponse renders a reload response.
func (app application) handleReloadResponse(response *generated.ReloadResponse) int {
	if response.StatusCode() != http.StatusAccepted {
		return app.serverError("reload", response.StatusCode(), response.JSONDefault)
	}
	return app.writeAccepted(response.JSON202)
}

// writeAccepted writes a stable accepted response in the requested output mode.
func (app application) writeAccepted(response *generated.AcceptedResponse) int {
	if response == nil {
		return app.serverError("mutation", http.StatusBadGateway, nil)
	}

	return app.writeObject(response, func(writer io.Writer) error {
		_, err := fmt.Fprintf(writer, "status=%s\n", response.Status)
		return err
	})
}

// writeObject renders a generated response object in text or JSON mode.
func (app application) writeObject(value any, writeText func(io.Writer) error) int {
	if app.options.Output == outputJSON {
		return app.writeJSON(value)
	}
	if err := writeText(app.stdout); err != nil {
		_, _ = fmt.Fprintf(app.stderr, "write failed: %v\n", err)
		return 1
	}

	return 0
}

// writeSessionList renders a session page and advertises continuation cursors.
func (app application) writeSessionList(response *generated.SessionListResponse) int {
	sort.Slice(response.Sessions, func(left int, right int) bool {
		return response.Sessions[left].SessionID < response.Sessions[right].SessionID
	})

	return app.writeObject(response, func(writer io.Writer) error {
		for _, session := range response.Sessions {
			writeSessionLine(writer, session)
		}
		writeNextCursorLine(writer, response.NextCursor)

		return nil
	})
}

// writeUserList renders a user page and advertises continuation cursors.
func (app application) writeUserList(response *generated.UserListResponse) int {
	sort.Slice(response.Users, func(left int, right int) bool {
		return response.Users[left].UserKey < response.Users[right].UserKey
	})

	return app.writeObject(response, func(writer io.Writer) error {
		for _, user := range response.Users {
			writeUserLine(writer, user)
		}
		writeNextCursorLine(writer, response.NextCursor)

		return nil
	})
}

// writeRuntimeSummary renders repairable aggregate runtime totals.
func (app application) writeRuntimeSummary(response *generated.RuntimeSummaryResponse) int {
	return app.writeObject(response, func(writer io.Writer) error {
		_, _ = fmt.Fprintf(
			writer,
			"routing_authority=%t active_sessions=%d active_accuracy=%s idle_affinities=%d idle_accuracy=%s\n",
			response.RoutingAuthority,
			response.ActiveSessions.Total.Count,
			response.ActiveSessions.Total.Accuracy,
			response.IdleAffinities.Count,
			response.IdleAffinities.Accuracy,
		)
		writeRuntimeDimensionCounts(writer, "active_sessions_by_protocol", "protocol", response.ActiveSessions.ByProtocol)
		writeRuntimeDimensionCounts(writer, "active_sessions_by_listener", "listener", response.ActiveSessions.ByListener)
		writeRuntimeDimensionCounts(writer, "active_sessions_by_service", "service", response.ActiveSessions.ByService)
		writeRuntimeDimensionCounts(writer, "active_sessions_by_shard", "shard_tag", response.ActiveSessions.ByShardTag)
		for _, backend := range response.BackendCapacity {
			_, _ = fmt.Fprintf(
				writer,
				"backend_capacity backend=%s active_sessions=%d active_accuracy=%s reserved_sessions=%d reserved_accuracy=%s repairable=%t routing_authority=%t\n",
				backend.Backend,
				backend.ActiveSessions.Count,
				backend.ActiveSessions.Accuracy,
				backend.ReservedSessions.Count,
				backend.ReservedSessions.Accuracy,
				backend.SummaryRepairable,
				backend.RoutingAuthority,
			)
		}
		_, _ = fmt.Fprintf(
			writer,
			"repairs expired_sessions=%d stale_index_entries=%d backend_reservations=%d accuracy=%s\n",
			response.Repairs.ExpiredSessions.Count,
			response.Repairs.StaleIndexEntries.Count,
			response.Repairs.BackendReservations.Count,
			response.Repairs.ExpiredSessions.Accuracy,
		)

		return nil
	})
}

// writeRuntimeDimensionCounts renders one aggregate dimension list.
func writeRuntimeDimensionCounts(writer io.Writer, prefix string, key string, counts []generated.RuntimeDimensionCount) {
	for _, count := range counts {
		_, _ = fmt.Fprintf(writer, "%s %s=%s count=%d accuracy=%s\n", prefix, key, count.Value, count.Count, count.Accuracy)
	}
}

// writeJSON renders stable indented JSON.
func (app application) writeJSON(value any) int {
	encoder := json.NewEncoder(app.stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		_, _ = fmt.Fprintf(app.stderr, "write failed: %v\n", err)
		return 1
	}

	return 0
}

// writeConfigDocument prints only the requested config document content.
func (app application) writeConfigDocument(document *generated.ConfigDocument, format string) int {
	switch generated.ConfigDocumentFormat(format) {
	case generated.ConfigDocumentFormatJSON:
		return app.writeJSON(document.Data)
	case generated.ConfigDocumentFormatYaml:
		output, err := yaml.Marshal(document.Data)
		if err != nil {
			_, _ = fmt.Fprintf(app.stderr, "config dump failed: %v\n", err)
			return 1
		}
		if _, err := app.stdout.Write(output); err != nil {
			_, _ = fmt.Fprintf(app.stderr, "write failed: %v\n", err)
			return 1
		}
		return 0
	default:
		return app.usageError("config dump format must be yaml or json")
	}
}

// usageError reports a local command-line or configuration error.
func (app application) usageError(format string, args ...any) int {
	_, _ = fmt.Fprintf(app.stderr, format+"\n", args...)
	return 2
}

// requestError reports a failed generated-client request.
func (app application) requestError(operation string, err error) int {
	_, _ = fmt.Fprintf(app.stderr, "%s failed: %v\n", operation, err)
	return 1
}

// cursorLoopError reports a repeated server cursor without looping forever.
func (app application) cursorLoopError(operation string) int {
	_, _ = fmt.Fprintf(app.stderr, "%s failed: repeated pagination cursor\n", operation)
	return 1
}

// serverError reports an operation failure returned by the Director.
func (app application) serverError(operation string, status int, problem *generated.ErrorResponse) int {
	message := http.StatusText(status)
	if problem != nil && strings.TrimSpace(problem.Message) != "" {
		message = problem.Message
	}
	if message == "" {
		message = "unexpected response"
	}

	_, _ = fmt.Fprintf(app.stderr, "%s failed: HTTP %d: %s\n", operation, status, message)
	return 1
}

// configDumpServerError reports remote config failures without printing partial config data.
func (app application) configDumpServerError(status int, problem *generated.ErrorResponse, protected bool) int {
	if protected && status == http.StatusForbidden {
		_, _ = fmt.Fprintln(app.stderr, "config dump failed: protected config output is forbidden (HTTP 403)")
		return 1
	}

	return app.serverError("config dump", status, problem)
}

// newGeneratedControlClient creates the OpenAPI-generated client-with-responses SDK.
func newGeneratedControlClient(address string, timeout time.Duration) (generated.ClientWithResponsesInterface, error) {
	baseURL, err := normalizeAddress(address)
	if err != nil {
		return nil, err
	}

	return generated.NewClientWithResponses(baseURL, generated.WithHTTPClient(&http.Client{Timeout: timeout}))
}

// normalizeAddress returns a generated-client-compatible base URL.
func normalizeAddress(address string) (string, error) {
	trimmed := strings.TrimSpace(address)
	if trimmed == "" {
		trimmed = defaultControlAddress
	}

	if !strings.Contains(trimmed, "://") {
		trimmed = "http://" + trimmed
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid control API address: %w", err)
	}

	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("invalid control API address %q", address)
	}

	return strings.TrimRight(parsed.String(), "/"), nil
}

// parseCommandLine parses command-local flags even when they follow positionals.
func parseCommandLine(args []string, definitions []commandFlag) (parsedCommandLine, error) {
	line := parsedCommandLine{
		values: make(map[string][]string),
		bools:  make(map[string]bool),
	}
	lookup := make(map[string]commandFlag)
	for _, definition := range definitions {
		lookup[definition.name] = definition
		for _, alias := range definition.aliases {
			lookup[alias] = definition
		}
	}

	for index := 0; index < len(args); index++ {
		arg := args[index]
		if arg == "--" {
			line.positionals = append(line.positionals, args[index+1:]...)
			break
		}
		if strings.HasPrefix(arg, "--") && len(arg) > 2 {
			var err error
			index, err = parseCommandFlag(args, index, strings.TrimPrefix(arg, "--"), lookup, &line)
			if err != nil {
				return parsedCommandLine{}, err
			}
			continue
		}
		if strings.HasPrefix(arg, "-") && len(arg) > 1 {
			var err error
			index, err = parseCommandFlag(args, index, strings.TrimPrefix(arg, "-"), lookup, &line)
			if err != nil {
				return parsedCommandLine{}, err
			}
			continue
		}

		line.positionals = append(line.positionals, arg)
	}

	return line, nil
}

// parseCommandFlag parses one flag token and returns the next consumed index.
func parseCommandFlag(args []string, index int, token string, lookup map[string]commandFlag, line *parsedCommandLine) (int, error) {
	name, value, hasValue := strings.Cut(token, "=")
	definition, ok := lookup[name]
	if !ok {
		return index, fmt.Errorf("unknown flag --%s", name)
	}

	switch definition.kind {
	case commandFlagBool:
		if hasValue {
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				return index, fmt.Errorf("flag --%s expects a boolean value", name)
			}
			line.bools[definition.name] = parsed
			return index, nil
		}
		line.bools[definition.name] = true
		return index, nil
	case commandFlagValue:
		if !hasValue {
			index++
			if index >= len(args) {
				return index, fmt.Errorf("flag --%s requires a value", name)
			}
			value = args[index]
		}
		line.values[definition.name] = append(line.values[definition.name], value)
		return index, nil
	default:
		return index, fmt.Errorf("flag --%s is invalid", name)
	}
}

// bool returns true when the named boolean flag was set.
func (line parsedCommandLine) bool(name string) bool {
	return line.bools[name]
}

// value returns the last value for a command-local flag.
func (line parsedCommandLine) value(name string) string {
	values := line.values[name]
	if len(values) == 0 {
		return ""
	}

	return values[len(values)-1]
}

// all returns all values for a repeatable command-local flag.
func (line parsedCommandLine) all(name string) []string {
	return line.values[name]
}

// boolFlag describes a boolean command-local flag.
func boolFlag(name string, aliases ...string) commandFlag {
	return commandFlag{name: name, aliases: aliases, kind: commandFlagBool}
}

// valueFlag describes a value-bearing command-local flag.
func valueFlag(name string, aliases ...string) commandFlag {
	return commandFlag{name: name, aliases: aliases, kind: commandFlagValue}
}

// requiredValue returns a non-empty trimmed flag value.
func requiredValue(line parsedCommandLine, name string) (string, bool) {
	value := strings.TrimSpace(line.value(name))
	if value == "" {
		return "", false
	}

	return value, true
}

// optionalNonNegativeInt returns a non-negative integer flag when set.
func optionalNonNegativeInt(line parsedCommandLine, name string) (*int, error) {
	values := line.all(name)
	if len(values) == 0 {
		return nil, nil
	}

	value := strings.TrimSpace(values[len(values)-1])
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return nil, fmt.Errorf("flag --%s must be a non-negative integer", name)
	}

	return &parsed, nil
}

// optionalPositiveInt returns a positive integer flag when set.
func optionalPositiveInt(line parsedCommandLine, name string) (*int, error) {
	values := line.all(name)
	if len(values) == 0 {
		return nil, nil
	}

	value := strings.TrimSpace(values[len(values)-1])
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return nil, fmt.Errorf("flag --%s must be a positive integer", name)
	}

	return &parsed, nil
}

// parseHoldDurationSeconds converts a Go duration into whole REST seconds.
func parseHoldDurationSeconds(value string) (int, error) {
	duration, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("users hold set requires a valid Go duration for --duration")
	}
	if duration <= 0 {
		return 0, fmt.Errorf("users hold set requires a positive --duration")
	}
	if duration%time.Second != 0 {
		return 0, fmt.Errorf("users hold set requires --duration to use whole seconds")
	}

	seconds := int64(duration / time.Second)
	maxInt := int64(^uint(0) >> 1)
	if seconds > maxInt {
		return 0, fmt.Errorf("users hold set --duration is too large")
	}

	return int(seconds), nil
}

// parseRouteAttributes converts repeated k=v flags to the generated request shape.
func parseRouteAttributes(values []string) (*map[string][]string, error) {
	if len(values) == 0 {
		return nil, nil
	}

	attributes := make(map[string][]string)
	for _, raw := range values {
		key, value, ok := strings.Cut(raw, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			return nil, fmt.Errorf("route lookup attributes must use k=v syntax")
		}
		if credentialBearingName(key) {
			return nil, fmt.Errorf("route lookup does not accept credential-bearing attributes")
		}
		attributes[key] = append(attributes[key], value)
	}

	return &attributes, nil
}

// credentialBearingName reports whether a route attribute name could carry secrets.
func credentialBearingName(name string) bool {
	lower := strings.ToLower(name)
	for _, marker := range []string{"password", "passwd", "secret", "token", "bearer", "credential", "sasl", "oauth"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}

	return false
}

// firstProblem returns the first non-nil generated error response.
func firstProblem(problems ...*generated.ErrorResponse) *generated.ErrorResponse {
	for _, problem := range problems {
		if problem != nil {
			return problem
		}
	}

	return nil
}

// writeBackendLine writes one scriptable backend text row.
func writeBackendLine(writer io.Writer, backend generated.BackendDetail) {
	weight := ""
	if backend.Runtime.Weight != nil {
		weight = strconv.Itoa(*backend.Runtime.Weight)
	}
	_, _ = fmt.Fprintf(
		writer,
		"identifier=%s protocol=%s backend_pool=%s shard_tag=%s in_service=%t draining=%t maintenance=%s weight=%s\n",
		fieldValue(backend.Identifier),
		fieldValue(backend.Protocol),
		fieldValue(backend.BackendPool),
		fieldValue(backend.ShardTag),
		backend.Runtime.InService,
		backend.Runtime.Draining,
		fieldValue(string(backend.Runtime.Maintenance)),
		fieldValue(weight),
	)
}

// writeListenerLine writes one scriptable listener text row.
func writeListenerLine(writer io.Writer, listener generated.ListenerDetail) {
	boundAddress := ""
	if listener.BoundAddress != nil {
		boundAddress = *listener.BoundAddress
	}
	drainMode := ""
	if listener.DrainMode != nil {
		drainMode = string(*listener.DrainMode)
	}

	_, _ = fmt.Fprintf(
		writer,
		"name=%s protocol=%s service_name=%s network=%s configured_address=%s bound_address=%s state=%s active_local_sessions=%d drain_mode=%s\n",
		fieldValue(listener.Name),
		fieldValue(listener.Protocol),
		fieldValue(listener.ServiceName),
		fieldValue(listener.Network),
		fieldValue(listener.Address),
		fieldValue(boundAddress),
		fieldValue(string(listener.State)),
		listener.ActiveLocalSessions,
		fieldValue(drainMode),
	)
}

// writeSessionLine writes one scriptable session text row.
func writeSessionLine(writer io.Writer, session generated.SessionDetail) {
	_, _ = fmt.Fprintf(
		writer,
		"session_id=%s user_key=%s protocol=%s backend=%s shard_tag=%s expires_at=%s\n",
		fieldValue(session.SessionID),
		fieldValue(session.UserKey),
		fieldValue(session.Protocol),
		fieldValue(session.Backend),
		fieldValue(session.ShardTag),
		fieldValue(session.ExpiresAt.UTC().Format(time.RFC3339)),
	)
}

// writeUserLine writes one scriptable user text row.
func writeUserLine(writer io.Writer, user generated.UserDetail) {
	affinityShard := ""
	if user.Affinity != nil {
		affinityShard = user.Affinity.ShardTag
	}
	_, _ = fmt.Fprintf(
		writer,
		"user_key=%s active_sessions=%d affinity_shard=%s\n",
		fieldValue(user.UserKey),
		user.ActiveSessions,
		fieldValue(affinityShard),
	)
}

// writeBackendPinLine writes one scriptable backend-pin text row.
func writeBackendPinLine(writer io.Writer, pin generated.UserBackendPin) {
	backend := stringPointerValue(pin.Backend)
	protocol := stringPointerValue(pin.Protocol)
	backendPool := stringPointerValue(pin.BackendPool)
	shardTag := stringPointerValue(pin.ShardTag)
	strategy := ""
	if pin.Strategy != nil {
		strategy = string(*pin.Strategy)
	}
	generation := stringPointerValue(pin.Generation)
	activeSessionCount := ""
	if pin.ActiveSessionCount != nil {
		activeSessionCount = strconv.Itoa(*pin.ActiveSessionCount)
	}

	_, _ = fmt.Fprintf(
		writer,
		"user_key=%s present=%t backend=%s protocol=%s backend_pool=%s shard_tag=%s strategy=%s generation=%s active_session_count=%s\n",
		fieldValue(pin.UserKey),
		pin.Present,
		fieldValue(backend),
		fieldValue(protocol),
		fieldValue(backendPool),
		fieldValue(shardTag),
		fieldValue(strategy),
		fieldValue(generation),
		fieldValue(activeSessionCount),
	)
}

// writeUserHoldLine writes one scriptable placement-hold text row.
func writeUserHoldLine(writer io.Writer, hold generated.UserHold) {
	createdAt := timePointerValue(hold.CreatedAt)
	expiresAt := timePointerValue(hold.ExpiresAt)
	generation := stringPointerValue(hold.Generation)
	remainingSeconds := ""
	if hold.RemainingSeconds != nil {
		remainingSeconds = strconv.Itoa(*hold.RemainingSeconds)
	}

	_, _ = fmt.Fprintf(
		writer,
		"user_key=%s present=%t created_at=%s expires_at=%s remaining_seconds=%s generation=%s\n",
		fieldValue(hold.UserKey),
		hold.Present,
		fieldValue(createdAt),
		fieldValue(expiresAt),
		fieldValue(remainingSeconds),
		fieldValue(generation),
	)
}

// stringPointerValue returns the pointed string or an empty value.
func stringPointerValue(value *string) string {
	if value == nil {
		return ""
	}

	return *value
}

// timePointerValue returns an RFC3339 timestamp for present generated times.
func timePointerValue(value *time.Time) string {
	if value == nil {
		return ""
	}

	return value.UTC().Format(time.RFC3339)
}

// writeNextCursorLine writes the explicit continuation hint for partial pages.
func writeNextCursorLine(writer io.Writer, nextCursor *string) {
	if nextCursor == nil || strings.TrimSpace(*nextCursor) == "" {
		return
	}

	_, _ = fmt.Fprintf(writer, "more=true next_cursor=%s\n", fieldValue(strings.TrimSpace(*nextCursor)))
}

// writeAffinityLine writes one scriptable affinity text row.
func writeAffinityLine(writer io.Writer, affinity generated.UserAffinity) {
	generation := ""
	if affinity.Generation != nil {
		generation = *affinity.Generation
	}
	expiresAt := ""
	if affinity.ExpiresAt != nil {
		expiresAt = affinity.ExpiresAt.UTC().Format(time.RFC3339)
	}
	_, _ = fmt.Fprintf(
		writer,
		"user_key=%s shard_tag=%s active_sessions=%d generation=%s expires_at=%s\n",
		fieldValue(affinity.UserKey),
		fieldValue(affinity.ShardTag),
		affinity.ActiveSessions,
		fieldValue(generation),
		fieldValue(expiresAt),
	)
}

// writeRouteLine writes one scriptable route lookup text row.
func writeRouteLine(writer io.Writer, route generated.RouteLookupResponse) {
	generation := ""
	if route.RoutingGeneration != nil {
		generation = *route.RoutingGeneration
	}
	_, _ = fmt.Fprintf(
		writer,
		"selected_backend=%s shard_tag=%s routing_source=%s healthy=%t maintenance=%t fail_closed=%t affected_health=%t affected_maintenance=%t affected_runtime=%t affected_max_connections=%t affected_user_hold=%t reason=%s routing_generation=%s",
		fieldValue(route.SelectedBackend),
		fieldValue(route.ShardTag),
		fieldValue(route.Routing.Source),
		route.Healthy,
		route.Maintenance,
		route.FailClosed,
		route.AffectedBy.Health,
		route.AffectedBy.Maintenance,
		route.AffectedBy.RuntimeOverride,
		route.AffectedBy.MaxConnections,
		route.AffectedBy.UserHold,
		fieldValue(route.Reason),
		fieldValue(generation),
	)
	if route.IdentityResolution != nil {
		_, _ = fmt.Fprintf(
			writer,
			" identity_source=%s identity_authoritative=%t identity_nauthilus=%t identity_account_resolved=%t",
			fieldValue(route.IdentityResolution.Source),
			route.IdentityResolution.Authoritative,
			route.IdentityResolution.NauthilusUsed,
			route.IdentityResolution.AccountResolved,
		)
	}
	if route.Affinity != nil {
		shardTag := ""
		if route.Affinity.ShardTag != nil {
			shardTag = *route.Affinity.ShardTag
		}
		_, _ = fmt.Fprintf(
			writer,
			" affinity_present=%t affinity_active=%t affinity_shard=%s affinity_sessions=%d",
			route.Affinity.Present,
			route.Affinity.Active,
			fieldValue(shardTag),
			route.Affinity.ActiveSessions,
		)
	}
	pinBackend := stringPointerValue(route.BackendPin.Backend)
	pinProtocol := stringPointerValue(route.BackendPin.Protocol)
	pinPool := stringPointerValue(route.BackendPin.BackendPool)
	pinShard := stringPointerValue(route.BackendPin.ShardTag)
	_, _ = fmt.Fprintf(
		writer,
		" backend_pin_present=%t backend_pin_applied=%t backend_pin_backend=%s backend_pin_protocol=%s backend_pin_pool=%s backend_pin_shard=%s backend_pin_reason=%s",
		route.BackendPin.Present,
		route.BackendPin.Applied,
		fieldValue(pinBackend),
		fieldValue(pinProtocol),
		fieldValue(pinPool),
		fieldValue(pinShard),
		fieldValue(route.BackendPin.Reason),
	)
	holdExpiresAt := timePointerValue(route.UserHold.ExpiresAt)
	holdGeneration := stringPointerValue(route.UserHold.Generation)
	holdRemainingSeconds := ""
	if route.UserHold.RemainingSeconds != nil {
		holdRemainingSeconds = strconv.Itoa(*route.UserHold.RemainingSeconds)
	}
	_, _ = fmt.Fprintf(
		writer,
		" user_hold_present=%t user_hold_deferred=%t user_hold_expires_at=%s user_hold_remaining_seconds=%s user_hold_reason=%s user_hold_generation=%s",
		route.UserHold.Present,
		route.UserHold.PlacementDeferred,
		fieldValue(holdExpiresAt),
		fieldValue(holdRemainingSeconds),
		fieldValue(route.UserHold.Reason),
		fieldValue(holdGeneration),
	)
	_, _ = fmt.Fprintln(writer)
}

// fieldValue quotes text values only when needed for scriptable key-value output.
func fieldValue(value string) string {
	if value == "" || strings.ContainsAny(value, " \t\r\n=") {
		return strconv.Quote(value)
	}

	return value
}
