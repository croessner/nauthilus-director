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
//nolint:dupl,funlen,goconst,gocyclo,wsl_v5 // The CLI keeps generated-client command paths explicit and dependency-free.
package main

import (
	"context"
	"encoding/json"
	"flag"
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

// main delegates to run so command behavior stays testable at the binary boundary.
func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run parses global flags and dispatches supported operator commands.
func run(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("nauthilus-directorctl", flag.ContinueOnError)
	flags.SetOutput(stderr)

	showVersion := flags.Bool("version", false, "print version and exit")
	address := flags.String("address", defaultControlAddress, "control API base URL")
	timeout := flags.Duration("timeout", defaultTimeout, "control API request timeout")
	output := flags.String("output", string(outputText), "output mode: text or json")
	flags.StringVar(output, "format", string(outputText), "output mode: text or json")

	if err := flags.Parse(args); err != nil {
		return 2
	}

	if *showVersion {
		_, _ = fmt.Fprintf(stdout, "nauthilus-directorctl %s\n", version)
		return 0
	}

	mode, err := parseOutputMode(*output)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}
	if *timeout <= 0 {
		_, _ = fmt.Fprintln(stderr, "timeout must be greater than zero")
		return 2
	}

	app := application{
		options: commandOptions{
			Address: *address,
			Timeout: *timeout,
			Output:  mode,
		},
		stdout: stdout,
		stderr: stderr,
	}

	remaining := flags.Args()
	if len(remaining) == 0 {
		return 0
	}

	return app.dispatch(remaining)
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
		"selected_backend=%s shard_tag=%s routing_source=%s healthy=%t maintenance=%t fail_closed=%t affected_health=%t affected_maintenance=%t affected_runtime=%t affected_max_connections=%t reason=%s routing_generation=%s",
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
	_, _ = fmt.Fprintln(writer)
}

// fieldValue quotes text values only when needed for scriptable key-value output.
func fieldValue(value string) string {
	if value == "" || strings.ContainsAny(value, " \t\r\n=") {
		return strconv.Quote(value)
	}

	return value
}
