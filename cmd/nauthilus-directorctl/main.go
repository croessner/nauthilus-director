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
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/client/generated"
)

var version = "dev"

const (
	defaultControlAddress = "http://127.0.0.1:9090"
	statusCommand         = "status"
)

var newStatusClient = newGeneratedStatusClient

type statusClient interface {
	GetHealthzWithResponse(ctx context.Context, reqEditors ...generated.RequestEditorFn) (*generated.GetHealthzResponse, error)
	GetReadyzWithResponse(ctx context.Context, reqEditors ...generated.RequestEditorFn) (*generated.GetReadyzResponse, error)
	GetVersionWithResponse(ctx context.Context, reqEditors ...generated.RequestEditorFn) (*generated.GetVersionResponse, error)
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

	if err := flags.Parse(args); err != nil {
		return 2
	}

	if *showVersion {
		_, _ = fmt.Fprintf(stdout, "nauthilus-directorctl %s\n", version)
		return 0
	}

	remaining := flags.Args()
	if len(remaining) == 0 {
		return 0
	}

	switch remaining[0] {
	case statusCommand:
		return runStatus(*address, stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command %q\n", remaining[0])
		return 2
	}
}

// runStatus calls read-only generated SDK methods for the control API status.
func runStatus(address string, stdout io.Writer, stderr io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := newStatusClient(address)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "status failed: %v\n", err)
		return 2
	}

	health, err := client.GetHealthzWithResponse(ctx)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "status failed: health request failed: %v\n", err)
		return 1
	}

	if err := requireStatus("healthz", health.StatusCode(), http.StatusOK); err != nil {
		_, _ = fmt.Fprintf(stderr, "status failed: %v\n", err)
		return 1
	}

	ready, err := client.GetReadyzWithResponse(ctx)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "status failed: readiness request failed: %v\n", err)
		return 1
	}

	if err := requireStatus("readyz", ready.StatusCode(), http.StatusOK); err != nil {
		_, _ = fmt.Fprintf(stderr, "status failed: %v\n", err)
		return 1
	}

	versionResponse, err := client.GetVersionWithResponse(ctx)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "status failed: version request failed: %v\n", err)
		return 1
	}

	if err := requireStatus("version", versionResponse.StatusCode(), http.StatusOK); err != nil {
		_, _ = fmt.Fprintf(stderr, "status failed: %v\n", err)
		return 1
	}

	if health.JSON200 == nil || ready.JSON200 == nil || versionResponse.JSON200 == nil {
		_, _ = fmt.Fprintln(stderr, "status failed: control API returned an unexpected response body")
		return 1
	}

	_, _ = fmt.Fprintf(stdout, "health=%s\n", health.JSON200.Status)
	_, _ = fmt.Fprintf(stdout, "ready=%s\n", ready.JSON200.Status)
	_, _ = fmt.Fprintf(stdout, "version=%s\n", versionResponse.JSON200.Version)
	_, _ = fmt.Fprintf(stdout, "api_version=%s\n", versionResponse.JSON200.APIVersion)

	return 0
}

// newGeneratedStatusClient creates the generated status client adapter.
func newGeneratedStatusClient(address string) (statusClient, error) {
	return newGeneratedClient(address)
}

// newGeneratedClient creates the OpenAPI-generated client-with-responses SDK.
func newGeneratedClient(address string) (generated.ClientWithResponsesInterface, error) {
	baseURL, err := normalizeAddress(address)
	if err != nil {
		return nil, err
	}

	return generated.NewClientWithResponses(baseURL)
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

// requireStatus converts unexpected generated-client statuses into operator errors.
func requireStatus(endpoint string, got int, want int) error {
	if got == want {
		return nil
	}

	return fmt.Errorf("%s returned HTTP %d, want %d", endpoint, got, want)
}
