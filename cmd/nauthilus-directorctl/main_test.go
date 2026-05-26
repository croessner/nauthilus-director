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

package main

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/croessner/nauthilus-director/internal/client/generated"
)

const testStatusOK = "ok"

// TestVersionOutput keeps the client version flag stable for operators.
func TestVersionOutput(t *testing.T) {
	previousVersion := version
	version = "test-version"

	t.Cleanup(func() {
		version = previousVersion
	})

	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)

	code := run([]string{"--version"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run returned exit code %d, want 0; stderr=%q", code, stderr.String())
	}

	const want = "nauthilus-directorctl test-version\n"
	if stdout.String() != want {
		t.Fatalf("version output = %q, want %q", stdout.String(), want)
	}
}

// TestStatusCommandUsesGeneratedClient verifies the read-only SDK transport path.
func TestStatusCommandUsesGeneratedClient(t *testing.T) {
	previousClient := newStatusClient
	newStatusClient = func(string) (statusClient, error) {
		return fakeStatusClient{}, nil
	}

	t.Cleanup(func() {
		newStatusClient = previousClient
	})

	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)

	code := run([]string{"--address", "127.0.0.1:9090", "status"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run returned exit code %d, want 0; stderr=%q", code, stderr.String())
	}

	output := stdout.String()
	for _, want := range []string{"health=ok", "ready=ok", "version=test-version", "api_version=v1"} {
		if !strings.Contains(output, want) {
			t.Fatalf("status output = %q, want to contain %q", output, want)
		}
	}
}

// fakeStatusClient returns generated response objects without binding a test port.
type fakeStatusClient struct{}

// GetHealthzWithResponse returns a successful generated health response.
func (fakeStatusClient) GetHealthzWithResponse(context.Context, ...generated.RequestEditorFn) (*generated.GetHealthzResponse, error) {
	return &generated.GetHealthzResponse{
		HTTPResponse: &http.Response{StatusCode: http.StatusOK},
		JSON200:      &generated.StatusResponse{Status: testStatusOK},
	}, nil
}

// GetReadyzWithResponse returns a successful generated readiness response.
func (fakeStatusClient) GetReadyzWithResponse(context.Context, ...generated.RequestEditorFn) (*generated.GetReadyzResponse, error) {
	return &generated.GetReadyzResponse{
		HTTPResponse: &http.Response{StatusCode: http.StatusOK},
		JSON200:      &generated.StatusResponse{Status: testStatusOK},
	}, nil
}

// GetVersionWithResponse returns a successful generated version response.
func (fakeStatusClient) GetVersionWithResponse(context.Context, ...generated.RequestEditorFn) (*generated.GetVersionResponse, error) {
	return &generated.GetVersionResponse{
		HTTPResponse: &http.Response{StatusCode: http.StatusOK},
		JSON200: &generated.VersionResponse{
			APIVersion: "v1",
			Version:    "test-version",
		},
	}, nil
}
