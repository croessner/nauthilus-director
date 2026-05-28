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

//nolint:goconst,wsl_v5 // CLI test tables repeat operator syntax intentionally.
package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/client/generated"
)

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

// TestNestedCommandsUseGeneratedClient verifies every stable command calls the generated SDK interface.
func TestNestedCommandsUseGeneratedClient(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantCalls []string
	}{
		{name: "status", args: []string{"status"}, wantCalls: []string{"GetHealthz", "GetReadyz", "GetVersion"}},
		{name: "backends list", args: []string{"backends", "list"}, wantCalls: []string{"ListBackends"}},
		{name: "backends show", args: []string{"backends", "show", "backend-a"}, wantCalls: []string{"GetBackend"}},
		{name: "backends maintenance enable", args: []string{"backends", "maintenance", "enable", "backend-a", "--reason", "planned"}, wantCalls: []string{"EnableBackendMaintenance"}},
		{name: "backends maintenance disable", args: []string{"backends", "maintenance", "disable", "backend-a", "--reason", "done"}, wantCalls: []string{"DisableBackendMaintenance"}},
		{name: "backends out", args: []string{"backends", "out", "backend-a", "--reason", "planned"}, wantCalls: []string{"MarkBackendOut"}},
		{name: "backends in", args: []string{"backends", "in", "backend-a", "--reason", "done"}, wantCalls: []string{"MarkBackendIn"}},
		{name: "backends drain", args: []string{"backends", "drain", "backend-a", "--mode", "soft", "--reason", "planned"}, wantCalls: []string{"DrainBackend"}},
		{name: "backends weight", args: []string{"backends", "weight", "backend-a", "--weight", "0", "--reason", "drain placement"}, wantCalls: []string{"SetBackendWeight"}},
		{name: "backends runtime clear", args: []string{"backends", "runtime", "clear", "backend-a", "--reason", "reset"}, wantCalls: []string{"ClearBackendRuntime"}},
		{name: "backends runtime weight", args: []string{"backends", "runtime", "weight", "backend-a", "--weight", "100", "--reason", "restore"}, wantCalls: []string{"SetBackendWeight"}},
		{name: "config dump defaults", args: []string{"config", "dump", "-d"}, wantCalls: []string{"GetDefaultConfig"}},
		{name: "config dump non default", args: []string{"config", "dump", "-n", "-P", "--format", "json"}, wantCalls: []string{"GetNonDefaultConfig"}},
		{name: "sessions list", args: []string{"sessions", "list", "--protocol", "imap"}, wantCalls: []string{"ListSessions"}},
		{name: "sessions show", args: []string{"sessions", "show", "session-a"}, wantCalls: []string{"GetSession"}},
		{name: "sessions kill", args: []string{"sessions", "kill", "session-a", "--reason", "abuse"}, wantCalls: []string{"DeleteSession"}},
		{name: "users list", args: []string{"users", "list"}, wantCalls: []string{"ListUsers"}},
		{name: "users show", args: []string{"users", "show", "user-a"}, wantCalls: []string{"GetUser"}},
		{name: "users sessions", args: []string{"users", "sessions", "user-a"}, wantCalls: []string{"GetUserSessions"}},
		{name: "users affinity show", args: []string{"users", "affinity", "show", "user-a"}, wantCalls: []string{"GetUserAffinity"}},
		{name: "users affinity set", args: []string{"users", "affinity", "set", "user-a", "--shard", "shard-b", "--reason", "move"}, wantCalls: []string{"SetUserAffinity"}},
		{name: "users affinity clear", args: []string{"users", "affinity", "clear", "user-a", "--reason", "done"}, wantCalls: []string{"ClearUserAffinity"}},
		{name: "users move", args: []string{"users", "move", "user-a", "--to-shard", "shard-b", "--strategy", "kick_existing", "--reason", "rebalance"}, wantCalls: []string{"MoveUser"}},
		{name: "users kick", args: []string{"users", "kick", "user-a", "--reason", "abuse"}, wantCalls: []string{"KickUser"}},
		{name: "route lookup", args: []string{"route", "lookup", "--protocol", "imap", "--user", "user-a", "--listener", "imap", "--attribute", "tier=gold"}, wantCalls: []string{"LookupRoute"}},
		{name: "reload", args: []string{"reload"}, wantCalls: []string{"Reload"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := newFakeControlClient()
			stdout, stderr, code := runWithFakeClient(test.args, fake)
			if code != 0 {
				t.Fatalf("run returned exit code %d, want 0; stdout=%q stderr=%q", code, stdout, stderr)
			}
			if !reflect.DeepEqual(fake.calls, test.wantCalls) {
				t.Fatalf("calls = %#v, want %#v", fake.calls, test.wantCalls)
			}
		})
	}
}

// TestMutatingCommandsRequireReason keeps runtime changes auditable before any request is sent.
func TestMutatingCommandsRequireReason(t *testing.T) {
	tests := [][]string{
		{"backends", "maintenance", "enable", "backend-a"},
		{"backends", "maintenance", "disable", "backend-a"},
		{"backends", "out", "backend-a"},
		{"backends", "in", "backend-a"},
		{"backends", "drain", "backend-a", "--mode", "soft"},
		{"backends", "weight", "backend-a", "--weight", "0"},
		{"backends", "runtime", "clear", "backend-a"},
		{"sessions", "kill", "session-a"},
		{"users", "affinity", "set", "user-a", "--shard", "shard-a"},
		{"users", "affinity", "clear", "user-a"},
		{"users", "move", "user-a", "--to-shard", "shard-b", "--strategy", "kick_existing"},
		{"users", "kick", "user-a"},
	}

	for _, args := range tests {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			fake := newFakeControlClient()
			_, stderr, code := runWithFakeClient(args, fake)
			if code != 2 {
				t.Fatalf("run returned exit code %d, want 2; stderr=%q", code, stderr)
			}
			if len(fake.calls) != 0 {
				t.Fatalf("calls = %#v, want none", fake.calls)
			}
			if !strings.Contains(stderr, "--reason") {
				t.Fatalf("stderr = %q, want reason guidance", stderr)
			}
		})
	}
}

// TestConfigDumpEndpointsAndProtectedFlag verifies remote config dump flag mapping.
func TestConfigDumpEndpointsAndProtectedFlag(t *testing.T) {
	defaultFake := newFakeControlClient()
	_, stderr, code := runWithFakeClient([]string{"config", "dump", "-d"}, defaultFake)
	if code != 0 {
		t.Fatalf("defaults dump returned exit code %d, want 0; stderr=%q", code, stderr)
	}
	if defaultFake.defaultConfigParams == nil {
		t.Fatal("GetDefaultConfig params were not recorded")
	}
	if got := string(*defaultFake.defaultConfigParams.Format); got != "yaml" {
		t.Fatalf("default format = %q, want yaml", got)
	}
	if got := bool(*defaultFake.defaultConfigParams.IncludeProtected); got {
		t.Fatal("default include_protected = true, want false")
	}

	protectedFake := newFakeControlClient()
	stdout, stderr, code := runWithFakeClient([]string{"config", "dump", "-n", "-P", "--format", "json"}, protectedFake)
	if code != 0 {
		t.Fatalf("protected dump returned exit code %d, want 0; stderr=%q", code, stderr)
	}
	if protectedFake.nonDefaultConfigParams == nil {
		t.Fatal("GetNonDefaultConfig params were not recorded")
	}
	if got := string(*protectedFake.nonDefaultConfigParams.Format); got != "json" {
		t.Fatalf("non-default format = %q, want json", got)
	}
	if got := bool(*protectedFake.nonDefaultConfigParams.IncludeProtected); !got {
		t.Fatal("protected include_protected = false, want true")
	}
	if !strings.Contains(stdout, "\"runtime\"") {
		t.Fatalf("stdout = %q, want JSON config data", stdout)
	}
}

// TestProtectedConfigForbiddenDoesNotPrintPartialOutput keeps denied protected dumps closed.
func TestProtectedConfigForbiddenDoesNotPrintPartialOutput(t *testing.T) {
	fake := newFakeControlClient()
	fake.defaultConfigStatus = http.StatusForbidden
	fake.defaultConfigProblem = &generated.ErrorResponse{
		Code:    "protected_config_forbidden",
		Message: "denied",
		Status:  http.StatusForbidden,
	}

	stdout, stderr, code := runWithFakeClient([]string{"config", "dump", "-d", "-P"}, fake)
	if code != 1 {
		t.Fatalf("run returned exit code %d, want 1", code)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty protected output", stdout)
	}
	if !strings.Contains(stderr, "protected config output is forbidden") {
		t.Fatalf("stderr = %q, want protected error", stderr)
	}
}

// TestRouteLookupAttributes verifies route lookup request shaping and repeated attributes.
func TestRouteLookupAttributes(t *testing.T) {
	fake := newFakeControlClient()
	_, stderr, code := runWithFakeClient([]string{
		"route", "lookup",
		"--protocol", "imap",
		"--user", "user-a",
		"--tenant", "blue",
		"--listener", "imap",
		"--service-name", "imap",
		"--backend-pool", "imap-default",
		"--include-affinity",
		"--attribute", "tier=gold",
		"--attribute", "tier=silver",
	}, fake)
	if code != 0 {
		t.Fatalf("run returned exit code %d, want 0; stderr=%q", code, stderr)
	}

	request := fake.routeRequest
	if request.Protocol != "imap" || request.UserKey == nil || *request.UserKey != "user-a" || request.Listener == nil || *request.Listener != "imap" {
		t.Fatalf("route request = %#v, want protocol/user/listener", request)
	}
	if request.Tenant == nil || *request.Tenant != "blue" || request.ServiceName == nil || *request.ServiceName != "imap" {
		t.Fatalf("route request = %#v, want tenant/service", request)
	}
	if request.BackendPool == nil || *request.BackendPool != "imap-default" {
		t.Fatalf("route request = %#v, want backend pool", request)
	}
	if request.IncludeAffinity == nil || !*request.IncludeAffinity {
		t.Fatalf("route request = %#v, want include affinity", request)
	}
	if request.Attributes == nil {
		t.Fatal("route request attributes were nil")
	}
	if got := (*request.Attributes)["tier"]; !reflect.DeepEqual(got, []string{"gold", "silver"}) {
		t.Fatalf("tier attributes = %#v, want two values", got)
	}
}

// TestRouteLookupRecipient verifies LMTP recipient diagnostics use the generated DTO field.
func TestRouteLookupRecipient(t *testing.T) {
	fake := newFakeControlClient()
	_, stderr, code := runWithFakeClient([]string{
		"route", "lookup",
		"--protocol", "lmtp",
		"--recipient", "user@example.test",
	}, fake)
	if code != 0 {
		t.Fatalf("run returned exit code %d, want 0; stderr=%q", code, stderr)
	}

	request := fake.routeRequest
	if request.Recipient == nil || *request.Recipient != "user@example.test" {
		t.Fatalf("route request = %#v, want recipient", request)
	}

	if request.UserKey != nil {
		t.Fatalf("route request = %#v, want no caller-supplied user key", request)
	}
}

// TestHTTPStatusAndUsageExitCodes verifies stable local and remote failure mapping.
func TestHTTPStatusAndUsageExitCodes(t *testing.T) {
	fake := newFakeControlClient()
	fake.getBackendStatus = http.StatusNotFound
	fake.getBackendProblem = &generated.ErrorResponse{Status: http.StatusNotFound, Code: "not_found", Message: "unknown backend"}

	stdout, stderr, code := runWithFakeClient([]string{"backends", "show", "missing"}, fake)
	if code != 1 {
		t.Fatalf("server failure exit code = %d, want 1", code)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty output", stdout)
	}
	if !strings.Contains(stderr, "HTTP 404: unknown backend") {
		t.Fatalf("stderr = %q, want stable HTTP error", stderr)
	}

	usageFake := newFakeControlClient()
	_, usageStderr, usageCode := runWithFakeClient([]string{"does-not-exist"}, usageFake)
	if usageCode != 2 {
		t.Fatalf("usage exit code = %d, want 2; stderr=%q", usageCode, usageStderr)
	}
}

// TestTextAndJSONOutputDeterministic verifies compact text and generated JSON rendering.
func TestTextAndJSONOutputDeterministic(t *testing.T) {
	textFake := newFakeControlClient()
	stdout, stderr, code := runWithFakeClient([]string{"backends", "list"}, textFake)
	if code != 0 {
		t.Fatalf("text command returned exit code %d, want 0; stderr=%q", code, stderr)
	}
	wantText := "identifier=backend-a protocol=imap backend_pool=imap-default shard_tag=shard-a in_service=true draining=false maintenance=disabled weight=100\n" +
		"identifier=backend-b protocol=imap backend_pool=imap-default shard_tag=shard-b in_service=false draining=true maintenance=soft weight=\"\"\n"
	if stdout != wantText {
		t.Fatalf("text output = %q, want %q", stdout, wantText)
	}

	jsonFake := newFakeControlClient()
	stdout, stderr, code = runWithFakeClient([]string{"--output", "json", "backends", "show", "backend-a"}, jsonFake)
	if code != 0 {
		t.Fatalf("json command returned exit code %d, want 0; stderr=%q", code, stderr)
	}
	wantJSON := "{\n" +
		"  \"backend_pool\": \"imap-default\",\n" +
		"  \"identifier\": \"backend-a\",\n" +
		"  \"protocol\": \"imap\",\n" +
		"  \"runtime\": {\n" +
		"    \"draining\": false,\n" +
		"    \"in_service\": true,\n" +
		"    \"maintenance\": \"disabled\",\n" +
		"    \"weight\": 100\n" +
		"  },\n" +
		"  \"shard_tag\": \"shard-a\"\n" +
		"}\n"
	if stdout != wantJSON {
		t.Fatalf("JSON output = %q, want %q", stdout, wantJSON)
	}
}

// TestUsageErrorsDoNotPrintSecrets verifies rejected route facts do not echo secret values.
func TestUsageErrorsDoNotPrintSecrets(t *testing.T) {
	fake := newFakeControlClient()
	stdout, stderr, code := runWithFakeClient([]string{
		"route", "lookup",
		"--protocol", "imap",
		"--user", "user-a",
		"--attribute", "token=super-secret-value",
	}, fake)
	if code != 2 {
		t.Fatalf("run returned exit code %d, want 2", code)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty output", stdout)
	}
	if strings.Contains(stderr, "super-secret-value") || strings.Contains(stderr, "token=") {
		t.Fatalf("stderr leaked secret-bearing input: %q", stderr)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("calls = %#v, want none", fake.calls)
	}
}

// TestManpagesDocumentImplementedSurface keeps manual sources aligned with the stable CLI.
func TestManpagesDocumentImplementedSurface(t *testing.T) {
	directorCtl := readManpage(t, "nauthilus-directorctl.1")
	for _, want := range []string{
		"backends maintenance enable",
		"backends runtime clear",
		"config dump -d",
		"config dump -n",
		"sessions kill",
		"users affinity set",
		"route lookup",
		"reload",
		"--address",
		"--timeout",
		"--output",
		"EXIT STATUS",
		"protected config output",
		"runtime state",
		"YAML",
	} {
		if !strings.Contains(directorCtl, want) {
			t.Fatalf("nauthilus-directorctl.1 missing %q", want)
		}
	}

	director := readManpage(t, "nauthilus-director.1")
	for _, want := range []string{"config dump -d", "config dump -n", "-P", "--config", "--version"} {
		if !strings.Contains(director, want) {
			t.Fatalf("nauthilus-director.1 missing %q", want)
		}
	}

	config := readManpage(t, "nauthilus-director.yaml.5")
	for _, want := range []string{
		"runtime.servers.control",
		"storage.redis",
		"auth.authorities",
		"director.backends",
		"includes",
		"patch",
		"${NAME}",
		"NAUTHILUS_DIRECTOR_",
		"redacted",
		"protected",
		".yml",
	} {
		if !strings.Contains(config, want) {
			t.Fatalf("nauthilus-director.yaml.5 missing %q", want)
		}
	}
}

// runWithFakeClient runs the CLI with a fake generated client.
func runWithFakeClient(args []string, fake *fakeControlClient) (string, string, int) {
	previousClient := newControlClient
	newControlClient = func(address string, timeout time.Duration) (generated.ClientWithResponsesInterface, error) {
		fake.address = address
		fake.timeout = timeout
		return fake, nil
	}
	defer func() {
		newControlClient = previousClient
	}()

	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)
	code := run(args, &stdout, &stderr)

	return stdout.String(), stderr.String(), code
}

// readManpage reads one manpage source from the repository docs tree.
func readManpage(t *testing.T, name string) string {
	t.Helper()

	content, err := os.ReadFile(filepath.Join("..", "..", "docs", "man", name))
	if err != nil {
		t.Fatalf("read manpage %s: %v", name, err)
	}

	return string(content)
}

// fakeControlClient records generated interface calls and returns stable responses.
type fakeControlClient struct {
	calls                  []string
	address                string
	timeout                time.Duration
	defaultConfigParams    *generated.GetDefaultConfigParams
	nonDefaultConfigParams *generated.GetNonDefaultConfigParams
	listSessionsParams     *generated.ListSessionsParams
	routeRequest           generated.RouteLookupRequest
	defaultConfigStatus    int
	defaultConfigProblem   *generated.ErrorResponse
	getBackendStatus       int
	getBackendProblem      *generated.ErrorResponse
}

// newFakeControlClient creates a fake generated client with successful defaults.
func newFakeControlClient() *fakeControlClient {
	return &fakeControlClient{
		defaultConfigStatus: http.StatusOK,
		getBackendStatus:    http.StatusOK,
	}
}

// record appends one generated method name.
func (fake *fakeControlClient) record(call string) {
	fake.calls = append(fake.calls, call)
}

// acceptedResponse returns a generated accepted response.
func acceptedResponse() *generated.AcceptedResponse {
	return &generated.AcceptedResponse{Status: generated.Accepted}
}

// httpResponse returns a generated-compatible HTTP response shell.
func httpResponse(status int) *http.Response {
	return &http.Response{StatusCode: status}
}

// backendA returns a stable backend fixture.
func backendA() generated.BackendDetail {
	weight := 100
	return generated.BackendDetail{
		BackendPool: "imap-default",
		Identifier:  "backend-a",
		Protocol:    "imap",
		Runtime: generated.BackendRuntimeState{
			InService:   true,
			Maintenance: generated.MaintenanceModeDisabled,
			Weight:      &weight,
		},
		ShardTag: "shard-a",
	}
}

// backendB returns a second stable backend fixture.
func backendB() generated.BackendDetail {
	return generated.BackendDetail{
		BackendPool: "imap-default",
		Identifier:  "backend-b",
		Protocol:    "imap",
		Runtime: generated.BackendRuntimeState{
			Draining:    true,
			Maintenance: generated.MaintenanceModeSoft,
		},
		ShardTag: "shard-b",
	}
}

// sessionA returns a stable session fixture.
func sessionA() generated.SessionDetail {
	return generated.SessionDetail{
		Backend:   "backend-a",
		ExpiresAt: time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC),
		Protocol:  "imap",
		SessionID: "session-a",
		ShardTag:  "shard-a",
		UserKey:   "user-a",
	}
}

// affinityA returns a stable affinity fixture.
func affinityA() generated.UserAffinity {
	generation := "gen-a"
	return generated.UserAffinity{
		ActiveSessions: 1,
		Generation:     &generation,
		ShardTag:       "shard-a",
		UserKey:        "user-a",
	}
}

// userA returns a stable user fixture.
func userA() generated.UserDetail {
	affinity := affinityA()
	return generated.UserDetail{
		ActiveSessions: 1,
		Affinity:       &affinity,
		UserKey:        "user-a",
	}
}

// configDocument returns a stable config fixture.
func configDocument() *generated.ConfigDocument {
	return &generated.ConfigDocument{
		Data: map[string]any{
			"runtime": map[string]any{
				"instance_name": "director-a",
			},
		},
		Format:   generated.ConfigDocumentFormatYaml,
		Redacted: true,
	}
}

// ListBackendsWithResponse records and returns backend list data.
func (fake *fakeControlClient) ListBackendsWithResponse(context.Context, ...generated.RequestEditorFn) (*generated.ListBackendsResponse, error) {
	fake.record("ListBackends")
	return &generated.ListBackendsResponse{
		HTTPResponse: httpResponse(http.StatusOK),
		JSON200:      &generated.BackendListResponse{Backends: []generated.BackendDetail{backendB(), backendA()}},
	}, nil
}

// GetBackendWithResponse records and returns backend detail data.
func (fake *fakeControlClient) GetBackendWithResponse(context.Context, generated.Identifier, ...generated.RequestEditorFn) (*generated.GetBackendResponse, error) {
	fake.record("GetBackend")
	return &generated.GetBackendResponse{
		HTTPResponse: httpResponse(fake.getBackendStatus),
		JSON200:      &[]generated.BackendDetail{backendA()}[0],
		JSONDefault:  fake.getBackendProblem,
	}, nil
}

// DisableBackendMaintenanceWithBodyWithResponse records unsupported raw-body usage.
func (fake *fakeControlClient) DisableBackendMaintenanceWithBodyWithResponse(context.Context, generated.Identifier, string, io.Reader, ...generated.RequestEditorFn) (*generated.DisableBackendMaintenanceResponse, error) {
	fake.record("DisableBackendMaintenanceWithBody")
	return nil, nil
}

// DisableBackendMaintenanceWithResponse records and returns an accepted response.
func (fake *fakeControlClient) DisableBackendMaintenanceWithResponse(context.Context, generated.Identifier, generated.DisableBackendMaintenanceJSONRequestBody, ...generated.RequestEditorFn) (*generated.DisableBackendMaintenanceResponse, error) {
	fake.record("DisableBackendMaintenance")
	return &generated.DisableBackendMaintenanceResponse{HTTPResponse: httpResponse(http.StatusAccepted), JSON202: acceptedResponse()}, nil
}

// EnableBackendMaintenanceWithBodyWithResponse records unsupported raw-body usage.
func (fake *fakeControlClient) EnableBackendMaintenanceWithBodyWithResponse(context.Context, generated.Identifier, string, io.Reader, ...generated.RequestEditorFn) (*generated.EnableBackendMaintenanceResponse, error) {
	fake.record("EnableBackendMaintenanceWithBody")
	return nil, nil
}

// EnableBackendMaintenanceWithResponse records and returns an accepted response.
func (fake *fakeControlClient) EnableBackendMaintenanceWithResponse(context.Context, generated.Identifier, generated.EnableBackendMaintenanceJSONRequestBody, ...generated.RequestEditorFn) (*generated.EnableBackendMaintenanceResponse, error) {
	fake.record("EnableBackendMaintenance")
	return &generated.EnableBackendMaintenanceResponse{HTTPResponse: httpResponse(http.StatusAccepted), JSON202: acceptedResponse()}, nil
}

// ClearBackendRuntimeWithBodyWithResponse records unsupported raw-body usage.
func (fake *fakeControlClient) ClearBackendRuntimeWithBodyWithResponse(context.Context, generated.Identifier, string, io.Reader, ...generated.RequestEditorFn) (*generated.ClearBackendRuntimeResponse, error) {
	fake.record("ClearBackendRuntimeWithBody")
	return nil, nil
}

// ClearBackendRuntimeWithResponse records and returns an accepted response.
func (fake *fakeControlClient) ClearBackendRuntimeWithResponse(context.Context, generated.Identifier, generated.ClearBackendRuntimeJSONRequestBody, ...generated.RequestEditorFn) (*generated.ClearBackendRuntimeResponse, error) {
	fake.record("ClearBackendRuntime")
	return &generated.ClearBackendRuntimeResponse{HTTPResponse: httpResponse(http.StatusAccepted), JSON202: acceptedResponse()}, nil
}

// DrainBackendWithBodyWithResponse records unsupported raw-body usage.
func (fake *fakeControlClient) DrainBackendWithBodyWithResponse(context.Context, generated.Identifier, string, io.Reader, ...generated.RequestEditorFn) (*generated.DrainBackendResponse, error) {
	fake.record("DrainBackendWithBody")
	return nil, nil
}

// DrainBackendWithResponse records and returns an accepted response.
func (fake *fakeControlClient) DrainBackendWithResponse(context.Context, generated.Identifier, generated.DrainBackendJSONRequestBody, ...generated.RequestEditorFn) (*generated.DrainBackendResponse, error) {
	fake.record("DrainBackend")
	return &generated.DrainBackendResponse{HTTPResponse: httpResponse(http.StatusAccepted), JSON202: acceptedResponse()}, nil
}

// MarkBackendInWithBodyWithResponse records unsupported raw-body usage.
func (fake *fakeControlClient) MarkBackendInWithBodyWithResponse(context.Context, generated.Identifier, string, io.Reader, ...generated.RequestEditorFn) (*generated.MarkBackendInResponse, error) {
	fake.record("MarkBackendInWithBody")
	return nil, nil
}

// MarkBackendInWithResponse records and returns an accepted response.
func (fake *fakeControlClient) MarkBackendInWithResponse(context.Context, generated.Identifier, generated.MarkBackendInJSONRequestBody, ...generated.RequestEditorFn) (*generated.MarkBackendInResponse, error) {
	fake.record("MarkBackendIn")
	return &generated.MarkBackendInResponse{HTTPResponse: httpResponse(http.StatusAccepted), JSON202: acceptedResponse()}, nil
}

// MarkBackendOutWithBodyWithResponse records unsupported raw-body usage.
func (fake *fakeControlClient) MarkBackendOutWithBodyWithResponse(context.Context, generated.Identifier, string, io.Reader, ...generated.RequestEditorFn) (*generated.MarkBackendOutResponse, error) {
	fake.record("MarkBackendOutWithBody")
	return nil, nil
}

// MarkBackendOutWithResponse records and returns an accepted response.
func (fake *fakeControlClient) MarkBackendOutWithResponse(context.Context, generated.Identifier, generated.MarkBackendOutJSONRequestBody, ...generated.RequestEditorFn) (*generated.MarkBackendOutResponse, error) {
	fake.record("MarkBackendOut")
	return &generated.MarkBackendOutResponse{HTTPResponse: httpResponse(http.StatusAccepted), JSON202: acceptedResponse()}, nil
}

// SetBackendWeightWithBodyWithResponse records unsupported raw-body usage.
func (fake *fakeControlClient) SetBackendWeightWithBodyWithResponse(context.Context, generated.Identifier, string, io.Reader, ...generated.RequestEditorFn) (*generated.SetBackendWeightResponse, error) {
	fake.record("SetBackendWeightWithBody")
	return nil, nil
}

// SetBackendWeightWithResponse records and returns an accepted response.
func (fake *fakeControlClient) SetBackendWeightWithResponse(context.Context, generated.Identifier, generated.SetBackendWeightJSONRequestBody, ...generated.RequestEditorFn) (*generated.SetBackendWeightResponse, error) {
	fake.record("SetBackendWeight")
	return &generated.SetBackendWeightResponse{HTTPResponse: httpResponse(http.StatusAccepted), JSON202: acceptedResponse()}, nil
}

// GetDefaultConfigWithResponse records and returns config defaults.
func (fake *fakeControlClient) GetDefaultConfigWithResponse(_ context.Context, params *generated.GetDefaultConfigParams, _ ...generated.RequestEditorFn) (*generated.GetDefaultConfigResponse, error) {
	fake.record("GetDefaultConfig")
	fake.defaultConfigParams = params
	return &generated.GetDefaultConfigResponse{
		Body:         []byte("secret: leaked"),
		HTTPResponse: httpResponse(fake.defaultConfigStatus),
		JSON200:      configDocument(),
		JSONDefault:  fake.defaultConfigProblem,
	}, nil
}

// GetEffectiveConfigWithResponse records and returns effective config data.
func (fake *fakeControlClient) GetEffectiveConfigWithResponse(context.Context, *generated.GetEffectiveConfigParams, ...generated.RequestEditorFn) (*generated.GetEffectiveConfigResponse, error) {
	fake.record("GetEffectiveConfig")
	return &generated.GetEffectiveConfigResponse{HTTPResponse: httpResponse(http.StatusOK), JSON200: configDocument()}, nil
}

// GetNonDefaultConfigWithResponse records and returns non-default config data.
func (fake *fakeControlClient) GetNonDefaultConfigWithResponse(_ context.Context, params *generated.GetNonDefaultConfigParams, _ ...generated.RequestEditorFn) (*generated.GetNonDefaultConfigResponse, error) {
	fake.record("GetNonDefaultConfig")
	fake.nonDefaultConfigParams = params
	return &generated.GetNonDefaultConfigResponse{HTTPResponse: httpResponse(http.StatusOK), JSON200: configDocument()}, nil
}

// ReloadWithResponse records and returns an accepted reload response.
func (fake *fakeControlClient) ReloadWithResponse(context.Context, ...generated.RequestEditorFn) (*generated.ReloadResponse, error) {
	fake.record("Reload")
	return &generated.ReloadResponse{HTTPResponse: httpResponse(http.StatusAccepted), JSON202: acceptedResponse()}, nil
}

// LookupRouteWithBodyWithResponse records unsupported raw-body usage.
func (fake *fakeControlClient) LookupRouteWithBodyWithResponse(context.Context, string, io.Reader, ...generated.RequestEditorFn) (*generated.LookupRouteResponse, error) {
	fake.record("LookupRouteWithBody")
	return nil, nil
}

// LookupRouteWithResponse records and returns route lookup data.
func (fake *fakeControlClient) LookupRouteWithResponse(_ context.Context, body generated.LookupRouteJSONRequestBody, _ ...generated.RequestEditorFn) (*generated.LookupRouteResponse, error) {
	fake.record("LookupRoute")
	fake.routeRequest = body
	generation := "route-gen-a"
	return &generated.LookupRouteResponse{
		HTTPResponse: httpResponse(http.StatusOK),
		JSON200: &generated.RouteLookupResponse{
			Healthy:           true,
			Reason:            "selected",
			RoutingGeneration: &generation,
			SelectedBackend:   "backend-a",
			ShardTag:          "shard-a",
		},
	}, nil
}

// ListSessionsWithResponse records and returns session list data.
func (fake *fakeControlClient) ListSessionsWithResponse(_ context.Context, params *generated.ListSessionsParams, _ ...generated.RequestEditorFn) (*generated.ListSessionsResponse, error) {
	fake.record("ListSessions")
	fake.listSessionsParams = params
	return &generated.ListSessionsResponse{
		HTTPResponse: httpResponse(http.StatusOK),
		JSON200:      &generated.SessionListResponse{Sessions: []generated.SessionDetail{sessionA()}},
	}, nil
}

// DeleteSessionWithBodyWithResponse records unsupported raw-body usage.
func (fake *fakeControlClient) DeleteSessionWithBodyWithResponse(context.Context, generated.SessionID, string, io.Reader, ...generated.RequestEditorFn) (*generated.DeleteSessionResponse, error) {
	fake.record("DeleteSessionWithBody")
	return nil, nil
}

// DeleteSessionWithResponse records and returns an accepted response.
func (fake *fakeControlClient) DeleteSessionWithResponse(context.Context, generated.SessionID, generated.DeleteSessionJSONRequestBody, ...generated.RequestEditorFn) (*generated.DeleteSessionResponse, error) {
	fake.record("DeleteSession")
	return &generated.DeleteSessionResponse{HTTPResponse: httpResponse(http.StatusAccepted), JSON202: acceptedResponse()}, nil
}

// GetSessionWithResponse records and returns session detail data.
func (fake *fakeControlClient) GetSessionWithResponse(context.Context, generated.SessionID, ...generated.RequestEditorFn) (*generated.GetSessionResponse, error) {
	fake.record("GetSession")
	return &generated.GetSessionResponse{HTTPResponse: httpResponse(http.StatusOK), JSON200: &[]generated.SessionDetail{sessionA()}[0]}, nil
}

// ListUsersWithResponse records and returns user list data.
func (fake *fakeControlClient) ListUsersWithResponse(context.Context, ...generated.RequestEditorFn) (*generated.ListUsersResponse, error) {
	fake.record("ListUsers")
	return &generated.ListUsersResponse{HTTPResponse: httpResponse(http.StatusOK), JSON200: &generated.UserListResponse{Users: []generated.UserDetail{userA()}}}, nil
}

// GetUserWithResponse records and returns user detail data.
func (fake *fakeControlClient) GetUserWithResponse(context.Context, generated.UserKey, ...generated.RequestEditorFn) (*generated.GetUserResponse, error) {
	fake.record("GetUser")
	return &generated.GetUserResponse{HTTPResponse: httpResponse(http.StatusOK), JSON200: &[]generated.UserDetail{userA()}[0]}, nil
}

// ClearUserAffinityWithBodyWithResponse records unsupported raw-body usage.
func (fake *fakeControlClient) ClearUserAffinityWithBodyWithResponse(context.Context, generated.UserKey, string, io.Reader, ...generated.RequestEditorFn) (*generated.ClearUserAffinityResponse, error) {
	fake.record("ClearUserAffinityWithBody")
	return nil, nil
}

// ClearUserAffinityWithResponse records and returns an accepted response.
func (fake *fakeControlClient) ClearUserAffinityWithResponse(context.Context, generated.UserKey, generated.ClearUserAffinityJSONRequestBody, ...generated.RequestEditorFn) (*generated.ClearUserAffinityResponse, error) {
	fake.record("ClearUserAffinity")
	return &generated.ClearUserAffinityResponse{HTTPResponse: httpResponse(http.StatusAccepted), JSON202: acceptedResponse()}, nil
}

// GetUserAffinityWithResponse records and returns user affinity data.
func (fake *fakeControlClient) GetUserAffinityWithResponse(context.Context, generated.UserKey, ...generated.RequestEditorFn) (*generated.GetUserAffinityResponse, error) {
	fake.record("GetUserAffinity")
	return &generated.GetUserAffinityResponse{HTTPResponse: httpResponse(http.StatusOK), JSON200: &[]generated.UserAffinity{affinityA()}[0]}, nil
}

// SetUserAffinityWithBodyWithResponse records unsupported raw-body usage.
func (fake *fakeControlClient) SetUserAffinityWithBodyWithResponse(context.Context, generated.UserKey, string, io.Reader, ...generated.RequestEditorFn) (*generated.SetUserAffinityResponse, error) {
	fake.record("SetUserAffinityWithBody")
	return nil, nil
}

// SetUserAffinityWithResponse records and returns an accepted response.
func (fake *fakeControlClient) SetUserAffinityWithResponse(context.Context, generated.UserKey, generated.SetUserAffinityJSONRequestBody, ...generated.RequestEditorFn) (*generated.SetUserAffinityResponse, error) {
	fake.record("SetUserAffinity")
	return &generated.SetUserAffinityResponse{HTTPResponse: httpResponse(http.StatusAccepted), JSON202: acceptedResponse()}, nil
}

// KickUserWithBodyWithResponse records unsupported raw-body usage.
func (fake *fakeControlClient) KickUserWithBodyWithResponse(context.Context, generated.UserKey, string, io.Reader, ...generated.RequestEditorFn) (*generated.KickUserResponse, error) {
	fake.record("KickUserWithBody")
	return nil, nil
}

// KickUserWithResponse records and returns an accepted response.
func (fake *fakeControlClient) KickUserWithResponse(context.Context, generated.UserKey, generated.KickUserJSONRequestBody, ...generated.RequestEditorFn) (*generated.KickUserResponse, error) {
	fake.record("KickUser")
	return &generated.KickUserResponse{HTTPResponse: httpResponse(http.StatusAccepted), JSON202: acceptedResponse()}, nil
}

// MoveUserWithBodyWithResponse records unsupported raw-body usage.
func (fake *fakeControlClient) MoveUserWithBodyWithResponse(context.Context, generated.UserKey, string, io.Reader, ...generated.RequestEditorFn) (*generated.MoveUserResponse, error) {
	fake.record("MoveUserWithBody")
	return nil, nil
}

// MoveUserWithResponse records and returns an accepted response.
func (fake *fakeControlClient) MoveUserWithResponse(context.Context, generated.UserKey, generated.MoveUserJSONRequestBody, ...generated.RequestEditorFn) (*generated.MoveUserResponse, error) {
	fake.record("MoveUser")
	return &generated.MoveUserResponse{HTTPResponse: httpResponse(http.StatusAccepted), JSON202: acceptedResponse()}, nil
}

// GetUserSessionsWithResponse records and returns sessions for one user.
func (fake *fakeControlClient) GetUserSessionsWithResponse(context.Context, generated.UserKey, ...generated.RequestEditorFn) (*generated.GetUserSessionsResponse, error) {
	fake.record("GetUserSessions")
	return &generated.GetUserSessionsResponse{HTTPResponse: httpResponse(http.StatusOK), JSON200: &generated.SessionListResponse{Sessions: []generated.SessionDetail{sessionA()}}}, nil
}

// GetVersionWithResponse records and returns version data.
func (fake *fakeControlClient) GetVersionWithResponse(context.Context, ...generated.RequestEditorFn) (*generated.GetVersionResponse, error) {
	fake.record("GetVersion")
	return &generated.GetVersionResponse{
		HTTPResponse: httpResponse(http.StatusOK),
		JSON200: &generated.VersionResponse{
			APIVersion: "v1",
			Component:  "nauthilus-director",
			Version:    "test-version",
		},
	}, nil
}

// GetHealthzWithResponse records and returns health data.
func (fake *fakeControlClient) GetHealthzWithResponse(context.Context, ...generated.RequestEditorFn) (*generated.GetHealthzResponse, error) {
	fake.record("GetHealthz")
	return &generated.GetHealthzResponse{
		HTTPResponse: httpResponse(http.StatusOK),
		JSON200:      &generated.StatusResponse{Status: "ok"},
	}, nil
}

// GetMetricsWithResponse records and returns no metrics body.
func (fake *fakeControlClient) GetMetricsWithResponse(context.Context, ...generated.RequestEditorFn) (*generated.GetMetricsResponse, error) {
	fake.record("GetMetrics")
	return &generated.GetMetricsResponse{HTTPResponse: httpResponse(http.StatusOK)}, nil
}

// GetReadyzWithResponse records and returns readiness data.
func (fake *fakeControlClient) GetReadyzWithResponse(context.Context, ...generated.RequestEditorFn) (*generated.GetReadyzResponse, error) {
	fake.record("GetReadyz")
	return &generated.GetReadyzResponse{
		HTTPResponse: httpResponse(http.StatusOK),
		JSON200:      &generated.StatusResponse{Status: "ok"},
	}, nil
}
