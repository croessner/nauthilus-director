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

//nolint:dupl,goconst,wsl_v5 // CLI test tables and fake generated-client responses repeat operator syntax intentionally.
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

// TestHelpOutputListsCommands verifies root and nested help are operator-friendly.
func TestHelpOutputListsCommands(t *testing.T) {
	var rootOut, rootErr bytes.Buffer
	code := run([]string{"--help"}, &rootOut, &rootErr)
	if code != 0 {
		t.Fatalf("root help exit code %d, want 0; stderr=%q", code, rootErr.String())
	}
	rootHelp := rootOut.String()
	for _, want := range []string{
		"Available Commands:",
		"backends",
		"listeners",
		"route",
		"sessions",
		"users",
		"Use \"nauthilus-directorctl [command] --help\"",
	} {
		if !strings.Contains(rootHelp, want) {
			t.Fatalf("root help missing %q:\n%s", want, rootHelp)
		}
	}

	var drainOut, drainErr bytes.Buffer
	code = run([]string{"listeners", "drain", "--help"}, &drainOut, &drainErr)
	if code != 0 {
		t.Fatalf("nested help exit code %d, want 0; stderr=%q", code, drainErr.String())
	}
	drainHelp := drainOut.String()
	for _, want := range []string{"--mode", "--reason", "--grace-seconds", "Global Flags:"} {
		if !strings.Contains(drainHelp, want) {
			t.Fatalf("nested help missing %q:\n%s", want, drainHelp)
		}
	}

	var backendPinOut, backendPinErr bytes.Buffer
	code = run([]string{"users", "backend-pin", "--help"}, &backendPinOut, &backendPinErr)
	if code != 0 {
		t.Fatalf("backend-pin help exit code %d, want 0; stderr=%q", code, backendPinErr.String())
	}
	backendPinHelp := backendPinOut.String()
	for _, want := range []string{"show", "set", "clear", "Inspect and control user backend pins"} {
		if !strings.Contains(backendPinHelp, want) {
			t.Fatalf("backend-pin help missing %q:\n%s", want, backendPinHelp)
		}
	}

	var backendPinSetOut, backendPinSetErr bytes.Buffer
	code = run([]string{"users", "backend-pin", "set", "--help"}, &backendPinSetOut, &backendPinSetErr)
	if code != 0 {
		t.Fatalf("backend-pin set help exit code %d, want 0; stderr=%q", code, backendPinSetErr.String())
	}
	backendPinSetHelp := backendPinSetOut.String()
	for _, want := range []string{"--backend", "--strategy", "--reason"} {
		if !strings.Contains(backendPinSetHelp, want) {
			t.Fatalf("backend-pin set help missing %q:\n%s", want, backendPinSetHelp)
		}
	}
}

// TestLongOptionsRequireDoubleDash rejects long options written with one dash.
func TestLongOptionsRequireDoubleDash(t *testing.T) {
	fake := newFakeControlClient()
	stdout, stderr, code := runWithFakeClient([]string{"-address", "http://127.0.0.1:1", "status"}, fake)
	if code != 2 {
		t.Fatalf("run returned exit code %d, want 2; stderr=%q", code, stderr)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty output", stdout)
	}
	if !strings.Contains(stderr, "long options require double dash: -address") {
		t.Fatalf("stderr = %q, want double-dash guidance", stderr)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("calls = %#v, want none", fake.calls)
	}

	fake = newFakeControlClient()
	_, stderr, code = runWithFakeClient([]string{"sessions", "kill", "session-a", "-reason", "cleanup"}, fake)
	if code != 2 {
		t.Fatalf("run returned exit code %d, want 2; stderr=%q", code, stderr)
	}
	if !strings.Contains(stderr, "long options require double dash: -reason") {
		t.Fatalf("stderr = %q, want double-dash guidance", stderr)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("calls = %#v, want none", fake.calls)
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
		{name: "listeners list", args: []string{"listeners", "list"}, wantCalls: []string{"ListListeners"}},
		{name: "listeners show", args: []string{"listeners", "show", "imap"}, wantCalls: []string{"GetListener"}},
		{name: "listeners drain soft", args: []string{"listeners", "drain", "imap", "--mode", "soft", "--reason", "planned"}, wantCalls: []string{"DrainListener"}},
		{name: "listeners drain hard", args: []string{"listeners", "drain", "imap", "--mode", "hard", "--reason", "planned", "--grace-seconds", "0"}, wantCalls: []string{"DrainListener"}},
		{name: "listeners resume", args: []string{"listeners", "resume", "imap", "--reason", "done"}, wantCalls: []string{"ResumeListener"}},
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
		{name: "users backend-pin show", args: []string{"users", "backend-pin", "show", "user-a"}, wantCalls: []string{"GetUserBackendPin"}},
		{name: "users backend-pin set", args: []string{"users", "backend-pin", "set", "user-a", "--backend", "backend-a", "--strategy", "kick_existing", "--reason", "commission"}, wantCalls: []string{"SetUserBackendPin"}},
		{name: "users backend-pin clear", args: []string{"users", "backend-pin", "clear", "user-a", "--reason", "done"}, wantCalls: []string{"ClearUserBackendPin"}},
		{name: "users move", args: []string{"users", "move", "user-a", "--to-shard", "shard-b", "--strategy", "kick_existing", "--reason", "rebalance"}, wantCalls: []string{"MoveUser"}},
		{name: "users kick", args: []string{"users", "kick", "user-a", "--reason", "abuse"}, wantCalls: []string{"KickUser"}},
		{name: "runtime summary", args: []string{"runtime", "summary"}, wantCalls: []string{"GetRuntimeSummary"}},
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
		{"listeners", "drain", "imap", "--mode", "soft"},
		{"listeners", "resume", "imap"},
		{"sessions", "kill", "session-a"},
		{"users", "affinity", "set", "user-a", "--shard", "shard-a"},
		{"users", "affinity", "clear", "user-a"},
		{"users", "backend-pin", "set", "user-a", "--backend", "backend-a", "--strategy", "kick_existing"},
		{"users", "backend-pin", "clear", "user-a"},
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

// TestBackendPinRequestsUseGeneratedDTOs verifies backend-pin requests stay on the generated client boundary.
func TestBackendPinRequestsUseGeneratedDTOs(t *testing.T) {
	setFake := newFakeControlClient()
	stdout, stderr, code := runWithFakeClient([]string{
		"users", "backend-pin", "set", "user-a",
		"--backend", "backend-a",
		"--strategy", "kick_existing",
		"--reason", "commission",
	}, setFake)
	if code != 0 {
		t.Fatalf("backend-pin set returned exit code %d, want 0; stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !reflect.DeepEqual(setFake.calls, []string{"SetUserBackendPin"}) {
		t.Fatalf("calls = %#v, want SetUserBackendPin", setFake.calls)
	}
	if setFake.setBackendPinUserKey != generated.UserKey("user-a") {
		t.Fatalf("set user key = %q, want user-a", setFake.setBackendPinUserKey)
	}
	if setFake.setBackendPinRequest.Backend != "backend-a" {
		t.Fatalf("backend = %q, want backend-a", setFake.setBackendPinRequest.Backend)
	}
	if setFake.setBackendPinRequest.Strategy != generated.KickExisting {
		t.Fatalf("strategy = %q, want kick_existing", setFake.setBackendPinRequest.Strategy)
	}
	if setFake.setBackendPinRequest.Reason != "commission" {
		t.Fatalf("reason = %q, want commission", setFake.setBackendPinRequest.Reason)
	}

	clearFake := newFakeControlClient()
	stdout, stderr, code = runWithFakeClient([]string{"users", "backend-pin", "clear", "user-a", "--reason", "done"}, clearFake)
	if code != 0 {
		t.Fatalf("backend-pin clear returned exit code %d, want 0; stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !reflect.DeepEqual(clearFake.calls, []string{"ClearUserBackendPin"}) {
		t.Fatalf("calls = %#v, want ClearUserBackendPin", clearFake.calls)
	}
	if clearFake.clearBackendPinUserKey != generated.UserKey("user-a") {
		t.Fatalf("clear user key = %q, want user-a", clearFake.clearBackendPinUserKey)
	}
	if clearFake.clearBackendPinRequest.Reason != "done" {
		t.Fatalf("clear reason = %q, want done", clearFake.clearBackendPinRequest.Reason)
	}
}

// TestBackendPinUsageValidationKeepsRequestsLocal rejects malformed backend-pin commands before transport.
func TestBackendPinUsageValidationKeepsRequestsLocal(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantStderr string
	}{
		{name: "show missing user", args: []string{"users", "backend-pin", "show"}, wantStderr: "exactly one user key"},
		{name: "show empty user", args: []string{"users", "backend-pin", "show", ""}, wantStderr: "non-empty user key"},
		{name: "set missing user", args: []string{"users", "backend-pin", "set", "--backend", "backend-a", "--strategy", "kick_existing", "--reason", "commission"}, wantStderr: "exactly one user key"},
		{name: "set missing backend", args: []string{"users", "backend-pin", "set", "user-a", "--strategy", "kick_existing", "--reason", "commission"}, wantStderr: "--backend"},
		{name: "set empty backend", args: []string{"users", "backend-pin", "set", "user-a", "--backend", "", "--strategy", "kick_existing", "--reason", "commission"}, wantStderr: "--backend"},
		{name: "set missing reason", args: []string{"users", "backend-pin", "set", "user-a", "--backend", "backend-a", "--strategy", "kick_existing"}, wantStderr: "--reason"},
		{name: "set unsupported strategy", args: []string{"users", "backend-pin", "set", "user-a", "--backend", "backend-a", "--strategy", "later", "--reason", "commission"}, wantStderr: "new_sessions_only"},
		{name: "clear missing user", args: []string{"users", "backend-pin", "clear", "--reason", "done"}, wantStderr: "exactly one user key"},
		{name: "clear empty user", args: []string{"users", "backend-pin", "clear", "", "--reason", "done"}, wantStderr: "non-empty user key"},
		{name: "clear missing reason", args: []string{"users", "backend-pin", "clear", "user-a"}, wantStderr: "--reason"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := newFakeControlClient()
			stdout, stderr, code := runWithFakeClient(test.args, fake)
			if code != 2 {
				t.Fatalf("run returned exit code %d, want 2; stderr=%q", code, stderr)
			}
			if stdout != "" {
				t.Fatalf("stdout = %q, want empty output", stdout)
			}
			if !strings.Contains(stderr, test.wantStderr) {
				t.Fatalf("stderr = %q, want %q", stderr, test.wantStderr)
			}
			if len(fake.calls) != 0 {
				t.Fatalf("calls = %#v, want none", fake.calls)
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

// TestRuntimeSessionListFlagsPassPaginationParams verifies session list pagination fields.
func TestRuntimeSessionListFlagsPassPaginationParams(t *testing.T) {
	fake := newFakeControlClient()
	_, stderr, code := runWithFakeClient([]string{
		"sessions", "list",
		"--protocol", "imap",
		"--backend", "backend-a",
		"--cursor", "cursor-a",
		"--limit", "25",
	}, fake)
	if code != 0 {
		t.Fatalf("sessions list returned exit code %d, want 0; stderr=%q", code, stderr)
	}

	assertSessionListPaginationParams(t, fake)
}

// TestRuntimeUserListFlagsPassPaginationParams verifies user list pagination fields.
func TestRuntimeUserListFlagsPassPaginationParams(t *testing.T) {
	fake := newFakeControlClient()
	_, stderr, code := runWithFakeClient([]string{"users", "list", "--cursor", "user-cursor", "--limit", "30"}, fake)
	if code != 0 {
		t.Fatalf("users list returned exit code %d, want 0; stderr=%q", code, stderr)
	}

	assertUserListPaginationParams(t, fake)
}

// assertSessionListPaginationParams checks the generated session list request fields.
func assertSessionListPaginationParams(t *testing.T, fake *fakeControlClient) {
	t.Helper()

	if fake.listSessionsParams == nil {
		t.Fatal("ListSessions params were not recorded")
	}

	if fake.listSessionsParams.Protocol == nil || *fake.listSessionsParams.Protocol != "imap" {
		t.Fatalf("protocol param = %#v, want imap", fake.listSessionsParams.Protocol)
	}

	if fake.listSessionsParams.Backend == nil || *fake.listSessionsParams.Backend != "backend-a" {
		t.Fatalf("backend param = %#v, want backend-a", fake.listSessionsParams.Backend)
	}

	if fake.listSessionsParams.Cursor == nil || string(*fake.listSessionsParams.Cursor) != "cursor-a" {
		t.Fatalf("cursor param = %#v, want cursor-a", fake.listSessionsParams.Cursor)
	}

	if fake.listSessionsParams.Limit == nil || int(*fake.listSessionsParams.Limit) != 25 {
		t.Fatalf("limit param = %#v, want 25", fake.listSessionsParams.Limit)
	}
}

// assertUserListPaginationParams checks the generated user list request fields.
func assertUserListPaginationParams(t *testing.T, fake *fakeControlClient) {
	t.Helper()

	if fake.listUsersParams == nil {
		t.Fatal("ListUsers params were not recorded")
	}

	if fake.listUsersParams.Cursor == nil || string(*fake.listUsersParams.Cursor) != "user-cursor" {
		t.Fatalf("user cursor param = %#v, want user-cursor", fake.listUsersParams.Cursor)
	}

	if fake.listUsersParams.Limit == nil || int(*fake.listUsersParams.Limit) != 30 {
		t.Fatalf("user limit param = %#v, want 30", fake.listUsersParams.Limit)
	}
}

// TestRuntimeListDefaultOutputReportsNextCursor keeps first-page output explicit.
func TestRuntimeListDefaultOutputReportsNextCursor(t *testing.T) {
	nextCursor := "cursor-b"
	fake := newFakeControlClient()
	fake.listSessionPages = []generated.SessionListResponse{{
		NextCursor: &nextCursor,
		Sessions:   []generated.SessionDetail{sessionA()},
	}}

	stdout, stderr, code := runWithFakeClient([]string{"sessions", "list"}, fake)
	if code != 0 {
		t.Fatalf("sessions list returned exit code %d, want 0; stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "more=true next_cursor=cursor-b") {
		t.Fatalf("stdout = %q, want continuation cursor", stdout)
	}

	userNext := "user-cursor-b"
	userFake := newFakeControlClient()
	userFake.listUserPages = []generated.UserListResponse{{
		NextCursor: &userNext,
		Users:      []generated.UserDetail{userA()},
	}}

	stdout, stderr, code = runWithFakeClient([]string{"users", "list"}, userFake)
	if code != 0 {
		t.Fatalf("users list returned exit code %d, want 0; stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "more=true next_cursor=user-cursor-b") {
		t.Fatalf("stdout = %q, want user continuation cursor", stdout)
	}
}

// TestRuntimeSummaryUsesGeneratedClient verifies summaries avoid paged session listing.
func TestRuntimeSummaryUsesGeneratedClient(t *testing.T) {
	fake := newFakeControlClient()

	stdout, stderr, code := runWithFakeClient([]string{"runtime", "summary"}, fake)
	if code != 0 {
		t.Fatalf("runtime summary returned exit code %d, want 0; stderr=%q", code, stderr)
	}

	if !reflect.DeepEqual(fake.calls, []string{"GetRuntimeSummary"}) {
		t.Fatalf("calls = %#v, want only GetRuntimeSummary", fake.calls)
	}

	for _, want := range []string{
		"routing_authority=false active_sessions=2",
		"active_sessions_by_protocol protocol=imap count=2",
		"backend_capacity backend=backend-a active_sessions=2",
		"repairs expired_sessions=3 stale_index_entries=2 backend_reservations=1",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("runtime summary stdout = %q, want %q", stdout, want)
		}
	}
}

// TestRuntimeListAllIteratesUntilCursorExhausted verifies explicit full walks are paginated.
func TestRuntimeListAllIteratesUntilCursorExhausted(t *testing.T) {
	nextCursor := "cursor-b"
	fake := newFakeControlClient()
	fake.listSessionPages = []generated.SessionListResponse{
		{NextCursor: &nextCursor, Sessions: []generated.SessionDetail{sessionA()}},
		{Sessions: []generated.SessionDetail{sessionB()}},
	}

	stdout, stderr, code := runWithFakeClient([]string{"sessions", "list", "--all"}, fake)
	if code != 0 {
		t.Fatalf("sessions list --all returned exit code %d, want 0; stderr=%q", code, stderr)
	}
	if !reflect.DeepEqual(fake.calls, []string{"ListSessions", "ListSessions"}) {
		t.Fatalf("calls = %#v, want two ListSessions calls", fake.calls)
	}
	if len(fake.listSessionsHistory) != 2 || fake.listSessionsHistory[0].Cursor != nil || fake.listSessionsHistory[1].Cursor == nil {
		t.Fatalf("session cursor history = %#v, want nil then cursor", fake.listSessionsHistory)
	}
	if got := string(*fake.listSessionsHistory[1].Cursor); got != nextCursor {
		t.Fatalf("second cursor = %q, want %q", got, nextCursor)
	}
	if !strings.Contains(stdout, "session_id=session-a") || !strings.Contains(stdout, "session_id=session-b") {
		t.Fatalf("stdout = %q, want both paged sessions", stdout)
	}
	if strings.Contains(stdout, "more=true") {
		t.Fatalf("stdout = %q, want no continuation after --all completes", stdout)
	}
}

// TestRuntimeUserListAllIteratesUntilCursorExhausted verifies explicit user walks are paginated.
func TestRuntimeUserListAllIteratesUntilCursorExhausted(t *testing.T) {
	nextCursor := "user-cursor-b"
	fake := newFakeControlClient()
	fake.listUserPages = []generated.UserListResponse{
		{NextCursor: &nextCursor, Users: []generated.UserDetail{userA()}},
		{Users: []generated.UserDetail{userB()}},
	}

	stdout, stderr, code := runWithFakeClient([]string{"users", "list", "--all"}, fake)
	if code != 0 {
		t.Fatalf("users list --all returned exit code %d, want 0; stderr=%q", code, stderr)
	}
	if !reflect.DeepEqual(fake.calls, []string{"ListUsers", "ListUsers"}) {
		t.Fatalf("calls = %#v, want two ListUsers calls", fake.calls)
	}
	if len(fake.listUsersHistory) != 2 || fake.listUsersHistory[0].Cursor != nil || fake.listUsersHistory[1].Cursor == nil {
		t.Fatalf("user cursor history = %#v, want nil then cursor", fake.listUsersHistory)
	}
	if got := string(*fake.listUsersHistory[1].Cursor); got != nextCursor {
		t.Fatalf("second user cursor = %q, want %q", got, nextCursor)
	}
	if !strings.Contains(stdout, "user_key=user-a") || !strings.Contains(stdout, "user_key=user-b") {
		t.Fatalf("stdout = %q, want both paged users", stdout)
	}
	if strings.Contains(stdout, "more=true") {
		t.Fatalf("stdout = %q, want no continuation after --all completes", stdout)
	}
}

// TestRuntimeListAllDetectsRepeatedCursor verifies pagination loops fail closed.
func TestRuntimeListAllDetectsRepeatedCursor(t *testing.T) {
	repeated := "same-cursor"
	fake := newFakeControlClient()
	fake.listSessionPages = []generated.SessionListResponse{
		{NextCursor: &repeated, Sessions: []generated.SessionDetail{sessionA()}},
		{NextCursor: &repeated, Sessions: []generated.SessionDetail{sessionB()}},
	}

	stdout, stderr, code := runWithFakeClient([]string{"sessions", "list", "--all"}, fake)
	if code != 1 {
		t.Fatalf("sessions list --all returned exit code %d, want 1", code)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want no partial output on repeated cursor", stdout)
	}
	if !strings.Contains(stderr, "repeated pagination cursor") {
		t.Fatalf("stderr = %q, want repeated cursor error", stderr)
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

// TestListenerUsageValidationKeepsRequestsLocal verifies listener command errors fail before dispatch.
func TestListenerUsageValidationKeepsRequestsLocal(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantStderr string
	}{
		{name: "empty show name", args: []string{"listeners", "show", ""}, wantStderr: "non-empty listener name"},
		{name: "missing reason", args: []string{"listeners", "drain", "imap", "--mode", "soft"}, wantStderr: "--reason"},
		{name: "invalid mode", args: []string{"listeners", "drain", "imap", "--mode", "later", "--reason", "planned"}, wantStderr: "soft or hard"},
		{name: "empty grace", args: []string{"listeners", "drain", "imap", "--mode", "hard", "--reason", "planned", "--grace-seconds", ""}, wantStderr: "non-negative integer"},
		{name: "negative grace", args: []string{"listeners", "drain", "imap", "--mode", "hard", "--reason", "planned", "--grace-seconds", "-1"}, wantStderr: "non-negative integer"},
		{name: "hard without grace", args: []string{"listeners", "drain", "imap", "--mode", "hard", "--reason", "planned"}, wantStderr: "--grace-seconds"},
		{name: "empty resume name", args: []string{"listeners", "resume", "", "--reason", "done"}, wantStderr: "non-empty listener name"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := newFakeControlClient()
			stdout, stderr, code := runWithFakeClient(test.args, fake)
			if code != 2 {
				t.Fatalf("run returned exit code %d, want 2; stderr=%q", code, stderr)
			}
			if stdout != "" {
				t.Fatalf("stdout = %q, want empty output", stdout)
			}
			if !strings.Contains(stderr, test.wantStderr) {
				t.Fatalf("stderr = %q, want %q", stderr, test.wantStderr)
			}
			if len(fake.calls) != 0 {
				t.Fatalf("calls = %#v, want none", fake.calls)
			}
		})
	}
}

// TestHardListenerDrainZeroGraceSendsExplicitZero keeps immediate hard drain intentional.
func TestHardListenerDrainZeroGraceSendsExplicitZero(t *testing.T) {
	fake := newFakeControlClient()
	_, stderr, code := runWithFakeClient([]string{
		"listeners", "drain", "imap",
		"--mode", "hard",
		"--reason", "planned",
		"--grace-seconds", "0",
	}, fake)
	if code != 0 {
		t.Fatalf("run returned exit code %d, want 0; stderr=%q", code, stderr)
	}
	if !reflect.DeepEqual(fake.calls, []string{"DrainListener"}) {
		t.Fatalf("calls = %#v, want DrainListener", fake.calls)
	}
	if fake.listenerDrainRequest.GraceSeconds == nil {
		t.Fatal("grace_seconds was nil, want explicit zero")
	}
	if got := *fake.listenerDrainRequest.GraceSeconds; got != 0 {
		t.Fatalf("grace_seconds = %d, want 0", got)
	}
	if fake.listenerDrainRequest.Mode != generated.DrainModeHard {
		t.Fatalf("mode = %q, want hard", fake.listenerDrainRequest.Mode)
	}
	if fake.listenerDrainRequest.Reason != "planned" {
		t.Fatalf("reason = %q, want planned", fake.listenerDrainRequest.Reason)
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

	listenerFake := newFakeControlClient()
	listenerFake.getListenerStatus = http.StatusNotFound
	listenerFake.getListenerProblem = &generated.ErrorResponse{Status: http.StatusNotFound, Code: "not_found", Message: "unknown listener"}

	stdout, stderr, code = runWithFakeClient([]string{"listeners", "show", "missing"}, listenerFake)
	if code != 1 {
		t.Fatalf("listener server failure exit code = %d, want 1", code)
	}
	if stdout != "" {
		t.Fatalf("listener stdout = %q, want empty output", stdout)
	}
	if !strings.Contains(stderr, "HTTP 404: unknown listener") {
		t.Fatalf("listener stderr = %q, want stable HTTP error", stderr)
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

	listenerTextFake := newFakeControlClient()
	stdout, stderr, code = runWithFakeClient([]string{"listeners", "list"}, listenerTextFake)
	if code != 0 {
		t.Fatalf("listener text command returned exit code %d, want 0; stderr=%q", code, stderr)
	}
	wantListenerText := "name=imap protocol=imap service_name=imap-login network=tcp configured_address=127.0.0.1:1143 bound_address=127.0.0.1:1143 state=accepting active_local_sessions=1 drain_mode=\"\"\n"
	if stdout != wantListenerText {
		t.Fatalf("listener text output = %q, want %q", stdout, wantListenerText)
	}

	listenerJSONFake := newFakeControlClient()
	stdout, stderr, code = runWithFakeClient([]string{"--output", "json", "listeners", "show", "imap"}, listenerJSONFake)
	if code != 0 {
		t.Fatalf("listener json command returned exit code %d, want 0; stderr=%q", code, stderr)
	}
	wantListenerJSON := "{\n" +
		"  \"active_local_sessions\": 1,\n" +
		"  \"address\": \"127.0.0.1:1143\",\n" +
		"  \"bound_address\": \"127.0.0.1:1143\",\n" +
		"  \"implicit_tls\": false,\n" +
		"  \"name\": \"imap\",\n" +
		"  \"network\": \"tcp\",\n" +
		"  \"protocol\": \"imap\",\n" +
		"  \"proxy_protocol\": false,\n" +
		"  \"service_name\": \"imap-login\",\n" +
		"  \"state\": \"accepting\",\n" +
		"  \"tls_mode\": \"starttls\"\n" +
		"}\n"
	if stdout != wantListenerJSON {
		t.Fatalf("listener JSON output = %q, want %q", stdout, wantListenerJSON)
	}

	absentPinFake := newFakeControlClient()
	stdout, stderr, code = runWithFakeClient([]string{"users", "backend-pin", "show", "user-a"}, absentPinFake)
	if code != 0 {
		t.Fatalf("absent backend-pin command returned exit code %d, want 0; stderr=%q", code, stderr)
	}
	wantAbsentPinText := "user_key=user-a present=false backend=\"\" protocol=\"\" backend_pool=\"\" shard_tag=\"\" strategy=\"\" generation=\"\" active_session_count=\"\"\n"
	if stdout != wantAbsentPinText {
		t.Fatalf("absent backend-pin text output = %q, want %q", stdout, wantAbsentPinText)
	}

	presentPinFake := newFakeControlClient()
	pin := backendPinA()
	presentPinFake.backendPinResponse = &pin
	stdout, stderr, code = runWithFakeClient([]string{"users", "backend-pin", "show", "user-a"}, presentPinFake)
	if code != 0 {
		t.Fatalf("present backend-pin command returned exit code %d, want 0; stderr=%q", code, stderr)
	}
	wantPresentPinText := "user_key=user-a present=true backend=backend-a protocol=imap backend_pool=imap-default shard_tag=shard-a strategy=kick_existing generation=pin-gen-a active_session_count=2\n"
	if stdout != wantPresentPinText {
		t.Fatalf("present backend-pin text output = %q, want %q", stdout, wantPresentPinText)
	}

	jsonPinFake := newFakeControlClient()
	pin = backendPinA()
	jsonPinFake.backendPinResponse = &pin
	stdout, stderr, code = runWithFakeClient([]string{"--output", "json", "users", "backend-pin", "show", "user-a"}, jsonPinFake)
	if code != 0 {
		t.Fatalf("backend-pin json command returned exit code %d, want 0; stderr=%q", code, stderr)
	}
	wantPinJSON := "{\n" +
		"  \"active_session_count\": 2,\n" +
		"  \"backend\": \"backend-a\",\n" +
		"  \"backend_pool\": \"imap-default\",\n" +
		"  \"generation\": \"pin-gen-a\",\n" +
		"  \"present\": true,\n" +
		"  \"protocol\": \"imap\",\n" +
		"  \"shard_tag\": \"shard-a\",\n" +
		"  \"strategy\": \"kick_existing\",\n" +
		"  \"user_key\": \"user-a\"\n" +
		"}\n"
	if stdout != wantPinJSON {
		t.Fatalf("backend-pin JSON output = %q, want %q", stdout, wantPinJSON)
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
		"listeners list",
		"listeners drain",
		"listeners resume",
		"config dump -d",
		"config dump -n",
		"sessions kill",
		"users affinity set",
		"users backend-pin set",
		"commissioning",
		"runtime summary",
		"route lookup",
		"reload",
		"--address",
		"--timeout",
		"--output",
		"EXIT STATUS",
		"protected config output",
		"process-local",
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
	listUsersParams        *generated.ListUsersParams
	listSessionsHistory    []generated.ListSessionsParams
	listUsersHistory       []generated.ListUsersParams
	listSessionPages       []generated.SessionListResponse
	listUserPages          []generated.UserListResponse
	listSessionsCalls      int
	listUsersCalls         int
	runtimeSummary         *generated.RuntimeSummaryResponse
	routeRequest           generated.RouteLookupRequest
	listenerDrainRequest   generated.ListenerDrainRequest
	listenerResumeRequest  generated.ListenerResumeRequest
	backendPinResponse     *generated.UserBackendPin
	setBackendPinUserKey   generated.UserKey
	setBackendPinRequest   generated.UserBackendPinRequest
	clearBackendPinUserKey generated.UserKey
	clearBackendPinRequest generated.UserBackendPinClearRequest
	defaultConfigStatus    int
	defaultConfigProblem   *generated.ErrorResponse
	getBackendStatus       int
	getBackendProblem      *generated.ErrorResponse
	getListenerStatus      int
	getListenerProblem     *generated.ErrorResponse
}

// newFakeControlClient creates a fake generated client with successful defaults.
func newFakeControlClient() *fakeControlClient {
	return &fakeControlClient{
		defaultConfigStatus: http.StatusOK,
		getBackendStatus:    http.StatusOK,
		getListenerStatus:   http.StatusOK,
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

// listenerA returns a stable listener fixture.
func listenerA() generated.ListenerDetail {
	boundAddress := "127.0.0.1:1143"

	return generated.ListenerDetail{
		ActiveLocalSessions: 1,
		Address:             "127.0.0.1:1143",
		BoundAddress:        &boundAddress,
		ImplicitTLS:         false,
		Name:                "imap",
		Network:             "tcp",
		Protocol:            "imap",
		ProxyProtocol:       false,
		ServiceName:         "imap-login",
		State:               generated.Accepting,
		TLSMode:             "starttls",
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

// sessionB returns a second stable session fixture.
func sessionB() generated.SessionDetail {
	session := sessionA()
	session.Backend = "backend-b"
	session.SessionID = "session-b"
	session.ShardTag = "shard-b"

	return session
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

// backendPinA returns a stable present backend-pin fixture.
func backendPinA() generated.UserBackendPin {
	activeSessionCount := 2
	backend := "backend-a"
	backendPool := "imap-default"
	generation := "pin-gen-a"
	protocol := "imap"
	shardTag := "shard-a"
	strategy := generated.KickExisting

	return generated.UserBackendPin{
		ActiveSessionCount: &activeSessionCount,
		Backend:            &backend,
		BackendPool:        &backendPool,
		Generation:         &generation,
		Present:            true,
		Protocol:           &protocol,
		ShardTag:           &shardTag,
		Strategy:           &strategy,
		UserKey:            "user-a",
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

// userB returns a second stable user fixture.
func userB() generated.UserDetail {
	user := userA()
	user.UserKey = "user-b"

	return user
}

// runtimeSummaryFixture returns a stable aggregate summary fixture.
func runtimeSummaryFixture() generated.RuntimeSummaryResponse {
	count := func(value int, accuracy generated.RuntimeCountSummaryAccuracy) generated.RuntimeCountSummary {
		return generated.RuntimeCountSummary{Accuracy: accuracy, Count: value}
	}
	dimension := func(value string, total int) generated.RuntimeDimensionCount {
		return generated.RuntimeDimensionCount{
			Accuracy: generated.RuntimeDimensionCountAccuracyEventuallyRepaired,
			Count:    total,
			Value:    value,
		}
	}

	return generated.RuntimeSummaryResponse{
		ActiveSessions: generated.RuntimeSessionAggregateSummary{
			Total:      count(2, generated.RuntimeCountSummaryAccuracyEventuallyRepaired),
			ByProtocol: []generated.RuntimeDimensionCount{dimension("imap", 2)},
			ByListener: []generated.RuntimeDimensionCount{dimension("imap", 2)},
			ByService:  []generated.RuntimeDimensionCount{dimension("imap-login", 2)},
			ByShardTag: []generated.RuntimeDimensionCount{dimension("shard-a", 2)},
		},
		BackendCapacity: []generated.RuntimeBackendCapacitySummary{{
			ActiveSessions:    count(2, generated.RuntimeCountSummaryAccuracyEventuallyRepaired),
			Backend:           "backend-a",
			ReservedSessions:  count(2, generated.RuntimeCountSummaryAccuracyEventuallyRepaired),
			RoutingAuthority:  false,
			SummaryRepairable: true,
		}},
		GeneratedAt:    time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC),
		IdleAffinities: count(1, generated.RuntimeCountSummaryAccuracyEventuallyRepaired),
		Repairs: generated.RuntimeRepairSummary{
			BackendReservations: count(1, generated.RuntimeCountSummaryAccuracyCumulative),
			ExpiredSessions:     count(3, generated.RuntimeCountSummaryAccuracyCumulative),
			StaleIndexEntries:   count(2, generated.RuntimeCountSummaryAccuracyCumulative),
		},
		RoutingAuthority: false,
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

// ListListenersWithResponse records and returns listener list data.
func (fake *fakeControlClient) ListListenersWithResponse(context.Context, ...generated.RequestEditorFn) (*generated.ListListenersResponse, error) {
	fake.record("ListListeners")
	return &generated.ListListenersResponse{
		HTTPResponse: httpResponse(http.StatusOK),
		JSON200:      &generated.ListenerListResponse{Listeners: []generated.ListenerDetail{listenerA()}},
	}, nil
}

// GetListenerWithResponse records and returns listener detail data.
func (fake *fakeControlClient) GetListenerWithResponse(context.Context, generated.ListenerName, ...generated.RequestEditorFn) (*generated.GetListenerResponse, error) {
	fake.record("GetListener")
	return &generated.GetListenerResponse{
		HTTPResponse: httpResponse(fake.getListenerStatus),
		JSON200:      &[]generated.ListenerDetail{listenerA()}[0],
		JSONDefault:  fake.getListenerProblem,
	}, nil
}

// DrainListenerWithBodyWithResponse records unsupported raw-body usage.
func (fake *fakeControlClient) DrainListenerWithBodyWithResponse(context.Context, generated.ListenerName, string, io.Reader, ...generated.RequestEditorFn) (*generated.DrainListenerResponse, error) {
	fake.record("DrainListenerWithBody")
	return nil, nil
}

// DrainListenerWithResponse records and returns updated listener detail.
func (fake *fakeControlClient) DrainListenerWithResponse(_ context.Context, _ generated.ListenerName, body generated.DrainListenerJSONRequestBody, _ ...generated.RequestEditorFn) (*generated.DrainListenerResponse, error) {
	fake.record("DrainListener")
	fake.listenerDrainRequest = body
	return &generated.DrainListenerResponse{HTTPResponse: httpResponse(http.StatusAccepted), JSON202: &[]generated.ListenerDetail{listenerA()}[0]}, nil
}

// ResumeListenerWithBodyWithResponse records unsupported raw-body usage.
func (fake *fakeControlClient) ResumeListenerWithBodyWithResponse(context.Context, generated.ListenerName, string, io.Reader, ...generated.RequestEditorFn) (*generated.ResumeListenerResponse, error) {
	fake.record("ResumeListenerWithBody")
	return nil, nil
}

// ResumeListenerWithResponse records and returns updated listener detail.
func (fake *fakeControlClient) ResumeListenerWithResponse(_ context.Context, _ generated.ListenerName, body generated.ResumeListenerJSONRequestBody, _ ...generated.RequestEditorFn) (*generated.ResumeListenerResponse, error) {
	fake.record("ResumeListener")
	fake.listenerResumeRequest = body
	return &generated.ResumeListenerResponse{HTTPResponse: httpResponse(http.StatusAccepted), JSON202: &[]generated.ListenerDetail{listenerA()}[0]}, nil
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
			BackendPin: generated.RouteLookupBackendPin{
				Applied: false,
				Present: false,
				Reason:  "backend_pin_absent",
			},
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
	if params != nil {
		fake.listSessionsHistory = append(fake.listSessionsHistory, *params)
	}
	page := generated.SessionListResponse{Sessions: []generated.SessionDetail{sessionA()}}
	if fake.listSessionsCalls < len(fake.listSessionPages) {
		page = fake.listSessionPages[fake.listSessionsCalls]
	}
	fake.listSessionsCalls++

	return &generated.ListSessionsResponse{
		HTTPResponse: httpResponse(http.StatusOK),
		JSON200:      &page,
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
func (fake *fakeControlClient) ListUsersWithResponse(_ context.Context, params *generated.ListUsersParams, _ ...generated.RequestEditorFn) (*generated.ListUsersResponse, error) {
	fake.record("ListUsers")
	fake.listUsersParams = params
	if params != nil {
		fake.listUsersHistory = append(fake.listUsersHistory, *params)
	}
	page := generated.UserListResponse{Users: []generated.UserDetail{userA()}}
	if fake.listUsersCalls < len(fake.listUserPages) {
		page = fake.listUserPages[fake.listUsersCalls]
	}
	fake.listUsersCalls++

	return &generated.ListUsersResponse{HTTPResponse: httpResponse(http.StatusOK), JSON200: &page}, nil
}

// GetRuntimeSummaryWithResponse records and returns aggregate runtime totals.
func (fake *fakeControlClient) GetRuntimeSummaryWithResponse(context.Context, ...generated.RequestEditorFn) (*generated.GetRuntimeSummaryResponse, error) {
	fake.record("GetRuntimeSummary")
	summary := runtimeSummaryFixture()
	if fake.runtimeSummary != nil {
		summary = *fake.runtimeSummary
	}

	return &generated.GetRuntimeSummaryResponse{HTTPResponse: httpResponse(http.StatusOK), JSON200: &summary}, nil
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

// ClearUserBackendPinWithBodyWithResponse records unsupported raw-body usage.
func (fake *fakeControlClient) ClearUserBackendPinWithBodyWithResponse(context.Context, generated.UserKey, string, io.Reader, ...generated.RequestEditorFn) (*generated.ClearUserBackendPinResponse, error) {
	fake.record("ClearUserBackendPinWithBody")
	return nil, nil
}

// ClearUserBackendPinWithResponse records and returns an accepted response.
func (fake *fakeControlClient) ClearUserBackendPinWithResponse(_ context.Context, userKey generated.UserKey, body generated.ClearUserBackendPinJSONRequestBody, _ ...generated.RequestEditorFn) (*generated.ClearUserBackendPinResponse, error) {
	fake.record("ClearUserBackendPin")
	fake.clearBackendPinUserKey = userKey
	fake.clearBackendPinRequest = body
	return &generated.ClearUserBackendPinResponse{HTTPResponse: httpResponse(http.StatusAccepted), JSON202: acceptedResponse()}, nil
}

// GetUserBackendPinWithResponse records and returns backend-pin state.
func (fake *fakeControlClient) GetUserBackendPinWithResponse(_ context.Context, userKey generated.UserKey, _ ...generated.RequestEditorFn) (*generated.GetUserBackendPinResponse, error) {
	fake.record("GetUserBackendPin")
	pin := generated.UserBackendPin{Present: false, UserKey: string(userKey)}
	if fake.backendPinResponse != nil {
		pin = *fake.backendPinResponse
	}

	return &generated.GetUserBackendPinResponse{
		HTTPResponse: httpResponse(http.StatusOK),
		JSON200:      &pin,
	}, nil
}

// SetUserBackendPinWithBodyWithResponse records unsupported raw-body usage.
func (fake *fakeControlClient) SetUserBackendPinWithBodyWithResponse(context.Context, generated.UserKey, string, io.Reader, ...generated.RequestEditorFn) (*generated.SetUserBackendPinResponse, error) {
	fake.record("SetUserBackendPinWithBody")
	return nil, nil
}

// SetUserBackendPinWithResponse records and returns an accepted response.
func (fake *fakeControlClient) SetUserBackendPinWithResponse(_ context.Context, userKey generated.UserKey, body generated.SetUserBackendPinJSONRequestBody, _ ...generated.RequestEditorFn) (*generated.SetUserBackendPinResponse, error) {
	fake.record("SetUserBackendPin")
	fake.setBackendPinUserKey = userKey
	fake.setBackendPinRequest = body
	return &generated.SetUserBackendPinResponse{HTTPResponse: httpResponse(http.StatusAccepted), JSON202: acceptedResponse()}, nil
}

// ClearUserHoldWithBodyWithResponse records unsupported raw-body usage.
func (fake *fakeControlClient) ClearUserHoldWithBodyWithResponse(context.Context, generated.UserKey, string, io.Reader, ...generated.RequestEditorFn) (*generated.ClearUserHoldResponse, error) {
	fake.record("ClearUserHoldWithBody")
	return nil, nil
}

// ClearUserHoldWithResponse records and returns an accepted response.
func (fake *fakeControlClient) ClearUserHoldWithResponse(context.Context, generated.UserKey, generated.ClearUserHoldJSONRequestBody, ...generated.RequestEditorFn) (*generated.ClearUserHoldResponse, error) {
	fake.record("ClearUserHold")
	return &generated.ClearUserHoldResponse{HTTPResponse: httpResponse(http.StatusAccepted), JSON202: acceptedResponse()}, nil
}

// GetUserHoldWithResponse records and returns absent placement-hold state.
func (fake *fakeControlClient) GetUserHoldWithResponse(_ context.Context, userKey generated.UserKey, _ ...generated.RequestEditorFn) (*generated.GetUserHoldResponse, error) {
	fake.record("GetUserHold")
	return &generated.GetUserHoldResponse{
		HTTPResponse: httpResponse(http.StatusOK),
		JSON200:      &generated.UserHold{Present: false, UserKey: string(userKey)},
	}, nil
}

// SetUserHoldWithBodyWithResponse records unsupported raw-body usage.
func (fake *fakeControlClient) SetUserHoldWithBodyWithResponse(context.Context, generated.UserKey, string, io.Reader, ...generated.RequestEditorFn) (*generated.SetUserHoldResponse, error) {
	fake.record("SetUserHoldWithBody")
	return nil, nil
}

// SetUserHoldWithResponse records and returns an accepted response.
func (fake *fakeControlClient) SetUserHoldWithResponse(context.Context, generated.UserKey, generated.SetUserHoldJSONRequestBody, ...generated.RequestEditorFn) (*generated.SetUserHoldResponse, error) {
	fake.record("SetUserHold")
	return &generated.SetUserHoldResponse{HTTPResponse: httpResponse(http.StatusAccepted), JSON202: acceptedResponse()}, nil
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
