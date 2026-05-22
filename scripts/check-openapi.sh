#!/usr/bin/env bash
#
# Copyright (C) 2026 Christian Rößner
#
# SPDX-License-Identifier: AGPL-3.0-only
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, version 3 of the License.

set -euo pipefail

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"

generator="github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen"
generator_version="v2.7.0"
spec="docs/specs/openapi/nauthilus-director.yaml"
server_config="docs/specs/openapi/oapi-codegen.server.yml"
client_config="docs/specs/openapi/oapi-codegen.client.yml"
server_output="internal/rest/generated/server.gen.go"
client_output="internal/client/generated/client.gen.go"
go_cmd="${GO:-go}"
tmpdir="$(mktemp -d)"

trap 'rm -rf "$tmpdir"' EXIT HUP INT TERM

if ! grep -Fq "github.com/oapi-codegen/oapi-codegen/v2 ${generator_version}" go.mod; then
	printf 'expected %s %s to be pinned in go.mod\n' "$generator" "$generator_version" >&2
	exit 1
fi

rewrite_output() {
	local source_config=$1
	local output_path=$2
	local target_config=$3

	awk -v output="$output_path" '
		/^output:/ {
			print "output: " output
			next
		}
		{ print }
	' "$source_config" >"$target_config"
}

rewrite_output "$server_config" "$tmpdir/server.gen.go" "$tmpdir/server.yml"
rewrite_output "$client_config" "$tmpdir/client.gen.go" "$tmpdir/client.yml"

"$go_cmd" run -mod=vendor "$generator" --config "$tmpdir/server.yml" "$spec"
"$go_cmd" run -mod=vendor "$generator" --config "$tmpdir/client.yml" "$spec"

stale=0

if ! cmp -s "$tmpdir/server.gen.go" "$server_output"; then
	printf 'stale generated OpenAPI server output: run make generate-openapi\n' >&2
	diff -u "$server_output" "$tmpdir/server.gen.go" | sed -n '1,160p' >&2
	stale=1
fi

if ! cmp -s "$tmpdir/client.gen.go" "$client_output"; then
	printf 'stale generated OpenAPI client output: run make generate-openapi\n' >&2
	diff -u "$client_output" "$tmpdir/client.gen.go" | sed -n '1,160p' >&2
	stale=1
fi

exit "$stale"
