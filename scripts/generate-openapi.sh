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
go_cmd="${GO:-go}"

if ! grep -Fq "github.com/oapi-codegen/oapi-codegen/v2 ${generator_version}" go.mod; then
	printf 'expected %s %s to be pinned in go.mod\n' "$generator" "$generator_version" >&2
	exit 1
fi

"$go_cmd" run -mod=vendor "$generator" --config "$server_config" "$spec"
"$go_cmd" run -mod=vendor "$generator" --config "$client_config" "$spec"
