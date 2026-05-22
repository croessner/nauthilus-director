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

repo_root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

go_cmd="${GO:-go}"
tmpdir="$(mktemp -d)"

trap 'rm -rf "$tmpdir"' EXIT HUP INT TERM

printf 'nauthilus-director e2e: starting deterministic fake-service guardrail lane\n'
printf 'nauthilus-director e2e: public sockets only for externally visible behavior\n'
printf 'nauthilus-director e2e: credentials, SASL blobs and bearer material must remain redacted\n'

expected_paths=(
	"test/e2e/README.md"
	"test/e2e/fakes/nauthilus_http/README.md"
	"test/e2e/fakes/nauthilus_grpc/README.md"
	"test/e2e/fakes/imap_backend/README.md"
	"test/e2e/fakes/lmtp_backend/README.md"
	"test/e2e/fakes/managesieve_backend/README.md"
	"test/e2e/fakes/pop3_backend/README.md"
	"test/e2e/interop/README.md"
)

for path in "${expected_paths[@]}"; do
	if [[ ! -f "$path" ]]; then
		printf 'FAIL e2e: required scaffold file is missing: %s\n' "$path" >&2
		exit 1
	fi
done

printf 'ok e2e: required fake-service and interoperability scaffold files exist\n'

"$go_cmd" test -mod=vendor -count=1 ./test/e2e

printf 'ok e2e: fake Nauthilus HTTP authority, scaffolded gRPC authority, fake IMAP backend, TLS and observability checks passed\n'

"$go_cmd" run -mod=vendor ./cmd/nauthilus-director --version >"$tmpdir/nauthilus-director.version"
"$go_cmd" run -mod=vendor ./cmd/nauthilus-directorctl --version >"$tmpdir/nauthilus-directorctl.version"

if ! grep -Eq '^nauthilus-director .+' "$tmpdir/nauthilus-director.version"; then
	printf 'FAIL e2e: nauthilus-director --version returned unexpected output\n' >&2
	exit 1
fi

if ! grep -Eq '^nauthilus-directorctl .+' "$tmpdir/nauthilus-directorctl.version"; then
	printf 'FAIL e2e: nauthilus-directorctl --version returned unexpected output\n' >&2
	exit 1
fi

printf 'ok e2e: server and CLI version commands run as real processes\n'
printf 'nauthilus-director e2e: completed deterministic fake-service checks\n'
