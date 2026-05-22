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

repo_root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$repo_root"

go_cmd="${GO:-go}"
docker_cmd="${DOCKER:-docker}"
dovecot_image="${DOVECOT_IMAGE:-dovecot/dovecot:2.4.3-dev}"
interop_password="${NAUTHILUS_DIRECTOR_INTEROP_PASSWORD:-e2e-secret-password}"

printf 'nauthilus-director e2e-interop: using Dovecot image %s\n' "$dovecot_image"

if ! command -v "$docker_cmd" >/dev/null 2>&1; then
	printf 'SKIP e2e-interop: docker command not found\n'
	exit 0
fi

if ! "$docker_cmd" info >/dev/null 2>&1; then
	printf 'SKIP e2e-interop: docker daemon is unavailable\n'
	exit 0
fi

container_id="$(
	"$docker_cmd" run \
		--rm \
		--detach \
		--pull=missing \
		--publish '127.0.0.1::31143' \
		--env "USER_PASSWORD=${interop_password}" \
		"$dovecot_image" 2>/dev/null
)" || {
	printf 'SKIP e2e-interop: could not start pinned Dovecot image %s\n' "$dovecot_image"
	exit 0
}

cleanup() {
	"$docker_cmd" rm -f "$container_id" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

mapped=""
for _ in {1..80}; do
	mapped="$("$docker_cmd" port "$container_id" 31143/tcp 2>/dev/null | head -n 1 || true)"
	if [[ -n "$mapped" ]]; then
		host="${mapped%:*}"
		port="${mapped##*:}"
		if bash -c "</dev/tcp/${host}/${port}" >/dev/null 2>&1; then
			break
		fi
	fi
	sleep 0.25
done

if [[ -z "$mapped" ]]; then
	printf 'FAIL e2e-interop: Dovecot container did not expose IMAP port 31143\n' >&2
	exit 1
fi

printf 'nauthilus-director e2e-interop: Dovecot IMAP mapped at %s\n' "$mapped"

NAUTHILUS_DIRECTOR_INTEROP_BACKEND_ADDR="$mapped" \
	"$go_cmd" test -mod=vendor -tags=interop -count=1 -run TestDovecotCredentialReplayInterop ./test/e2e

printf 'ok e2e-interop: real Dovecot login and post-auth proxy handoff passed\n'
