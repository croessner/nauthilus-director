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
tmpdir="$(mktemp -d)"

trap 'rm -rf "$tmpdir"' EXIT HUP INT TERM

close_imap_probe() {
	{ exec 3>&-; } 2>/dev/null || true
	{ exec 3<&-; } 2>/dev/null || true
}

imap_login_ready() {
	local host="$1"
	local port="$2"
	local password="$3"
	local escaped
	local line
	local response

	escaped="${password//\\/\\\\}"
	escaped="${escaped//\"/\\\"}"
	escaped="${escaped//$'\r'/ }"
	escaped="${escaped//$'\n'/ }"

	if command -v openssl >/dev/null 2>&1; then
		response="$(
			{
				printf 'A001 LOGIN "interop-ready@example.test" "%s"\r\n' "$escaped"
				printf 'A002 LOGOUT\r\n'
			} | openssl s_client -starttls imap -connect "${host}:${port}" -servername localhost -quiet 2>/dev/null || true
		)"
		[[ "$response" == *"A001 OK"* ]]
		return
	fi

	exec 3<>"/dev/tcp/${host}/${port}" || return 1
	if ! IFS= read -r -t 2 line <&3; then
		close_imap_probe
		return 1
	fi

	if ! printf 'A001 LOGIN "interop-ready@example.test" "%s"\r\n' "$escaped" >&3; then
		close_imap_probe
		return 1
	fi

	for _ in {1..8}; do
		if ! IFS= read -r -t 2 line <&3; then
			close_imap_probe
			return 1
		fi

		case "$line" in
			A001\ OK* | A001\ *\ OK*)
				close_imap_probe
				return 0
				;;
			A001\ NO* | A001\ BAD*)
				close_imap_probe
				return 1
				;;
		esac
	done

	close_imap_probe
	return 1
}

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
	rm -rf "$tmpdir"
}
trap cleanup EXIT HUP INT TERM

mapped=""
ready=""
for _ in {1..80}; do
	mapped="$("$docker_cmd" port "$container_id" 31143/tcp 2>/dev/null | head -n 1 || true)"
	if [[ -n "$mapped" ]]; then
		host="${mapped%:*}"
		port="${mapped##*:}"
		if imap_login_ready "$host" "$port" "$interop_password"; then
			ready="yes"
			break
		fi
	fi
	sleep 0.25
done

if [[ -z "$mapped" || -z "$ready" ]]; then
	printf 'FAIL e2e-interop: Dovecot container did not become IMAP-login ready on port 31143\n' >&2
	exit 1
fi

printf 'nauthilus-director e2e-interop: Dovecot IMAP mapped at %s\n' "$mapped"

"$go_cmd" build -mod=vendor -trimpath -o "$tmpdir/nauthilus-director" ./cmd/nauthilus-director

NAUTHILUS_DIRECTOR_INTEROP_BACKEND_ADDR="$mapped" \
	NAUTHILUS_DIRECTOR_E2E_SERVER_BINARY="$tmpdir/nauthilus-director" \
	"$go_cmd" test -mod=vendor -tags=interop -count=1 -run TestDovecotCredentialReplayInterop ./test/e2e

printf 'ok e2e-interop: real server binary, Dovecot login and post-auth proxy handoff passed\n'
