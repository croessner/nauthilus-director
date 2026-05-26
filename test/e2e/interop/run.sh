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

containers=()
last_container=""
container_names=(
	default_a
	default_b
	shard1_a
	shard1_b
	shard2_a
	shard2_b
)

cleanup() {
	if ((${#containers[@]} > 0)); then
		"$docker_cmd" rm -f "${containers[@]}" >/dev/null 2>&1 || true
	fi
	rm -rf "$tmpdir"
}
trap cleanup EXIT HUP INT TERM

start_dovecot() {
	local name="$1"
	local container

	container="$(
		"$docker_cmd" run \
			--rm \
			--detach \
			--pull=missing \
			--hostname "nauthilus-director-e2e-dovecot-${name//_/-}" \
			--publish '127.0.0.1::31143' \
			--env "USER_PASSWORD=${interop_password}" \
			"$dovecot_image" 2>/dev/null
	)" || return 1

	containers+=("$container")
	last_container="$container"
}

declare -A container_by_name=()
for name in "${container_names[@]}"; do
	if ! start_dovecot "$name"; then
		printf 'SKIP e2e-interop: could not start pinned Dovecot image %s for %s\n' "$dovecot_image" "$name"
		exit 0
	fi
	container_by_name["$name"]="$last_container"
done

wait_mapped_dovecot() {
	local container="$1"
	local mapped=""
	local ready=""
	local host
	local port

	for _ in {1..80}; do
		mapped="$("$docker_cmd" port "$container" 31143/tcp 2>/dev/null | head -n 1 || true)"
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
		return 1
	fi

	printf '%s\n' "$mapped"
}

declare -A mapped_by_name=()
for name in "${container_names[@]}"; do
	mapped_by_name["$name"]="$(wait_mapped_dovecot "${container_by_name[$name]}")" || {
		printf 'FAIL e2e-interop: Dovecot container %s did not become IMAP-login ready on port 31143\n' "$name" >&2
		exit 1
	}
done

printf 'nauthilus-director e2e-interop: Dovecot IMAP backends mapped as default=(%s,%s), test_shard1=(%s,%s), test_shard2=(%s,%s)\n' \
	"${mapped_by_name[default_a]}" \
	"${mapped_by_name[default_b]}" \
	"${mapped_by_name[shard1_a]}" \
	"${mapped_by_name[shard1_b]}" \
	"${mapped_by_name[shard2_a]}" \
	"${mapped_by_name[shard2_b]}"

if ! "$docker_cmd" exec "${container_by_name[default_a]}" doveadm who >/dev/null 2>&1; then
	printf 'nauthilus-director e2e-interop: doveadm who is unavailable; backend identity proof will use Director state only\n'
fi

"$go_cmd" build -mod=vendor -trimpath -o "$tmpdir/nauthilus-director" ./cmd/nauthilus-director

NAUTHILUS_DIRECTOR_INTEROP_BACKEND_ADDR="${mapped_by_name[default_a]}" \
	NAUTHILUS_DIRECTOR_INTEROP_DEFAULT_A_ADDR="${mapped_by_name[default_a]}" \
	NAUTHILUS_DIRECTOR_INTEROP_DEFAULT_B_ADDR="${mapped_by_name[default_b]}" \
	NAUTHILUS_DIRECTOR_INTEROP_SHARD1_A_ADDR="${mapped_by_name[shard1_a]}" \
	NAUTHILUS_DIRECTOR_INTEROP_SHARD1_B_ADDR="${mapped_by_name[shard1_b]}" \
	NAUTHILUS_DIRECTOR_INTEROP_SHARD2_A_ADDR="${mapped_by_name[shard2_a]}" \
	NAUTHILUS_DIRECTOR_INTEROP_SHARD2_B_ADDR="${mapped_by_name[shard2_b]}" \
	NAUTHILUS_DIRECTOR_INTEROP_DOCKER="$docker_cmd" \
	NAUTHILUS_DIRECTOR_INTEROP_DEFAULT_A_CONTAINER="${container_by_name[default_a]}" \
	NAUTHILUS_DIRECTOR_INTEROP_DEFAULT_B_CONTAINER="${container_by_name[default_b]}" \
	NAUTHILUS_DIRECTOR_INTEROP_SHARD1_A_CONTAINER="${container_by_name[shard1_a]}" \
	NAUTHILUS_DIRECTOR_INTEROP_SHARD1_B_CONTAINER="${container_by_name[shard1_b]}" \
	NAUTHILUS_DIRECTOR_INTEROP_SHARD2_A_CONTAINER="${container_by_name[shard2_a]}" \
	NAUTHILUS_DIRECTOR_INTEROP_SHARD2_B_CONTAINER="${container_by_name[shard2_b]}" \
	NAUTHILUS_DIRECTOR_E2E_SERVER_BINARY="$tmpdir/nauthilus-director" \
	"$go_cmd" test -mod=vendor -tags=interop -count=1 -run 'TestDovecot(CredentialReplayInterop|ClusterRuntimeInterop)' ./test/e2e

printf 'ok e2e-interop: real server binary, six Dovecot backends, health ownership, cluster affinity and runtime control passed\n'
