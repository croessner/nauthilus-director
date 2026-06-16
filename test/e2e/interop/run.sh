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
dovecot_image="${DOVECOT_IMAGE:-dovecot/dovecot:2.4.4}"
interop_password="${NAUTHILUS_DIRECTOR_INTEROP_PASSWORD:-e2e-secret-password}"
interop_master_password="${NAUTHILUS_DIRECTOR_INTEROP_MASTER_PASSWORD:-$interop_password}"
tmpdir="$(mktemp -d)"

trap 'rm -rf "$tmpdir"' EXIT HUP INT TERM

close_imap_probe() {
	{ exec 3>&-; } 2>/dev/null || true
	{ exec 3<&-; } 2>/dev/null || true
}

close_sieve_probe() {
	{ exec 4>&-; } 2>/dev/null || true
	{ exec 4<&-; } 2>/dev/null || true
}

close_pop3_probe() {
	{ exec 5>&-; } 2>/dev/null || true
	{ exec 5<&-; } 2>/dev/null || true
}

lmtp_backend_ready() {
	local host="$1"
	local port="$2"
	local response

	if command -v openssl >/dev/null 2>&1; then
		response="$(
			{
				printf 'LHLO interop-ready.example\r\n'
				printf 'QUIT\r\n'
			} | openssl s_client -connect "${host}:${port}" -servername localhost -quiet 2>/dev/null || true
		)"
		[[ "$response" == *"220 "* && "$response" == *"250 "* ]]
		return
	fi

	exec 6<>"/dev/tcp/${host}/${port}" || return 1
	{ exec 6>&-; } 2>/dev/null || true
	{ exec 6<&-; } 2>/dev/null || true
	return 0
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

sieve_tcp_ready() {
	local host="$1"
	local port="$2"

	exec 4<>"/dev/tcp/${host}/${port}" || return 1
	close_sieve_probe
	return 0
}

pop3_login_ready() {
	local host="$1"
	local port="$2"
	local password="$3"
	local escaped
	local response
	local line

	escaped="${password//\\/\\\\}"
	escaped="${escaped//\"/\\\"}"
	escaped="${escaped//$'\r'/ }"
	escaped="${escaped//$'\n'/ }"

	if command -v openssl >/dev/null 2>&1; then
		response="$(
			{
				printf 'USER interop-ready@example.test\r\n'
				printf 'PASS %s\r\n' "$escaped"
				printf 'QUIT\r\n'
			} | openssl s_client -starttls pop3 -connect "${host}:${port}" -servername localhost -quiet 2>/dev/null || true
		)"
		[[ "$response" == *"+OK Logged"* ]]
		return
	fi

	exec 5<>"/dev/tcp/${host}/${port}" || return 1
	if ! IFS= read -r -t 2 line <&5; then
		close_pop3_probe
		return 1
	fi

	if ! printf 'USER interop-ready@example.test\r\nPASS %s\r\nQUIT\r\n' "$escaped" >&5; then
		close_pop3_probe
		return 1
	fi

	for _ in {1..8}; do
		if ! IFS= read -r -t 2 line <&5; then
			close_pop3_probe
			return 1
		fi

		case "$line" in
			+OK\ Logged*)
				close_pop3_probe
				return 0
				;;
			-ERR*)
				close_pop3_probe
				return 1
				;;
		esac
	done

	close_pop3_probe
	return 1
}

dovecot_master_config="$tmpdir/99-nauthilus-director-master.conf"
dovecot_protocols_config="$tmpdir/98-nauthilus-director-protocols.conf"
cat >"$dovecot_protocols_config" <<'DOVECOT_PROTOCOLS_CONF'
protocols = imap pop3 submission lmtp sieve
DOVECOT_PROTOCOLS_CONF

cat >"$dovecot_master_config" <<'DOVECOT_MASTER_CONF'
import_environment {
  USER_PASSWORD = %{env:USER_PASSWORD | default('e2e-secret-password')}
  DOVECOT_MASTER_PASSWORD = %{env:DOVECOT_MASTER_PASSWORD | default('e2e-secret-password')}
}

auth_master_user_separator = *

passdb master {
  driver = static
  username_filter = nauthilus-director
  static_password = $ENV:DOVECOT_MASTER_PASSWORD
  master = yes
  result_success = continue
}

passdb users {
  driver = static
  static_password = $ENV:USER_PASSWORD
}
DOVECOT_MASTER_CONF

printf 'nauthilus-director e2e-interop: using Dovecot image %s\n' "$dovecot_image"
printf 'nauthilus-director e2e-interop: fake Nauthilus requires OIDC Bearer caller auth for authority requests\n'

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
			--publish '127.0.0.1::31024' \
			--publish '127.0.0.1::34190' \
			--publish '127.0.0.1::31110' \
			--env "USER_PASSWORD=${interop_password}" \
			--env "DOVECOT_MASTER_PASSWORD=${interop_master_password}" \
			--volume "${dovecot_protocols_config}:/etc/dovecot/conf.d/98-nauthilus-director-protocols.conf:ro" \
			--volume "${dovecot_master_config}:/etc/dovecot/conf.d/99-nauthilus-director-master.conf:ro" \
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
declare -A mapped_lmtp_by_name=()
declare -A mapped_sieve_by_name=()
declare -A mapped_pop3_by_name=()
sieve_interop_available="yes"
pop3_interop_available="yes"
for name in "${container_names[@]}"; do
	mapped_by_name["$name"]="$(wait_mapped_dovecot "${container_by_name[$name]}")" || {
		printf 'FAIL e2e-interop: Dovecot container %s did not become IMAP-login ready on port 31143\n' "$name" >&2
		exit 1
	}
	for _ in {1..80}; do
		mapped_lmtp_by_name["$name"]="$("$docker_cmd" port "${container_by_name[$name]}" 31024/tcp 2>/dev/null | head -n 1 || true)"
		if [[ -n "${mapped_lmtp_by_name[$name]}" ]]; then
			host="${mapped_lmtp_by_name[$name]%:*}"
			port="${mapped_lmtp_by_name[$name]##*:}"
			if lmtp_backend_ready "$host" "$port"; then
				break
			fi
		fi
		mapped_lmtp_by_name["$name"]=""
		sleep 0.25
	done
	if [[ -z "${mapped_lmtp_by_name[$name]}" ]]; then
		printf 'FAIL e2e-interop: Dovecot container %s did not expose ready LMTP port 31024\n' "$name" >&2
		exit 1
	fi

	for _ in {1..80}; do
		mapped_sieve_by_name["$name"]="$("$docker_cmd" port "${container_by_name[$name]}" 34190/tcp 2>/dev/null | head -n 1 || true)"
		if [[ -n "${mapped_sieve_by_name[$name]}" ]]; then
			host="${mapped_sieve_by_name[$name]%:*}"
			port="${mapped_sieve_by_name[$name]##*:}"
			if sieve_tcp_ready "$host" "$port"; then
				break
			fi
		fi
		mapped_sieve_by_name["$name"]=""
		sleep 0.25
	done

	for _ in {1..80}; do
		mapped_pop3_by_name["$name"]="$("$docker_cmd" port "${container_by_name[$name]}" 31110/tcp 2>/dev/null | head -n 1 || true)"
		if [[ -n "${mapped_pop3_by_name[$name]}" ]]; then
			host="${mapped_pop3_by_name[$name]%:*}"
			port="${mapped_pop3_by_name[$name]##*:}"
			if pop3_login_ready "$host" "$port" "$interop_password"; then
				break
			fi
		fi
		mapped_pop3_by_name["$name"]=""
		sleep 0.25
	done
done

if [[ -z "${mapped_sieve_by_name[default_a]}" || -z "${mapped_sieve_by_name[default_b]}" ]]; then
	sieve_interop_available="no"
	printf 'SKIP e2e-interop ManageSieve scenario: Dovecot image %s did not expose ready ManageSieve port 34190 for both default backends; IMAP and LMTP interop lanes continue\n' "$dovecot_image"
fi
if [[ -z "${mapped_pop3_by_name[default_a]}" ]]; then
	pop3_interop_available="no"
	printf 'SKIP e2e-interop POP3 scenario: Dovecot image %s did not expose ready POP3 port 31110 for default_a; IMAP, LMTP and ManageSieve interop lanes continue\n' "$dovecot_image"
fi

printf 'nauthilus-director e2e-interop: Dovecot IMAP backends mapped as default=(%s,%s), test_shard1=(%s,%s), test_shard2=(%s,%s)\n' \
	"${mapped_by_name[default_a]}" \
	"${mapped_by_name[default_b]}" \
	"${mapped_by_name[shard1_a]}" \
	"${mapped_by_name[shard1_b]}" \
	"${mapped_by_name[shard2_a]}" \
	"${mapped_by_name[shard2_b]}"
printf 'nauthilus-director e2e-interop: Dovecot LMTP backends mapped as default=(%s,%s)\n' \
	"${mapped_lmtp_by_name[default_a]}" \
	"${mapped_lmtp_by_name[default_b]}"
if [[ "$sieve_interop_available" == "yes" ]]; then
	printf 'nauthilus-director e2e-interop: Dovecot ManageSieve backends mapped as default=(%s,%s)\n' \
		"${mapped_sieve_by_name[default_a]}" \
		"${mapped_sieve_by_name[default_b]}"
fi
if [[ "$pop3_interop_available" == "yes" ]]; then
	printf 'nauthilus-director e2e-interop: Dovecot POP3 backend mapped as default_a=%s\n' \
		"${mapped_pop3_by_name[default_a]}"
fi

if ! "$docker_cmd" exec "${container_by_name[default_a]}" doveadm who >/dev/null 2>&1; then
	printf 'nauthilus-director e2e-interop: doveadm who is unavailable; backend identity proof will use Director state only\n'
fi

"$go_cmd" build -mod=vendor -trimpath -o "$tmpdir/nauthilus-director" ./cmd/nauthilus-director

NAUTHILUS_DIRECTOR_INTEROP_BACKEND_ADDR="${mapped_by_name[default_a]}" \
	NAUTHILUS_DIRECTOR_INTEROP_DEFAULT_A_ADDR="${mapped_by_name[default_a]}" \
	NAUTHILUS_DIRECTOR_INTEROP_DEFAULT_B_ADDR="${mapped_by_name[default_b]}" \
	NAUTHILUS_DIRECTOR_INTEROP_DEFAULT_A_LMTP_ADDR="${mapped_lmtp_by_name[default_a]}" \
	NAUTHILUS_DIRECTOR_INTEROP_DEFAULT_B_LMTP_ADDR="${mapped_lmtp_by_name[default_b]}" \
	NAUTHILUS_DIRECTOR_INTEROP_DEFAULT_A_SIEVE_ADDR="${mapped_sieve_by_name[default_a]:-}" \
	NAUTHILUS_DIRECTOR_INTEROP_DEFAULT_B_SIEVE_ADDR="${mapped_sieve_by_name[default_b]:-}" \
	NAUTHILUS_DIRECTOR_INTEROP_DEFAULT_A_POP3_ADDR="${mapped_pop3_by_name[default_a]:-}" \
	NAUTHILUS_DIRECTOR_INTEROP_MASTER_PASSWORD="$interop_master_password" \
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
	"$go_cmd" test -mod=vendor -tags=interop -count=1 -run 'TestDovecot(CredentialReplayInterop|ClusterRuntimeInterop|LMTPInterop|ManageSieveInterop|POP3Interop)' ./test/e2e

printf 'SKIP e2e-interop multi-protocol backend-node pin proof: current Docker topology does not expose one canary backend node with matching IMAP, ManageSieve and LMTP services\n'
printf 'ok e2e-interop: OIDC Bearer caller-auth proof, real server binary, six Dovecot IMAP backends, Dovecot LMTP backend, Dovecot ManageSieve and POP3 backends when available, swaks-to-Postfix submitter, curl IMAP delivery proof, health ownership, cluster affinity and runtime control passed\n'
