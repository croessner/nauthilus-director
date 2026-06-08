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

image=""
expected_certs_digest=""
expected_golang_digest=""

usage() {
	cat <<'USAGE'
Usage: scripts/docker-stable-refresh-check.sh [options]

Options:
  --image <image>                      Stable image tag to inspect.
  --expected-certs-digest <digest>     Current certificate-stage base image digest.
  --expected-golang-digest <digest>    Current Go builder image digest.
  -h, --help                           Show this help.
USAGE
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--image)
			image="$2"
			shift 2
			;;
		--expected-certs-digest)
			expected_certs_digest="$2"
			shift 2
			;;
		--expected-golang-digest)
			expected_golang_digest="$2"
			shift 2
			;;
		-h | --help)
			usage
			exit 0
			;;
		*)
			printf 'Unknown argument: %s\n' "$1" >&2
			usage >&2
			exit 1
			;;
	esac
done

if [[ -z "$image" || -z "$expected_certs_digest" || -z "$expected_golang_digest" ]]; then
	usage >&2
	exit 1
fi

if ! docker pull "$image" >/dev/null 2>&1; then
	printf 'reason=image-missing\n'
	printf 'should_rebuild=true\n'
	exit 0
fi

existing_certs_digest="$(
	docker inspect --format '{{ index .Config.Labels "io.nauthilus.director.base.certs.digest" }}' "$image" 2>/dev/null || true
)"
existing_golang_digest="$(
	docker inspect --format '{{ index .Config.Labels "io.nauthilus.director.base.golang.digest" }}' "$image" 2>/dev/null || true
)"

printf 'existing_certs_digest=%s\n' "$existing_certs_digest"
printf 'existing_golang_digest=%s\n' "$existing_golang_digest"

if [[ -z "$existing_certs_digest" || -z "$existing_golang_digest" ]]; then
	printf 'reason=missing-base-digest-labels\n'
	printf 'should_rebuild=true\n'
	exit 0
fi

if [[ "$existing_certs_digest" != "$expected_certs_digest" ]]; then
	printf 'reason=certs-digest-changed\n'
	printf 'should_rebuild=true\n'
	exit 0
fi

if [[ "$existing_golang_digest" != "$expected_golang_digest" ]]; then
	printf 'reason=golang-digest-changed\n'
	printf 'should_rebuild=true\n'
	exit 0
fi

printf 'reason=up-to-date\n'
printf 'should_rebuild=false\n'
