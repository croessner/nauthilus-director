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

root_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
default_output_prefix="nauthilus-director"

output_dir="${OUTPUT_DIR:-${root_dir}/sbom}"
output_prefix="${OUTPUT_PREFIX:-$default_output_prefix}"
output_prefix_set=false
source_dir="${SOURCE_DIR:-$root_dir}"
skip_source=false
file_target=""
docker_image=""
skip_docker=false
docker_pull="${DOCKER_PULL:-false}"
syft_version="${SYFT_VERSION:-v1.16.0}"
syft_bin="${SYFT_BIN:-${root_dir}/bin/syft}"

# pretty_print_json formats generated SPDX JSON when a local formatter exists.
pretty_print_json() {
	local target="$1"
	local tmp

	tmp="${target}.tmp"

	if command -v jq >/dev/null 2>&1; then
		jq . "$target" >"$tmp"
		mv "$tmp" "$target"
		return
	fi

	if command -v python3 >/dev/null 2>&1; then
		python3 -m json.tool "$target" >"$tmp"
		mv "$tmp" "$target"
		return
	fi

	if command -v python >/dev/null 2>&1; then
		python -m json.tool "$target" >"$tmp"
		mv "$tmp" "$target"
		return
	fi

	printf 'No JSON formatter found (jq/python3/python) to pretty-print %s\n' "$target" >&2
	exit 1
}

usage() {
	cat <<'USAGE'
Usage: scripts/sbom.sh [options]

Options:
  --output-dir <path>       Output directory for SBOM files (default: ./sbom)
  --output-prefix <name>    File name prefix for SBOMs (default: nauthilus-director)
  --source-dir <path>       Directory to scan (default: repo root)
  --skip-source             Skip source directory SBOM
  --file <path>             Generate SBOM for a file.
  --docker-image <image>    Generate SBOM for a Docker image.
  --docker-pull <true|false> Pull image before SBOM generation (default: false)
  --skip-docker             Skip Docker image SBOM
  --syft-version <version>  Syft version to install if missing (default: v1.16.0)
  --syft-bin <path>         Path to syft binary (default: ./bin/syft)
  -h, --help                Show this help.
USAGE
}

# ensure_syft installs a pinned Syft binary into the repo-local bin directory.
ensure_syft() {
	if [[ -x "$syft_bin" ]]; then
		return
	fi

	if ! command -v curl >/dev/null 2>&1; then
		printf 'curl is required to install syft\n' >&2
		exit 1
	fi

	mkdir -p "$(dirname -- "$syft_bin")"

	curl -sSfL "https://raw.githubusercontent.com/anchore/syft/${syft_version}/install.sh" \
		| sh -s -- -b "$(dirname -- "$syft_bin")" "$syft_version"

	if [[ ! -x "$syft_bin" ]]; then
		printf 'syft installation failed\n' >&2
		exit 1
	fi
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--output-dir)
			output_dir="$2"
			shift 2
			;;
		--output-prefix)
			output_prefix="$2"
			output_prefix_set=true
			shift 2
			;;
		--source-dir)
			source_dir="$2"
			shift 2
			;;
		--skip-source)
			skip_source=true
			shift
			;;
		--file)
			file_target="$2"
			shift 2
			;;
		--docker-image)
			docker_image="$2"
			shift 2
			;;
		--docker-pull)
			docker_pull="$2"
			shift 2
			;;
		--skip-docker)
			skip_docker=true
			shift
			;;
		--syft-version)
			syft_version="$2"
			shift 2
			;;
		--syft-bin)
			syft_bin="$2"
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

if [[ -n "$file_target" && "$output_prefix_set" == false && "$output_prefix" == "$default_output_prefix" ]]; then
	output_prefix="$(basename -- "$file_target")"
fi

ensure_syft

mkdir -p "$output_dir"

if [[ "$skip_source" == false ]]; then
	if [[ ! -d "$source_dir" ]]; then
		printf 'Source directory not found: %s\n' "$source_dir" >&2
		exit 1
	fi

	"$syft_bin" "dir:${source_dir}" -o "spdx-json=${output_dir}/${output_prefix}-source.spdx.json"
	pretty_print_json "${output_dir}/${output_prefix}-source.spdx.json"
fi

if [[ -n "$file_target" ]]; then
	if [[ ! -f "$file_target" ]]; then
		printf 'File not found: %s\n' "$file_target" >&2
		exit 1
	fi

	"$syft_bin" "file:${file_target}" -o "spdx-json=${output_dir}/${output_prefix}.spdx.json"
	pretty_print_json "${output_dir}/${output_prefix}.spdx.json"
fi

if [[ "$skip_docker" == false && -n "$docker_image" ]]; then
	if ! command -v docker >/dev/null 2>&1; then
		printf 'docker is required for Docker image SBOMs\n' >&2
		exit 1
	fi

	if [[ "$docker_pull" == true ]]; then
		docker pull "$docker_image"
	fi

	"$syft_bin" "$docker_image" -o "spdx-json=${output_dir}/${output_prefix}-image.spdx.json"
	pretty_print_json "${output_dir}/${output_prefix}-image.spdx.json"
fi
