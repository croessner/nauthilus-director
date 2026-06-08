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

usage() {
	cat <<'USAGE'
Usage: scripts/release-semver-metadata.sh <tag>

Print GitHub Actions output lines for supported release tags.
Supported tags use vMAJOR.MINOR.PATCH with an optional SemVer prerelease
suffix, for example v2.1.3, v2.1.3-rc.1, or v2.1.3-alpha.5.
USAGE
}

if [[ $# -ne 1 ]]; then
	usage >&2
	exit 1
fi

tag="$1"
semver_pattern='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?$'

if [[ ! "$tag" =~ $semver_pattern ]]; then
	printf "Unsupported release tag '%s'. Expected vMAJOR.MINOR.PATCH[-PRERELEASE].\n" "$tag" >&2
	exit 1
fi

version="${tag#v}"
base_version="${version%%-*}"
base_tag="${tag%%-*}"
prerelease=false

if [[ "$version" == *-* ]]; then
	prerelease=true
fi

IFS='.' read -r major minor patch <<<"$base_version"

printf 'tag=%s\n' "$tag"
printf 'version=%s\n' "$version"
printf 'base_version=%s\n' "$base_version"
printf 'package_version=%s\n' "${version//-/\~}"
printf 'prerelease=%s\n' "$prerelease"
printf 'tag_major=v%s\n' "$major"
printf 'tag_minor=v%s.%s\n' "$major" "$minor"
printf 'tag_patch=%s\n' "$base_tag"
printf 'major=%s\n' "$major"
printf 'minor=%s\n' "$minor"
printf 'patch=%s\n' "$patch"
