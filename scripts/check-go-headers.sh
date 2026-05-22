#!/bin/sh
#
# Copyright (C) 2026 Christian Rößner
#
# SPDX-License-Identifier: AGPL-3.0-only
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, version 3 of the License.

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
file_list="${TMPDIR:-/tmp}/nauthilus-director-go-headers.$$"
unsorted_list="${file_list}.unsorted"

trap 'rm -f "$file_list" "$unsorted_list"' EXIT HUP INT TERM

find "$repo_root" -name '*.go' \
	-not -path "$repo_root/vendor/*" \
	-not -path "$repo_root/poc/*" \
	-not -path "$repo_root/temp/*" \
	-print >"$unsorted_list"
sort "$unsorted_list" >"$file_list"

missing=0

while IFS= read -r file; do
	if sed -n '1,20p' "$file" | grep -Eq '^// Code generated .* DO NOT EDIT\.$'; then
		continue
	fi

	rel=${file#"$repo_root"/}

	if ! sed -n '1,20p' "$file" | grep -Fq 'Copyright (C) 2026 Christian Rößner'; then
		printf 'missing copyright header: %s\n' "$rel" >&2
		missing=1
	fi

	if ! sed -n '1,20p' "$file" | grep -Fq 'SPDX-License-Identifier: AGPL-3.0-only'; then
		printf 'missing SPDX license header: %s\n' "$rel" >&2
		missing=1
	fi

	if ! sed -n '1,20p' "$file" | grep -Fq 'GNU Affero General Public License'; then
		printf 'missing AGPL notice header: %s\n' "$rel" >&2
		missing=1
	fi
done <"$file_list"

if [ "$missing" -ne 0 ]; then
	exit 1
fi
