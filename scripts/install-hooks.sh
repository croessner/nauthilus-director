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

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(CDPATH='' cd -- "${script_dir}/.." && pwd)"
hooks_dir="${project_root}/.git/hooks"

if [[ ! -d "${project_root}/.git" ]]; then
	printf 'install-hooks: %s is not a Git working tree\n' "$project_root" >&2
	exit 1
fi

mkdir -p "$hooks_dir"

printf 'Installing nauthilus-director Git hooks...\n'

cat >"${hooks_dir}/pre-push" <<'HOOKEOF'
#!/usr/bin/env bash
# Pre-push hook for nauthilus-director.
# This hook runs govulncheck before publishing main or version tags.
#
# Installation:
#   Run: make install-hooks
#
# To bypass this hook temporarily (not recommended):
#   git push --no-verify

set -euo pipefail

git_root="$(git rev-parse --show-toplevel)"

exec "${git_root}/scripts/pre-push-govulncheck.sh" "$@"
HOOKEOF

chmod +x "${hooks_dir}/pre-push"
chmod +x "${project_root}/scripts/pre-push-govulncheck.sh"

printf 'Git hooks installed successfully.\n\n'
printf 'The following hook is now active:\n'
printf '  - pre-push: runs govulncheck before pushing main or version tags\n\n'
printf 'To manually validate release-sensitive pushes, run:\n'
printf '  make release-guardrails\n'
