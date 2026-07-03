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

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"

fail() {
	printf 'check-release-hardening: %s\n' "$*" >&2
	exit 1
}

require_file() {
	local path="$1"

	[[ -f "$path" ]] || fail "missing required file: $path"
}

require_contains() {
	local path="$1"
	local pattern="$2"
	local description="$3"

	grep -Eq "$pattern" "$path" || fail "$description"
}

require_file "scripts/sbom.sh"
require_file "contrib/demo-stack/Dockerfile.stalwart-cli"
require_file ".github/workflows/guardrails.yaml"
require_file ".github/workflows/build-stable.yaml"
require_file ".github/workflows/docker-stable.yaml"
require_file ".github/workflows/docker-stable-build.yaml"
require_file ".github/workflows/govulncheck-main.yaml"
require_file "Makefile"

if grep -R -n -E '(curl|wget)[^|]*\|[[:space:]]*(sh|bash)\b' \
	--exclude='check-release-hardening.sh' \
	scripts .github/workflows contrib/demo-stack; then
	fail "remote installer bytes must not be piped directly into a shell"
fi

require_contains "scripts/sbom.sh" 'checksums\.txt' \
	"scripts/sbom.sh must verify Syft release checksums"
require_contains "scripts/sbom.sh" '(sha256sum|shasum -a 256)' \
	"scripts/sbom.sh must use a SHA-256 verifier"
require_contains "contrib/demo-stack/Dockerfile.stalwart-cli" 'STALWART_CLI_INSTALLER_SHA256' \
	"demo Stalwart CLI installer must require a pinned SHA-256"
require_contains "contrib/demo-stack/Dockerfile.stalwart-cli" '(sha256sum|shasum -a 256)' \
	"demo Stalwart CLI installer must verify the downloaded installer"
require_contains ".github/workflows/guardrails.yaml" 'go install "?github\.com/golangci/golangci-lint/v2/cmd/golangci-lint@\$\{GOLANGCI_LINT_VERSION\}"?' \
	"guardrails workflow must install golangci-lint through pinned Go module verification"

require_contains ".github/workflows/docker-stable-build.yaml" 'GO_IMAGE=\$\{golang_image\}@\$\{golang_digest\}' \
	"stable Docker build must pass a digest-pinned Go builder image"
require_contains ".github/workflows/docker-stable-build.yaml" 'CERTS_IMAGE=\$\{certs_image\}@\$\{certs_digest\}' \
	"stable Docker build must pass a digest-pinned certificate-stage image"
require_contains ".github/workflows/docker-stable-build.yaml" 'CLIENT_RUNTIME_IMAGE=\$\{certs_image\}@\$\{certs_digest\}' \
	"stable Docker build must pass a digest-pinned client runtime image"

require_contains "Makefile" '^GOVULNCHECK_GOFLAGS \?= -mod=vendor$' \
	"make govulncheck must default to vendored dependency analysis"
require_contains "Makefile" 'GOFLAGS="\$\(GOVULNCHECK_GOFLAGS\)" \$\(GOVULNCHECK\)' \
	"make govulncheck must apply GOVULNCHECK_GOFLAGS"

require_contains ".github/workflows/build-stable.yaml" '^[[:space:]]{2}govulncheck:' \
	"release artifact workflow must define a govulncheck job"
require_contains ".github/workflows/build-stable.yaml" '^[[:space:]]{6}- govulncheck$' \
	"release artifact jobs must depend on govulncheck before publishing"
require_contains ".github/workflows/docker-stable.yaml" '^[[:space:]]{2}govulncheck:' \
	"Docker publishing workflow must define a govulncheck job"
require_contains ".github/workflows/docker-stable.yaml" '^[[:space:]]{4}needs: govulncheck$' \
	"Docker publishing workflow must require govulncheck before the reusable build"
require_contains ".github/workflows/govulncheck-main.yaml" "^[[:space:]]{6}- 'v\\*'$" \
	"govulncheck main workflow must also run for v* tag pushes"

printf 'check-release-hardening: release supply-chain guardrails are present\n'
