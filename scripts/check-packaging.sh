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
	printf 'check-packaging: %s\n' "$*" >&2
	exit 1
}

require_file() {
	local path="$1"

	[[ -f "$path" ]] || fail "missing required file: $path"
}

require_dir() {
	local path="$1"

	[[ -d "$path" ]] || fail "missing required directory: $path"
}

require_file "README.md"
require_file ".dockerignore"
require_file "packaging/README.md"
require_file "packaging/docker/Dockerfile"
require_file "packaging/docker/README.md"
require_file "packaging/systemd/nauthilus-director.service"
require_file "packaging/systemd/nauthilus-director.env.example"
require_file "packaging/systemd/README.md"
require_file "docs/operations/README.md"
require_file "docs/operations/production-deployment.md"
require_file "docs/config/nauthilus-director.target.yml"
require_file "docs/reference/config-defaults.yaml"
require_file "docs/reference/config-paths.md"

require_dir "packaging/docker"
require_dir "packaging/systemd"
require_dir "docs/operations"

dockerfile="packaging/docker/Dockerfile"

grep -R "Go 1.26" packaging docs/operations >/dev/null || \
	fail "production packaging docs must reference Go 1.26"

grep -R "contrib/demo-stack" README.md packaging docs/operations >/dev/null || \
	fail "production inventory must document the demo-stack boundary"

if grep -R -n -E '\bpoc/' packaging docs/operations; then
	fail "production packaging docs must not depend on archived proof-of-concept paths"
fi

grep -Eq '^check-packaging:' Makefile || \
	fail "Makefile is missing check-packaging target"

grep -Eq '^docker-build:' Makefile || \
	fail "Makefile is missing docker-build target"

grep -Eq '^docker-smoke:' Makefile || \
	fail "Makefile is missing docker-smoke target"

grep -Eq '^systemd-verify:' Makefile || \
	fail "Makefile is missing systemd-verify target"

grep -Eq '^\.PHONY:.*\bcheck-packaging\b' Makefile || \
	fail "check-packaging must be listed in .PHONY"

grep -Eq '^\.PHONY:.*\bdocker-build\b' Makefile || \
	fail "docker-build must be listed in .PHONY"

grep -Eq '^\.PHONY:.*\bdocker-smoke\b' Makefile || \
	fail "docker-smoke must be listed in .PHONY"

grep -Eq '^\.PHONY:.*\bsystemd-verify\b' Makefile || \
	fail "systemd-verify must be listed in .PHONY"

guardrails_line="$(awk '/^guardrails:/{print; exit}' Makefile)"
[[ -n "$guardrails_line" ]] || fail "Makefile is missing guardrails target"
[[ "$guardrails_line" == *"check-packaging"* ]] || \
	fail "guardrails must include static packaging checks"

for forbidden_target in docker-build docker-check docker-smoke systemd-verify systemd-install; do
	if [[ "$guardrails_line" == *"$forbidden_target"* ]]; then
		fail "guardrails must not depend on host-specific target: $forbidden_target"
	fi
done

target_block="$(
	awk '
		/^check-packaging:/ { in_target = 1; print; next }
		/^[[:alnum:]_.-]+:/ && in_target { exit }
		in_target { print }
	' Makefile
)"

if grep -Eq '\b(docker|systemctl|systemd-analyze)\b' <<<"$target_block"; then
	fail "check-packaging target must not call Docker or systemd tooling"
fi

grep -Eq '^ARG GO_IMAGE=.*1\.26' "$dockerfile" || \
	fail "production Dockerfile must use a Go 1.26 build stage"

grep -Eq '^FROM[[:space:]]+--platform=\$BUILDPLATFORM[[:space:]]+\$\{GO_IMAGE\}[[:space:]]+AS[[:space:]]+builder[[:space:]]*$' "$dockerfile" || \
	fail "production Dockerfile builder stage must run on BUILDPLATFORM for cross-compiled multi-arch builds"

grep -Eq '^FROM[[:space:]]+--platform=\$BUILDPLATFORM[[:space:]]+\$\{CERTS_IMAGE\}[[:space:]]+AS[[:space:]]+runtime-files[[:space:]]*$' "$dockerfile" || \
	fail "production Dockerfile runtime-files stage must run on BUILDPLATFORM for multi-arch builds"

grep -F -- "-mod=vendor" "$dockerfile" >/dev/null || \
	fail "production Dockerfile must build with vendored dependencies"

grep -Eq '^[[:space:]]*COPY[[:space:]].*vendor' "$dockerfile" || \
	fail "production Dockerfile must copy vendor/ into the build stage"

grep -Eq '^USER[[:space:]]+[1-9][0-9]*(:[1-9][0-9]*)?[[:space:]]*$' "$dockerfile" || \
	fail "production Dockerfile must run as a non-root user"

grep -Eq '^ARG RUNTIME_IMAGE=scratch[[:space:]]*$' "$dockerfile" || \
	fail "production Dockerfile must default to a scratch runtime image"

for label in version revision created source licenses; do
	grep -F "org.opencontainers.image.$label" "$dockerfile" >/dev/null || \
		fail "production Dockerfile is missing OCI label: $label"
done

while IFS= read -r line; do
	case "$line" in
		ARG\ *IMAGE=*)
			value="${line#*=}"
			value="${value%% *}"
			value="${value%%	*}"
			[[ "$value" != *:latest ]] || fail "production Dockerfile must not use mutable latest base tags: $line"
			[[ "$value" == "scratch" || "$value" == *:* ]] || \
				fail "production Dockerfile base image must be explicit or scratch: $line"
			;;
	esac
done < "$dockerfile"

if grep -nE '^[[:space:]]*FROM[[:space:]].*:latest([[:space:]]|$)' "$dockerfile"; then
	fail "production Dockerfile must not use mutable latest FROM tags"
fi

copy_violation=0
while IFS= read -r line; do
	if [[ "$line" =~ ^[[:space:]]*(COPY|ADD)[[:space:]] ]]; then
		for forbidden in ".git" "poc" "temp" "contrib/demo-stack" "entrypoint.sh" "generate-grpc-tls.sh"; do
			if [[ "$line" == *"$forbidden"* ]]; then
				printf 'check-packaging: forbidden production Dockerfile copy: %s\n' "$line" >&2
				copy_violation=1
			fi
		done
	fi
done < "$dockerfile"
[[ "$copy_violation" -eq 0 ]] || fail "production Dockerfile must not copy source-only or demo-only paths"

if grep -nE 'contrib/demo-stack|entrypoint\.sh|generate-[[:alnum:]_-]*tls\.sh' "$dockerfile"; then
	fail "production Dockerfile must not depend on demo-stack entrypoints or TLS helpers"
fi

for ignored_path in '\.git' 'temp' 'poc' 'contrib/demo-stack'; do
	display_path="${ignored_path//\\/}"
	if [[ "$display_path" == "contrib/demo-stack" ]]; then
		grep -Eq "^${ignored_path}(/\\*)?/?$" .dockerignore || \
			fail ".dockerignore must exclude $display_path"
	else
		grep -Eq "^${ignored_path}/?$" .dockerignore || \
			fail ".dockerignore must exclude $display_path"
	fi
done

unit_file="packaging/systemd/nauthilus-director.service"
env_example="packaging/systemd/nauthilus-director.env.example"

require_unit_field() {
	local field="$1"

	grep -Fx "$field" "$unit_file" >/dev/null || \
		fail "systemd unit is missing required field: $field"
}

require_unit_pattern() {
	local pattern="$1"
	local description="$2"

	grep -Eq "$pattern" "$unit_file" || \
		fail "systemd unit is missing required field: $description"
}

require_unit_field "User=nauthilus-director"
require_unit_field "Group=nauthilus-director"
require_unit_field "RuntimeDirectory=nauthilus-director"
require_unit_field "Restart=on-failure"
require_unit_field "NoNewPrivileges=true"
require_unit_field "PrivateTmp=true"
require_unit_field "ProtectSystem=strict"
require_unit_field "ProtectHome=true"
require_unit_field "KillSignal=SIGTERM"
require_unit_field "EnvironmentFile=-/etc/default/nauthilus-director"

require_unit_pattern '^ExecStart=/usr/local/bin/nauthilus-director --config /etc/nauthilus-director/nauthilus-director\.yml serve$' \
	"production ExecStart path"
require_unit_pattern '^ExecReload=/usr/local/bin/nauthilus-directorctl .* reload$' \
	"public nauthilus-directorctl reload path"

if grep -Eq '^ExecReload=.*(SIGHUP|HUP|kill|systemctl)' "$unit_file"; then
	fail "systemd ExecReload must use the public control-plane reload command"
fi

if grep -Eq '^KillSignal=SIGHUP$' "$unit_file"; then
	fail "systemd unit must not use KillSignal=SIGHUP as reload"
fi

if grep -R -n -E 'Authorization:|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|(^|[[:space:]])(--token|--password|--bearer)([=[:space:]]|$)|(^|[[:space:]])(PASSWORD|TOKEN|SECRET|BEARER)=[^/$<{[:space:]#]' "$unit_file" "$env_example"; then
	fail "systemd artifacts must not embed literal secret material"
fi

while IFS= read -r line; do
	[[ -n "$line" && "$line" != \#* ]] || continue
	key="${line%%=*}"
	value="${line#*=}"
	if [[ "$key" =~ (PASSWORD|TOKEN|SECRET|BEARER) && "$key" != *_FILE ]]; then
		fail "systemd env example secret-like keys must point to files: $key"
	fi
	if [[ "$key" =~ _FILE$ && "$value" != /* && "$value" != \$\{* ]]; then
		fail "systemd env example file variables must use absolute paths or placeholders: $key"
	fi
done < "$env_example"

grep -R "systemctl reload" packaging/systemd/README.md docs/operations/production-deployment.md >/dev/null || \
	fail "systemd docs must document reload"

grep -R "restart-required" packaging/systemd/README.md docs/operations/production-deployment.md >/dev/null || \
	fail "systemd docs must document restart-required changes"

grep -R -E "rejected reload|reload is rejected|A rejected reload" packaging/systemd/README.md docs/operations/production-deployment.md >/dev/null || \
	fail "systemd docs must document safe reload rejection behavior"

printf 'check-packaging: production inventory is present and guardrails remains host-independent\n'
