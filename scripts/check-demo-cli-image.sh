#!/usr/bin/env bash
# Copyright (C) 2026 Christian Rößner
# SPDX-License-Identifier: AGPL-3.0-only

# Verify the bootstrap image through its real binary and an isolated volume.
set -euo pipefail

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"
docker_cmd="${DOCKER:-docker}"
image="${DEMO_CLI_IMAGE:-nauthilus-director-demo-cli:test}"

"$docker_cmd" build --file contrib/demo-stack/Dockerfile.stalwart-cli --tag "$image" .
"$docker_cmd" run --rm --network none --read-only --tmpfs /tmp \
    --mount type=volume,destination=/run/stalwart-bootstrap \
    --entrypoint /bin/sh "$image" -ec '
    test "$(id -u)" = 10001
    test "$(id -g)" = 10001
    stalwart-cli --version
    touch /run/stalwart-bootstrap/bootstrap.ready
    touch /run/stalwart-bootstrap/bootstrap.done
    test -r /run/stalwart-bootstrap/bootstrap.ready
    test -r /run/stalwart-bootstrap/bootstrap.done
    echo "ok demo CLI: non-root binary and writable bootstrap state"
    '
