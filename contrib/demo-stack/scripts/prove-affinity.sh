#!/usr/bin/env bash
#
# Copyright (C) 2026 Christian Rößner
#
# SPDX-License-Identifier: AGPL-3.0-only

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export DEMO_PROOF_MODE=affinity
export DEMO_USER="${DEMO_USER:-alice@example.test}"
export DEMO_EXPECTED_BACKEND="${DEMO_EXPECTED_BACKEND:-}"

exec python3 "${script_dir}/proof_mail_flow.py"
