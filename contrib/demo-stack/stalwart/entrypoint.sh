#!/bin/sh
#
# Copyright (C) 2026 Christian Rößner
#
# SPDX-License-Identifier: AGPL-3.0-only

set -eu

config_file="${STALWART_CONFIG_FILE:-/etc/stalwart/config.json}"
bootstrap_ready_marker="${STALWART_BOOTSTRAP_READY_MARKER:-/run/stalwart-bootstrap/bootstrap.ready}"

start_normal() {
  exec /usr/local/bin/stalwart --config "${config_file}"
}

if [ -f "${bootstrap_ready_marker}" ]; then
  start_normal
fi

STALWART_RECOVERY_MODE=1 /usr/local/bin/stalwart --config "${config_file}" &
pid="$!"

trap 'kill "${pid}" 2>/dev/null || true; wait "${pid}" 2>/dev/null || true' INT TERM

while kill -0 "${pid}" 2>/dev/null; do
  if [ -f "${bootstrap_ready_marker}" ]; then
    kill "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
    start_normal
  fi

  sleep 2
done

wait "${pid}"
