#!/bin/sh
#
# Copyright (C) 2026 Christian Rößner
#
# SPDX-License-Identifier: AGPL-3.0-only

set -eu

admin_user="${STALWART_ADMIN_USER:-admin}"
admin_password="${STALWART_ADMIN_PASSWORD:-demo-stalwart-admin}"
plan_file="${STALWART_PLAN:-/etc/stalwart-demo/bootstrap.ndjson}"
bootstrap_ready_marker="${STALWART_BOOTSTRAP_READY_MARKER:-/run/stalwart-bootstrap/bootstrap.ready}"
bootstrap_done_marker="${STALWART_BOOTSTRAP_DONE_MARKER:-/run/stalwart-bootstrap/bootstrap.done}"

if [ -f "${bootstrap_done_marker}" ]; then
  printf 'Stalwart bootstrap marker already exists at %s; skipping bootstrap plan\n' "${bootstrap_done_marker}"
  exit 0
fi

wait_for_server() {
  url="$1"
  attempts="${STALWART_CONFIGURE_ATTEMPTS:-60}"

  i=1
  while [ "${i}" -le "${attempts}" ]; do
    if stalwart-cli \
      --url "${url}" \
      --user "${admin_user}" \
      --password "${admin_password}" \
      --no-color \
      describe >/dev/null 2>&1; then
      return 0
    fi

    sleep 2
    i=$((i + 1))
  done

  printf 'Stalwart management API did not become ready at %s\n' "${url}" >&2
  return 1
}

wait_for_default_roles() {
  url="$1"
  attempts="${STALWART_CONFIGURE_ATTEMPTS:-60}"

  i=1
  while [ "${i}" -le "${attempts}" ]; do
    if stalwart-cli \
      --url "${url}" \
      --user "${admin_user}" \
      --password "${admin_password}" \
      --no-color \
      query Role --fields description --json 2>/dev/null | grep -q '"id":"b"'; then
      return 0
    fi

    sleep 2
    i=$((i + 1))
  done

  printf 'Stalwart default roles did not become ready at %s\n' "${url}" >&2
  return 1
}

apply_plan() {
  url="$1"
  file="$2"

  stalwart-cli \
    --url "${url}" \
    --user "${admin_user}" \
    --password "${admin_password}" \
    --no-color \
    apply --file "${file}" --json
}

configure_default_user_role() {
  url="$1"

  stalwart-cli \
    --url "${url}" \
    --user "${admin_user}" \
    --password "${admin_password}" \
    --no-color \
    update Authentication --json '{"defaultUserRoleIds":{"b":true}}'
}

if [ ! -f "${bootstrap_ready_marker}" ]; then
  wait_for_server "http://stalwart-a:8080"
  wait_for_server "http://stalwart-b:8080"
  apply_plan "http://stalwart-a:8080" "${plan_file}"
  mkdir -p "$(dirname "${bootstrap_ready_marker}")"
  touch "${bootstrap_ready_marker}"
fi

wait_for_default_roles "http://stalwart-a:8080"
wait_for_default_roles "http://stalwart-b:8080"
configure_default_user_role "http://stalwart-a:8080"
touch "${bootstrap_done_marker}"
