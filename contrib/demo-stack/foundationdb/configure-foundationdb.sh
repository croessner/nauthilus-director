#!/bin/sh
#
# Copyright (C) 2026 Christian Rößner
#
# SPDX-License-Identifier: AGPL-3.0-only

set -eu

cluster_file="${FDB_CLUSTER_FILE:-/etc/foundationdb/fdb.cluster}"
attempts="${FDB_CONFIGURE_ATTEMPTS:-60}"

is_available() {
  fdbcli -C "${cluster_file}" --exec "status minimal" 2>/dev/null | grep -q "The database is available"
}

i=1
while [ "${i}" -le "${attempts}" ]; do
  if is_available; then
    exit 0
  fi

  if fdbcli -C "${cluster_file}" --exec "configure new single ssd" >/dev/null 2>&1; then
    if is_available; then
      exit 0
    fi
  fi

  sleep 2
  i=$((i + 1))
done

printf 'FoundationDB did not become available after configuration attempts.\n' >&2
fdbcli -C "${cluster_file}" --exec "status" >&2 || true
exit 1
