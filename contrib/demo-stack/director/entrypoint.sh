#!/bin/sh
#
# Copyright (C) 2026 Christian Rößner
#
# SPDX-License-Identifier: AGPL-3.0-only

set -eu

tls_dir="${DIRECTOR_TLS_DIR:-/run/nauthilus-director/tls}"
cert_file="${DIRECTOR_TLS_CERT:-${tls_dir}/server.crt}"
key_file="${DIRECTOR_TLS_KEY:-${tls_dir}/server.key}"
cert_cn="${DIRECTOR_CERT_CN:-nauthilus-director-demo}"

mkdir -p "${tls_dir}"

if [ ! -s "${cert_file}" ] || [ ! -s "${key_file}" ]; then
  openssl req \
    -x509 \
    -newkey rsa:2048 \
    -nodes \
    -days 7 \
    -subj "/CN=${cert_cn}" \
    -addext "subjectAltName=DNS:localhost,DNS:director-a,DNS:director-b,IP:127.0.0.1" \
    -keyout "${key_file}" \
    -out "${cert_file}" >/dev/null 2>&1
  chmod 0600 "${key_file}"
  chmod 0644 "${cert_file}"
fi

exec /usr/local/bin/nauthilus-director "$@"
