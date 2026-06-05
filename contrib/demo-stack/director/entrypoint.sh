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
control_token_file="${DIRECTOR_CONTROL_TOKEN_FILE:-/run/nauthilus-director/control-token}"
control_token="${DIRECTOR_CONTROL_TOKEN:-demo-control-token}"
oidc_client_secret_file="${DIRECTOR_OIDC_CLIENT_SECRET_FILE:-/run/nauthilus-director/oidc-client-secret}"
oidc_client_secret="${DIRECTOR_OIDC_CLIENT_SECRET:-demo-director-oidc-secret}"

mkdir -p "${tls_dir}"
mkdir -p "$(dirname "${control_token_file}")"
mkdir -p "$(dirname "${oidc_client_secret_file}")"

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

if [ ! -s "${control_token_file}" ]; then
  printf '%s\n' "${control_token}" >"${control_token_file}"
  chmod 0600 "${control_token_file}"
fi

if [ ! -s "${oidc_client_secret_file}" ]; then
  printf '%s\n' "${oidc_client_secret}" >"${oidc_client_secret_file}"
  chmod 0600 "${oidc_client_secret_file}"
fi

exec /usr/local/bin/nauthilus-director "$@"
