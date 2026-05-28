#!/bin/sh
#
# Copyright (C) 2026 Christian Rößner
#
# SPDX-License-Identifier: AGPL-3.0-only

set -eu

tls_dir="${DEMO_GRPC_TLS_DIR:-/run/nauthilus-demo/grpc-tls}"
server_name="${DEMO_GRPC_TLS_SERVER_NAME:-nauthilus}"
nauthilus_uid="${DEMO_NAUTHILUS_UID:-65532}"
nauthilus_gid="${DEMO_NAUTHILUS_GID:-65532}"

ca_key="${tls_dir}/ca.key"
ca_cert="${tls_dir}/ca.crt"
server_key="${tls_dir}/server.key"
server_cert="${tls_dir}/server.crt"

fix_permissions() {
  chmod 0600 "${ca_key}" "${server_key}"
  chmod 0644 "${ca_cert}" "${server_cert}"
  chown "${nauthilus_uid}:${nauthilus_gid}" "${server_key}" "${server_cert}"
}

mkdir -p "${tls_dir}"

if [ -s "${ca_key}" ] && [ -s "${ca_cert}" ] && [ -s "${server_key}" ] && [ -s "${server_cert}" ]; then
  fix_permissions
  exit 0
fi

work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT

rm -f "${ca_key}" "${ca_cert}" "${tls_dir}/ca.srl" "${server_key}" "${server_cert}" "${work_dir}/server.csr"

cat >"${work_dir}/server.ext" <<EOF
subjectAltName=DNS:${server_name},DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
keyUsage=digitalSignature,keyEncipherment
EOF

openssl genrsa -out "${ca_key}" 2048 >/dev/null 2>&1
openssl req \
  -x509 \
  -new \
  -nodes \
  -key "${ca_key}" \
  -sha256 \
  -days 7 \
  -subj "/CN=Nauthilus Director Demo gRPC CA" \
  -out "${ca_cert}" >/dev/null 2>&1

openssl genrsa -out "${server_key}" 2048 >/dev/null 2>&1
openssl req \
  -new \
  -key "${server_key}" \
  -subj "/CN=${server_name}" \
  -out "${work_dir}/server.csr" >/dev/null 2>&1
openssl x509 \
  -req \
  -in "${work_dir}/server.csr" \
  -CA "${ca_cert}" \
  -CAkey "${ca_key}" \
  -CAcreateserial \
  -out "${server_cert}" \
  -days 7 \
  -sha256 \
  -extfile "${work_dir}/server.ext" >/dev/null 2>&1

fix_permissions
