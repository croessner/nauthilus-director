#!/bin/sh
# Copyright (C) 2026 Christian Rößner
# SPDX-License-Identifier: AGPL-3.0-only

# Run the supplied test command against a disposable loopback-only Redis Cluster.
set -eu

cluster_base_port=${DIRECTOR_TEST_CLUSTER_BASE_PORT:-18379}
case "$cluster_base_port" in
  ''|*[!0-9]*) echo 'DIRECTOR_TEST_CLUSTER_BASE_PORT must be numeric' >&2; exit 1 ;;
esac
if [ "$cluster_base_port" -lt 1024 ] || [ "$cluster_base_port" -gt 55533 ]; then
  echo 'DIRECTOR_TEST_CLUSTER_BASE_PORT must be between 1024 and 55533' >&2
  exit 1
fi
cluster_second_port=$((cluster_base_port + 1))
cluster_third_port=$((cluster_base_port + 2))
cluster_container="director-cluster-test-$$"
cluster_image='redis:8.6.2@sha256:832d7785830f3f4b559300e6191fc914b15642c1935252338825cf4332200148'
cluster_created=false

# cleanup removes only the container created by this invocation and preserves test failures.
cleanup() {
  cluster_status=$?
  trap - EXIT HUP INT TERM
  if [ "$cluster_created" = true ]; then
    if ! docker rm -f "$cluster_container" >/dev/null; then
      echo "Failed to remove test container $cluster_container" >&2
      cluster_status=1
    fi
  fi
  exit "$cluster_status"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

command -v docker >/dev/null
# All three nodes share one container so announced loopback addresses work both
# between nodes and for tests on Linux and Docker Desktop hosts.
docker create --name "$cluster_container" \
  -p "127.0.0.1:$cluster_base_port:$cluster_base_port" \
  -p "127.0.0.1:$cluster_second_port:$cluster_second_port" \
  -p "127.0.0.1:$cluster_third_port:$cluster_third_port" \
  "$cluster_image" sh -c '
    for port in "$@"; do
      mkdir -p "/tmp/node-$port"
      redis-server --port "$port" --bind 0.0.0.0 --protected-mode no \
        --cluster-enabled yes --cluster-announce-ip 127.0.0.1 \
        --cluster-config-file "/tmp/node-$port/nodes.conf" --dir "/tmp/node-$port" \
        --appendonly no --save "" --daemonize yes
    done
    exec sleep infinity
  ' cluster "$cluster_base_port" "$cluster_second_port" "$cluster_third_port" >/dev/null
cluster_created=true
docker start "$cluster_container" >/dev/null

cluster_attempt=0
until docker exec "$cluster_container" redis-cli -p "$cluster_third_port" ping >/dev/null 2>&1; do
  cluster_attempt=$((cluster_attempt + 1))
  if [ "$cluster_attempt" -ge 30 ]; then echo 'Test Redis did not become ready' >&2; exit 1; fi
  sleep 1
done

docker exec "$cluster_container" redis-cli --cluster create \
  "127.0.0.1:$cluster_base_port" "127.0.0.1:$cluster_second_port" "127.0.0.1:$cluster_third_port" \
  --cluster-replicas 0 --cluster-yes

export NAUTHILUS_DIRECTOR_TEST_CLUSTER_ADDRS="127.0.0.1:$cluster_base_port,127.0.0.1:$cluster_second_port,127.0.0.1:$cluster_third_port"
"$@"
