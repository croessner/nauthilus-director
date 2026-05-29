# Runtime State Scale Harness

`test/scale` is an optional Redis sizing harness for the scale-safe runtime
state model. It is not part of `make guardrails`, and its numbers are not a
universal capacity claim. Use it to compare Redis standalone or Redis Cluster
behavior in a controlled, non-production environment.

## Safety Rules

- The harness requires an explicit Redis target through `--redis-addr` or
  `--redis-cluster-addrs`.
- Non-loopback targets and production-looking key prefixes are refused unless
  `--allow-production-target` is set.
- The default key prefix is a temporary `nauthilus-director-scale-*` namespace.
- The harness does not run `FLUSHDB`, `FLUSHALL`, `KEYS` or pattern deletes.
  Cleanup closes known synthetic sessions and releases known reservations only.
- Keep `--cleanup=true` unless you are deliberately inspecting the generated
  keys in an isolated Redis instance.
- Use `--redis-password-file` instead of putting Redis passwords on the command
  line.

## Make Targets

Bounded local smoke against an explicit loopback Redis or Valkey target:

```text
SCALE_REDIS_ADDR=127.0.0.1:6379 make scale-smoke
```

Explicit stress run for larger standalone or Cluster sizing:

```text
SCALE_REDIS_CLUSTER_ADDRS=redis-1:6379,redis-2:6379,redis-3:6379 \
SCALE_ALLOW_PRODUCTION_TARGET=1 \
SCALE_STRESS_SESSIONS=1000000 \
make scale-stress
```

`make guardrails` intentionally does not call either target.

Useful Make variables include `SCALE_SMOKE_SESSIONS`,
`SCALE_SMOKE_HEARTBEAT_SAMPLE`, `SCALE_SMOKE_CLOSE_SAMPLE`,
`SCALE_SMOKE_REAP_EXPIRED`, `SCALE_STRESS_SESSIONS`,
`SCALE_STRESS_HEARTBEAT_SAMPLE`, `SCALE_STRESS_CLOSE_SAMPLE` and
`SCALE_STRESS_REAP_EXPIRED`.

## Inputs

Important harness flags:

- `--redis-addr`: standalone Redis target.
- `--redis-cluster-addrs`: comma-separated Redis Cluster seed addresses.
- `--redis-username` and `--redis-password-file`: optional ACL credentials.
- `--tls`, `--tls-server-name`, `--tls-insecure-skip-verify`: optional Redis
  TLS settings.
- `--sessions`: synthetic active sessions to open.
- `--heartbeat-sample`: active sessions to heartbeat.
- `--close-sample`: active sessions to close.
- `--reap-expired`: short-lived sessions to seed for the due-time reaper.
- `--max-connections`: backend reservation capacity budget. If omitted, the
  harness uses a fail-closed budget large enough for the requested synthetic
  sessions.
- `--key-prefix`: temporary Redis namespace.
- `--cleanup`: close synthetic sessions and release reservations before exit.

## Outputs

The text output includes:

- active session count from aggregate runtime state
- session open, heartbeat and close rates
- reaper due-record rate
- Redis operation latency percentiles for each operation family
- bounded error classes
- memory estimate from Redis `INFO memory`
- Redis Cluster slot distribution for synthetic affinity and backend
  reservation keys

Interpret rates and memory in the context of the Redis topology, persistence
settings, network latency, TLS, CPU limits, client concurrency and configured
runtime-state shard counts. A result from one laptop, VM or Cluster is only
evidence for that environment.
