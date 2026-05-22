# E2E Harness

`make e2e` runs `test/e2e/run.sh`, the deterministic guardrail lane for
externally visible behavior. This lane must start real binaries or test
processes, communicate through public sockets, REST endpoints, and CLI commands
where applicable, and avoid internal package shortcuts as proof of behavior.

M0 creates the harness entrypoint and fake-service scaffold before production
mail protocol entrypoints exist. The runner therefore succeeds with explicit
stable `SKIP e2e:` lines for protocol scenarios, Redis-backed state scenarios,
and Docker interoperability until those entrypoints are available.

## Guardrail Lane

The default lane is fake-service based and deterministic:

- fake Nauthilus HTTP authority under `test/e2e/fakes/nauthilus_http/`
- fake Nauthilus gRPC authority under `test/e2e/fakes/nauthilus_grpc/`
- fake IMAP, LMTP, ManageSieve, and POP3 backends under `test/e2e/fakes/`
- public loopback sockets or Unix sockets only when the tested listener
  behavior is explicitly socket based
- CLI commands through `nauthilus-directorctl` when the control API exists
- REST calls through the control listener when `runtime.servers.control` is
  runnable from the server binary

Fake services must expose counters or request observations that prove protocol
mapping, routing, and backend behavior without logging credentials, SASL blobs,
passwords, bearer tokens, private keys, session secrets, or raw authorization
headers. Tests that need secret-bearing input must assert only redacted log
fields or stable non-secret fingerprints.

## Redis Expectations

Active affinity and runtime overrides are production Redis behavior. Once E2E
state scenarios are added, the harness must use a real Redis or
Redis-compatible test service and the same production key builder and script
loader used by `internal/state`.

The Redis lane must verify connectivity through production configuration,
exercise Cluster hash-tagged per-affinity key groups, and fail closed on
ambiguous state or missing script behavior. Redis must not become optional for
production active affinity.

## Docker Interoperability

Docker interoperability is intentionally additive to this guardrail lane and is
documented in `test/e2e/interop/README.md`. It must not replace deterministic
fake-service coverage for edge cases, forced failures, routing decisions, or
secret-safe observability.

