# E2E Harness

`make e2e` runs `test/e2e/run.sh`, the deterministic guardrail lane for
externally visible behavior. This lane must start real binaries or test
processes, communicate through public sockets, REST endpoints, and CLI commands
where applicable, and avoid internal package shortcuts as proof of behavior.

The harness entrypoint starts production listener/session code or the
production server binary, talks IMAP and LMTP through public loopback sockets,
and keeps deterministic fake services in-process unless the behavior under test
requires an external artifact.

## Guardrail Lane

The default lane is fake-service based and deterministic:

- fake Nauthilus HTTP authority under `test/e2e/fakes/nauthilus_http/`
  with deterministic OIDC discovery, token and introspection fixtures for
  Director caller-auth proofs
- scaffolded fake Nauthilus gRPC authority under
  `test/e2e/fakes/nauthilus_grpc/`
- fake IMAP backend under `test/e2e/fakes/imap_backend/`
- deterministic fake LMTP backend under `test/e2e/fakes/lmtp_backend/`
- public loopback sockets for frontend IMAP, LMTP, LMTPS, STARTTLS, implicit
  TLS and fake backend handoff
- CLI commands through `nauthilus-directorctl` when the control API exists
- REST calls through the control listener when `runtime.servers.control` is
  runnable from the server binary
- OIDC client-credentials caller auth for Director-to-Nauthilus requests,
  including an insufficient-scope negative proof that fails closed before
  backend placement
- mail SASL `XOAUTH2` and `OAUTHBEARER` validation through the fake
  Nauthilus OIDC discovery and introspection endpoint for IMAP, LMTP peer
  auth, ManageSieve and POP3 public listeners
- a mixed authority lane where POP3 password auth stays on the generated gRPC
  AuthService while SASL bearer validation uses the HTTP OIDC introspection
  endpoint
- inactive tokens, missing required scopes, missing account claims and malformed
  introspection responses failing closed without exposing bearer token
  sentinels
- backend bearer replay through explicit credential-replay policy, proving
  bearer credentials are not converted into master-user password auth
- listener runtime control proof through `nauthilus-directorctl listeners ...`,
  including process-local soft drain, resume, hard drain with explicit zero
  grace, and public frontend socket observations

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

Docker interoperability is intentionally additive to this guardrail lane and
runs through `make e2e-interop`. It is documented in
`test/e2e/interop/README.md` and must not replace deterministic fake-service
coverage for edge cases, forced failures, routing decisions, or secret-safe
observability.

The current Docker lane starts production `nauthilus-director` binaries, a
fake Nauthilus authority that requires OIDC Bearer caller tokens, real Dovecot
IMAP and LMTP backends, and a pinned Postfix submitter image. Its
cluster scenario shares one Redis-compatible state service across three
Director processes and six Dovecot IMAP backends: two untagged default
backends, two `test_shard1` backends and two `test_shard2` backends. It verifies
deep health checks, health-owner distribution, active affinity, parallel
connections for one user, route lookup, session kill, user kick, user move,
hard backend drain and affinity clear through public sockets, Redis-backed
runtime state and `nauthilus-directorctl`. Its LMTP scenario proves
Postfix-to-Director-to-Dovecot delivery and preserves the real IMAP interop
lane.
