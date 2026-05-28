# M3 Listener Runtime Control Follow-up

Status: completed. The local v1 listener runtime-control surface is
implemented, documented and covered by public-boundary E2E. `make
check-openapi`, `make test`, `make build-check`, `make e2e` and `make
guardrails` passed on 2026-05-28.

This document defines the listener-level runtime control surface for
`nauthilus-director`. Before this follow-up, production code could manage
backend, user and session runtime state through the generated REST API and
`nauthilus-directorctl`, and safe reload could add or remove configured
protocol listeners. The missing operator workflow was a temporary listener
drain or resume command that did not edit YAML configuration.

This follow-up belongs to M3 because it extends the REST and generated-client
operator control surface. It must not be folded into M6 ManageSieve or a later
protocol milestone: listener maintenance is protocol-neutral infrastructure and
is useful for IMAP, LMTP and every later protocol entrypoint.

## Source Documents

This follow-up is governed by:

- `AGENTS.md`
- `docs/ARCHITECTURE_ROADMAP.md`
- `docs/specs/implementation/M0_FOUNDATION_SPEC.md`
- `docs/specs/implementation/M1_IMAP_MVP_SPEC.md`
- `docs/specs/implementation/M2_M3_BACKEND_RUNTIME_CONTROL_SPEC.md`
- `docs/specs/implementation/M4_OBSERVABILITY_SPEC.md`
- `docs/specs/implementation/M5_LMTP_PRODUCTION_SPEC.md`
- `docs/specs/openapi/nauthilus-director.yaml`
- `docs/man/nauthilus-directorctl.1`
- `docs/man/nauthilus-director.1`
- `Makefile`

If this document conflicts with those source documents, fix the drift before
implementation continues.

## Original Gap

`nauthilus-directorctl` currently exposes runtime control for backends, users
and sessions. Backend drain is available as
`backends drain <identifier> --mode soft|hard --reason <text>`, and it is backed
by `POST /api/v1/backends/{identifier}/runtime/drain`.

Before this follow-up, listener lifecycle was available only through
configuration and safe reload:

- adding a listener to YAML and running `reload` starts the new configured
  listener when the change is safe;
- removing a listener from YAML and running `reload` closes the listener socket
  and drains active sessions according to the listener manager shutdown
  deadline;
- changing an existing listener's socket or transport configuration is rejected
  as a restart-required change.

That path is useful for declarative configuration changes, but it is not an
operator-friendly temporary drain. It requires a config edit, it cannot express
audited runtime intent separate from the static baseline, and it does not give
the CLI a direct `listeners drain` or `listeners resume` workflow.

## Goal

Add an OpenAPI-first listener runtime control surface that lets an operator
temporarily stop accepting new connections on one configured listener, optionally
close local active sessions after explicit hard-drain intent, and later resume
the same listener from the unchanged typed configuration snapshot.

The result supports this operator flow:

```text
operator
  -> nauthilus-directorctl listeners list
  -> nauthilus-directorctl listeners drain imaps --mode soft --reason "node maintenance"
  -> existing IMAP/LMTP sessions continue until they close naturally
  -> new frontend connections to that listener are not accepted by this process
  -> nauthilus-directorctl listeners resume imaps --reason "maintenance complete"
  -> listener is rebound from the current config snapshot
```

The control surface must remain generated-client-backed. Hand-written CLI code
may own command grammar and output formatting, but it must not maintain a
parallel HTTP client or duplicate REST DTOs.

## Delivery Placement

Implement this as a small M3 follow-up before relying on listener drains in
operations or before starting the next protocol milestone that needs the same
maintenance behavior.

Implementation slices:

1. Listener manager runtime state and unit tests.
2. Runtime orchestration service, audit metadata and observability.
3. OpenAPI schema update plus generated server and client refresh.
4. REST adapter implementation and handler tests.
5. `nauthilus-directorctl listeners ...` commands with fake generated-client
   tests.
6. Manpage updates and deterministic E2E proof through the running binary.

The implementation may be committed separately, but the follow-up is complete
only when REST, CLI and public-socket behavior all prove the same semantics.

## Scope

In scope:

- Read-only listener inventory through REST and CLI.
- Process-local runtime drain and resume for configured protocol listeners.
- Soft listener drain:
  - close the listening socket;
  - stop accepting new frontend connections in the addressed Director process;
  - leave already accepted sessions or delivery transactions running.
- Hard listener drain:
  - close the listening socket;
  - stop accepting new frontend connections in the addressed Director process;
  - after optional grace, close local active protocol streams for that listener
    with a controlled runtime action.
- Resume:
  - rebind the listener from the current normalized typed config;
  - fail closed when the listener no longer exists in config or the address
    cannot be bound;
  - preserve static configuration as the source of listener transport truth.
- Audit-safe reason handling for every mutating listener operation.
- Low-cardinality observability for listener runtime operations.
- Documentation and manpage updates.
- Unit, REST, CLI and E2E tests.

Out of scope:

- Writing listener runtime changes back into YAML.
- Changing listener address, TLS, PROXY protocol, authority or backend-pool
  configuration through runtime control.
- Cluster-wide listener orchestration hidden behind a single local control API
  call.
- Adding feature-specific Redis configuration under `storage.redis`.
- Treating listener drain as backend maintenance, user movement or route lookup.
- Replacing backend drain or backend maintenance semantics.
- Making route lookup mutate or depend on listener lifecycle state.

## Runtime Semantics

Listener runtime control is local to the Director process addressed by the
control API. A listener socket is an operating-system resource owned by one
process. The v1 API must not imply that draining `imaps` on one Director process
automatically drains the same named listener on every other process in a
cluster.

Clustered deployments have two supported v1 choices:

- call the listener runtime endpoint on each Director process that should stop
  accepting traffic;
- use the external load balancer or orchestrator to remove the process from
  frontend rotation, and use backend/user/session runtime controls for shared
  Redis-backed state.

A future cluster-wide control plane may be designed explicitly after the
instance registry, authorization model and operational failure modes are
settled. That later design must not be smuggled into this local v1 endpoint by
using implicit Redis pub/sub, broad fan-out or best-effort hidden RPC.

Runtime state is intentionally non-persistent in v1. After process restart, the
typed configuration snapshot controls which listeners start. This keeps runtime
listener drains temporary, auditable and reversible without creating a second
configuration source.

Soft drain closes only the listener accept socket. It does not close active
sessions, active proxy streams or active LMTP delivery transactions. Existing
streams continue until the protocol path closes them normally or until a later
hard drain or other runtime control action closes them explicitly.

Hard drain requires an explicit `grace_seconds` value, including `0` when the
operator wants immediate closure. Hard drain closes the listener accept socket,
waits for the requested grace and then closes active local protocol streams for
that listener with a controlled runtime action.

## Listener States

Expose listener state with stable, operator-readable values:

- `accepting`: the configured listener is bound and accepting new frontend
  sockets.
- `draining`: the configured listener is not accepting new sockets because a
  runtime drain closed the accept socket, but active local sessions may still be
  running.
- `drained`: the configured listener is not accepting new sockets and has no
  active local sessions known to the manager.
- `stopped`: the listener is configured but not currently bound because startup
  or resume failed.

These four values are the complete v1 listener-state enum. Do not add
operation-specific states such as `resume_failed`, `drain_failed` or `removed`.
Operation failures are returned as request errors; they are not represented by
expanding the listener state vocabulary.

Read-only listener details must include only secret-safe fields:

- listener name;
- protocol;
- service name;
- network;
- configured address;
- bound address when accepting;
- TLS mode;
- whether implicit TLS is active;
- whether PROXY protocol is enabled;
- runtime state;
- active local session count;
- current drain mode when a drain is active;

Do not expose raw peer addresses, usernames, recipients, session IDs,
credentials, private key paths or operator reason text in metric labels.

## OpenAPI Shape

Add a `listeners` tag and generate both server and client artifacts from
`docs/specs/openapi/nauthilus-director.yaml`.

Endpoints:

```text
GET  /api/v1/listeners
GET  /api/v1/listeners/{name}
POST /api/v1/listeners/{name}/runtime/drain
POST /api/v1/listeners/{name}/runtime/resume
```

Operation IDs:

```text
listListeners
getListener
drainListener
resumeListener
```

Request schemas:

```yaml
ListenerDrainRequest:
  type: object
  additionalProperties: false
  required:
    - mode
    - reason
  properties:
    mode:
      $ref: "#/components/schemas/DrainMode"
    reason:
      type: string
      minLength: 1
    grace_seconds:
      type: integer
      minimum: 0

ListenerResumeRequest:
  type: object
  additionalProperties: false
  required:
    - reason
  properties:
    reason:
      type: string
      minLength: 1
```

For `mode: hard`, `grace_seconds` is required by runtime validation even though
the field is optional at the shared schema level. This keeps soft-drain requests
compact while requiring explicit operator intent before active client
connections are closed.

Read endpoints return generated listener DTOs, not hand-written CLI models.
Drain and resume return `202` with the updated generated `ListenerDetail`
response body. The updated state matters operationally: after drain or resume,
the caller should immediately see whether the listener is `draining`, `drained`,
`accepting` or `stopped`, along with the current bound address and active local
session count where applicable.

Use `404` when the named listener is not configured. Use `409` when a resume or
drain request conflicts with current runtime state and cannot be made
idempotent. Use `503` when the listener manager is unavailable.

## CLI Shape

Add a top-level `listeners` command:

```text
nauthilus-directorctl listeners list
nauthilus-directorctl listeners show <name>
nauthilus-directorctl listeners drain <name> --mode soft|hard \
  --reason <text> [--grace-seconds <seconds>]
nauthilus-directorctl listeners resume <name> --reason <text>
```

Text output must remain compact key-value output suitable for scripts. JSON
output must return generated response bodies where practical. The command
must use `generated.ClientWithResponsesInterface` just like the existing
backend, session, user, route and reload commands.

The CLI must reject empty listener names, missing reasons, invalid modes and
negative grace values before sending a request. For hard drain, the CLI must
also require `--grace-seconds`, even when the intended value is `0`.

## Package Boundaries

`internal/listener` owns listener lifecycle and local listener state:

- binding and closing accept sockets;
- keeping existing sessions alive during soft drain;
- closing active local sessions for hard drain;
- rebinding from immutable typed config on resume;
- producing secret-safe snapshots.

`internal/runtime` may own the listener runtime orchestration use case:

- request validation;
- audit metadata;
- operation generation;
- mapping listener manager errors into runtime errors.

It must not become a generic helper package and must not own socket-level
transport details.

`internal/rest/adapters` adapts generated OpenAPI DTOs to runtime requests and
responses.

`cmd/nauthilus-directorctl` owns only command grammar, flag parsing, output
formatting and operator-facing errors.

`internal/observability` owns event names, metric labels and log policy. Reason
text is acceptable as audit/log context only where existing redaction policy
allows it; reason text must not become a metric label.

## Implementation Notes

Do not implement soft drain by calling the existing full manager stop path. The
full stop path waits for active sessions and then closes active connections
after the shutdown deadline. Soft drain needs a narrower operation: close only
the accept socket, keep the listener object and active connection tracking, and
leave protocol sessions to end normally.

Resume must rebind the existing configured listener object. If the address is
already in use or TLS material can no longer be loaded, resume must fail closed
and keep the listener non-accepting.

Hard drain must reuse local session handles where possible so protocol and
proxy code observe a controlled runtime action rather than a generic transport
failure. IMAP sessions, LMTP transactions and later protocol handlers should be
closed through the same local-control pattern used by backend and user runtime
operations when they have registered handles. Connections accepted before handle
registration may still need transport closure from the listener manager.

The listener manager must remain concurrency-safe. Draining and resuming while
accept loops exit, sessions close naturally or safe reload runs must have
deterministic outcomes. Existing safe reload behavior remains valid: config
removal can still drain a listener declaratively, and config addition can still
start a new listener. Runtime drain must not make safe reload accept in-place
socket configuration changes that currently require restart.

## Tests

Required unit tests:

- Listener soft drain closes the bound address and rejects new connections while
  an already accepted connection remains open.
- Listener hard drain requires explicit grace and closes active local
  connections after the requested grace, including immediate closure when grace
  is `0`.
- Resume rebinds a drained listener and accepts a new connection.
- Resume fails closed when the listener no longer exists or bind fails.
- Drain and resume are safe when called repeatedly.
- Safe reload and runtime drain do not race into duplicate bound sockets.
- Listener snapshots expose state and counts without high-cardinality or secret
  fields.
- Runtime request validation rejects empty listener names, missing reasons,
  invalid modes, negative grace and hard drain without explicit grace.

Required REST and CLI tests:

- Generated REST handlers list and show listener state.
- REST drain and resume map generated request bodies into runtime requests and
  return the updated generated listener detail.
- Error mapping covers `404`, `409` and `503`.
- `nauthilus-directorctl listeners ...` uses the generated client interface and
  fake-client tests, not raw HTTP mocks.
- Text output is stable and JSON output emits generated DTOs.

Required E2E proof:

- Start the production `nauthilus-director` binary with at least one public IMAP
  or LMTP listener and the control API.
- Prove the listener accepts a frontend connection before drain.
- Drain the listener through `nauthilus-directorctl`.
- Prove new frontend connections to that listener are not accepted by the
  addressed process.
- For soft drain, prove an already accepted protocol stream can continue until
  it closes normally.
- Resume the listener through `nauthilus-directorctl`.
- Prove new frontend connections are accepted again.

Run `make generate-openapi` after changing the OpenAPI spec, then run
`make check-openapi`. Before commit or pull request, run `make guardrails`.

## Acceptance Criteria

- Operators can list listener runtime state through REST and CLI.
- Operators can temporarily drain one configured listener without editing YAML.
- Soft drain stops new accepts without killing active local sessions.
- Hard drain requires explicit intent and can close active local sessions after
  grace.
- Resume restores accepts from the unchanged typed config snapshot.
- Runtime listener control is clearly documented as process-local in v1.
- Generated OpenAPI server and client artifacts are reproducible.
- `nauthilus-directorctl` uses the generated client SDK for every listener
  command.
- Observability remains low-cardinality and secret-safe.
- E2E proves the externally visible socket behavior, not only internal state.

## Closeout Evidence

The deterministic fake-service E2E lane now includes
`TestServerBinaryListenerDrainResumeKeepsActiveStream`. The test starts the
production `nauthilus-director` binary with a public IMAP listener and the REST
control API, builds and runs the real `nauthilus-directorctl` binary, and proves
listener runtime control through public sockets and generated-client CLI
commands:

- `nauthilus-directorctl listeners list` observes the configured `imap`
  listener in `accepting` state with a bound address.
- A frontend IMAP connection succeeds before drain and remains open.
- `nauthilus-directorctl listeners drain imap --mode soft --reason ...` moves
  the addressed process-local listener to `draining` without editing YAML.
- New frontend connections to the same listener address are rejected while the
  listener is soft-drained.
- The already accepted IMAP stream continues during soft drain by completing an
  `ID` command.
- `nauthilus-directorctl listeners resume imap --reason ...` restores new
  accepts from the current typed config snapshot.
- The CLI rejects hard drain without `--grace-seconds` before sending a
  request.
- `nauthilus-directorctl listeners drain imap --mode hard --grace-seconds 0
  --reason ...` closes the active local stream and returns `drained`.

Operator-facing documentation now states the v1 semantics explicitly in
`docs/man/nauthilus-directorctl.1`, `docs/man/nauthilus-director.1`,
`test/e2e/README.md` and `docs/ARCHITECTURE_ROADMAP.md`: listener runtime
control is process-local, non-persistent, does not edit YAML, soft drain stops
only new accepts, hard drain requires explicit grace and resume rebinds from the
current typed config.

Validation evidence from the closeout run:

- `make check-openapi`: passed; generated OpenAPI artifacts are fresh.
- `make test`: passed.
- `make build-check`: passed.
- `make e2e`: passed and exercised the production server binary plus CLI.
- `make guardrails`: passed.

The final review found no YAML persistence path for listener runtime mutations,
no cluster-wide fan-out, no Redis pub/sub listener orchestration and no listener
state persistence across process restart.

## Review Checklist

- Verify no listener runtime mutation writes YAML config.
- Verify no hidden cluster-wide fan-out is added.
- Verify the listener manager keeps soft drain separate from full shutdown.
- Verify hard drain uses controlled runtime close paths where available.
- Verify safe reload still rejects changed existing listener config.
- Verify route lookup remains side-effect-free and does not become listener
  lifecycle control.
- Verify all new hand-written Go functions and methods have doc comments.
- Verify generated files are updated only through the OpenAPI generator.
- Verify manpages and operator docs describe process-local semantics.

## Resolved Decisions

No blocking questions remain for the local v1 API. The following decisions are
settled for this follow-up:

1. Listener runtime control is process-local in v1.
2. Listener runtime drain state is not persistent and does not survive process
   restart.
3. Resume is modeled explicitly as
   `POST /api/v1/listeners/{name}/runtime/resume`.
4. Drain and resume return `202` with the updated generated `ListenerDetail`
   response body.
5. The listener state enum is limited to `accepting`, `draining`, `drained` and
   `stopped`.
6. Soft drain closes only the accept socket and leaves active streams running.
7. Hard drain requires explicit `grace_seconds`, including explicit `0` for
   immediate closure.
8. The CLI command is the top-level plural resource command
   `nauthilus-directorctl listeners`.

A later cluster-wide listener drain remains an explicit future design topic and
must not be inferred from this follow-up.
