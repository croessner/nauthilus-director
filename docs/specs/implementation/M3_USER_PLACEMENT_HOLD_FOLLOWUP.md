# M3 User Placement Hold Follow-up

Status: completed. This follow-up defines and closes the binding design for a
temporary operator-controlled user placement hold.

This follow-up amends the completed M2/M3 backend runtime and control milestone
with a migration workflow that can pause new backend placement for one user key
for a strictly bounded time window.

The existing runtime model can move a user to another shard, kick active
sessions, clear active affinity and pin one user to a concrete backend for
commissioning. Those operations decide or change where placement should go. The
missing migration primitive is different: an operator sometimes needs a short
window during which newly authenticated or resolved user traffic waits instead
of racing to the old backend while mailbox data is moving.

This document defines that primitive as an OpenAPI-first runtime-control
extension. The hold is a temporary placement gate, not a routing decision, not a
backend pin, not a session, not a delivery hold and not a YAML rewrite feature.

## Source Documents

This follow-up is governed by:

- `AGENTS.md`
- `docs/ARCHITECTURE_ROADMAP.md`
- `docs/specs/implementation/M0_FOUNDATION_SPEC.md`
- `docs/specs/implementation/M1_IMAP_MVP_SPEC.md`
- `docs/specs/implementation/M2_M3_BACKEND_RUNTIME_CONTROL_SPEC.md`
- `docs/specs/implementation/M2_M3_RUNTIME_STATE_MILLION_SCALE_CHANGE_SPEC.md`
- `docs/specs/implementation/M3_LISTENER_RUNTIME_CONTROL_FOLLOWUP.md`
- `docs/specs/implementation/M3_USER_BACKEND_PINNING_FOLLOWUP.md`
- `docs/specs/implementation/M4_OBSERVABILITY_SPEC.md`
- `docs/specs/implementation/M5_LMTP_PRODUCTION_SPEC.md`
- `docs/specs/openapi/nauthilus-director.yaml`
- `docs/developer/AFFINITY_SESSION_HANDLING.md`
- `docs/man/nauthilus-directorctl.1`
- `docs/man/nauthilus-director.1`
- `Makefile`

If this document conflicts with those source documents, fix the drift before
implementation continues. In particular, do not weaken active-user stickiness,
route-lookup side-effect freedom, Redis fail-closed behavior, metric-label
policy, generated OpenAPI boundaries or the separation between Nauthilus identity
authority and director-owned routing decisions.

## Original Gap

A safe user migration needs to prevent new sessions from slipping onto the old
placement while the operator is moving mailbox state and changing runtime
placement.

The existing runtime controls cover related but different operations:

- `users move` changes the target shard for future placement.
- `users backend-pin` constrains one user to a concrete backend after placement
  is allowed to continue.
- `users kick` closes active sessions through the controlled runtime action
  path.
- `users affinity clear` removes active shard affinity but does not block the
  next connection.
- LMTP delivery-scoped holds protect an accepted delivery transaction from
  concurrent user-stateful placement, but they are created by protocol traffic,
  not by an operator migration plan.

None of those operations creates an audited, bounded, operator-set pending state
that says: for this user key, new placements must wait and must not connect to a
backend yet.

Without that primitive, a migration has a race:

```text
operator
  -> kicks current user sessions
  -> starts mailbox migration from backend A to backend B
  -> user reconnects before the target move or backend pin is ready
  -> director places the user on backend A again
```

The follow-up must close that race without making Nauthilus choose backends,
without holding unauthenticated sockets indefinitely and without creating a
second routing source of truth.

## Goal

Add a generated REST and `nauthilus-directorctl` control surface that lets an
operator set, inspect and clear a time-limited placement hold for one user key:

```text
operator
  -> nauthilus-directorctl users hold set alice@example.org \
       --duration 10m \
       --reason "migrate alice to shard-b"
  -> nauthilus-directorctl users kick alice@example.org \
       --reason "begin migration"
  -> mailbox data is moved from backend A to backend B
  -> nauthilus-directorctl users move alice@example.org \
       --to-shard shard-b \
       --strategy kick_existing \
       --reason "migration target ready"
  -> nauthilus-directorctl users hold clear alice@example.org \
       --reason "migration complete"
  -> newly waiting sessions re-check runtime state and place normally
```

The placement hold blocks only new backend placement attempts for the affected
affinity key. It does not choose the target shard or backend. Target selection
remains owned by normal routing, active affinity, `users move`,
`users backend-pin` and the runtime-aware selector.

## Delivery Placement

Implement this as an M3 runtime-control follow-up. The feature is protocol-
neutral runtime infrastructure for user-stateful placement and belongs beside
user movement, backend pinning, route lookup and Redis-backed active affinity.
It must not be delayed into a later protocol milestone merely because LMTP,
ManageSieve or POP3 also need to observe it.

Implementation slices:

1. Runtime domain semantics, request validation and configuration validation.
2. Redis-backed user hold state, expiry handling and read model.
3. Placement-gate integration for IMAP and LMTP, with extension seams for later
   ManageSieve and POP3.
4. OpenAPI schema update plus generated server and client refresh.
5. REST adapter implementation and handler tests.
6. `nauthilus-directorctl users hold ...` commands with fake generated-client
   tests.
7. Route lookup diagnostics, observability and operator documentation.
8. Deterministic public-boundary E2E proof through the production binary.

The slices may be committed separately, but the follow-up is complete only when
REST, CLI, route lookup and public protocol behavior all prove the same
semantics.

## Implementation Effort

Expected effort is medium to high. The REST and CLI shape is small, but the
runtime behavior touches the protocol placement boundary and must be careful
about timeouts, local waiter bounds, Redis clock use and race behavior.

The smallest safe implementation should be comparable to backend pinning plus a
new protocol wait point:

- Low risk: CLI grammar, generated-client plumbing, read model and manpage text.
- Medium risk: Redis state shape, expiry, route lookup reporting and audit.
- Highest risk: protocol wait behavior that blocks placement without opening
  sessions, reserving backend capacity or exhausting local resources.

Plan for focused implementation slices plus full `make guardrails`.

## Scope

In scope:

- Add a user-scoped operator placement hold for one affinity key.
- Require every hold to have a positive, finite duration.
- Compute `expires_at` from Redis server time, not client wall-clock time.
- Reject requested hold durations above the configured maximum; do not silently
  clamp operator intent.
- Block new placement for affected user-stateful protocol traffic after
  authoritative identity resolution and before backend selection.
- Keep existing sessions and already attached backend streams running unless an
  explicit `users kick`, session kill, backend drain or listener hard drain
  closes them.
- Keep migration target selection in existing runtime controls:
  `users move`, `users backend-pin`, affinity clear and normal selector rules.
- Store holds in Redis runtime state, not YAML.
- Expose hold state through generated REST DTOs and CLI output.
- Include hold context in route lookup without mutating state or waiting.
- Bound local waiters and per-connection wait time.
- Return protocol-appropriate temporary failure when a connection cannot wait
  until the hold clears or expires.
- Audit every mutating operation with reason, actor when available, generation
  and affected user metadata.
- Add low-cardinality observability for hold set, clear, wait, release, timeout
  and resource-limit outcomes.
- Add unit, REST, CLI and public-boundary E2E coverage.

Out of scope:

- Letting Nauthilus create, clear, inspect or enforce placement holds.
- Letting Nauthilus return concrete backend identifiers or migration targets.
- Writing holds or migration state into YAML config.
- Making a hold choose a shard or backend.
- Adding `to_backend` to `UserMoveRequest`.
- Extending backend pinning with time-based expiry in this follow-up.
- Holding unauthenticated sockets before the director knows the user key.
- Holding already attached protocol streams retroactively.
- Treating waiters as runtime sessions or delivery holds.
- Exposing waiter lists through the v1 REST API.
- Adding feature-specific Redis connection settings under `storage.redis`.
- Using Redis Pub/Sub or streams as a correctness requirement for releasing
  waiters.
- Making route lookup create, refresh, clear, consume or wait on holds.

## Binding Options

The v1 operator surface is intentionally narrow. These options are binding for
the first implementation.

Set command:

```text
nauthilus-directorctl users hold set <user-key> \
  --duration <duration> \
  --reason <text>
```

- `--duration` is required. It uses the same Go duration syntax as existing
  config dumps and must be greater than zero.
- `--reason` is required and must be non-empty.
- The CLI must reject empty user keys, missing duration, non-positive duration,
  missing reason and unsupported duration syntax before transport.
- The server must reject durations above
  `director.affinity.user_holds.max_duration`.
- The server computes `expires_at` from Redis server time. The client never
  sends an absolute expiry timestamp in v1.

Show command:

```text
nauthilus-directorctl users hold show <user-key>
```

- `show` returns deterministic absent or present output.
- `show` must not refresh, extend, clear or consume the hold.
- Expired holds are reported as absent even if a cleanup TTL or repair pass has
  not removed the Redis hash yet.

Clear command:

```text
nauthilus-directorctl users hold clear <user-key> --reason <text>
```

- `--reason` is required and must be non-empty.
- `clear` removes only the placement hold. It does not kill sessions, clear
  active affinity, clear backend pins, change shard movement state or rewrite
  YAML.
- Clearing an absent or expired hold is idempotent and should return an accepted
  response with audit metadata.

There are no per-request options for wait mode, timeout, target shard, target
backend, failover behavior, client-visible message, force placement or
indefinite hold in v1. Those concerns are either global safety bounds or existing
runtime controls.

## Configuration Shape

Add the following typed config paths when implementing this follow-up:

```yaml
director:
  affinity:
    user_holds:
      enabled: true
      max_duration: 30m
      max_wait: 30s
      poll_interval: 250ms
      max_local_waiters: 1024
      max_local_waiters_per_user: 16
```

The paths are stable once shipped. They must be included in config defaults,
config path metadata, generated reference docs, config dumps and validation.

Validation rules:

- `enabled` defaults to `true`. No hold exists unless an authenticated operator
  creates one, so enabling the capability does not weaken default routing.
- `max_duration` must be greater than zero.
- `max_wait` must be greater than zero.
- `poll_interval` must be greater than zero and must not exceed `max_wait`.
- `max_local_waiters` must be greater than zero.
- `max_local_waiters_per_user` must be greater than zero and must not exceed
  `max_local_waiters`.

Behavior rules:

- `max_duration` is the upper bound for operator-requested hold lifetime.
- `max_wait` is the maximum time one frontend protocol placement may wait for a
  hold to clear or expire.
- `poll_interval` is the upper bound for Redis re-check cadence while waiting.
  Implementations may wake local waiters sooner after a local clear, but they
  must still work correctly with polling only.
- `max_local_waiters` bounds all placement hold waiters in one Director process.
- `max_local_waiters_per_user` bounds waiters for one affinity key in one
  Director process.

Do not add hold-specific Redis connection, Cluster, Sentinel, TLS or
authentication settings. User holds use the central `storage.redis` runtime
state client.

## Runtime Semantics

A user placement hold is an authoritative, Redis-backed runtime gate for one
affinity key. The affinity key uses the same tenant and normalized account key as
active affinity, user movement, backend pinning and delivery-scoped holds.

The hold stores:

- tenant;
- account key;
- hold generation;
- created timestamp from Redis server time;
- expiry timestamp from Redis server time;
- requested duration;
- reason and actor metadata for audit;
- update timestamp.

The hold does not store backend addresses, backend credentials, TLS material,
private key paths, raw frontend peer addresses, session IDs or raw usernames in
Redis key names.

Placement must check the hold after identity is known and before any backend
selection side effect:

```text
frontend protocol identity resolution
  -> derive tenant + account key
  -> read active user placement hold
  -> wait, release or temporary-fail
  -> read active affinity and movement/backend-pin state
  -> select backend
  -> reserve backend capacity
  -> open session or delivery hold
  -> connect/authenticate to backend
```

While a hold is active:

- new matching placement must not select a backend;
- new matching placement must not reserve backend capacity;
- new matching placement must not open a Redis session record;
- new matching LMTP placement must not open a delivery-scoped hold;
- route lookup must report the hold without waiting or mutating state;
- existing sessions and existing delivery transactions continue unless another
  explicit runtime operation closes them.

When a hold clears or expires before the local `max_wait` budget is exhausted,
the waiting protocol path must re-read runtime state and then continue through
normal placement. It must not reuse a stale routing, affinity, backend-pin or
backend-health decision captured before the wait.

When `max_wait` is exhausted while the hold is still active, the protocol path
must return a temporary failure and close or finish the command according to the
protocol-specific rules below. It must not route to the old backend as a
fallback.

If a placement passes the hold gate before a concurrent `set` operation is
accepted, that placement may continue. The accepted `set` operation guarantees
that later hold checks observe the hold. Operators that need a hard migration
barrier must set the hold first and then use `users kick` or session kill for
already active streams.

## Migration Semantics

The placement hold is deliberately target-free. A migration target is expressed
with existing runtime controls while the hold protects the cutover window.

Recommended shard migration:

```text
1. users hold set <user> --duration 10m --reason "migrate to shard-b"
2. users kick <user> --reason "begin migration"
3. copy or sync mailbox data from old shard to new shard
4. users move <user> --to-shard shard-b --strategy kick_existing \
     --reason "migration target ready"
5. users hold clear <user> --reason "migration complete"
6. held sessions re-check state and place on the new shard
```

Recommended concrete backend commissioning or repair:

```text
1. users hold set <user> --duration 10m --reason "move to backend-b"
2. users kick <user> --reason "begin migration"
3. copy or sync mailbox data
4. users backend-pin set <user> --backend backend-b \
     --strategy kick_existing \
     --reason "target backend ready"
5. users hold clear <user> --reason "migration complete"
6. held sessions re-check state and place on the pinned backend
```

The hold itself must not infer, store or apply `shard-b` or `backend-b` from the
reason text. Reason text is audit context only.

If the hold expires before the operator completes the move or backend pin,
waiting and future sessions continue through normal placement. This is a safety
choice: v1 holds are bounded and cannot become silent indefinite account
outages. Operators must choose a duration that covers the planned migration or
renew the hold explicitly with a new audited `set`.

## Protocol Semantics

The hold is applied only after the director can derive the same affinity key used
for placement.

IMAP:

- Check the hold after Nauthilus authentication and routing fact resolution, but
  before backend selection, backend reservation, Redis session open and backend
  connect.
- While waiting, do not send an authentication success response that implies the
  backend session is ready.
- If the hold clears or expires before `max_wait`, continue the login path
  normally.
- If `max_wait` expires, return a generic temporary unavailable response for the
  authentication command or close with a controlled `BYE` if the IMAP state
  machine cannot produce a safe tagged response. Do not expose operator reason
  text, target shard, backend identifier or expiry timestamp to the client.

LMTP:

- Check the hold after recipient identity lookup resolves the canonical tenant
  and account key, but before accepting the recipient with a final success
  status.
- While waiting, do not open a delivery-scoped hold and do not select or connect
  to a backend.
- If the hold clears or expires before `max_wait`, continue recipient placement
  normally.
- If `max_wait` expires, return a `4xx` temporary recipient status. Do not use a
  permanent `5xx` status for an operator migration hold.
- A hold set after a recipient has already been accepted does not retroactively
  affect that in-flight transaction. Operators must kick or drain separately if
  they need to stop established traffic.

ManageSieve and POP3:

- Later protocol implementations must apply the same gate after authoritative
  identity resolution and before backend selection.
- They must use protocol-appropriate temporary failure behavior on `max_wait`
  timeout.

Unauthenticated sockets:

- The director must not hold unauthenticated sockets merely because the client
  has supplied a candidate username string. The hold key is derived only after
  the normal identity authority path has produced the account key.

## Redis State Model

User-hold state belongs to the existing Redis-backed runtime model. It must use
the same tenant and account-key normalization as active affinity, user move,
backend pinning and delivery-scoped holds.

Use the same per-affinity Redis Cluster hash tag as the existing user runtime
state. The required authoritative key family is:

```text
<prefix>:v<schema>:{aff:<affinity_hash>}:hold
```

The implementation may add repairable secondary indexes only if they are needed
for future listing or cleanup. The v1 API does not require listing all holds, so
the first implementation should not add a global authoritative hold index.

Required operations:

- `SetUserHold`
- `GetUserHold`
- `ClearUserHold`
- `CheckUserHold`

`SetUserHold` must be atomic for the affinity key group. It must use Redis
server time to compute `created_at` and `expires_at`, write the hold hash and set
a cleanup TTL. It must reject non-positive durations and durations above
`director.affinity.user_holds.max_duration`.

`GetUserHold` and `CheckUserHold` must report expired holds as absent based on
Redis server time. They may leave physical cleanup to the key TTL or a later
repair pass. A stale expired hash must never block placement.

`ClearUserHold` must delete only the hold hash. It must not change active
affinity, future move overrides, backend pins, session records, delivery holds
or backend reservations.

Normal placement must not acquire a distributed lock. It reads the hold state,
waits locally if needed, and re-checks the hold with bounded polling or local
notification.

## Waiter Model

Waiters are process-local protocol continuations. They are not Redis sessions,
not delivery holds and not backend reservations.

The implementation must bound waiters in one Director process with
`director.affinity.user_holds.max_local_waiters` and
`director.affinity.user_holds.max_local_waiters_per_user`. If either bound is
exceeded, the new placement attempt must temporary-fail immediately instead of
queuing.

Waiting must be cancellable when the frontend connection closes, the protocol
command is cancelled, the process shuts down, the listener is hard-drained or
the caller context expires.

Waiting must not rely on Redis Pub/Sub, keyspace notifications or streams for
correctness. A local clear operation may wake same-process waiters immediately,
but cross-process release must be correct through bounded polling against Redis.

Waiters released after clear or expiry must re-enter normal placement from the
runtime-state read point. They must not continue from pre-wait selector,
health, backend-pin, affinity or backend-capacity decisions.

## OpenAPI Shape

Extend the existing `users` tag and generate both server and client artifacts
from `docs/specs/openapi/nauthilus-director.yaml`.

Endpoints:

```text
GET    /api/v1/users/{user_key}/hold
PUT    /api/v1/users/{user_key}/hold
DELETE /api/v1/users/{user_key}/hold
```

Operation IDs:

```text
getUserHold
setUserHold
clearUserHold
```

Request schemas:

```yaml
UserHoldRequest:
  type: object
  additionalProperties: false
  required:
    - duration_seconds
    - reason
  properties:
    duration_seconds:
      type: integer
      minimum: 1
    reason:
      type: string
      minLength: 1

UserHoldClearRequest:
  type: object
  additionalProperties: false
  required:
    - reason
  properties:
    reason:
      type: string
      minLength: 1
```

Response schema:

```yaml
UserHold:
  type: object
  additionalProperties: false
  required:
    - present
    - user_key
  properties:
    present:
      type: boolean
    user_key:
      type: string
      minLength: 1
    expires_at:
      type: string
      format: date-time
    remaining_seconds:
      type: integer
      minimum: 0
    generation:
      type: string
    created_at:
      type: string
      format: date-time
```

`GET` returns `200` with `present: false` when no active hold exists. Expired
holds are absent.

`PUT` and `DELETE` return `202` with `AcceptedResponse`. The CLI may call `show`
after a successful mutation when it needs to display the resulting state, but
the REST mutation response remains the same accepted shape used by existing user
runtime mutations.

Use `400` for malformed requests, missing reason, invalid duration or durations
above the configured maximum. Use `409` for state conflicts that cannot be made
idempotent. Use `503` for Redis/runtime ambiguity that must fail closed.

Do not expose operator reason text through the `UserHold` read DTO in v1. Reason
belongs in audit and logs under the existing redaction policy, not in routine
read output.

## CLI Shape

Add a nested user command:

```text
nauthilus-directorctl users hold show <user-key>
nauthilus-directorctl users hold set <user-key> \
  --duration <duration> \
  --reason <text>
nauthilus-directorctl users hold clear <user-key> --reason <text>
```

The CLI must use the generated `ClientWithResponsesInterface`. Hand-written code
may own command grammar, flag validation, output formatting and operator-facing
errors only.

Text output must be compact key-value output. JSON output should emit generated
DTOs where practical. The CLI must reject empty user keys, missing duration,
invalid duration, non-positive duration and missing reason before sending a
request.

Do not add hold flags to `users move`, `users backend-pin`, `users kick` or
`route lookup` in v1. Keeping hold as a separate noun prevents a migration
barrier from being confused with a routing target.

## Route Lookup Diagnostics

Route lookup remains side-effect-free. It may read hold state as diagnostic
context, but it must not set, clear, refresh, consume or wait on a hold.

When a hold is active for the lookup identity, route lookup should report:

- hold presence;
- hold expiry;
- remaining hold time;
- whether placement would be deferred;
- the bounded reason class `user_hold_active`.

Route lookup must not expose operator reason text. It must not call mutating
state methods and must not create waiters. If the existing OpenAPI response
shape cannot represent a deferred placement cleanly, the OpenAPI response must
be extended before runtime code is adapted.

## Observability And Audit

Add or reuse bounded runtime events for:

- user hold set;
- user hold clear;
- user hold read failure;
- user hold wait started;
- user hold wait released;
- user hold wait timeout;
- user hold local waiter limit exceeded;
- placement deferred by user hold;
- route lookup affected by user hold.

Metrics must stay low-cardinality. Do not add username, user hash, session ID,
trace ID, request ID, client IP, raw backend identifier, recipient, raw error
text, reason text or secret-bearing values as metric labels.

Acceptable metric labels are bounded values such as protocol, operation,
outcome, wait outcome and reason class. Raw operator reason text must not be a
metric label.

Logs and audit metadata may include reason text only where the existing
redaction policy permits operator reason text. They must not include passwords,
bearer material, SASL blobs, backend auth secrets, private key paths or raw
client-supplied credentials.

## Package Boundaries

`internal/runtime` owns the user-hold use case:

- request validation;
- configuration-bound duration checks;
- audit metadata;
- operation generation;
- runtime errors used by REST and protocol paths.

`internal/state` owns Redis key layout and atomic hold operations. It must not
import generated REST or client packages.

`internal/protocol/...` packages own protocol-specific wait points and temporary
failure responses. They must call the shared runtime placement gate instead of
duplicating hold logic.

`internal/routing` and `internal/backend` must not know about CLI flags or REST
DTOs. They should see only a placement request that is allowed to continue after
the hold gate has passed.

`internal/rest/adapters` adapts generated OpenAPI DTOs to runtime requests and
responses.

`cmd/nauthilus-directorctl` owns only command grammar, flag parsing, output
formatting and operator-facing errors.

`internal/observability` owns event names, metric labels and log policy.

## Tests

Required unit tests:

- User-hold request validation rejects empty user keys, missing reasons,
  missing durations, non-positive durations and durations above the configured
  maximum.
- `SetUserHold` computes expiry from Redis server time and stores the expected
  bounded fields.
- `GetUserHold` reports absent, present and expired holds deterministically.
- `ClearUserHold` removes only the hold and leaves active affinity, backend
  pins, future move overrides, sessions and delivery holds untouched.
- Setting or clearing a hold does not write YAML config.
- Placement with no hold is unchanged.
- Placement with an active hold waits before selector, backend reservation,
  session open, delivery hold open and backend connect.
- Placement released after clear or expiry re-reads affinity, backend-pin,
  health and selector state before continuing.
- Placement timeout while a hold remains active returns a classified temporary
  failure and does not select a backend.
- Local waiter limits temporary-fail excess placement attempts without queuing.
- Wait cancellation releases local resources on frontend close, context cancel,
  hard listener drain and process shutdown.
- Route lookup reads hold state without waiting or calling mutating state
  methods.

Required protocol tests:

- IMAP authentication waits behind an active hold before backend connect.
- IMAP authentication continues normally when the hold clears before `max_wait`.
- IMAP authentication returns a generic temporary unavailable outcome when
  `max_wait` expires.
- LMTP recipient placement waits behind an active hold before recipient success,
  delivery-hold open and backend selection.
- LMTP recipient placement returns `4xx` when `max_wait` expires.
- A hold set after an IMAP session is attached or an LMTP recipient is accepted
  does not retroactively close that in-flight work.

Required REST and CLI tests:

- OpenAPI contract tests cover the new hold paths and schemas.
- Generated server and client artifacts are fresh after schema changes.
- REST handlers adapt generated DTOs into runtime request structs, not domain
  packages importing generated REST code.
- REST status mapping covers `400`, `409` and `503`.
- `nauthilus-directorctl users hold ...` uses the generated client interface and
  fake-client tests, not raw HTTP mocks.
- Text and JSON output represent absent and present holds deterministically.

Required E2E proof:

- Start the production `nauthilus-director` binary with the control API, fake
  Nauthilus and at least two public protocol backends.
- Set a hold for one test user through `nauthilus-directorctl`.
- Start a public IMAP login for that user and prove no backend connection is
  opened while the hold is active.
- Apply a migration target through `users move` or `users backend-pin`.
- Clear the hold through `nauthilus-directorctl`.
- Prove the waiting login completes through the public protocol path and reaches
  the new placement target.
- Prove an unrelated user is not blocked by the held user's state.
- Prove route lookup reports the active hold before clear without mutating
  Redis, creating sessions or opening delivery holds.
- Prove `max_wait` timeout produces a temporary protocol failure and no backend
  placement when the hold is not cleared.

Run `make generate-openapi` after changing the OpenAPI spec, then run
`make check-openapi`. Before commit or pull request, run `make guardrails`.

## Acceptance Criteria

- Operators can set, show and clear a time-limited placement hold for one user
  through REST and CLI.
- Every hold has a finite duration and an expiry computed from Redis server
  time.
- Holds are capped by `director.affinity.user_holds.max_duration`.
- New placement for the affected user waits before backend selection and before
  any backend-side effect.
- Existing sessions and accepted delivery transactions continue unless another
  explicit runtime operation closes them.
- Waiters are local, bounded, cancellable and not exposed as runtime sessions.
- Placement timeout while a hold remains active temporary-fails and never routes
  to the old backend as a fallback.
- Hold clear removes only the hold and wakes same-process waiters where
  practical.
- Cross-process release works through bounded Redis polling without relying on
  Pub/Sub or keyspace notifications.
- Migration target selection remains owned by `users move`, `users backend-pin`
  and normal selector rules.
- Route lookup reports hold context without waiting or mutating state.
- Generated OpenAPI server and client artifacts are reproducible.
- `nauthilus-directorctl` uses the generated client SDK for every hold command.
- Observability remains low-cardinality and secret-safe.
- E2E proves externally visible protocol behavior through the production binary.

## Completion Evidence

Completed on 2026-05-31.

Implemented and verified behavior:

- Generated OpenAPI REST and generated-client-backed
  `nauthilus-directorctl users hold show|set|clear` are implemented.
- Redis-backed hold state stores bounded runtime metadata only, uses Redis
  server time for expiry, and clear deletes only the hold hash.
- IMAP and LMTP placement check the shared hold gate after identity resolution
  and before backend selection, session or delivery-hold open, backend
  reservation and backend connect.
- Route lookup reports `user_hold_active` context without waiting, mutating
  state, opening sessions or exposing operator reason text.
- Public-boundary fake-service E2E now includes
  `TestServerBinaryUserHoldPublicIMAPReleaseFlow` and
  `TestServerBinaryUserHoldPublicIMAPTimeoutFlow`.
- `contrib/demo-stack/scripts/prove-user-hold.sh` demonstrates the same
  operator workflow against the Compose demo stack.
- `docs/config/nauthilus-director.target.yml` and generated config reference
  docs include `director.affinity.user_holds`.

Verification run:

```text
NAUTHILUS_DIRECTOR_E2E_SERVER_BINARY=/private/tmp/nauthilus-director-e2e \
  go test -mod=vendor -count=1 ./test/e2e \
  -run 'TestServerBinaryUserHoldPublicIMAP(Release|Timeout)Flow' -v
PASS

make guardrails
PASS

cd contrib/demo-stack
docker compose build director-a director-b
docker compose up -d --no-deps --force-recreate director-a director-b
docker compose exec -T director-a nauthilus-directorctl --address http://127.0.0.1:9090 status
health=ok
ready=ok
version=demo
api_version=v1
docker compose exec -T director-b nauthilus-directorctl --address http://127.0.0.1:9090 status
health=ok
ready=ok
version=demo
api_version=v1
./scripts/prove-user-hold.sh
proof ok: mode=user-hold user=dave@example.test backend=mailstore-b-imap held_login_waited=true route_lookup_read_only=true
```

Director demo image IDs after the scoped rebuild:

```text
nauthilus-director-demo-director-a sha256:98d6aee5d6d3a2f477ca0a95fb395fd83c992edbf0e7a2d368eaa46e95aae5ef
nauthilus-director-demo-director-b sha256:3219ec895f7551ef801be24532c9733f570846585a5e7a5e0d12c6a67d442e8b
```

`make e2e-interop` was not required for this closeout because the changed
production behavior was already implemented before this slice; this slice added
public fake-service E2E, demo-stack proof scripting and documentation without
changing IMAP, LMTP, proxy or bootstrap production code.

## Review und Ist/Soll-Abgleich

| Area | Soll | Ist | Status | Notes |
| --- | --- | --- | --- | --- |
| E2E hold | Held user waits with no backend/session/reservation side effect | `TestServerBinaryUserHoldPublicIMAPReleaseFlow` starts a held public IMAP login, proves no fake backend connections, no REST sessions and no runtime reservations while the hold is active | OK | Route lookup is also checked while the login is waiting |
| E2E release | Clear releases waiting placement to new target | The test sets `users backend-pin` to `mailstore-b-imap`, clears the hold through CLI and verifies the waiting login proxies to backend B | OK | Demo stack repeats this with `prove-user-hold.sh` |
| E2E timeout | `max_wait` temporary-fails without backend placement | `TestServerBinaryUserHoldPublicIMAPTimeoutFlow` uses a short `max_wait`, receives IMAP `[UNAVAILABLE]` and proves no backend connection, session or reservation | OK | Route lookup still reports the active hold after timeout |
| Route lookup | Hold diagnostics read-only and non-waiting | Route lookup returns active hold context in under the bounded probe window and does not change public session or runtime-summary counts | OK | DTO exposes bounded reason class, not operator text |
| Docs | Manpages, developer docs, spec and roadmap match shipped behavior | CLI manpage, affinity developer doc, architecture roadmap and this closeout describe runtime-only temporary holds, explicit clear and route lookup diagnostics | OK | Unsupported list, renew, force-placement and target flags remain undocumented |
| Generated | OpenAPI and config docs current | `make guardrails` includes `check-openapi` and `check-docs`; reference docs and target YAML include `director.affinity.user_holds` | OK | No generated drift after the closeout |
| Guardrails | Full gate run and results recorded | `make guardrails` passed on 2026-05-31 | OK | E2E runner output includes user placement holds |

## Review Checklist

- Verify no hold mutation writes YAML config.
- Verify no target shard or backend is stored in the hold state.
- Verify hold expiry uses Redis server time.
- Verify expired holds never block placement.
- Verify no raw usernames are used in Redis key names.
- Verify no generated REST DTO leaks into runtime, state, routing, backend or
  protocol domain packages.
- Verify protocol paths check holds before backend selection, backend
  reservation, session open, delivery hold open and backend connect.
- Verify held waiters are not listed as sessions.
- Verify local waiter limits prevent unbounded memory growth.
- Verify timeout behavior is temporary failure, not silent placement fallback.
- Verify route lookup remains read-only and does not call wait paths.
- Verify reason text is not returned through routine read DTOs and is not used
  as a metric label.
- Verify manpages document the migration workflow and explicit clear operation.
- Verify E2E proves public-socket behavior, not only internal state.

## Resolved Decisions

1. The feature name is user placement hold; the CLI noun is `users hold`.
2. A hold is a temporary placement gate, not a routing target.
3. A hold applies after identity resolution and before backend selection.
4. A hold blocks new placement but does not retroactively affect existing
   sessions or accepted delivery transactions.
5. Every hold requires a positive duration and a non-empty reason.
6. The server computes expiry from Redis server time.
7. The client sends `duration_seconds` through REST and `--duration` through CLI;
   it does not send an absolute expiry timestamp in v1.
8. Requested durations above `director.affinity.user_holds.max_duration` are
   rejected, not clamped.
9. Placement wait is bounded by `director.affinity.user_holds.max_wait`.
10. Waiters are process-local and correctness must not depend on Redis Pub/Sub,
    streams or keyspace notifications.
11. Timeout while a hold remains active returns a protocol temporary failure and
    does not route.
12. Hold clear removes only the hold. It does not clear active affinity, backend
    pins, movement overrides or sessions.
13. Route lookup reports hold context without waiting or mutating state.
14. Reason text is audit context and is not returned by the v1 hold read DTO.

## Open Questions

No blocking questions remain for an initial v1 implementation if the runtime
semantics above are accepted.

Future enhancements may add hold listing, cluster-wide waiter statistics,
explicit renewal commands or target metadata for operator dashboards. Those are
intentionally out of scope for v1 so the first implementation stays a bounded
migration barrier rather than a second routing control plane.
