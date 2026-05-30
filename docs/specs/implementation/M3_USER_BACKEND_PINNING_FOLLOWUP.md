# M3 User Backend Pinning Follow-up

Status: proposed. This follow-up amends the completed M2/M3 backend runtime and
control milestone with an operator workflow for binding one user key to one
concrete backend for controlled canary and commissioning tests.

The current user movement model intentionally targets shards, not concrete
backends. That keeps normal placement director-owned and avoids turning
Nauthilus or operator input into the general backend selector. The missing
workflow is narrower: an operator sometimes needs to add a new backend with
effective weight `0`, keep it out of normal placement, and route exactly one
test user to that backend before raising weight for production traffic.

This document defines that workflow as an OpenAPI-first runtime-control
extension. It is not a YAML rewrite feature and not a replacement for normal
shard routing.

## Source Documents

This follow-up is governed by:

- `AGENTS.md`
- `docs/ARCHITECTURE_ROADMAP.md`
- `docs/specs/implementation/M0_FOUNDATION_SPEC.md`
- `docs/specs/implementation/M1_IMAP_MVP_SPEC.md`
- `docs/specs/implementation/M2_M3_BACKEND_RUNTIME_CONTROL_SPEC.md`
- `docs/specs/implementation/M2_M3_RUNTIME_STATE_MILLION_SCALE_CHANGE_SPEC.md`
- `docs/specs/implementation/M3_LISTENER_RUNTIME_CONTROL_FOLLOWUP.md`
- `docs/specs/implementation/M4_OBSERVABILITY_SPEC.md`
- `docs/specs/implementation/M5_LMTP_PRODUCTION_SPEC.md`
- `docs/specs/openapi/nauthilus-director.yaml`
- `docs/man/nauthilus-directorctl.1`
- `docs/man/nauthilus-director.1`
- `Makefile`

If this document conflicts with those source documents, fix the drift before
implementation continues.

## Original Gap

`nauthilus-directorctl users move <user-key> --to-shard <shard>` changes the
runtime placement target at the shard boundary. It does not accept a concrete
backend identifier, and the OpenAPI `UserMoveRequest` has no `to_backend`
field. After the target shard is known, the runtime-aware selector still chooses
one concrete backend from the configured protocol and backend-pool candidates.

That is the right default behavior, but it leaves a real operations gap:

- a new backend can be configured in the correct shard with weight `0`;
- normal user placement should not select that backend yet;
- a test user must still be able to exercise that exact backend through the
  public protocol path;
- raising the backend weight just to test it risks sending unrelated users to
  the backend;
- creating a temporary one-backend shard changes the routing model instead of
  testing the intended production shard;
- route lookup can diagnose selection, but it must remain side-effect-free and
  cannot establish the test placement.

The follow-up must close that gap without weakening the director-owned routing
boundary.

## Goal

Add a generated REST and `nauthilus-directorctl` control surface that lets an
operator set, inspect and clear a user-scoped backend pin:

```text
operator
  -> configure new backend mailstore-c-imap in shard mailstore-a with weight 0
  -> nauthilus-directorctl backends show mailstore-c-imap
  -> nauthilus-directorctl users backend-pin set test@example.org \
       --backend mailstore-c-imap \
       --strategy kick_existing \
       --reason "commission mailstore-c"
  -> test@example.org logs in through the public IMAP listener
  -> selector chooses mailstore-c-imap because of the explicit operator pin
  -> unrelated users continue normal placement and do not select weight-0 backend
  -> nauthilus-directorctl users backend-pin clear test@example.org \
       --reason "commissioning complete"
```

The backend pin is a runtime override for one affinity key and one concrete
protocol backend. It must be audited, generated-client-backed, Redis-backed and
visible through diagnostics. It must not write YAML, create a second hand-written
REST model, or make Nauthilus responsible for backend selection.

## Delivery Placement

Implement this as an M3 runtime-control follow-up. The feature is not a new
protocol milestone: it extends the existing backend/user/session runtime control
model and the generated REST/CLI operator surface.

Implementation slices:

1. Runtime domain semantics and request validation.
2. Redis-backed user backend-pin state and read model.
3. Backend selector support for an explicit operator target.
4. OpenAPI schema update plus generated server and client refresh.
5. REST adapter implementation and handler tests.
6. `nauthilus-directorctl users backend-pin ...` commands with fake generated
   client tests.
7. Route lookup diagnostics for backend pins.
8. Manpage updates and deterministic E2E proof through the production binary.

The slices may be committed separately, but the follow-up is complete only when
REST, CLI, route lookup and public protocol behavior all prove the same
semantics.

## Implementation Effort

Expected effort is medium. This is not a one-flag CLI extension because the
selector, Redis state, generated OpenAPI artifacts, CLI, route diagnostics and
E2E proof all need to agree.

The smallest safe implementation should be comparable to the listener runtime
follow-up, with slightly more selector and Redis-state work:

- Low risk: CLI grammar, generated-client plumbing, manpage text and handler
  adaptation.
- Medium risk: Redis state shape, strategy behavior while sessions are active,
  and route-lookup reporting.
- Highest risk: selector semantics that intentionally bypass `weight_zero` for
  the pinned backend while continuing to fail closed for unsafe backend states.

Plan for several focused implementation slices plus full `make guardrails`. A
single concentrated engineering pass is realistic if the state model below is
accepted before coding starts.

## Scope

In scope:

- Add a user-scoped operator backend pin for one concrete configured backend
  identifier.
- Derive protocol, backend pool and effective shard from the configured backend
  entry; do not trust operator-supplied duplicates for those facts.
- Keep normal routing and Nauthilus identity resolution unchanged.
- Keep normal user movement to shards unchanged.
- Require backend pins to remain inside the pinned backend's derived effective
  shard; cross-shard backend pinning is invalid and must fail closed.
- Let an explicit backend pin override `weight_zero` for the pinned backend only.
- Keep all other backend safety exclusions fail-closed unless this document
  explicitly allows them.
- Support the same user move strategies as shard movement:
  - `new_sessions_only`
  - `kick_existing`
  - `drain_existing`
- Store backend pins in Redis runtime state, not YAML.
- Expose backend-pin state through generated REST DTOs and CLI output.
- Include backend-pin context in route lookup without mutating state.
- Audit every mutating operation with reason, actor when available, generation
  and affected user/backend metadata.
- Add low-cardinality observability for backend-pin operations and selector
  outcomes.
- Add unit, REST, CLI and public-boundary E2E coverage.

Out of scope:

- Letting Nauthilus return concrete backend identifiers.
- Adding `to_backend` to the existing shard move request.
- Replacing shard routing or changing routing facts in Nauthilus.
- Writing backend pins into YAML config.
- Adding an unbounded global user-to-backend map.
- Pinning one user to multiple backends through one request.
- Pinning a user across all protocols by naming an IMAP backend.
- Silently failing over from a pinned backend to another backend.
- Bypassing hard or soft maintenance, runtime out, runtime drain, failed health,
  max-connection limits, TLS policy or backend authentication failures.
- Making route lookup create, refresh, move, kick, clear or pin sessions.

## Runtime Semantics

A backend pin is a runtime placement override for one affinity key and one
protocol backend scope. The server resolves the requested backend identifier
against the current config-backed backend registry. The resulting pin stores:

- tenant;
- account key;
- backend identifier;
- backend protocol;
- backend pool;
- backend effective shard;
- strategy;
- generation;
- reason and actor metadata for audit;
- update timestamp.

The backend pin affects only placements whose listener protocol and backend pool
match the pinned backend. Other protocols and backend pools continue to use the
normal shard routing and active-affinity rules.

The target backend's effective shard becomes the target shard for the user move
strategy. This keeps active affinity coherent: a user pinned to
`mailstore-c-imap` in effective shard `mailstore-a` still has shard affinity to
`mailstore-a`. The concrete backend pin is an additional selector constraint,
not a replacement for shard affinity.

A backend pin must never select a backend outside the target effective shard for
the matching placement request. Cross-shard backend pinning is invalid; the
server derives the target shard from the configured backend and the selector must
fail closed if the pinned backend's effective shard does not match the request
shard.

Strategy behavior:

- `new_sessions_only` stores the backend pin and target shard for future
  placement. Existing active sessions continue. While active affinity is still
  present, new sessions preserve the existing active placement. After the active
  affinity expires or is cleared, new matching-protocol sessions use the pinned
  backend.
- `drain_existing` stores the backend pin and target shard while allowing
  existing sessions to drain naturally. It must not force-close sessions.
  Matching-protocol sessions follow existing active affinity until the active
  state is gone.
- `kick_existing` stores the backend pin, updates the active shard to the pinned
  backend's effective shard, increments the control generation and asks active
  sessions for that affinity key to close through the existing controlled
  runtime action path.

Clearing a backend pin removes the concrete backend override. It does not kill
active sessions, clear shard affinity or rewrite YAML. Existing sessions continue
until they close normally or another explicit runtime operation affects them.

If the pinned backend is removed from config, changes protocol, leaves the
backend pool or moves to a different effective shard before the pin is cleared,
matching-protocol placement must fail closed with a clear operator diagnostic.
It must not silently route the test user to a different backend.

## Selector Semantics

Add an explicit operator backend target to the backend selection request. The
selector remains responsible for converting:

```text
account key + tenant + effective shard + protocol + backend pool
  -> one concrete backend
```

When no operator backend target is present, the selector behavior is unchanged.

When an operator backend target is present:

1. Validate that the backend identifier exists in the current registry.
2. Validate that the backend protocol, backend pool and effective shard match the
   selection request.
3. Build the same effective backend state used by route lookup and normal
   placement.
4. Ignore only the `weight_zero` exclusion for the target backend.
5. Reject the target backend for all other effective exclusions:
   - ambiguous runtime state;
   - hard or soft maintenance;
   - runtime out;
   - runtime drain;
   - failed or stale health when health enforcement applies;
   - max-connections saturation;
   - static or runtime policy that excludes placement;
   - protocol or backend-pool mismatch.
6. Return the target backend with reason `operator_backend_pin`.

No implicit failover is allowed for an operator backend pin. If the target
backend is not usable, the placement must fail closed. The failure is the test
result the operator needs.

The selector must still reserve backend capacity before attaching the selected
backend to the session. A backend pin must not bypass the backend reservation
model or max-connection accounting.

## Redis State Model

Backend-pin state belongs to the existing Redis-backed runtime model. It must
use the same tenant and account-key normalization as active affinity and user
move state. It must not use raw usernames in Redis keys.

Use per-affinity key groups so user pin mutations remain Redis Cluster safe. The
pin state can be represented as one hash per affinity key plus protocol and
backend-pool scope, or as a bounded field set under the existing affinity hash
tag. The implementation must document the chosen key layout in
`docs/developer/AFFINITY_SESSION_HANDLING.md` when it lands.

Required operations:

- `SetUserBackendPin`
- `GetUserBackendPin`
- `ClearUserBackendPin`

The set operation must be atomic for the user affinity key group. When
`kick_existing` is requested, setting the backend pin and updating the user
control generation must happen as one same-slot mutation. Repairable indexes may
be updated from Go after the authoritative mutation, following the existing
runtime-state pattern.

Do not store backend transport details, TLS material, credentials or raw
addresses in backend-pin state. Those remain in the typed config snapshot and
backend registry.

## OpenAPI Shape

Extend the existing `users` tag and generate both server and client artifacts
from `docs/specs/openapi/nauthilus-director.yaml`.

Endpoints:

```text
GET    /api/v1/users/{user_key}/backend-pin
PUT    /api/v1/users/{user_key}/backend-pin
DELETE /api/v1/users/{user_key}/backend-pin
```

Operation IDs:

```text
getUserBackendPin
setUserBackendPin
clearUserBackendPin
```

Request schemas:

```yaml
UserBackendPinRequest:
  type: object
  additionalProperties: false
  required:
    - backend
    - strategy
    - reason
  properties:
    backend:
      type: string
      minLength: 1
    strategy:
      $ref: "#/components/schemas/UserMoveRequestStrategy"
    reason:
      type: string
      minLength: 1

UserBackendPinClearRequest:
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
UserBackendPin:
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
    backend:
      type: string
    protocol:
      type: string
    backend_pool:
      type: string
    shard_tag:
      type: string
    strategy:
      $ref: "#/components/schemas/UserMoveRequestStrategy"
    generation:
      type: string
    active_session_count:
      type: integer
      minimum: 0
```

`GET` returns `200` with `present: false` when no backend pin exists. `PUT` and
`DELETE` return `202` with an `AcceptedResponse` unless implementation chooses to
return the updated `UserBackendPin`; either shape must be used consistently in
REST, CLI and tests before closeout.

Use `400` for malformed requests or unsupported strategies, `404` for unknown
target backends, `409` for state conflicts, and `503` for Redis/runtime
ambiguity that must fail closed.

## CLI Shape

Add a nested user command:

```text
nauthilus-directorctl users backend-pin show <user-key>
nauthilus-directorctl users backend-pin set <user-key> \
  --backend <identifier> \
  --strategy <new_sessions_only|kick_existing|drain_existing> \
  --reason <text>
nauthilus-directorctl users backend-pin clear <user-key> --reason <text>
```

The CLI must use the generated `ClientWithResponsesInterface`. Hand-written code
may own command grammar, flag validation, output formatting and operator-facing
errors only.

Text output must be compact key-value output. JSON output should emit generated
DTOs where practical. The CLI must reject empty user keys, empty backend
identifiers, missing reasons and unsupported strategies before sending a request.

Do not extend `users move` with a `--to-backend` flag in v1. Keeping backend
pinning under a separate `backend-pin` noun prevents a targeted commissioning
override from being confused with normal shard movement.

## Route Lookup Diagnostics

Route lookup remains side-effect-free. It may read backend-pin state as
diagnostic context, but it must not set, clear, refresh or consume the pin.

When a backend pin applies to the lookup protocol and backend pool, the route
lookup response should include:

- pin presence;
- pinned backend identifier;
- pinned backend protocol and backend pool;
- pinned backend effective shard;
- whether the pin was applied;
- if not applied, the bounded exclusion reason.

Route lookup must continue to reject credential-bearing input and must not call
Nauthilus.

## Observability And Audit

Add or reuse bounded runtime events for:

- backend pin set;
- backend pin clear;
- backend pin read failure;
- selector use of an operator backend pin;
- selector rejection of a pinned backend.

Metrics must stay low-cardinality. Do not add username, user hash, session ID,
trace ID, request ID, client IP, raw backend identifier, recipient, raw error
text, reason text or secret-bearing values as metric labels.

Logs and audit metadata may include the backend identifier where the existing log
policy permits backend identifiers for runtime diagnostics. They must not include
credentials, bearer material, backend auth secrets, passwords or private key
paths.

## Tests

Required unit tests:

- Backend-pin request validation rejects empty user keys, empty backend
  identifiers, missing reasons and unsupported strategies.
- Setting a pin validates that the target backend exists and derives protocol,
  backend pool and effective shard from the registry.
- Setting a pin does not write YAML config.
- `new_sessions_only` and `drain_existing` do not close active sessions.
- `kick_existing` increments control generation and asks active sessions to close
  through the existing controlled runtime action path.
- Clearing a pin removes only the concrete backend override and leaves active
  sessions alone.
- Selector behavior without a pin is unchanged.
- Selector with a pin chooses the target backend even when effective weight is
  `0`.
- Selector with a pin rejects hard maintenance, soft maintenance, runtime out,
  runtime drain, unhealthy state, max-connection saturation, shard mismatch,
  protocol mismatch and backend-pool mismatch.
- Selector with a pin does not silently fail over to another backend.
- Backend reservation and attach still run for pinned selections.
- Route lookup reads backend-pin context without calling mutating state methods.

Required REST and CLI tests:

- OpenAPI contract tests cover the new backend-pin paths and schemas.
- Generated server and client artifacts are fresh after schema changes.
- REST handlers adapt generated DTOs into runtime request structs, not domain
  packages importing generated REST code.
- REST status mapping covers `400`, `404`, `409` and `503`.
- `nauthilus-directorctl users backend-pin ...` uses the generated client
  interface and fake-client tests, not raw HTTP mocks.
- Text and JSON output represent absent and present pins deterministically.

Required E2E proof:

- Start the production `nauthilus-director` binary with the control API and at
  least three IMAP backends in one pool.
- Configure the new test backend in the intended shard with weight `0`.
- Prove an unrelated user is not placed on the weight-0 backend through normal
  login or route lookup.
- Set a backend pin for one test user through `nauthilus-directorctl`.
- Prove the test user reaches the pinned backend through a public IMAP socket and
  normal backend connect/auth/proxy behavior.
- Prove route lookup reports the backend pin and selection reason without
  mutating state.
- Clear the backend pin through `nauthilus-directorctl`.
- Prove the test user returns to normal shard placement after active affinity is
  closed or cleared.

Run `make generate-openapi` after changing the OpenAPI spec, then run
`make check-openapi`. Before commit or pull request, run `make guardrails`.

## Acceptance Criteria

- Operators can set, show and clear a backend pin for one user through REST and
  CLI.
- Backend pinning is backed by generated OpenAPI server and client artifacts.
- The targeted backend can have effective weight `0` and still receive the pinned
  test user.
- Unrelated users do not select the weight-0 backend through normal placement.
- Backend pinning remains protocol and backend-pool scoped.
- Backend pinning does not rewrite YAML configuration.
- Backend pinning does not make Nauthilus choose concrete backends.
- Backend pinning does not bypass non-weight safety exclusions.
- Pinned backend failure does not silently fail over to another backend.
- Route lookup reports backend-pin context without mutating state.
- Observability remains low-cardinality and secret-safe.
- E2E proves externally visible protocol behavior through the production binary.

## Review Checklist

- Verify no `to_backend` field is added to `UserMoveRequest`.
- Verify backend-pin runtime state uses normalized tenant and account keys.
- Verify no raw usernames are used in Redis key names.
- Verify backend-pin mutation does not write YAML.
- Verify generated files are updated only through the OpenAPI generator.
- Verify domain packages do not import generated REST or client packages.
- Verify selector pinning bypasses only `weight_zero`.
- Verify selector pinning fails closed for every other exclusion.
- Verify backend capacity reservation and selected-backend attach still run.
- Verify route lookup remains read-only and does not call Nauthilus.
- Verify manpages document the commissioning workflow and clear operation.
- Verify E2E proves public-socket placement, not only internal state.

## Resolved Decisions

1. Backend pinning is a separate `users backend-pin` workflow, not a `users move
   --to-backend` extension.
2. A backend pin targets one concrete configured backend identifier.
3. Protocol, backend pool and effective shard are derived from the backend
   registry, not trusted from operator input.
4. A backend pin applies only when the session protocol and backend pool match
   the pinned backend.
5. The pinned backend may be selected with effective weight `0`.
6. The pinned backend must still pass all non-weight safety checks.
7. A pinned backend failure fails closed and does not silently fail over.
8. Clearing a backend pin does not kill active sessions or clear shard affinity.
9. Backend-pin route lookup support is diagnostic only and remains
   side-effect-free.

## Open Questions

No blocking questions remain for an initial v1 implementation if the runtime
semantics above are accepted.

A future enhancement may add explicit pin expiry or time-limited pins. That is
intentionally out of scope for v1 so the first implementation stays aligned with
the existing runtime override model: state persists until an explicit clear,
reload does not rewrite it, and every mutating operation is audited.
