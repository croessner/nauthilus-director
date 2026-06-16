# M8 Multi-Protocol Backend Pinning Follow-up

Status: completed. The scoped Redis state model, generated REST boundary,
`nauthilus-directorctl` backend-node workflow, selector and route-lookup
integration, documentation and public-boundary fake-service E2E proof are in
place. Final validation completed on 2026-06-16.

This document defines a focused runtime-control repair for user backend pins.
It is motivated by a real mail-stack migration drill where a single mailbox
account had to be moved to a weight-zero canary backend node across IMAP,
ManageSieve and LMTP at the same time.

The existing backend-pin implementation is correct for the original M3
commissioning case: one user, one concrete protocol backend, one selector
bypass of `weight_zero`. It is not sufficient for a per-user mailbox migration
where the same account must be pinned to one backend node across multiple
stateful protocols. The implementation must therefore grow from a single
per-affinity backend-pin record to a bounded, protocol/backend-pool-scoped pin
set with an operator-friendly all-protocol workflow.

The follow-up must preserve the existing architecture boundaries:

- Nauthilus remains the authentication and identity authority only.
- `nauthilus-director` remains responsible for routing, affinity, backend
  selection, runtime state and proxy behavior.
- Runtime control remains Redis-backed and must not rewrite YAML config.
- Route lookup remains side-effect-free.

## Source Documents

This follow-up is governed by:

- `AGENTS.md`
- `POLICY.md`
- `docs/ARCHITECTURE_ROADMAP.md`
- `docs/specs/implementation/M0_FOUNDATION_SPEC.md`
- `docs/specs/implementation/M1_IMAP_MVP_SPEC.md`
- `docs/specs/implementation/M2_M3_BACKEND_RUNTIME_CONTROL_SPEC.md`
- `docs/specs/implementation/M2_M3_RUNTIME_STATE_MILLION_SCALE_CHANGE_SPEC.md`
- `docs/specs/implementation/M3_ROUTE_LOOKUP_FOLLOWUP.md`
- `docs/specs/implementation/M3_USER_BACKEND_PINNING_FOLLOWUP.md`
- `docs/specs/implementation/M3_USER_PLACEMENT_HOLD_FOLLOWUP.md`
- `docs/specs/implementation/M5_CROSS_PROTOCOL_BACKEND_AFFINITY_FOLLOWUP.md`
- `docs/specs/implementation/M5_LMTP_PRODUCTION_SPEC.md`
- `docs/specs/implementation/M6_MANAGESIEVE_PROXY_SPEC.md`
- `docs/specs/implementation/M7_POP3_PROXY_SPEC.md`
- `docs/specs/implementation/M8_PRODUCTION_HARDENING_SPEC.md`
- `docs/developer/AFFINITY_SESSION_HANDLING.md`
- `docs/specs/openapi/nauthilus-director.yaml`
- `docs/man/nauthilus-directorctl.1`
- `docs/man/nauthilus-director.yaml.5`
- `docs/config/nauthilus-director.target.yml`
- `docs/reference/config-defaults.yaml`
- `docs/reference/config-paths.md`
- `Makefile`

If this document conflicts with those source documents, fix the drift before
implementation continues. The M3 backend-pinning follow-up remains the source
for one concrete protocol backend pin. This document supersedes only the
assumption that a user can have at most one backend pin and that all-protocol
pinning is out of scope.

## Observed Failure

A production-like canary configuration had these backends in active Director
pools:

```text
node2-imap                protocol=imap  shard_tag=node2
node2-sieve               protocol=sieve shard_tag=node2
node2-lmtp                protocol=lmtp  shard_tag=node2
mailstack-canary-imap     protocol=imap  shard_tag=mailstack-canary weight=0
mailstack-canary-sieve    protocol=sieve shard_tag=mailstack-canary weight=0
mailstack-canary-lmtp     protocol=lmtp  shard_tag=mailstack-canary weight=0
```

The intended migration workflow was:

```text
users hold set pilot@example.org --duration 15m
users move pilot@example.org --to-shard mailstack-canary --strategy new_sessions_only
users backend-pin set pilot@example.org --backend mailstack-canary-imap  --strategy new_sessions_only
users backend-pin set pilot@example.org --backend mailstack-canary-sieve --strategy new_sessions_only
users backend-pin set pilot@example.org --backend mailstack-canary-lmtp  --strategy new_sessions_only
```

The first route lookups before mutation were healthy and selected `node2-*`.
After the three backend-pin commands, only the last pin remained authoritative.
The stored pin pointed to `mailstack-canary-lmtp`.

The resulting route lookup behavior was:

- LMTP selected `mailstack-canary-lmtp` with `source=operator_backend_pin`.
- IMAP and ManageSieve saw a present backend pin, but it was the LMTP pin.
- IMAP and ManageSieve reported `backend_pin_mismatch`.
- Because the user had been moved to `mailstack-canary` and the canary
  protocol backends had effective weight `0`, there was no matching operator
  pin to bypass the `weight_zero` exclusion.
- IMAP and ManageSieve failed closed with `reason=no_backend`.

This is the correct fail-closed behavior for the current single-pin model, but
it proves that the model does not satisfy the per-user mailbox migration
workflow.

The reproduction also exposed a test gap. Existing unit and public-boundary E2E
coverage prove one protocol-scoped backend pin, but they do not prove that:

- setting an IMAP pin followed by an LMTP pin does not overwrite the IMAP pin;
- a route lookup for one protocol ignores a different protocol's pin without
  poisoning that protocol;
- one user can be canary-pinned across IMAP, ManageSieve and LMTP at the same
  time;
- clearing without a protocol removes every scoped pin for that user.

## Original Gap

The current Redis model stores one `backend_pin` hash per affinity key. The
record contains derived selector facts:

```text
backend identifier
protocol
backend pool
effective shard
strategy
generation
audit metadata
```

That shape cannot represent more than one protocol/backend-pool scope for the
same user. The CLI and REST surface mirror that limitation:

```text
nauthilus-directorctl users backend-pin set <user-key> --backend <identifier>
nauthilus-directorctl users backend-pin clear <user-key> --reason <text>
```

The command does not accept a protocol argument, but the concrete backend
identifier resolves to exactly one protocol and backend pool. Repeating the
command with another protocol backend overwrites the previous pin because the
authoritative key remains only the affinity key.

This conflicts with the cross-protocol mailbox invariant:

```text
tenant + normalized_account -> shard_tag + backend_node
backend_node + protocol + backend_pool -> backend_identifier
```

For a controlled mailbox migration, an operator needs to say:

```text
pin this account to backend_node=mailstack-canary for every configured
stateful mailbox protocol this deployment exposes
```

The operator should not have to hand-maintain three or four independent commands
for the common all-protocol case, and the implementation must still support
focused protocol-scoped pins for commissioning a single protocol backend.

## Goal

Extend backend pinning so one affinity key can hold multiple scoped backend
pins:

```text
tenant + account_key + protocol + backend_pool -> backend_identifier
```

Add an operator workflow that can pin or unpin every configured protocol for a
backend node without requiring a protocol argument:

```text
nauthilus-directorctl users backend-pin set pilot@example.org \
  --backend-node mailstack-canary \
  --strategy new_sessions_only \
  --reason "mailbox canary"

nauthilus-directorctl users backend-pin clear pilot@example.org \
  --reason "mailbox canary done"
```

The all-protocol set operation must resolve `backend_node=mailstack-canary`
against the current backend registry and materialize one scoped pin per required
protocol/backend-pool entry, for example:

```text
imap  + imap-default  -> mailstack-canary-imap
sieve + sieve-default -> mailstack-canary-sieve
lmtp  + lmtp-default  -> mailstack-canary-lmtp
```

The existing concrete-backend workflow remains useful and should stay available:

```text
nauthilus-directorctl users backend-pin set pilot@example.org \
  --backend mailstack-canary-imap \
  --strategy new_sessions_only \
  --reason "commission IMAP only"
```

Implementation may adjust exact flag names if needed, but the operator
semantics are mandatory:

- naming one concrete backend pins that backend's protocol/backend-pool scope;
- naming a backend node with no protocol pins all configured protocol scopes for
  that node;
- clearing with no protocol clears all backend pins for that user;
- protocol-scoped clear remains possible for narrow commissioning cleanup.

## Delivery Shape

Implement this follow-up as eight slices:

1. Failing unit reproducer for the observed overwrite and route-mismatch case.
2. Redis state model change from one backend-pin record to a bounded scoped pin
   set under the same per-affinity hash tag.
3. Placement and selector integration that reads only the pin matching the
   current protocol and backend pool.
4. Backend-node all-protocol resolution and atomic set/clear operations.
5. OpenAPI schema update plus generated server and client refresh.
6. REST adapter and `nauthilus-directorctl users backend-pin ...` updates.
7. Route lookup diagnostics for absent, scoped, all-protocol and mismatched
   pin state.
8. Deterministic public-boundary E2E and Docker interoperability proof for
   multi-protocol canary pinning.

The implementation may be split further, but it is complete only when unit,
REST, CLI, route lookup, fake-service E2E and real-server interoperability
coverage all prove the same semantics.

## Scope

In scope:

- Allow multiple backend pins for one affinity key when their
  `protocol + backend_pool` scopes differ.
- Keep each individual pin tied to one concrete configured backend identifier.
- Add an all-protocol operator workflow that resolves a backend node to all
  required protocol/backend-pool entries for that user placement domain.
- Keep the existing concrete `--backend <identifier>` workflow backward
  compatible for one protocol-scoped pin.
- Derive protocol, backend pool, shard tag and backend node from the backend
  registry. Do not trust operator-supplied duplicates for those facts.
- Keep `users move --to-shard` as the shard movement workflow. Backend pins do
  not silently move users between shards.
- Require a scoped pin to match the current placement request's protocol,
  backend pool, shard tag and backend node before it can apply.
- Let matching operator pins bypass only the `weight_zero` exclusion.
- Keep every other safety exclusion fail-closed.
- Store scoped pins in Redis runtime state, not YAML.
- Make multi-pin set and all-pin clear atomic for the affinity key group.
- Expose all backend-pin state through generated REST DTOs and CLI output.
- Include scoped backend-pin context in route lookup without mutating state.
- Preserve existing active/retained affinity and backend-node safety rules.
- Update developer docs, manpages and generated OpenAPI artifacts.
- Add unit, REST, CLI, fake-service E2E and Docker interoperability coverage.

Out of scope:

- Letting Nauthilus select concrete backends or return backend identifiers.
- Adding `--to-backend` to `users move`.
- Writing backend pins into YAML config.
- Bypassing hard maintenance, soft maintenance, runtime out, runtime drain,
  failed health, max-connection limits, TLS policy or backend authentication
  failures.
- Silently failing over from a pinned backend to another backend.
- Making route lookup create, refresh, move, clear, pin or unpin sessions.
- Treating a backend node name as a network address, credential, TLS name or
  secret-bearing value.
- Requiring deployments without a configured protocol listener or backend pool
  to invent a pin for that absent protocol.

## Runtime Semantics

A scoped backend pin is a runtime override for:

```text
tenant + account_key + protocol + backend_pool
```

The authoritative per-pin facts are:

- tenant;
- account key;
- backend identifier;
- protocol;
- backend pool;
- shard tag;
- backend node;
- strategy;
- generation;
- reason and actor metadata;
- update timestamp.

When a placement request is evaluated, the placement service reads at most the
pin whose protocol and backend pool match the request. Pins for other protocols
are ignored for placement and reported only as aggregate diagnostic state where
appropriate. A cross-protocol pin must never poison another protocol's
placement.

The all-protocol set operation is a convenience mutation over scoped pins. It
must resolve the requested backend node to the complete set of configured
required protocol scopes before it writes anything. It must fail without partial
state when:

- the backend node is unknown;
- two entries on the node match the same `protocol + backend_pool`;
- a required configured protocol/backend-pool scope is missing for the backend
  node;
- any resolved backend is outside the same effective shard;
- any resolved backend is already invalid according to registry validation.

The implementation must define "required protocol scopes" from the active
configuration, not from hard-coded protocol names. A deployment with IMAP,
ManageSieve and LMTP listeners should require those three scopes. A deployment
without POP3 must not fail all-protocol pinning because POP3 is absent.

Strategy behavior remains aligned with the existing backend-pin model:

- `new_sessions_only` stores scoped pins without changing active sessions.
- `drain_existing` stores scoped pins and lets active sessions drain naturally.
- `kick_existing` stores scoped pins and increments the control generation so
  matching active sessions close through the controlled runtime path.

Clearing with no protocol removes every backend pin for the affinity key. It
does not kill sessions, clear shard affinity, clear movement overrides, rewrite
YAML or modify backend runtime state.

Protocol-scoped clear removes only the requested `protocol + backend_pool` pin.
It must preserve all other scoped pins for that affinity key.

## Redis State Model

The existing per-affinity hash tag must remain the atomicity boundary:

```text
<prefix>:v<schema>:{aff:<affinity_hash>}:backend_pin
```

The implementation may choose one of these shapes:

- one Redis hash whose fields are namespaced by `protocol + backend_pool`; or
- one bounded set of sibling hashes under the same `{aff:<affinity_hash>}` hash
  tag.

The chosen layout must be documented in
`docs/developer/AFFINITY_SESSION_HANDLING.md`.

Required state operations:

- `SetUserBackendPin` for one concrete protocol scope;
- `SetUserBackendPins` for an atomic all-protocol or multi-scope mutation;
- `GetUserBackendPin` for one placement scope;
- `ListUserBackendPins` for REST/CLI diagnostics;
- `ClearUserBackendPin` for one scope;
- `ClearUserBackendPins` for all scopes.

All operations must use normalized tenant and account keys. Redis key names must
not include raw usernames, recipients, backend addresses, TLS names, passwords,
tokens or private-key paths.

Atomicity requirements:

- A multi-scope set either writes every resolved scoped pin or writes none.
- A no-protocol clear deletes every scoped pin for the affinity key as one
  authoritative same-slot mutation.
- `kick_existing` must update scoped pins and control generation atomically.
- Repairable secondary indexes may be updated from Go after the authoritative
  mutation, following existing runtime-state patterns.

Backward compatibility:

- Existing single-scope backend-pin state must be read as one scoped pin when
  possible.
- If migration of old Redis state is needed, it must happen lazily and
  fail-closed on ambiguous data.
- The implementation must document any Redis schema version change.

## OpenAPI Shape

Update `docs/specs/openapi/nauthilus-director.yaml` first and regenerate server
and client artifacts.

The existing path may remain:

```text
GET    /api/v1/users/{user_key}/backend-pin
PUT    /api/v1/users/{user_key}/backend-pin
DELETE /api/v1/users/{user_key}/backend-pin
```

The schema must grow from a singular pin to an aggregate view that can represent
zero, one or many scoped pins. Exact names may be adjusted during
implementation, but the shape must express:

```yaml
UserBackendPinRequest:
  type: object
  additionalProperties: false
  required:
    - strategy
    - reason
  properties:
    backend:
      type: string
      minLength: 1
      description: Concrete backend identifier for one protocol-scoped pin.
    backend_node:
      type: string
      minLength: 1
      description: Backend node to resolve for all configured protocol scopes.
    protocol:
      type: string
      minLength: 1
      description: Optional protocol filter for backend-node scoped requests.
    backend_pool:
      type: string
      minLength: 1
      description: Optional backend-pool filter paired with protocol.
    strategy:
      $ref: "#/components/schemas/UserMoveRequestStrategy"
    reason:
      type: string
      minLength: 1
```

Validation rules:

- Exactly one of `backend` or `backend_node` is required.
- `backend` resolves to one concrete protocol/backend-pool scope.
- `backend_node` with no `protocol` resolves to all required configured
  protocol scopes for that node.
- `backend_node` with `protocol` and `backend_pool` resolves to one scoped pin.
- `protocol` without `backend_pool` is invalid when more than one pool exists
  for that protocol.
- Empty strings are invalid.

Clear requests must allow scoped and all-scope behavior:

```yaml
UserBackendPinClearRequest:
  type: object
  additionalProperties: false
  required:
    - reason
  properties:
    protocol:
      type: string
      minLength: 1
    backend_pool:
      type: string
      minLength: 1
    reason:
      type: string
      minLength: 1
```

`DELETE` with no `protocol` clears all pins for the user. `DELETE` with
`protocol + backend_pool` clears only that scope.

Responses should expose an aggregate model:

```yaml
UserBackendPins:
  type: object
  additionalProperties: false
  required:
    - present
    - user_key
    - pins
  properties:
    present:
      type: boolean
    user_key:
      type: string
      minLength: 1
    pins:
      type: array
      items:
        $ref: "#/components/schemas/UserBackendPinEntry"

UserBackendPinEntry:
  type: object
  additionalProperties: false
  required:
    - backend
    - protocol
    - backend_pool
    - shard_tag
    - backend_node
    - strategy
  properties:
    backend:
      type: string
    protocol:
      type: string
    backend_pool:
      type: string
    shard_tag:
      type: string
    backend_node:
      type: string
    strategy:
      $ref: "#/components/schemas/UserMoveRequestStrategy"
    generation:
      type: string
    active_session_count:
      type: integer
      minimum: 0
```

If the implementation keeps singular compatibility fields in the response, the
rules must be deterministic and documented. Do not add a parallel hand-written
client model.

Use `400` for malformed requests, `404` for unknown target backend or backend
node, `409` for incomplete all-protocol resolution or state conflicts, and
`503` for Redis/runtime ambiguity that must fail closed.

## CLI Shape

Keep the command noun:

```text
nauthilus-directorctl users backend-pin show <user-key>
nauthilus-directorctl users backend-pin set <user-key> ...
nauthilus-directorctl users backend-pin clear <user-key> --reason <text>
```

Concrete protocol-scoped pin:

```text
nauthilus-directorctl users backend-pin set user@example.org \
  --backend mailstack-canary-imap \
  --strategy new_sessions_only \
  --reason "commission IMAP"
```

All-protocol backend-node pin:

```text
nauthilus-directorctl users backend-pin set user@example.org \
  --backend-node mailstack-canary \
  --strategy new_sessions_only \
  --reason "mailbox canary"
```

Optional narrow backend-node scope:

```text
nauthilus-directorctl users backend-pin set user@example.org \
  --backend-node mailstack-canary \
  --protocol imap \
  --backend-pool imap-default \
  --strategy new_sessions_only \
  --reason "commission IMAP"
```

Clear all pins:

```text
nauthilus-directorctl users backend-pin clear user@example.org \
  --reason "mailbox canary done"
```

Clear one scope:

```text
nauthilus-directorctl users backend-pin clear user@example.org \
  --protocol imap \
  --backend-pool imap-default \
  --reason "IMAP canary done"
```

Show with no protocol prints all pins. JSON output emits the generated
aggregate DTO. Text output must remain scriptable and deterministic, for
example one line per scoped pin sorted by protocol and backend pool.

The CLI must use the generated OpenAPI client SDK. Hand-written code may own
command grammar, local validation, output formatting and operator-friendly
errors only.

## Placement And Selector Semantics

When no scoped backend pin matches the placement request, selector behavior is
unchanged.

When a scoped pin matches:

1. Validate that the pinned backend still exists.
2. Validate that its protocol and backend pool match the request.
3. Validate that its effective shard matches the selected shard.
4. Validate that its backend node matches active or retained backend-node
   binding when such a binding exists.
5. Build the same effective backend state used by normal placement and route
   lookup.
6. Ignore only the `weight_zero` exclusion for the pinned backend.
7. Reject all other exclusions fail-closed.
8. Disable implicit attach-retry failover for explicit operator pins.
9. Reserve backend capacity before attaching the selected backend to the
   session or delivery hold.

A pin for another protocol or backend pool is non-matching state. It must not
be treated as an operator target for the current request. Route lookup may
report that other scoped pins exist, but placement must not use them.

The all-protocol workflow does not change the selector. It only creates several
ordinary scoped pins atomically.

## Route Lookup Diagnostics

Route lookup remains side-effect-free. It may read the scoped backend-pin set
but must not create, refresh, clear, pin, unpin, open sessions, open delivery
holds or perform backend authentication.

For the lookup's protocol/backend-pool scope, responses must report:

- whether a matching pin is present;
- whether a matching pin was applied;
- the pinned backend identifier;
- pinned protocol and backend pool;
- pinned shard tag and backend node;
- mismatch or exclusion reason when not applied.

For aggregate diagnostics, responses may additionally report counts or bounded
summaries:

- total scoped pins for the user;
- other pinned protocol/backend-pool scopes;
- whether the current protocol is unpinned while other protocols are pinned.

Do not expose raw usernames, recipients, reason text or high-cardinality values
as metrics labels.

## Observability And Audit

Audit every mutating operation with reason, actor when available, user key,
operation, scope count, backend identifier or backend node, generation and
outcome. Logs must remain secret-safe.

Add or update bounded events for:

- protocol-scoped backend pin set;
- all-protocol backend-node pin set;
- protocol-scoped backend pin clear;
- all backend pins clear;
- route lookup with matching pin;
- route lookup with non-matching other-protocol pins;
- selector use of a scoped operator backend pin;
- selector rejection of a pinned backend.

Metrics must stay low-cardinality. Do not label by username, user hash,
recipient, raw backend identifier, session ID, trace ID, request ID, client IP,
raw reason text or secret-bearing values.

## Tests

Required failing reproducers before production changes:

- Setting an IMAP backend pin and then an LMTP backend pin for the same user must
  fail under the current model because the second set overwrites the first.
- Moving a user to a weight-zero canary shard with only an LMTP pin must make
  IMAP route lookup fail closed with a bounded `backend_pin_mismatch` or
  `no_backend` reason.
- Clearing all pins must remove the stale state and return route lookup to
  normal placement.

Required unit tests:

- Request validation rejects empty user keys, empty backend identifiers, empty
  backend nodes, missing reasons, unsupported strategies and ambiguous
  `protocol` without `backend_pool`.
- `backend` requests derive protocol, backend pool, shard tag and backend node
  from the registry.
- `backend_node` requests with no protocol resolve all configured required
  protocol scopes for that node.
- All-protocol resolution rejects unknown nodes, duplicate node entries for one
  scope, missing required scopes and cross-shard node data without partial
  mutation.
- Scoped set can store IMAP, ManageSieve and LMTP pins for the same affinity key
  without overwriting each other.
- Scoped clear removes only the requested protocol/backend-pool pin.
- Clear with no protocol removes every scoped pin.
- `new_sessions_only` and `drain_existing` do not close active sessions.
- `kick_existing` increments control generation once and asks active sessions
  to close through the controlled runtime path.
- Placement reads only the matching protocol/backend-pool pin.
- Other-protocol pins do not poison placement for the current protocol.
- Matching pins choose the target backend when effective weight is `0`.
- Matching pins reject hard maintenance, soft maintenance, runtime out, runtime
  drain, unhealthy state, max-connection saturation, shard mismatch,
  backend-node mismatch, protocol mismatch and backend-pool mismatch.
- Matching pins do not silently fail over to another backend.
- Backend reservation and attach still run for pinned selections.
- Route lookup reads scoped pin context without calling mutating state methods.
- Legacy single-pin Redis data, if supported, is read or migrated
  deterministically and fails closed when ambiguous.

Required REST and CLI tests:

- OpenAPI contract tests cover aggregate backend-pin schemas.
- Generated server and client artifacts are fresh after schema changes.
- REST handlers adapt generated DTOs into runtime request structs; domain
  packages do not import generated REST code.
- REST status mapping covers `400`, `404`, `409` and `503`.
- `nauthilus-directorctl users backend-pin ...` uses the generated client
  interface and fake-client tests, not raw HTTP mocks.
- CLI rejects ambiguous local input before transport.
- Text and JSON output represent absent, single-scope and multi-scope pins
  deterministically.
- `show` with no protocol lists all scoped pins.
- `clear` with no protocol sends the all-clear request.

Required deterministic E2E proof:

- Start the production `nauthilus-director` binary with the control API, Redis
  or the project's Redis-compatible test service, fake Nauthilus, and fake IMAP,
  ManageSieve and LMTP backends.
- Configure a `node2` backend node with non-zero weight for IMAP, ManageSieve
  and LMTP.
- Configure a `mailstack-canary` backend node with weight `0` for IMAP,
  ManageSieve and LMTP.
- Prove an unrelated user is not placed on any weight-zero canary backend
  through normal route lookup and public protocol flows.
- Move the test user to the canary shard and set one all-protocol backend-node
  pin through `nauthilus-directorctl`.
- Prove route lookup selects `mailstack-canary-imap`,
  `mailstack-canary-sieve` and `mailstack-canary-lmtp`, each with
  `source=operator_backend_pin` or the equivalent generated reason.
- Prove the test user reaches the canary fake IMAP backend through a public IMAP
  socket.
- Prove the test user reaches the canary fake ManageSieve backend through a
  public ManageSieve socket.
- Prove a recipient delivery reaches the canary fake LMTP backend through a
  public LMTP socket.
- Prove the all-protocol pin as one mailbox flow: submit a unique marker
  message for the pinned user through the public delivery path and then fetch
  that same marker for the same user through public IMAP, with the test
  observing that delivery used the pinned LMTP backend and fetch used the
  pinned IMAP backend. In fake-service E2E, the proof may correlate the public
  LMTP delivery observation and public IMAP backend observation by user and
  marker; in Docker interop, it must use the real send/fetch path.
- Clear pins with no protocol through `nauthilus-directorctl`.
- Clear or move runtime affinity as needed through documented runtime controls.
- Prove the user returns to normal placement and no stale scoped pin remains.
- Prove route lookup remains side-effect-free throughout.

Required Docker interoperability proof:

- Add or extend `make e2e-interop` when the current interop lane is the right
  home; otherwise document and add the specific Docker interop target.
- Use real Redis or the same Redis-compatible service policy as the guardrail
  lane.
- Use real protocol peers for at least IMAP, ManageSieve and LMTP. Dovecot
  project-provided Docker assets are preferred for backend protocol proof when
  available.
- Prove the all-protocol pin through public sockets, not only control API state.
- Prove the all-protocol pin with the operator mail-flow shape: send a unique
  message through the public LMTP/submission path, then fetch the same message
  through public IMAP, and verify both operations land on the pinned backend
  node's LMTP and IMAP services. Existing demo-stack `send-mail.sh`,
  `fetch-mail.sh` or `proof_mail_flow.py` helpers may be extended for this
  proof when they are the appropriate interop lane.
- Skip with an explicit stable message when Docker or the required protocol
  entrypoint is unavailable.
- Update `contrib/demo-stack` config, backend wiring, proof scripts or docs in
  the same change if the interop proof discovers required operator-facing
  topology behavior.

Run `make generate-openapi` after OpenAPI changes, then run
`make check-openapi`. Run focused unit tests while iterating. Before commit or
pull request, run `make guardrails`. If the interop lane is not part of
`make guardrails`, run and report it explicitly.

## Documentation Updates

Update:

- `docs/developer/AFFINITY_SESSION_HANDLING.md` with the scoped Redis key
  layout and all-protocol mutation semantics.
- `docs/man/nauthilus-directorctl.1` with concrete and backend-node pin
  examples.
- `docs/specs/implementation/M3_USER_BACKEND_PINNING_FOLLOWUP.md` only if it
  needs a pointer to this superseding follow-up for multi-protocol behavior.
- `docs/ARCHITECTURE_ROADMAP.md` if the runtime control summary still implies
  exactly one backend pin per user.
- generated OpenAPI, config reference or manpage artifacts required by the
  implementation.

Documentation must be English and must not refer to migration hostnames,
private domains, real user names, tokens, passwords or secret paths.

## Acceptance Criteria

- One user can hold separate scoped backend pins for IMAP, ManageSieve and LMTP
  at the same time.
- Setting a pin for one protocol does not overwrite pins for other protocols.
- Setting an all-protocol backend-node pin requires no protocol argument and
  creates every required scoped pin atomically.
- Clearing without a protocol removes every scoped pin for the user.
- Protocol-scoped clear removes only that scope.
- Existing concrete-backend pin workflows remain available.
- Backend pins remain runtime-only Redis state and never rewrite YAML config.
- Backend pins do not make Nauthilus choose concrete backends.
- Matching pins bypass only `weight_zero`.
- Non-weight exclusions remain fail-closed.
- Pinned backend failure does not silently fail over.
- Route lookup reports scoped pin context without mutating runtime state.
- Unit tests cover the observed overwrite regression and the new scoped model.
- REST and CLI tests prove the generated OpenAPI boundary and operator UX.
- E2E proves multi-protocol pinning through public sockets and the production
  binary.
- E2E or interop proves the all-protocol pin with a send/fetch mailbox flow:
  delivery reaches the pinned LMTP backend and the later IMAP fetch reaches the
  pinned IMAP backend for the same user and message marker.
- Docker interoperability proves the same behavior against real protocol peers
  or skips with a stable documented reason.
- Observability and audit remain low-cardinality and secret-safe.

## Review Checklist

- Verify `users move` remains shard-targeted and has no `--to-backend` alias.
- Verify all protocol/backend-pool facts are derived from the backend registry.
- Verify all-protocol set is atomic and cannot leave partial scoped pins.
- Verify clear-without-protocol deletes every scoped pin for the user.
- Verify Redis keys use normalized tenant/account hashes, not raw usernames.
- Verify backend transport details and credentials are not stored in pin state.
- Verify generated OpenAPI artifacts are updated only through the generator.
- Verify CLI uses the generated client SDK.
- Verify domain packages do not import generated REST packages.
- Verify selector pinning bypasses only `weight_zero`.
- Verify other-protocol pins are ignored by placement for the current protocol.
- Verify route lookup does not authenticate credentials or mutate Redis.
- Verify public-boundary E2E uses real sockets and not internal package calls.
- Verify the public proof includes an all-pinned send/fetch flow where LMTP
  delivery and IMAP fetch both land on the pinned backend node.
- Verify Docker interop or skip evidence is included in closeout.
- Verify manpages and developer docs describe both single-scope and
  all-protocol workflows.

## Resolved Decisions

1. Multi-protocol migration requires several scoped backend pins for one
   affinity key, not one overwritten backend-pin record.
2. A concrete backend identifier still creates one protocol-scoped pin.
3. A backend node without a protocol argument creates all required protocol
   pins for that node.
4. Clearing without a protocol clears all scoped pins for the user.
5. Backend pins still do not move users between shards; `users move` remains
   the shard movement command.
6. Route lookup remains diagnostic and side-effect-free.
7. The implementation must add both unit reproducers and public-boundary E2E
   coverage for the observed regression.

## Closeout Evidence

M8 multi-protocol backend-pinning closeout completed on 2026-06-16. The
implementation keeps the original concrete-backend workflow and extends the
runtime model so one affinity key can hold multiple `protocol + backend_pool`
backend pins at the same time.

Closeout evidence:

| Area | Evidence |
| --- | --- |
| Scoped Redis state | The per-affinity `backend_pin` hash now stores a bounded scoped pin set under the existing Redis Cluster hash tag. Concrete pins, backend-node all-protocol pins, protocol-scoped clear and clear-without-protocol are atomic runtime mutations and never rewrite YAML configuration. |
| REST and CLI | OpenAPI, generated server/client artifacts, REST adapters and `nauthilus-directorctl users backend-pin` support aggregate show output, concrete `--backend` set, all-protocol `--backend-node` set, scoped backend-node set and scoped/all clear. |
| Placement and route lookup | Placement reads only the matching protocol/backend-pool pin, bypasses only `weight_zero`, rejects non-weight exclusions fail-closed and does not silently fail over from pinned backend failure. Route lookup reports scoped backend-pin context, including other scopes, without creating sessions, refreshing leases or mutating Redis state. |
| Public-boundary E2E | `TestServerBinaryBackendNodeAllProtocolPinPublicFlow` starts the production `nauthilus-director` binary with Valkey, fake Nauthilus, fake IMAP, fake ManageSieve and fake LMTP backends over public loopback sockets. It uses `nauthilus-directorctl users move --to-shard mailstack-canary`, sets one all-protocol backend-node pin, proves route lookup selects `mailstack-canary-imap`, `mailstack-canary-sieve` and `mailstack-canary-lmtp` with `source=operator_backend_pin`, proves public IMAP, ManageSieve and LMTP traffic reaches the canary backends, correlates a unique LMTP marker with a later public IMAP backend observation for the same user, clears all scoped pins and verifies normal placement resumes. |
| Interoperability lane | `make e2e-interop` remains the Docker real-peer proof lane and is documented to skip with a stable reason when Docker or a required protocol entrypoint is unavailable. The final review records the pass or stable skip reason for the current environment. |
| Documentation | `docs/developer/AFFINITY_SESSION_HANDLING.md`, `docs/man/nauthilus-directorctl.1`, generated OpenAPI artifacts, E2E documentation and the architecture roadmap describe scoped backend pins, backend-node all-protocol pinning, concrete backend compatibility, clear semantics, safety exclusions and route-lookup side-effect boundaries. |

Validation evidence from the closeout run:

- Targeted public-boundary E2E:
  `NAUTHILUS_DIRECTOR_E2E_SERVER_BINARY=/tmp/nauthilus-director-e2e go test -mod=vendor -count=1 ./test/e2e -run TestServerBinaryBackendNodeAllProtocolPinPublicFlow -v`
  passed on 2026-06-16.
- Full project validation: see the final review output for the required
  `make check-openapi`, `make check-docs`, `make test`, `make race`,
  `make e2e`, `make build-check`, `make guardrails` and `make e2e-interop`
  results from the same closeout pass.

## Closed Questions

1. The REST API keeps the singular `/backend-pin` path for compatibility and
   returns aggregate backend-pin state from generated DTOs.
2. All-protocol backend-node resolution uses listener-derived configured
   protocol/backend-pool scopes.
3. Subset pinning is supported either by the existing concrete-backend workflow
   or by an explicit backend-node `protocol + backend_pool` scope.
4. Scoped backend pins remain explicit-clear-only. Expiry is out of scope.
