# M2/M3 Backend Runtime and Control Specification

Status: completed. The backend runtime and generated REST/CLI control
implementation is in place. `make guardrails` and `make e2e-interop` passed on
2026-05-26; the real-server interoperability lane used pinned
`dovecot/dovecot:2.4.3-dev`. A 2026-05-26 closeout correction wired the
production `nauthilus-director` server entrypoint and added real-binary E2E
proof for IMAP startup plus REST/CLI state parity through the running process.
A follow-up correction on the same date expands real-server interop to two
Director processes sharing one Redis-compatible state service and two Dovecot
backends, proving cross-process active affinity and runtime control operations.
A later correction expands the same lane to three Director processes and six
Dovecot backends covering untagged default placement, `test_shard1`,
`test_shard2` and Redis-distributed deep health ownership.

This document combines the backend runtime milestone and the REST/CLI control
milestone for `nauthilus-director`. The split in the roadmap is conceptually
useful, but implementation is tightly coupled: backend runtime operations need
a real operator control surface for black-box E2E proof, and the REST/CLI
surface must be backed by the same runtime domain model that normal IMAP
placement uses.

M2/M3 builds on the completed M0 foundation and the completed M1 IMAP MVP. It
is not a proof-of-concept migration. The archived implementation under `poc/`
may be read only as historical source material, and production code must not
import it, preserve its package layout or use it as a compatibility target.

## Source Documents

M2/M3 is governed by:

- `AGENTS.md`
- `docs/ARCHITECTURE_ROADMAP.md`
- `docs/specs/implementation/M0_FOUNDATION_SPEC.md`
- `docs/specs/implementation/M1_IMAP_MVP_SPEC.md`
- `docs/specs/implementation/M3_ROUTE_LOOKUP_FOLLOWUP.md`
- `docs/config/nauthilus-director.target.yml`
- `docs/specs/openapi/nauthilus-director.yaml`
- `docs/specs/README.md`
- `.gitignore`

If this specification conflicts with those source documents, fix the drift
before implementation continues.

## Combined Goal

M2/M3 implements the first operator-usable runtime control loop:

```text
IMAP session
  -> Nauthilus auth
  -> director-owned routing facts
  -> Redis-backed affinity/session/runtime state
  -> health and maintenance aware backend selection
  -> backend connect/auth/proxy
  -> heartbeat, close, reap and control-action handling

Operator
  -> generated OpenAPI REST boundary
  -> runtime domain service
  -> Redis-backed backend/user/session state
  -> nauthilus-directorctl generated client SDK
  -> externally observable protocol behavior
```

The final result is not just "state exists in Redis" and not just "REST routes
return non-501". It is one shared runtime model used by normal placement,
operator REST handlers, CLI commands, route lookup and E2E tests.

## Delivery Shape

Implement this as one specification with explicit implementation slices:

1. Runtime domain, Redis state and selection semantics.
2. Health, maintenance, drain, max-connection and lifecycle behavior.
3. OpenAPI schema alignment and generated server/client refresh.
4. REST handlers backed by runtime domain services.
5. `nauthilus-directorctl` nested commands backed by the generated client SDK.
6. Route lookup wired read-only to the shared routing/selection pipeline.
7. E2E proof through public IMAP sockets, REST calls and CLI commands.

The slices may be committed separately, but the combined milestone is not done
until REST and CLI manage the same Redis-backed runtime state that IMAP
placement uses.

## Global Scope

In scope:

- Promote M1 static backend selection into a runtime-aware selector.
- Keep `effective_shard_tag + protocol + backend_pool -> backend_identifier`
  as the concrete backend selection boundary.
- Extend Redis state to include selected backend sessions, backend runtime
  overrides, user move/kick/clear state, repairable indexes and expired-session
  reaping.
- Implement backend runtime override semantics:
  - runtime in/out
  - runtime weight override
  - runtime drain
  - runtime maintenance mode
  - runtime clear
- Implement Redis-coordinated backend health ownership and health state
  transitions for IMAP backends.
- Enforce backend `max_connections` with Redis-coordinated active-session
  counts.
- Preserve active-user stickiness unless hard-down, hard maintenance, explicit
  administrative drain, explicit administrative kick or a documented
  fail-closed condition allows movement.
- Implement user runtime operations:
  - move
  - kick
  - affinity clear
  - expired-session reap
- Complete the OpenAPI-first REST server handlers for v1 control operations
  listed in the roadmap.
- Keep generated REST server and generated client artifacts reproducible through
  the pinned `oapi-codegen` workflow.
- Expand `nauthilus-directorctl` with nested operator commands that use the
  generated OpenAPI client SDK for transport.
- Wire route lookup read-only to the same routing resolver and selector domain
  objects used by IMAP placement.
- Implement safe config and reload control endpoints.
- Add auditable operation metadata without logging credentials or raw
  high-cardinality user data.
- Add runtime-aware observability events and metrics under the existing
  low-cardinality metric label policy.
- Add E2E proof for backend weight `0`, runtime in/out, drain, maintenance,
  user move, user kick, affinity clear, session kill, route lookup and CLI/REST
  parity.

Out of scope:

- Implementing POP3, LMTP or ManageSieve protocol entrypoints.
- Implementing mailbox data migration. User move changes director placement
  state only.
- Making Nauthilus choose concrete director backends.
- Writing runtime mutations back into YAML config.
- Adding feature-specific Redis config subtrees outside `storage.redis`.
- Adding a second persistent runtime state backend.
- Adding distributed locks for normal routing.
- Adding Pub/Sub, streams or queues unless Redis lease heartbeats cannot safely
  close kicked or drained sessions.
- Adding hand-written REST DTOs or a parallel hand-written CLI HTTP model.
- Full M4 telemetry exporter polish.

## Stable Config Paths

M2/M3 uses the existing stable M0/M1 config paths. It must not rename, remove
or invert these paths without an explicit breaking-change decision plus docs,
examples, migration notes and tests:

- `runtime.process`
- `runtime.servers.control`
- `runtime.timeouts`
- `runtime.clients`
- `observability`
- `storage.redis`
- `auth.authorities`
- `director.security`
- common listener fields: `protocol`, `service_name`, `network`, `address`,
  `authority`, `backend_pool`, `proxy_protocol` and `tls`
- `director.listeners.imap`
- `director.listeners.imaps`
- `director.routing`
- `director.affinity`
- `director.health`
- `director.maintenance`
- `director.runtime_overrides`
- `director.backend_pools`
- `director.backends`

M2/M3 may validate currently defined values more strictly when the stricter
behavior follows the architecture. It must not silently reinterpret a stable
setting into its opposite.

## Target Package Boundaries

M2/M3 expands existing production packages and may add a small runtime
orchestration package:

```text
cmd/nauthilus-directorctl/
internal/backend/
internal/state/
internal/runtime/
internal/protocol/imap/
internal/proxy/
internal/rest/
internal/rest/adapters/
internal/rest/generated/
internal/client/generated/
internal/app/
internal/observability/
test/e2e/
```

Boundary rules:

- `internal/backend` owns backend domain objects, effective backend state,
  health state, maintenance state, max-connection policy and selector policy.
- `internal/state` owns Redis-backed affinity, session, backend runtime, user
  runtime, Lua scripts, key builders and failure classification.
- `internal/runtime` may be added only as a cohesive orchestration layer for
  runtime use cases such as backend state changes, user move/kick, session
  kill, route lookup and session reaping. It must not become a generic helper
  package.
- `internal/protocol/imap` consumes runtime-aware interfaces and remains the
  IMAP protocol boundary.
- `internal/proxy` owns transparent proxy mode, heartbeat cadence, close
  handling and runtime control-action shutdown.
- `internal/rest` owns control listener guards, generated route registration,
  auth middleware and REST-specific error mapping.
- `internal/rest/adapters` adapts generated OpenAPI request/response types to
  runtime domain request/response objects.
- `internal/client/generated` contains generated OpenAPI client code only.
- `cmd/nauthilus-directorctl` owns command grammar, output formatting and
  operator errors. It must not duplicate REST DTOs or bypass the generated
  client SDK.
- `internal/app` wires runtime services, health runners, selectors, stores,
  REST server, listener lifecycle and reload through Fx.
- `internal/observability` owns runtime events, metrics, trace fields and
  redaction-safe helpers.

Do not add package-level mutable state for backend runtime, health, session
tracking or user operations. Runtime behavior must be owned by cohesive types
with narrow interfaces.

## M2/M3.1 Runtime Domain and Effective Backend State

### Purpose

Define the runtime domain model that overlays immutable config, health state,
maintenance state, runtime overrides and active-session counts into one
effective backend view.

### In Scope

- Add typed domain objects for:
  - effective backend state
  - backend runtime override
  - backend health state
  - backend maintenance state
  - backend drain state
  - session runtime state
  - user runtime state
  - route lookup diagnostic state
  - runtime audit metadata
- Keep configured backend identity, protocol, pool, effective shard and
  transport details immutable until config reload.
- Allow backend `shard_tag` to be omitted in YAML for simple deployments, but
  normalize every backend to a non-empty effective shard during config loading.
- Treat runtime overrides as Redis-backed state layered over config.
- Treat static config maintenance as the baseline and runtime maintenance as a
  live override.
- Preserve enough session metadata for runtime actions without requiring raw
  usernames in Redis keys.
- Add generation counters for mutable backend and user runtime state.
- Record audit metadata for mutating operations:
  - operation type
  - reason
  - actor when available
  - generation
  - server time
  - affected backend or user hash
- Normalize operation inputs before storing state.

### Out of Scope

- Rewriting YAML configuration.
- Moving backend transport settings into Redis.
- Persisting credentials, bearer material or backend auth secrets in runtime
  state.
- Exposing raw normalized usernames in Redis keys.

### Expected Files or Packages

```text
internal/backend/runtime.go
internal/backend/health.go
internal/backend/maintenance.go
internal/backend/limits.go
internal/runtime/backend.go
internal/runtime/users.go
internal/runtime/sessions.go
internal/runtime/route_lookup.go
internal/runtime/audit.go
internal/app/module.go
```

### Implementation Notes

- The effective backend state should be derived from:
  - config backend entry
  - config pool membership
  - effective shard tag
  - static maintenance
  - runtime in/out state
  - runtime maintenance state
  - runtime drain state
  - runtime weight override
  - health state
  - Redis-backed active session count
- Runtime override values are optional. Absence means "use config".
- Backend `shard_tag` is optional in YAML, but never optional in the runtime
  model. The config loader must assign an effective shard before validation
  hands the snapshot to runtime packages.
- The default effective shard should come from `director.routing.default_shard`
  when present, otherwise `default`.
- If routing returns no shard, placement uses the configured effective default
  shard.
- If routing returns a shard that no backend in the selected pool effectively
  serves, placement fails closed.
- In multi-shard deployments, operators should set `shard_tag` explicitly for
  every backend that is not meant to belong to the default shard.
- Runtime clear removes runtime overrides only. It must not alter config
  maintenance defaults, configured backend weight, configured max connections,
  TLS settings or backend auth settings.
- Runtime operation methods should accept explicit request structs and return
  explicit result structs. Do not pass raw generated REST DTOs into the domain
  layer.
- Every mutating request must require a non-empty reason once exposed through
  REST or CLI.
- An actor field may be empty for local tests or unauthenticated development
  fixtures, but the domain model must carry it so control auth can populate it.
- Effective state must be deterministic when the same config and Redis state are
  observed.
- Ambiguous runtime state fails closed for new placement.

### Required Unit Tests

- Effective state overlay applies config defaults when no runtime override
  exists.
- Backend entries without `shard_tag` receive the configured effective default
  shard.
- Routing with no shard uses the effective default shard.
- Routing to an unserved shard fails closed.
- Runtime weight override respects `director.runtime_overrides.backends.min_weight`
  and `max_weight`.
- Runtime clear removes only runtime overrides.
- Static hard maintenance cannot be weakened by runtime in-service state.
- Runtime hard maintenance excludes all new sessions.
- Runtime soft maintenance preserves active pins only when policy allows it.
- Audit metadata is created without secret-bearing values.
- Runtime domain objects reject empty reasons for mutating operations.

### Acceptance Criteria

- M2/M3 has one effective backend state model shared by selectors, REST, CLI and
  route lookup.
- Runtime overrides never rewrite YAML config.
- Effective shard defaults are stable and immutable until config reload.
- Static config remains the immutable baseline until explicit reload.
- Mutating operations create auditable, secret-safe metadata.

### Review Checklist

- Verify no package reads Viper outside `internal/config`.
- Verify no generated REST DTO leaks into backend, state or runtime domain
  objects.
- Verify runtime state does not store credentials.
- Verify raw backend identifiers are not metric labels.

## M2/M3.2 Redis Runtime State, Lua Scripts and Indexes

### Purpose

Extend Redis state from M1 session open/heartbeat/close/lookup into the runtime
coordination layer needed for backend limits, user operations, REST/CLI listing
and route diagnostics.

### In Scope

- Extend M1 Redis scripts:
  - `open`
  - `heartbeat`
  - `close`
  - `lookup`
- Add Redis scripts or atomic operations for:
  - `reap`
  - `move`
  - `kick`
  - `clear`
  - `session_kill`
  - `backend_runtime_set`
  - `backend_runtime_clear`
  - selected-backend session attach or equivalent atomic registration
- Store selected backend identity in session records after selection.
- Maintain backend active-session counters for max-connection checks.
- Maintain repairable secondary indexes for sessions, users, backends and
  backend-to-session membership so backend-scoped operations can affect all
  currently attached sessions without per-user operator loops.
- Keep all per-affinity atomic operations inside one Redis Cluster hash tag.
- Use Redis server time for state transitions and expiry decisions.
- Update generation counters on every mutating user or backend operation.
- Return structured script payloads that can be parsed into typed results.
- Classify ambiguous Redis results as fail-closed state errors.

### Out of Scope

- Distributed locks for normal routing.
- Runtime state stored outside `storage.redis`.
- Making secondary indexes the source of truth for placement.
- Storing raw usernames in keys.
- Storing raw passwords, tokens, SASL blobs or private keys in values.

### Expected Files or Packages

```text
internal/state/affinity.go
internal/state/sessions.go
internal/state/runtime.go
internal/state/reap.go
internal/state/scripts/open.lua
internal/state/scripts/heartbeat.lua
internal/state/scripts/close.lua
internal/state/scripts/lookup.lua
internal/state/scripts/reap.lua
internal/state/scripts/move.lua
internal/state/scripts/kick.lua
internal/state/scripts/clear.lua
internal/state/scripts/session_kill.lua
internal/state/scripts/backend_runtime_set.lua
internal/state/scripts/backend_runtime_clear.lua
internal/state/*_test.go
```

### Implementation Notes

- Preserve the M1 key shape and extend beneath the same namespace:

```text
<prefix>:v<schema>:{aff:<affinity_hash>}:state
<prefix>:v<schema>:{aff:<affinity_hash>}:sessions
<prefix>:v<schema>:{aff:<affinity_hash>}:session:<session_id>
<prefix>:v<schema>:{aff:<affinity_hash>}:override
<prefix>:v<schema>:runtime:backend:<backend_id>
<prefix>:v<schema>:idx:sessions
<prefix>:v<schema>:idx:backends
<prefix>:v<schema>:idx:backend:<backend_id>:sessions
```

- Additional M2/M3 keys are allowed only when documented and derived from the
  same namespace, for example user indexes, health owner leases or
  per-instance liveness facts.
- Session records should include:
  - session ID
  - affinity key hash facts
  - protocol
  - listener name
  - effective shard tag
  - selected backend identifier
  - director instance ID
  - opened-at server time
  - lease expiry server time
  - current control generation
- The placement flow must avoid leaking a session count if backend selection,
  backend connect or backend auth fails.
- If the implementation keeps M1's "open affinity before backend selection"
  shape, M2/M3 must add a second atomic selected-backend attach step that can
  fail safely and then close the affinity/session reservation.
- If the implementation refactors into "lookup, select, open" shape, the open
  script must detect affinity generation changes and force a bounded placement
  retry instead of silently violating an active pin.
- Backend active-session counts must be updated by the same terminal close/reap
  path that updates affinity session counts.
- The `heartbeat` result may include a control action such as `none`, `kick`,
  `drain` or `move_generation_changed`. Proxy code must treat terminal control
  actions as controlled shutdown, not as generic Redis failure.
- The `kick` and `session_kill` scripts should mark sessions by generation so
  sessions on every director instance observe the change through heartbeat.
- Backend drain, hard maintenance and backend-scoped kick behavior must use the
  backend-to-session membership index to mark all active sessions currently
  attached to the backend. Operators must not need to enumerate and kick every
  affected user individually.
- The `reap` script should repair expired leases and counts using Redis server
  time. It should be safe to run periodically and safe to run from tests.
- Indexes are repairable convenience indexes. If an index is missing or stale,
  normal placement must still be correct or fail closed.

### Required Unit Tests

- New scripts load and expose deterministic SHA values.
- Redis Cluster hash tags keep per-affinity state, session and override keys in
  the same slot.
- Open/attach increments backend active-session counts exactly once.
- Close decrements backend active-session counts exactly once.
- Reap expires stale sessions and repairs active counts.
- Move updates user runtime generation and preserves or changes active affinity
  according to strategy.
- Kick/session kill marks active sessions and heartbeat observes the generation.
- Backend-scoped drain or hard maintenance marks every indexed session attached
  to the backend without requiring per-user calls.
- Clear removes inactive affinity or pending override state without touching
  unrelated users.
- Runtime backend set/clear preserves config baseline and audit metadata.
- Ambiguous script payloads fail closed.

### Acceptance Criteria

- Redis remains the production source of truth for active affinity and session
  coordination.
- Backend active-session counts are Redis-coordinated.
- Move, kick, clear, kill and reap operations are atomic enough for multiple
  director instances.
- Listing indexes support REST/CLI without becoming routing truth.

### Review Checklist

- Verify normal routing does not use distributed locks.
- Verify local caches are accelerators only.
- Verify session indexes are not required for routing correctness.
- Verify raw usernames are not required in Redis keys.

## M2/M3.3 Health, Maintenance, Selection and Limits

### Purpose

Make backend selection enforce runtime state, health state, maintenance,
draining, active pins and max-connection limits while preserving deterministic
placement.

### In Scope

- Implement a backend health runner owned by lifecycle-managed types.
- Coordinate credentialed backend health checks through Redis health ownership
  leases so only one director instance performs deep checks for a backend at a
  time.
- Implement local light IMAP backend checks:
  - TCP connect
  - optional TLS handshake
  - optional greeting read
- Implement Redis-owned deep IMAP backend checks when `health_check.mode`
  requires backend login coverage.
- Apply `director.health.interval`, `timeout`, `jitter`, `unhealthy_after` and
  `healthy_after`.
- Treat stale or missing health state as fail-closed for health-enabled
  backends after startup grace.
- Extend `backend.Selector` or add a replacement implementation that consumes
  effective backend state.
- Enforce configured and runtime weight for initial placement.
- Enforce backend runtime in/out.
- Enforce runtime drain.
- Enforce health eligibility.
- Enforce static and runtime maintenance.
- Enforce backend `max_connections` with Redis-backed active counts.
- Preserve active affinity precedence over normal hash, weight and
  least-connection style balancing.
- Keep weighted rendezvous hashing deterministic for initial placement.

### Out of Scope

- POP3, LMTP and ManageSieve deep health checks.
- Least-connections selection unless a later architecture decision adds it.
- Cross-shard load balancing for user-stateful protocols.
- Selecting concrete backends in Nauthilus.
- Disabling certificate verification to make health checks pass.

### Expected Files or Packages

```text
internal/backend/health.go
internal/backend/maintenance.go
internal/backend/runtime_selector.go
internal/backend/limits.go
internal/backend/registry.go
internal/protocol/imap/backend.go
internal/protocol/imap/placement.go
internal/app/module.go
```

### Implementation Notes

- Only IMAP backend health checks can be fully enabled in this combined
  milestone because M1 is the only production protocol entrypoint.
- Later protocol backend entries may keep config fields, but their deep health
  behavior must remain disabled or explicit until their protocol milestones.
- Runtime maintenance, in/out, drain and weight overrides are Redis-backed
  cluster state.
- Light health checks are local reachability checks. They may run per instance
  without credentials and should never publish global backend-down state by
  themselves.
- Deep health checks are Redis-owned per backend. Exactly one current health
  owner may use the configured health credentials for a backend at a time.
- Health ownership must be lease-based and fenced:
  - each director instance publishes an `instance_id` heartbeat with TTL
  - each backend has a Redis owner lease with TTL
  - ownership renewal increments or preserves a fencing token according to the
    final Lua design
  - deep-check results include owner instance, fencing token, generation,
    checked-at server time, expiry and reason class
  - stale owners must not overwrite newer results
  - a new owner may take over only after the previous lease expires or is proven
    stale
- Suggested Redis key shape:

```text
<prefix>:v<schema>:runtime:instance:<instance_id>
<prefix>:v<schema>:health:backend:<backend_id>:owner
<prefix>:v<schema>:health:backend:<backend_id>:state
```

- Normal routing must not acquire a distributed lock. It reads the published
  deep-health state and combines it with local connect outcomes.
- A session's real backend connect remains authoritative for that instance. If
  local connect fails after placement, the session state must roll back or close
  and the failure must be observable.
- Backend TLS validation for health checks must use the same SNI and
  certificate rules as production backend connect.
- Effective eligibility precedence for new initial placement:
  1. protocol and backend pool match
  2. effective shard tag match
  3. static hard maintenance excludes
  4. runtime hard maintenance excludes
  5. runtime out excludes
  6. runtime drain excludes
  7. unhealthy or stale health excludes when health is enabled
  8. max connections excludes
  9. static or runtime weight `0` excludes
  10. weighted deterministic selector chooses among remaining candidates
- Effective eligibility precedence for active pins:
  1. protocol and backend pool match
  2. active pin effective shard tag match
  3. hard maintenance excludes unless explicit failover policy allows movement
  4. hard-down health excludes only when hard-down failover is allowed or the
     session must fail closed
  5. runtime out does not by itself terminate an existing active pin
  6. runtime drain preserves or closes active sessions according to drain mode
     and grace
  7. soft maintenance preserves active pins only when configured
  8. weight `0` does not terminate active pins
- If max connections is reached during selected-backend attach, placement must
  retry another eligible backend in the same shard or fail closed.
- Backend connect failure after session registration must close or roll back
  the Redis session and backend count.

### Required Unit Tests

- Health transition thresholds require the configured number of consecutive
  failures or successes.
- Stale published deep health fails closed after startup grace.
- Only the current Redis health owner performs credentialed deep checks for a
  backend.
- A stale owner cannot overwrite a newer health result.
- Runtime out excludes new placement.
- Runtime drain excludes new initial placement.
- Runtime weight override changes deterministic weighted selection.
- Runtime weight `0` excludes initial placement but allows active pins when no
  stronger exclusion applies.
- Static and runtime hard maintenance exclude active pins unless explicit
  failover policy allows movement.
- Max-connection limits exclude full backends.
- Active affinity overrides normal weighted placement.
- All-ineligible candidates fail closed with a classified selector error.

### Acceptance Criteria

- Selector decisions reflect effective runtime state.
- Active affinity remains the highest normal placement priority.
- Max-connection limits are Redis-coordinated.
- Health, maintenance and selection failures are observable, classified and
  fail closed.

### Review Checklist

- Verify Nauthilus is never asked for a concrete backend identifier.
- Verify selector code does not read raw config maps.
- Verify all session registration rollback paths close Redis state.
- Verify health-check secrets are redacted.
- Verify deep health ownership prevents parallel credentialed checks against the
  same backend.

## M2/M3.4 User, Session and Lifecycle Operations

### Purpose

Implement user move/kick, session kill, affinity clear, reap, drain and process
lifecycle behavior in the shared runtime domain.

### In Scope

- Implement user move with configured strategies.
- Implement user kick through Redis generation state plus heartbeat observation.
- Implement session kill through Redis generation state plus local acceleration.
- Implement affinity clear with safe inactive-state behavior.
- Implement expired session reap.
- Add a local active-session registry so the current process can close its own
  sessions promptly when a local operation affects them.
- Keep cross-process behavior correct through Redis state and heartbeat.
- Extend session lifecycle to register selected backend and local session
  control handles.
- Ensure proxy close always attempts Redis close.
- Ensure backend connect/auth failure closes or rolls back session state.
- Run periodic heartbeat and reap loops through lifecycle-managed objects.
- Stop health runners and reap loops during process shutdown.
- Implement backend drain operation:
  - exclude backend from new initial placement
  - preserve or close active sessions according to drain mode and grace
  - audit start and terminal outcome

### Out of Scope

- Storing raw usernames in Redis keys.
- Requiring Pub/Sub for correctness.
- Mailbox data migration.
- Migrating active sessions to a different backend without reconnecting.
- Spooling protocol traffic.

### Expected Files or Packages

```text
internal/runtime/users.go
internal/runtime/sessions.go
internal/runtime/backend.go
internal/state/reap.go
internal/proxy/pipe.go
internal/protocol/imap/placement.go
internal/listener/listener.go
```

### Implementation Notes

- User operations act on the production affinity key:

```text
tenant + normalized_username -> shard_tag + active_session_count + expiry_after_last_close
```

- Move strategies should align across config, OpenAPI and CLI. The recommended
  canonical values are:
  - `new_sessions_only`
  - `kick_existing`
  - `drain_existing`
- `new_sessions_only` preserves current active sessions and applies the target
  shard after the active session count reaches zero.
- `kick_existing` writes the target shard and marks existing sessions for
  closure for the targeted affinity key. It applies to all active sessions for
  that user/affinity, not just one frontend connection. New sessions use the
  target shard once the kick generation is active.
- `drain_existing` may allow a temporary operator-requested split where new
  sessions use the target shard while existing sessions drain on the old shard.
  This is an explicit exception to normal active-user stickiness and must be
  audited.
- User kick writes a kick generation. Heartbeats that observe that generation
  close the proxy streams with a controlled runtime result.
- Session kill writes a session-specific generation and should close local
  streams immediately when the affected session is in the same process.
- Backend-scoped drain and hard maintenance must operate in bulk across all
  sessions attached to the backend by using Redis backend-session membership.
  A backend operation may affect many users; it must not require operators to
  run one user kick per affected account.
- Affinity clear should refuse to clear active affinity by default. Active
  sessions should be kicked or moved explicitly before clearing.
- Reap may be triggered periodically, by REST/CLI if exposed, and from tests. It
  should use Redis server time and repair counts and indexes.
- Runtime drain is not the same as weight `0`. Drain is auditable and may affect
  active sessions after grace. Weight `0` only removes a backend from weighted
  initial placement.
- Runtime out is not the same as hard maintenance. Runtime out excludes new
  placement but does not by itself imply session termination.
- Hard maintenance is stronger than out and drain.
- A process shutdown should not mark a backend as unhealthy or out globally just
  because one director instance is stopping.

### Required Unit Tests

- `new_sessions_only` creates pending move state without changing active
  sessions.
- `kick_existing` marks active sessions and applies target shard for future
  placement.
- `drain_existing` records explicit drain semantics and audit metadata.
- Backend drain/hard maintenance marks all sessions attached to the backend
  through Redis membership state.
- Kick/session kill generation is observed by heartbeat and converted into
  controlled proxy shutdown.
- Clear refuses active affinity by default.
- Reap removes expired sessions and updates active counts.
- Backend connect/auth failure rolls back or closes session registration.
- Proxy close path closes Redis lease once.
- Shutdown closes local active sessions after graceful timeout.

### Acceptance Criteria

- User move, kick, session kill, clear and reap are Redis-backed and auditable.
- Backend drain and hard maintenance can affect all sessions attached to one
  backend without per-user operator loops.
- Cross-process correctness comes from Redis state plus heartbeats.
- Local session registries are accelerators only.
- Runtime lifecycle paths do not leak Redis sessions or backend counts.

### Review Checklist

- Verify move does not imply mailbox data migration.
- Verify user/session operation logs do not include raw usernames or credentials.
- Verify repeated operations do not corrupt Redis counts.
- Verify process shutdown does not mutate global backend runtime state.

## M2/M3.5 OpenAPI REST Control API

### Purpose

Complete the generated REST server boundary for the v1 control API and route
every implemented handler through explicit runtime domain services.

### In Scope

- Keep `docs/specs/openapi/nauthilus-director.yaml` as the source of truth.
- Align schema enums and request/response bodies with runtime semantics before
  implementation.
- Regenerate server and client artifacts after schema changes.
- Keep `make generate-openapi` and `make check-openapi` authoritative.
- Introduce generated config documentation guardrails before or alongside the
  config REST endpoints:
  - add a small Go helper that reflects the typed config model and
    `DefaultConfig()`
  - add human-authored config path metadata under `docs/config/metadata.yml`
  - generate committed config references under `docs/reference/`
  - add `make generate-docs` and `make check-docs`
  - make `docs-check` and therefore `make guardrails` fail on stale generated
    config documentation
- Implement:
  - `GET /healthz`
  - `GET /readyz`
  - `GET /api/v1/version`
  - `GET /api/v1/config/effective`
  - `GET /api/v1/config/defaults`
  - `GET /api/v1/config/non-default`
  - `POST /api/v1/reload`
  - `GET /api/v1/backends`
  - `GET /api/v1/backends/{identifier}`
  - `POST /api/v1/backends/{identifier}/maintenance`
  - `DELETE /api/v1/backends/{identifier}/maintenance`
  - `POST /api/v1/backends/{identifier}/runtime/in`
  - `POST /api/v1/backends/{identifier}/runtime/out`
  - `POST /api/v1/backends/{identifier}/runtime/drain`
  - `DELETE /api/v1/backends/{identifier}/runtime`
  - `GET /api/v1/sessions`
  - `GET /api/v1/sessions/{session_id}`
  - `DELETE /api/v1/sessions/{session_id}`
  - `GET /api/v1/users`
  - `GET /api/v1/users/{user_key}`
  - `GET /api/v1/users/{user_key}/sessions`
  - `GET /api/v1/users/{user_key}/affinity`
  - `PUT /api/v1/users/{user_key}/affinity`
  - `DELETE /api/v1/users/{user_key}/affinity`
  - `POST /api/v1/users/{user_key}/move`
  - `POST /api/v1/users/{user_key}/kick`
  - `POST /api/v1/route/lookup`
  - `GET /metrics`
- Preserve strict generated request/response handling.
- Map domain errors to stable REST status codes and problem payloads.
- Keep route lookup credential rejection before the generated handler boundary.
- Keep REST config output redacted by default, but implement explicit protected
  config output for the generated config endpoints so
  `nauthilus-directorctl config dump -d`, `-n` and `-P` target the running
  Director, not the client process.
- Implement safe reload semantics from the architecture.

### Out of Scope

- Replacing generated server interfaces with hand-written routing.
- Accepting credential-bearing route lookup input.
- Returning private config values through the REST control API without an
  explicit protected request, authorization and audit event.
- Writing YAML config from runtime mutation endpoints.

### Expected Files or Packages

```text
docs/specs/openapi/nauthilus-director.yaml
docs/specs/openapi/oapi-codegen.server.yml
docs/specs/openapi/oapi-codegen.client.yml
docs/config/metadata.yml
docs/reference/config-defaults.yaml
docs/reference/config-paths.md
internal/rest/server.go
internal/rest/auth.go
internal/rest/adapters/handler.go
internal/rest/adapters/handler_test.go
internal/rest/generated/server.gen.go
internal/client/generated/client.gen.go
scripts/generate-openapi.sh
scripts/check-openapi.sh
scripts/generate-docs.sh
scripts/check-docs.sh
tools/configdoc/
```

### Implementation Notes

- REST handlers should adapt generated DTOs into domain request structs and
  domain response structs back into generated DTOs.
- Domain packages must not import `internal/rest/generated` or
  `internal/client/generated`.
- Mutating operations must require a reason in the schema and in handler logic.
- Recommended status mapping:
  - `400` for malformed or invalid operator input
  - `401` or `403` for control authentication/authorization failure
  - `404` for unknown backend, session or user state where absence is known
  - `409` for state conflicts such as clearing active affinity
  - `501` only for intentionally deferred operations, none by final closeout
  - `503` for Redis/runtime ambiguity that must fail closed
- Config endpoints must return redacted documents by default.
- Protected credential-bearing config output is implemented by an explicit
  request flag in the OpenAPI contract, for example `include_protected=true`.
  `nauthilus-directorctl config dump -P` must set that flag against the
  Director's control API.
- Protected output requires a control-plane authorization decision that is
  stronger than "the caller authenticated". If the configured control auth mode
  cannot distinguish protected-config permission, the endpoint must return a
  structured `403` for protected requests.
- Protected config reads must be audited with actor, operation, config view,
  generation when available and request outcome. Audit events must not include
  the protected values themselves.
- Config documentation generation must use Go code, not ad hoc parsing of Go
  source text. The helper should import the typed config package, reflect config
  tags and defaults, derive environment override names through the same rules as
  the loader and mark protected values from the shared secret metadata.
- `docs/config/metadata.yml` is the human-owned layer for stable config-path
  descriptions, section grouping and stability notes. The generator may create
  TODO stubs for new paths, but `make check-docs` must fail for TODO
  descriptions on stable config paths.
- `docs/reference/config-defaults.yaml` must be generated from the same behavior
  as `nauthilus-director config dump -d --format yaml`.
- `docs/reference/config-paths.md` must list at least path, type, default,
  stability, protected status, environment override name and description for
  stable config paths.
- Metadata must be validated both ways: every stable config path needs metadata,
  and metadata for removed or unknown paths must fail the check.
- Reload should:
  1. parse new config
  2. validate new config
  3. build new runtime snapshot
  4. apply listener/backend/resolver changes
  5. keep existing sessions on old backend objects until closed
  6. use the new snapshot for new sessions
- If reload cannot safely apply a class of change, it must reject that change
  with an operator-readable reason instead of partially applying it.
- Safe reload is real apply behavior, not validate-only. It should apply
  listener additions, listener removals with graceful drain, backend
  additions/removals, backend weights, routing resolver configuration, health
  intervals and logging level when those changes can be applied without
  breaking active sessions.
- Safe reload must reject unsupported or unsafe live changes, such as changing
  the control listener bind address or changing core protocol semantics, unless
  a later implementation proves those changes can be applied safely.
- `/metrics` may expose the existing Prometheus handler if metrics are enabled.
  It must not introduce high-cardinality labels.

### Required Unit Tests

- OpenAPI contract tests cover all implemented paths.
- `make check-openapi` detects stale generated output after schema changes.
- `make check-docs` detects stale generated config references.
- Stable config paths without metadata or with TODO descriptions fail
  `make check-docs`.
- Metadata for removed or unknown config paths fails `make check-docs`.
- Handler adapters do not leak generated DTOs into domain packages.
- Mutating handlers reject missing reasons.
- REST errors map domain classifications to stable status codes.
- Route lookup rejects credential-bearing JSON before generated decoding.
- REST config endpoints return redacted output by default.
- Protected config requests require explicit request flags, authorization and
  audit events.
- Reload applies supported safe changes and rejects unsafe changes cleanly.

### Acceptance Criteria

- All v1 roadmap REST endpoints are either implemented or have an explicit
  documented deferral agreed before closeout.
- Runtime mutation endpoints change Redis-backed runtime state only.
- Generated OpenAPI server and client artifacts are reproducible.
- Generated config documentation artifacts are reproducible and guarded by
  `make check-docs`.
- REST handlers share the same runtime domain as IMAP placement and CLI.

### Review Checklist

- Verify no non-OpenAPI control endpoint exists.
- Verify no handler rewrites YAML config.
- Verify generated code is not manually edited.
- Verify generated config references are current and metadata has no stable-path
  TODO descriptions.
- Verify route lookup still cannot call Nauthilus or mutate state.

## M2/M3.6 nauthilus-directorctl

### Purpose

Make runtime operations scriptable through `nauthilus-directorctl` while keeping
all API transport on the generated OpenAPI client SDK.

### In Scope

- Preserve `nauthilus-directorctl --version`.
- Preserve and expand `nauthilus-directorctl status`.
- Add nested commands:

```text
nauthilus-directorctl backends list
nauthilus-directorctl backends show <identifier>
nauthilus-directorctl backends maintenance enable <identifier> --reason <text>
nauthilus-directorctl backends maintenance disable <identifier> --reason <text>
nauthilus-directorctl backends out <identifier> --reason <text>
nauthilus-directorctl backends in <identifier> --reason <text>
nauthilus-directorctl backends drain <identifier> --mode <soft|hard> --reason <text>
nauthilus-directorctl backends runtime clear <identifier> --reason <text>
nauthilus-directorctl config dump -d [--format yaml|json] [-P]
nauthilus-directorctl config dump -n [--format yaml|json] [-P]
nauthilus-directorctl sessions list --protocol imap
nauthilus-directorctl sessions show <session-id>
nauthilus-directorctl sessions kill <session-id> --reason <text>
nauthilus-directorctl users list
nauthilus-directorctl users show <user-key>
nauthilus-directorctl users sessions <user-key>
nauthilus-directorctl users affinity show <user-key>
nauthilus-directorctl users affinity set <user-key> --shard <shard> --reason <text>
nauthilus-directorctl users affinity clear <user-key> --reason <text>
nauthilus-directorctl users move <user-key> --to-shard <shard> --strategy <strategy> --reason <text>
nauthilus-directorctl users kick <user-key> --reason <text>
nauthilus-directorctl route lookup --protocol imap --user <user-key> [--listener <name>] [--attribute k=v]
nauthilus-directorctl reload
```

- Add operator-friendly output in stable text or JSON mode.
- Add global flags for control API address, timeout and output format.
- Use generated `ClientWithResponsesInterface` for every HTTP call.
- Convert generated client responses into clear exit codes.
- Preserve `nauthilus-director config dump` as the local server-process
  inspection path and add matching `nauthilus-directorctl config dump` commands
  for remote Director inspection.
- Add or update initial manpage sources under `docs/man/` for
  `nauthilus-director(1)`, `nauthilus-directorctl(1)` and
  `nauthilus-director.yaml(5)` once the M2/M3 command grammar, flags, output
  modes, exit codes and stable config paths are clear enough to document.

### Out of Scope

- Hand-written HTTP transport.
- Duplicate CLI DTO structs that mirror generated OpenAPI models.
- Shelling out to `curl`.
- Writing YAML config from CLI runtime commands.

### Expected Files or Packages

```text
cmd/nauthilus-directorctl/main.go
cmd/nauthilus-directorctl/main_test.go
internal/client/generated/client.gen.go
docs/man/
```

### Implementation Notes

- A small command dispatcher is acceptable. Avoid a dependency unless the
  command grammar becomes hard to maintain with the standard library.
- Commands should require `--reason` for mutating operations.
- `nauthilus-directorctl config dump -d`, `-n` and `-P` target the Director's
  runtime config through the generated OpenAPI client. They do not inspect or
  dump client-local configuration.
- `nauthilus-directorctl config dump -P` must fail clearly with authorization
  errors when the Director rejects protected remote config output.
- Text output should be compact and scriptable. JSON output should return the
  generated response body when practical.
- Command manpages should document stable operator-facing command grammar, flags,
  output formats, exit codes, protected config behavior and the distinction
  between runtime-state mutations and YAML configuration changes.
- The `nauthilus-director.yaml(5)` manpage should document the YAML config file
  format, stable config path groups, include and patch behavior, `${NAME}`
  placeholder expansion, `NAUTHILUS_DIRECTOR_*` environment overrides, redaction
  and protected-value semantics. It may mention `.yml` as an accepted file
  extension, but the canonical manual page name is `nauthilus-director.yaml(5)`.
- Exit code guidance:
  - `0` success
  - `1` request reached the server but operation failed
  - `2` local usage/configuration error
- CLI tests should use fake generated client implementations where possible and
  binary-boundary tests for parsing/output behavior.

### Required Unit Tests

- Every nested command parses expected flags.
- Mutating commands require a reason.
- Commands call the generated client interface, not hand-written transport.
- Config dump commands call the generated config endpoints and map `-P` to the
  protected output request flag.
- Config dump `-P` handles `403` without printing partial config output.
- HTTP status mappings produce stable exit codes.
- Text and JSON output are deterministic.
- Manpage content matches implemented stable commands, flags, output modes, exit
  code behavior and stable documented config paths.

### Acceptance Criteria

- CLI covers the M2/M3 REST runtime surface.
- CLI does not duplicate REST DTOs.
- CLI command grammar stays nested and operator-oriented.
- E2E tests prove CLI and REST operate on the same Redis-backed state.
- Initial manpages cover the stable server/client operator command surfaces and
  the YAML config file format.

### Review Checklist

- Verify no command bypasses the generated client SDK.
- Verify no CLI command writes YAML config.
- Verify usage errors do not print secrets.
- Verify manpages do not document commands, flags, output formats or stable
  config paths that are not implemented.

## M2/M3.7 Route Lookup and Read-Only Diagnostics

### Purpose

Connect `POST /api/v1/route/lookup` and CLI route lookup to the shared routing
and backend selection pipeline without authenticating, opening sessions or
mutating Redis state.

### In Scope

- Build a route lookup service that consumes operator-provided identity and
  routing facts.
- Reuse the shared routing resolver.
- Reuse the runtime-aware backend selector in read-only mode.
- Optionally read Redis-backed affinity and runtime state without refreshing
  leases.
- Explain selection decisions and exclusion reasons.
- Reject credential-bearing input before the generated handler boundary.
- Add side-effect tests with counting fakes for Nauthilus, session store and
  runtime stores.

### Out of Scope

- Calling Nauthilus.
- Authenticating credentials.
- Creating sessions.
- Refreshing session leases.
- Mutating affinity, backend runtime state or indexes.
- Backend auth or backend connect.

### Expected Files or Packages

```text
internal/runtime/route_lookup.go
internal/rest/adapters/handler.go
cmd/nauthilus-directorctl/main.go
docs/specs/implementation/M3_ROUTE_LOOKUP_FOLLOWUP.md
```

### Implementation Notes

- Route lookup input is diagnostic. The caller supplies already-known user,
  tenant, listener, protocol and optional attributes.
- The service should return:
  - routing source
  - shard tag
  - active affinity state when requested
  - eligible backend summaries
  - selected backend
  - exclusion reasons
  - whether health, maintenance, runtime overrides or max connections affected
    the result
- Do not expose passwords, bearer tokens, SASL blobs, raw session IDs, raw
  client IPs, raw error text or secret-bearing attributes.
- Backend identifiers are acceptable in REST/CLI diagnostic output, but not as
  metric labels.

### Required Unit Tests

- Route lookup does not call Nauthilus.
- Route lookup does not open, heartbeat, close, reap, move, kick or clear
  sessions.
- Credential-bearing request keys are rejected before generated decoding.
- Runtime state reads are read-only.
- Selection explanations reflect runtime exclusions.

### Acceptance Criteria

- Route lookup is implemented and remains side-effect-free.
- Route lookup uses the same routing/selection domain as IMAP placement.
- CLI route lookup uses the generated client SDK.

### Review Checklist

- Verify no credential field can sneak into lookup input.
- Verify lookup does not mutate Redis state.
- Verify lookup does not become a parallel selector implementation.

## M2/M3.8 Observability, E2E, Interoperability and Guardrails

### Purpose

Prove runtime and control behavior through focused unit tests, integration tests
and externally visible E2E tests while keeping observability secret-safe.

### In Scope

- Add runtime observability events for:
  - backend health transition
  - backend effective-state change
  - backend runtime operation
  - backend maintenance operation
  - backend drain start/end
  - selector exclusion reason
  - session attach/close/reap
  - session kill
  - user move
  - user kick
  - affinity clear
  - route lookup
  - reload
- Add Prometheus metrics only with approved low-cardinality labels.
- Extend fake-service E2E to prove runtime behavior through public IMAP
  sockets, REST calls and CLI commands.
- Keep `make e2e` deterministic and Docker-independent.
- Keep `make e2e-interop` as the real IMAP interoperability regression lane
  when M2/M3 changes IMAP backend/proxy behavior.
- Prove the real-server interop path with at least three Director processes,
  six Dovecot IMAP backends and one shared Redis-compatible state service when
  runtime-control, affinity, shard selection or health behavior changes.
- Run validation through Makefile targets.

### Out of Scope

- Full M4 OpenTelemetry exporter polish.
- High-cardinality metrics for users, sessions, client IPs, request IDs or raw
  backend identifiers.
- Replacing fake-service E2E with Docker interoperability tests.

### Expected Files or Packages

```text
internal/observability/events.go
internal/observability/metrics.go
internal/observability/policy.go
internal/observability/*_test.go
test/e2e/fake_lane_test.go
test/e2e/run.sh
test/e2e/interop/run.sh
Makefile
```

### Implementation Notes

- Metric labels may include protocol, listener, backend pool, shard tag,
  operation, result, reason class and maintenance mode when bounded.
- Metric labels must not include username, user hash, recipient, session ID,
  trace ID, request ID, client IP, raw backend identifier or raw error text.
- Logs may include backend identifiers for operator diagnostics, but they must
  not include credentials or raw high-cardinality user data.
- E2E assertions should observe backend routing through fake backend behavior,
  REST responses, CLI output and Redis-visible effects only through public
  system boundaries.
- At least one fast E2E assertion must start the production
  `nauthilus-director` binary and prove the public IMAP entrypoint. REST/CLI
  parity proof must include a running production server process, not only an
  in-process handler.
- E2E tests must not import internal packages to mutate runtime state.
- E2E tests should use the same Redis-compatible policy as M1.
- If Docker is unavailable, `make e2e-interop` may skip with its established
  stable skip message, but closeout must record whether it passed or skipped.

### Required Unit Tests

- Observability policy rejects disallowed metric labels.
- Runtime event normalization strips or classifies unsafe fields.
- Secret-bearing runtime errors are redacted.
- Runtime operation reason classes are low-cardinality.

### Required Integration or E2E Tests

- Runtime weight `0` changes externally observed backend placement.
- Runtime out excludes a backend from new placement.
- Runtime drain excludes new placement and preserves or closes active sessions
  according to mode/grace.
- Backend maintenance changes placement and audit state.
- User move changes reconnect placement according to strategy.
- User kick closes active proxy sessions.
- Session kill closes only the target session.
- Affinity clear refuses active state and succeeds after sessions are closed.
- Max connections prevents overbooking under parallel sessions.
- Reap repairs stale Redis sessions after an unclean disconnect or process
  termination.
- REST and CLI perform equivalent mutations against the same Redis-backed state.
- The production `nauthilus-director` binary starts IMAP and control listeners
  from typed config.
- The real interop lane proves cross-process active affinity, deep health
  checks, distributed health ownership, untagged default backends, explicit
  shard backends, parallel connections for one user, user move, user kick,
  targeted session kill, hard backend drain and affinity clear against real
  Dovecot backends.
- Route lookup reads runtime state without calling Nauthilus or mutating Redis.
- Reload applies safe changes or rejects unsafe changes cleanly.
- Secret-safe logs do not include credentials, tokens or SASL blobs.

### Acceptance Criteria

- `make guardrails` passes before M2/M3 is marked complete or committed.
- `make e2e` proves all externally visible runtime/control behavior.
- `make e2e-interop` is run and recorded when IMAP interop-sensitive paths
  change.
- Observability remains low-cardinality and secret-safe.

### Review Checklist

- Verify E2E tests talk to public sockets, REST endpoints or CLI commands.
- Verify E2E tests do not mutate runtime state through internal packages.
- Verify fake services still prove deterministic edge cases.
- Verify real interop coverage remains available for IMAP regressions.

## Top-Level Acceptance Checklist

M2/M3 is complete only when all items below are true:

- [ ] Effective backend state overlays config, runtime override, maintenance,
      health, drain and active-session counts in one shared domain model.
- [ ] Backend `shard_tag` is optional in YAML but always normalized to a
      non-empty effective shard before runtime use.
- [ ] Hard-down active-pin failover is same-effective-shard only, explicitly
      configured and audited.
- [ ] Runtime overrides never rewrite YAML config.
- [ ] Redis stores selected backend session state and backend active counts.
- [ ] Redis scripts or atomic operations cover open, heartbeat, close, lookup,
      reap, move, kick, clear, session kill, backend runtime set and backend
      runtime clear.
- [ ] User move strategies are aligned between config, OpenAPI, REST, CLI and
      domain code.
- [ ] User kick and session kill are observed by active proxy sessions through
      heartbeat or an equally durable Redis-backed mechanism.
- [ ] Affinity clear refuses active affinity by default.
- [ ] Reap repairs expired session leases and backend counts.
- [ ] Health checks influence backend eligibility without weakening TLS or
      logging secrets.
- [ ] Static and runtime hard maintenance exclude new sessions.
- [ ] Soft maintenance excludes new initial placements while preserving active
      pins only when configured.
- [ ] Runtime drain is auditable and distinct from runtime weight `0`.
- [ ] Runtime out is distinct from hard maintenance and does not imply YAML
      mutation.
- [ ] Runtime weight `0` excludes initial placement but does not by itself
      terminate active pins.
- [ ] Max-connection limits are Redis-coordinated and fail closed on races.
- [ ] Active affinity remains the highest normal placement priority.
- [ ] Backend connect/auth failure after placement rolls back or closes Redis
      state.
- [ ] All v1 REST endpoints in scope are implemented through generated OpenAPI
      server boundaries.
- [ ] Generated OpenAPI artifacts pass stale-output checks.
- [ ] Generated config documentation references pass stale-output checks, and
      stable config paths have complete metadata without TODO descriptions.
- [ ] `nauthilus-directorctl` uses the generated OpenAPI client SDK for every
      API call.
- [ ] Initial manpages under `docs/man/` document
      `nauthilus-director(1)`, `nauthilus-directorctl(1)` and
      `nauthilus-director.yaml(5)` without advertising unimplemented commands,
      flags, output formats or config paths.
- [ ] Route lookup is side-effect-free, does not call Nauthilus and does not
      mutate Redis.
- [ ] REST config endpoints are redacted by default and expose protected values
      only through explicit authorized and audited protected requests.
- [ ] `nauthilus-directorctl config dump -d`, `-n` and `-P` target the running
      Director through the generated client SDK.
- [ ] Reload is real Safe Reload: it applies supported safe changes and rejects
      unsafe changes cleanly.
- [ ] Runtime logs, traces and metrics remain secret-safe.
- [ ] Metrics use only the low-cardinality allowlist.
- [ ] E2E guardrail lane proves runtime weight `0`, in/out, drain,
      maintenance, user move, user kick, session kill, max connections, reap,
      route lookup and REST/CLI parity through public system boundaries.
- [ ] `make guardrails` is the final local gate before any commit or pull
      request that contains M2/M3 implementation work.

### Completion Evidence

M2/M3 closeout completed on 2026-05-26 after the required final review pass.
The implementation includes the shared effective backend state model, Redis
runtime/session operations, generated OpenAPI server/client boundaries,
`nauthilus-directorctl` generated-client transport, side-effect-free route
lookup, safe reload, generated config documentation guardrails, manpage
coverage and secret-safe runtime/control observability.

The deterministic fake-service E2E lane proves runtime/control behavior through
public IMAP sockets, generated REST endpoints and real
`nauthilus-directorctl` commands. The corrected binary-entry E2E additionally
starts the production `nauthilus-director` process, verifies IMAP login and
proxy handoff through its public listener, and proves CLI and REST observe the
same Redis-backed backend runtime state in that running process. Reap repair is
covered by Redis/runtime guardrail tests because no public reap command exists
in the stable v1 control surface. Real-server interoperability passed against
pinned Dovecot and now uses the production server binary as its director
entrypoint. The interop lane also starts three production Director processes on
one Redis-compatible state service with six Dovecot backends, then proves deep
health checks, distributed Redis health ownership, untagged default placement,
two explicit shards, same-user active affinity, parallel connections, route
lookup, `sessions kill`, `users kick`, `users move --strategy
new_sessions_only`, hard backend drain and affinity clear through public IMAP
sockets and `nauthilus-directorctl`.

## Required M2/M3 Review Pass

Before closing M2/M3, perform this review:

1. Re-read `AGENTS.md`.
2. Re-read `docs/ARCHITECTURE_ROADMAP.md`, especially sections 8, 9, 14, 15,
   18, 19, 20, 21 and 22.
3. Re-read `docs/specs/implementation/M0_FOUNDATION_SPEC.md`.
4. Re-read `docs/specs/implementation/M1_IMAP_MVP_SPEC.md`.
5. Re-read `docs/specs/implementation/M3_ROUTE_LOOKUP_FOLLOWUP.md`.
6. Re-read `docs/config/nauthilus-director.target.yml`.
7. Re-read `docs/specs/openapi/nauthilus-director.yaml`.
8. Compare implementation and docs against this specification and the source
   documents.
9. Fix drift, missing constraints, accidental POC coupling, duplicate runtime
   models, non-OpenAPI control surfaces, false REST capability advertisement
   and vague acceptance criteria.
10. Run `make check-openapi` after any OpenAPI schema or generated-code change.
11. Run `make check-docs` after any typed config, config metadata or generated
    docs change.
12. Run targeted runtime, Redis, selector, REST and CLI tests.
13. Run `make guardrails` before any commit or pull request.
14. Run and record `make e2e-interop` when IMAP backend/proxy behavior that
    real Dovecot interoperability can regress was changed.
15. Record `git status --short` and the exact validation result in the
    M2/M3 closeout.

## Decisions and Open Questions

These decisions are recorded as they are settled. Remaining questions should be
settled before broad implementation starts.

1. Decision: backend health uses Redis-coordinated deep-check ownership.

   Credentialed deep health checks must be coordinated through Redis so only
   one director instance checks a given backend with the shared health
   credentials at a time. This avoids concurrent Dovecot health logins with the
   same test account and reduces the risk of mailbox index damage. Local light
   checks remain allowed for per-instance reachability. Published deep-health
   state is read by placement and diagnostics, while normal routing never
   acquires a distributed lock.

2. Decision: hard-down active-pin failover is same-shard only and explicitly
   gated.

   When an active pin points at a hard-down backend, the director may fail over
   only to another eligible backend with the same effective shard when
   `director.affinity.active_user_pinning.failover.allow_on_hard_down` is true.
   The movement must be audited. If the flag is false, or no eligible backend
   exists for the same effective shard, placement fails closed. Cross-shard
   failover is not allowed; that remains an explicit user move operation.

   Backend `shard_tag` is optional in YAML. The config loader must normalize an
   omitted backend `shard_tag` to the configured `director.routing.default_shard`
   or `default` if no explicit default is present. Runtime state, selection,
   affinity and route lookup always use the resulting non-empty effective
   shard.

3. Decision: active affinity clear does not force-close active sessions.

   Affinity clear remains conservative. If active sessions exist, clear returns
   a conflict and the operator must use an explicit user kick, user move with
   `kick_existing`, backend drain or hard maintenance operation first. User
   `kick_existing` applies to all active sessions for the targeted affinity key.
   Backend-scoped drain and hard maintenance apply in bulk to all sessions
   attached to the backend, so operators do not need to kick affected users one
   by one.

4. Decision: `nauthilus-directorctl config dump` targets the running Director,
   including `-P`.

   The local server command `nauthilus-director config dump -d|-n [-P]` remains
   available for local process inspection. M2/M3 also implements matching
   `nauthilus-directorctl config dump -d|-n [-P]` behavior through the generated
   REST client so the flags apply to the remote Director config, not to
   client-local settings. REST config output is redacted by default. Protected
   remote output requires an explicit protected request flag, a successful
   control-plane authorization decision for protected config export and an
   audit event that does not contain the protected values.

5. Decision: M2/M3 implements real Safe Reload, not validate-only reload.

   Reload must parse and validate the new config, build a new runtime snapshot
   and apply supported safe changes. Existing sessions remain on their old
   listener/backend objects until they close; new sessions use the new snapshot.
   Unsupported or unsafe live changes must be rejected with operator-readable
   reasons instead of being partially applied or silently ignored.
