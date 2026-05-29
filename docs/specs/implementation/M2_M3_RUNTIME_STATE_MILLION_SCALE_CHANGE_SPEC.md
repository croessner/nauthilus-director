# M2/M3 Runtime State Million-Scale Change Specification

Status: draft. This change specification is pending implementation. It amends
the completed M2/M3 backend runtime and control milestone so the Redis-backed
runtime state can scale from demonstration and moderate production sizes to
deployments with millions of active or recently idle frontend sessions.

This document does not replace the M6 ManageSieve milestone in the architecture
roadmap. It is a focused M2/M3 runtime-state change set because the affected
behavior is active affinity, session leases, Redis indexes, backend runtime
accounting, REST control reads and `nauthilus-directorctl` operator views.

The goal is not to store every possible mailbox account in Redis. The director
must keep Redis state proportional to active, idle-grace and repairable runtime
activity. A deployment with many millions of provisioned accounts but only a
smaller active population should pay for the active population only.

## Source Documents

This change specification is governed by:

- `AGENTS.md`
- `docs/ARCHITECTURE_ROADMAP.md`
- `docs/specs/implementation/M0_FOUNDATION_SPEC.md`
- `docs/specs/implementation/M1_IMAP_MVP_SPEC.md`
- `docs/specs/implementation/M2_M3_BACKEND_RUNTIME_CONTROL_SPEC.md`
- `docs/specs/implementation/M4_OBSERVABILITY_SPEC.md`
- `docs/specs/implementation/M5_LMTP_PRODUCTION_SPEC.md`
- `docs/config/nauthilus-director.target.yml`
- `docs/reference/config-defaults.yaml`
- `docs/reference/config-paths.md`
- `docs/specs/openapi/nauthilus-director.yaml`
- `docs/man/nauthilus-directorctl.1`
- `Makefile`

If this specification conflicts with those source documents, fix the drift
before implementation continues. In particular, do not weaken active-user
stickiness, route-lookup side-effect freedom, Redis fail-closed behavior, metric
label policy or generated OpenAPI boundaries to make the scale work easier.

## Million-Scale Goal

The target runtime model is:

```text
frontend protocol session
  -> per-affinity Redis lease state
  -> backend capacity reservation
  -> bounded heartbeat and close updates
  -> sharded repairable indexes
  -> due-time reaping without global scans
  -> paginated REST and CLI reads
  -> aggregate counters for operator dashboards
```

The normal placement path must stay small and predictable:

- Opening, heartbeating and closing one session must touch only a bounded number
  of Redis keys.
- Active affinity decisions must continue to be per-affinity and atomic.
- A user with many sessions must not force scans across unrelated users.
- A deployment with many users must not make one user's open, heartbeat, close
  or route lookup slower merely because other users exist.
- Redis Cluster support must respect hash-slot rules. A Lua script must not
  require keys from unrelated hash slots.
- Repairable indexes may be eventually consistent, but routing correctness,
  lease expiry and backend capacity safety must not depend on an unbounded
  global index being perfectly current.

This specification targets at least the following design envelope:

- Millions of provisioned accounts without Redis state for inactive accounts.
- Millions of active or recently idle session records distributed across a
  properly sized Redis Cluster.
- Hundreds to low thousands of Directors and backend hosts without a single
  global runtime index becoming the dominant bottleneck.
- Control-plane list and diagnostic operations that remain bounded, paginated
  and cancellable under load.

These are architectural targets, not a promise that one small Redis instance or
one default demo stack can carry that load. Production sizing remains an
operator responsibility and must be documented.

## Current Limitations To Remove

The existing core active-affinity model is a good base: per-affinity keys are
hash-tagged, session liveness is lease-based, usernames are not required in key
names, and open/heartbeat/close semantics already use Redis server time.

The following current behaviors are not acceptable for million-scale operation:

- `ListRuntimeSessions` reads the complete global session index with `HGETALL`.
- `ListRuntimeUsers` derives users by first listing all runtime sessions.
- `reap.lua` reads the complete global session index with `HGETALL` before
  applying its `limit`.
- User and backend session list helpers use unbounded set reads for control
  views.
- REST and CLI list operations have no cursor contract and may try to return an
  unbounded response.
- Global runtime indexes are single logical keys, which creates hot keys and
  large object payloads.
- The current Redis scripts receive per-affinity keys plus global or backend
  index keys. That shape cannot be the final Redis Cluster design because one
  Lua invocation cannot atomically mutate unrelated hash slots.
- Backend active-session accounting is updated together with affinity/session
  state. Million-scale Redis Cluster support needs an explicit cross-slot
  reservation model, or another design with equivalent safety and repairability.

## Delivery Shape

Implement this change as explicit slices:

1. Redis Cluster-safe mutation boundary and state schema.
2. Sharded runtime indexes and due-time reaper design.
3. Backend capacity reservations and idempotent release/repair.
4. Paginated REST and CLI runtime reads.
5. Aggregate runtime counters and scale-safe observability.
6. Migration, compatibility and operational documentation.
7. Deterministic scale tests, stress harness and closeout review.

The slices may be committed separately. The change is not complete until the
normal protocol path, the periodic reaper, the REST control API and
`nauthilus-directorctl` all avoid unbounded runtime-state scans.

## Global Scope

In scope:

- Preserve the existing per-affinity active-user stickiness semantics.
- Preserve Redis as the only production runtime state backend.
- Keep Redis configuration centralized under `storage.redis`.
- Add typed runtime-state and reaper configuration only where hardcoded limits
  must become operator-tunable.
- Redesign repairable indexes so they are sharded, cursor-readable and safe for
  millions of entries.
- Redesign expired-session reaping so each pass reads a bounded due set or
  bucket, not the whole deployment.
- Add or adapt backend capacity reservations so max-connection enforcement
  remains safe across Redis Cluster hash slots.
- Add OpenAPI cursor, limit and filter parameters for list endpoints.
- Update generated REST server and generated client artifacts through the
  pinned `oapi-codegen` workflow.
- Update `nauthilus-directorctl` to expose cursor-aware list commands and avoid
  silently fetching the entire deployment.
- Add aggregate runtime counters for operator totals.
- Add tests that fail if unbounded `HGETALL`, `SMEMBERS` or full-index reads are
  reintroduced on million-scale paths.
- Add deterministic scale tests that do not require actually opening millions of
  sockets.
- Add an optional stress harness that can be enabled outside normal guardrails
  for Redis Cluster sizing work.

Out of scope:

- Replacing Redis with another production state backend.
- Writing runtime state into YAML configuration.
- Making Nauthilus own backend selection.
- Weakening active affinity to deterministic hashing while a user has active
  sessions.
- Transparent live migration of established TCP sessions between Directors.
- Storing all provisioned accounts in Redis before they are active.
- Adding usernames, recipients, session IDs, client IPs, raw backend identifiers
  or raw Redis keys as metric labels.
- Replacing generated REST DTOs or generated client SDK usage with hand-written
  transport models.

## Stable And New Config Paths

Existing stable paths must not be renamed, removed or inverted:

- `storage.redis`
- `runtime.timeouts`
- `runtime.servers.control`
- `director.affinity`
- `director.backend_pools`
- `director.backends`
- `director.health`
- `director.maintenance`
- `director.runtime_overrides`
- `observability`

This change may add typed configuration for runtime-state scaling. New paths
must be added to config defaults, generated config references, validation,
manpages and examples in the same implementation slice.

Proposed new paths:

- `runtime.state.reaper.interval`
- `runtime.state.reaper.batch_size`
- `runtime.state.reaper.max_pass_duration`
- `runtime.state.reaper.jitter`
- `runtime.state.indexes.session_shards`
- `runtime.state.indexes.user_shards`
- `runtime.state.indexes.backend_shards`
- `runtime.state.indexes.page_default`
- `runtime.state.indexes.page_max`
- `runtime.state.backend_reservations.ttl`
- `runtime.state.backend_reservations.repair_interval`

These paths configure runtime behavior, not Redis connection topology. Redis
connection, TLS, authentication, Cluster and Sentinel settings remain under
`storage.redis`.

## Target Package Boundaries

This change expands existing packages and may add narrowly scoped helpers:

```text
internal/state/
internal/runtime/
internal/backend/
internal/app/
internal/rest/adapters/
internal/rest/generated/
internal/client/generated/
cmd/nauthilus-directorctl/
internal/observability/
test/e2e/
test/scale/
docs/
```

Boundary rules:

- `internal/state` owns Redis key shapes, Lua scripts, sharded indexes, backend
  reservation persistence, pagination cursors and Redis error classification.
- `internal/runtime` owns operator use cases such as list sessions, list users,
  get session, get user, reap, repair and aggregate reads. It must not become a
  generic pagination helper package.
- `internal/backend` consumes reservation results and capacity state through
  narrow interfaces. It must not know Redis key names.
- `internal/app` owns Fx wiring for reaper, repair workers and typed config.
- `internal/rest/adapters` maps generated OpenAPI cursor contracts to runtime
  domain requests and responses.
- `cmd/nauthilus-directorctl` owns command grammar, cursor iteration,
  formatting and operator errors while continuing to use the generated client.
- `internal/observability` records bounded aggregate metrics and scale-safe
  events without turning metrics into runtime state.
- `test/scale` may hold optional stress harnesses that are not part of
  `make guardrails` unless they are deterministic and bounded.

## M2/M3.S1 Redis Cluster-Safe Mutation Boundary

### Purpose

Make the authoritative routing and lease mutations safe for actual Redis
Cluster hash-slot rules while keeping active affinity atomic.

### In Scope

- Keep per-affinity keys hash-tagged by affinity hash.
- Keep open, heartbeat, close, lookup and affinity control mutations atomic
  inside one affinity hash slot.
- Remove unrelated global, backend or deployment-wide keys from per-affinity Lua
  invocations.
- Return explicit mutation deltas from scripts so callers can update repairable
  indexes or counters through separate idempotent operations.
- Ensure routing correctness does not depend on a secondary index update
  succeeding in the same command as the affinity mutation.
- Keep script payloads bounded and typed.
- Preserve fail-closed behavior for ambiguous affinity state.

### Out of Scope

- Cross-slot Lua or Redis transactions.
- Distributed locks in the normal placement path.
- Any design that requires all affinity keys to live in one Redis Cluster slot.

### Expected Files or Packages

```text
internal/state/keys.go
internal/state/sessions.go
internal/state/scripts/open.lua
internal/state/scripts/heartbeat.lua
internal/state/scripts/close.lua
internal/state/scripts/lookup.lua
internal/state/*_test.go
```

### Implementation Notes

- Per-affinity scripts may mutate:
  - `<prefix>:v<schema>:{aff:<hash>}:state`
  - `<prefix>:v<schema>:{aff:<hash>}:sessions`
  - `<prefix>:v<schema>:{aff:<hash>}:session:<session_id>`
  - `<prefix>:v<schema>:{aff:<hash>}:override`
- Per-affinity scripts must not mutate:
  - global session indexes
  - backend runtime keys
  - backend session indexes
  - deployment-wide user indexes
  - aggregate counter keys outside the affinity slot
- Script return values should include enough information for idempotent
  follow-up writes:
  - session ID
  - affinity hash
  - tenant
  - account key
  - protocol
  - listener
  - service
  - shard tag
  - holder kind
  - lease expiry
  - idle expiry
  - selected backend when known
  - generation and control generation
- Follow-up index writes must be retried or made repairable. Missing secondary
  index entries must not make active routing incorrect.
- Unit tests should include key-slot assertions or deterministic key-group
  checks so future scripts cannot accidentally add cross-slot keys.

### Required Unit Tests

- Per-affinity key builders produce one hash tag for all affinity-owned keys.
- Per-affinity script wrappers pass only affinity-owned keys.
- Open, heartbeat and close still preserve active affinity semantics.
- Missing or failed secondary index updates do not change routing decisions.
- Script deltas contain all fields required for idempotent indexing.
- Cluster-mode validation rejects any script wrapper that attempts to mix
  affinity keys with unrelated global or backend keys.

### Acceptance Criteria

- Active affinity remains atomic per user.
- Redis Cluster hash-slot rules are respected by authoritative Lua scripts.
- Repairable index writes are no longer required for routing correctness.

### Review Checklist

- Verify no production script receives unrelated hash-slot keys.
- Verify retry or repair behavior exists for every secondary-index mutation.
- Verify key names still do not expose raw usernames.

## M2/M3.S2 Sharded Runtime Indexes And Due-Time Reaping

### Purpose

Replace global full-index scans with sharded, cursor-readable indexes and a
bounded due-time reaper.

### In Scope

- Replace the single global session index with sharded session locator indexes.
- Replace unbounded user/backend session reads with cursor-based or bounded
  reads.
- Add a due-time index for expired or soon-expiring sessions.
- Rework the reaper so each pass reads only a bounded due shard or bucket.
- Keep reaper progress durable enough that many Director processes can
  participate without duplicating excessive work.
- Ensure reaping repairs backend reservations, backend session indexes and
  aggregate counters idempotently.
- Ensure stale indexes are tolerated and cleaned opportunistically.

### Out of Scope

- A single deployment-wide `HGETALL` or `SMEMBERS` on runtime session state.
- A reaper that scans every active session to find expired ones.
- Relying on keyspace notifications for correctness.

### Expected Files or Packages

```text
internal/state/keys.go
internal/state/reap.go
internal/state/runtime_read.go
internal/state/scripts/reap.lua
internal/runtime/sessions.go
internal/app/server.go
```

### Implementation Notes

- Index shard selection must be deterministic from stable values such as
  session ID, affinity hash or backend identifier.
- Runtime list cursors must encode:
  - index family
  - shard number
  - Redis cursor or bucket cursor
  - optional filter state
  - a version marker
- Cursors must be opaque to clients and safe to log only as bounded diagnostic
  tokens. They must not contain raw usernames, recipients, credentials or Redis
  keys.
- Reaper due indexes should prefer sorted sets or time buckets so the worker can
  fetch "sessions due before now" without inspecting unrelated sessions.
- Each reap pass must have both a batch-size bound and a wall-clock duration
  bound.
- Multiple Directors may run reapers. Coordination may use short Redis leases
  per due shard or idempotent compare-and-repair logic. It must not rely on a
  long-lived distributed lock for normal routing.
- The reaper must use Redis server time for lease decisions.

### Required Unit Tests

- Session locator indexes are sharded deterministically.
- Runtime list reads honor page size and cursor boundaries.
- User session reads cannot fetch an unbounded set in one operation.
- Backend session reads cannot fetch an unbounded set in one operation.
- Reaper selects only due sessions and respects batch size.
- Reaper respects max pass duration.
- Reaper is idempotent when two workers see the same due session.
- Stale locator entries are removed without failing the whole page.

### Required Integration or E2E Tests

- Populate many fake session records without opening sockets and verify list
  APIs page through them.
- Populate expired and non-expired records and verify reaping touches only due
  records.
- Run two reaper workers against the same state and verify final counts are
  correct.

### Acceptance Criteria

- No runtime list or reaper path performs a deployment-wide full scan.
- Reaper cost is proportional to due work, not total active sessions.
- Stale repairable indexes do not break routing, pagination or future repair.

### Review Checklist

- Search for unbounded `HGetAll`, `SMembers`, `KEYS` and whole-index Lua reads
  on runtime session paths.
- Verify cursor tokens cannot leak raw user, session, backend or Redis-key
  material.
- Verify every reaper loop can stop promptly during process shutdown.

## M2/M3.S3 Backend Capacity Reservations

### Purpose

Preserve backend max-connection and active-session accounting without requiring
one Redis Cluster Lua script to touch both affinity keys and backend keys.

### In Scope

- Add a backend-slot reservation lease for selected backend capacity.
- Reserve capacity before or during attach in a way that fails closed when the
  backend is at capacity.
- Attach the reservation to the affinity session idempotently.
- Release the reservation on clean close.
- Expire and repair reservations after Director crash or partial failure.
- Keep backend active-session counts safe for placement decisions.
- Preserve backend maintenance, drain, runtime out and health behavior.

### Out of Scope

- Process-local backend active counts as the production source of truth.
- Over-admitting a backend because capacity repair is delayed.
- Cross-slot distributed transactions in the normal path.

### Expected Files or Packages

```text
internal/state/backend_reservations.go
internal/state/scripts/backend_reserve.lua
internal/state/scripts/backend_release.lua
internal/state/scripts/backend_reap.lua
internal/backend/runtime_selector.go
internal/protocol/imap/placement.go
internal/protocol/lmtp/
```

### Implementation Notes

- A reservation should be keyed by backend identifier and reservation/session
  id, with a lease expiry at least as conservative as the session lease.
- Reserving capacity may increment an active or reserved count before the
  affinity session is attached. If the later attach fails, release must be
  idempotent. If release cannot run, the reservation must expire and be repaired.
- Over-reservation is acceptable for a short lease window because it fails
  closed by reducing available capacity. Over-admission is not acceptable.
- Close and reaper paths must release reservations exactly once where possible
  and idempotently otherwise.
- Route lookup must read capacity state but never create a reservation.
- Delivery-scoped LMTP holds must use the same reservation model when they
  consume backend capacity.

### Required Unit Tests

- Reserve succeeds below max connections and fails at capacity.
- Repeated reserve with the same id is idempotent.
- Attach stores the reservation reference on the session.
- Clean close releases the reservation.
- Repeated release is idempotent.
- Expired reservations are repaired without lowering counts below zero.
- Route lookup does not create reservations.
- Backend drain and maintenance exclusion still take precedence over capacity.

### Required Integration or E2E Tests

- Two Director processes cannot exceed backend max connections under concurrent
  placement.
- A failed backend attach releases or expires the reservation.
- A killed Director leaves a reservation that expires and is repaired.

### Acceptance Criteria

- Backend capacity remains safe in Redis Cluster mode.
- Partial failures fail closed by temporarily reserving too much capacity rather
  than overloading a backend.
- Runtime counts converge after expiry and repair.

### Review Checklist

- Verify backend counters cannot become negative.
- Verify max-connection enforcement does not depend on local process state.
- Verify reservation IDs are not exposed as metric labels.

## M2/M3.S4 Paginated REST And CLI Runtime Reads

### Purpose

Make operator reads usable and safe when the deployment has millions of runtime
records.

### In Scope

- Add cursor and limit parameters to session and user list endpoints.
- Add protocol, listener, service, tenant, shard and backend filters where they
  can be implemented without global scans.
- Add hard maximum page sizes.
- Return `next_cursor` only when another page may exist.
- Keep get-by-id and get-by-user targeted reads efficient.
- Update generated REST server and client artifacts.
- Update `nauthilus-directorctl` list commands to page explicitly.
- Make CLI output clear when only one page is shown.
- Add an opt-in `--all` behavior that iterates pages deliberately and can be
  interrupted.

### Out of Scope

- Returning all sessions or users by default.
- Client-side filtering after fetching every runtime record.
- Raw Redis cursors in public API responses.

### Expected Files or Packages

```text
docs/specs/openapi/nauthilus-director.yaml
internal/rest/generated/
internal/client/generated/
internal/rest/adapters/handler.go
internal/runtime/redis_reader.go
cmd/nauthilus-directorctl/main.go
docs/man/nauthilus-directorctl.1
```

### Implementation Notes

- Public cursors should be opaque, versioned and integrity checked.
- Cursor decoding failures should return a stable client error without exposing
  cursor internals.
- The default page size should be conservative. The maximum page size should be
  low enough to protect the control API under load.
- `users list` must not derive users by loading every session. It should read
  sharded user-affinity indexes or aggregate records directly.
- `sessions list --protocol imap` must use an index compatible with protocol
  filtering or a bounded page scan that states filtering is page-local.
- CLI commands must not hide large deployment size by silently stopping at the
  first page without saying so.

### Required Unit Tests

- OpenAPI request and response types include cursor and limit fields.
- REST handler rejects invalid cursors and excessive limits.
- Runtime readers return deterministic pages and cursors.
- CLI passes cursor and limit through the generated client.
- CLI `--all` iterates pages until no cursor remains.
- CLI default output indicates when more records are available.

### Required Integration or E2E Tests

- Production server returns multiple pages for seeded runtime sessions.
- CLI can fetch the first page and then continue from the returned cursor.
- CLI `--all` can be interrupted through context cancellation.

### Acceptance Criteria

- REST and CLI list behavior is bounded by default.
- Operators can still inspect targeted users, sessions and filtered pages.
- Generated OpenAPI artifacts remain reproducible.

### Review Checklist

- Verify no REST handler builds an unbounded response slice.
- Verify no CLI command loops forever on a repeated cursor.
- Verify docs explain page defaults and maximums.

## M2/M3.S5 Aggregate Counters And Scale-Safe Observability

### Purpose

Provide useful operator totals without requiring full session listing and keep
telemetry low-cardinality.

### In Scope

- Maintain aggregate counts for:
  - active sessions by protocol
  - active sessions by listener
  - active sessions by service
  - active sessions by shard tag
  - active or reserved sessions by backend
  - idle affinity count
  - expired sessions repaired
  - stale index entries repaired
  - backend reservations repaired
- Expose aggregate runtime summaries through REST and CLI if the current API
  cannot answer operational questions without full listing.
- Keep Prometheus labels within the existing allowlist.
- Record reaper and repair durations with bounded reason classes.
- Record pagination result classes without cursor values as labels.

### Out of Scope

- Prometheus labels for username, user hash, session ID, recipient, client IP,
  raw backend identifier, Redis key or raw error text.
- Per-user metrics.
- Per-session metrics.
- Metrics as the source of truth for routing.

### Expected Files or Packages

```text
internal/state/aggregates.go
internal/runtime/
internal/observability/
internal/rest/adapters/
docs/specs/openapi/nauthilus-director.yaml
cmd/nauthilus-directorctl/
```

### Implementation Notes

- Aggregates are operational summaries. Placement must continue to use
  authoritative affinity and backend reservation state.
- Aggregates may be repaired asynchronously, but stale aggregate values must be
  marked or bounded enough that operators do not mistake them for exact
  placement decisions.
- The production summary API reports active-session, idle-affinity and backend
  capacity values as `eventually_repaired` operator summaries. Cumulative repair
  counters are reported as `cumulative`. None of these aggregate values is
  routing authority; placement continues to use affinity state and backend
  reservation state.
- Backend identifiers may be visible in REST and CLI diagnostics when necessary,
  but they remain forbidden as Prometheus labels.
- Shard tags are allowed only if the existing metric policy treats them as
  bounded deployment labels.

### Required Unit Tests

- Aggregate increments and decrements are idempotent.
- Reaper repair updates affected aggregate counters.
- Metrics reject forbidden labels.
- Metrics do not contain cursor values, raw session IDs or Redis keys.
- REST summaries distinguish exact values from repaired or approximate values
  when applicable.

### Required Integration or E2E Tests

- Opening, heartbeating, closing and reaping sessions updates aggregate views.
- Metrics scrape remains bounded after seeding many runtime records.

### Acceptance Criteria

- Operators can see useful totals without listing all sessions.
- Metrics remain low-cardinality and secret-safe.
- Aggregate drift is repairable and documented.

### Review Checklist

- Verify aggregate state is not used as a routing authority.
- Verify high-cardinality identifiers do not enter metrics.
- Verify dashboard-style views do not force full runtime scans.

## M2/M3.S6 Migration, Compatibility And Operations

### Purpose

Allow existing deployments and demo stacks to move to the scale-safe runtime
state model without ambiguous behavior.

### Development Schema Decision

Because this change is still part of the pre-release production implementation,
the target default is to keep `storage.redis.schema_version: 1` and update the
v1 runtime-state layout in place. Do not add dual-read migration complexity or a
schema-version bump unless there is explicit evidence that an already published
production compatibility contract depends on the current Redis key layout.

Existing demo or development runtime state may be cleared, expired or recreated
as part of this change. That reset must be documented for operators and test
stacks, but it is not a production migration requirement.

### In Scope

- Keep the default Redis runtime schema at v1 for this development-stage
  change.
- Define the dev/demo reset behavior for old v1 runtime keys.
- Preserve safe startup behavior when old runtime keys exist.
- Provide a documented operator path for clearing old runtime state in demo and
  non-production environments.
- Stop and require an explicit compatibility decision if real production
  deployments must preserve old active runtime keys.
- Update generated config docs and manpages for new runtime-state paths.
- Update demo-stack comments only when new defaults or operator guidance affect
  the demo.

### Out of Scope

- A hidden best-effort migration that silently drops active affinity.
- A migration path that requires Nauthilus to make director placement decisions.
- Demo-only behavior in production code.

### Expected Files or Packages

```text
internal/config/
docs/reference/
docs/man/
contrib/demo-stack/
docs/specs/implementation/
```

### Implementation Notes

- Do not bump `storage.redis.schema_version` during this implementation unless
  the project explicitly changes the compatibility decision.
- Do not add dual-read or old-index migration code for development/demo state
  without a concrete compatibility requirement.
- Old development keys should age out or be cleared by an explicit documented
  command path.
- Startup validation should warn or fail closed when config asks for Redis
  Cluster mode but runtime-state scripts still require cross-slot keys.
- Operational docs must state that the demo stack is not a million-session load
  environment.

### Required Unit Tests

- Config validation accepts new runtime-state defaults.
- Config validation rejects invalid shard counts, page sizes and reaper limits.
- Config dump redaction behavior is unchanged.
- Development reset behavior for old v1 runtime keys is deterministic and
  documented.

### Required Integration or E2E Tests

- A deployment with existing old idle runtime keys starts safely.
- A seeded old development runtime state either expires or is reported according
  to the documented reset mode.
- Demo stack still starts with default scale-safe settings.

### Acceptance Criteria

- Operators have a clear upgrade path.
- New defaults are safe for small deployments and tunable for large ones.
- Demo and production behavior are not conflated.

### Review Checklist

- Verify no migration path deletes active sessions without an explicit operator
  action.
- Verify config documentation and generated references match code.
- Verify v1 reset behavior is easy to diagnose from logs and CLI.

## M2/M3.S7 Scale Tests And Stress Harness

### Purpose

Prove the new runtime-state design with deterministic tests and provide an
optional harness for real Redis Cluster sizing.

### In Scope

- Add unit tests for all key-shaping, cursor, reservation and reaper invariants.
- Add integration tests that seed large logical datasets without opening one TCP
  socket per record.
- Add E2E tests for paginated REST and CLI behavior through the production
  binary.
- Add a stress harness that can target standalone Redis and Redis Cluster.
- Document stress harness inputs, outputs and expected interpretation.
- Ensure normal `make guardrails` stays deterministic and bounded.

### Out of Scope

- Requiring million-record stress tests in every local guardrail run.
- Treating synthetic stress results as a fixed capacity promise for all
  deployments.
- Running destructive Redis commands against an operator's production Redis.

### Expected Files or Packages

```text
internal/state/*_test.go
internal/runtime/*_test.go
test/e2e/
test/scale/
docs/
Makefile
```

### Implementation Notes

- Deterministic tests should assert operation shape and boundedness, not wall
  clock performance on a developer laptop.
- Stress harnesses should emit:
  - active session count
  - session open rate
  - heartbeat rate
  - close rate
  - reaper due rate
  - Redis command latency percentiles
  - error classes
  - memory estimate
  - cluster slot distribution
- The harness must require explicit Redis target configuration and must refuse
  to run against obvious production-looking targets unless an override is set.
- Add Makefile targets only if they are clearly separated from guardrails, for
  example `make scale-smoke` for bounded local proof and `make scale-stress` for
  explicit operator-run stress.

### Required Unit Tests

- Cursor encoding and decoding round-trip.
- Cursor tampering is rejected.
- Bounded readers enforce maximum page sizes.
- Reaper and reservation repairs remain idempotent under repeated calls.

### Required Integration or E2E Tests

- Seed at least tens of thousands of logical records in a bounded test and prove
  list/read/reap operations remain paginated.
- Run production REST and CLI pagination against seeded records.
- Verify `make guardrails` does not run unbounded stress tests.

### Acceptance Criteria

- The implementation has regression coverage for bounded operation shape.
- Operators have a documented path to run real Redis sizing tests.
- The project does not claim a universal capacity number without environment
  context.

### Review Checklist

- Verify stress tools cannot accidentally wipe or overload production Redis.
- Verify deterministic tests fail on reintroduced unbounded scans.
- Verify scale documentation distinguishes architecture, guardrail proof and
  deployment sizing.

## Top-Level Acceptance Checklist

- [ ] Authoritative affinity scripts touch only same-slot affinity keys.
- [ ] Backend capacity enforcement is Redis Cluster-safe and fail-closed.
- [ ] Reaping is due-time and bounded by batch size and duration.
- [ ] Runtime session, user and backend list APIs are cursor-paginated.
- [ ] REST and CLI default list operations have hard maximum page sizes.
- [ ] `users list` no longer derives users by loading every session.
- [ ] Full-index `HGETALL`, unbounded `SMEMBERS`, `KEYS` and whole-index Lua
      reads are absent from million-scale runtime paths.
- [ ] Aggregates answer common operator totals without full scans.
- [ ] OpenAPI server/client code is regenerated reproducibly.
- [ ] Config defaults, generated references, manpages and examples are updated.
- [ ] Deterministic tests prove bounded operation shape.
- [ ] Optional stress harness documentation explains Redis Cluster sizing limits.
- [ ] `make guardrails` passes after implementation.

## Final Review Questions

- Does any normal protocol path perform work proportional to total deployment
  sessions or users?
- Does any REST or CLI default operation attempt to read the entire runtime
  state?
- Can a crashed Director leave a permanent active session, permanent backend
  reservation or permanent stale index entry?
- Can partial Redis failures over-admit a backend past max connections?
- Can route lookup create leases, reservations, delivery holds or index writes?
- Can any metric label contain user, recipient, session, client, Redis key or
  raw backend identifiers?
- Can the same implementation run against both standalone Redis and real Redis
  Cluster without hidden cross-slot assumptions?
