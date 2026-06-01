# M5 Cross-Protocol Backend Affinity Follow-up

Status: completed. The backend-node affinity follow-up, deterministic E2E
coverage, real-server interoperability, demo-stack proof and guardrails are in
place as of 2026-06-01.

This document corrects the active-affinity invariant for the already implemented
IMAP and LMTP protocol paths. The previous shard-only interpretation is not safe
enough for production mailbox index integrity. The director must preserve the
concrete backend authority for a user across protocols, not only the logical
shard. A shard is a placement and failover boundary. The selected backend node
is the mailbox-index safety boundary.

M6 ManageSieve and later POP3 must build on the corrected placement model rather
than copying the current IMAP or LMTP shard-only placement code.

## Source Documents

This follow-up is governed by:

- `AGENTS.md`
- `docs/ARCHITECTURE_ROADMAP.md`
- `docs/specs/implementation/M0_FOUNDATION_SPEC.md`
- `docs/specs/implementation/M1_IMAP_MVP_SPEC.md`
- `docs/specs/implementation/M2_M3_BACKEND_RUNTIME_CONTROL_SPEC.md`
- `docs/specs/implementation/M2_M3_RUNTIME_STATE_MILLION_SCALE_CHANGE_SPEC.md`
- `docs/specs/implementation/M3_USER_BACKEND_PINNING_FOLLOWUP.md`
- `docs/specs/implementation/M3_USER_PLACEMENT_HOLD_FOLLOWUP.md`
- `docs/specs/implementation/M5_LMTP_PRODUCTION_SPEC.md`
- `docs/specs/implementation/M6_MANAGESIEVE_PROXY_SPEC.md`
- `docs/developer/AFFINITY_SESSION_HANDLING.md`
- `docs/specs/openapi/nauthilus-director.yaml`
- `docs/config/nauthilus-director.target.yml`
- `docs/reference/config-defaults.yaml`
- `docs/reference/config-paths.md`
- `contrib/demo-stack/`
- `contrib/demo-stack/scripts/`

If any older source document still describes active affinity as shard-only, this
follow-up supersedes that wording for production behavior. Update the older text
or reference this follow-up before implementing new protocol placement.

## Problem

The implemented IMAP and LMTP placement paths already use the same tenant plus
normalized account affinity key. They also preserve active affinity across
processes through Redis. The missing requirement is that the active pin must
carry the concrete backend identity at the cross-protocol backend-node level.

Routing every protocol to the same `shard_tag` is insufficient when multiple
backend replicas or nodes inside a shard can independently maintain mailbox
indexes. If IMAP selects one backend and LMTP or ManageSieve selects another
backend inside the same shard, the user mailbox index can diverge or be damaged.

There is also a post-delivery race. LMTP may receive a final successful response
from the backend before the backend has fully synchronized mailbox storage or
index state. If the last active delivery hold closes immediately and a following
IMAP connection is allowed to select another backend, the same index-integrity
risk exists even though no active frontend connection remains.

## Hard Invariant

For every mailbox account:

```text
tenant + normalized_account -> shard_tag + backend_node
backend_node + protocol + backend_pool -> backend_identifier
```

The director must preserve `backend_node` across IMAP, LMTP, ManageSieve and
later POP3 while active or retained affinity exists.

Rules:

- A new stateful mailbox session must use an existing active backend node for
  the same affinity key.
- A new LMTP recipient placement must use an existing active or retained backend
  node for the resolved recipient account.
- When no active or retained binding exists, initial placement may select a
  backend through the configured selector, but the selected backend node must
  be persisted atomically before proxy or delivery side effects begin.
- A retained backend binding remains authoritative for a configurable grace
  window after the final session or delivery hold closes.
- The default backend-retention grace is 15 minutes.
- If the bound backend node is authoritatively hard-down according to the
  configured health model, the binding is no longer a safe placement target.
  The director must invalidate or supersede the binding and select a new healthy
  backend node through the configured failover policy.
- If the bound backend node is not authoritatively hard-down, but the requested
  protocol entry is missing, soft-unhealthy, runtime-out, hard-maintenance or
  otherwise unusable, placement fails closed unless an explicit
  operator-controlled movement policy allows a safe backend-node change.
- Route lookup must explain whether placement came from active affinity,
  retained backend binding, operator backend pin, movement override or initial
  placement.

## Terminology

- `shard_tag`: logical placement boundary returned by routing. It groups backend
  candidates but does not by itself protect user indexes.
- `backend_node`: stable identifier for one concrete mailbox backend authority
  across protocol-specific entries. It is the cross-protocol stickiness target.
- `backend_identifier`: concrete configured backend entry for one protocol,
  backend pool and endpoint.
- `active binding`: Redis affinity state with at least one active session or
  delivery hold.
- `retained binding`: Redis affinity state with zero active holders that still
  pins the account to the previous backend node until retention expiry.
- `delivery hold`: LMTP holder that protects affinity during one accepted
  delivery transaction without appearing as a mailbox login session.

## Scope

In scope:

- Add backend-node modeling to configured backend entries and backend registry
  validation.
- Persist active and retained backend binding in Redis affinity state.
- Add configurable backend-retention grace with a 15 minute default.
- Refactor IMAP placement to use a shared backend-affinity domain service.
- Refactor LMTP recipient placement and delivery holds to use the same service.
- Keep delivery holds hidden from session APIs while their backend binding
  influences placement.
- Update route lookup, runtime reads, observability, docs and E2E tests for
  backend-node affinity.
- Update `contrib/demo-stack` config, images, backend wiring, proof scripts and
  docs when backend-node affinity changes operator-visible behavior.
- Update M6 ManageSieve wording and implementation prompts to consume the fixed
  model.

Out of scope:

- Letting Nauthilus select or return concrete backend identifiers.
- Allowing protocol handlers to independently reimplement backend-affinity rules.
- Treating shard-only stickiness as acceptable for user-stateful protocols.
- Using process-local memory as the source of truth for production affinity.
- Spooling LMTP message bodies for delivery to multiple backend nodes.
- Exposing raw backend identifiers as metric labels.

## Configuration

Add a stable backend-node field to backend entries:

```yaml
director:
  backends:
    mailstore-a-imap:
      protocol: imap
      backend_pool: imap-default
      shard_tag: shard-a
      backend_node: mailstore-a-node-1
      address: 10.0.0.11:143

    mailstore-a-lmtp:
      protocol: lmtp
      backend_pool: lmtp-default
      shard_tag: shard-a
      backend_node: mailstore-a-node-1
      address: 10.0.0.11:24
```

Validation rules:

- `backend_node` is required for production multi-protocol stateful configs.
- All entries with the same `backend_node` must have the same effective
  `shard_tag`.
- A backend node may have at most one backend entry for each
  `protocol + backend_pool`.
- A protocol-specific entry may be absent from a backend node only when that
  protocol is not configured for the deployment. A requested protocol with no
  entry in the bound backend node fails closed.
- Existing single-protocol test configs may derive `backend_node` from the
  backend identifier only as a compatibility migration path. Multi-protocol
  configs must declare it explicitly.
- Backend node values are identifiers, not addresses, hostnames, credentials or
  secret-bearing metadata.

Add central affinity retention config:

```yaml
director:
  affinity:
    backend_retention:
      enabled: true
      default_ttl: 15m
      max_ttl: 24h
```

Rules:

- The default must be enabled with `default_ttl: 15m`.
- `default_ttl: 0` may disable retained binding only when the deployment has
  explicitly opted into that weaker behavior.
- Retention config belongs under central affinity configuration, not under IMAP,
  LMTP, Sieve or POP3 protocol subtrees.
- Config dump and generated references must show the safe default.

## Target Package Boundaries

Introduce a shared placement domain boundary instead of duplicating protocol
placement logic:

```text
internal/placement/
internal/backend/
internal/state/
internal/runtime/
internal/protocol/imap/
internal/protocol/lmtp/
internal/protocol/sieve/
```

Responsibilities:

- `internal/placement` owns backend-affinity orchestration, binding invariants,
  retention decisions, rollback and the narrow protocol-facing APIs.
- `internal/backend` owns backend inventory, backend-node validation,
  eligibility, health, maintenance, capacity and protocol-specific endpoint
  resolution inside a backend node.
- `internal/state` owns Redis persistence, Lua scripts, Cluster-safe key groups,
  active holder counts and retained binding expiry.
- `internal/runtime` exposes operator diagnostics and control without becoming a
  placement implementation.
- Protocol packages own protocol parsing, auth choreography and proxy handoff.
  They request placement through cohesive interfaces and must not directly
  compose Redis scripts plus selector calls for normal placement.

Do not add package-level mutable state. Use cohesive types with constructors and
methods. Keep interfaces narrow enough that IMAP and LMTP unit tests can provide
recording implementations without starting Redis or the full application.

Suggested domain types:

```go
type BackendBinding struct {
    Key                  state.AffinityKey
    ShardTag             string
    BackendNode         string
    BackendIdentifier    string
    Source               BindingSource
    ActiveHolderCount    int
    RetentionExpiresAt   time.Time
}

type SessionPlacementRequest struct {
    Key           state.AffinityKey
    Protocol      string
    BackendPool   string
    Routing       routing.RoutingResult
    ListenerName  string
    ServiceName   string
    HolderKind    string
    LeaseTTL      time.Duration
    RetentionTTL  time.Duration
}

type PlacementLease interface {
    Binding() BackendBinding
    Close(ctx context.Context) error
    Heartbeat(ctx context.Context) error
}
```

The final implementation may use different names if they better match the
codebase, but the ownership boundary must stay intact.

## Redis State

The per-affinity Redis key group must persist backend binding as part of the
affinity state:

```text
<prefix>:v<schema>:{aff:<affinity_hash>}:state
  shard_tag
  backend_node
  active_holder_count
  retention_expires_at_ms
  binding_generation
```

Session or delivery hold records must persist:

```text
session_id
holder_kind
protocol
backend_node
selected_backend_id
backend_reservation_id
lease_expires_at_ms
```

Script rules:

- Opening the first holder for an affinity key must atomically create the
  binding with `shard_tag` and `backend_node`.
- Opening a later holder must reuse the existing active or retained binding.
- If a caller proposes a different backend node while state exists, the script
  returns the existing binding and the caller must reselect inside that backend
  node or fail closed.
- Closing the last holder leaves the state present with
  `retention_expires_at_ms = now + retention_ttl`.
- Expired retained bindings may be reaped. Reaping must be repairable and safe
  for Redis Cluster.
- Runtime clear or move operations must distinguish active binding, retained
  binding and inactive expired state.
- Backend capacity reservations must be tied to the concrete
  `backend_identifier`, while affinity binding is tied to `backend_node`.

## Backend Selection

Backend selection becomes a two-stage domain behavior:

1. Select or reuse `backend_node` for the account.
2. Resolve the requested protocol's concrete backend entry inside that backend node.

Initial placement may use the existing selector strategy within the routed shard
to pick a concrete backend. The selected backend's `backend_node` becomes the
affinity binding. Later protocol placements must not rerun an unconstrained
selector inside the shard; they must resolve inside the bound backend node.

Fail-closed cases:

- The bound backend node has no backend for the requested protocol and pool.
- The backend-node entry exists but is runtime-out, soft-unhealthy, in
  hard-maintenance, over capacity or otherwise unusable while the node has not
  been declared authoritatively hard-down by the health model.
- A backend pin targets a backend in a different backend node than active or
  retained affinity.
- A movement override would change backend node while active sessions or
  delivery holds remain and the operation is not an explicit audited migration.

Allowed movement:

- A health-authoritative hard-down backend node invalidates or supersedes the
  active or retained binding and permits automatic failover to a new healthy
  backend node through the configured selector. A single client connection
  failure or ambiguous health state is not enough for this path.
- Operator `users backend-pin set --strategy kick_existing` may move future
  placement after active holders are terminated through the runtime control path.
- A documented hard-maintenance or operator movement policy may move from the
  retained or active backend node when fail-closed behavior would be worse for
  the deployment. Such movement must be explicit, observable and auditable.
- `users affinity clear` may clear retained binding when no active holders
  remain and the operator supplies a reason.

## IMAP Changes

IMAP placement must call the shared placement domain after Nauthilus auth,
routing and user-hold gate release.

Required behavior:

- Use canonical tenant plus normalized account key from Nauthilus/routing.
- Apply user placement hold before creating sessions, reservations or backend
  connections.
- Reuse active or retained backend node before selecting a backend.
- Open the IMAP session lease with backend node and concrete IMAP backend
  identity.
- Keep backend capacity reservation and attach rollback atomic from the
  protocol caller's perspective.
- On logout, proxy close or connection loss, close the session and leave retained
  backend binding for the configured grace.
- Do not return frontend auth success until backend node resolution, backend
  capacity reservation, backend connect and backend auth have all succeeded.

Unit tests:

- Existing active LMTP delivery binding makes IMAP select the matching IMAP
  backend node, not merely any backend in the same shard.
- Existing retained LMTP binding with zero active holders makes IMAP select the
  retained backend node.
- Existing active IMAP binding makes a second IMAP session reuse the same
  concrete backend when the backend remains usable.
- If the retained backend node has no IMAP backend, login temporary-fails without
  choosing another same-shard backend.
- Closing the final IMAP session leaves retained backend binding with the
  configured TTL.

## LMTP Changes

LMTP recipient placement must use the same backend-affinity domain as IMAP.

Required behavior:

- Recipient identity lookup yields canonical tenant and normalized account key.
- User placement hold runs before backend binding or delivery side effects.
- The first accepted recipient selects or reuses a backend node and concrete
  LMTP backend.
- Additional accepted recipients in the same transaction must resolve to the
  same concrete LMTP backend. Different backend nodes or backend identifiers
  temporary-fail before `DATA` or `BDAT`.
- Delivery holds are hidden from session APIs but visible to placement as active
  backend binding.
- Final successful delivery status, `RSET`, `QUIT`, connection close and error
  close active delivery holds but leave retained backend binding for the
  configured grace.
- A later IMAP session during retention must reuse the retained backend node.

Unit tests:

- Active IMAP backend binding makes LMTP select the matching LMTP backend node.
- Retained IMAP backend binding makes LMTP select the matching LMTP backend
  node after all IMAP sessions have closed.
- LMTP delivery close leaves retained binding and no runtime session listing.
- A second recipient resolving to the same shard but a different backend node
  is rejected before message body transfer.
- Backend reservation rollback clears concrete backend accounting without
  clearing active or retained affinity incorrectly.

## Runtime, REST and CLI

OpenAPI must be updated before changing REST behavior.

Runtime affinity reads should expose, with redaction-safe fields:

- affinity key hash or user key input as already supported;
- `shard_tag`;
- `backend_node`;
- active holder count;
- retained-binding expiry;
- binding source;
- selected backend identifiers where existing REST policy permits diagnostics.

Route lookup must stay side-effect-free. It may read active and retained binding
state but must not create sessions, delivery holds, retained bindings,
reservations or backend connections.

`nauthilus-directorctl route lookup --include-affinity` should show whether the
selected backend came from:

- `active_affinity`;
- `retained_backend_binding`;
- `operator_backend_pin`;
- `movement_override`;
- `initial_placement`;
- `fail_closed`.

Runtime clear/move commands must require explicit reasons and audit metadata
when clearing retained backend binding or forcing backend-node movement.

## Observability

Metrics remain low-cardinality. Do not add usernames, recipients, session IDs,
client IPs, raw backend identifiers, backend nodes or raw error text as metric
labels.

Logs and traces may include backend node and backend identifier only where the
existing operator-diagnostic policy permits backend identifiers. They must never
include credentials, SASL blobs, bearer tokens, raw recipients, message IDs,
script names or script contents.

New bounded reason classes:

- `active_backend_binding`
- `retained_backend_binding`
- `backend_node_missing_protocol`
- `backend_node_unusable`
- `backend_node_mismatch`
- `binding_invalidated_hard_down`
- `binding_retained`
- `binding_expired`

## E2E Requirements

Deterministic fake-service E2E must prove:

- IMAP login establishes backend-node binding.
- LMTP delivery for the same account uses the matching LMTP backend in that
  backend node.
- LMTP delivery establishes backend-node binding.
- Concurrent IMAP login during the LMTP delivery uses the matching IMAP backend.
- IMAP login after LMTP final delivery but before retention expiry still uses
  the retained backend node.
- IMAP login after retention expiry may use normal initial placement.
- Same-shard but different-backend-node drift is impossible under active and
  retained binding.
- Route lookup explains active and retained binding sources without mutation.
- Health-authoritative hard-down invalidates or supersedes stale binding and
  selects a new healthy backend node; ambiguous or single-connection failures do
  not.

Real interop should prove, where practical:

- Postfix-to-Director-to-real-LMTP delivery followed immediately by IMAP access
  remains on the same backend node.
- The immediate IMAP proof runs after LMTP final success, not only while the
  delivery connection is still open.
- Existing IMAP and LMTP interop lanes remain intact.

Demo-stack proof must:

- keep `contrib/demo-stack` aligned with backend-node affinity, retained
  binding config and proof-script expectations;
- rebuild the director image before proof when code, config or packaging
  changes affect the image;
- prove the send/fetch/affinity path through the demo topology, including the
  retained LMTP-to-IMAP backend-node case where practical;
- preserve existing public proof scripts or update them in the same change.

## Implementation Order

1. Add backend-node config, registry validation and generated references.
2. Add Redis state/script support for backend node and retained binding.
3. Add shared placement domain types and interfaces.
4. Refactor IMAP placement onto the shared placement domain.
5. Refactor LMTP recipient placement and delivery holds onto the shared domain.
6. Update runtime reads, route lookup, OpenAPI and directorctl output.
7. Update M6 ManageSieve spec/prompts to require backend-node affinity.
8. Add unit, E2E and interop coverage for active and retained binding.
9. Update and prove `contrib/demo-stack` on a Docker/Compose-capable
   environment.
10. Run targeted tests, `make e2e` and `make guardrails`.

## Acceptance Criteria

- The architecture, specs and implementation no longer describe shard-only
  affinity as sufficient for user-stateful protocols.
- Redis affinity state stores and returns backend node for active and retained
  binding.
- IMAP and LMTP both consume one shared backend-affinity placement domain.
- No protocol package independently reimplements cross-protocol binding rules.
- Active IMAP influences LMTP concrete backend node.
- Active LMTP delivery influences IMAP concrete backend node.
- Retained LMTP binding influences later IMAP placement after delivery success.
- Retained IMAP binding influences later LMTP placement after logout.
- Route lookup explains active and retained backend-binding decisions without
  mutating Redis.
- Health-authoritative hard-down invalidates or supersedes active and retained
  bindings and permits selection of a new healthy backend node.
- `make e2e` proves same-account, cross-protocol backend-node consistency.
- `contrib/demo-stack` stays aligned with the corrected affinity model and
  proves the operator-facing send/fetch/affinity path on a Docker/Compose-capable
  environment.
- M6 starts only after this follow-up is complete or is implemented on top of
  the same corrected placement domain.

## Review Checklist

- Verify backend-node validation prevents ambiguous same-shard mappings.
- Verify retained binding defaults to 15 minutes and is visible in config dumps.
- Verify active and retained bindings fail closed when the protocol-specific
  backend entry is missing.
- Verify operator backend pins cannot silently override active or retained
  backend node.
- Verify hard-down is health-authoritative, invalidates or supersedes stale
  binding and is not triggered by a single client connection failure.
- Verify hard maintenance, runtime out and ambiguous health behavior is explicit
  and auditable.
- Verify LMTP delivery holds remain hidden from session APIs.
- Verify no metric label contains backend node, backend identifier, recipient
  or user identity.
- Verify M6 ManageSieve implementation uses the shared placement domain instead
  of copying old IMAP or LMTP placement logic.
- Verify `contrib/demo-stack` and its proof scripts were checked and updated
  for backend-node affinity and retained-binding behavior.

## Closeout Notes

- Backend-node placement, retained binding, route lookup diagnostics and
  bounded observability reason classes are implemented in the current working
  tree.
- Completion evidence recorded on 2026-06-01: `make check-openapi`,
  `make check-docs`, `make test`, `make race`, `make e2e`,
  `make build-check`, `make e2e-interop` and `make guardrails` passed.
- The `contrib/demo-stack` Director images were rebuilt and the operator proof
  path passed through `send-mail.sh`, `fetch-mail.sh`, `prove-affinity.sh`,
  `prove-user-backend-pin.sh` and `prove-user-hold.sh`.
