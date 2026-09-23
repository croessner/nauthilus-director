# Redis Cluster state ownership and migration

A namespace-wide hash tag such as `{nauthilus-director}` forces every Director
key into slot 386. Redis uses the first brace pair, so a later `{aff:...}` tag
cannot distribute affinity state. Adding masters or changing slot ownership
only moves this concentration; it does not split it.

Use a plain `storage.redis.key_prefix`, for example `nauthilus-director:`.
The key builder rejects braces in namespace prefixes to prevent accidental
shadowing of the authority groups below.

## Atomic ownership

| State | Hash tag | Atomic boundary |
| --- | --- | --- |
| Affinity, session leases, pins and holds | `{aff:<hash>}` | One affinity |
| Backend reservations and capacity | `{backend:<hash>:<NN>.<nonce>}` | One of 12 buckets per backend |
| Session aggregate markers, counters and idle affinities | `{agg:<NN>.<nonce>}` | One of 12 aggregate groups |
| Health ownership and health result | `{health:<backend hash>}` | One backend |
| Instance heartbeat | none | One key |
| Backend runtime overrides and backend inventory | `{backend-control}` | Small shared backend control group |
| Session locator and due index | `{session-index:<shard>}` | One bounded index shard |

The backend control group deliberately preserves inventory atomicity for
operator overrides; logins only read it, and the add-only inventory member is
rewritten at most once per minute and process. Other repairable listing keys
route independently.

### Bucketed families

Per-login writes never share one key across logins. Reservations, aggregate
markers and aggregate counters are split into twelve groups. The tag of bucket
`NN` carries a search nonce that places its slot inside the bucket's twelfth
of the slot space. With three, four or six masters that own equal contiguous
slot ranges, each master holds exactly the same number of groups. The nonce is
a pure function of family and bucket and is part of the key contract.

Capacity stays exact. Each bucket enforces an integer share of
`max_connections`, and the shares add up to the limit. A new reservation tries
the bucket selected by its session identifier and spills into buckets with free
share before it fails; it is rejected only when every share is used. The
issued reservation identifier ends in `#rb<NN>` and names its bucket, so
refresh and release touch one slot. Reservation admission repairs up to
sixteen expired leases of its own bucket first; spill tries full buckets that
hold an expired lease last, so a crashed writer cannot cause a false capacity
rejection. A retried attach of the same session may name another bucket; the
session adopts it and the replaced reservation is released. The pre-selection
repair of expired leases runs at most once per second per backend and process.

Selection reads a backend-wide count that each process reuses for up to
500 ms. A process applies its own admissions and releases to it at once, and
a failed admission marks the backend as full for that window, so the same
process does not select a saturated backend again. The login that hit the
full backend is rejected rather than moved to a sister backend, because its
affinity already names the backend node chosen before admission. It is refreshed by that repair pass or by one pipelined read of all
buckets, so a busy backend costs about one to two bucket sweeps per second and
process instead of twelve reads per login and candidate. Selection only skips
saturated backends with it; the per-bucket Lua scripts remain the capacity
authority. Operator summaries sum every aggregate group exactly.

Health owner and result share a per-backend tag. The owner scripts no longer
read the instance heartbeat key. The heartbeat key stays as a write-only
operator marker of live instances; its successful write is the process' own
Redis reachability proof and gates its owner requests. A process that sees a
valid foreign owner lease skips acquisition until that lease can have expired.
Takeover timing is unchanged.

Diagnosis: `runtime:instance:<id>` shows which instances wrote a heartbeat
recently, but no owner script reads it. Deleting it does not fence an
instance out; that instance keeps acquiring until its own locally tracked
heartbeat TTL runs out, and its next successful heartbeat restores the key.
To stop a misbehaving owner, stop its process or wait for its owner lease
(`{health:<backend hash>}:…:owner`) to expire. An owner that cannot write its
heartbeat to Redis stops asking for ownership within one heartbeat TTL.

The reaper pipelines bounded candidate reads across due-index shards. It then
resolves each locator, validates the affinity-owned key shape, and rechecks the
lease against Redis time inside that affinity's Lua operation. A candidate read
is advisory; it cannot authorize the removal of a renewed session. Empty shards
do not execute a Lua reaper. The configured pass budget and duration still bound
authority mutations; candidate reads are bounded by shard count times batch size.

Backend release and secondary index updates follow the authority operation.
Index cleanup atomically compares the observed locator and due time before
removing entries. A replacement locator or later due time wins. Backend release
remains idempotent; interrupted follow-up repairs are not a reason to decrement
capacity twice. Session identifiers must remain globally unique.

Session kill similarly resolves its repairable locator before entering the
session's slot. The authority script validates the stored session identity and
control fields before marking it. Missing or contradictory state fails closed.

## Verification

`make test-cluster` starts a disposable Redis 8.6.2 container containing three
masters, tests actual cross-slot routing, and removes its container on exit.
The image digest is pinned. Only loopback client ports are published; no
production credentials or production data are used. Docker is required.
`DIRECTOR_TEST_CLUSTER_BASE_PORT` changes the default base port of 18379.

The target is part of `make guardrails`, including CI. It covers the original
health, backend override, session-kill and reaper failures, preservation of a
renewed lease and a replaced locator, absence of Lua calls for empty reaping,
and distribution of 60 real affinity states across all three masters. It also
compares the local slot function with `CLUSTER KEYSLOT`, runs the mixed-layout
reservation, aggregate and health contracts, races concurrent reservations
against one limit and checks that one backend's reservation buckets and the
aggregate groups split 4/4/4 across the three masters.
`go test ./internal/state -run TestClusterKeyDistributionReport -v` prints the
modelled distribution for 10 backends, 3 instances and 10,000 sessions.
The existing standalone state and protocol E2E suites remain required.

## Rolling upgrade from the single-slot layout

Releases that already use a plain prefix but still keep reservations in
`{backend:<hash>}`, aggregates in untagged `runtime:aggregates:*` keys and
health in `{health}` can be upgraded replica by replica. Affinity, session,
pin, hold, override and index keys are unchanged, so stickiness holds across
old and new replicas. No drain, flush or offline migration is required.

While old and new replicas run together:

- New replicas admit reservations only into buckets. Their bucket shares are
  computed from `max_connections` minus the legacy reservation count, which is
  reread at most once per second. Counts, reaping and releases include the
  legacy group, and identifiers without a bucket suffix release there.
  Old replicas still admit into the legacy group and see only its count. The
  combined count can therefore exceed `max_connections` only through
  admissions by old replicas while new replicas hold bucket reservations,
  bounded by the old replicas' own limit check. When a strict limit must hold
  during the upgrade, pause new admissions for the few minutes of the rollout.
- A reservation is stored in exactly one layout. An old reaper that releases a
  bucket identifier in the legacy group changes nothing; the bucket lease then
  expires and new replicas repair it. Nothing is released twice.
- New replicas write session aggregates only into groups. Summaries and repair
  read both layouts. Removals fall back to the legacy keys while they exist.
  A session opened by a new replica but reaped by an old replica can leave a
  stale group marker; `nauthilus-directorctl runtime reconcile aggregates`
  removes it. Old replicas' summaries omit sessions of new replicas.
- Each layout elects its own health owner, so an owner exists for old and for
  new readers. Deep checks can run twice per interval during the rollout.
  Fencing tokens are separate per layout and never compete. New replicas read
  the legacy health result while the per-backend result is missing or stale
  and the legacy result is fresh.

After the last old replica has stopped and one lease TTL has passed, legacy
reservations, markers and owner leases have drained. Run an aggregate
reconcile once. The following keys are then no longer written and can be
removed after explicit approval with bounded `SCAN` and `UNLINK`:

- `<prefix>:v1:{backend:<hash>}:runtime:backend:*:reservations` and
  `…:reservations_due`, only when `active_session_count` is `0`
- `<prefix>:v1:runtime:aggregates:sessions`, `…:idle_affinities` and
  `…:active:*`, including the retired `…:active:reserved_backend`
- `<prefix>:v1:{health}:*`

Keep `<prefix>:v1:runtime:aggregates:repairs`. Rolling back to the old release
is possible while legacy keys exist. Old replicas ignore bucketed state, so
their capacity checks and summaries omit sessions of new replicas until those
end; expired bucket reservations left behind are repaired by the next upgrade.

## Existing installations with a namespace hash tag

This is a state-key migration, not a rolling configuration edit. The namespace
prefix, health/control keys and locator/due index keys change. Do not deploy a
mixture of old and new writers, remove prefix braces while old processes run,
flush Redis, or discard operator state as a shortcut.

For an approved maintenance window:

- Record the exact old image, configuration and replica count. Inventory active
  sessions, in-flight deliveries, retained affinities, user holds, pins,
  overrides and backend maintenance/drain settings without logging user data.
- Quiesce new frontend admissions and drain the old fleet. Existing long-lived
  sessions may reconnect under the approved maintenance policy. Verify zero
  active sessions and in-flight deliveries, then stop every old writer.
- Preserve the old namespace for rollback. Prepare and verify a bounded state
  migration that preserves retained affinity, operator controls and remaining
  TTLs. Empty/stale secondary session indexes can be rebuilt, but namespace
  replacement alone is insufficient: stored Redis-key references must also be
  handled. Do not silently drop holds, pending moves or backend maintenance.
- Deploy the validated release with a plain prefix and consistent new keys.
  Verify migrated operator state before reopening admissions. Prove real IMAP,
  Sieve and LMTP paths, lease refresh/close, reaping and fenced health handling.
- After acceptance and explicit retirement approval, remove only the old
  Director namespace using bounded `SCAN` and small `UNLINK` batches. Verify
  that a complete follow-up scan finds zero old keys. Never use `FLUSHDB` or
  `FLUSHALL`. Retiring old state ends the preserved-namespace rollback option.
- Compare command-rate deltas, slot distribution and latency across all masters.
  AOF write pauses require a separate storage/scheduling correlation; spreading
  Director traffic does not by itself establish that their cause is fixed.

Rollback after new traffic has been admitted requires reconciling new state;
simply starting old writers against the old namespace would create two competing
state histories. Plan and rehearse this before the production window.
