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
| Backend reservations and capacity | `{backend:<hash>}` | One backend |
| Instance heartbeat, health ownership and health result | `{health}` | Small shared health control group |
| Backend runtime overrides and backend inventory | `{backend-control}` | Small shared backend control group |
| Session locator and due index | `{session-index:<shard>}` | One bounded index shard |

The shared control groups deliberately preserve fencing and inventory atomicity.
They do not contain user sessions or the per-affinity write traffic. Other
repairable listing and aggregate keys continue to route independently.

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
and distribution of 60 real affinity states across all three masters.
The existing standalone state and protocol E2E suites remain required.

## Existing installations

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
