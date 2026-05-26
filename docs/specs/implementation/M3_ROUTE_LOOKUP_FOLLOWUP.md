# M3 Route Lookup Follow-up

Status: closed in M2/M3.7

M1 leaves `POST /api/v1/route/lookup` as an explicit structured
`501 Not Implemented` stub. The endpoint remains director-only and
side-effect-free: it rejects credential-bearing input before the generated
handler boundary and does not call Nauthilus, create sessions, refresh leases
or mutate Redis state.

M2/M3.7 connects route lookup read-only to the same domain pipeline used by
IMAP placement:

- Done: the runtime route-lookup service consumes diagnostic identity facts,
  listener/backend-pool context and optional attributes.
- Done: lookup uses the shared `internal/routing` resolver chain and the
  runtime-aware backend selector explanation path; it does not implement a
  parallel REST-only selector.
- Done: optional active-affinity context is read through `LookupAffinity` only;
  lookup does not open, heartbeat, close, reap, move, kick or clear sessions.
- Done: responses include routing source, effective shard, selected backend,
  active-affinity context, backend eligibility summaries, exclusion reasons and
  health/maintenance/runtime/max-connection effect flags.
- Done: generated OpenAPI DTOs remain the REST and CLI boundary.
- Done: side-effect tests use counting runtime fakes plus an import-boundary
  check proving the runtime package does not call the Nauthilus auth boundary.

No remaining route-lookup deferrals are tracked in this follow-up.
