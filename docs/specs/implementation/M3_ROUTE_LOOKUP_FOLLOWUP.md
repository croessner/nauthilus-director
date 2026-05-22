# M3 Route Lookup Follow-up

Status: M3 handoff from M1 closeout

M1 leaves `POST /api/v1/route/lookup` as an explicit structured
`501 Not Implemented` stub. The endpoint remains director-only and
side-effect-free: it rejects credential-bearing input before the generated
handler boundary and does not call Nauthilus, create sessions, refresh leases
or mutate Redis state.

M3 must connect route lookup read-only to the same domain pipeline used by IMAP
placement:

- Build a route-lookup service that consumes already-known diagnostic identity
  facts and listener/backend-pool context.
- Reuse the shared routing resolver and backend selector domain objects instead
  of creating a parallel REST-only routing model.
- Use Redis lookup-only affinity reads when the request asks for active-affinity
  context; do not open, heartbeat, close, reap, move, kick or clear sessions.
- Return logical routing facts and eligible backend summaries without exposing
  passwords, bearer tokens, SASL blobs, raw usernames, session IDs, client IPs,
  raw backend identifiers as metric labels or raw error text.
- Keep the generated OpenAPI DTOs at the REST boundary and adapt into explicit
  domain request/response objects.
- Add side-effect tests that inject counting Nauthilus, session-store and
  runtime-state fakes and prove route lookup performs no authentication or
  mutation.
